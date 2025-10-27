"""
EWMA-Enabled User Activity Proxy
================================
A clean, structured mitmproxy addon that tracks user activities 
and uses EWMA (Exponentially Weighted Moving Average) to detect suspicious behavior.
Usage:

 mitmdump -s mitm_addon.py --listen-port 8080 --set confdir=./certs
Flow:
1. Intercept Google Drive requests (API or Browser)
2. Extract user email (from Bearer token or response)
3. Detect activity type (delete, download, sensitive, unshared)
4. Update EWMA scores
5. Check if activity is suspicious
6. Block or allow the request

"""

import re
import time
import json
import hashlib
import threading
from datetime import datetime
from typing import Dict, Optional, Any
import os
from dotenv import load_dotenv
import requests
from mitmproxy import http
from pymongo import MongoClient

load_dotenv()

# Import EWMA functions (don't modify these files)
try:
    from ewmaUtils import update_user_activity_ewma
    from ewmaDetector import get_and_update_user_allowance
    EWMA_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  WARNING: EWMA modules not found - {e}")
    EWMA_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

# MongoDB Configuration
MONGO_CONNECTION_STRING = os.getenv('MONGODB_URI')
DB_NAME = "UserTokenMapping"
COLLECTION_NAME = "userCookies"

# Google Drive API Hosts
GOOGLE_DRIVE_HOSTS = [
    'www.googleapis.com',
    'drive.google.com',
    'docs.google.com',
    'clients6.google.com',
    'drivefrontend-pa.clients6.google.com',
    'drive.usercontent.google.com'  # For file downloads
]

# Google Authentication Host
AUTH_HOST = 'accounts.google.com'

# Google APIs for email lookup
GOOGLE_DRIVE_ABOUT_API = "https://www.googleapis.com/drive/v3/about?fields=user"
GOOGLE_USERINFO_API = "https://www.googleapis.com/oauth2/v2/userinfo"

# Cache settings
TOKEN_CACHE_TTL = 300  # 5 minutes

# Log file
LOG_FILE = "ewma_proxy.log"
blocked_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Google Drive Access Blocked</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 50px; text-align: center; background-color: #f5f5f5; }}
                        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        .blocked {{ color: #d32f2f; font-size: 28px; margin-bottom: 20px; font-weight: bold; }}
                        .icon {{ font-size: 64px; margin-bottom: 20px; }}
                        .reason {{ color: #666; font-size: 16px; margin-bottom: 15px; line-height: 1.5; }}
                        .timestamp {{ color: #999; font-size: 12px; margin-top: 20px; }}
                        .service {{ color: #1a73e8; font-weight: bold; }}
                        .alert {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                        .details {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; font-size: 14px; color: #666; }}
                        hr {{ border: none; border-top: 1px solid #eee; margin: 20px 0; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">🚫</div>
                        <div class="blocked"><span class="service">Google Drive</span> Access Blocked</div>
                        <div class="alert">
                            <strong>Unauthorized File Access Detected</strong>
                        </div>
                        <div class="reason">You do not have permission to access this file.</div>
                        <div class="reason">Your access to this Google Drive resource has been restricted by the security system.</div>
                        <hr>
                        <small>Contact your system administrator if you believe this is an error.</small>
                    </div>
                </body>
                </html>
                """

# ============================================================================
# LOGGING HELPER
# ============================================================================

def log(message: str):
    """Write message to both console and log file."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    try:
        with open(LOG_FILE, 'a', encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except:
        pass


# ============================================================================
# EWMA PROXY CLASS
# ============================================================================

class EWMAProxy:
    """
    Main proxy class that handles Google Drive request/response interception
    and EWMA-based activity tracking and blocking.
    """
    
    def __init__(self):
        """Initialize the proxy with MongoDB connection and caches."""
        log("="*80)
        log("🚀 EWMA-Enabled Google Drive Proxy Starting...")
        log("="*80)
        
        # MongoDB connection
        try:
            self.mongo_client = MongoClient(MONGO_CONNECTION_STRING)
            self.db = self.mongo_client[DB_NAME]
            self.collection = self.db[COLLECTION_NAME]
            # UserCookies collection for download email lookup (NID-based)
            self.user_cookies_collection = self.db['UserCookies']
            self.file_info_db = self.mongo_client['FileInfo']
            self.file_activity_collection = self.file_info_db['FileActivityLogs']
            self.ewma_config_db = self.mongo_client['EWMAconfig']
            self.blocked_users_collection = self.ewma_config_db['blockedUsers']
            self.initialize_blocked_users_document()
            log("✅ MongoDB connected successfully")
        except Exception as e:
            log(f"❌ MongoDB connection failed: {e}")
            self.collection = None
            self.user_cookies_collection = None
            self.file_activity_collection = None
            self.blocked_users_collection = None
        
        # Token to email cache: {token: (email, timestamp)}
        self.token_cache = {}
        
        # Pending deletions: {request_hash: {original_request, timestamp}}
        self.pending_deletions = {}
        
        # Statistics
        self.stats = {
            'deletions_intercepted': 0,
            'deletions_blocked': 0,
            'downloads_detected': 0,
            'unauthorized_access_blocked': 0,
            'activities_tracked': 0,
            'requests_blocked': 0
        }
        self.permission_cache = {}
        self.PERMISSION_CACHE_TTL = 60
        
        log(f"✅ EWMA Module: {'Active' if EWMA_AVAILABLE else 'Disabled'}")
        log("="*80)
    def initialize_blocked_users_document(self):
        """Initialize the blockedUsers document if it doesn't exist."""
        if self.blocked_users_collection is None:
            return
        
        try:
            # Check if document exists
            doc = self.blocked_users_collection.find_one()
            
            if not doc:
                # Create initial document with empty arrays
                initial_doc = {
                    "sensitiveCount": [],
                    "unsharedAccess": [],
                    "downloadCount": [],
                    "deleteCount": []
                }
                self.blocked_users_collection.insert_one(initial_doc)
                log("📋 Initialized blockedUsers document")
            else:
                log("📋 blockedUsers document already exists")
        except Exception as e:
            log(f"❌ Failed to initialize blockedUsers document: {e}")
    def add_blocked_user(self, email: str, activity_type: str):
        """
        Add user email to blocked users list for specific activity type.
        
        Args:
            email: User email address
            activity_type: One of 'sensitiveCount', 'unsharedAccess', 'downloadCount', 'deleteCount'
        """
        if self.blocked_users_collection is None or not email:
            return
        
        try:
            # Map activity types to field names
            activity_field_map = {
                'sensitiveCount': 'sensitiveCount',
                'unsharedAccess': 'unsharedAccess',
                'downloadCount': 'downloadCount',
                'deleteCount': 'deleteCount'
            }
            
            field_name = activity_field_map.get(activity_type)
            if not field_name:
                log(f"⚠️  Unknown activity type: {activity_type}")
                return
            
            # Check if user is already in the blocked list
            doc = self.blocked_users_collection.find_one()
            if doc and email in doc.get(field_name, []):
                log(f"ℹ️  User {email} already in blocked list for {activity_type}")
                return
            
            # Add user to blocked list (using $addToSet to avoid duplicates)
            result = self.blocked_users_collection.update_one(
                {},  # Match the single document
                {"$addToSet": {field_name: email}},  # Add to array if not exists
                upsert=True  # Create document if it doesn't exist
            )
            
            if result.modified_count > 0 or result.upserted_id:
                log(f"🚫 Added {email} to blocked users for {activity_type}")
            
        except Exception as e:
            log(f"❌ Failed to add blocked user: {e}")
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def is_google_drive_request(self, flow: http.HTTPFlow) -> bool:
        """Check if request is to Google Drive."""
        try:
            host = flow.request.host.lower()
            return any(drive_host in host for drive_host in GOOGLE_DRIVE_HOSTS)
        except:
            return False
    
    def extract_bearer_token(self, headers) -> Optional[str]:
        """Extract Bearer token from Authorization header."""
        auth = headers.get("authorization") or headers.get("Authorization")
        if not auth:
            return None
        match = re.match(r"Bearer\s+(.+)", auth, flags=re.I)
        return match.group(1) if match else None
    
    def get_request_hash(self, request) -> str:
        """Generate unique hash for a request."""
        url = request.pretty_url
        method = request.method
        content = request.content[:1000] if request.content else b""
        hash_string = f"{method}:{url}:{content}"
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    # ========================================================================
    # EMAIL EXTRACTION METHODS
    # ========================================================================
    
    def get_email_from_token_cache(self, token: str) -> Optional[str]:
        """Get email from cache if not expired."""
        cached = self.token_cache.get(token)
        if cached:
            email, timestamp = cached
            age = time.time() - timestamp
            if age < TOKEN_CACHE_TTL:
                log(f"📦 Cache hit: {email}")
                return email
            else:
                del self.token_cache[token]
        return None
    
    def cache_token_email(self, token: str, email: str):
        """Cache token to email mapping."""
        self.token_cache[token] = (email, time.time())
    
    def lookup_email_from_drive_api(self, token: str) -> Optional[str]:
        """
        Lookup user email using Google Drive API with Bearer token.
        First tries /drive/v3/about, then falls back to /oauth2/v2/userinfo.
        """
        session = requests.Session()
        session.trust_env = False  # Don't use proxy for this call
        headers = {"Authorization": f"Bearer {token}"}
        
        # Try Drive API first
        try:
            log(f"🔍 Looking up email from Drive API...")
            r = session.get(GOOGLE_DRIVE_ABOUT_API, headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                email = data.get("user", {}).get("emailAddress")
                if email:
                    log(f"✅ Drive API: {email}")
                    return email
        except Exception as e:
            log(f"⚠️  Drive API failed: {e}")
        
        # Fallback to userinfo API
        try:
            log(f"🔍 Trying userinfo API...")
            r = session.get(GOOGLE_USERINFO_API, headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                email = data.get("email")
                if email:
                    log(f"✅ Userinfo API: {email}")
                    return email
        except Exception as e:
            log(f"⚠️  Userinfo API failed: {e}")
        
        return None
    
    def get_email_from_mongodb(self, token: str) -> Optional[str]:
        """Get email from MongoDB token mapping."""
        if self.collection is None:
            return None
        try:
            doc = self.collection.find_one({"token": token})
            if doc and "email" in doc:
                return doc["email"]
        except:
            pass
        return None
    
    def get_email_for_api_request(self, token: str) -> Optional[str]:
        """
        Get email for API request (has Bearer token).
        Tries: Cache → MongoDB → Drive API → Cache result
        """
        # Try cache first
        email = self.get_email_from_token_cache(token)
        if email:
            return email
        
        # Try MongoDB
        email = self.get_email_from_mongodb(token)
        if email:
            self.cache_token_email(token, email)
            return email
        
        # Try Drive API
        email = self.lookup_email_from_drive_api(token)
        if email:
            self.cache_token_email(token, email)
            return email
        
        return None
    
    def extract_email_from_response(self, response_text: str) -> Optional[str]:
        """Extract email from Google Drive API response."""
        try:
            # Look for email pattern in response (works for multipart responses too)
            # Try multiple patterns since Google uses different field names
            email_patterns = [
                r'"emailAddressFromAccount"\s*:\s*"([^"]+@[^"]+)"',  # Browser deletion response
                r'"emailAddress"\s*:\s*"([^"]+@[^"]+)"',              # Standard API response
                r'"email"\s*:\s*"([^"]+@[^"]+)"'                      # Alternate format
            ]
            
            for pattern in email_patterns:
                match = re.search(pattern, response_text)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    def extract_nid_from_cookies(self, cookies) -> Optional[str]:
        """Extract NID cookie value from request cookies."""
        try:
            if hasattr(cookies, 'get'):
                # Dictionary-like object
                return cookies.get('NID')
            elif hasattr(cookies, 'items'):
                # Items object
                for name, value in cookies.items():
                    if name == 'NID':
                        return value
        except Exception as e:
            log(f"❌ Error extracting NID: {e}")
        return None
    
    def get_email_from_nid(self, nid: str) -> Optional[str]:
        """Lookup email from UserCookies collection using NID."""
        if self.user_cookies_collection is None or not nid:
            return None
        
        try:
            user = self.user_cookies_collection.find_one({"nid": nid})
            if user:
                email = user.get("email")
                log(f"👤 Found user by NID: {email}")
                return email
        except Exception as e:
            log(f"❌ MongoDB NID lookup failed: {e}")
        return None
    
    def extract_email_and_ouid_from_auth_header(self, header: str) -> tuple:
        """Extract email and obfuscated ID from google-accounts-signin header."""
        try:
            email_match = re.search(r'email="([^"]+)"', header)
            ouid_match = re.search(r'obfuscatedid="([^"]+)"', header)
            email = email_match.group(1) if email_match else None
            ouid = ouid_match.group(1) if ouid_match else None
            return email, ouid
        except:
            return None, None
    def extract_file_id_from_request(self, flow: http.HTTPFlow) -> Optional[str]:
        """Extract Google Drive file ID from request URL or content."""
        try:
            url = flow.request.pretty_url
            path = flow.request.path
            
            # Pattern 1: /d/{fileId}/ in Google Docs URLs (HIGHEST PRIORITY)
            match = re.search(r'/d/([a-zA-Z0-9_-]{20,})', path)
            if match:
                file_id = match.group(1)
                log(f"📄 File ID from /d/ path: {file_id}")
                return file_id
            
            # Pattern 2: /files/{fileId} in API URLs
            match = re.search(r'/files/([a-zA-Z0-9_-]{20,})', path)
            if match:
                file_id = match.group(1)
                log(f"📄 File ID from /files/ path: {file_id}")
                return file_id
            
            # Pattern 3: ?id= or &id= parameter
            match = re.search(r'[?&]id=([a-zA-Z0-9_-]{20,})', url)
            if match:
                file_id = match.group(1)
                log(f"📄 File ID from query param: {file_id}")
                return file_id
            
            # Pattern 4: In request body (for batch requests)
            if flow.request.content:
                try:
                    content = flow.request.text
                    # Look for file IDs in JSON content
                    match = re.search(r'"fileId"\s*:\s*"([a-zA-Z0-9_-]{20,})"', content)
                    if match:
                        file_id = match.group(1)
                        log(f"📄 File ID from request body: {file_id}")
                        return file_id
                except:
                    pass
            
            return None
        except Exception as e:
            log(f"❌ Error extracting file ID: {e}")
            return None
    def check_file_permission(self, email: str, file_id: str, use_cache:bool = True) -> bool:
        """
        Check if user has permission to access the file.
        Returns True if user has permission, False otherwise.
        """
        # Check cache first
        if use_cache:
            cache_key = (email, file_id)
            cached = self.permission_cache.get(cache_key)
            if cached:
                has_permission, timestamp = cached
                age = time.time() - timestamp
                if age < self.PERMISSION_CACHE_TTL:
                    log(f"📦 Permission cache hit: {email} → {file_id} = {has_permission}")
                    return has_permission
        if self.file_activity_collection is None:
            log(f"⚠️  FileInfo collection not available - allowing by default")
            return True
        
        try:
            # Look up file in FileActivityLogs collection
            file_doc = self.file_activity_collection.find_one({"file_id": file_id})
            
            if not file_doc:
                log(f"⚠️  File {file_id} not found in database - allowing by default")
                return True
            
            file_name = file_doc.get("file_name", "unknown")
            owner = file_doc.get("owner", "unknown")
            permissions = file_doc.get("permissions", [])
            
            log(f"📄 File: {file_name} (Owner: {owner})")
            log(f"👥 Checking permissions for {email}...")
            
            # Check if user is the owner
            if email == owner:
                log(f"✅ User is the OWNER - access granted")
                result = True
                self.permission_cache[(email, file_id)] = (result, time.time())
                return result
            
            # Check if user is in permissions list
            for perm in permissions:
                perm_email = perm.get("emailAddress", "")
                role = perm.get("role", "")
                
                if perm_email.lower() == email.lower():
                    log(f"✅ User has '{role}' permission - access granted")
                    result = True
                    self.permission_cache[(email, file_id)] = (result, time.time())
                    return result
            
            # User not found in permissions
            log(f"🚫 User NOT in permissions list - access DENIED")
            log(f"📋 Allowed users: {[p.get('emailAddress') for p in permissions]}")
            result = False
            self.permission_cache[(email, file_id)] = (result, time.time())
            return result
            
        except Exception as e:
            log(f"❌ Error checking file permission: {e}")
            return True  # Fail open - allow by default if error
# ========================================================================
# COOKIE EXTRACTION AND STORAGE
# ========================================================================
    def extract_cookies_from_request(self, flow: http.HTTPFlow) -> dict:
        """Extract all important cookies from request."""
        cookies_data = {}
        
        try:
            if flow.request.cookies:
                # Extract important Google cookies
                important_cookies = ['NID', 'SID', 'HSID', 'SSID', '__Secure-1PSID', '__Secure-3PSID']
                
                for cookie_name in important_cookies:
                    cookie_value = None
                    
                    # Try dictionary-like access
                    if hasattr(flow.request.cookies, 'get'):
                        cookie_value = flow.request.cookies.get(cookie_name)
                    
                    # Try items() iteration
                    elif hasattr(flow.request.cookies, 'items'):
                        for name, value in flow.request.cookies.items():
                            if name == cookie_name:
                                cookie_value = value
                                break
                    
                    if cookie_value:
                        cookies_data[cookie_name.lower()] = cookie_value
                
                if cookies_data:
                    log(f"🍪 Extracted cookies: {list(cookies_data.keys())}")
        
        except Exception as e:
            log(f"❌ Error extracting cookies: {e}")
        
        return cookies_data
    
    def store_cookies_in_mongodb(self, email: str, cookies_data: dict) -> bool:
        """Store user cookies in MongoDB for later lookup."""
        if self.user_cookies_collection is None or not email or not cookies_data:
            return False
        
        try:
            from datetime import datetime
            
            # Check if user already exists
            existing_user = self.user_cookies_collection.find_one({"email": email})
            
            update_data = {
                **cookies_data,  # Add all cookies (nid, sid, hsid, etc.)
                "last_updated": datetime.utcnow().isoformat()
            }
            
            if existing_user:
                # Update existing user
                self.user_cookies_collection.update_one(
                    {"email": email},
                    {"$set": update_data}
                )
                log(f"🔄 Updated cookies for {email}")
            else:
                # Insert new user
                user_data = {
                    "email": email,
                    **cookies_data,
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                }
                self.user_cookies_collection.insert_one(user_data)
                log(f"🆕 Stored new cookies for {email}")
            
            return True
        except Exception as e:
            log(f"❌ Failed to store cookies: {e}")
            return False
    
    def get_email_from_cookies(self, cookies_data: dict) -> Optional[str]:
        """Lookup email from UserCookies collection using any of the cookies."""
        if self.user_cookies_collection is None or not cookies_data:
            return None
        
        try:
            # Try to find user by NID first (most reliable)
            if 'nid' in cookies_data:
                user = self.user_cookies_collection.find_one({"nid": cookies_data['nid']})
                if user:
                    email = user.get("email")
                    log(f"👤 Found user by NID: {email}")
                    return email
            
            # Fallback to other cookies
            for cookie_name in ['sid', 'hsid', 'ssid', '__secure-1psid', '__secure-3psid']:
                if cookie_name in cookies_data:
                    user = self.user_cookies_collection.find_one({cookie_name: cookies_data[cookie_name]})
                    if user:
                        email = user.get("email")
                        log(f"👤 Found user by {cookie_name.upper()}: {email}")
                        return email
            
            log(f"⚠️  No user found for provided cookies")
        except Exception as e:
            log(f"❌ MongoDB cookie lookup failed: {e}")
    def extract_cookies_from_response_headers(self, response) -> dict:
        """Extract all important cookies from response Set-Cookie headers."""
        cookies_data = {}
        
        try:
            # Get all Set-Cookie headers
            set_cookie_headers = response.headers.get_all("set-cookie") or []
            
            log(f"🔍 Checking {len(set_cookie_headers)} Set-Cookie headers")
            
            # Extract important Google cookies
            important_cookies = ['NID', 'SID', 'HSID', 'SSID', '__Secure-1PSID', '__Secure-3PSID', 'APISID', 'SAPISID']
            
            for cookie_header in set_cookie_headers:
                for cookie_name in important_cookies:
                    # Look for COOKIENAME=value
                    pattern = f'{cookie_name}=([^;]+)'
                    match = re.search(pattern, cookie_header, re.IGNORECASE)
                    if match:
                        cookie_value = match.group(1)
                        cookies_data[cookie_name.lower()] = cookie_value
                        log(f"🔍 Found {cookie_name} in Set-Cookie: {cookie_value[:20]}...")
            
            if cookies_data:
                log(f"🍪 Extracted cookies from Set-Cookie: {list(cookies_data.keys())}")
            else:
                log(f"⚠️  No important cookies found in Set-Cookie headers")
        
        except Exception as e:
            log(f"❌ Error extracting cookies from Set-Cookie: {e}")
        
        return cookies_data    
        return None
    def handle_auth_response(self, flow: http.HTTPFlow):
        """Handle Google authentication responses to populate UserCookies."""
        if flow.request.pretty_host != AUTH_HOST:
            return
        
        if not flow.response or not flow.response.headers:
            return
        
        # Look for google-accounts-signin header
        google_signin_header = flow.response.headers.get("google-accounts-signin", "")
        if not google_signin_header:
            return
        
        log(f"\n{'='*80}")
        log(f"🔐 AUTHENTICATION DETECTED")
        log(f"URL: {flow.request.pretty_url[:80]}")
        
        # Extract email and ouid from response header
        email, ouid = self.extract_email_and_ouid_from_auth_header(google_signin_header)
        
        if email:
            log(f"📧 Email from auth header: {email}")
        
        # Extract cookies from RESPONSE Set-Cookie headers (where Google sets NEW cookies)
        cookies_data = self.extract_cookies_from_response_headers(flow.response)
        
        # Add OUID to cookies data
        if ouid:
            cookies_data['ouid'] = ouid
        
        if email and cookies_data:
            log(f"🍪 Cookies being set by Google: {list(cookies_data.keys())}")
            success = self.store_cookies_in_mongodb(email, cookies_data)
            if success:
                log(f"✅ Successfully stored auth data for {email}")
            else:
                log(f"❌ Failed to store auth data for {email}")
        else:
            log(f"⚠️  Incomplete auth data - Email: {email or 'Missing'}, Cookies: {list(cookies_data.keys()) if cookies_data else 'None'}")
    # ========================================================================
    # ACTIVITY DETECTION METHODS
    # ========================================================================
    
    def detect_activity_type(self, flow: http.HTTPFlow) -> Optional[str]:
        """
        Detect Google Drive activity type from request.
        Returns: 'deleteCount', 'downloadCount', 'sensitiveCount', 'unsharedAccess', or None
        """
        url = flow.request.pretty_url.lower()
        method = flow.request.method.upper()
        path = flow.request.path.lower()
        
        # Get request content
        content = ""
        if flow.request.content:
            try:
                content = flow.request.text.lower()
            except:
                content = str(flow.request.content).lower()
        
        # 1. DELETION (deleteCount)
        # Only check for actual deletion requests, not account info requests
        
        # Pattern 1: DELETE method to /files/
        if method == 'DELETE' and '/files/' in path:
            return 'deleteCount'
        
        # Pattern 2: PATCH with trashed:true to /files/ endpoint
        if method == 'PATCH' and '/files/' in path and ('"trashed":true' in content or '"trashed": true' in content):
            return 'deleteCount'
        
        # Pattern 3: POST to batch endpoint with trashed:true (MOST COMMON for browser)
        # Make sure it's the batch/drive endpoint specifically
        if method == 'POST' and '/batch/drive' in path and ('"trashed":true' in content or '"trashed": true' in content):
            return 'deleteCount'
        
        # Pattern 4: Explicit trash endpoint only (NOT any URL with 'trash')
        if method in ['POST', 'PUT', 'PATCH'] and path.startswith('/trash'):
            return 'deleteCount'
        
        # 2. DOWNLOAD (downloadCount)
        # Pattern 1: File download from drive.usercontent.google.com
        if flow.request.pretty_host == 'drive.usercontent.google.com':
            if method == 'POST' and '/uc?id=' in path:
                log(f"📥 DOWNLOAD detected: {flow.request.pretty_url}")
                self.stats['downloads_detected'] += 1
                return 'downloadCount'
        
        # Pattern 2: API downloads with alt=media or export
        if 'alt=media' in url or '/export' in path or 'exportlinks' in path:
            log(f"📥 DOWNLOAD detected (API): {flow.request.pretty_url}")
            self.stats['downloads_detected'] += 1
            return 'downloadCount'
        
        # Pattern 3: Generic download parameter
        if method == 'GET' and 'download' in url:
            log(f"📥 DOWNLOAD detected (generic): {flow.request.pretty_url}")
            self.stats['downloads_detected'] += 1
            return 'downloadCount'
        
        # 3. PERMISSION CHANGES (sensitiveCount)
        # Check permissions endpoint first (highest priority)
        if '/permissions' in path:
            # Distinguish between permission CHANGES and permission CHECKS
            if method in ['POST', 'PATCH', 'PUT', 'DELETE']:
                log(f"🔐 Permission CHANGE detected in path: {path}")
                return 'sensitiveCount'
            elif method in ['GET', 'OPTIONS']:
                log(f"🔍 Permission CHECK detected (GET/OPTIONS): {path}")
                return 'permissionCheck'  # New activity type for permission checks
        
        # Check for permission-related content (but exclude account info)
        if method in ['POST', 'PATCH', 'PUT'] and '/v1/account' not in path:
            if 'permission' in content or '"role"' in content:
                # Make sure it's actually a permission change
                if 'share' in content or 'reader' in content or 'writer' in content or 'commenter' in content:
                    log(f"🔐 Permission change detected in content")
                    return 'sensitiveCount'
        
        # 4. FILE ACCESS (unsharedAccess)
        if '/files/' in path:
            if method in ['GET', 'POST', 'PATCH']:
                # Exclude metadata/batch endpoints
                if '/batch' not in path and '/about' not in path and '/permissions' not in path:
                    # Check if this is a file content request (not just metadata)
                    if '?alt=' in url or 'fields=' in url or '/export' in path or method == 'GET':
                        log(f"📂 File content access detected")
                        return 'unsharedAccess'
        
        # Also check for file access in document URLs
        if 'docs.google.com/document' in url or 'docs.google.com/spreadsheets' in url or 'docs.google.com/presentation' in url:
            if method == 'GET' and '/d/' in path:
                # Extract file ID from /d/{fileId}/ pattern
                match = re.search(r'/d/([a-zA-Z0-9_-]+)', path)
                if match:
                    log(f"📂 Google Docs file access detected")
                    return 'unsharedAccess'
        
        return None
    
    # ========================================================================
    # DELETION HANDLING METHODS
    # ========================================================================
    
    def handle_deletion_request(self, flow: http.HTTPFlow) -> bool:
        """
        Handle deletion request by modifying trashed:true → trashed:false.
        Stores original request for later execution after EWMA check.
        Returns True if this was a deletion request.
        """
        activity_type = self.detect_activity_type(flow)
        if activity_type != 'deleteCount':
            return False
        
        log(f"🗑️  DELETION DETECTED: {flow.request.pretty_url}")
        
        # Store original request
        request_hash = self.get_request_hash(flow.request)
        self.pending_deletions[request_hash] = {
            'url': flow.request.pretty_url,
            'method': flow.request.method,
            'headers': dict(flow.request.headers),
            'content': flow.request.content,
            'timestamp': time.time()
        }
        
        # Modify request to prevent immediate deletion
        if flow.request.content:
            try:
                content_str = flow.request.text
                # Replace trashed:true with trashed:false
                modified_content = content_str.replace('"trashed":true', '"trashed":false')
                modified_content = modified_content.replace('"trashed": true', '"trashed": false')
                flow.request.text = modified_content
                
                self.stats['deletions_intercepted'] += 1
                log(f"✏️  Modified: trashed:true → trashed:false (Hash: {request_hash[:8]})")
                
            except Exception as e:
                log(f"❌ Error modifying deletion request: {e}")
        
        return True
    
    def schedule_actual_deletion(self, deletion_data: dict):
        """
        Schedule the actual deletion to be executed after 20 seconds.
        This runs in a separate thread.
        """
        def delayed_delete():
            time.sleep(20)
            
            try:
                log(f"⏰ Executing delayed deletion to {deletion_data['url'][:50]}...")
                session = requests.Session()
                session.trust_env = False
                
                response = session.request(
                    method=deletion_data['method'],
                    url=deletion_data['url'],
                    headers=deletion_data['headers'],
                    data=deletion_data['content'],
                    timeout=10
                )
                
                log(f"✅ Delayed deletion executed - Status: {response.status_code}")
                
            except Exception as e:
                log(f"❌ Failed to execute delayed deletion: {e}")
        
        thread = threading.Thread(target=delayed_delete, daemon=True)
        thread.start()
    
    # ========================================================================
    # EWMA TRACKING METHODS
    # ========================================================================
    
    def track_and_check_activity(self, email: str, activity_type: str) -> bool:
        """
        Update EWMA scores and check if activity should be blocked.
        Returns True if activity is allowed, False if blocked.
        """
        if not EWMA_AVAILABLE:
            return True  # Allow by default if EWMA not available
        
        try:
            # Update EWMA scores
            log(f"📊 EWMA Tracking: {email} → {activity_type}")
            update_user_activity_ewma(email, activity_type)
            
            # Check if activity is suspicious
            log(f"🔍 Checking allowance for {email}...")
            is_allowed = get_and_update_user_allowance(email, activity_type)
            
            if is_allowed == False:
                log(f"🚨 BLOCKED: {email} - {activity_type} - Suspicious activity detected!")
                self.add_blocked_user(email, activity_type)
                self.stats['requests_blocked'] += 1
                return False
            elif is_allowed == True:
                log(f"✅ ALLOWED: {email} - {activity_type}")
                return True
            else:
                log(f"⚠️  EWMA ERROR: {email} - {activity_type} - Allowing by default")
                return True
                
        except Exception as e:
            log(f"❌ EWMA check failed: {e}")
            return True  # Fail open
    
    # ========================================================================
    # REQUEST HANDLER
    # ========================================================================
    
    def request(self, flow: http.HTTPFlow):
        """
        Main request handler.
        Handles API requests (with Bearer token) immediately.
        Stores browser deletion requests for processing in response phase.
        """
        # Only process Google Drive requests
        if not self.is_google_drive_request(flow):
            return
        
        log(f"\n{'='*80}")
        log(f"📨 REQUEST: {flow.request.method} {flow.request.pretty_url[:80]}")
        
        # Detect activity type first
        activity_type = self.detect_activity_type(flow)
        
        # Handle browser downloads (no Bearer token, uses cookies)
       # Handle ALL downloads (browser and API) - BLOCK IN REQUEST PHASE
        if activity_type == 'downloadCount':
            log(f"📥 Download detected - processing for immediate blocking check")
            
            # For API downloads (with Bearer token), we can get email immediately
            token = self.extract_bearer_token(flow.request.headers)
            if token:
                log(f"🔑 API download with Bearer token")
                email = self.get_email_for_api_request(token)
                if email:
                    log(f"✉️  Email from Bearer token: {email}")
                    # Track and check with EWMA IMMEDIATELY
                    is_allowed = self.track_and_check_activity(email, 'downloadCount')
                    if not is_allowed:
                        log(f"🚫 Download BLOCKED for {email}")
                        flow.response = http.Response.make(
                            403,
                            b"Access Denied: Suspicious download pattern detected",
                            {"Content-Type": "text/plain"}
                        )
                        return
                    self.stats['activities_tracked'] += 1
                    return  # Download allowed, continue
            
            # For browser downloads (no token, uses cookies), extract email from cookies
            if flow.request.pretty_host == 'drive.usercontent.google.com':
                log(f"📥 Browser download detected - extracting email from cookies")
                
                # Extract cookies from request
                cookies_data = self.extract_cookies_from_request(flow)
                
                if cookies_data:
                    log(f"🍪 Found cookies: {list(cookies_data.keys())}")
                    
                    # Look up email using cookies
                    email = self.get_email_from_cookies(cookies_data)
                    
                    if email:
                        log(f"✉️  Email from cookies: {email}")
                        
                        # Track and check with EWMA IMMEDIATELY IN REQUEST PHASE
                        is_allowed = self.track_and_check_activity(email, 'downloadCount')
                        
                        if not is_allowed:
                            log(f"🚫 Download BLOCKED for {email}")
                            flow.response = http.Response.make(
                                403,
                                b"Access Denied: Suspicious download pattern detected",
                                {"Content-Type": "text/plain"}
                            )
                            return
                        
                        log(f"✅ Download ALLOWED for {email}")
                        self.stats['activities_tracked'] += 1
                    else:
                        log(f"⚠️  No user found for cookies - allowing download by default")
                else:
                    log(f"⚠️  No cookies found - allowing download by default")
                
                return  # Download processed (allowed or blocked)
        
        # Check if this is a browser deletion request
        elif activity_type == 'deleteCount' and not self.extract_bearer_token(flow.request.headers):
            # Browser deletion - handle in response phase
            self.handle_deletion_request(flow)
            return
        # ===== HANDLE FILE ACCESS (PERMISSION CHECK) =====
        elif activity_type == 'permissionCheck':
            log(f"🔍 Permission check request detected")
            
            # Extract file ID from request
            file_id = self.extract_file_id_from_request(flow)
            if not file_id:
                log(f"⚠️  Could not extract file ID - allowing by default")
                return
            
            # Get email
            token = self.extract_bearer_token(flow.request.headers)
            email = None
            
            if token:
                email = self.get_email_for_api_request(token)
            else:
                cookies_data = self.extract_cookies_from_request(flow)
                if cookies_data:
                    email = self.get_email_from_cookies(cookies_data)
            
            if not email:
                log(f"⚠️  Could not identify user - blocking by default")
                flow.response = http.Response.make(
                    401,
                    blocked_html.encode('utf-8'),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                return
            
            # Check permission (with caching)
            has_permission = self.check_file_permission(email, file_id, use_cache=True)
            
            if not has_permission:
                # BLOCK permission check for unauthorized users
                log(f"🚫 #1 Permission check BLOCKED: {email} → File {file_id}")
                accept_header = flow.request.headers.get("accept", "").lower()
                
                if "application/json" in accept_header or "/json" in accept_header:
                    # Return JSON error for API clients
                    flow.response = http.Response.make(
                        403,
                        json.dumps({
                            "error": {
                                "code": 403,
                                "message": "Permission denied",
                                "status": "PERMISSION_DENIED"
                            }
                        }).encode(),
                        {"Content-Type": "application/json"}
                    )
                else:
                    flow.response = http.Response.make(
                        403,
                        blocked_html.encode('utf-8'),
                        {"Content-Type": "text/html; charset=utf-8"}
                    )
                return
            else:
                log(f"✅ Permission check ALLOWED for {email}")
                return
        elif activity_type == 'unsharedAccess':
            log(f"📂 File access request detected - checking permissions")
            
            # Extract file ID from request
            file_id = self.extract_file_id_from_request(flow)
            if not file_id:
                log(f"⚠️  Could not extract file ID - allowing by default")
                return  # Can't determine file, allow request
            
            # For API requests (with Bearer token)
            token = self.extract_bearer_token(flow.request.headers)
            email = None
            
            if token:
                # API request - get email from token
                email = self.get_email_for_api_request(token)
                log(f"🔑 API request - Email: {email}")
            else:
                # Browser request - get email from cookies
                cookies_data = self.extract_cookies_from_request(flow)
                if cookies_data:
                    email = self.get_email_from_cookies(cookies_data)
                    log(f"🍪 Browser request - Email: {email}")
            
            if not email:
                log(f"⚠️  Could not identify user - allowing by default")
                return  # Can't identify user, allow request
            
            # Check if user has permission to access this file
            has_permission = self.check_file_permission(email, file_id)
            
            if not has_permission:
                # BLOCK unauthorized access
                log(f"🚨 Unauthorized access attempt detected!")
                log(f"📊 EWMA Tracking: {email} → unsharedAccess")
                if EWMA_AVAILABLE:
                    update_user_activity_ewma(email, 'unsharedAccess')
                    self.add_blocked_user(email, 'unsharedAccess')
                log(f"#2 🚫 UNAUTHORIZED ACCESS BLOCKED: {email} → File {file_id}")
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                flow.response = http.Response.make(
                    403,
                    blocked_html.encode('utf-8'),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                self.stats['unauthorized_access_blocked'] += 1
                self.stats['activities_tracked'] += 1
    
            else:
                log(f"✅ File access ALLOWED for {email}")
        # Check if this is an API request (has Bearer token)
        token = self.extract_bearer_token(flow.request.headers)
        
        if token:
            # ===== API REQUEST =====
            log(f"🔑 API Request detected (Bearer token present)")
            
            # Get email from token
            email = self.get_email_for_api_request(token)
            if not email:
                log(f"⚠️  Could not identify user from token")
                  # Can't identify user, allow request
            
            if not activity_type:
                log(f"ℹ️  No tracked activity detected")
                  # Not a tracked activity
            
            log(f"🎯 Activity detected: {activity_type}")
            
            # Track and check with EWMA
            is_allowed = self.track_and_check_activity(email, activity_type)
            
            if not is_allowed:
                # Block the request
                log(f"🚫 Request BLOCKED")
                flow.response = http.Response.make(
                    403,
                    b"Access Denied: Suspicious activity pattern detected",
                    {"Content-Type": "text/plain"}
                )
                return
            
            self.stats['activities_tracked'] += 1
    
    # ========================================================================
    # RESPONSE HANDLER
    # ========================================================================
    
    def response(self, flow: http.HTTPFlow):
        """
        Main response handler.
        Handles browser requests (extract email from response, do EWMA check).
        Also handles authentication responses to populate UserCookies.
        """
        # Handle authentication responses (for any host)
        self.handle_auth_response(flow)
        
        # Only process Google Drive requests for activity tracking
        if not self.is_google_drive_request(flow):
            return        
        
        # ===== HANDLE DELETION RESPONSES =====
        request_hash = self.get_request_hash(flow.request)
        if request_hash not in self.pending_deletions:
            return
        
        log(f"\n{'='*80}")
        log(f"📬 RESPONSE for deletion request (Hash: {request_hash[:8]})")
        
        # Extract email from response
        if not flow.response or not flow.response.text:
            log(f"⚠️  No response text available")
            return
        
        # LOG THE RESPONSE CONTENT FOR DEBUGGING
        log(f"📄 Response content (first 2000 chars):")
        log(f"{flow.response.text[:2000]}")
        log(f"{'='*80}")
        
        email = self.extract_email_from_response(flow.response.text)
        if not email:
            log(f"⚠️  Could not extract email from deletion response")
            return
        
        log(f"✉️  Email extracted: {email}")
        
        # Track deletion activity with EWMA
        is_allowed = self.track_and_check_activity(email, 'deleteCount')
        
        # Get the original deletion data
        deletion_data = self.pending_deletions[request_hash]
        
        if is_allowed:
            # Activity is allowed - schedule actual deletion after 20 seconds
            log(f"⏰ Scheduling deletion for {email} in 20 seconds...")
            self.schedule_actual_deletion(deletion_data)
        else:
            # Activity is blocked - do NOT schedule deletion
            log(f"🚫 Deletion BLOCKED for {email} - file will NOT be deleted")
            self.stats['deletions_blocked'] += 1
        
        # Remove from pending
        del self.pending_deletions[request_hash]
        
        self.stats['activities_tracked'] += 1
    
    # ========================================================================
    # LIFECYCLE METHODS
    # ========================================================================
    
    def done(self):
        """Called when proxy is shutting down."""
        log("\n" + "="*80)
        log("🔴 EWMA Proxy Shutting Down")
        log("="*80)
        log(f"📊 Statistics:")
        log(f"   🗑️  Deletions intercepted: {self.stats['deletions_intercepted']}")
        log(f"   🚫 Deletions blocked: {self.stats['deletions_blocked']}")
        log(f"   📥 Downloads detected: {self.stats['downloads_detected']}")
        log(f"   🔒 Unauthorized access blocked: {self.stats.get('unauthorized_access_blocked', 0)}")
        log(f"   📊 Activities tracked: {self.stats['activities_tracked']}")
        log(f"   🚨 Requests blocked: {self.stats['requests_blocked']}")
        log("="*80)
        
        # Close MongoDB connection
        if self.mongo_client is not None:
            self.mongo_client.close()
            log("💾 MongoDB connection closed")


# ============================================================================
# MITMPROXY ADDON INTERFACE
# ============================================================================

# Create global instance
proxy = EWMAProxy()

# Export hooks for mitmproxy
def request(flow: http.HTTPFlow):
    """mitmproxy request hook."""
    proxy.request(flow)

def response(flow: http.HTTPFlow):
    """mitmproxy response hook."""
    proxy.response(flow)

def done():
    """mitmproxy shutdown hook."""
    proxy.done()