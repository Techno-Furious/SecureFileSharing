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

# Import Slack/Jira notification utilities
try:
    from slack_jira_utils import notify_user_blocked
    SLACK_JIRA_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  WARNING: Slack/Jira utilities not found - {e}")
    SLACK_JIRA_AVAILABLE = False


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

# HTML for unauthorized access (unsharedAccess)
unauthorized_access_html = f"""
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

# HTML for sensitive file blocking (sensitiveCount)
sensitive_file_blocked_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Sensitive File Access Blocked</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 50px; text-align: center; background-color: #f5f5f5; }}
                        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        .blocked {{ color: #d32f2f; font-size: 28px; margin-bottom: 20px; font-weight: bold; }}
                        .icon {{ font-size: 64px; margin-bottom: 20px; }}
                        .reason {{ color: #666; font-size: 16px; margin-bottom: 15px; line-height: 1.5; }}
                        .timestamp {{ color: #999; font-size: 12px; margin-top: 20px; }}
                        .service {{ color: #1a73e8; font-weight: bold; }}
                        .alert {{ background: #ffebee; border: 1px solid #ef9a9a; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                        .details {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; font-size: 14px; color: #666; }}
                        hr {{ border: none; border-top: 1px solid #eee; margin: 20px 0; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">⚠️</div>
                        <div class="blocked"><span class="service">Sensitive File</span> Access Blocked</div>
                        <div class="alert">
                            <strong>High-Risk File Access Restricted</strong>
                        </div>
                        <div class="reason">This file has been classified as sensitive with a high security risk level.</div>
                        <div class="reason">Your access to sensitive files has been restricted due to suspicious activity patterns detected by the security system.</div>
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
            self.blocked_user_activities_collection = self.ewma_config_db['blockedUserActivities']
            self.initialize_blocked_users_document()
            log("✅ MongoDB connected successfully")
        except Exception as e:
            log(f"❌ MongoDB connection failed: {e}")
            self.collection = None
            self.user_cookies_collection = None
            self.file_activity_collection = None
            self.blocked_users_collection = None
            self.blocked_user_activities_collection = None
        
        # Token to email cache: {token: (email, timestamp)}
        self.token_cache = {}
        
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
        
        # Cache for sensitive file access detection (to prevent duplicate triggers)
        self.sensitive_file_cache = {}
        self.SENSITIVE_FILE_CACHE_TTL = 0  # 0 seconds cooldown for same file
        
        # Cache for activity logging deduplication (prevent logging same activity multiple times)
        self.activity_log_cache = {}
        self.ACTIVITY_LOG_CACHE_TTL = 5  # 5 seconds cooldown for same activity
        
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
    def log_blocked_user_activity(self, email: str, activity_type: str, file_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        """
        Log activity performed by a blocked user.
        Includes deduplication to prevent logging the same activity multiple times.
        
        Args:
            email: User email address
            activity_type: Activity type being attempted
            file_id: Optional file ID being accessed
            details: Optional additional details about the activity
        """
        if self.blocked_user_activities_collection is None or not email:
            return
        
        try:
            # Create a unique key for this activity to prevent duplicates
            cache_key = f"{email}:{activity_type}:{file_id or 'none'}:{int(time.time() / self.ACTIVITY_LOG_CACHE_TTL)}"
            
            # Check if we already logged this activity recently
            if cache_key in self.activity_log_cache:
                log(f"⏭️  Skipping duplicate activity log: {email} - {activity_type}")
                return
            
            # Mark this activity as logged
            self.activity_log_cache[cache_key] = time.time()
            
            # Clean up old cache entries (older than TTL)
            current_time = time.time()
            self.activity_log_cache = {
                k: v for k, v in self.activity_log_cache.items() 
                if current_time - v < self.ACTIVITY_LOG_CACHE_TTL * 2
            }
            
            activity_log = {
                'email': email,
                'activity_type': activity_type,
                'timestamp': datetime.now().isoformat(),
                'file_id': file_id,
                'details': details or {}
            }
            
            self.blocked_user_activities_collection.insert_one(activity_log)
            log(f"📝 Logged blocked user activity: {email} attempted {activity_type}")
            
        except Exception as e:
            log(f"❌ Failed to log blocked user activity: {e}")
    
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
                
                # Send notification to Slack and Jira
                if SLACK_JIRA_AVAILABLE:
                    try:
                        # Define wrapper function to capture exceptions in thread
                        def send_notification_wrapper():
                            try:
                                log(f"🚀 Starting notification thread for {email} - {activity_type}")
                                result = notify_user_blocked(email, activity_type, force=True)
                                log(f"✅ Notification completed: {result.get('message', 'Unknown')}")
                                if result.get('success'):
                                    log(f"   Jira: {result.get('jira_ticket', 'N/A')}")
                                    log(f"   Slack: {'✅' if result.get('slack_sent') else '❌'}")
                                    log(f"   Chart: {'✅' if result.get('chart_uploaded') else '❌'}")
                                else:
                                    log(f"❌ Notification failed: {result.get('message', 'Unknown error')}")
                            except Exception as thread_error:
                                log(f"❌ Exception in notification thread: {thread_error}")
                                import traceback
                                log(f"Stack trace: {traceback.format_exc()}")
                        
                        # Run notification in background thread to avoid blocking proxy
                        notification_thread = threading.Thread(
                            target=send_notification_wrapper,
                            daemon=True
                        )
                        notification_thread.start()
                        log(f"📤 Notification thread started for {email} - {activity_type}")
                    except Exception as notif_error:
                        log(f"⚠️  Failed to start notification thread: {notif_error}")
            
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
    
    def is_user_blocked(self, email: str, activity_type: Optional[str] = None) -> bool:
        """
        Check if user is currently blocked for any activity or a specific activity type.
        
        Args:
            email: User email address
            activity_type: Optional - specific activity to check ('sensitiveCount', 'unsharedAccess', 'downloadCount', 'deleteCount')
                          If None, checks if user is blocked in ANY activity type
        
        Returns True if user is blocked, False otherwise.
        """
        if self.blocked_users_collection is None or not email:
            return False
        
        try:
            # Get the blockedUsers document (there's only one)
            blocked_doc = self.blocked_users_collection.find_one()
            
            if not blocked_doc:
                return False
            
            # If checking for specific activity type
            if activity_type:
                blocked_list = blocked_doc.get(activity_type, [])
                is_blocked = email in blocked_list
                if is_blocked:
                    log(f"🚨 User {email} is BLOCKED for {activity_type}")
                return is_blocked
            
            # Check if user is in ANY blocked list
            activity_types = ['sensitiveCount', 'unsharedAccess', 'downloadCount', 'deleteCount']
            for act_type in activity_types:
                blocked_list = blocked_doc.get(act_type, [])
                if email in blocked_list:
                    log(f"🚨 User {email} is BLOCKED for {act_type}")
                    return True
            
            return False
            
        except Exception as e:
            log(f"❌ Error checking if user is blocked: {e}")
            return False
    
    def is_user_blocked_for_any_activity(self, email: str) -> bool:
        """
        Check if user is blocked for ANY activity type.
        This is used to determine if we should log all their activities.
        
        Args:
            email: User email address
        
        Returns True if user is blocked for any activity, False otherwise.
        """
        return self.is_user_blocked(email, activity_type=None)
    
    def get_file_risk_level(self, file_id: str) -> Optional[str]:
        """
        Get the risk level of a file from FileActivityLogs collection.
        Returns: 'low', 'medium', 'high', 'critical', or None if not found
        """
        if self.file_activity_collection is None or not file_id:
            return None
        
        try:
            file_doc = self.file_activity_collection.find_one({"file_id": file_id})
            if file_doc:
                risk_level = file_doc.get("current_risk_level", "low").lower()
                return risk_level
            return None
        except Exception as e:
            log(f"❌ Error getting file risk level: {e}")
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
        
        # 1. DOWNLOAD (downloadCount)
        # Pattern 1: File download from drive.usercontent.google.com
        if flow.request.pretty_host == 'drive.usercontent.google.com':
            if method == 'POST' and '/uc?id=' in path:
                log(f"📥 DOWNLOAD detected: {flow.request.pretty_url}")
                self.stats['downloads_detected'] += 1
                return 'downloadCount'
        
        # Pattern 2: API downloads with alt=media or export
        elif 'alt=media' in url or '/export' in path or 'exportlinks' in path:
            log(f"📥 DOWNLOAD detected (API): {flow.request.pretty_url}")
            self.stats['downloads_detected'] += 1
            return 'downloadCount'
        
        # Pattern 3: Generic download parameter
        elif method == 'GET' and 'download' in url:
            log(f"📥 DOWNLOAD detected (generic): {flow.request.pretty_url}")
            self.stats['downloads_detected'] += 1
            return 'downloadCount'
        
        # 3. SENSITIVE FILE ACCESS (sensitiveCount)
        # Check if file being accessed has high/critical risk level
        # First extract file_id from the request
        file_id = None
        
        # Pattern 1: /d/{fileId}/ in Google Docs URLs
        match = re.search(r'/d/([a-zA-Z0-9_-]{20,})', path)
        if match:
            file_id = match.group(1)
        
        # Pattern 2: /files/{fileId} in API URLs
        if not file_id:
            match = re.search(r'/files/([a-zA-Z0-9_-]{20,})', path)
            if match:
                file_id = match.group(1)
        
        # Pattern 3: ?id= or &id= parameter
        if not file_id:
            match = re.search(r'[?&]id=([a-zA-Z0-9_-]{20,})', url)
            if match:
                file_id = match.group(1)
        
        # If we have a file_id, check its risk level
        if file_id and self.file_activity_collection is not None and "uc?id" in path:
            try:
                # Check cache first to prevent duplicate detections
                cached = self.sensitive_file_cache.get(file_id)
                if cached:
                    risk_level, timestamp = cached
                    age = time.time() - timestamp
                    if age < self.SENSITIVE_FILE_CACHE_TTL:
                        # Recently detected, skip to avoid duplicate tracking
                        log(f"📦 Sensitive file cache hit: {file_id} (detected {age:.1f}s ago) - skipping")
                        return None  # Don't trigger sensitiveCount again
                
                # Use case-insensitive regex to match file_id
                file_doc = self.file_activity_collection.find_one({"file_id": {"$regex": f"^{file_id}$", "$options": "i"}})
                
                if file_doc:
                    current_risk_level = file_doc.get("current_risk_level", "").upper()
                    if current_risk_level in ["HIGH", "CRITICAL"]:
                        # Cache this detection
                        self.sensitive_file_cache[file_id] = (current_risk_level, time.time())
                        log(f"🔴 SENSITIVE FILE ACCESS detected - File has {current_risk_level} risk level")
                        return 'sensitiveCount'
            except Exception as e:
                log(f"⚠️  Error checking file risk level: {e}")
        
        # Permission checks (for monitoring, not for sensitiveCount)
        if '/permissions' in path:
            if method in ['GET', 'OPTIONS']:
                log(f"🔍 Permission CHECK detected (GET/OPTIONS): {path}")
                return 'permissionCheck'
        
        # 4. FILE ACCESS (unsharedAccess)
        if '/file/' in path:
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
        Handle deletion request to drivefrontend-pa.clients6.google.com/v1/items:update.
        1. Check payload to differentiate delete (0 at position 14) vs refresh (1 at position 14)
        2. Extract cookies and get user email
        3. Check if user is blocked for deleteCount
        4. If blocked, drop the request (don't forward)
        5. If not blocked, update EWMA score and allow
        Returns True if deletion request was processed (blocked or allowed).
        """
        # Check if this is the deletion endpoint
        if 'drivefrontend-pa.clients6.google.com' not in flow.request.pretty_host:
            return False
        
        if '/v1/items:update' not in flow.request.path:
            return False
        
        if flow.request.method != 'POST':
            return False
        
        # Check payload to differentiate delete vs refresh request
        try:
            payload = json.loads(flow.request.text)
            # Navigate to position 14 in the payload array structure
            # payload[0][0][14] should be 0 for delete, 1 for refresh
            if isinstance(payload, list) and len(payload) > 0:
                if isinstance(payload[0], list) and len(payload[0]) > 0:
                    if isinstance(payload[0][0], list) and len(payload[0][0]) > 14:
                        value_at_14 = payload[0][0][14]
                        
                        if value_at_14 == 1:
                            # This is a REFRESH request, not a delete - allow it to pass through
                            log(f"🔄 REFRESH REQUEST detected (position 14 = 1) - allowing without tracking")
                            return False  # Let it pass through normally
                        
                        if value_at_14 == 0:
                            # This is a DELETE request - proceed with blocking logic
                            log(f"🗑️  DELETE REQUEST detected (position 14 = 0)")
                        else:
                            # Unknown value at position 14
                            log(f"⚠️  Unknown value at position 14: {value_at_14} - treating as potential delete")
        except Exception as e:
            log(f"⚠️  Error parsing payload: {e} - proceeding with caution")
        
        log(f"🗑️  DELETION REQUEST DETECTED: {flow.request.pretty_url}")
        
        # Extract cookies from request
        cookies_data = self.extract_cookies_from_request(flow)
        
        if not cookies_data:
            log(f"⚠️  No cookies found in deletion request - allowing by default")
            return False
        
        # Get user email from cookies
        email = self.get_email_from_cookies(cookies_data)
        
        if not email:
            log(f"⚠️  Could not identify user from cookies - allowing by default")
            return False
        
        log(f"✉️  User identified: {email}")
        
        # Check if user is blocked for deleteCount
        is_blocked = self.is_user_blocked(email, activity_type='deleteCount')
        is_blocked_any = self.is_user_blocked_for_any_activity(email)
        
        if is_blocked:
            # User is blocked - DROP the request (don't forward it)
            log(f"🚫 DELETION BLOCKED: {email} is blocked for deleteCount")
            
            # Log this blocked activity
            self.log_blocked_user_activity(
                email=email,
                activity_type='deleteCount',
                file_id=None,
                details={'url': flow.request.pretty_url, 'method': flow.request.method, 'block_point': 'deletion_handler', 'status': 'blocked'}
            )
            
            flow.response = http.Response.make(
                403,
                b"Access Denied: Your account has been restricted from deleting files due to suspicious activity patterns.",
                {"Content-Type": "text/plain"}
            )
            self.stats['deletions_blocked'] += 1
            return True
        
        # If user is blocked for any other activity, log this attempt (even though it's allowed)
        if is_blocked_any and not is_blocked:
            log(f"📝 Logging activity for blocked user: {email} - deleteCount (allowed)")
            self.log_blocked_user_activity(
                email=email,
                activity_type='deleteCount',
                file_id=None,
                details={'url': flow.request.pretty_url, 'method': flow.request.method, 'block_point': 'deletion_handler', 'status': 'allowed'}
            )
        
        # User is NOT blocked - update EWMA score and allow the request to proceed
        log(f"📊 Updating EWMA score for {email} - deleteCount")
        is_allowed = self.track_and_check_activity(email, 'deleteCount')
        
        if not is_allowed:
            # EWMA flagged this as suspicious - BLOCK
            log(f"🚫 DELETION BLOCKED by EWMA: {email}")
            flow.response = http.Response.make(
                403,
                b"Access Denied: Suspicious deletion pattern detected.",
                {"Content-Type": "text/plain"}
            )
            self.stats['deletions_blocked'] += 1
            return True
        
        # Allow deletion - manually forward request WITHOUT going through proxy
        log(f"✅ Deletion ALLOWED for {email} - forwarding request (bypassing proxy)")
        
        try:
            # Create session that bypasses proxy completely
            session = requests.Session()
            session.trust_env = False  # Don't use proxy settings from environment
            session.proxies = {
                'http': None,
                'https': None,
                'no_proxy': '*'
            }  # Explicitly disable all proxies
            
            # Forward the request
            response = session.request(
                method=flow.request.method,
                url=flow.request.pretty_url,
                headers=dict(flow.request.headers),
                data=flow.request.content,
                timeout=30
            )
            
            # Return the response to the client
            flow.response = http.Response.make(
                response.status_code,
                response.content,
                dict(response.headers)
            )
            
            log(f"✅ Deletion forwarded successfully - Status: {response.status_code}")
            self.stats['deletions_intercepted'] += 1
            self.stats['activities_tracked'] += 1
            
        except Exception as e:
            log(f"❌ Error forwarding deletion request: {e}")
            flow.response = http.Response.make(
                500,
                b"Internal Error: Failed to process deletion request.",
                {"Content-Type": "text/plain"}
            )
        
        return True
    
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
        
        # ===== EARLY CHECK: Block users who are blocked for sensitiveCount from accessing high/critical files =====
        # Extract file ID first
        file_id = self.extract_file_id_from_request(flow)
        
        if file_id:
            # Get email from token or cookies
            token = self.extract_bearer_token(flow.request.headers)
            email = None
            
            if token:
                email = self.get_email_for_api_request(token)
            else:
                cookies_data = self.extract_cookies_from_request(flow)
                if cookies_data:
                    email = self.get_email_from_cookies(cookies_data)
            
            if email:
                # Check if user is blocked for sensitiveCount
                is_blocked_sensitive = self.is_user_blocked(email, activity_type='sensitiveCount')
                
                if is_blocked_sensitive:
                    # User is blocked for sensitiveCount - check file risk level
                    risk_level = self.get_file_risk_level(file_id)
                    log(f"🚨 BLOCKED USER (sensitiveCount) accessing file - Risk Level: {risk_level}")
                    
                    if risk_level in ['high', 'critical']:
                        log(f"🚫 BLOCKING ACCESS: {email} is blocked for sensitiveCount and file has {risk_level.upper()} risk")
                        
                        # Log this blocked activity (early check - before activity type detection)
                        self.log_blocked_user_activity(
                            email=email,
                            activity_type='sensitiveCount',
                            file_id=file_id,
                            details={
                                'url': flow.request.pretty_url,
                                'method': flow.request.method,
                                'risk_level': risk_level,
                                'block_point': 'early_check',
                                'status': 'blocked'
                            }
                        )
                        
                        flow.response = http.Response.make(
                            403,
                            sensitive_file_blocked_html.encode('utf-8'),
                            {"Content-Type": "text/html; charset=utf-8"}
                        )
                        self.stats['requests_blocked'] += 1
                        return
                    else:
                        log(f"✅ File has {risk_level or 'unknown'} risk - allowing access")
        
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
                    
                    # Check if user is already blocked
                    is_blocked = self.is_user_blocked(email, activity_type='downloadCount')
                    is_blocked_any = self.is_user_blocked_for_any_activity(email)
                    
                    if is_blocked:
                        log(f"🚫 Download BLOCKED: {email} is already blocked for downloadCount")
                        
                        # Log this blocked activity
                        self.log_blocked_user_activity(
                            email=email,
                            activity_type='downloadCount',
                            file_id=file_id,
                            details={'url': flow.request.pretty_url, 'method': flow.request.method, 'block_point': 'api_download', 'status': 'blocked'}
                        )
                        
                        flow.response = http.Response.make(
                            403,
                            b"Access Denied: Suspicious download pattern detected",
                            {"Content-Type": "text/plain"}
                        )
                        return
                    
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
                    
                    # If user is blocked for any other activity, log this attempt (even though it's allowed)
                    if is_blocked_any and not is_blocked:
                        log(f"📝 Logging activity for blocked user: {email} - downloadCount (allowed)")
                        self.log_blocked_user_activity(
                            email=email,
                            activity_type='downloadCount',
                            file_id=file_id,
                            details={'url': flow.request.pretty_url, 'method': flow.request.method, 'block_point': 'api_download', 'status': 'allowed'}
                        )
                    
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
                        
                        # Check if user is already blocked
                        is_blocked = self.is_user_blocked(email, activity_type='downloadCount')
                        is_blocked_any = self.is_user_blocked_for_any_activity(email)
                        
                        if is_blocked:
                            log(f"🚫 Download BLOCKED: {email} is already blocked for downloadCount")
                            
                            # Log this blocked activity
                            self.log_blocked_user_activity(
                                email=email,
                                activity_type='downloadCount',
                                file_id=file_id,
                                details={'url': flow.request.pretty_url, 'method': flow.request.method, 'block_point': 'browser_download', 'status': 'blocked'}
                            )
                            
                            flow.response = http.Response.make(
                                403,
                                b"Access Denied: Suspicious download pattern detected",
                                {"Content-Type": "text/plain"}
                            )
                            return
                        
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
                        
                        # If user is blocked for any other activity, log this attempt (even though it's allowed)
                        if is_blocked_any and not is_blocked:
                            log(f"📝 Logging activity for blocked user: {email} - downloadCount (allowed)")
                            self.log_blocked_user_activity(
                                email=email,
                                activity_type='downloadCount',
                                file_id=file_id,
                                details={'url': flow.request.pretty_url, 'method': flow.request.method, 'block_point': 'browser_download', 'status': 'allowed'}
                            )
                        
                        log(f"✅ Download ALLOWED for {email}")
                        self.stats['activities_tracked'] += 1
                    else:
                        log(f"⚠️  No user found for cookies - allowing download by default")
                else:
                    log(f"⚠️  No cookies found - allowing download by default")
                
                return  # Download processed (allowed or blocked)
        
        # ===== HANDLE DELETION REQUESTS =====
        # Check for deletion endpoint (drivefrontend-pa.clients6.google.com/v1/items:update)
        if self.handle_deletion_request(flow):
            return  # Deletion request processed (blocked or allowed)
        
        # ===== HANDLE SENSITIVE FILE ACCESS (EWMA TRACKING ONLY) =====
        elif activity_type == 'sensitiveCount':
            log(f"🔴 Sensitive file access detected - tracking with EWMA")
            
            # Extract file ID to check risk level
            file_id = self.extract_file_id_from_request(flow)
            
            # Get email from token or cookies
            token = self.extract_bearer_token(flow.request.headers)
            email = None
            
            if token:
                email = self.get_email_for_api_request(token)
                log(f"✉️  Email from Bearer token: {email}")
            else:
                cookies_data = self.extract_cookies_from_request(flow)
                if cookies_data:
                    email = self.get_email_from_cookies(cookies_data)
                    log(f"✉️  Email from cookies: {email}")
            
            if email:
                # FIRST: Check if user is blocked for sensitiveCount specifically and file is high/critical risk
                is_blocked = self.is_user_blocked(email, activity_type='sensitiveCount')  # Check ONLY for sensitiveCount
                is_blocked_any = self.is_user_blocked_for_any_activity(email)
                
                if is_blocked and file_id:
                    risk_level = self.get_file_risk_level(file_id)
                    log(f"🔍 User is BLOCKED for sensitiveCount - File risk level: {risk_level}")
                    
                    if risk_level in ['high', 'critical']:
                        log(f"🚫 BLOCKED USER (sensitiveCount) attempting to access {risk_level.upper()} risk file - ACCESS DENIED")
                        
                        # Log this blocked activity
                        self.log_blocked_user_activity(
                            email=email,
                            activity_type='sensitiveCount',
                            file_id=file_id,
                            details={
                                'url': flow.request.pretty_url,
                                'method': flow.request.method,
                                'risk_level': risk_level,
                                'block_point': 'sensitive_handler',
                                'status': 'blocked'
                            }
                        )
                        
                        flow.response = http.Response.make(
                            403,
                            sensitive_file_blocked_html.encode('utf-8'),
                            {"Content-Type": "text/html; charset=utf-8"}
                        )
                        self.stats['requests_blocked'] += 1
                        return
                    else:
                        log(f"✅ Blocked user (sensitiveCount) accessing {risk_level or 'unknown'} risk file - ALLOWED")
                
                # SECOND: Track with EWMA and check allowance
                log(f"📊 EWMA Tracking: {email} → sensitiveCount")
                is_allowed = self.track_and_check_activity(email, 'sensitiveCount')
                
                if not is_allowed:
                    log(f"🚫 Sensitive file access BLOCKED by EWMA for {email}")
                    
                    # Log this blocked activity (EWMA blocked)
                    risk_level = self.get_file_risk_level(file_id) if file_id else None
                    self.log_blocked_user_activity(
                        email=email,
                        activity_type='sensitiveCount',
                        file_id=file_id,
                        details={
                            'url': flow.request.pretty_url,
                            'method': flow.request.method,
                            'risk_level': risk_level,
                            'block_point': 'sensitive_handler_ewma',
                            'status': 'blocked'
                        }
                    )
                    
                    flow.response = http.Response.make(
                        403,
                        sensitive_file_blocked_html.encode('utf-8'),
                        {"Content-Type": "text/html; charset=utf-8"}
                    )
                    return
                
                # THIRD: Log for blocked users (other activities) - only if access was ACTUALLY allowed
                # If user is blocked for ANY activity, log this attempt
                # Only log as "allowed" if the user is NOT blocked for sensitiveCount (since we're in sensitiveCount handler)
                if is_blocked_any and not is_blocked:
                    # User is blocked for other activities but NOT for sensitiveCount, and access is allowed
                    log(f"📝 Logging activity for blocked user: {email} - sensitiveCount (allowed)")
                    risk_level = self.get_file_risk_level(file_id) if file_id else None
                    self.log_blocked_user_activity(
                        email=email,
                        activity_type='sensitiveCount',
                        file_id=file_id,
                        details={
                            'url': flow.request.pretty_url,
                            'method': flow.request.method,
                            'risk_level': risk_level,
                            'block_point': 'sensitive_handler',
                            'status': 'allowed'
                        }
                    )
                
                log(f"✅ Sensitive file access ALLOWED (tracked) for {email}")
                self.stats['activities_tracked'] += 1
            else:
                log(f"⚠️  Could not identify user - allowing by default")
            
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
                    unauthorized_access_html.encode('utf-8'),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                return
            
            # Check permission (with caching)
            has_permission = self.check_file_permission(email, file_id, use_cache=True)
            
            if not has_permission:
                # BLOCK permission check for unauthorized users
                log(f"🚫 #1 Permission check BLOCKED: {email} → File {file_id}")
                
                # Log this blocked activity
                self.log_blocked_user_activity(
                    email=email,
                    activity_type='unsharedAccess',
                    file_id=file_id,
                    details={
                        'url': flow.request.pretty_url,
                        'method': flow.request.method,
                        'reason': 'permission_check_failed',
                        'block_point': 'permission_check'
                    }
                )
                
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
                        unauthorized_access_html.encode('utf-8'),
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
            is_blocked_any = self.is_user_blocked_for_any_activity(email)
            
            if not has_permission:
                # User doesn't have permission - this is UNAUTHORIZED ACCESS
                log(f"🚨 Unauthorized access attempt detected! {email} trying to access file without permission")
                log(f"📊 EWMA Tracking: {email} → unsharedAccess")
                
                # Log this blocked activity
                self.log_blocked_user_activity(
                    email=email,
                    activity_type='unsharedAccess',
                    file_id=file_id,
                    details={
                        'url': flow.request.pretty_url,
                        'method': flow.request.method,
                        'block_point': 'unshared_access_handler',
                        'status': 'blocked'
                    }
                )
                
                # Track with EWMA and add to blocked list
                if EWMA_AVAILABLE:
                    update_user_activity_ewma(email, 'unsharedAccess')
                    self.add_blocked_user(email, 'unsharedAccess')
                
                log(f"🚫 UNAUTHORIZED ACCESS BLOCKED: {email} → File {file_id}")
                
                flow.response = http.Response.make(
                    403,
                    unauthorized_access_html.encode('utf-8'),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                self.stats['unauthorized_access_blocked'] += 1
                self.stats['activities_tracked'] += 1
                return
    
            else:
                # User HAS permission - allow access
                log(f"✅ File access ALLOWED for {email} (user has permission)")
                return
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