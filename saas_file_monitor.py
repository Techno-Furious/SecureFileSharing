# -*- coding: utf-8 -*-
import os
import csv
import requests
import json
import datetime
import ssl
import certifi
import hashlib
import re
import numpy as np
import smtplib
import sys
import logging
import logging.handlers
import time
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer
import logging
import logging.handlers
import time
import sys
# import slack_notify
import dropbox  # New import for Dropbox
from pymongo import MongoClient, errors  # MongoDB imports
from dotenv import load_dotenv


load_dotenv()

# Configure the logger
logger = logging.getLogger('SaaS_Monitoring')
logger.setLevel(logging.INFO)

# Configure the SysLogHandler
syslog_handler = logging.handlers.SysLogHandler(address=('127.0.0.1', 1514))
formatter = logging.Formatter('%(asctime)s %(name)s: %(message)s', datefmt='%b %d %H:%M:%S')
syslog_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(syslog_handler)

# **🔹 Load Embedding Model**
model = SentenceTransformer("all-MiniLM-L6-v2")

# **🔹 SSL Fix**
os.environ["SSL_CERT_FILE"] = certifi.where()
ssl_context = ssl.create_default_context(cafile=certifi.where())

# Configure proxy if needed - comment out if proxy is not needed
# os.environ['HTTP_PROXY'] = 'http://localhost:8001'  # Update with your actual proxy address
# os.environ['HTTPS_PROXY'] = 'http://localhost:8001'  # Use HTTP protocol for HTTPS requests


# **🔹 Configuration**
# Google Drive Configuration
SCOPES = ["https://www.googleapis.com/auth/drive"]
TOKEN_FILE = "token.json"  # Ensure this is properly configured
CREDENTIALS_FILE = "credentials.json"  # Replace with your actual credentials file

# Dropbox Configuration
DROPBOX_ACCESS_TOKEN = os.getenv('DROPBOX_ACCESS_TOKEN')
PINECONE_API_KEY = os.getenv('PINECONE_API_KEY') 
GDRIVE_INDEX_NAME = "drive-metadata-index"
DROPBOX_INDEX_NAME = "cloud-metadata-index"
LOG_FILE = "syslog_client.log"  # Log file for monitoring
ALERTS_FILE = "alerts_log.json"  # Store previously alerted changes
DROPBOX_ALERTS_FILE = "dropbox_alerts_log.json"  # Store Dropbox alerts

# Slack Config
SLACK_GDRIVE_CHANNEL = "#eventlog"
SLACK_DROPBOX_CHANNEL = "#all-sfs"
SLACK_TOKEN = os.getenv('SLACK_TOKEN')

# MongoDB Configuration
MONGO_URI = os.getenv('MONGODB_URI')
DB_NAME = "FileInfo"
COLLECTION_NAME = "FileActivityLogs"

# **🔹 Initialize Services**
# Initialize Pinecone for Google Drive
pc = Pinecone(api_key=PINECONE_API_KEY)
if GDRIVE_INDEX_NAME not in pc.list_indexes().names():
    pc.create_index(
        name=GDRIVE_INDEX_NAME,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
gdrive_index = pc.Index(GDRIVE_INDEX_NAME)

# Initialize Pinecone for Dropbox
if DROPBOX_INDEX_NAME not in pc.list_indexes().names():
    pc.create_index(
        name=DROPBOX_INDEX_NAME,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
dropbox_index = pc.Index(DROPBOX_INDEX_NAME)

# Initialize Dropbox client with proper scopes
dbx = dropbox.Dropbox(
    DROPBOX_ACCESS_TOKEN,
    scope=['files.metadata.read', 'sharing.read', 'files.content.read']
)

# Initialize MongoDB client
try:
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    # Create unique index on file_id (run once)
    try:
        collection.create_index("file_id", unique=True)
        print("[SUCCESS] MongoDB connected and unique index on 'file_id' created.")
    except errors.OperationFailure as e:
        print(f"[WARNING] Index creation skipped or failed: {e}")
except Exception as e:
    print(f"[ERROR] Failed to connect to MongoDB: {e}")
    mongo_client = None
    collection = None


def get_existing_record_from_db(file_id):
    """Get existing record from MongoDB for comparison."""
    try:
        if collection is None:
            return None
            
        existing_record = collection.find_one({"file_id": file_id})
        return existing_record
        
    except Exception as e:
        print(f"[ERROR] Failed to fetch existing record from MongoDB: {e}")
        return None


def should_insert_log(log_data, existing_record):
    """Determine if the log should be inserted based on comparison with existing data."""
    if existing_record is None:
        # No existing record, this is a new file
        return True
        
    # Get the latest event from history
    history = existing_record.get("history", [])
    if not history:
        return True
        
    latest_event = history[-1]
    current_details = log_data.get("details", {})
    
    # Compare timestamps - only insert if this is a newer event
    latest_timestamp = latest_event.get("timestamp", "")
    current_timestamp = current_details.get("timestamp", "")
    
    if current_timestamp <= latest_timestamp:
        print(f"[WARNING] Skipping log insert - event is not newer than existing: {current_timestamp} <= {latest_timestamp}")
        return False
        
    # For permission changes, we should generally allow them since each change is meaningful
    event_type = current_details.get("type")
    
    # Allow all new files, permission changes, and trash operations to be recorded
    if event_type in ["new_file", "changes", "permission_added", "permission_changed", "permission_removed", 
                      "file_trashed", "file_untrashed", "file_deleted"]:
        return True
        
    # For other types of changes, use stricter comparison
    if (latest_event.get("type") == current_details.get("type") and
        latest_event.get("details", {}) == current_details):
        print(f"[WARNING] Skipping log insert - duplicate event detected")
        return False
        
    return True


def insert_log_to_mongodb(log_data):
    """Insert log data into MongoDB with structured format after checking for changes."""
    try:
        if collection is None:
            print("MongoDB collection not available, skipping database insert")
            return False
            
        # Ensure log_data is a dictionary
        if not isinstance(log_data, dict):
            print(f"Log data is not a dictionary, skipping MongoDB insert: {type(log_data)}")
            return False
            
        # Check if this is a valid log entry with file_id
        if "file_id" not in log_data:
            print("Log entry missing file_id, skipping MongoDB insert")
            return False
            
        file_id = log_data["file_id"]
        
        # Get existing record to compare
        existing_record = get_existing_record_from_db(file_id)
        
        # Check if we should insert this log
        should_insert = should_insert_log(log_data, existing_record)
        if not should_insert:
            return False
            
        details = log_data.get("details", {})
        timestamp = details.get("timestamp", log_data.get("timestamp", datetime.datetime.now().isoformat()))

        # Get current permissions - prioritize from direct log_data, then from details
        current_permissions = []
        
        # Method 1: Check if permissions are directly in log_data (current state from Drive API)
        if log_data.get("permissions"):
            current_permissions = log_data.get("permissions", [])
            print(f"Using current permissions from log_data for {file_id}: {len(current_permissions)} permissions")
        
        # Method 2: Check if permissions are in details (for new_file type)
        elif details.get("permissions"):
            current_permissions = details.get("permissions", [])
            print(f"Using permissions from details for {file_id}: {len(current_permissions)} permissions")
        
        # Method 3: For changes without current permissions, preserve existing permissions
        elif existing_record and existing_record.get("permissions"):
            current_permissions = existing_record.get("permissions", [])
            print(f"Preserving existing permissions for {file_id}: {len(current_permissions)} permissions")
        
        # Method 4: Default to empty if no permissions found
        else:
            current_permissions = []
            print(f"No permissions available for {file_id}, using empty array")

        update_fields = {
            "file_name": log_data.get("file_name"),
            "owner": log_data.get("owner"),
            "permissions": current_permissions,
            "modified_by": details.get("modified_by", {"name": "Unknown", "email": "Unknown"}),
            "source": details.get("source", "google_drive"),
            "last_event_type": details.get("type"),
            "last_event_timestamp": timestamp,
        }

        history_entry = {
            "type": details.get("type"),
            "timestamp": timestamp,
            "details": details
        }

        # Upsert: update current fields and append to history
        result = collection.update_one(
            {"file_id": file_id},
            {
                "$set": update_fields,
                "$push": {"history": history_entry}
            },
            upsert=True
        )
        
        if result.upserted_id:
            print(f"[SUCCESS] New log record created in MongoDB for file_id: {file_id}")
        else:
            print(f"[SUCCESS] Log updated in MongoDB for file_id: {file_id}")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to insert log to MongoDB: {e}")
        return False


def log_event(message):
    """Save logs to a file, print them, and automatically insert to MongoDB."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} - SaaS_Monitor - {message}"
    print(log_message)  # Print to console

    try:
        # Write to syslog via logger
        if isinstance(message, dict):
            # Ensure the message is properly formatted as JSON
            json_str = json.dumps(message)
            logger.info(json_str)
        else:
            # If it's a string, log as is
            logger.info(message)

        # Force logger to flush its handlers
        for handler in logger.handlers:
            handler.flush()

        # Direct write fallback - ensure we get something in the log file
        try:
            if isinstance(message, dict):
                json_str = json.dumps(message)
                with open("syslog.log", "a", encoding="utf-8") as f:
                    f.write(json_str + "\n")
            else:
                with open("syslog.log", "a", encoding="utf-8") as f:
                    f.write(f"{message}\n")
        except Exception as e:
            print(f"Error writing directly to syslog.log: {e}")
            
        # **NEW: Automatically insert to MongoDB if it's a structured log entry**
        if isinstance(message, dict) and "file_id" in message:
            print(f"[INFO] Attempting MongoDB insertion for file_id: {message.get('file_id')}")
            insert_success = insert_log_to_mongodb(message)
            if insert_success:
                print(f"[SUCCESS] MongoDB insertion successful for file_id: {message.get('file_id')}")
            else:
                print(f"[ERROR] MongoDB insertion failed for file_id: {message.get('file_id')}")
        elif isinstance(message, dict):
            print(f"[INFO] Skipping MongoDB insertion - no file_id in message: {list(message.keys())}")
            
    except Exception as e:
        print(f"Error writing to syslog: {e}")


def load_alerts():
    """Load previously sent alerts to avoid duplicate notifications."""
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_alerts(alerts):
    """Save the updated alerts log."""
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def clean_vector(vector):
    """Ensure the vector is 384-dimensional and contains valid values."""
    vector = np.nan_to_num(vector, nan=0.0, posinf=1.0, neginf=-1.0)  # Replace invalid values
    if len(vector) != 384:
        print(f"Warning: Adjusting vector size from {len(vector)} to 384.")
        vector = np.pad(vector, (0, max(0, 384 - len(vector))), mode='constant')[:384]  # Trim or pad
    return vector.tolist()


def get_existing_metadata(file_id):
    """Fetch stored metadata & permissions from Pinecone."""
    try:
        fetched_vectors = gdrive_index.fetch(ids=[file_id])
        if file_id in fetched_vectors.vectors:
            metadata = fetched_vectors.vectors[file_id].metadata
            # Convert JSON strings back to objects
            for key, value in metadata.items():
                if isinstance(value, str):
                    try:
                        parsed = json.loads(value)
                        if isinstance(parsed, (dict, list)):
                            metadata[key] = parsed
                    except:
                        pass  # Keep as string if not valid JSON
            return metadata
    except Exception as e:
        log_event(f"Error fetching metadata from Pinecone: {e}")
    return None


def stream_file_content(file_id, service):
    """Stream and log the content of a file."""
    try:
        # Get the file metadata first to check if it's a text-based file
        file_metadata = service.files().get(
            fileId=file_id,
            fields='mimeType,name'
        ).execute()
        
        mime_type = file_metadata.get('mimeType', '')
        file_name = file_metadata.get('name', 'Unknown')
        
        # Only process text-based files
        text_mime_types = [
            'text/plain',
            'text/csv',
            'text/html',
            'text/xml',
            'application/json',
            'application/xml',
            'application/csv',
            'application/x-www-form-urlencoded'
        ]
        
        if mime_type in text_mime_types:
            # Request the file content
            request = service.files().get_media(fileId=file_id)
            file_content = request.execute()
            
            # Decode the content if it's bytes
            if isinstance(file_content, bytes):
                try:
                    file_content = file_content.decode('utf-8')
                except UnicodeDecodeError:
                    file_content = file_content.decode('latin-1')
            
            # Log the file content
            log_event({
                "type": "file_content",
                "file_id": file_id,
                "file_name": file_name,
                "mime_type": mime_type,
                "content": file_content,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            return True
        else:
            log_event(f"Skipping content logging for non-text file: {file_name} ({mime_type})")
            return False
            
    except Exception as e:
        log_event(f"Error streaming file content for {file_id}: {e}")
        return False

def get_file_modifier(file_id, service, is_trashed=False):
    """Simplified modifier detection for Google Drive files."""
    modifier_info = {"name": "Unknown", "email": "Unknown", "action": "unknown"}
    
    try:
        # Method 1: Get basic file metadata
        file_metadata = service.files().get(
            fileId=file_id,
            fields="lastModifyingUser,trashingUser,owners,sharingUser",
            supportsAllDrives=True
        ).execute()
        
        # For trashed files, prioritize trashingUser
        if is_trashed and file_metadata.get('trashingUser'):
            user = file_metadata['trashingUser']
            modifier_info = {
                "name": user.get('displayName', 'Unknown'),
                "email": user.get('emailAddress', 'Unknown'),
                "action": "trashed"
            }
            print(f"Found trashing user for {file_id}: {modifier_info['name']}")
            return modifier_info
        
        # Use lastModifyingUser if available
        if file_metadata.get('lastModifyingUser'):
            user = file_metadata['lastModifyingUser']
            modifier_info = {
                "name": user.get('displayName', 'Unknown'),
                "email": user.get('emailAddress', 'Unknown'),
                "action": "modified"
            }
            print(f"Found last modifying user for {file_id}: {modifier_info['name']}")
            return modifier_info
        
        # Use sharingUser for shared files
        if file_metadata.get('sharingUser'):
            user = file_metadata['sharingUser']
            modifier_info = {
                "name": user.get('displayName', 'Unknown'),
                "email": user.get('emailAddress', 'Unknown'),
                "action": "shared"
            }
            print(f"Found sharing user for {file_id}: {modifier_info['name']}")
            return modifier_info
        
        # Fallback to owner
        if file_metadata.get('owners') and len(file_metadata['owners']) > 0:
            owner = file_metadata['owners'][0]
            modifier_info = {
                "name": owner.get('displayName', 'Unknown'),
                "email": owner.get('emailAddress', 'Unknown'),
                "action": "owner_fallback"
            }
            print(f"Using owner as modifier for {file_id}: {modifier_info['name']}")
            return modifier_info
            
    except Exception as e:
        print(f"Error getting file modifier for {file_id}: {e}")
        
        # Method 2: Try revision history as fallback
        try:
            revisions = service.revisions().list(
                fileId=file_id,
                fields="revisions(lastModifyingUser,modifiedTime)",
                pageSize=1
            ).execute()
            
            if revisions.get('revisions'):
                revision = revisions['revisions'][0]
                if revision.get('lastModifyingUser'):
                    user = revision['lastModifyingUser']
                    modifier_info = {
                        "name": user.get('displayName', 'Unknown'),
                        "email": user.get('emailAddress', 'Unknown'),
                        "action": "revision_history"
                    }
                    print(f"Found modifier from revision history for {file_id}: {modifier_info['name']}")
                    return modifier_info
                    
        except Exception as e:
            print(f"Error getting revision history for {file_id}: {e}")
    
    print(f"Could not determine modifier for {file_id}, using Unknown")
    return modifier_info




def get_file_owner(file_id, service, permissions):
    """Enhanced owner detection for shared files."""
    # Method 1: Check permissions array first
    owner = next((p.get("emailAddress") for p in permissions if p.get("role") == "owner"), None)
    if owner and owner != "Unknown":
        return owner
    
    # Method 2: Try to get detailed file metadata
    try:
        detailed_file = service.files().get(
            fileId=file_id,
            fields="owners,permissions",
            supportsAllDrives=True
        ).execute()
        
        # Check owners field
        if detailed_file.get('owners'):
            owner_info = detailed_file['owners'][0]
            return owner_info.get('emailAddress', 'Unknown')
            
        # Check permissions from detailed call
        if detailed_file.get('permissions'):
            for perm in detailed_file['permissions']:
                if perm.get('role') == 'owner':
                    return perm.get('emailAddress', 'Unknown')
                    
    except Exception as e:
        print(f"Error getting detailed file info: {e}")
    
    # Method 3: For shared files, try to get sharing info
    try:
        # Sometimes the current user's permissions don't show the owner
        # but we can infer from other metadata
        file_metadata = service.files().get(
            fileId=file_id,
            fields="sharingUser,lastModifyingUser",
            supportsAllDrives=True
        ).execute()
        
        if file_metadata.get('sharingUser'):
            return file_metadata['sharingUser'].get('emailAddress', 'Unknown')
            
    except Exception as e:
        print(f"Error getting sharing info: {e}")
    
    return "Unknown"


def fix_unknown_owners():
    """Fix existing MongoDB records with unknown owners."""
    if collection is None:
        print("MongoDB not available")
        return
        
    # Find records with unknown owners
    unknown_owner_records = collection.find({"owner": "Unknown"})
    
    for record in unknown_owner_records:
        file_id = record.get("file_id")
        if not file_id:
            continue
            
        try:
            if os.path.exists("token.json"):
                creds = Credentials.from_authorized_user_file("token.json", SCOPES)
            # Try to get current file information
            service = build("drive", "v3", credentials=creds)  # You'll need to pass creds
            
            file_info = service.files().get(
                fileId=file_id,
                fields="owners,permissions",
                supportsAllDrives=True
            ).execute()
            
            owner_email = "Unknown"
            
            # Check owners field
            if file_info.get('owners'):
                owner_email = file_info['owners'][0].get('emailAddress', 'Unknown')
            
            # Check permissions
            elif file_info.get('permissions'):
                for perm in file_info['permissions']:
                    if perm.get('role') == 'owner':
                        owner_email = perm.get('emailAddress', 'Unknown')
                        break
            
            if owner_email != "Unknown":
                # Update the record
                collection.update_one(
                    {"file_id": file_id},
                    {"$set": {"owner": owner_email}}
                )
                print(f"Updated owner for {file_id}: {owner_email}")
                
        except Exception as e:
            print(f"Error fixing owner for {file_id}: {e}")


def process_drive_file(file, service):
    """Process a single drive file with enhanced owner detection."""
    try:
        file_id = file.get('id')
        if not file_id:
            return

        metadata = {
            'id': file_id,
            'name': file.get('name', 'Unknown'),
            'mimeType': file.get('mimeType', 'Unknown'),
            'permissions': file.get('permissions', []),
            'trashed': file.get('trashed', False)
        }

        # Enhanced owner detection
        owner_email = get_file_owner(file_id, service, metadata['permissions'])
        
        # Get modifier information
        modifier_info = get_file_modifier(file_id, service, metadata.get('trashed', False))
        
        changes = detect_change(file_id, metadata, service)
        if changes:
            if changes.get('type') == 'new_file':
                stream_file_content(file_id, service)
                
            # Ensure modifier_info is included in the log
            if 'modified_by' not in changes:
                changes['modified_by'] = modifier_info
                
            log_event({
                "file_id": file_id,
                "file_name": metadata.get("name", "Unknown"),
                "owner": owner_email,
                "permissions": metadata.get("permissions", []),
                "details": changes,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    except Exception as e:
        log_event(f"Error processing file {file.get('id', 'Unknown')}: {e}")

def calculate_metadata_hash(metadata):
    """Calculate a hash of the metadata to detect changes."""
    relevant_data = {
        "name": metadata.get("name"),
        "permissions": sorted([
            (p.get("emailAddress", ""), p.get("role", ""))
            for p in metadata.get("permissions", [])
        ])
    }
    return hashlib.md5(json.dumps(relevant_data, sort_keys=True).encode()).hexdigest()


def sanitize_metadata(metadata):
    """Convert complex metadata to simple types for Pinecone."""
    sanitized = {}
    for key, value in metadata.items():
        if isinstance(value, (str, int, float, bool)):
            sanitized[key] = value
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            sanitized[key] = value
        else:
            # Convert complex objects to JSON string
            sanitized[key] = json.dumps(value)
    return sanitized


def detect_change(file_id, new_metadata, service):
    """Detects metadata changes and sends alerts only for new changes."""
    try:
        existing_metadata = get_existing_metadata(file_id)
        if existing_metadata and not isinstance(existing_metadata, dict):
            log_event(f"Invalid metadata format for {file_id}")
            existing_metadata = None

        new_hash = calculate_metadata_hash(new_metadata)

        # Load alerts
        alerts = load_alerts()
        alert_key = f"{file_id}"

        # Check if this exact state was already processed
        if alert_key in alerts and alerts[alert_key] == new_hash:
            return None

        # Get the user who made the change using simplified method
        is_trashed = new_metadata.get('trashed', False)
        modifier_info = get_file_modifier(file_id, service, is_trashed)
        
        try:
            # Enhanced modifier detection - try multiple methods for better accuracy
            
            # Method 1: Try to get detailed file metadata with more fields
            try:
                detailed_file = service.files().get(
                    fileId=file_id,
                    fields="lastModifyingUser,sharingUser,trashingUser,owners,createdTime,modifiedTime",
                    supportsAllDrives=True
                ).execute()
                
                # For trashed files, try trashingUser first
                if new_metadata.get('trashed', False) and detailed_file.get('trashingUser'):
                    modifier_info = {
                        "name": detailed_file['trashingUser'].get('displayName', 'Unknown'),
                        "email": detailed_file['trashingUser'].get('emailAddress', 'Unknown'),
                        "action": "trashed"
                    }
                    log_event(f"Found trashing user for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                
                # For permission changes, use sharingUser if available
                elif detailed_file.get('sharingUser'):
                    modifier_info = {
                        "name": detailed_file['sharingUser'].get('displayName', 'Unknown'),
                        "email": detailed_file['sharingUser'].get('emailAddress', 'Unknown'),
                        "action": "shared"
                    }
                    log_event(f"Found sharing user for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                
                # For other changes, use lastModifyingUser
                elif detailed_file.get('lastModifyingUser'):
                    modifier_info = {
                        "name": detailed_file['lastModifyingUser'].get('displayName', 'Unknown'),
                        "email": detailed_file['lastModifyingUser'].get('emailAddress', 'Unknown'),
                        "action": "modified"
                    }
                    log_event(f"Found last modifying user for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                
                # If still unknown, try the file owner
                elif detailed_file.get('owners') and len(detailed_file['owners']) > 0:
                    owner = detailed_file['owners'][0]
                    modifier_info = {
                        "name": owner.get('displayName', 'Unknown'),
                        "email": owner.get('emailAddress', 'Unknown'),
                        "action": "owner_fallback"
                    }
                    log_event(f"Using file owner as modifier for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                    
            except Exception as e:
                log_event(f"Error getting detailed file metadata for {file_id}: {e}")
            
            # Method 2: If still unknown, try revision history with more details
            if modifier_info["name"] == "Unknown":
                try:
                    revision = service.revisions().list(
                        fileId=file_id,
                        fields="revisions(lastModifyingUser,modifiedTime)",
                        pageSize=5  # Get more recent revisions
                    ).execute()
                    
                    if revision.get('revisions'):
                        for rev in revision['revisions']:
                            if rev.get('lastModifyingUser'):
                                last_modifier = rev['lastModifyingUser']
                                modifier_info = {
                                    "name": last_modifier.get('displayName', 'Unknown'),
                                    "email": last_modifier.get('emailAddress', 'Unknown'),
                                    "action": "revision_history",
                                    "revision_time": rev.get('modifiedTime', 'Unknown')
                                }
                                log_event(f"Found modifier from revision history for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                                break
                                
                except Exception as e:
                    log_event(f"Error getting revision history for {file_id}: {e}")
            
            # Method 3: For deleted files, try to get info from existing_metadata 
            if modifier_info["name"] == "Unknown" and existing_metadata:
                try:
                    # Look for recent permission changes in existing metadata
                    if existing_metadata.get("permissions"):
                        recent_modifier = None
                        for perm in existing_metadata["permissions"]:
                            if perm.get("emailAddress") and perm.get("displayName"):
                                recent_modifier = {
                                    "name": perm.get("displayName", "Unknown"),
                                    "email": perm.get("emailAddress", "Unknown"),
                                    "action": "inferred_from_permissions"
                                }
                                break
                        
                        if recent_modifier:
                            modifier_info = recent_modifier
                            log_event(f"Inferred modifier from existing permissions for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                            
                except Exception as e:
                    log_event(f"Error inferring modifier from existing metadata for {file_id}: {e}")
            
            # Method 4: Try getting activity/changes from Drive Activity API (if available)
            # Note: This would require additional API permissions, so keeping as a fallback
            if modifier_info["name"] == "Unknown":
                try:
                    # Try to get the file's current permissions to find an active user
                    current_file = service.files().get(
                        fileId=file_id,
                        fields="permissions",
                        supportsAllDrives=True
                    ).execute()
                    
                    if current_file.get('permissions'):
                        for perm in current_file['permissions']:
                            if perm.get('role') == 'owner' and perm.get('emailAddress'):
                                modifier_info = {
                                    "name": perm.get('displayName', 'Unknown'),
                                    "email": perm.get('emailAddress', 'Unknown'),
                                    "action": "file_owner"
                                }
                                log_event(f"Using current file owner as modifier for {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                                break
                                
                except Exception as e:
                    log_event(f"Error getting current file permissions for {file_id}: {e}")
                    
        except Exception as e:
            log_event(f"Error in enhanced modifier detection for {file_id}: {e}")
            modifier_info = {
                "name": "Unknown",
                "email": "Unknown",
                "action": "error"
            }

        # Prepare change details for other changes
        if not existing_metadata:
            # Check if this is a trashed file being discovered for the first time
            if new_metadata.get('trashed', False):
                change_details = {
                    "type": "file_trashed",
                    "file_name": new_metadata.get("name", "Unknown"),
                    "owner": next((p.get("emailAddress") for p in new_metadata.get("permissions", [])
                                   if p.get("role") == "owner"), "Unknown"),
                    "permissions": new_metadata.get("permissions", []),
                    "modified_by": modifier_info,
                    "source": "google_drive",
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                change_details = {
                    "type": "new_file",
                    "file_name": new_metadata.get("name", "Unknown"),
                    "owner": next((p.get("emailAddress") for p in new_metadata.get("permissions", [])
                                   if p.get("role") == "owner"), "Unknown"),
                    "permissions": new_metadata.get("permissions", []),
                    "modified_by": modifier_info,
                    "source": "google_drive",  # Mark the source as Google Drive
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
        else:
            changes = []

            # Check if file was trashed or untrashed
            old_trashed = existing_metadata.get("trashed", False)
            new_trashed = new_metadata.get("trashed", False)
            
            if old_trashed != new_trashed:
                if new_trashed:
                    changes.append({
                        "type": "file_trashed",
                        "file_name": new_metadata.get("name", "Unknown"),
                        "modified_by": modifier_info
                    })
                else:
                    changes.append({
                        "type": "file_untrashed",
                        "file_name": new_metadata.get("name", "Unknown"),
                        "modified_by": modifier_info
                    })

            # Check name changes
            if existing_metadata.get("name") != new_metadata.get("name"):
                changes.append({
                    "type": "name_change",
                    "old": existing_metadata.get("name"),
                    "new": new_metadata.get("name"),
                    "modified_by": modifier_info
                })

            # Check permission changes
            old_perms = {p.get("emailAddress"): p for p in existing_metadata.get("permissions", [])}
            new_perms = {p.get("emailAddress"): p for p in new_metadata.get("permissions", [])}

            for email, perm in new_perms.items():
                if email not in old_perms:
                    changes.append({
                        "type": "permission_added",
                        "user": email,
                        "user_name": perm.get("displayName", "Unknown"),
                        "role": perm.get("role"),
                        "modified_by": modifier_info
                    })
                elif old_perms[email].get("role") != perm.get("role"):
                    changes.append({
                        "type": "permission_changed",
                        "user": email,
                        "user_name": perm.get("displayName", "Unknown"),
                        "old_role": old_perms[email].get("role"),
                        "new_role": perm.get("role"),
                        "modified_by": modifier_info
                    })

            for email, perm in old_perms.items():
                if email not in new_perms:
                    changes.append({
                        "type": "permission_removed",
                        "user": email,
                        "user_name": perm.get("displayName", "Unknown"),
                        "role": perm.get("role"),
                        "modified_by": modifier_info
                    })

            if not changes:
                return None

            change_details = {
                "type": "changes",
                "file_name": new_metadata.get("name", "Unknown"),
                "owner": next((p.get("emailAddress") for p in new_metadata.get("permissions", [])
                               if p.get("role") == "owner"), "Unknown"),
                "changes": changes,
                # "modified_by": modifier_info,
                # "source": "google_drive",  # Mark the source as Google Drive
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # Update alerts with new hash
        alerts[alert_key] = new_hash
        save_alerts(alerts)

        # Store the new metadata in Pinecone
        try:
            # Create a vector of 384 dimensions with small random values
            vector = [float(0.1) for _ in range(384)]

            # Sanitized metadata for Pinecone
            sanitized_metadata = sanitize_metadata(new_metadata)

            gdrive_index.upsert(vectors=[{
                "id": file_id,
                "metadata": sanitized_metadata,
                "values": vector
            }])
        except Exception as e:
            log_event(f"Error updating Pinecone: {e}")

        # Send email alert (but don't log here - let process_drive_file handle logging)
        try:
            send_email_alert(file_id, change_details)
        except Exception as e:
            log_event(f"Failed to send email alert: {e}")

        return change_details

    except Exception as e:
        log_event(f"Error in detect_change: {e}")
        return None


def send_email_alert(file_id, change_details):
    """Send email alert for changes."""
    try:
        # For testing, we'll just log the email content
        sender = "your-email@gmail.com"
        receivers = ["admin@example.com"]

        # Get modifier information
        modifier = change_details.get("modified_by", {})
        modifier_text = f"{modifier.get('name', 'Unknown')}"
        if modifier.get('email') and modifier.get('email') != "Unknown":
            modifier_text += f" ({modifier.get('email')})"

        # Identify the source (Google Drive or Dropbox)
        source = change_details.get("source", "google_drive")
        source_display = "Google Drive" if source == "google_drive" else "Dropbox"

        # Create a more detailed message
        if change_details["type"] == "new_file":
            subject = f"New {source_display} file detected: {change_details['file_name']}"
            body = [
                f"New {source_display} file '{change_details['file_name']}' was created by {modifier_text}",
                f"Owner: {change_details['owner']}",
                "\nInitial permissions:"
            ]
            for perm in change_details.get("permissions", []):
                body.append(f"- {perm.get('displayName', 'Unknown')} ({perm.get('emailAddress')}): {perm.get('role')}")
        elif change_details["type"] == "file_trashed":
            subject = f"{source_display} file moved to trash: {change_details['file_name']}"
            body = [
                f"{source_display} file '{change_details['file_name']}' was moved to trash by {modifier_text}",
                f"Owner: {change_details.get('owner', 'Unknown')}",
                f"File ID: {file_id}"
            ]
            # Add modifier action details if available
            modifier_action = modifier.get('action', '')
            if modifier_action and modifier_action != 'error':
                body.append(f"Detection method: {modifier_action}")
        elif change_details["type"] == "file_deleted":
            subject = f"{source_display} file deleted: {change_details['file_name']}"
            body = [
                f"{source_display} file '{change_details['file_name']}' was deleted",
                f"Previous owner: {change_details['owner']}",
                f"File ID: {file_id}"
            ]
            if modifier_text != "Unknown":
                body.insert(1, f"Deleted by: {modifier_text}")
                # Add modifier action details if available
                modifier_action = modifier.get('action', '')
                if modifier_action and modifier_action != 'error':
                    body.append(f"Detection method: {modifier_action}")
        else:
            subject = f"Changes detected in {source_display} file: {change_details['file_name']}"
            body = [f"The following changes were detected in {source_display} file '{change_details['file_name']}':"]

            for change in change_details.get("changes", []):
                change_modifier = change.get("modified_by", {})
                change_modifier_text = f"{change_modifier.get('name', 'Unknown')}"
                if change_modifier.get('email') and change_modifier.get('email') != "Unknown":
                    change_modifier_text += f" ({change_modifier.get('email')})"

                if change["type"] == "name_change":
                    body.append(f"- File renamed from '{change['old']}' to '{change['new']}' by {change_modifier_text}")
                elif change["type"] == "file_trashed":
                    body.append(f"- File moved to trash by {change_modifier_text}")
                elif change["type"] == "file_untrashed":
                    body.append(f"- File restored from trash by {change_modifier_text}")
                elif change["type"] == "permission_added":
                    body.append(
                        f"- {change_modifier_text} added {change['role']} permission for {change['user_name']} ({change['user']})")
                elif change["type"] == "permission_removed":
                    body.append(
                        f"- {change_modifier_text} removed permission for {change['user_name']} ({change['user']})")
                elif change["type"] == "permission_changed":
                    body.append(
                        f"- {change_modifier_text} changed {change['user_name']} ({change['user']})'s role from {change['old_role']} to {change['new_role']}")

        body.append(f"\nTimestamp: {change_details['timestamp']}")
        body.append(f"File ID: {file_id}")

        # For now, just log the email content instead of sending
        email_content = f"Would send email:\nSubject: {subject}\nBody:\n" + "\n".join(body)
        log_event(email_content)

        # Create a more concise Slack message
        # slack_message = f"*{subject}*\n"
        # if change_details["type"] == "changes":
        #     slack_message += "Changes made:\n"
        #     for line in body[1:]:  # Skip the first line as it's redundant with the subject
        #         if line.startswith("-"):  # Only include the change lines
        #             slack_message += f"{line}\n"
        # else:
        #     slack_message += "\n".join(body)

        # # Send to Slack - use different channels based on source
        # channel = SLACK_GDRIVE_CHANNEL if source == "google_drive" else SLACK_DROPBOX_CHANNEL
        # slack_notify.send_slack_message(
        #     SLACK_TOKEN,
        #     channel,
        #     slack_message
        # )

    except Exception as e:
        log_event(f"Failed to prepare email alert: {str(e)}")


def test_logging():
    """Test function for logging functionality."""
    print("=== Testing Logging Functionality ===")
    
    # Test simple string log
    log_event("Testing logging functionality")
    
    # Test JSON log without file_id
    log_event({
        "test": "Sample JSON log entry",
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    # Test JSON log with file_id (this should trigger MongoDB insertion)
    test_file_log = {
        "file_id": "test_file_123",
        "file_name": "test_document.pdf",
        "owner": {
            "name": "Test User",
            "email": "test@example.com"
        },
        "details": {
            "type": "new_file",
            "source": "test_system",
            "permissions": [
                {
                    "emailAddress": "test@example.com",
                    "role": "owner",
                    "displayName": "Test User"
                }
            ],
            "modified_by": {
                "name": "Test User",
                "email": "test@example.com"
            },
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print("\n=== Testing MongoDB insertion with sample file log ===")
    log_event(test_file_log)
    
    print("\n=== Logging test completed ===")


def test_permissions_update_logging():
    """Test function to verify that permissions are properly updated in MongoDB."""
    print("=== Testing Permissions Update in MongoDB ===")
    
    file_id = "test_permissions_update_" + str(int(datetime.datetime.now().timestamp()))
    
    # Test 1: Create a new file with initial permissions
    initial_permissions = [
        {
            "emailAddress": "owner@example.com",
            "role": "owner", 
            "displayName": "File Owner",
            "id": "owner123"
        },
        {
            "emailAddress": "user1@example.com",
            "role": "writer",
            "displayName": "User One", 
            "id": "user123"
        }
    ]
    
    initial_log = {
        "file_id": file_id,
        "file_name": "test_permissions_file.docx",
        "owner": "owner@example.com",
        "permissions": initial_permissions,  # Include current permissions
        "details": {
            "type": "new_file",
            "source": "google_drive",
            "permissions": initial_permissions,
            "modified_by": {
                "name": "File Owner",
                "email": "owner@example.com"
            },
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n1. Creating file with initial permissions...")
    log_event(initial_log)
    
    # Check permissions after initial creation
    record = get_existing_record_from_db(file_id)
    if record:
        perms = record.get("permissions", [])
        print(f"   Initial permissions count: {len(perms)}")
        for p in perms:
            print(f"   - {p.get('displayName', 'Unknown')} ({p.get('emailAddress', 'Unknown')}): {p.get('role', 'Unknown')}")
    
    # Wait a moment
    import time
    time.sleep(1)
    
    # Test 2: Simulate permission change - user1 becomes reader, user2 added as writer
    updated_permissions = [
        {
            "emailAddress": "owner@example.com",
            "role": "owner",
            "displayName": "File Owner",
            "id": "owner123"
        },
        {
            "emailAddress": "user1@example.com",
            "role": "reader",  # Changed from writer to reader
            "displayName": "User One",
            "id": "user123"
        },
        {
            "emailAddress": "user2@example.com",  # New user added
            "role": "writer",
            "displayName": "User Two",
            "id": "user456"
        }
    ]
    
    permission_change_log = {
        "file_id": file_id,
        "file_name": "test_permissions_file.docx",
        "owner": "owner@example.com",
        "permissions": updated_permissions,  # Include current permissions after change
        "details": {
            "type": "changes",
            "file_name": "test_permissions_file.docx",
            "owner": "owner@example.com",
            "changes": [
                {
                    "type": "permission_changed",
                    "user": "user1@example.com",
                    "user_name": "User One",
                    "old_role": "writer",
                    "new_role": "reader",
                    "modified_by": {
                        "name": "File Owner",
                        "email": "owner@example.com"
                    }
                },
                {
                    "type": "permission_added",
                    "user": "user2@example.com",
                    "user_name": "User Two",
                    "role": "writer",
                    "modified_by": {
                        "name": "File Owner",
                        "email": "owner@example.com"
                    }
                }
            ],
            "modified_by": {
                "name": "File Owner",
                "email": "owner@example.com"
            },
            "source": "google_drive",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n2. Updating permissions (user1: writer→reader, add user2 as writer)...")
    log_event(permission_change_log)
    
    # Check permissions after change
    record = get_existing_record_from_db(file_id)
    if record:
        perms = record.get("permissions", [])
        print(f"   Updated permissions count: {len(perms)}")
        for p in perms:
            print(f"   - {p.get('displayName', 'Unknown')} ({p.get('emailAddress', 'Unknown')}): {p.get('role', 'Unknown')}")
        
        # Show history
        history = record.get("history", [])
        print(f"\n   History entries: {len(history)}")
        for i, entry in enumerate(history, 1):
            entry_type = entry.get('type')
            timestamp = entry.get('timestamp')
            print(f"   {i}. {entry_type} at {timestamp}")
            
            if entry_type == 'changes':
                changes = entry.get('details', {}).get('changes', [])
                for change in changes:
                    print(f"      - {change.get('type')}: {change.get('user', 'N/A')}")
    else:
        print("[ERROR] No record found in MongoDB")
        
    print(f"\n=== Permissions Update Test Completed ===")


def test_trashed_file_logging():
    """Test function to verify trashed file detection and modifier logging."""
    print("=== Testing Trashed File Modifier Detection ===")
    
    file_id = "test_trashed_file_" + str(int(datetime.datetime.now().timestamp()))
    
    # Test 1: Simulate a trashed file being detected
    trashed_file_log = {
        "file_id": file_id,
        "file_name": "test_trashed_document.docx",
        "owner": "owner@example.com",
        "details": {
            "type": "file_trashed",
            "file_name": "test_trashed_document.docx",
            "owner": "owner@example.com",
            "permissions": [
                {
                    "emailAddress": "owner@example.com",
                    "role": "owner",
                    "displayName": "File Owner"
                }
            ],
            "modified_by": {
                "name": "Trash User",
                "email": "trashuser@example.com",
                "action": "trashed"
            },
            "source": "google_drive",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n1. Testing trashed file detection...")
    log_event(trashed_file_log)
    
    # Wait a moment
    import time
    time.sleep(1)
    
    # Test 2: Simulate file being restored from trash
    untrashed_file_log = {
        "file_id": file_id,
        "file_name": "test_trashed_document.docx",
        "owner": "owner@example.com",
        "details": {
            "type": "changes",
            "file_name": "test_trashed_document.docx",
            "owner": "owner@example.com",
            "changes": [
                {
                    "type": "file_untrashed",
                    "file_name": "test_trashed_document.docx",
                    "modified_by": {
                        "name": "Restore User",
                        "email": "restoreuser@example.com",
                        "action": "restored"
                    }
                }
            ],
            "modified_by": {
                "name": "Restore User",
                "email": "restoreuser@example.com",
                "action": "restored"
            },
            "source": "google_drive",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n2. Testing file restore from trash...")
    log_event(untrashed_file_log)
    
    # Check the final state in MongoDB
    print(f"\n3. Checking MongoDB history for trashed file operations: {file_id}")
    final_record = get_existing_record_from_db(file_id)
    if final_record:
        history = final_record.get("history", [])
        print(f"[INFO] Total history entries: {len(history)}")
        for i, entry in enumerate(history, 1):
            entry_type = entry.get('type')
            timestamp = entry.get('timestamp')
            print(f"   {i}. {entry_type} at {timestamp}")
            
            # Show modifier details
            details = entry.get('details', {})
            modifier = details.get('modified_by', {})
            if modifier.get('name') != 'Unknown':
                action = modifier.get('action', 'unknown')
                print(f"      Modified by: {modifier.get('name')} ({modifier.get('email')}) - {action}")
            
            if entry_type == 'changes':
                changes = details.get('changes', [])
                for change in changes:
                    change_modifier = change.get('modified_by', {})
                    print(f"      - {change.get('type')}: modified by {change_modifier.get('name', 'Unknown')}")
    else:
        print("[ERROR] No record found in MongoDB")
        
    print(f"\n=== Trashed File Logging Test Completed ===")


def test_permission_change_logging():
    """Test function to verify permission changes are logged to MongoDB history."""
    print("=== Testing Permission Change Logging ===")
    
    file_id = "test_permission_change_" + str(int(datetime.datetime.now().timestamp()))
    
    # Test 1: New file with initial permissions
    initial_log = {
        "file_id": file_id,
        "file_name": "test_permissions.docx",
        "owner": "owner@example.com",
        "details": {
            "type": "new_file",
            "source": "google_drive",
            "permissions": [
                {
                    "emailAddress": "owner@example.com",
                    "role": "owner",
                    "displayName": "File Owner"
                },
                {
                    "emailAddress": "reader@example.com", 
                    "role": "reader",
                    "displayName": "Initial Reader"
                }
            ],
            "modified_by": {
                "name": "File Owner",
                "email": "owner@example.com"
            },
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n1. Creating initial file record...")
    log_event(initial_log)
    
    # Wait a moment to ensure different timestamp
    import time
    time.sleep(1)
    
    # Test 2: Permission change - reader becomes writer
    permission_change_log = {
        "file_id": file_id,
        "file_name": "test_permissions.docx", 
        "owner": "owner@example.com",
        "details": {
            "type": "changes",
            "file_name": "test_permissions.docx",
            "owner": "owner@example.com",
            "changes": [
                {
                    "type": "permission_changed",
                    "user": "reader@example.com",
                    "user_name": "Initial Reader",
                    "old_role": "reader",
                    "new_role": "writer", 
                    "modified_by": {
                        "name": "File Owner",
                        "email": "owner@example.com"
                    }
                }
            ],
            "modified_by": {
                "name": "File Owner", 
                "email": "owner@example.com"
            },
            "source": "google_drive",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n2. Testing permission change (reader → writer)...")
    log_event(permission_change_log)
    
    # Wait a moment
    time.sleep(1)
    
    # Test 3: Add new permission
    add_permission_log = {
        "file_id": file_id,
        "file_name": "test_permissions.docx",
        "owner": "owner@example.com", 
        "details": {
            "type": "changes",
            "file_name": "test_permissions.docx",
            "owner": "owner@example.com",
            "changes": [
                {
                    "type": "permission_added",
                    "user": "newuser@example.com",
                    "user_name": "New User",
                    "role": "reader",
                    "modified_by": {
                        "name": "File Owner",
                        "email": "owner@example.com"
                    }
                }
            ],
            "modified_by": {
                "name": "File Owner",
                "email": "owner@example.com"
            },
            "source": "google_drive",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"\n3. Testing add permission...")
    log_event(add_permission_log)
    
    # Check the final state in MongoDB
    print(f"\n4. Checking MongoDB history for file_id: {file_id}")
    final_record = get_existing_record_from_db(file_id)
    if final_record:
        history = final_record.get("history", [])
        print(f"[INFO] Total history entries: {len(history)}")
        for i, entry in enumerate(history, 1):
            print(f"   {i}. {entry.get('type')} at {entry.get('timestamp')}")
            if entry.get('type') == 'changes':
                changes = entry.get('details', {}).get('changes', [])
                for change in changes:
                    print(f"      - {change.get('type')}: {change.get('user', 'N/A')}")
    else:
        print("[ERROR] No record found in MongoDB")
        
    print(f"\n=== Permission Change Logging Test Completed ===")


def test_mongodb_directly():
    """Test MongoDB connection and insertion directly."""
    print("=== Testing MongoDB Connection Directly ===")
    
    if collection is None:
        print("[ERROR] MongoDB collection is not available")
        return
        
    try:
        # Test connection
        mongo_client.admin.command('ping')
        print("[SUCCESS] MongoDB ping successful")
        
        # Count existing documents
        count = collection.count_documents({})
        print(f"[INFO] Current document count in collection: {count}")
        
        # Test a simple insert
        test_doc = {
            "file_id": "mongodb_test_" + str(int(datetime.datetime.now().timestamp())),
            "file_name": "MongoDB Test File",
            "owner": {"name": "Test User", "email": "test@example.com"},
            "source": "test",
            "last_event_type": "test_insert",
            "last_event_timestamp": datetime.datetime.now().isoformat(),
            "history": [{
                "type": "test_insert",
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"source": "direct_test"}
            }]
        }
        
        result = collection.insert_one(test_doc)
        print(f"[SUCCESS] Direct MongoDB insert successful. Inserted ID: {result.inserted_id}")
        
        # Count again
        new_count = collection.count_documents({})
        print(f"[INFO] New document count in collection: {new_count}")
        
    except Exception as e:
        print(f"[ERROR] MongoDB test failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main function to monitor both Google Drive and Dropbox."""
    try:
        # First monitor Google Drive
        monitor_google_drive()

        # Then monitor Dropbox
        #monitor_dropbox()

    except Exception as e:
        log_event(f"Error in main monitoring function: {e}")
    finally:
        log_event("All monitoring completed.")


def monitor_google_drive():
    """Shows basic usage of the Drive v3 API."""
    try:
        creds = None
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=52166)
            with open("token.json", "w") as token:
                token.write(creds.to_json())

        service = build("drive", "v3", credentials=creds)

        log_event("Real-time Google Drive Metadata Monitoring Started...")

        try:
            # Get all files including trashed ones
            results = service.files().list(
                pageSize=100,
                fields="nextPageToken, files(id, name, mimeType, permissions(role,emailAddress,displayName), owners(emailAddress,displayName), trashed)",
                includeItemsFromAllDrives=True,
                supportsAllDrives=True
            ).execute()

            log_event("Successfully fetched Drive metadata!")

            # Get current file IDs
            current_files = {file['id']: file for file in results.get('files', [])}

            # Get previously stored file IDs from Pinecone
            try:
                # Query Pinecone to get all stored file IDs
                query_response = gdrive_index.query(
                    vector=[0.1] * 384,  # Dummy vector
                    top_k=1000,
                    include_metadata=True
                )

                # Convert metadata strings back to objects
                stored_files = {}
                for match in query_response.matches:
                    if match.id and match.metadata:
                        metadata = match.metadata
                        # Convert JSON strings back to objects
                        for key, value in metadata.items():
                            if isinstance(value, str):
                                try:
                                    parsed = json.loads(value)
                                    if isinstance(parsed, (dict, list)):
                                        metadata[key] = parsed
                                except:
                                    pass  # Keep as string if not valid JSON
                        stored_files[match.id] = metadata

                # Check for deleted files (files that were in storage but not in current files)
                for file_id, metadata in stored_files.items():
                    if file_id not in current_files:
                        # File was deleted - try to get enhanced modifier information
                        
                        # Enhanced modifier detection for deleted files
                        modifier_info = {"name": "Unknown", "email": "Unknown", "action": "unknown"}
                        
                        try:
                            log_event(f"Attempting to identify who deleted file {file_id}: {metadata.get('name', 'Unknown')}")
                            
                            # Method 1: Try to get file information even though it's deleted 
                            # (sometimes Google keeps revision history even for deleted files)
                            try:
                                revision = service.revisions().list(
                                    fileId=file_id,
                                    fields="revisions(lastModifyingUser,modifiedTime)",
                                    pageSize=5
                                ).execute()
                                
                                if revision.get('revisions'):
                                    for rev in revision['revisions']:
                                        if rev.get('lastModifyingUser'):
                                            last_modifier = rev['lastModifyingUser']
                                            modifier_info = {
                                                "name": last_modifier.get('displayName', 'Unknown'),
                                                "email": last_modifier.get('emailAddress', 'Unknown'),
                                                "action": "revision_history_deleted",
                                                "revision_time": rev.get('modifiedTime', 'Unknown')
                                            }
                                            log_event(f"Found modifier from revision history for deleted file {file_id}: {modifier_info['name']} ({modifier_info['email']})")
                                            break
                                            
                            except Exception as e:
                                log_event(f"Could not get revision history for deleted file {file_id}: {e}")
                            
                            # Method 2: Try to get any remaining file metadata
                            if modifier_info["name"] == "Unknown":
                                try:
                                    file_info = service.files().get(
                                        fileId=file_id,
                                        fields="lastModifyingUser,trashingUser,owners,trashed,explicitlyTrashed",
                                        supportsAllDrives=True
                                    ).execute()
                                    
                                    # Check if file is in trash rather than deleted
                                    if file_info.get('trashed', False):
                                        log_event(f"File {file_id} is in trash, not deleted")
                                        if file_info.get('trashingUser'):
                                            modifier_info = {
                                                "name": file_info['trashingUser'].get('displayName', 'Unknown'),
                                                "email": file_info['trashingUser'].get('emailAddress', 'Unknown'),
                                                "action": "trashed_file"
                                            }
                                            log_event(f"Found trashing user for {file_id}: {modifier_info['name']}")
                                        elif file_info.get('lastModifyingUser'):
                                            modifier_info = {
                                                "name": file_info['lastModifyingUser'].get('displayName', 'Unknown'),
                                                "email": file_info['lastModifyingUser'].get('emailAddress', 'Unknown'),
                                                "action": "last_modifier_trashed"
                                            }
                                            log_event(f"Found last modifier for trashed file {file_id}: {modifier_info['name']}")
                                    else:
                                        # File is actually deleted
                                        if file_info.get('lastModifyingUser'):
                                            modifier_info = {
                                                "name": file_info['lastModifyingUser'].get('displayName', 'Unknown'),
                                                "email": file_info['lastModifyingUser'].get('emailAddress', 'Unknown'),
                                                "action": "deleted_file_last_modifier"
                                            }
                                            log_event(f"Found last modifier for deleted file {file_id}: {modifier_info['name']}")
                                            
                                except Exception as e:
                                    log_event(f"Could not get file metadata for deleted file {file_id}: {e}")
                            
                            # Method 3: Use stored metadata to get owner information as fallback
                            if modifier_info["name"] == "Unknown" and metadata.get("permissions"):
                                try:
                                    for perm in metadata["permissions"]:
                                        if perm.get("role") == "owner" and perm.get("displayName"):
                                            modifier_info = {
                                                "name": perm.get("displayName", "Unknown"),
                                                "email": perm.get("emailAddress", "Unknown"),
                                                "action": "inferred_from_stored_owner"
                                            }
                                            log_event(f"Using stored owner as fallback modifier for {file_id}: {modifier_info['name']}")
                                            break
                                except Exception as e:
                                    log_event(f"Error using stored metadata for {file_id}: {e}")
                                    
                        except Exception as e:
                            log_event(f"Error in enhanced deletion detection for {file_id}: {e}")
                        
                        # Determine if this is a trashed file or actually deleted
                        try:
                            file_check = service.files().get(
                                fileId=file_id,
                                fields="trashed,explicitlyTrashed",
                                supportsAllDrives=True
                            ).execute()
                            
                            is_trashed = file_check.get('trashed', False)
                            file_status = "file_trashed" if is_trashed else "file_deleted"
                            
                        except:
                            # If we can't access the file at all, it's likely permanently deleted
                            file_status = "file_deleted"
                        
                        change_details = {
                            "type": file_status,
                            "file_name": metadata.get("name", "Unknown"),
                            "owner": next((p.get("emailAddress") for p in metadata.get("permissions", [])
                                           if p.get("role") == "owner"), "Unknown"),
                            "modified_by": modifier_info,
                            "source": "google_drive",
                            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }

                        # Log the deletion/trashing
                        log_message = {
                            "file_id": file_id,
                            "file_name": change_details["file_name"],
                            "owner": change_details["owner"],
                            "details": change_details,
                            "timestamp": change_details["timestamp"]
                        }
                        log_event(log_message)

                        try:
                            send_email_alert(file_id, change_details)
                        except Exception as e:
                            log_event(f"Failed to send email alert: {e}")

                        # Remove the deleted file from Pinecone
                        try:
                            gdrive_index.delete(ids=[file_id])
                            log_event(f"Removed deleted file {file_id} from Pinecone")
                        except Exception as e:
                            log_event(f"Error removing deleted file from Pinecone: {e}")

            except Exception as e:
                log_event(f"Error checking for deleted files: {e}")

            # Process current files
            for file in current_files.values():
                process_drive_file(file, service)

        except Exception as error:
            log_event(f'An error occurred: {error}')

    except Exception as e:
        log_event(f"Error in Google Drive monitoring: {e}")
    finally:
        log_event("Google Drive monitoring complete.")


# === Dropbox Functions ===

def load_dropbox_alerts():
    """Load previously sent Dropbox alerts to avoid duplicate notifications."""
    if os.path.exists(DROPBOX_ALERTS_FILE):
        with open(DROPBOX_ALERTS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_dropbox_alerts(alerts):
    """Save the updated Dropbox alerts log."""
    with open(DROPBOX_ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def get_existing_dropbox_metadata(file_id):
    """Fetch stored Dropbox metadata from Pinecone."""
    try:
        result = dropbox_index.fetch(ids=[file_id])
        if file_id in result.vectors:
            return result.vectors[file_id].metadata
        return {}
    except Exception as e:
        log_event(f"Error fetching Dropbox metadata from Pinecone: {e}")
        return {}


def get_dropbox_files():
    """Fetch all files from Dropbox with their metadata."""
    try:
        result = dbx.files_list_folder("", recursive=True)
        files = []

        # Process initial batch
        for entry in result.entries:
            if isinstance(entry, dropbox.files.FileMetadata):
                files.append({
                    "id": entry.id,
                    "name": entry.name,
                    "path": entry.path_display,
                    "size": str(entry.size),
                    "client_modified": str(entry.client_modified),
                    "server_modified": str(entry.server_modified)
                })

        # Handle pagination
        while result.has_more:
            result = dbx.files_list_folder_continue(result.cursor)
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    files.append({
                        "id": entry.id,
                        "name": entry.name,
                        "path": entry.path_display,
                        "size": str(entry.size),
                        "client_modified": str(entry.client_modified),
                        "server_modified": str(entry.server_modified)
                    })

        log_event(f"Successfully fetched {len(files)} files from Dropbox")
        return files

    except dropbox.exceptions.ApiError as e:
        log_event(f"Dropbox API error: {e}")
        return []
    except Exception as e:
        log_event(f"Error fetching Dropbox files: {e}")
        return []


def get_dropbox_file_permissions(file_path):
    """Get actual sharing permissions for a Dropbox file."""
    try:
        permissions = []
        modifier_info = None
        
        # First try to get sharing metadata
        try:
            sharing_info = dbx.sharing_get_file_metadata(file_path)
            
            if sharing_info:
                # Get file members and sharing history
                try:
                    members = dbx.sharing_list_file_members(file_path)
                    
                    # Get sharing history to identify who made the changes
                    try:
                        # Get the file's sharing history
                        history = dbx.sharing_get_file_metadata(file_path)
                        if history and hasattr(history, 'modified_by'):
                            modifier = history.modified_by
                            modifier_info = {
                                'name': getattr(modifier, 'display_name', 'Unknown'),
                                'email': getattr(modifier, 'email', 'Unknown'),
                                'timestamp': str(datetime.datetime.now())
                            }
                        
                        # If no modifier found in metadata, try to get it from the owner
                        if not modifier_info and hasattr(history, 'owner'):
                            owner = history.owner
                            modifier_info = {
                                'name': getattr(owner, 'display_name', 'Unknown'),
                                'email': getattr(owner, 'email', 'Unknown'),
                                'timestamp': str(datetime.datetime.now())
                            }
                    except Exception as e:
                        log_event(f"Error getting sharing history: {str(e)}")
                    
                    # Process active users
                    if members and hasattr(members, 'users'):
                        for user in members.users:
                            # Get user info
                            user_info = user.user
                            access_type = str(user.access_type).lower()
                            
                            permission = {
                                'displayName': getattr(user_info, 'display_name', 'Unknown'),
                                'emailAddress': getattr(user_info, 'email', 'Unknown'),
                                'role': 'reader',  # Default role
                                'modified_by': modifier_info  # Add modifier info
                            }
                            
                            # Map access levels to roles
                            if 'owner' in access_type:
                                permission['role'] = 'owner'
                            elif 'editor' in access_type:
                                permission['role'] = 'writer'
                            elif 'viewer' in access_type:
                                permission['role'] = 'reader'
                            
                            permissions.append(permission)
                    
                    # Process pending invites
                    if members and hasattr(members, 'invitees'):
                        for invitee in members.invitees:
                            access_type = str(invitee.access_type).lower()
                            
                            # For invitees, get the email value
                            if hasattr(invitee, 'invitee'):
                                invitee_info = invitee.invitee
                                # Get the actual email string value
                                if hasattr(invitee_info, '_email_value'):
                                    invitee_email = invitee_info._email_value
                                elif hasattr(invitee_info, '_value'):
                                    invitee_email = invitee_info._value
                                else:
                                    # Try direct access or string representation
                                    try:
                                        invitee_email = str(invitee_info).split("'")[1]
                                    except:
                                        invitee_email = "Unknown"
                                
                                permission = {
                                    'displayName': 'Pending User',
                                    'emailAddress': invitee_email,
                                    'role': 'reader',  # Default role
                                    'status': 'pending',  # Add status to indicate pending invitation
                                    'modified_by': modifier_info  # Add modifier info
                                }
                                
                                # Map access levels to roles
                                if 'owner' in access_type:
                                    permission['role'] = 'owner'
                                elif 'editor' in access_type:
                                    permission['role'] = 'writer'
                                elif 'viewer' in access_type:
                                    permission['role'] = 'reader'
                                
                                permissions.append(permission)
                    
                    # Also check groups if any
                    if members and hasattr(members, 'groups'):
                        for group in members.groups:
                            group_info = group.group
                            access_type = str(group.access_type).lower()
                            
                            permission = {
                                'displayName': f"Group: {getattr(group_info, 'display_name', 'Unknown Group')}",
                                'emailAddress': f"group:{getattr(group_info, 'group_id', 'unknown')}",
                                'role': 'reader',  # Default role
                                'modified_by': modifier_info  # Add modifier info
                            }
                            
                            # Map access levels to roles
                            if 'editor' in access_type:
                                permission['role'] = 'writer'
                            elif 'viewer' in access_type:
                                permission['role'] = 'reader'
                            
                            permissions.append(permission)
                
                except Exception as e:
                    log_event(f"Error getting file members: {str(e)}")
                
                # If no permissions found yet, try to get owner from sharing info
                if not permissions and hasattr(sharing_info, 'access_type'):
                    try:
                        # Get current account as it might be the owner
                        current_account = dbx.users_get_current_account()
                        if current_account and 'owner' in str(sharing_info.access_type).lower():
                            owner_permission = {
                                'displayName': current_account.name.display_name,
                                'emailAddress': current_account.email,
                                'role': 'owner',
                                'modified_by': modifier_info  # Add modifier info
                            }
                            permissions.append(owner_permission)
                    except Exception as e:
                        log_event(f"Error getting current account info: {str(e)}")
        
        except dropbox.exceptions.ApiError as e:
            if 'sharing.read' in str(e):
                log_event(f"Missing sharing.read permission for file {file_path}")
            else:
                log_event(f"Error getting sharing metadata: {str(e)}")
        
        # If still no permissions found, try to get file metadata
        if not permissions:
            try:
                metadata = dbx.files_get_metadata(file_path)
                
                # Try to get owner from file metadata
                if hasattr(metadata, 'sharing_info'):
                    sharing_info = metadata.sharing_info
                    owner_team = getattr(sharing_info, 'owner_team', None)
                    owner_display = getattr(sharing_info, 'owner_display_name', None)
                    
                    if owner_display or owner_team:
                        owner_permission = {
                            'displayName': owner_display or f"Team: {owner_team.name}",
                            'emailAddress': owner_team.team_id if owner_team else 'Unknown',
                            'role': 'owner',
                            'modified_by': modifier_info  # Add modifier info
                        }
                        permissions.append(owner_permission)
                
                # If still no permissions, try to get the current user's info
                if not permissions:
                    try:
                        current_account = dbx.users_get_current_account()
                        if current_account:
                            owner_permission = {
                                'displayName': current_account.name.display_name,
                                'emailAddress': current_account.email,
                                'role': 'owner',
                                'modified_by': modifier_info  # Add modifier info
                            }
                            permissions.append(owner_permission)
                    except Exception as e:
                        log_event(f"Error getting current account info: {str(e)}")
            
            except Exception as e:
                log_event(f"Error getting file metadata: {str(e)}")
        
        return permissions

    except Exception as e:
        log_event(f"Error in get_dropbox_file_permissions: {str(e)}")
        return []


def prepare_pinecone_metadata(file_data, permissions):
    """Prepare metadata for Pinecone storage by converting complex structures to strings."""
    metadata = {
        "id": file_data.get("id", ""),
        "name": file_data.get("name", ""),
        "path": file_data.get("path", ""),
        "size": str(file_data.get("size", "0")),
        "client_modified": str(file_data.get("client_modified", "")),
        "server_modified": str(file_data.get("server_modified", "")),
        "permissions_json": json.dumps(permissions),  # Store permissions as JSON string
        "owner_name": "",  # Initialize owner fields
        "owner_email": "",
        "owner_timestamp": ""
    }
    
    # Extract owner from permissions and store as separate fields
    owner = next((p for p in permissions if p.get('role') == 'owner'), {})
    if owner:
        metadata["owner_name"] = owner.get('displayName', 'Unknown Owner')
        metadata["owner_email"] = owner.get('emailAddress', 'Unknown')
        metadata["owner_timestamp"] = str(datetime.datetime.now())
    
    return metadata


def detect_dropbox_change(file_id, new_metadata):
    """Detect and alert on Dropbox metadata changes."""
    try:
        old_metadata = get_existing_dropbox_metadata(file_id)
        alerts_log = load_dropbox_alerts()

        if old_metadata != new_metadata:
            # Parse old and new permissions
            old_permissions = json.loads(old_metadata.get("permissions_json", "[]")) if old_metadata else []
            new_permissions = json.loads(new_metadata.get("permissions_json", "[]"))
            
            # Create sets of permission tuples for comparison
            old_perm_set = {(p.get('emailAddress', ''), p.get('role', ''), p.get('status', 'active')) 
                           for p in old_permissions}
            new_perm_set = {(p.get('emailAddress', ''), p.get('role', ''), p.get('status', 'active')) 
                           for p in new_permissions}
            
            # Detect permission changes
            added_perms = new_perm_set - old_perm_set
            removed_perms = old_perm_set - new_perm_set
            
            change_details = {
                "file_id": file_id,
                "file_name": new_metadata.get("name", "Unknown"),
                "path": new_metadata.get("path", ""),
                "timestamp": str(datetime.datetime.now()),
                "source": "dropbox",
                "changes": {
                    "metadata_changes": {
                    key: {"old": old_metadata.get(key), "new": new_metadata.get(key)}
                        for key in new_metadata 
                        if key != "permissions_json" and old_metadata and old_metadata.get(key) != new_metadata.get(key)
                    },
                    "permission_changes": {
                        "added": [{"email": email, "role": role, "status": status} 
                                for email, role, status in added_perms],
                        "removed": [{"email": email, "role": role, "status": status} 
                                  for email, role, status in removed_perms]
                    }
                }
            }

            # Only send alert if there are actual changes
            if (change_details["changes"]["metadata_changes"] or 
                change_details["changes"]["permission_changes"]["added"] or 
                change_details["changes"]["permission_changes"]["removed"]):
                
                send_dropbox_alert(file_id, change_details)

                # Update Pinecone with new metadata
                try:
                    vector = model.encode(json.dumps(new_metadata)).tolist()
                    dropbox_index.upsert(vectors=[{
                        "id": file_id,
                        "values": vector,
                        "metadata": new_metadata
                    }])
                except Exception as e:
                    log_event(f"Error updating Pinecone with Dropbox metadata: {e}")

                alerts_log[file_id] = change_details["changes"]
                save_dropbox_alerts(alerts_log)
                log_event(f"Dropbox change detected and alerts sent for {file_id}")
                return change_details

        return None
    except Exception as e:
        log_event(f"Error in detect_dropbox_change: {e}")
        return None


def send_dropbox_alert(file_id, change_details):
    """Send rich formatted alerts for Dropbox changes, using the same structure as Google Drive."""
    try:
        file_name = change_details.get("file_name", "Unknown")
        details = change_details.get("details", {})
        path = details.get("path", "")
        event_type = details.get("type", "changes")
        changes = details.get("changes", [])
        owner = change_details.get("owner", {})
        timestamp = change_details.get("timestamp", str(datetime.datetime.now()))

        # Format email content
        subject = f"Dropbox Change: {file_name}"
        body = [
            f"Changes detected in Dropbox file '{file_name}':",
            f"Path: {path}",
            f"File ID: {file_id}",
            f"Owner: {owner.get('name', 'Unknown Owner')} ({owner.get('email', 'Unknown')})",
            f"Timestamp: {timestamp}",
            "\nChanges:"
        ]

        if event_type == "new_file":
            body.append("- New file created")
            perms = details.get("permissions", [])
            if perms:
                body.append("Initial permissions:")
                for perm in perms:
                    status = f" ({perm.get('status')})" if perm.get('status') == 'pending' else ""
                    body.append(f"- {perm.get('displayName', 'Unknown')} ({perm.get('emailAddress', 'Unknown')}): {perm.get('role', 'Unknown')}{status}")
        elif event_type == "file_deleted":
            body.append("- File deleted")
        else:
            for change in changes:
                modifier = change.get("modified_by", {})
                modifier_text = f" by {modifier.get('name', 'Unknown')} ({modifier.get('email', 'Unknown')})" if modifier else ""
                status = f" ({change.get('status')})" if change.get('status') == 'pending' else ""
                if change["type"] == "permission_added":
                    body.append(f"- Added {change['role']} permission for {change['user_name']} ({change['user']}){status}{modifier_text}")
                elif change["type"] == "permission_changed":
                    body.append(f"- Changed permission for {change['user_name']} ({change['user']}) from {change['old_role']} to {change['new_role']}{status}{modifier_text}")
                elif change["type"] == "permission_removed":
                    body.append(f"- Removed {change['role']} permission for {change['user_name']} ({change['user']}){status}{modifier_text}")

        message = "\n".join(body)
        log_event(f"Alert content:\n{message}")
        # TODO: Implement your alert sending mechanism here
        # send_alert(subject, message)
    except Exception as e:
        log_event(f"Error sending Dropbox alert: {e}")


def monitor_dropbox():
    """Main function to monitor Dropbox files."""
    try:
        log_event("Real-time Dropbox Metadata Monitoring Started...")
        dropbox_files = get_dropbox_files()
        try:
            query_response = dropbox_index.query(
                vector=[0.1] * 384,
                top_k=1000,
                include_metadata=True
            )
            stored_files = {}
            for match in query_response.matches:
                if match.id and match.metadata:
                    stored_files[match.id] = match.metadata
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for file in dropbox_files:
                try:
                    file_id = file['id']
                    file_path = file['path']
                    permissions = get_dropbox_file_permissions(file_path)
                    owner_info = next((p for p in permissions if p.get('role') == 'owner'), {})
                    owner_details = {
                        'name': owner_info.get('displayName', 'Unknown Owner'),
                        'email': owner_info.get('emailAddress', 'Unknown'),
                        'timestamp': current_time
                    }
                    pinecone_metadata = prepare_pinecone_metadata(file, permissions)
                    if file_id in stored_files:
                        old_metadata = stored_files[file_id]
                        try:
                            old_permissions = json.loads(old_metadata.get('permissions_json', '[]'))
                        except:
                            old_permissions = []
                        old_perms_dict = {p.get('emailAddress'): p for p in old_permissions if p.get('emailAddress')}
                        new_perms_dict = {p.get('emailAddress'): p for p in permissions if p.get('emailAddress')}
                        changes = []
                        for email, new_perm in new_perms_dict.items():
                            modifier_info = new_perm.get('modified_by') or {
                                'name': owner_info.get('displayName', 'Unknown Owner'),
                                'email': owner_info.get('emailAddress', 'Unknown'),
                                'is_owner': True,
                                'timestamp': current_time
                            }
                            if 'timestamp' not in modifier_info:
                                modifier_info['timestamp'] = current_time
                            if email not in old_perms_dict:
                                changes.append({
                                    "type": "permission_added",
                                    "user": email,
                                    "user_name": new_perm.get('displayName', 'Unknown'),
                                    "role": new_perm.get('role', 'Unknown'),
                                    "status": new_perm.get('status', 'active'),
                                    "modified_by": modifier_info,
                                    "timestamp": current_time
                                })
                            elif old_perms_dict[email].get('role') != new_perm.get('role'):
                                changes.append({
                                    "type": "permission_changed",
                                    "user": email,
                                    "user_name": new_perm.get('displayName', 'Unknown'),
                                    "old_role": old_perms_dict[email].get('role', 'Unknown'),
                                    "new_role": new_perm.get('role', 'Unknown'),
                                    "status": new_perm.get('status', 'active'),
                                    "modified_by": modifier_info,
                                    "timestamp": current_time
                                })
                        for email, old_perm in old_perms_dict.items():
                            if email not in new_perms_dict:
                                modifier_info = old_perm.get('modified_by') or {
                                    'name': owner_info.get('displayName', 'Unknown Owner'),
                                    'email': owner_info.get('emailAddress', 'Unknown'),
                                    'is_owner': True,
                                    'timestamp': current_time
                                }
                                if 'timestamp' not in modifier_info:
                                    modifier_info['timestamp'] = current_time
                                changes.append({
                                    "type": "permission_removed",
                                    "user": email,
                                    "user_name": old_perm.get('displayName', 'Unknown'),
                                    "role": old_perm.get('role', 'Unknown'),
                                    "modified_by": modifier_info,
                                    "timestamp": current_time
                                })
                        if changes:
                            change_event = {
                        "file_id": file_id,
                                "file_name": file['name'],
                                "timestamp": current_time,
                                "owner": owner_details,
                                "details": {
                                    "type": "changes",
                                    "source": "dropbox",
                                    "file_name": file['name'],
                                    "path": file_path,
                                    "changes": changes,
                                    "timestamp": current_time
                                }
                            }
                            log_event(change_event)
                            send_dropbox_alert(file_id, change_event)
                    else:
                        new_file_event = {
                            "file_id": file_id,
                            "file_name": file['name'],
                            "timestamp": current_time,
                            "owner": owner_details,
                            "details": {
                                "type": "new_file",
                                "source": "dropbox",
                                "file_name": file['name'],
                                "path": file_path,
                                "permissions": permissions,
                                "owner": owner_details,
                                "timestamp": current_time
                            }
                        }
                        log_event(new_file_event)
                        send_dropbox_alert(file_id, new_file_event)
                    dropbox_index.upsert(vectors=[{
                        "id": file_id,
                        "metadata": pinecone_metadata,
                        "values": clean_vector(model.encode(file['name'] + " " + file['path']).tolist())
                    }])
                except Exception as e:
                    log_event(f"Error processing Dropbox file {file.get('id', 'Unknown')}: {e}")
                    continue
            current_file_ids = {f['id'] for f in dropbox_files}
            for stored_id in stored_files:
                if stored_id not in current_file_ids:
                    stored_file = stored_files[stored_id]
                    owner_details = {
                        'name': stored_file.get('owner_name', 'Unknown Owner'),
                        'email': stored_file.get('owner_email', 'Unknown'),
                        'timestamp': current_time
                    }
                    deleted_event = {
                        "file_id": stored_id,
                        "file_name": stored_file.get('name', 'Unknown'),
                        "timestamp": current_time,
                        "owner": owner_details,
                        "details": {
                            "type": "file_deleted",
                            "source": "dropbox",
                            "file_name": stored_file.get('name', 'Unknown'),
                            "path": stored_file.get('path', ''),
                            "owner": owner_details,
                            "timestamp": current_time
                        }
                    }
                    log_event(deleted_event)
                    send_dropbox_alert(stored_id, deleted_event)
                    try:
                        dropbox_index.delete(ids=[stored_id])
                    except Exception as e:
                        log_event(f"Error removing deleted Dropbox file from Pinecone: {e}")
        except Exception as e:
            log_event(f"Error checking Dropbox files: {e}")
        except Exception as e:
            log_event(f"Error in Dropbox monitoring: {e}")
    finally:
        log_event("Dropbox monitoring completed.")


# Add a test call after the main function
if __name__ == "__main__":
    # Call the main function if no arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--test-log":
            test_logging()
        elif sys.argv[1] == "--test-mongodb":
            test_mongodb_directly()
        elif sys.argv[1] == "--test-permissions":
            test_permission_change_logging()
        elif sys.argv[1] == "--test-trashed":
            test_trashed_file_logging()
        elif sys.argv[1] == "--test-all":
            test_mongodb_directly()
            print("\n" + "="*50 + "\n")
            test_logging()
            print("\n" + "="*50 + "\n") 
            test_permission_change_logging()
            print("\n" + "="*50 + "\n")
            test_trashed_file_logging()
        else:
            print("Available options:")
            print("  --test-log          Test logging functionality")
            print("  --test-mongodb      Test MongoDB connection directly")
            print("  --test-permissions  Test permission change logging")
            print("  --test-trashed      Test trashed file modifier detection")
            print("  --test-all          Run all tests")
            print("  (no args)           Run normal monitoring")
    else:
        main()