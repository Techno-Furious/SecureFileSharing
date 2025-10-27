"""
Flask web application that serves as the central dashboard for SaaS file monitoring.
Provides REST APIs and web interfaces for tracking Google Drive and Dropbox file activities,
managing user permissions, and displaying sensitivity analysis results from Presidio scans.
Handles OAuth authentication flows and webhook notifications for real-time file monitoring.
"""

import os
import json
import logging
import traceback
import time
import asyncio
import urllib.parse
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, render_template, request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
import re
import dropbox
import threading
import asyncio
import time
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId
from permissionCounter import update_all_user_count

app = Flask(__name__)



SAAS_MONITOR_THROTTLE_SECONDS=os.getenv('SAAS_MONITOR_THROTTLE_SECONDS', 60)
PRESIDIO_SCANNER_THROTTLE_SECONDS=os.getenv('PRESIDIO_SCANNER_THROTTLE_SECONDS', 60)
PRESIDIO_DELAY_SECONDS=int(os.getenv('PRESIDIO_DELAY_SECONDS', 120))
# MongoDB Configuration - Central database for file activity tracking
MONGODB_URI = os.getenv('MONGODB_URI')
client = MongoClient(MONGODB_URI)
db = client["FileInfo"]  # Primary database for file information
collection = db["FileActivityLogs"]  # Collection storing file activity history

# Google Drive API scopes - restricted to read-only access for security
SCOPES = ['https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/drive.metadata.readonly']

# Configure basic logging without rotation to avoid file access issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler()  # Console output only to prevent file locking issues
    ]
)
app.logger.setLevel(logging.INFO)
app.logger.info('Flask app startup')

# Shared last run time with a lock for throttling API calls
last_run_time = 0
run_lock = threading.Lock()

def throttle(seconds):
    """
    Throttle decorator to prevent a function from being called more than once in `seconds`.
    Used to rate-limit expensive operations like API calls or file scans.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            global last_run_time
            with run_lock:
                current_time = time.time()
                if current_time - last_run_time >= float(seconds):
                    last_run_time = current_time
                    return func(*args, **kwargs)
                else:
                    app.logger.info(f"Function {func.__name__} throttled. Remaining: {float(seconds) - (current_time - last_run_time):.1f}s")
                    return None
        return wrapper
    return decorator

def get_mongodb_logs():
    """
    Fetch all logs from MongoDB and transform them for dashboard consumption.
    Converts nested document history into flat log entries for frontend display.
    """
    try:
        # Fetch all documents from MongoDB
        documents = list(collection.find())
        
        # Transform each document's history into individual log entries
        all_logs = []
        
        for doc in documents:
            file_id = doc.get('file_id', '')
            file_name = doc.get('file_name', '')
            owner = doc.get('owner', '')
            source = doc.get('source', 'google_drive')
            permissions = doc.get('permissions', [])
            
            # Process each history entry
            history = doc.get('history', [])
            for history_entry in history:
                details = history_entry.get('details', {})
                
                # Create a log entry in the format expected by the frontend
                log_entry = {
                    'file_id': file_id,
                    'file_name': file_name,
                    'owner': owner,
                    'timestamp': details.get('timestamp', ''),
                    'details': details,
                    'permissions': permissions  # Current permissions for reference
                }
                
                all_logs.append(log_entry)
        
        # Sort logs by timestamp (newest first)
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        app.logger.info(f"Fetched {len(all_logs)} log entries from MongoDB")
        return all_logs
        
    except Exception as e:
        app.logger.error(f"Error fetching logs from MongoDB: {str(e)}\n{traceback.format_exc()}")
        return []

def get_mongodb_files():
    """
    Fetch all files from MongoDB for file-based view.
    Filters out deleted files by checking the latest history entry.
    """
    try:
        # Fetch all documents from MongoDB
        documents = list(collection.find())
        
        files = []
        for doc in documents:
            file_id = doc.get('file_id', '')
            file_name = doc.get('file_name', '')
            source = doc.get('source', 'google_drive')
            
            # Check if file is currently deleted by looking at the latest history entry
            history = doc.get('history', [])
            if history:
                # Sort history by timestamp to get the latest entry
                sorted_history = sorted(history, key=lambda x: x.get('details', {}).get('timestamp', ''), reverse=True)
                latest_entry = sorted_history[0] if sorted_history else {}
                latest_details = latest_entry.get('details', {})
                
                # Skip files that are currently deleted
                if latest_details.get('type') == 'file_deleted':
                    continue
            
            file_info = {
                "id": file_id,
                "name": file_name,
                "source": source,
                "path": "",  # Path info may not be available in current structure
                "timestamp": history[-1].get('details', {}).get('timestamp', '') if history else ''
            }
            
            files.append(file_info)
        
        # Sort by name
        files.sort(key=lambda x: x['name'].lower())
        
        app.logger.info(f"Fetched {len(files)} files from MongoDB")
        return files
        
    except Exception as e:
        app.logger.error(f"Error fetching files from MongoDB: {str(e)}\n{traceback.format_exc()}")
        return []

def get_mongodb_file_permissions(file_id):
    """
    Get permissions for a specific file from MongoDB.
    Returns organized permission data by role (owner, reader, writer, commenter).
    """
    try:
        # Find the document for this file
        doc = collection.find_one({"file_id": file_id})
        
        if not doc:
            return None
        
        # Get current permissions from the document
        permissions = doc.get('permissions', [])
        
        # Organize permissions by role
        roles = {"owner": [], "reader": [], "writer": [], "commenter": []}
        
        for perm in permissions:
            role = perm.get('role', '').lower()
            if role in roles:
                roles[role].append({
                    "name": perm.get('displayName', 'Unknown'),
                    "email": perm.get('emailAddress', '')
                })
        
        file_info = {
            "name": doc.get('file_name', 'Unknown'),
            "source": doc.get('source', 'google_drive')
        }
        
        return {"file": file_info, "permissions": roles}
        
    except Exception as e:
        app.logger.error(f"Error fetching file permissions from MongoDB: {str(e)}\n{traceback.format_exc()}")
        return None

def get_mongodb_users():
    """
    Get all unique users from MongoDB using aggregation pipeline.
    Extracts unique users from file permissions across all documents.
    """
    try:
        # Use aggregation to get all unique users from permissions
        pipeline = [
            {"$unwind": "$permissions"},
            {
                "$group": {
                    "_id": "$permissions.emailAddress",
                    "name": {"$first": "$permissions.displayName"},
                    "email": {"$first": "$permissions.emailAddress"}
                }
            },
            {"$match": {"_id": {"$ne": None, "$ne": ""}}},
            {"$sort": {"name": 1}}
        ]
        
        result = list(collection.aggregate(pipeline))
        
        users = []
        for user in result:
            users.append({
                "name": user.get('name', 'Unknown'),
                "email": user.get('email', user.get('_id', ''))
            })
        
        app.logger.info(f"Fetched {len(users)} users from MongoDB")
        return users
        
    except Exception as e:
        app.logger.error(f"Error fetching users from MongoDB: {str(e)}\n{traceback.format_exc()}")
        return []

def get_mongodb_user_files(email):
    """
    Get all files and their permissions for a specific user from MongoDB.
    Categorizes files by the user's permission level (owned, can_edit, can_comment, can_view).
    """
    try:
        # Find all documents where the user has permissions
        query = {"permissions.emailAddress": email}
        documents = list(collection.find(query))
        
        files = {
            "owned": [],
            "can_edit": [],
            "can_comment": [],
            "can_view": []
        }
        
        for doc in documents:
            file_id = doc.get('file_id', '')
            file_name = doc.get('file_name', '')
            source = doc.get('source', 'google_drive')
            permissions = doc.get('permissions', [])
            
            # Check if file is currently deleted
            history = doc.get('history', [])
            if history:
                sorted_history = sorted(history, key=lambda x: x.get('details', {}).get('timestamp', ''), reverse=True)
                latest_entry = sorted_history[0] if sorted_history else {}
                latest_details = latest_entry.get('details', {})
                
                # Skip files that are currently deleted
                if latest_details.get('type') == 'file_deleted':
                    continue
            
            # Find user's role in this file
            user_role = None
            for perm in permissions:
                if perm.get('emailAddress', '').lower() == email.lower():
                    user_role = perm.get('role', '').lower()
                    break
            
            if user_role:
                file_info = {
                    "id": file_id,
                    "name": file_name,
                    "source": source,
                    "role": user_role
                }
                
                # Add to appropriate category based on permission level
                if user_role == 'owner':
                    files["owned"].append(file_info)
                elif user_role == 'writer':
                    files["can_edit"].append(file_info)
                elif user_role == 'commenter':
                    files["can_comment"].append(file_info)
                elif user_role == 'reader':
                    files["can_view"].append(file_info)
        
        # Sort each category by name
        for category in files.values():
            category.sort(key=lambda x: x['name'].lower())
        
        app.logger.info(f"Fetched files for user {email} from MongoDB")
        return files
        
    except Exception as e:
        app.logger.error(f"Error fetching user files from MongoDB: {str(e)}\n{traceback.format_exc()}")
        return {"owned": [], "can_edit": [], "can_comment": [], "can_view": []}

def update_mongodb_sensitivity_score(file_id, sensitivity_data):
    """
    Update sensitivity score for a specific file in MongoDB.
    Maintains both current score and historical tracking of sensitivity changes.
    """
    try:
        # Find the document for this file
        doc = collection.find_one({"file_id": file_id})
        
        if not doc:
            app.logger.warning(f"File {file_id} not found in MongoDB for sensitivity update")
            return False
        
        # Prepare the sensitivity entry with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        sensitivity_entry = {
            "timestamp": timestamp,
            "sensitivity_score": sensitivity_data.get('sensitivity_score', 0),
            "risk_level": sensitivity_data.get('risk_level', 'NONE'),
            "high_sensitivity": sensitivity_data.get('high_sensitivity', 0),
            "moderate_sensitivity": sensitivity_data.get('moderate_sensitivity', 0),
            "low_sensitivity": sensitivity_data.get('low_sensitivity', 0),
            "total_entities": sensitivity_data.get('total_entities', 0),
            "scan_type": "presidio_scan",
            "modified_by": sensitivity_data.get('modified_by', 'Unknown')
        }
        
        # Update the document with both current state and historical data
        update_result = collection.update_one(
            {"file_id": file_id},
            {
                "$set": {
                    "current_sensitivity_score": sensitivity_entry["sensitivity_score"],
                    "current_risk_level": sensitivity_entry["risk_level"],
                    "last_sensitivity_scan": timestamp
                },
                "$push": {
                    "sensitivity_history": sensitivity_entry
                }
            }
        )
        
        if update_result.modified_count > 0:
            app.logger.info(f"Updated sensitivity score for file {file_id}: {sensitivity_data}")
            return True
        else:
            app.logger.warning(f"No documents updated for file {file_id} sensitivity score")
            return False
            
    except Exception as e:
        app.logger.error(f"Error updating sensitivity score in MongoDB: {str(e)}\n{traceback.format_exc()}")
        return False

def get_mongodb_sensitive_files():
    """
    Get sensitive files data from MongoDB.
    Processes sensitivity history to create dashboard entries with score change tracking.
    """
    try:
        # Find all documents that have sensitivity history
        documents = list(collection.find({"sensitivity_history": {"$exists": True, "$ne": []}}))
        
        sensitive_files = []
        
        for doc in documents:
            file_id = doc.get('file_id', '')
            file_name = doc.get('file_name', '')
            owner = doc.get('owner', '')
            source = doc.get('source', 'google_drive')
            sensitivity_history = doc.get('sensitivity_history', [])
            
            # Skip if no sensitivity history
            if not sensitivity_history:
                continue
            
            # Sort sensitivity history by timestamp (newest first)
            sensitivity_history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            # Create entries for each sensitivity scan in the history
            for i, scan in enumerate(sensitivity_history):
                # Calculate score change from previous scan
                score_change = 0
                previous_score = None
                
                if i < len(sensitivity_history) - 1:
                    # There's a previous scan - calculate delta
                    previous_scan = sensitivity_history[i + 1]
                    current_score = scan.get('sensitivity_score', 0)
                    prev_score = previous_scan.get('sensitivity_score', 0)
                    score_change = current_score - prev_score
                    previous_score = prev_score
                
                # Create a log entry in the format expected by the frontend
                sensitive_file = {
                    'file_id': file_id,
                    'file_name': file_name,
                    'owner': owner,
                    'timestamp': scan.get('timestamp', ''),
                    'sensitivity_score': f"{scan.get('sensitivity_score', 0)}/100",
                    'risk_level': scan.get('risk_level', 'NONE'),
                    'high_sensitivity': str(scan.get('high_sensitivity', 0)),
                    'moderate_sensitivity': str(scan.get('moderate_sensitivity', 0)),
                    'low_sensitivity': str(scan.get('low_sensitivity', 0)),
                    'total_entities': str(scan.get('total_entities', 0)),
                    'details': {
                        'type': 'sensitivity_scan',
                        'source': source,
                        'file_name': file_name,
                        'modified_by': scan.get('modified_by', {'name': 'Unknown', 'email': 'unknown@example.com'}),
                        'changes': [{
                            'type': 'sensitivity_scan',
                            'score': str(scan.get('sensitivity_score', 0)),
                            'risk_level': scan.get('risk_level', 'NONE'),
                            'high_sensitivity': str(scan.get('high_sensitivity', 0)),
                            'moderate_sensitivity': str(scan.get('moderate_sensitivity', 0)),
                            'low_sensitivity': str(scan.get('low_sensitivity', 0)),
                            'total_entities': str(scan.get('total_entities', 0)),
                            'score_change': str(score_change),
                            'previous_score': str(previous_score) if previous_score is not None else None
                        }]
                    }
                }
                
                sensitive_files.append(sensitive_file)
        
        # Sort by timestamp (newest first)
        sensitive_files.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        app.logger.info(f"Fetched {len(sensitive_files)} sensitive file entries from MongoDB")
        return sensitive_files
        
    except Exception as e:
        app.logger.error(f"Error fetching sensitive files from MongoDB: {str(e)}\n{traceback.format_exc()}")
        return []

# Function to run saas_file_monitor.py asynchronously
async def run_saas_file_monitor():
    """
    Execute saas_file_monitor.py script in a separate process for file monitoring.
    Uses virtual environment if available, falls back to system Python.
    """
    try:
        # Use the absolute path to the script
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saas_file_monitor.py')
        app.logger.info(f"Executing saas_file_monitor.py at path: {script_path}")
        
        # Attempt to use venv if it exists, otherwise fall back to system python
        venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv', 'Scripts', 'python.exe')
        python_exe = venv_python if os.path.exists(venv_python) else "python"
        
        process = await asyncio.create_subprocess_exec(
            python_exe,
            script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        app.logger.info(f"saas_file_monitor.py stdout:\n{stdout.decode()}")
        if stderr:
            app.logger.error(f"saas_file_monitor.py stderr:\n{stderr.decode()}")
    except Exception as e:
        app.logger.error(f"Error running saas_file_monitor.py: {str(e)}\n{traceback.format_exc()}")

# Function to run presidio_scanner.py asynchronously
async def run_presidio_scanner():
    """
    Execute presidio_scanner.py in a separate process for sensitivity analysis.
    Runs after saas_file_monitor.py to scan files for sensitive data using Presidio.
    """
    try:
        # Use the absolute path to the script
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pres_presidio_scanner.py')
        app.logger.info(f"Executing presidio_scanner.py at path: {script_path}")
        
        # Attempt to use venv if it exists, otherwise fall back to system python
        venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv', 'Scripts', 'python.exe')
        python_exe = venv_python if os.path.exists(venv_python) else "python"
        
        process = await asyncio.create_subprocess_exec(
            python_exe,
            script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        app.logger.info(f"presidio_scanner.py stdout:\n{stdout.decode()}")
        if stderr:
            app.logger.error(f"presidio_scanner.py stderr:\n{stderr.decode()}")
    except Exception as e:
        app.logger.error(f"Error running presidio_scanner.py: {str(e)}\n{traceback.format_exc()}")

def read_syslog(max_lines=1000):
    """
    Read and parse the syslog file for legacy log data.
    Handles both JSON log entries and embedded Dropbox notifications.
    """
    logs = []
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'syslog.log')
        if not os.path.exists(log_path):
            app.logger.warning(f"Syslog file not found at {log_path}")
            return logs

        line_count = 0
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    line = line.strip()
                    if not line:
                        continue

                    # Skip header lines and non-JSON lines
                    if line.startswith('===') or line.startswith('Real-time') or \
                       line.startswith('Successfully') or line.startswith('Monitoring') or \
                       line.startswith('Error') or line.startswith('Would send email') or \
                       line.startswith('Google Drive') or line.startswith('All monitoring') or \
                       line.startswith('Subject:') or line.startswith('Body:') or \
                       line.startswith('The following') or line.startswith('File') or \
                       line.startswith('New file') or line.startswith('Owner:') or \
                       line.startswith('Initial permissions') or line.startswith('Timestamp:') or \
                       line.startswith('-') or line.startswith('removed') or line.startswith('  '):
                        
                        # Check specifically for Dropbox email notifications that contain detailed changes
                        if "Subject: Dropbox Change:" in line:
                            # This is a Dropbox change email notification - capture file info
                            filename = line.replace("Subject: Dropbox Change:", "").strip()
                            path = ""
                            file_id = ""
                            changes = {}
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # Read the next few lines to get details
                            next_lines = []
                            for _ in range(10):  # Read up to 10 lines to find relevant info
                                try:
                                    next_line = next(f).strip()
                                    next_lines.append(next_line)
                                    
                                    if "Path:" in next_line:
                                        path = next_line.replace("Path:", "").strip()
                                    elif "File ID:" in next_line:
                                        file_id = next_line.replace("File ID:", "").strip()
                                    elif "Timestamp:" in next_line:
                                        timestamp = next_line.replace("Timestamp:", "").strip()
                                    elif "Changes:" in next_line:
                                        # The changes details follow
                                        change_lines = []
                                        for _ in range(5):  # Read up to 5 change lines
                                            try:
                                                change_line = next(f).strip()
                                                if change_line.startswith('-'):
                                                    change_parts = change_line.lstrip('- ').split(': Changed from ')
                                                    if len(change_parts) >= 2:
                                                        key = change_parts[0].strip()
                                                        values = change_parts[1].replace("'", "").split(' to ')
                                                        old_val = values[0].strip()
                                                        new_val = values[1].strip() if len(values) > 1 else None
                                                        changes[key] = {"old": old_val, "new": new_val}
                                            except StopIteration:
                                                break
                                except StopIteration:
                                    break
                            
                            # Create a log entry for this Dropbox change
                            if file_id:
                                log_entry = {
                                    "file_id": file_id,
                                    "file_name": filename,
                                    "owner": "Dropbox User",
                                    "timestamp": timestamp,
                                    "details": {
                                        "source": "dropbox",
                                        "file_name": filename,
                                        "path": path,
                                        "type": "file_deleted" if "status" in changes and changes["status"]["new"] == "deleted" else "changes",
                                        "changes": changes,
                                        "modified_by": {
                                            "name": "Dropbox System",
                                            "email": "notifications@dropbox.com"
                                        }
                                    }
                                }
                                logs.append(log_entry)
                                line_count += 1
                        
                        continue

                    # Special handling for Dropbox notification lines embedded in logs
                    if "Subject: Dropbox Change:" in line:
                        continue  # Skip, this will be handled above

                    # Parse JSON logs
                    if line.startswith('{') and line.endswith('}'):
                        log_data = json.loads(line)
                        
                        # Ensure all logs have details object and source field
                        if 'details' not in log_data:
                            log_data['details'] = {}
                        
                        # Determine the source based on the structure
                        if 'details' in log_data:
                            # Set default source as google_drive if not specified
                            if 'source' not in log_data['details']:
                                # Check if it's a Dropbox log based on content
                                if ('file_id' in log_data and log_data['file_id'].startswith('id:')) or \
                                   ('path' in log_data['details'] and 'dropbox' in log_data['details'].get('path', '').lower()):
                                    log_data['details']['source'] = 'dropbox'
                                else:
                                    log_data['details']['source'] = 'google_drive'
                            
                            # Ensure there's a 'modified_by' field
                            if 'modified_by' not in log_data['details']:
                                # Try to extract from changes if it exists
                                if 'changes' in log_data['details'] and isinstance(log_data['details']['changes'], list):
                                    for change in log_data['details']['changes']:
                                        if 'modified_by' in change:
                                            log_data['details']['modified_by'] = change['modified_by']
                                            break
                                    else:
                                        # Default if not found in changes
                                        log_data['details']['modified_by'] = {
                                            'name': 'Unknown',
                                            'email': 'unknown@example.com'
                                        }
                                else:
                                    # Default if no changes field
                                    log_data['details']['modified_by'] = {
                                        'name': 'Unknown',
                                        'email': 'unknown@example.com'
                                    }
                        
                        logs.append(log_data)
                        line_count += 1
                        
                        if max_lines and line_count >= max_lines:
                            break
                except json.JSONDecodeError as json_err:
                    app.logger.warning(f"Failed to parse JSON in line: {line[:100]}... Error: {json_err}")
                    continue
                except Exception as e:
                    app.logger.warning(f"Error parsing log line: {str(e)}")
                    continue

        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return logs
    except Exception as e:
        app.logger.error(f"Error reading syslog: {str(e)}\n{traceback.format_exc()}")
        return []

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

@app.route('/file-based')
def file_based():
    """Render the file-based view page."""
    return render_template('file_based.html')

@app.route('/user-based')
def user_based():
    """Render the user-based view page."""
    return render_template('user_based.html')



@app.route('/blocked-users')
def blocked_users_page():
    return render_template('blocked_users.html')

@app.route('/api/blocked-users')
def get_blocked_users():
    """Get all blocked users from MongoDB EWMAconfig.blockedUsers collection"""
    try:
        
        db = client['EWMAconfig']
        collection = db['blockedUsers']
        
        # Get the blocked users document
        blocked_doc = collection.find_one()
        
        if not blocked_doc:
            # Return empty arrays if no document exists
            return jsonify({
                "sensitiveCount": [],
                "unsharedAccess": [],
                "downloadCount": [],
                "deleteCount": []
            })
        
        # Remove MongoDB _id field
        blocked_doc.pop('_id', None)
        
        return jsonify(blocked_doc)
        
    except Exception as e:
        print(f"Error fetching blocked users: {e}")
        return jsonify({"error": str(e)}), 500
@app.route('/api/unblock-user', methods=['POST'])
def unblock_user():
    """Unblock a user by removing them from blockedUsers and resetting their EWMA scores in userConfig."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        email = data.get('email')
        activity_types = data.get('activity_types', [])  # List of activity types to unblock
        
        if not email:
            return jsonify({"error": "email is required"}), 400
        
        if not activity_types:
            return jsonify({"error": "activity_types is required"}), 400
        
        app.logger.info(f"Unblocking user {email} for activities: {activity_types}")
        
        # MongoDB connection
        ewma_config_db = client['EWMAconfig']
        
        # ===== STEP 1: Get initial EWMA values from usersInit =====
        users_init_collection = ewma_config_db['usersInit']
        init_doc = users_init_collection.find_one()
        
        if not init_doc or 'general' not in init_doc:
            app.logger.error("usersInit document not found or invalid")
            return jsonify({
                "status": "error",
                "message": "Initial EWMA configuration not found in database"
            }), 500
        
        general_config = init_doc['general']
        app.logger.info(f"✅ Loaded initial EWMA config from usersInit")
        
        # ===== STEP 2: Remove from blockedUsers collection =====
        blocked_users_collection = ewma_config_db['blockedUsers']
        
        # Map activity types to field names
        activity_field_map = {
            'sensitiveCount': 'sensitiveCount',
            'unsharedAccess': 'unsharedAccess',
            'downloadCount': 'downloadCount',
            'deleteCount': 'deleteCount'
        }
        
        # Remove user from each activity type's blocked list
        for activity_type in activity_types:
            field_name = activity_field_map.get(activity_type)
            if field_name:
                result = blocked_users_collection.update_one(
                    {},  # Match the single document
                    {"$pull": {field_name: email}}  # Remove email from array
                )
                app.logger.info(f"✅ Removed {email} from blockedUsers.{field_name} (modified: {result.modified_count})")
        
        # ===== STEP 3: Reset EWMA scores in userConfig collection =====
        user_config_collection = ewma_config_db['usersConfig']
        
        # Build update query to reset specific activity types
        update_fields = {}
        for activity_type in activity_types:
            field_name = activity_field_map.get(activity_type)
            if field_name and field_name in general_config:
                # Get the initial values for this activity type from usersInit
                initial_values = general_config[field_name]
                
                # Convert MongoDB NumberInt to regular Python int/float
                reset_values = {}
                for time_window, value in initial_values.items():
                    if isinstance(value, dict) and '$numberInt' in value:
                        reset_values[time_window] = int(value['$numberInt'])
                    elif isinstance(value, dict) and '$numberDouble' in value:
                        reset_values[time_window] = float(value['$numberDouble'])
                    else:
                        reset_values[time_window] = value
                
                update_fields[field_name] = reset_values
                app.logger.info(f"📊 Will reset userConfig.{field_name} to: {reset_values}")
        
        if update_fields:
            # Update the user's EWMA scores in userConfig
            result = user_config_collection.update_one(
                {"email": email},
                {"$set": update_fields},
                upsert=True  # Create document if doesn't exist
            )
            
            if result.modified_count > 0:
                app.logger.info(f"✅ Reset EWMA scores in userConfig for {email}")
            elif result.upserted_id:
                app.logger.info(f"✅ Created new userConfig document for {email}")
            else:
                app.logger.warning(f"⚠️ No changes made to userConfig for {email}")
        
        app.logger.info(f"🎉 Successfully unblocked {email} for {len(activity_types)} activity type(s)")
        
        return jsonify({
            "status": "success",
            "message": f"User {email} unblocked for {len(activity_types)} activity type(s)",
            "email": email,
            "activities_unblocked": activity_types,
            "ewma_reset": update_fields
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error unblocking user: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route('/api/files')
def get_all_files():
    """API endpoint to get list of all files from MongoDB."""
    try:
        files = get_mongodb_files()
        return jsonify(files)
    except Exception as e:
        app.logger.error(f"Error getting file list: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/file-permissions/<file_id>')
def get_file_permissions(file_id):
    """API endpoint to get permissions for a specific file from MongoDB."""
    try:
        result = get_mongodb_file_permissions(file_id)
        if result is None:
            return jsonify({"error": "File not found"}), 404
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error getting file permissions: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/user-files/<email>')
def get_user_files(email):
    """API endpoint to get all files and permissions for a specific user from MongoDB."""
    try:
        files = get_mongodb_user_files(email)
        return jsonify(files)
    except Exception as e:
        app.logger.error(f"Error getting user files: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """API endpoint to get activity logs from MongoDB."""
    try:
        logs = get_mongodb_logs()  # Use MongoDB instead of syslog
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"Error reading logs: {str(e)}\n{traceback.format_exc()}")
        return jsonify([])

@app.route('/api/stats')
def get_stats():
    """
    API endpoint to get comprehensive statistics from MongoDB logs.
    Calculates metrics for Google Drive and Dropbox activity including recent changes.
    """
    try:
        # Read logs from MongoDB
        logs = get_mongodb_logs()  # Use MongoDB instead of syslog
        
        if not logs:
            # Return empty stats if no logs found
            return jsonify({
                'google_drive': {
                    'total_changes': 0,
                    'new_files': 0,
                    'deleted_files': 0,
                    'permission_changes': 0,
                    'last_24h': 0
                },
                'dropbox': {
                    'total_changes': 0,
                    'new_files': 0,
                    'deleted_files': 0,
                    'last_24h': 0
                },
                'total': {
                    'total_changes': 0,
                    'last_24h': 0
                },
                'gdrive_logs': [],
                'dropbox_logs': []
            })
        
        # Separate logs by source
        gdrive_logs = []
        dropbox_logs = []
        
        for log in logs:
            try:
                source = log.get('details', {}).get('source', 'google_drive')
                if source == 'dropbox':
                    dropbox_logs.append(log)
                else:
                    gdrive_logs.append(log)
            except Exception as e:
                app.logger.warning(f"Error sorting log by source: {e}")
        
        # Google Drive stats - only from actual logs
        gdrive_total = len(gdrive_logs)
        gdrive_new_files = sum(1 for log in gdrive_logs if log.get('details', {}).get('type') == 'new_file')
        gdrive_deleted_files = sum(1 for log in gdrive_logs if log.get('details', {}).get('type') == 'file_deleted')
        gdrive_permission_changes = sum(1 for log in gdrive_logs 
                                      if log.get('details', {}).get('type') == 'changes' 
                                      and log.get('details', {}).get('changes', []))
        
        # Dropbox stats - only from actual logs
        dropbox_total = len(dropbox_logs)
        dropbox_new_files = sum(1 for log in dropbox_logs 
                               if (log.get('details', {}).get('type') == 'changes' 
                                  and 'status' not in log.get('details', {}).get('changes', {})))
        dropbox_deleted_files = sum(1 for log in dropbox_logs if log.get('details', {}).get('type') == 'file_deleted')
        
        # Recent activity (last 24 hours) - only from actual logs
        try:
            last_24h = datetime.now() - timedelta(hours=24)
            
            # Count Google Drive logs in the last 24 hours
            gdrive_recent = 0
            for log in gdrive_logs:
                try:
                    if 'timestamp' in log:
                        log_time = datetime.strptime(log['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                        if log_time > last_24h:
                            gdrive_recent += 1
                except Exception as e:
                    app.logger.warning(f"Error parsing timestamp in Google Drive log: {e}")
            
            # Count Dropbox logs in the last 24 hours
            dropbox_recent = 0
            for log in dropbox_logs:
                try:
                    if 'timestamp' in log:
                        log_time = datetime.strptime(log['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                        if log_time > last_24h:
                            dropbox_recent += 1
                except Exception as e:
                    app.logger.warning(f"Error parsing timestamp in Dropbox log: {e}")
                    
        except Exception as e:
            # Default to zero if calculation fails
            app.logger.error(f"Error calculating recent logs: {e}")
            gdrive_recent = 0
            dropbox_recent = 0
        
        # Combined stats - only from actual logs
        total_changes = gdrive_total + dropbox_total
        total_recent = gdrive_recent + dropbox_recent
        
        # Return stats with logs for chart rendering - no sample data
        response_data = {
            'google_drive': {
                'total_changes': gdrive_total,
                'new_files': gdrive_new_files,
                'deleted_files': gdrive_deleted_files,
                'permission_changes': gdrive_permission_changes,
                'last_24h': gdrive_recent
            },
            'dropbox': {
                'total_changes': dropbox_total,
                'new_files': dropbox_new_files,
                'deleted_files': dropbox_deleted_files,
                'last_24h': dropbox_recent
            },
            'total': {
                'total_changes': total_changes,
                'last_24h': total_recent
            },
            'gdrive_logs': gdrive_logs,
            'dropbox_logs': dropbox_logs
        }
        
        return jsonify(response_data)
    except Exception as e:
        app.logger.error(f"Error calculating stats: {str(e)}\n{traceback.format_exc()}")
        # Return empty structure on error - no sample data
        return jsonify({
            'error': str(e),
            'google_drive': {'total_changes': 0, 'new_files': 0, 'deleted_files': 0, 'permission_changes': 0, 'last_24h': 0},
            'dropbox': {'total_changes': 0, 'new_files': 0, 'deleted_files': 0, 'last_24h': 0},
            'total': {'total_changes': 0, 'last_24h': 0},
            'gdrive_logs': [],
            'dropbox_logs': []
        })

@app.route('/api/users')
def get_users():
    """Get list of all users from MongoDB."""
    try:
        users = get_mongodb_users()
        # Convert to the format expected by the frontend
        user_list = [{"email": user["email"], "name": user["name"]} for user in users]
        return jsonify(user_list)
    except Exception as e:
        app.logger.error(f"Error getting users: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/user-permissions/<email>')
def get_user_permissions(email):
    """Get all file permissions for a specific user from MongoDB."""
    try:
        files = get_mongodb_user_files(email)
        
        # Convert the structure to match what the frontend expects
        result = {
            'owned_files': files.get('owned', []),
            'editable_files': files.get('can_edit', []),
            'commentable_files': files.get('can_comment', []),
            'viewable_files': files.get('can_view', [])
        }
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error getting user permissions: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

def get_credentials():
    """
    Get valid user credentials from storage.
    Handles token refresh and validation for Google Drive API access.
    """
    creds = None
    if os.path.exists("token.json"):
        # Load from our custom token format
        with open("token.json", "r") as token_file:
            token_data = json.load(token_file)
        
        creds = Credentials(
            token=token_data['token'],
            refresh_token=token_data.get('refresh_token'),
            token_uri=token_data['token_uri'],
            client_id=token_data['client_id'],
            client_secret=token_data['client_secret'],
            scopes=token_data['scopes']
        )
        
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Update token.json with refreshed credentials
            token_data = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
            with open("token.json", "w") as token_file:
                json.dump(token_data, token_file, indent=2)
        else:
            # Redirect to manual authentication
            raise Exception("Authentication required. Please visit /drive to authenticate.")
        
    return creds

@app.route('/drive')
def drive_auth():
    """
    Handle Google Drive authentication flow initialization.
    Creates authorization URL and manages OAuth flow state.
    """
    try:
        # Use localhost for authentication
        redirect_uri = 'http://localhost:5001/auth/google/callback'
        app.logger.info(f"Using redirect URI: {redirect_uri}")
        
        # Check if credentials.json is web or installed app
        with open('credentials.json', 'r') as f:
            creds_data = json.load(f)
        
        if 'web' in creds_data:
            # Web application flow
            flow = Flow.from_client_secrets_file(
                'credentials.json',
                scopes=SCOPES
            )
            flow.redirect_uri = redirect_uri
        else:
            # Installed application flow
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json',
                SCOPES,
                redirect_uri=redirect_uri
            )
        
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        # Store flow state for callback
        flow_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flow_state.json')
        with open(flow_path, 'w') as f:
            json.dump({
                'client_config': flow.client_config,
                'redirect_uri': flow.redirect_uri,
                'scopes': SCOPES,
                'state': state
            }, f)
        
        return jsonify({'auth_url': auth_url})
    except Exception as e:
        app.logger.error(f"Error in drive_auth: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/auth/google/callback')
def google_callback():
    """
    Handle Google OAuth callback and token exchange.
    Processes authorization code and saves credentials for future use.
    """
    try:
        # Get authorization code from callback
        code = request.args.get('code')
        state = request.args.get('state')
        if not code:
            return jsonify({'error': 'No code provided'}), 400
        
        # Load flow state
        flow_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flow_state.json')
        if not os.path.exists(flow_path):
            return jsonify({'error': 'Flow state not found. Please restart authentication.'}), 400
        
        with open(flow_path, 'r') as f:
            flow_data = json.load(f)
        
        # Verify state parameter
        if state != flow_data.get('state'):
            return jsonify({'error': 'Invalid state parameter'}), 400
        
        # Check if credentials.json is web or installed app
        with open('credentials.json', 'r') as f:
            creds_data = json.load(f)
        
        if 'web' in creds_data:
            # Web application flow - recreate from credentials.json
            flow = Flow.from_client_secrets_file(
                'credentials.json',
                scopes=None  # Don't enforce scopes, accept what Google gives us
            )
        else:
            # Installed application flow - recreate from credentials.json
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json',
                scopes=None  # Don't enforce scopes, accept what Google gives us
            )
        
        flow.redirect_uri = flow_data['redirect_uri']
        
        # Exchange the code for tokens
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        app.logger.info(f"Received scopes: {credentials.scopes}")
        
        # Save credentials to token.json
        token_data = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes  # Use the actual scopes granted
        }
        
        with open("token.json", "w") as token:
            json.dump(token_data, token, indent=2)
        
        # Clean up flow state
        if os.path.exists(flow_path):
            os.remove(flow_path)
        
        app.logger.info("Google Drive authentication successful. Token saved.")
        
        # Set up watch request using environment variables
        webhook_url = os.getenv('WEBHOOK_URL')
        folder_id = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
        
        if webhook_url and folder_id:
            # Use your watch_google_drive function
            watch_response = watch_google_drive(folder_id, webhook_url)
            if watch_response and watch_response.get('status') == 'success':
                return jsonify({
                    'status': 'success',
                    'message': 'Authentication successful! Google Drive monitoring is now active.',
                    'scopes_granted': credentials.scopes,
                    'watch_response': watch_response
                })
            else:
                return jsonify({
                    'status': 'success',
                    'message': 'Authentication successful! Warning: Could not set up Google Drive monitoring.',
                    'scopes_granted': credentials.scopes,
                    'watch_error': watch_response.get('message', 'Unknown error')
                })
        else:
            return jsonify({
                'status': 'success',
                'message': 'Authentication successful! Set WEBHOOK_URL and GOOGLE_DRIVE_FOLDER_ID to enable monitoring.',
                'scopes_granted': credentials.scopes
            })
            
    except Exception as e:
        app.logger.error(f"Error in google_callback: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Google Drive webhook route to handle notifications
@app.route('/webhooks/drive', methods=['POST'])
def drive_webhook():
    """
    Handle incoming webhook notifications from Google Drive.
    Processes file change notifications and triggers appropriate scanning workflows.
    """
    try:
        app.logger.info("==================================================")
        app.logger.info("NEW WEBHOOK REQUEST RECEIVED")
        app.logger.info("==================================================")
        app.logger.info(f"Headers: {dict(request.headers)}")
        app.logger.info(f"Body: {request.get_data(as_text=True)}")
        
        # Run saas_file_monitor.py in a separate thread with throttling
        saas_file_monitor_result = run_saas_file_monitor_throttled()
        
        # If saas_file_monitor started successfully, also run presidio scanner after a short delay
        if saas_file_monitor_result and saas_file_monitor_result.get('status') == 'started':
            # Add a slight delay to ensure saas_file_monitor has time to update syslog
            def delayed_presidio_scan():
                time.sleep(PRESIDIO_DELAY_SECONDS)  # Wait PRESIDIO_DELAY_SECONDS seconds for saas_file_monitor to finish and update logs
                app.logger.info("Running presidio scanner after saas_file_monitor execution")
                run_presidio_scanner_throttled()
                update_all_user_count()
                
            # Start a thread for the delayed presidio scan
            presidio_thread = threading.Thread(target=delayed_presidio_scan)
            presidio_thread.daemon = True
            presidio_thread.start()
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        app.logger.error(f"Error processing webhook: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Apply throttling to the saas_file_monitor.py execution (runs at most once every 15 seconds)
@throttle(SAAS_MONITOR_THROTTLE_SECONDS)
def run_saas_file_monitor_throttled():
    """
    Run saas_file_monitor.py with throttling (max once every 15 seconds).
    Prevents excessive API calls during high-frequency file changes.
    """
    app.logger.info(f"Running saas_file_monitor.py (throttled to once every {SAAS_MONITOR_THROTTLE_SECONDS} seconds)")
    # Create a new thread to run the async function
    def run_async_task():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_saas_file_monitor())
        loop.close()
    
    # Start a new thread for the async task
    thread = threading.Thread(target=run_async_task)
    thread.daemon = True  # Thread will exit when the main program exits
    thread.start()
    return {"status": "started"}

# Apply throttling to the presidio_scanner.py execution (runs at most once every 30 seconds)
@throttle(PRESIDIO_SCANNER_THROTTLE_SECONDS)
def run_presidio_scanner_throttled():
    """
    Run presidio_scanner.py with throttling (max once every 30 seconds).
    Prevents overlapping sensitivity scans which are computationally expensive.
    """
    app.logger.info(f"Running presidio_scanner.py (throttled to once every {PRESIDIO_SCANNER_THROTTLE_SECONDS} seconds)")
    # Create a new thread to run the async function
    def run_async_task():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_presidio_scanner())
        loop.close()
    
    # Start a new thread for the async task
    thread = threading.Thread(target=run_async_task)
    thread.daemon = True  # Thread will exit when the main program exits
    thread.start()
    return {"status": "started"}

# Function to set up Google Drive watch
def watch_google_drive(folder_id, webhook_url):
    """
    Set up a watch request for the entire Google Drive.
    (folder_id is ignored for compatibility with existing function calls)
    Configures webhook notifications for file changes in the entire Drive.
    """
    try:
        app.logger.info(f"Setting up global watch (ignoring folder_id={folder_id}) with webhook URL: {webhook_url}")

        # Check if token.json exists
        token_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'token.json')
        if not os.path.exists(token_path):
            app.logger.warning("token.json not found. Google Drive authentication required.")
            return {"status": "error", "message": "Authentication required. Please visit /drive to authenticate."}

        # Generate a unique channel ID
        channel_id = f"channel-{int(time.time())}-{os.urandom(4).hex()}"

        # Watch request body
        watch_request = {
            'id': channel_id,
            'type': 'web_hook',
            'address': webhook_url,
            'ttl': '3600'  # 1 hour TTL
        }

        app.logger.info(f"Watch request details:")
        app.logger.info(f"- Channel ID: {channel_id}")
        app.logger.info(f"- Webhook URL: {webhook_url}")

        # Load credentials
        app.logger.info(f"Loading credentials from: {token_path}")
        with open(token_path, 'r') as token_file:
            token_data = json.load(token_file)

        creds = Credentials(
            token=token_data['token'],
            refresh_token=token_data['refresh_token'],
            token_uri=token_data['token_uri'],
            client_id=token_data['client_id'],
            client_secret=token_data['client_secret'],
            scopes=token_data['scopes']
        )

        # Refresh token if expired
        if creds.expired:
            app.logger.info("Token expired, refreshing...")
            creds.refresh(Request())
            token_data['token'] = creds.token
            token_data['expiry'] = creds.expiry.isoformat() if creds.expiry else None
            with open(token_path, 'w') as token_file:
                json.dump(token_data, token_file)

        # Build Drive service
        service = build('drive', 'v3', credentials=creds)
        app.logger.info("Google Drive service created successfully")

        # Get the Start Page Token (for global Drive changes)
        start_page_token = service.changes().getStartPageToken().execute().get('startPageToken')
        app.logger.info(f"Start page token: {start_page_token}")

        # Send the watch request for entire Drive changes
        app.logger.info("Sending global watch request to Google Drive API...")
        response = service.changes().watch(
            pageToken=start_page_token,
            body=watch_request
        ).execute()

        app.logger.info(f"Global watch request successful: {json.dumps(response, indent=2)}")

        # Return consistent output
        return {
            "status": "success",
            "channel_id": channel_id,
            "folder_id": folder_id,
            "webhook_url": webhook_url,
            "ttl": 3600,
            "api_response": response
        }

    except Exception as e:
        app.logger.error(f"Error setting up global watch request: {str(e)}\n{traceback.format_exc()}")
        return {"status": "error", "message": str(e)}


@app.route('/api/scan-files', methods=['POST'])
def manual_scan_files():
    """Manually trigger a scan of modified files with presidio."""
    try:
        app.logger.info("Manual scan of files requested")
        result = run_presidio_scanner_throttled()
        if result:
            return jsonify({"status": "success", "message": "File scan started"}), 200
        else:
            return jsonify({"status": "throttled", "message": "Scanner is throttled, try again later"}), 429
    except Exception as e:
        app.logger.error(f"Error starting manual scan: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e)}), 500

def read_presidio_log(max_lines=1000):
    """Read and parse the presidio scan log file."""
    try:
        logs = []
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'presidio_scan.log')
        app.logger.info(f"Reading presidio log from: {log_path}")
        
        # Store previous scores for each file to track changes
        file_history = {}
        
        with open(log_path, 'r') as f:
            current_scan = None
            for line in f:
                line = line.strip()
                
                if line.startswith('FILE SCAN:'):
                    if current_scan and current_scan.get('file_id'):  # Only process if we have a valid file scan
                        # Create the changes structure if it doesn't exist
                        if 'details' not in current_scan:
                            current_scan['details'] = {'changes': [{}]}
                        elif 'changes' not in current_scan['details']:
                            current_scan['details']['changes'] = [{}]
                        
                        changes = current_scan['details']['changes'][0]
                        file_id = current_scan['file_id']
                        
                        # Get the current score from the scan data
                        current_score = int(current_scan.get('sensitivity_score', '0').split('/')[0])
                        
                        # Calculate score change from previous scan
                        if file_id in file_history:
                            prev_score = file_history[file_id]['score']
                            changes['score_change'] = str(current_score - prev_score)
                            changes['previous_score'] = str(prev_score)
                        else:
                            changes['score_change'] = '0'
                            changes['previous_score'] = None
                        
                        # Update file history
                        file_history[file_id] = {
                            'score': current_score,
                            'timestamp': current_scan['timestamp']
                        }
                        
                        # Copy scan data to changes
                        changes['score'] = str(current_score)
                        changes['risk_level'] = current_scan.get('risk_level', 'NONE')
                        changes['high_sensitivity'] = current_scan.get('high_sensitivity', '0')
                        changes['moderate_sensitivity'] = current_scan.get('moderate_sensitivity', '0')
                        changes['low_sensitivity'] = current_scan.get('low_sensitivity', '0')
                        changes['total_entities'] = current_scan.get('total_entities', '0')
                        
                        # Set type for consistency
                        changes['type'] = 'sensitivity_scan'
                        
                        logs.append(current_scan)
                    
                    # Start new scan
                    current_scan = {
                        'timestamp': None,
                        'details': {
                            'type': 'scan',
                            'source': 'google_drive',
                            'changes': [{}]
                        },
                        'file_id': None
                    }
                
                if current_scan:
                    if line.startswith('FILE SCAN:'):
                        current_scan['timestamp'] = line.split('FILE SCAN: ')[1]
                    elif line.startswith('FileID:'):
                        current_scan['file_id'] = line.split('FileID: ')[1]
                    elif line.startswith('FileName:'):
                        current_scan['details']['file_name'] = line.split('FileName: ')[1]
                    elif line.startswith('Owner:'):
                        current_scan['owner'] = line.split('Owner: ')[1]
                    elif line.startswith('LastModifiedBy:'):
                        current_scan['details']['modified_by'] = line.split('LastModifiedBy: ')[1]
                    elif line.startswith('SensitivityScore:'):
                        current_scan['sensitivity_score'] = line.split('SensitivityScore: ')[1]
                    elif line.startswith('RiskLevel:'):
                        current_scan['risk_level'] = line.split('RiskLevel: ')[1]
                    elif line.startswith('HighSensitivity:'):
                        current_scan['high_sensitivity'] = line.split('HighSensitivity: ')[1]
                    elif line.startswith('ModerateSensitivity:'):
                        current_scan['moderate_sensitivity'] = line.split('ModerateSensitivity: ')[1]
                    elif line.startswith('LowSensitivity:'):
                        current_scan['low_sensitivity'] = line.split('LowSensitivity: ')[1]
                    elif line.startswith('TotalEntities:'):
                        current_scan['total_entities'] = line.split('TotalEntities: ')[1]
                    elif line.startswith('SCAN SUMMARY:'):
                        # Finalize the prior FILE SCAN block before entering summary so that
                        # summary stats (which are often zero) do not overwrite the real data.
                        if current_scan and current_scan.get('file_id'):
                            changes = current_scan['details']['changes'][0]
                            file_id = current_scan['file_id']
                            current_score = int(current_scan.get('sensitivity_score', '0').split('/')[0])
                            if file_id in file_history:
                                prev_score = file_history[file_id]['score']
                                changes['score_change'] = str(current_score - prev_score)
                                changes['previous_score'] = str(prev_score)
                            else:
                                changes['score_change'] = '0'
                                changes['previous_score'] = None
                            changes['score'] = str(current_score)
                            changes['risk_level'] = current_scan.get('risk_level', 'NONE')
                            changes['high_sensitivity'] = current_scan.get('high_sensitivity', '0')
                            changes['moderate_sensitivity'] = current_scan.get('moderate_sensitivity', '0')
                            changes['low_sensitivity'] = current_scan.get('low_sensitivity', '0')
                            changes['total_entities'] = current_scan.get('total_entities', '0')
                            changes['type'] = 'sensitivity_scan'
                            logs.append(current_scan)
                            # update history
                            file_history[file_id] = {
                                'score': current_score,
                                'timestamp': current_scan['timestamp']
                            }
                        # Reset so summary does not alter it
                        current_scan = None
                        continue
            
            # Process the last scan if exists
            if current_scan and current_scan.get('file_id'):
                changes = current_scan['details']['changes'][0]
                file_id = current_scan['file_id']
                
                # Get the current score from the scan data
                current_score = int(current_scan.get('sensitivity_score', '0').split('/')[0])
                
                # Calculate score change from previous scan
                if file_id in file_history:
                    prev_score = file_history[file_id]['score']
                    changes['score_change'] = str(current_score - prev_score)
                    changes['previous_score'] = str(prev_score)
                else:
                    changes['score_change'] = '0'
                    changes['previous_score'] = None
                
                # Copy scan data to changes
                changes['score'] = str(current_score)
                changes['risk_level'] = current_scan.get('risk_level', 'NONE')
                changes['high_sensitivity'] = current_scan.get('high_sensitivity', '0')
                changes['moderate_sensitivity'] = current_scan.get('moderate_sensitivity', '0')
                changes['low_sensitivity'] = current_scan.get('low_sensitivity', '0')
                changes['total_entities'] = current_scan.get('total_entities', '0')
                
                # Set type for consistency
                changes['type'] = 'sensitivity_scan'
                
                logs.append(current_scan)
        
        # Sort logs by timestamp in descending order (most recent first)
        sorted_logs = sorted(logs, key=lambda x: x['timestamp'], reverse=True)
        
        return sorted_logs[-max_lines:] if max_lines else sorted_logs
    except Exception as e:
        app.logger.error(f"Error reading presidio log: {str(e)}")
        return []

@app.route('/sensitive_files')
def sensitive_files():
    """Render the sensitive files dashboard page."""
    return render_template('sensitive_files.html')

@app.route('/api/sensitive_files')
def get_sensitive_files():
    """API endpoint to get sensitive files data from MongoDB."""
    try:
        logs = get_mongodb_sensitive_files()  # Use MongoDB instead of presidio log
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"Error reading sensitive files: {str(e)}\n{traceback.format_exc()}")
        return jsonify([])

@app.route('/api/update-sensitivity', methods=['POST'])
def update_sensitivity_score():
    """
    API endpoint to update sensitivity score for a file in MongoDB.
    Accepts POST requests with sensitivity data and updates the database.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        file_id = data.get('file_id')
        if not file_id:
            return jsonify({"error": "file_id is required"}), 400
        
        # Extract sensitivity data from the request
        sensitivity_data = {
            'sensitivity_score': int(data.get('sensitivity_score', 0)),
            'risk_level': data.get('risk_level', 'NONE'),
            'high_sensitivity': int(data.get('high_sensitivity', 0)),
            'moderate_sensitivity': int(data.get('moderate_sensitivity', 0)),
            'low_sensitivity': int(data.get('low_sensitivity', 0)),
            'total_entities': int(data.get('total_entities', 0)),
            'modified_by': data.get('modified_by', 'Unknown')
        }
        
        # Update MongoDB
        success = update_mongodb_sensitivity_score(file_id, sensitivity_data)
        
        if success:
            return jsonify({"status": "success", "message": "Sensitivity score updated"}), 200
        else:
            return jsonify({"status": "error", "message": "Failed to update sensitivity score"}), 500
        
    except Exception as e:
        app.logger.error(f"Error updating sensitivity score: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Load environment variables from .env file
    try:
        import dotenv
        dotenv.load_dotenv()
        app.logger.info("Loaded environment variables from .env file")
    except ImportError:
        app.logger.warning("python-dotenv not installed, relying on OS environment variables")
    
    # Set up watch for Google Drive folder if environment variables are available
    webhook_url = os.environ.get('WEBHOOK_URL')
    folder_id = os.environ.get('GOOGLE_DRIVE_FOLDER_ID')
    
    if webhook_url and folder_id:
        app.logger.info(f"Starting application with webhook URL: {webhook_url}")
        app.logger.info(f"Monitoring folder ID: {folder_id}")
        
        # Check if token.json exists before trying to set up watch
        token_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'token.json')
        if os.path.exists(token_path):
            watch_result = watch_google_drive(folder_id, webhook_url)
            app.logger.info(f"Watch setup result: {json.dumps(watch_result, indent=2)}")
        else:
            app.logger.warning("token.json not found. Google Drive watch not configured.")
            
            # Generate authentication URL and log it for easy access
            try:
                redirect_uri = 'http://localhost:5001/auth/google/callback'
                
                # Check if credentials.json is web or installed app
                with open('credentials.json', 'r') as f:
                    creds_data = json.load(f)
                
                if 'web' in creds_data:
                    # Web application flow
                    flow = Flow.from_client_secrets_file(
                        'credentials.json',
                        scopes=SCOPES
                    )
                    flow.redirect_uri = redirect_uri
                else:
                    # Installed application flow
                    flow = InstalledAppFlow.from_client_secrets_file(
                        'credentials.json',
                        SCOPES,
                        redirect_uri=redirect_uri
                    )
                
                auth_url, state = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true',
                    prompt='consent'
                )
                
                # Store flow state for callback
                flow_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flow_state.json')
                with open(flow_path, 'w') as f:
                    json.dump({
                        'client_config': flow.client_config,
                        'redirect_uri': flow.redirect_uri,
                        'scopes': SCOPES,
                        'state': state
                    }, f)
                
                app.logger.info("=" * 80)
                app.logger.info("GOOGLE DRIVE AUTHENTICATION REQUIRED")
                app.logger.info("=" * 80)
                app.logger.info("Please click the following URL to authenticate:")
                app.logger.info(f"\n{auth_url}\n")
                app.logger.info("After authentication, your token will be saved automatically.")
                app.logger.info("=" * 80)
                
            except Exception as e:
                app.logger.error(f"Error generating authentication URL: {str(e)}")
                app.logger.warning("Visit /drive to authenticate manually.")
    else:
        app.logger.warning("WEBHOOK_URL or GOOGLE_DRIVE_FOLDER_ID environment variables not set. Google Drive watch not configured.")
    
    # Start the Flask development server
    app.run(debug=True, port=5001)