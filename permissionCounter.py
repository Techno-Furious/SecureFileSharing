"""
MongoDB file permission counter for tracking user file access statistics.
Analyzes user permissions across Google Drive and Dropbox files to calculate ownership and access counts.
Provides both individual user queries and bulk updates for the entire user base.
Integrates with the main dashboard system to maintain current file access metrics.
"""

from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

def get_file_count_for_user(user_email):
    """Get file counts for a specific user based on their permissions."""
    # MongoDB connection
    mongo_uri = os.getenv('MONGODB_URI')
    client = MongoClient(mongo_uri)
    db = client["FileInfo"]
    collection = db["FileActivityLogs2"]
    
    try:
        # Find all files where the user has any permission
        user_files = collection.find({
            "permissions": {
                "$elemMatch": {
                    "emailAddress": user_email
                }
            }
        })
        
        owned_count = 0
        edit_permission_count = 0
        total_count = 0
        
        for file_doc in user_files:
            # Skip deleted files by checking last history entry
            history = file_doc.get("history", [])
            if history and len(history) > 0:
                last_history_entry = history[-1]
                if last_history_entry.get("details", {}).get("type") == "file_deleted":
                    continue
            
            # Check user's permissions for this file
            user_permission = None
            for permission in file_doc.get("permissions", []):
                if permission.get("emailAddress") == user_email:
                    user_permission = permission.get("role")
                    break
            
            # Count based on permission level
            if user_permission == "owner":
                owned_count += 1
                edit_permission_count += 1  # Owners can also edit
                total_count += 1
            elif user_permission in ["writer", "editor"]:
                edit_permission_count += 1
                total_count += 1
        
        return (owned_count, edit_permission_count, total_count)
        
    except Exception as e:
        print(f"Error querying MongoDB: {e}")
        return (0, 0, 0)
    
    finally:
        client.close()

def get_detailed_file_access_for_user(user_email):
    """Get detailed file access information for a user."""
    # MongoDB connection
    mongo_uri = os.getenv('MONGODB_URI')
    client = MongoClient(mongo_uri)
    db = client["FileInfo"]
    collection = db["FileActivityLogs2"]
    
    result = {
        "owned_files": [],
        "editable_files": [],
        "commentable_files": [],
        "viewable_files": []
    }
    
    try:
        # Find all files where the user has any permission
        user_files = collection.find({
            "permissions": {
                "$elemMatch": {
                    "emailAddress": user_email
                }
            }
        })
        
        for file_doc in user_files:
            file_info = {
                "file_id": file_doc.get("file_id"),
                "file_name": file_doc.get("file_name"),
                "source": file_doc.get("source", "unknown")
            }
            
            # Find user's permission for this file
            user_permission = None
            for permission in file_doc.get("permissions", []):
                if permission.get("emailAddress") == user_email:
                    user_permission = permission.get("role")
                    break
            
            # Categorize based on permission level
            if user_permission == "owner":
                result["owned_files"].append(file_info)
            elif user_permission in ["writer", "editor"]:
                result["editable_files"].append(file_info)
            elif user_permission == "commenter":
                result["commentable_files"].append(file_info)
            elif user_permission in ["reader", "viewer"]:
                result["viewable_files"].append(file_info)
        
        return result
        
    except Exception as e:
        print(f"Error querying MongoDB: {e}")
        return result
    
    finally:
        client.close()

def update_all_user_count():
    """
    Update file counts for all users and store results in fileCount collection.
    Finds unique email addresses from permissions and calculates their file access statistics.
    """
    # MongoDB connection
    mongo_uri = os.getenv('MONGODB_URI')
    client = MongoClient(mongo_uri)
    db = client["FileInfo"]
    logs_collection = db["FileActivityLogs2"]
    count_collection = db["fileCount"]
    
    try:
        # Get all unique email addresses from permissions
        pipeline = [
            {"$unwind": "$permissions"},
            {"$group": {"_id": "$permissions.emailAddress"}},
            {"$match": {"_id": {"$ne": None, "$ne": ""}}}
        ]
        
        unique_users = logs_collection.aggregate(pipeline)
        user_emails = [user["_id"] for user in unique_users]
        
        processed_count = 0
        errors = []
        
        print(f"Found {len(user_emails)} unique users to process...")
        
        for user_email in user_emails:
            try:
                # Get file counts for this user
                owned_count, edit_permission_count, total_count = get_file_count_for_user_internal(user_email, logs_collection)
                
                # Prepare document for storage
                user_count_doc = {
                    "user_email": user_email,
                    "owned_count": owned_count,
                    "edit_permission_count": edit_permission_count,
                    "total_count": total_count,
                    "last_updated": datetime.utcnow(),
                    "last_updated_str": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Upsert the document
                count_collection.update_one(
                    {"user_email": user_email},
                    {"$set": user_count_doc},
                    upsert=True
                )
                
                processed_count += 1
                print(f"Processed {user_email}: owned={owned_count}, editable={edit_permission_count}, total={total_count}")
                
            except Exception as e:
                error_msg = f"Error processing user {user_email}: {str(e)}"
                errors.append(error_msg)
                print(error_msg)
        
        summary = {
            "total_users_found": len(user_emails),
            "users_processed": processed_count,
            "errors_count": len(errors),
            "errors": errors,
            "completion_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        print(f"Update completed! Processed {processed_count} users with {len(errors)} errors.")
        return summary
        
    except Exception as e:
        error_msg = f"Error in update_all_user_count: {str(e)}"
        print(error_msg)
        return {"error": error_msg}
    
    finally:
        client.close()

def get_file_count_for_user_internal(user_email, collection):
    """
    Internal function to get file counts using an existing collection reference.
    Used by update_all_user_count to avoid multiple database connections.
    """
    try:
        # Find all files where the user has any permission
        user_files = collection.find({
            "permissions": {
                "$elemMatch": {
                    "emailAddress": user_email
                }
            }
        })
        
        owned_count = 0
        edit_permission_count = 0
        total_count = 0
        
        for file_doc in user_files:
            # Skip deleted files by checking last history entry
            history = file_doc.get("history", [])
            if history and len(history) > 0:
                last_history_entry = history[-1]
                if last_history_entry.get("details", {}).get("type") == "file_deleted":
                    continue
            
            # Check user's permissions for this file
            user_permission = None
            for permission in file_doc.get("permissions", []):
                if permission.get("emailAddress") == user_email:
                    user_permission = permission.get("role")
                    break
            
            # Count based on permission level
            if user_permission == "owner":
                owned_count += 1
                edit_permission_count += 1  # Owners can also edit
                total_count += 1
            elif user_permission in ["writer", "editor"]:
                edit_permission_count += 1
                total_count += 1
        
        return (owned_count, edit_permission_count, total_count)
        
    except Exception as e:
        print(f"Error querying for user {user_email}: {e}")
        return (0, 0, 0)
