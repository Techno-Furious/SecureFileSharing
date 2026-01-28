
import time
from datetime import datetime
from typing import Dict, Optional, Any
import pymongo
from pymongo import MongoClient
import json
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# Lambda constants for different EWMA time windows
# Calculated to give observations from the time window boundary 10% weight
LAMBDA_CONSTANTS = {
    "ewma30m": 0.250,   # Highest - most responsive for immediate patterns
    "ewma1h": 0.200,    # High responsiveness for short-term
    "ewma2h": 0.160,    # Exponential decay continues
    "ewma8h": 0.100,    # Moderate responsiveness for medium-term
    "ewma1d": 0.063,    # Lower for daily smoothing
    "ewma7d": 0.025,    # Significant decay for weekly trends
    "ewma30d": 0.010,   # Low for monthly stability
    "ewma90d": 0.004    # Minimal for long-term baseline
}

# MongoDB connection string
MONGO_CONNECTION_STRING = os.getenv('MONGODB_URI')
DB_NAME = "EWMAconfig"
USERS_CONFIG_COLLECTION = "usersConfig"
USERS_INIT_COLLECTION = "usersInit"

# FileInfo database for file counts
FILEINFO_DB_NAME = "FileInfo"
FILECOUNT_COLLECTION = "fileCount"

# Valid activity types
VALID_ACTIVITY_TYPES = ["sensitiveCount", "unsharedAccess", "downloadCount", "deleteCount"]

# Dynamic initialization percentages based on file count
# These represent realistic activity levels as percentage of total files for each time window
INIT_PERCENTAGES = {
    "sensitiveCount": {
        "ewma30m": 0.02,    # 2% in 30 minutes
        "ewma1h": 0.04,     # 4% in 1 hour  
        "ewma2h": 0.07,     # 7% in 2 hours
        "ewma8h": 0.15,     # 15% in 8 hours
        "ewma1d": 0.25,     # 25% in 1 day
        "ewma7d": 0.50,     # 50% in 7 days
        "ewma30d": 0.80,    # 80% in 30 days
        "ewma90d": 0.95     # 95% in 90 days
    },
    "unsharedAccess": {
        "ewma30m": 0.03,    # 3% in 30 minutes
        "ewma1h": 0.06,     # 6% in 1 hour
        "ewma2h": 0.10,     # 10% in 2 hours
        "ewma8h": 0.20,     # 20% in 8 hours
        "ewma1d": 0.35,     # 35% in 1 day
        "ewma7d": 0.65,     # 65% in 7 days
        "ewma30d": 0.85,    # 85% in 30 days
        "ewma90d": 0.95     # 95% in 90 days
    },
    "downloadCount": {
        "ewma30m": 0.05,    # 5% in 30 minutes
        "ewma1h": 0.10,     # 10% in 1 hour
        "ewma2h": 0.15,     # 15% in 2 hours
        "ewma8h": 0.30,     # 30% in 8 hours
        "ewma1d": 0.50,     # 50% in 1 day
        "ewma7d": 0.80,     # 80% in 7 days
        "ewma30d": 0.95,    # 95% in 30 days
        "ewma90d": 1.00     # 100% in 90 days
    },
    "deleteCount": {
        "ewma30m": 0.01,    # 1% in 30 minutes
        "ewma1h": 0.02,     # 2% in 1 hour
        "ewma2h": 0.04,     # 4% in 2 hours
        "ewma8h": 0.08,     # 8% in 8 hours
        "ewma1d": 0.15,     # 15% in 1 day
        "ewma7d": 0.30,     # 30% in 7 days
        "ewma30d": 0.50,    # 50% in 30 days
        "ewma90d": 0.70     # 70% in 90 days
    }
}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EWMAUtils:
    def __init__(self):
        """Initialize MongoDB connection and collections."""
        try:
            self.client = MongoClient(MONGO_CONNECTION_STRING)
            self.db = self.client[DB_NAME]
            self.users_config = self.db[USERS_CONFIG_COLLECTION]
            self.users_init = self.db[USERS_INIT_COLLECTION]
            
            # FileInfo database connection for file counts
            self.fileinfo_db = self.client[FILEINFO_DB_NAME]
            self.filecount_collection = self.fileinfo_db[FILECOUNT_COLLECTION]
            
            logger.info("MongoDB connection established successfully")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    def parse_timestamp(self, timestamp_str: str) -> float:
        """
        Parse timestamp string to Unix timestamp.
        
        Args:
            timestamp_str: Timestamp string in format "HH:MM:SS DD-MM-YYYY"
            
        Returns:
            float: Unix timestamp
        """
        try:
            dt = datetime.strptime(timestamp_str, "%H:%M:%S %d-%m-%Y")
            return dt.timestamp()
        except ValueError as e:
            logger.error(f"Failed to parse timestamp {timestamp_str}: {e}")
            return time.time()  # Return current time as fallback
    
    def get_current_timestamp_str(self) -> str:
        """
        Get current timestamp in the expected format.
        
        Returns:
            str: Current timestamp in "HH:MM:SS DD-MM-YYYY" format
        """
        return datetime.now().strftime("%H:%M:%S %d-%m-%Y")
    
    def calculate_activity_rate(self, last_update_str: str, current_time: Optional[float] = None) -> float:
        """
        Calculate activity rate as activities per hour based on time interval since last activity.
        
        Example: If last activity was 10 minutes ago, rate = 1 activity / (10/60) hours = 6 activities/hour
        
        Args:
            last_update_str: Last update timestamp string
            current_time: Current timestamp (if None, uses current time)
            
        Returns:
            float: Activity rate (activities per hour)
        """
        if current_time is None:
            current_time = time.time()
        
        last_update_time = self.parse_timestamp(last_update_str)
        time_elapsed_seconds = current_time - last_update_time
        
        # Convert seconds to hours
        time_elapsed_hours = time_elapsed_seconds / 3600.0
        
        # Prevent division by zero for very quick consecutive activities
        # Minimum time interval is 1 second = 0.000278 hours
        if time_elapsed_hours < 0.000278:  # Less than 1 second
            time_elapsed_hours = 0.000278
        
        # Activity rate = 1 activity / time_elapsed_hours
        # This represents how many activities per hour at this rate
        activity_rate = 1.0 / time_elapsed_hours
        
        return activity_rate
    
    def calculate_ewma_score(self, previous_ewma: float, activity_rate: float, lambda_val: float) -> float:
        """
        Calculate new EWMA score using the formula:
        EWMA_new = λ × Current_Activity_Rate + (1 - λ) × EWMA_previous
        
        Where activity_rate is in activities per hour.
        
        Args:
            previous_ewma: Previous EWMA score (activities per hour)
            activity_rate: Current activity rate (activities per hour)
            lambda_val: Lambda constant for the time window (smoothing factor)
            
        Returns:
            float: New EWMA score (activities per hour)
        """
        return lambda_val * activity_rate + (1 - lambda_val) * previous_ewma
    
    def get_user_file_count(self, user_email: str) -> Dict[str, int]:
        """
        Get user's file count from the fileCount collection.
        
        Args:
            user_email: Email of the user
            
        Returns:
            Dict[str, int]: Dictionary with owned_count, edit_permission_count, total_count
        """
        try:
            file_count_doc = self.filecount_collection.find_one({"user_email": user_email})
            
            if file_count_doc:
                return {
                    "owned_count": file_count_doc.get("owned_count", 0),
                    "edit_permission_count": file_count_doc.get("edit_permission_count", 0),
                    "total_count": file_count_doc.get("total_count", 0)
                }
            else:
                # User not found in fileCount, return zeros
                logger.warning(f"No file count found for user {user_email}, using default values")
                return {"owned_count": 0, "edit_permission_count": 0, "total_count": 0}
                
        except Exception as e:
            logger.error(f"Failed to get file count for {user_email}: {e}")
            return {"owned_count": 0, "edit_permission_count": 0, "total_count": 0}
    
    def get_time_window_seconds(self, time_window: str) -> int:
        """
        Convert time window string to seconds.
        
        Args:
            time_window: Time window string (e.g., "ewma30m", "ewma1h", etc.)
            
        Returns:
            int: Time window in seconds
        """
        time_window_map = {
            "ewma30m": 30 * 60,      # 30 minutes = 1800 seconds
            "ewma1h": 60 * 60,       # 1 hour = 3600 seconds
            "ewma2h": 2 * 60 * 60,   # 2 hours = 7200 seconds
            "ewma8h": 8 * 60 * 60,   # 8 hours = 28800 seconds
            "ewma1d": 24 * 60 * 60,  # 1 day = 86400 seconds
            "ewma7d": 7 * 24 * 60 * 60,   # 7 days = 604800 seconds
            "ewma30d": 30 * 24 * 60 * 60, # 30 days = 2592000 seconds
            "ewma90d": 90 * 24 * 60 * 60  # 90 days = 7776000 seconds
        }
        return time_window_map.get(time_window, 3600)  # Default to 1 hour if unknown
    
    def calculate_dynamic_init_values(self, user_email: str) -> Dict[str, Dict[str, float]]:
        """
        Calculate dynamic initialization values based on activity rate logic.
        Formula: (time_window_in_seconds / 10) / 2 for each time window.
        This allows for 10-second bursts at half the time window rate.
        
        Args:
            user_email: Email of the user
            
        Returns:
            Dict[str, Dict[str, float]]: Dynamic init values for each activity type and time window
        """
        try:
            logger.info(f"Calculating dynamic init values for {user_email} using activity rate logic")
            
            dynamic_config = {}
            
            for activity_type in VALID_ACTIVITY_TYPES:
                dynamic_config[activity_type] = {}
                
                for time_window in LAMBDA_CONSTANTS.keys():
                    # Calculate initial value as activity rate based on time window
                    # Formula: (time_window_in_seconds / 10) / 2
                    # This allows for 10-second bursts at half the time window rate
                    time_window_seconds = self.get_time_window_seconds(time_window)
                    init_value = (time_window_seconds / 60) 
                    
                    # Ensure minimum value of 1 for any activity
                    init_value = max(init_value, 1.0)
                    
                    # Round to 2 decimal places for cleaner values
                    dynamic_config[activity_type][time_window] = round(init_value, 2)
                
                logger.info(f"Dynamic init values for {activity_type}: {dynamic_config[activity_type]}")
            
            return dynamic_config
            
        except Exception as e:
            logger.error(f"Failed to calculate dynamic init values for {user_email}: {e}")
            return self.get_fallback_init_config()
    
    def get_fallback_init_config(self) -> Dict[str, Dict[str, float]]:
        """
        Get fallback initialization configuration when dynamic calculation fails.
        Uses activity rate calculation based on time windows.
        
        Returns:
            Dict[str, Dict[str, float]]: Fallback init configuration with activity rates
        """
        fallback_config = {}
        
        for activity_type in VALID_ACTIVITY_TYPES:
            fallback_config[activity_type] = {}
            for time_window in LAMBDA_CONSTANTS.keys():
                # Calculate initial value as activity rate based on time window
                # Formula: (time_window_in_seconds / 10) / 2
                time_window_seconds = self.get_time_window_seconds(time_window)
                init_value = (time_window_seconds / 10) 
                init_value = max(init_value, 1.0)  # Minimum 1
                fallback_config[activity_type][time_window] = round(init_value, 2)
        
        logger.info(f"Using fallback config with activity rate calculation")
        return fallback_config
    def get_init_config(self) -> Dict[str, Any]:
        """
        Get the general initialization configuration from usersInit collection.
        (Kept for backward compatibility, but dynamic initialization is now preferred)
        
        Returns:
            Dict[str, Any]: Initial configuration for new users from usersInit.general
        """
        try:
            # Look for the "general" document in usersInit collection
            init_doc = self.users_init.find_one({"general": {"$exists": True}})
            
            if init_doc and "general" in init_doc:
                return init_doc["general"]
            
            # Fallback: look for any document and try to extract general config
            init_doc = self.users_init.find_one()
            if init_doc:
                # Remove MongoDB _id field if present
                if "_id" in init_doc:
                    del init_doc["_id"]
                
                # Return the general field if it exists, otherwise return the whole document
                return init_doc.get("general", init_doc)
            
            logger.warning("No usersInit configuration found, using fallback")
            return self.get_fallback_init_config()
            
        except Exception as e:
            logger.error(f"Failed to get init config: {e}")
            return self.get_fallback_init_config()
    
    def get_user_config(self, user_email: str) -> Optional[Dict[str, Any]]:
        """
        Get user configuration from MongoDB. Returns None if user doesn't exist.
        
        Args:
            user_email: Email of the user
            
        Returns:
            Optional[Dict[str, Any]]: User configuration or None if not found
        """
        try:
            # Look for user document with email field
            user_doc = self.users_config.find_one({"email": user_email})
            
            if user_doc:
                # Remove email and _id fields, return the config part
                config = user_doc.copy()
                config.pop("email", None)
                config.pop("_id", None)
                return config
            else:
                # User doesn't exist
                return None
                
        except Exception as e:
            logger.error(f"Failed to get user config for {user_email}: {e}")
            return None
    
    def user_exists(self, user_email: str) -> bool:
        """
        Check if user exists in the database.
        
        Args:
            user_email: Email of the user
            
        Returns:
            bool: True if user exists, False otherwise
        """
        try:
            user_doc = self.users_config.find_one({"email": user_email})
            return user_doc is not None
        except Exception as e:
            logger.error(f"Failed to check if user exists {user_email}: {e}")
            return False
    
    def initialize_new_user(self, user_email: str) -> Dict[str, Any]:
        """
        Initialize a new user with dynamic values based on their file count.
        
        Args:
            user_email: Email of the user to initialize
            
        Returns:
            Dict[str, Any]: Initial user configuration with dynamic values
        """
        try:
            logger.info(f"Initializing new user with activity rate logic: {user_email}")
            
            # Get dynamic initialization values based on activity rate logic
            dynamic_config = self.calculate_dynamic_init_values(user_email)
            
            if not dynamic_config:
                logger.error("No dynamic config generated, using fallback")
                dynamic_config = self.get_fallback_init_config()
            
            # Prepare user configuration
            current_timestamp = self.get_current_timestamp_str()
            user_config = {"email": user_email}
            
            logger.info(f"Using activity rate based initialization for {user_email}")
            
            for activity_type in VALID_ACTIVITY_TYPES:
                if activity_type in dynamic_config:
                    # Use dynamic values
                    user_config[activity_type] = dynamic_config[activity_type].copy()
                    
                    # Add the lastUpdate timestamp for this activity type
                    user_config[activity_type]["lastUpdate"] = current_timestamp
                    
                    logger.info(f"Initialized {activity_type} for {user_email}: {user_config[activity_type]}")
            
            # Add metadata
            user_config["createdAt"] = current_timestamp
            user_config["initMethod"] = "activity_rate_based"
            user_config["initFormula"] = "(time_window_seconds / 10) / 2"
            
            # Insert the new user
            result = self.users_config.insert_one(user_config)
            
            if result.inserted_id:
                logger.info(f"Successfully initialized new user with dynamic values: {user_email}")
                # Return config without email field
                config = user_config.copy()
                config.pop("email", None)
                return config
            else:
                logger.error(f"Failed to insert new user: {user_email}")
                return {}
            
        except Exception as e:
            logger.error(f"Failed to initialize user {user_email}: {e}")
            return {}
    
    def update_user_ewma_scores(self, user_email: str, activity_type: str) -> bool:
        """
        Main function to update EWMA scores for a user based on activity.
        For new users: Initialize with default values without EWMA calculation.
        For existing users: Calculate EWMA scores based on time since last update.
        
        Args:
            user_email: Email of the user
            activity_type: Type of activity (sensitiveCount, unsharedAccess, downloadCount, deleteCount)
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            # Validate activity type
            if activity_type not in VALID_ACTIVITY_TYPES:
                logger.error(f"Invalid activity type: {activity_type}")
                return False
            
            # Check if user exists
            if not self.user_exists(user_email):
                # New user - initialize with default values (no EWMA calculation)
                logger.info(f"New user detected: {user_email}. Initializing with default values.")
                user_config = self.initialize_new_user(user_email)
                if user_config:
                    logger.info(f"Successfully initialized new user {user_email} with default {activity_type} values")
                    return True
                else:
                    logger.error(f"Failed to initialize new user {user_email}")
                    return False
            
            # Existing user - calculate EWMA scores
            user_config = self.get_user_config(user_email)
            if not user_config:
                logger.error(f"Failed to get user config for existing user {user_email}")
                return False
            
            # Check if activity type exists in user config
            if activity_type not in user_config:
                logger.error(f"Activity type {activity_type} not found in user config for {user_email}")
                return False
            
            activity_config = user_config[activity_type]
            last_update = activity_config.get("lastUpdate")
            
            if not last_update:
                logger.error(f"No lastUpdate found for {activity_type} in user {user_email}")
                return False
            
            # Calculate activity rate based on time since last update
            activity_rate = self.calculate_activity_rate(last_update)
            current_timestamp = self.get_current_timestamp_str()
            
            # Log the time interval for debugging
            last_update_time = self.parse_timestamp(last_update)
            current_time = time.time()
            time_elapsed_minutes = (current_time - last_update_time) / 60.0
            
            logger.info(f"Calculating EWMA for existing user {user_email} - {activity_type}")
            logger.info(f"Time since last activity: {time_elapsed_minutes:.2f} minutes")
            logger.info(f"Activity rate: {activity_rate:.2f} activities/hour")
            
            # Update EWMA scores for all time windows
            updated_config = activity_config.copy()
            updated_config["lastUpdate"] = current_timestamp
            
            for time_window, lambda_val in LAMBDA_CONSTANTS.items():
                if time_window in activity_config:
                    previous_ewma = float(activity_config[time_window])
                    new_ewma = self.calculate_ewma_score(previous_ewma, activity_rate, lambda_val)
                    updated_config[time_window] = round(new_ewma, 6)  # Round to 6 decimal places
                    logger.debug(f"Updated {time_window}: {previous_ewma:.6f} -> {new_ewma:.6f} (λ={lambda_val}, rate={activity_rate:.2f})")
            
            # Update MongoDB
            update_query = {"email": user_email}
            update_data = {"$set": {activity_type: updated_config}}
            
            result = self.users_config.update_one(update_query, update_data)
            
            if result.matched_count > 0:
                logger.info(f"Successfully updated EWMA scores for existing user {user_email} - {activity_type}")
                return True
            else:
                logger.warning(f"No documents found for user {user_email}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update EWMA scores for {user_email} - {activity_type}: {e}")
            return False
    
    def close_connection(self):
        """Close MongoDB connection."""
        try:
            if hasattr(self, 'client'):
                self.client.close()
                logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")

# Global instance for easy access
ewma_utils = EWMAUtils()

def update_user_activity_ewma(user_email: str, activity_type: str) -> bool:
    """
    Convenience function to update EWMA scores for a user activity.
    For new users: Initializes with default values from usersInit.
    For existing users: Calculates EWMA scores based on time since last update.
    
    Args:
        user_email: Email of the user
        activity_type: Type of activity (sensitiveCount, unsharedAccess, downloadCount, deleteCount)
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    return ewma_utils.update_user_ewma_scores(user_email, activity_type)

def get_user_current_scores(user_email: str) -> Optional[Dict[str, Any]]:
    """
    Get current EWMA scores for a user.
    
    Args:
        user_email: Email of the user
        
    Returns:
        Optional[Dict[str, Any]]: User's current EWMA scores or None if not found
    """
    return ewma_utils.get_user_config(user_email)

def get_or_create_user_config(user_email: str) -> Optional[Dict[str, Any]]:
    """
    Get user configuration, creating it if the user doesn't exist.
    
    Args:
        user_email: Email of the user
        
    Returns:
        Optional[Dict[str, Any]]: User configuration or None if error
    """
    config = ewma_utils.get_user_config(user_email)
    if config is None and not ewma_utils.user_exists(user_email):
        # User doesn't exist, initialize them
        config = ewma_utils.initialize_new_user(user_email)
    return config




