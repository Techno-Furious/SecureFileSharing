import time
from datetime import datetime
from typing import Dict, Optional, Any
from pymongo import MongoClient
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB connection string
MONGO_CONNECTION_STRING = os.getenv('MONGODB_URI')
DB_NAME = "EWMAconfig"
USERS_CONFIG_COLLECTION = "usersConfig"
USERS_BOOL_COLLECTION = "usersBool"

# Valid activity types
VALID_ACTIVITY_TYPES = ["sensitiveCount", "unsharedAccess", "downloadCount", "deleteCount"]

def is_suspicious_activity(activity: dict) -> bool:
    """
    Returns True if suspicious behavior is detected using dynamic, environment-adaptive rules
    based on statistical relationships between EWMA values across time intervals.
    
    Parameters:
        activity: dict containing EWMA values like:
            {
              "ewma30m": ...,
              "ewma1h": ...,
              "ewma2h": ...,
              "ewma8h": ...,
              "ewma1d": ...,
              "ewma7d": ...,
              "ewma30d": ...,
              "ewma90d": ...
            }
    
    Returns:
        True if suspicious, False otherwise.
    """

    # Extract EWMA values
    e30m = activity["ewma30m"]
    e1h   = activity["ewma1h"]
    e2h   = activity["ewma2h"]
    e8h   = activity["ewma8h"]
    e1d   = activity["ewma1d"]
    e7d   = activity["ewma7d"]
    e30d  = activity["ewma30d"]
    e90d  = activity["ewma90d"]

    # Handle zero/near-zero baseline activity to prevent division errors
    baseline_threshold = 0.001

    # Rule 1: Recent activity spike detection
    # Check if recent activity (30m, 1h) is significantly higher than medium-term (8h, 1d)
    recent_max = max(e30m, e1h)
    medium_term_avg = (e8h + e1d) / 2
    
    if medium_term_avg > baseline_threshold:
        recent_spike_ratio = recent_max / medium_term_avg
        # Suspicious if recent activity is 3x higher than medium-term average
        recent_spike = recent_spike_ratio > 3.0
    else:
        # For low activity users, check absolute values
        recent_spike = recent_max > 20

    # Rule 2: Short-term vs long-term deviation
    # Compare short-term average to long-term average
    short_term_avg = (e30m + e1h + e2h) / 3
    long_term_avg = (e7d + e30d + e90d) / 3
    
    if long_term_avg > baseline_threshold:
        deviation_ratio = short_term_avg / long_term_avg
        # Suspicious if short-term is 150% above long-term
        significant_deviation = deviation_ratio > 2.5
    else:
        # For new users, check absolute threshold
        significant_deviation = short_term_avg > 15

    # Rule 3: Exponential growth pattern
    # Check if activity shows exponential growth in recent periods
    if e2h > baseline_threshold and e1h > baseline_threshold:
        growth_30m_1h = (e30m / e1h) if e1h > 0 else 1
        growth_1h_2h = (e1h / e2h) if e2h > 0 else 1
        
        # Suspicious if we see accelerating growth (each period growing faster)
        exponential_growth = (growth_30m_1h > 1.5 and growth_1h_2h > 1.3 and 
                            growth_30m_1h > growth_1h_2h)
    else:
        exponential_growth = False

    # Rule 4: Burst activity detection
    # Check for concentrated activity in very short timeframes
    short_term_max = max(e30m, e1h, e2h)
    longer_term_values = [e8h, e1d, e7d, e30d, e90d]
    longer_term_max = max(longer_term_values) if longer_term_values else baseline_threshold
    
    if longer_term_max > baseline_threshold:
        burst_ratio = short_term_max / longer_term_max
        # Suspicious if recent peak is 4x higher than any longer-term peak
        burst_pattern = burst_ratio > 4.0 and short_term_max > 10
    else:
        # For users with limited history
        burst_pattern = short_term_max > 30

    # Rule 5: Temporal inconsistency
    # Check for patterns that violate expected EWMA decay behavior
    # EWMA should generally decrease as time windows get longer (for recent activity)
    temporal_violations = 0
    
    # Check for inversions in expected order (shorter should be higher for recent activity)
    if e30m < e2h and e30m > 10:  # 30m should be >= 2h for recent activity
        temporal_violations += 1
    if e1h < e8h and e1h > 5:  # 1h should be >= 8h for recent activity
        temporal_violations += 1
    if e2h < e1d and e2h > 5:  # 2h should be >= 1d for recent activity
        temporal_violations += 1
    
    # Multiple violations suggest suspicious pattern
    consistency_violation = temporal_violations >= 2

    # Rule 6: Absolute threshold for extreme values
    # Flag extremely high absolute values regardless of ratios
    extreme_values = e30m > 100 or e1h > 80 or e2h > 60

    # Count active indicators
    indicators = [
        recent_spike,
        significant_deviation,
        exponential_growth,
        burst_pattern,
        consistency_violation,
        extreme_values
    ]
    
    active_indicators = sum(indicators)
    
    # Debug logging for the specific case
    if e30m > 100:  # For the provided example
        print(f"Debug - EWMA Analysis:")
        print(f"  Recent spike: {recent_spike} (ratio: {recent_max/medium_term_avg if medium_term_avg > baseline_threshold else 'N/A'})")
        print(f"  Significant deviation: {significant_deviation} (ratio: {short_term_avg/long_term_avg if long_term_avg > baseline_threshold else 'N/A'})")
        print(f"  Exponential growth: {exponential_growth}")
        print(f"  Burst pattern: {burst_pattern}")
        print(f"  Consistency violation: {consistency_violation} (violations: {temporal_violations})")
        print(f"  Extreme values: {extreme_values}")
        print(f"  Active indicators: {active_indicators}/6")

    # Decision logic: Suspicious if 2+ indicators OR 1 very strong indicator
    very_strong_indicators = (
        (recent_spike and recent_max / medium_term_avg > 5 if medium_term_avg > baseline_threshold else False) or
        (significant_deviation and short_term_avg / long_term_avg > 4 if long_term_avg > baseline_threshold else False) or
        (burst_pattern and short_term_max > 50) or
        extreme_values
    )
    
    return active_indicators >= 2 or very_strong_indicators

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EWMADetector:
    def __init__(self):
        """Initialize MongoDB connection and collections."""
        try:
            self.client = MongoClient(MONGO_CONNECTION_STRING)
            self.db = self.client[DB_NAME]
            self.users_config = self.db[USERS_CONFIG_COLLECTION]
            self.users_bool = self.db[USERS_BOOL_COLLECTION]
            logger.info("MongoDB connection established successfully")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    def get_user_ewma_scores(self, user_email: str) -> Optional[Dict[str, Any]]:
        """
        Get user EWMA scores from usersConfig collection.
        
        Args:
            user_email: Email of the user
            
        Returns:
            Optional[Dict[str, Any]]: User configuration or None if not found
        """
        try:
            user_doc = self.users_config.find_one({"email": user_email})
            
            if user_doc:
                config = user_doc.copy()
                config.pop("email", None)
                config.pop("_id", None)
                return config
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to get user EWMA scores for {user_email}: {e}")
            return None
    
    def check_activity_allowance(self, ewma_scores: Dict[str, float], activity_type: str) -> bool:
        """
        Check if user activity is allowed based on EWMA scores using anomaly detection ruleset.
        
        Args:
            ewma_scores: Dictionary of EWMA scores for the activity type
            activity_type: Type of activity to check
            
        Returns:
            bool: True if activity is allowed, False if blocked
        """
        # Extract EWMA scores for all time windows
        required_windows = ["ewma30m", "ewma1h", "ewma2h", "ewma8h", "ewma1d", "ewma7d", "ewma30d", "ewma90d"]
        
        # Check if all required EWMA scores are present
        for window in required_windows:
            if window not in ewma_scores:
                logger.warning(f"Missing EWMA score for {window} in {activity_type}")
                return True  # Default to allow if missing data
        
        # Check if activity is suspicious using the anomaly detection ruleset
        is_suspicious = is_suspicious_activity(ewma_scores)
        
        if is_suspicious:
            logger.info(f"Activity {activity_type} blocked: suspicious activity detected by anomaly detection")
            return False  # Block activity
        else:
            logger.info(f"Activity {activity_type} allowed: no suspicious anomalies detected")
            return True  # Allow activity
    
    def get_user_bool_config(self, user_email: str) -> Optional[Dict[str, Any]]:
        """
        Get user boolean configuration from usersBool collection.
        
        Args:
            user_email: Email of the user
            
        Returns:
            Optional[Dict[str, Any]]: User boolean configuration or None if not found
        """
        try:
            user_doc = self.users_bool.find_one({"email": user_email})
            
            if user_doc:
                config = user_doc.copy()
                config.pop("_id", None)
                return config
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to get user boolean config for {user_email}: {e}")
            return None
    
    def create_user_bool_record(self, user_email: str, activity_allowances: Dict[str, bool]) -> bool:
        """
        Create new user boolean record in usersBool collection.
        
        Args:
            user_email: Email of the user
            activity_allowances: Dictionary of activity allowances
            
        Returns:
            bool: True if creation was successful, False otherwise
        """
        try:
            user_bool_config = {"email": user_email}
            user_bool_config.update(activity_allowances)
            
            result = self.users_bool.insert_one(user_bool_config)
            
            if result.inserted_id:
                logger.info(f"Successfully created new usersBool record for: {user_email}")
                return True
            else:
                logger.error(f"Failed to create usersBool record for: {user_email}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to create usersBool record for {user_email}: {e}")
            return False
    
    def update_user_bool_record(self, user_email: str, activity_type: str, allowed: bool) -> bool:
        """
        Update existing user boolean record in usersBool collection.
        
        Args:
            user_email: Email of the user
            activity_type: Type of activity to update
            allowed: Whether the activity is allowed
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            update_query = {"email": user_email}
            update_data = {"$set": {activity_type: allowed}}
            
            result = self.users_bool.update_one(update_query, update_data)
            
            if result.matched_count > 0:
                logger.info(f"Successfully updated usersBool for {user_email} - {activity_type}: {allowed}")
                return True
            else:
                logger.warning(f"No usersBool document found for user {user_email}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update usersBool for {user_email} - {activity_type}: {e}")
            return False
    
    def get_and_update_user_allowance(self, user_email: str, activity_type: str) -> Optional[bool]:
        """
        Main function to get and update user activity allowance.
        
        Args:
            user_email: Email of the user
            activity_type: Type of activity (sensitiveCount, unsharedAccess, downloadCount, deleteCount)
            
        Returns:
            Optional[bool]: True if activity is allowed, False if blocked, None if error
        """
        try:
            # Validate activity type
            if activity_type not in VALID_ACTIVITY_TYPES:
                logger.error(f"Invalid activity type: {activity_type}")
                return None
            
            # Get user EWMA scores from usersConfig
            user_ewma_config = self.get_user_ewma_scores(user_email)
            if not user_ewma_config:
                logger.error(f"No EWMA scores found for user: {user_email}")
                return None
            
            # Check if the specific activity type exists in EWMA config
            if activity_type not in user_ewma_config:
                logger.error(f"Activity type {activity_type} not found in EWMA config for user: {user_email}")
                return None
            
            activity_ewma_scores = user_ewma_config[activity_type]
            
            # Remove non-score fields (like lastUpdate)
            ewma_scores = {k: v for k, v in activity_ewma_scores.items() if k.startswith('ewma')}
            
            # Check if activity is allowed based on EWMA scores
            is_allowed = self.check_activity_allowance(ewma_scores, activity_type)
            
            # Check if user exists in usersBool collection
            user_bool_config = self.get_user_bool_config(user_email)
            
            if user_bool_config is None:
                # User doesn't exist in usersBool, create new record with all activity types
                logger.info(f"Creating new usersBool record for user: {user_email}")
                
                # Calculate allowances for all activity types
                all_allowances = {}
                for act_type in VALID_ACTIVITY_TYPES:
                    if act_type in user_ewma_config:
                        act_ewma_scores = {k: v for k, v in user_ewma_config[act_type].items() if k.startswith('ewma')}
                        all_allowances[act_type] = self.check_activity_allowance(act_ewma_scores, act_type)
                    else:
                        all_allowances[act_type] = True  # Default to allowed if no EWMA data
                
                success = self.create_user_bool_record(user_email, all_allowances)
                if success:
                    return is_allowed
                else:
                    return None
            else:
                # User exists, update the specific activity type
                success = self.update_user_bool_record(user_email, activity_type, is_allowed)
                if success:
                    return is_allowed
                else:
                    return None
                    
        except Exception as e:
            logger.error(f"Failed to get and update user allowance for {user_email} - {activity_type}: {e}")
            return None
    
    def close_connection(self):
        """Close MongoDB connection."""
        try:
            if hasattr(self, 'client'):
                self.client.close()
                logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")

# Global instance for easy access
ewma_detector = EWMADetector()

def get_and_update_user_allowance(user_email: str, activity_type: str) -> Optional[bool]:
    """
    Convenience function to get and update user activity allowance.
    
    Args:
        user_email: Email of the user
        activity_type: Type of activity (sensitiveCount, unsharedAccess, downloadCount, deleteCount)
        
    Returns:
        Optional[bool]: True if activity is allowed, False if blocked, None if error
    """
    return ewma_detector.get_and_update_user_allowance(user_email, activity_type)

def get_user_allowance_status(user_email: str) -> Optional[Dict[str, bool]]:
    """
    Get current allowance status for all activity types for a user.
    
    Args:
        user_email: Email of the user
        
    Returns:
        Optional[Dict[str, bool]]: Dictionary of activity allowances or None if error
    """
    try:
        user_bool_config = ewma_detector.get_user_bool_config(user_email)
        if user_bool_config:
            # Remove email field and return only the boolean values
            allowances = {k: v for k, v in user_bool_config.items() if k != "email"}
            return allowances
        else:
            return None
    except Exception as e:
        logger.error(f"Failed to get user allowance status for {user_email}: {e}")
        return None