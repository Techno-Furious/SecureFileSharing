"""
Airtable integration module for logging and tracking file sensitivity analysis results.
Manages sensitivity scoring based on Presidio scan results and maintains scan history.
Calculates weighted sensitivity scores from entity detection counts and tracks content changes.
Provides query functions for retrieving sensitive and high-risk files from the Airtable database.
"""

import os
import hashlib
import datetime
import logging
from airtable import Airtable
from pres_helper_constants import *
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("drive_airtable.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("airtable_connector")

# Airtable configuration
AIRTABLE_BASE_ID = os.getenv('AIRTABLE_BASE_ID')
AIRTABLE_API_KEY = os.getenv('AIRTABLE_TOKEN')
AIRTABLE_TABLE_NAME = 'Drive_Scans'

airtable = Airtable(AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME, api_key=AIRTABLE_API_KEY)

def calculate_sensitivity_score(high, moderate, low):
    weights = {"HIGH": 3, "MODERATE": 2, "LOW": 1}

    weighted_score = high * weights["HIGH"] + moderate * weights["MODERATE"] + low * weights["LOW"]
    total_entities = high + moderate + low
    max_possible_score = total_entities * weights["HIGH"] if total_entities > 0 else 1
    normalized_score = (weighted_score / max_possible_score) * 100
    return round(normalized_score, 2)

def log_to_airtable(file_id, file_name, results, text, mime_type=None, modified_by=None, modified_date=None):
    """Log sensitivity scan results to Airtable with content change tracking."""
    high_count = 0
    moderate_count = 0
    low_count = 0
    found_types = set()
    has_sensitive_content = False
    
    # Calculate file content hash for tracking changes
    content_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
    
    # Count entities by sensitivity level
    for result in results:
        if result.score and result.score > 0.4:  # Apply score threshold
            entity = result.entity_type
            found_types.add(entity)
            
            if entity in highly_sensitive:
                high_count += 1
                has_sensitive_content = True
            elif entity in moderately_sensitive:
                moderate_count += 1
                has_sensitive_content = True
            elif entity in less_sensitive:
                low_count += 1

    # Calculate overall sensitivity score
    sensitivity_score = calculate_sensitivity_score(high_count, moderate_count, low_count)
    
    # Prepare record for Airtable
    record = {
        "File ID": file_id,
        "File Name": file_name,
        "MIME Type": mime_type or "Unknown",
        "File Content Hash": content_hash,
        "Has Sensitive Content": bool(has_sensitive_content),
        "High Count": int(high_count),
        "Moderate Count": int(moderate_count),
        "Low Count": int(low_count),
        "Sensitivity Score": float(sensitivity_score),
        "Last Scan Date": datetime.datetime.now().isoformat(),
        "Is Changed": False
    }
    
    # Add optional fields if provided
    if modified_by:
        record["Last Modified By"] = modified_by
    
    if modified_date:
        record["Last Modified Date"] = modified_date
    
    # Check if we already have a record for this file
    existing_records = airtable.search("File ID", file_id)
    
    if existing_records:
        # File was scanned before, update record and check for changes
        existing_record = existing_records[0]
        old_record_id = existing_record["id"]
        old_hash = existing_record["fields"].get("File Content Hash", "")
        
        # Check if content has changed
        if old_hash != content_hash:
            record["Is Changed"] = True
            logger.info(f"Content changed for file {file_name} (ID: {file_id})")
        
        # Update existing record
        airtable.update(old_record_id, record)
        logger.info(f"Updated Airtable record for file {file_name} (ID: {file_id})")
        return old_record_id
    else:
        # First time scanning this file, create new record
        result = airtable.insert(record)
        logger.info(f"Created new Airtable record for file {file_name} (ID: {file_id})")
        return result["id"]

def get_file_scan_history(file_id):
    """Retrieve the scan history for a specific file."""
    records = airtable.search("File ID", file_id)
    return records

def get_sensitive_files(min_sensitivity_score=50):
    """Get all files that have sensitive content with a score above the threshold."""
    # Fetch all records and filter by sensitivity criteria
    all_records = airtable.get_all()
    sensitive_files = [
        record for record in all_records 
        if record["fields"].get("Has Sensitive Content") == True and 
        record["fields"].get("Sensitivity Score", 0) >= min_sensitivity_score
    ]
    return sensitive_files

def get_high_risk_files():
    """Get all files that contain highly sensitive information."""
    all_records = airtable.get_all()
    high_risk_files = [
        record for record in all_records 
        if record["fields"].get("High Count", 0) > 0
    ]
    return high_risk_files