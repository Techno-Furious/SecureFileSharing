"""
Presidio-based file scanner for detecting sensitive data in modified Google Drive files.
Monitors syslog for file changes and performs comprehensive sensitivity analysis using Presidio.
Calculates weighted sensitivity scores and risk levels based on entity detection results.
Integrates with Airtable for result storage and MongoDB for centralized sensitivity tracking.
"""

import os
import json
import logging
import re
import datetime
import time
import argparse
import io
import PyPDF2
import pytz
import requests
from pres_drive_scan_airtable import get_credentials, get_file_content, get_file_metadata
from pres_presidio_connector import call_presidio, analyzer
from pres_airtableSensitivityUpdate import log_to_airtable
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from pres_helper_constants import highly_sensitive, moderately_sensitive, less_sensitive
try:
    from docx import Document
except ImportError:
    logging.warning("python-docx module not found. Word document extraction will be limited.")

# Configure logging
log_file = "presidio_scan.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("presidio_scanner")

# Initialize log file
try:
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"\n\n--- New logging session started at {datetime.datetime.now()} ---\n\n")
    logger.info(f"Logging to {os.path.abspath(log_file)}")
except Exception as e:
    print(f"Error setting up log file: {str(e)}")
    # Fall back to console-only logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    logger = logging.getLogger("presidio_scanner")
    logger.error(f"Could not set up file logging to {log_file}: {str(e)}")
    logger.info("Falling back to console-only logging")

def parse_syslog_for_changes(log_path, since_timestamp=None):
    """
    Parse syslog file for file change entries since the specified timestamp.
    Extracts file IDs, names, and timestamps from JSON log entries.
    """
    if not os.path.exists(log_path):
        logger.error(f"Syslog file not found: {log_path}")
        return []
    
    file_changes = []
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Look for lines containing file information
                if "file_id" in line:
                    # Extract JSON data if possible
                    json_data = None
                    try:
                        json_match = re.search(r'(\{.*\})', line)
                        if json_match:
                            json_str = json_match.group(1)
                            json_data = json.loads(json_str)
                    except json.JSONDecodeError:
                        pass
                    
                    # Extract timestamp from various sources
                    timestamp_str = None
                    timestamp_match = re.search(r'Timestamp:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                    if timestamp_match:
                        timestamp_str = timestamp_match.group(1)
                    
                    if not timestamp_str and json_data and 'timestamp' in json_data:
                        timestamp_str = json_data['timestamp']
                    
                    if not timestamp_str and json_data and 'details' in json_data and 'timestamp' in json_data['details']:
                        timestamp_str = json_data['details']['timestamp']
                    
                    # Fall back to log entry timestamp
                    if not timestamp_str:
                        syslog_timestamp_match = re.search(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                        if syslog_timestamp_match:
                            log_timestamp = syslog_timestamp_match.group(1)
                            current_year = datetime.datetime.now().year
                            log_date = datetime.datetime.strptime(f"{log_timestamp} {current_year}", "%b %d %H:%M:%S %Y")
                            timestamp_str = log_date.strftime("%Y-%m-%d %H:%M:%S")
                    
                    if not timestamp_str:
                        logger.debug(f"No timestamp found in line: {line[:100]}...")
                        continue
                    
                    # Skip entries before filter timestamp
                    if since_timestamp and timestamp_str < since_timestamp:
                        logger.debug(f"Skipping entry with timestamp {timestamp_str} (before {since_timestamp})")
                        continue
                      
                    # Extract file information
                    file_id = None
                    file_name = "Unknown"
                    
                    # Try JSON data first
                    if json_data and 'file_id' in json_data:
                        file_id = json_data['file_id']
                        file_name = json_data.get('file_name', json_data.get('name', "Unknown"))
                    else:
                        # Use regex patterns as fallback
                        file_id_match = re.search(r'"file_id":\s*"([^"]+)"', line)
                        if not file_id_match:
                            file_id_match = re.search(r'"file_id":\s*([^,}\s]+)', line)
                            
                        if not file_id_match:
                            file_id_match = re.search(r"'file_id':\s*'([^']+)'", line)
                        
                        if file_id_match:
                            file_id = file_id_match.group(1)
                            
                            # Extract file name
                            file_name_match = re.search(r'"file_name":\s*"([^"]+)"', line)
                            if not file_name_match:
                                file_name_match = re.search(r'"name":\s*"([^"]+)"', line)
                            
                            if not file_name_match:
                                file_name_match = re.search(r"'file_name':\s*'([^']+)'", line)
                                if not file_name_match:
                                    file_name_match = re.search(r"'name':\s*'([^']+)'", line)
                            
                            file_name = file_name_match.group(1) if file_name_match else "Unknown"
                      
                    # Add file to results if ID found
                    if file_id:
                        # Extract owner information
                        owner = "Unknown"
                        
                        if json_data and 'owner' in json_data:
                            owner = json_data['owner']
                        elif json_data and 'details' in json_data and 'owner' in json_data['details']:
                            owner = json_data['details']['owner']
                        else:
                            owner_match = re.search(r'"owner":\s*"([^"]+)"', line)
                            if not owner_match:
                                owner_match = re.search(r"'owner':\s*'([^']+)'", line)
                            
                            if owner_match:
                                owner = owner_match.group(1)
                        
                        file_changes.append({
                            "file_id": file_id,
                            "name": file_name,
                            "timestamp": timestamp_str,
                            "owner": owner
                        })
                        logger.debug(f"Found file: {file_name} (ID: {file_id}), Owner: {owner}, at timestamp {timestamp_str}")
    
    except Exception as e:
        logger.error(f"Error parsing syslog: {str(e)}")
    
    return file_changes

def get_last_scan_time(timestamp_file="last_presidio_scan.txt"):
    """Get timestamp of the last scan from file."""
    if os.path.exists(timestamp_file):
        try:
            with open(timestamp_file, 'r') as f:
                timestamp_str = f.read().strip()
                logger.info(f"Last scan timestamp: {timestamp_str}")
                return timestamp_str
        except Exception as e:
            logger.error(f"Error reading last scan timestamp: {str(e)}")
    
    logger.info("No previous scan timestamp found")
    return None

def save_scan_time(timestamp_file="last_presidio_scan.txt"):
    """Save current time as the last scan timestamp."""
    try:
        current_time = datetime.datetime.now()
        timestamp_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        
        with open(timestamp_file, 'w') as f:
            f.write(timestamp_str)
            
        logger.info(f"Saved current scan timestamp: {timestamp_str}")
    except Exception as e:
        logger.error(f"Error saving scan timestamp: {str(e)}")

def scan_modified_files(syslog_path="syslog.log", credentials_file="credentials.json", token_file="token.json"):
    """
    Scan files modified since the last scan for sensitive content.
    Returns statistics about the scan results.
    """
    stats = {
        'scanned_files': 0,
        'sensitive_files': 0,
        'total_entities': 0,
        'high_sensitivity': 0,
        'moderate_sensitivity': 0,
        'low_sensitivity': 0
    }
    
    # Debug: log all files in syslog
    all_changes = parse_syslog_for_changes(syslog_path, since_timestamp=None)
    logger.info(f"Total files found in syslog (regardless of timestamp): {len(all_changes)}")
    if len(all_changes) > 0:
        logger.info(f"First few files in syslog: {all_changes[:3]}")
    else:
        logger.info("No files found in syslog - pattern matching may be incorrect")
    
    # Get last scan time
    last_scan_time = get_last_scan_time()
    if last_scan_time:
        logger.info(f"Looking for files modified since {last_scan_time}")
    else:
        # Default to 1 day ago if no previous scan
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        last_scan_time = yesterday.strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"No previous scan time found, using default: {last_scan_time}")
      
    # Parse syslog for changes
    file_changes = parse_syslog_for_changes(syslog_path, last_scan_time)
    logger.info(f"Found {len(file_changes)} modified files to scan")
    
    # Deduplicate files by file_id (keep latest entry)
    unique_files = {}
    for file_info in file_changes:
        file_id = file_info['file_id']
        if file_id not in unique_files or file_info.get('timestamp', '') > unique_files[file_id].get('timestamp', ''):
            unique_files[file_id] = file_info
    
    file_changes = list(unique_files.values())
    logger.info(f"After deduplication: {len(file_changes)} unique files to scan")
    
    if not file_changes:
        logger.info("No modified files found - check if syslog.log has the correct format")
        logger.info("Sample syslog entry should contain 'file_id' and file details")
        # Debug syslog file
        if os.path.exists(syslog_path):
            file_size = os.path.getsize(syslog_path)
            logger.info(f"Syslog file size: {file_size} bytes")
            try:
                with open(syslog_path, 'r', encoding='utf-8') as f:
                    last_lines = f.readlines()[-5:]
                    logger.info("Last few lines of syslog.log:")
                    for line in last_lines:
                        logger.info(f"LOG: {line.strip()}")
            except Exception as e:
                logger.error(f"Error reading syslog: {str(e)}")
        return stats
        
    # Get Google Drive credentials
    creds = get_credentials(credentials_file, token_file)
    service = build('drive', 'v3', credentials=creds)
    
    # Process each file
    for file_info in file_changes:
        file_id = file_info['file_id']
        logger.info(f"Scanning file: {file_info.get('name', 'Unknown')} (ID: {file_id})")
        
        try:            
            # Get file metadata
            metadata = get_file_metadata(service, file_id)
            if not metadata:
                logger.warning(f"Could not get metadata for file {file_id}")
                continue
            
            # Get file MIME type
            try:
                file_details = service.files().get(fileId=file_id, fields='mimeType').execute()
                mime_type = file_details.get('mimeType', 'Unknown')
                
                # Use owner from syslog instead of additional API call
                owner = file_info.get('owner', 'Unknown')
                metadata['owner'] = owner
            except Exception as e:
                logger.warning(f"Could not get file details for file {file_id}: {e}")
                mime_type = 'Unknown'
                metadata['owner'] = file_info.get('owner', 'Unknown')
                
            modified_by = metadata.get('modified_by', 'Unknown')
            modified_date = metadata.get('modified_date', 'Unknown')
            owner = metadata.get('owner', 'Unknown')
            
            logger.info(f"File mime type: {mime_type}, Owner: {owner}, Modified by: {modified_by}, Date: {modified_date}")
            
            # Extract file content
            content = get_file_content(service, file_id, mime_type, file_info.get('name', 'Unknown'))
            
            if not content:
                logger.warning(f"Could not extract content from file {file_id}")
                continue
            
            content_length = len(content)
            logger.info(f"Got file content, length: {content_length} characters")
            
            # Analyze content with Presidio
            analyzer_results = analyzer.analyze(text=content, language="en")
            logger.info(f"Presidio analysis completed, found {len(analyzer_results)} potential entities")
              
            # Count entities by sensitivity level
            high_count = 0
            moderate_count = 0
            low_count = 0
            
            for result in analyzer_results:
                if result.score and result.score > 0.4:
                    stats['total_entities'] += 1
                    entity_type = result.entity_type
                    
                    if entity_type in highly_sensitive:
                        high_count += 1
                        stats['high_sensitivity'] += 1
                    elif entity_type in moderately_sensitive:
                        moderate_count += 1
                        stats['moderate_sensitivity'] += 1
                    else:
                        low_count += 1
                        stats['low_sensitivity'] += 1
              
            # Prepare entity counts for logging
            entity_counts = {
                'high': high_count,
                'moderate': moderate_count,
                'low': low_count
            }
              
            # Log detailed file information
            try:
                log_file_details(
                    file_info=file_info,
                    metadata=metadata,
                    mime_type=mime_type,
                    entity_counts=entity_counts,
                    analyzer_results=analyzer_results,
                    original_text=content
                )
            except Exception as e:
                logger.error(f"Error logging file details: {str(e)}", exc_info=True)
                logger.info(f"File {file_info.get('name', 'Unknown')} ({file_id}): Found {high_count} high, {moderate_count} moderate, {low_count} low sensitivity entities")
              
            # Log to Airtable if sensitive content found
            if high_count > 0 or moderate_count > 0 or low_count > 0:
                stats['sensitive_files'] += 1
                log_to_airtable(
                    file_id=file_id,
                    file_name=file_info.get('name', 'Unknown'),
                    results=analyzer_results,
                    text=content,
                    mime_type=mime_type,
                    modified_by=modified_by,
                    modified_date=modified_date
                )
                logger.info(f"Sensitive content found in {file_info.get('name', 'Unknown')}: {high_count} high, {moderate_count} moderate, {low_count} low")
            else:
                logger.info(f"No sensitive content found in {file_info.get('name', 'Unknown')}")
            
            stats['scanned_files'] += 1
            
        except Exception as e:
            logger.error(f"Error scanning file {file_id}: {str(e)}", exc_info=True)
      
    # Save scan completion timestamp
    save_scan_time()
    
    return stats

def log_file_details(file_info, metadata, mime_type, entity_counts, analyzer_results, original_text=None):
    """Log detailed scan information to the log file."""
    # Create timestamp for log entry
    scan_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate sensitivity metrics
    total_entities = entity_counts['high'] + entity_counts['moderate'] + entity_counts['low']
    sensitivity_score = calculate_sensitivity_score(entity_counts)
    risk_level = get_risk_level(sensitivity_score)
      
    # Create structured log entry
    log_entry = f"""
FILE SCAN: {scan_timestamp}
FileID: {file_info.get('file_id', 'Unknown')}
FileName: {file_info.get('name', 'Unknown')}
Owner: {metadata.get('owner', file_info.get('owner', 'Unknown'))}
LastModifiedBy: {metadata.get('modified_by', 'Unknown')}
LastModifiedDate: {metadata.get('modified_date', 'Unknown')}
SensitivityScore: {sensitivity_score}/100
RiskLevel: {risk_level}
HighSensitivity: {entity_counts['high']}
ModerateSensitivity: {entity_counts['moderate']}
LowSensitivity: {entity_counts['low']}
TotalEntities: {total_entities}
"""
    
    # Write directly to log file
    try:
        with open("presidio_scan.log", "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        logger.error(f"Error writing to log file: {str(e)}")
    
    logger.info(f"Scan details logged for file: {file_info.get('name', 'Unknown')} (ID: {file_info.get('file_id', 'Unknown')})")
    logger.info(f"Sensitivity Score: {sensitivity_score}/100, Risk Level: {risk_level}")
    
    # Update MongoDB via API
    modified_by = metadata.get('modified_by', 'Unknown')
    update_mongodb_sensitivity(file_info, sensitivity_score, risk_level, entity_counts, total_entities, modified_by)

def update_mongodb_sensitivity(file_info, sensitivity_score, risk_level, entity_counts, total_entities, modified_by=None):
    """Update MongoDB with sensitivity score via API endpoint."""
    try:
        # Prepare API request data
        data = {
            'file_id': file_info.get('file_id'),
            'sensitivity_score': sensitivity_score,
            'risk_level': risk_level,
            'high_sensitivity': entity_counts['high'],
            'moderate_sensitivity': entity_counts['moderate'],
            'low_sensitivity': entity_counts['low'],
            'total_entities': total_entities,
            'modified_by': modified_by or 'Unknown'
        }
        
        # Call API endpoint
        api_url = "http://localhost:5001/api/update-sensitivity"
        response = requests.post(api_url, json=data, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"Successfully updated MongoDB sensitivity data for file {file_info.get('file_id')}")
        else:
            logger.warning(f"Failed to update MongoDB sensitivity data: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Error updating MongoDB sensitivity data: {str(e)}")
        # Don't fail scan if MongoDB update fails
        pass

def calculate_sensitivity_score(entity_counts):
    """Calculate weighted sensitivity score from 0-100 based on entity counts."""
    # Weighted scoring system
    high_weight = 10
    moderate_weight = 5
    low_weight = 1
    
    # Calculate raw score
    raw_score = (entity_counts['high'] * high_weight + 
                entity_counts['moderate'] * moderate_weight + 
                entity_counts['low'] * low_weight)
    
    # Cap at 100
    return min(raw_score, 100)

def get_risk_level(sensitivity_score):
    """Convert sensitivity score to risk level classification."""
    if sensitivity_score >= 70:
        return "CRITICAL"
    elif sensitivity_score >= 50:
        return "HIGH"
    elif sensitivity_score >= 30:
        return "MODERATE"
    elif sensitivity_score > 0:
        return "LOW"
    else:
        return "NONE"

def mask_sensitive_data(text, entity_type):
    """Mask sensitive data for secure logging."""
    if text is None or not text:
        return "[EMPTY]"
    
    if not isinstance(text, str):
        text = str(text)
    
    if entity_type in highly_sensitive:
        # Show only first and last character for highly sensitive data
        if len(text) <= 2:
            return "*" * len(text)
        return text[0] + "*" * (len(text) - 2) + text[-1]
    elif entity_type in moderately_sensitive:
        # Show first 2 and last 2 characters for moderate sensitivity
        if len(text) <= 4:
            return "*" * len(text)
        return text[:2] + "*" * (len(text) - 4) + text[-2:]
    else:
        # Show 30% of characters for low sensitivity data
        visible_chars = max(2, int(len(text) * 0.3))
        hidden_chars = len(text) - visible_chars
        return text[:visible_chars] + "*" * hidden_chars

def main():
    """Main execution function with command-line argument handling."""
    parser = argparse.ArgumentParser(description='Scan modified files for sensitive content')
    parser.add_argument('--credentials', type=str, default='credentials.json',
                      help='Path to the Google API credentials file')
    parser.add_argument('--token', type=str, default='token.json',
                      help='Path to the token file for authentication')
    parser.add_argument('--syslog', type=str, default='syslog.log',
                      help='Path to the syslog file')
    parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      default='INFO', help='Set the logging level')
    parser.add_argument('--report', action='store_true',
                      help='Generate a report of sensitive files after scanning')
    
    args = parser.parse_args()

    # Set logging level
    logger.setLevel(getattr(logging, args.log_level))
    
    # Reset log file if it's from a previous day
    try:
        reset_log = False
        if os.path.exists("presidio_scan.log"):
            log_mtime = os.path.getmtime("presidio_scan.log")
            log_date = datetime.datetime.fromtimestamp(log_mtime).date()
            today = datetime.datetime.now().date()
            
            if log_date < today:
                reset_log = True
                with open("presidio_scan.log", "w", encoding="utf-8") as f:
                    f.write(f"Log reset on {datetime.datetime.now()}\n\n")
                logger.info("Log file reset (previous day's log)")
    except Exception as e:
        logger.warning(f"Error checking log file date: {str(e)}")
    
    # Log scan start
    start_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open("presidio_scan.log", "a", encoding="utf-8") as log_file:
            log_file.write(f"\nSCAN STARTED: {start_timestamp}\n")
    except Exception as e:
        logger.error(f"Error writing to log file: {str(e)}")
    
    logger.info(f"Starting presidio scanner - {start_timestamp}")
    
    # Perform file scanning
    stats = scan_modified_files(
        syslog_path=args.syslog,
        credentials_file=args.credentials,
        token_file=args.token
    )    
    
    # Generate summary
    scan_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate overall risk metrics
    overall_score = 0
    if stats['total_entities'] > 0:
        high_weight = 10
        moderate_weight = 5
        low_weight = 1
        
        raw_score = (stats['high_sensitivity'] * high_weight + 
                     stats['moderate_sensitivity'] * moderate_weight + 
                     stats['low_sensitivity'] * low_weight)
        
        overall_score = min(raw_score, 100)
    
    risk_level = get_risk_level(overall_score)
    
    # Create summary log entry
    summary_entry = f"""
SCAN SUMMARY: {scan_timestamp}
FilesScanned: {stats['scanned_files']}
FilesSensitive: {stats['sensitive_files']}
TotalEntities: {stats['total_entities']}
HighSensitivity: {stats['high_sensitivity']}
ModerateSensitivity: {stats['moderate_sensitivity']}
LowSensitivity: {stats['low_sensitivity']}
OverallScore: {overall_score}/100
RiskLevel: {risk_level}
"""
    
    # Write summary to log file
    try:
        with open("presidio_scan.log", "a", encoding="utf-8") as log_file:
            log_file.write("\n" + "="*50 + "\n")
            log_file.write(summary_entry)
            log_file.write("="*50 + "\n")
    except Exception as e:
        logger.error(f"Error writing summary to log file: {str(e)}")
    
    logger.info(f"Scan complete - {scan_timestamp}")
    logger.info(f"Files scanned: {stats['scanned_files']}, Files with sensitive data: {stats['sensitive_files']}")
    logger.info(f"Overall Risk Level: {risk_level} ({overall_score}/100)")
    
    # Generate detailed report if requested
    if args.report:
        from pres_airtableSensitivityUpdate import get_sensitive_files, get_high_risk_files
        logger.info("Generating sensitive files report from Airtable")
        
        high_risk_files = get_high_risk_files()
        logger.info(f"Found {len(high_risk_files)} high risk files")
        
        moderate_files = get_sensitive_files(min_sensitivity_score=30)
        logger.info(f"Found {len(moderate_files)} moderate risk files")        
        
        # Log detailed risk file information
        try:
            with open("presidio_scan.log", "a", encoding="utf-8") as log_file:
                log_file.write("\nHIGH RISK FILES:\n")
                
                for i, file in enumerate(high_risk_files, 1):
                    file_entry = f"""
{i}. {file.get('file_name', 'Unknown')}
   FileID: {file.get('file_id', 'Unknown')}
   Owner: {file.get('owner', 'Unknown')}
   ModifiedBy: {file.get('modified_by', 'Unknown')}
   ModifiedDate: {file.get('modified_date', 'Unknown')}
   SensitivityScore: {file.get('sensitivity_score', 'N/A')}
"""
                    log_file.write(file_entry)
                
                if moderate_files:
                    log_file.write(f"\nMODERATE RISK FILES: {len(moderate_files)}\n")
                
                log_file.write("\n" + "="*50 + "\n")
        except Exception as e:
            logger.error(f"Error writing risk file details to log file: {str(e)}")
        
        logger.info(f"Report generated - High risk files: {len(high_risk_files)}, Moderate+ risk files: {len(moderate_files)}")

if __name__ == "__main__":
    main()