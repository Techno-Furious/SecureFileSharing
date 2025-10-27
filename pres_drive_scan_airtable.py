"""
Google Drive content scanner with Airtable integration for sensitivity analysis.
Extracts text content from various file formats and analyzes for sensitive data using Presidio.
Supports Google Docs, Sheets, Slides, PDFs, Word documents, and text files.
Stores scan results and sensitivity scores in Airtable for centralized tracking and reporting.
"""

import os
import logging
import argparse
import datetime
import io
from googleapiclient.http import MediaIoBaseDownload
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from pres_presidio_connector import analyzer, call_presidio, print_analyzer_results
from pres_airtableSensitivityUpdate import log_to_airtable
import pytz

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("drive_analysis.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("drive_analyzer")

def get_credentials(credentials_file, token_file):
    """Authenticate and refresh Google Drive API credentials."""
    logger.info(f"Authenticating using {credentials_file} and {token_file}")
    creds = None
    
    # Google Drive API scopes
    SCOPES = ["https://www.googleapis.com/auth/drive"]

    # Load existing credentials if available
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        logger.info("Loaded credentials from token file")

    # Refresh or obtain new credentials
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logger.info("Refreshing expired credentials")
                creds.refresh(Request())
            except Exception as e:
                logger.warning(f"Failed to refresh credentials: {e}")
                logger.info("Initiating new authentication flow")
                flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
                creds = flow.run_local_server(port=0)
        else:
            logger.info("Initiating new authentication flow")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save credentials for future use
        with open(token_file, "w") as token:
            token.write(creds.to_json())
            logger.info(f"Saved new credentials to {token_file}")
            
    return creds

def get_file_content(service, file_id, mime_type, file_name="Unknown"):
    """Extract text content from files based on MIME type without local file storage."""
    content = ""
    
    try:
        logger.info(f"Processing file: {file_name} ({mime_type})")
        
        if 'application/vnd.google-apps.document' in mime_type:
            # Google Docs
            logger.info(f"Exporting Google Doc content for {file_name}")
            docs = service.files().export(fileId=file_id, mimeType='text/plain').execute()
            content = docs.decode('utf-8')
            logger.debug(f"Successfully exported Google Doc content, size: {len(content)} bytes")
            
        elif 'application/vnd.google-apps.spreadsheet' in mime_type:
            # Google Sheets
            logger.info(f"Exporting Google Sheet content for {file_name}")
            sheets = service.files().export(fileId=file_id, mimeType='text/csv').execute()
            content = sheets.decode('utf-8')
            logger.debug(f"Successfully exported Google Sheet content, size: {len(content)} bytes")
            
        elif 'application/vnd.google-apps.presentation' in mime_type:
            # Google Slides
            logger.info(f"Exporting Google Slides content for {file_name}")
            slides = service.files().export(fileId=file_id, mimeType='text/plain').execute()
            content = slides.decode('utf-8')
            logger.debug(f"Successfully exported Google Slides content, size: {len(content)} bytes")
            
        elif 'application/vnd.google-apps.script' in mime_type:
            # Google Apps Script
            logger.info(f"Exporting Google Apps Script content for {file_name}")
            script = service.files().export(fileId=file_id, mimeType='application/vnd.google-apps.script+json').execute()
            content = script.decode('utf-8')
            logger.debug(f"Successfully exported Google Apps Script content, size: {len(content)} bytes")
            
        elif 'application/pdf' in mime_type:
            # PDF files
            logger.info(f"Extracting text from PDF file: {file_name}")
            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                if status:
                    logger.debug(f"PDF download progress: {int(status.progress() * 100)}%")
            
            # Extract text from PDF in memory
            import PyPDF2
            fh.seek(0)
            pdf_reader = PyPDF2.PdfReader(fh)
            content = ""
            for i, page in enumerate(pdf_reader.pages):
                page_text = page.extract_text()
                content += page_text + "\n"
                logger.debug(f"Extracted text from PDF page {i+1}, size: {len(page_text)} bytes")
                
        elif 'text/' in mime_type or 'application/json' in mime_type:
            # Text files, JSON, etc.
            logger.info(f"Downloading text/JSON content for {file_name}")
            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                if status:
                    logger.debug(f"Text file download progress: {int(status.progress() * 100)}%")
            content = fh.getvalue().decode('utf-8')
            logger.debug(f"Successfully downloaded text content, size: {len(content)} bytes")
            
        elif 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' in mime_type:
            # Microsoft Word documents
            logger.info(f"Extracting text from Word document: {file_name}")
            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                if status:
                    logger.debug(f"Word document download progress: {int(status.progress() * 100)}%")
                
            # Extract text from Word document in memory
            from docx import Document
            fh.seek(0)
            doc = Document(fh)
            content = "\n".join([para.text for para in doc.paragraphs])
            logger.debug(f"Successfully extracted text from Word document, size: {len(content)} bytes")
                
        else:
            logger.warning(f"Unsupported MIME type: {mime_type}, skipping content extraction")
            
    except Exception as e:
        logger.error(f"Error extracting content from file {file_name}: {e}", exc_info=True)
    
    return content

def get_file_metadata(service, file_id):
    """Retrieve file metadata including modification details and convert timestamps to IST."""
    try:
        file = service.files().get(
            fileId=file_id,
            fields='id,name,mimeType,modifiedTime,lastModifyingUser'
        ).execute()
        
        # Convert UTC timestamp to IST
        utc_time = datetime.datetime.strptime(file['modifiedTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
        utc_time = utc_time.replace(tzinfo=pytz.UTC)
        
        ist = pytz.timezone('Asia/Kolkata')
        ist_time = utc_time.astimezone(ist)
        modified_date = ist_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Extract last modifier information
        modifier = None
        if 'lastModifyingUser' in file:
            user = file['lastModifyingUser']
            display_name = user.get('displayName', 'Unknown')
            email = user.get('emailAddress', '')
            if email:
                modifier = f"{display_name} ({email})"
            else:
                modifier = display_name
                
        return {
            'modified_date': modified_date,
            'modified_by': modifier
        }
    except Exception as e:
        logger.error(f"Error fetching metadata for file {file_id}: {e}")
        return {}

def analyze_drive_content(credentials_file, 
                      token_file,
                      file_types=None,
                      limit=None, 
                      query=None,
                      log_level="INFO"):
    """
    Main function to analyze Google Drive files for sensitive information and store results in Airtable.
    Returns statistics about the analysis including entity counts and sensitivity levels.
    """
    # Set log level
    logger.setLevel(getattr(logging, log_level))
    
    logger.info("Starting Google Drive content analysis with Airtable storage")
    
    # Get credentials
    creds = get_credentials(credentials_file, token_file)
    
    # Initialize statistics tracking
    stats = {
        'total_files': 0,
        'processed_files': 0,
        'entities_found': 0,
        'high_sensitivity': 0,
        'moderate_sensitivity': 0,
        'low_sensitivity': 0,
        'files_with_sensitive_data': []
    }
    
    # Create Drive API service
    try:
        service = build("drive", "v3", credentials=creds)
        
        # Build file query
        query_parts = ["trashed=false"]  # Exclude deleted files
        
        if file_types:
            mime_type_conditions = []
            for mime_type in file_types:
                mime_type_conditions.append(f"mimeType contains '{mime_type}'")
                
            if mime_type_conditions:
                query_parts.append(f"({' or '.join(mime_type_conditions)})")
        
        if query:
            query_parts.append(query)
            
        query_string = " and ".join(query_parts)
        logger.info(f"Using query: {query_string}")
        
        # List files from Drive
        results = service.files().list(
            pageSize=100 if not limit or limit > 100 else limit,
            fields="nextPageToken, files(id, name, mimeType, description)",
            q=query_string
        ).execute()
        
        items = results.get("files", [])
        stats['total_files'] = len(items)
        
        if not items:
            logger.warning("No files found in Google Drive matching the criteria.")
            return stats
        
        logger.info(f"Found {len(items)} files matching the criteria")
        
        # Process each file
        for i, item in enumerate(items):
            if limit and i >= limit:
                logger.info(f"Reached limit of {limit} files")
                break
                
            file_id = item['id']
            file_name = item['name']
            mime_type = item['mimeType']
            
            logger.info(f"Processing file {i+1}/{min(len(items), limit or len(items))}: {file_name} ({mime_type})")
            
            # Skip folders
            if mime_type == 'application/vnd.google-apps.folder':
                logger.debug(f"Skipping folder: {file_name}")
                continue
            
            # Get file metadata
            metadata = get_file_metadata(service, file_id)
            
            # Extract file content
            content = get_file_content(service, file_id, mime_type, file_name)
            
            if content:
                stats['processed_files'] += 1
                
                # Analyze content with Presidio
                analyzer_results = analyzer.analyze(text=content, language="en")
                
                # Track entities found in this file
                file_entities = 0
                file_has_sensitive_data = False
                
                # Store results in Airtable
                if analyzer_results:
                    airtable_id = log_to_airtable(
                        file_id=file_id,
                        file_name=file_name,
                        results=analyzer_results,
                        text=content,
                        mime_type=mime_type,
                        modified_by=metadata.get('modified_by'),
                        modified_date=metadata.get('modified_date')
                    )
                    
                    # Count entities by sensitivity level
                    for result in analyzer_results:
                        if result.score is not None and result.score > 0.4:
                            entity_type = result.entity_type
                            
                            if entity_type in [
                                "UK_NINO", "US_SSN", "US_ITIN", "US_DRIVER_LICENSE", 
                                "US_BANK_NUMBER", "CREDIT_CARD", "IBAN_CODE", "AADHAAR",
                                "IN_AADHAAR", "IN_PAN", "IN_PASSPORT", "IN_VOTER", "US_PASSPORT"
                            ]:
                                stats['high_sensitivity'] += 1
                                file_has_sensitive_data = True
                            elif entity_type in [
                                "MEDICAL_LICENSE", "CRYPTO", "EMAIL_ADDRESS", 
                                "PHONE_NUMBER", "IN_VEHICLE_REGISTRATION"
                            ]:
                                stats['moderate_sensitivity'] += 1
                                file_has_sensitive_data = True
                            elif entity_type in [
                                "PERSON", "LOCATION", "FIRST_NAME", "LAST_NAME"
                            ]:
                                stats['low_sensitivity'] += 1
                            
                            file_entities += 1
                            stats['entities_found'] += 1
                    
                    logger.info(f"Found {file_entities} entities in {file_name}, logged to Airtable with ID: {airtable_id}")
                
                if file_has_sensitive_data:
                    stats['files_with_sensitive_data'].append({
                        'name': file_name,
                        'id': file_id,
                        'mime_type': mime_type
                    })
            else:
                logger.warning(f"No content extracted from {file_name}")
                        
        logger.info(f"Analysis complete. Results saved to Airtable.")
        
        return stats
            
    except HttpError as error:
        logger.error(f"Google API error: {error}", exc_info=True)
        return stats


if __name__ == "__main__":
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description='Analyze Google Drive files for sensitive information.')
    parser.add_argument('--credentials', type=str, default='credentials1.json',
                        help='Path to the Google API credentials file')
    parser.add_argument('--token', type=str, default='token1.json',
                        help='Path to the token file for authentication')
    parser.add_argument('--mime-types', type=str, nargs='+',
                        help='Filter by MIME types (e.g., "application/pdf" "text/plain")')
    parser.add_argument('--limit', type=int, default=None,
                        help='Maximum number of files to process')
    parser.add_argument('--query', type=str, default=None,
                        help='Additional query string for file filtering')
    parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO', help='Set the logging level')
    
    args = parser.parse_args()
    
    # Run analysis
    stats = analyze_drive_content(
        credentials_file=args.credentials,
        token_file=args.token,
        file_types=args.mime_types,
        limit=args.limit,
        query=args.query,
        log_level=args.log_level
    )
    
    # Print summary statistics
    logger.info("Analysis complete!")
    logger.info(f"Total files found: {stats['total_files']}")
    logger.info(f"Files processed: {stats['processed_files']}")
    logger.info(f"Total entities found: {stats['entities_found']}")
    logger.info(f"HIGH sensitivity entities: {stats['high_sensitivity']}")
    logger.info(f"MODERATE sensitivity entities: {stats['moderate_sensitivity']}")
    logger.info(f"LOW sensitivity entities: {stats['low_sensitivity']}")
    logger.info(f"Files with sensitive data: {len(stats['files_with_sensitive_data'])}")
    
    logger.info("Results saved to Airtable")
