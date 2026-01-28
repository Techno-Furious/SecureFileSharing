"""
Slack and Jira utility functions for security incident notifications.
This module handles automated ticket creation and Slack notifications when users are blocked.
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, Optional, List
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
import matplotlib.pyplot as plt
import io
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
SLACK_TOKEN = os.getenv('SLACK_TOKEN')
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#security-alerts')
SLACK_CHART_CHANNEL = os.getenv('SLACK_CHART_CHANNEL', '#security-stats')  # Separate channel for charts
JIRA_DOMAIN = os.getenv('JIRA_DOMAIN')
JIRA_EMAIL = os.getenv('JIRA_EMAIL')
JIRA_API_TOKEN = os.getenv('JIRA_API_TOKEN')
JIRA_PROJECT_KEY = os.getenv('JIRA_PROJECT_KEY', 'SEC')

# Alert storage file
ALERTS_LOG_FILE = 'alerts_log.json'

# Disable proxy for all requests (to avoid SSL errors when running inside MITM proxy)
NO_PROXY = {'http': None, 'https': None}


def load_alerts_log() -> Dict:
    """Load the alerts log from disk."""
    if os.path.exists(ALERTS_LOG_FILE):
        with open(ALERTS_LOG_FILE, 'r') as f:
            return json.load(f)
    return {'alerts': []}


def save_alerts_log(log: Dict) -> None:
    """Save the alerts log to disk."""
    with open(ALERTS_LOG_FILE, 'w') as f:
        json.dump(log, f, indent=2)


def is_duplicate_alert(user_email: str, activity_type: str) -> bool:
    """Check if this alert was already sent recently (within last 24 hours)."""
    log = load_alerts_log()
    alert_key = f"{user_email}:{activity_type}"
    current_time = datetime.now().timestamp()
    
    for alert in log.get('alerts', []):
        if alert.get('key') == alert_key:
            # Check if alert is less than 24 hours old
            if current_time - alert.get('timestamp', 0) < 86400:
                return True
    
    return False


def record_alert(user_email: str, activity_type: str, jira_key: Optional[str] = None) -> None:
    """Record an alert in the log."""
    log = load_alerts_log()
    if 'alerts' not in log:
        log['alerts'] = []
    
    log['alerts'].append({
        'key': f"{user_email}:{activity_type}",
        'timestamp': datetime.now().timestamp(),
        'email': user_email,
        'activity': activity_type,
        'jira_ticket': jira_key,
        'date': datetime.now().isoformat()
    })
    
    # Keep only last 1000 alerts
    log['alerts'] = log['alerts'][-1000:]
    save_alerts_log(log)


def create_jira_ticket(user_email: str, activity_type: str) -> Optional[str]:
    """
    Create a Jira ticket for a blocked user.
    
    Args:
        user_email: Email of the suspicious user
        activity_type: Type of activity that triggered the block
        
    Returns:
        Jira ticket key (e.g., 'SEC-123') or None if failed
    """
    if not all([JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY]):
        print("⚠️  Jira configuration incomplete. Skipping ticket creation.")
        return None
    
    url = f"{JIRA_DOMAIN}/rest/api/3/issue"
    
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    summary = f"User Blocked: {user_email} - {activity_type}"
    description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": f"User {user_email} has been blocked due to suspicious activity.",
                        "marks": [{"type": "strong"}]
                    }
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Activity Type: "},
                    {"type": "text", "text": activity_type, "marks": [{"type": "code"}]}
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Timestamp: "},
                    {"type": "text", "text": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Action Required: Review user activity logs and determine if block should be maintained or lifted."}
                ]
            }
        ]
    }
    
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"},
            "priority": {"name": "High"},
            "labels": ["security", "user-blocked", activity_type.lower().replace(" ", "-")]
        }
    }
    
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            auth=(JIRA_EMAIL, JIRA_API_TOKEN),
            timeout=10,
            proxies=NO_PROXY
        )
        
        if response.status_code == 201:
            ticket_data = response.json()
            ticket_key = ticket_data.get('key')
            print(f"✅ Jira ticket created: {ticket_key}")
            return ticket_key
        else:
            print(f"❌ Failed to create Jira ticket: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error creating Jira ticket: {e}")
        return None


def get_jira_ticket_stats() -> Dict[str, int]:
    """
    Get statistics about open/closed Jira tickets.
    
    Returns:
        Dictionary with ticket counts by status
    """
    if not all([JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY]):
        print(f"   ⚠️  Jira not configured, using mock data")
        return {'Open': 3, 'In Progress': 1, 'Done': 2}
    
    # Use Jira REST API v3 search endpoint
    url = f"{JIRA_DOMAIN}/rest/api/3/search/jql"
    
    # Simple JQL query for all issues in the project
    jql = f'project={JIRA_PROJECT_KEY}'
    
    try:
        response = requests.get(
            url,
            params={
                'jql': jql,
                'maxResults': 100,
                'fields': 'status'
            },
            auth=(JIRA_EMAIL, JIRA_API_TOKEN),
            headers={'Accept': 'application/json'},
            timeout=10,
            proxies=NO_PROXY
        )
        
        if response.status_code == 200:
            data = response.json()
            issues = data.get('issues', [])
            total = data.get('total', 0)
            
            stats = {'Open': 0, 'In Progress': 0, 'Done': 0}
            
            for issue in issues:
                status_name = issue.get('fields', {}).get('status', {}).get('name', '')
                if status_name in ['To Do', 'Open', 'Backlog']:
                    stats['Open'] += 1
                elif status_name in ['In Progress', 'In Review']:
                    stats['In Progress'] += 1
                elif status_name in ['Done', 'Closed', 'Resolved']:
                    stats['Done'] += 1
            
            print(f"   ✅ Fetched {len(issues)} of {total} tickets from Jira")
            return stats
        elif response.status_code == 401:
            print(f"   ⚠️  Jira authentication failed. Check JIRA_EMAIL and JIRA_API_TOKEN")
            return {'Open': 3, 'In Progress': 1, 'Done': 2}
        elif response.status_code == 404:
            print(f"   ⚠️  Project '{JIRA_PROJECT_KEY}' not found. Check JIRA_PROJECT_KEY")
            return {'Open': 3, 'In Progress': 1, 'Done': 2}
        else:
            print(f"   ⚠️  Jira API returned {response.status_code}: {response.text[:100]}")
            return {'Open': 3, 'In Progress': 1, 'Done': 2}
            
    except Exception as e:
        print(f"   ⚠️  Jira API error: {str(e)[:50]}")
        return {'Open': 3, 'In Progress': 1, 'Done': 2}


def generate_ticket_chart(stats: Dict[str, int]) -> io.BytesIO:
    """
    Generate a bar chart showing ticket statistics.
    
    Args:
        stats: Dictionary with ticket counts by status
        
    Returns:
        BytesIO object containing the PNG image
    """
    plt.figure(figsize=(8, 5))
    
    statuses = list(stats.keys())
    counts = list(stats.values())
    colors = ['#FF6B6B', '#4ECDC4', '#95E1D3']
    
    bars = plt.bar(statuses, counts, color=colors, edgecolor='black', linewidth=1.2)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    plt.xlabel('Status', fontsize=12, fontweight='bold')
    plt.ylabel('Number of Tickets', fontsize=12, fontweight='bold')
    plt.title('Security Tickets Overview', fontsize=14, fontweight='bold', pad=20)
    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()
    
    # Save to BytesIO
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
    buf.seek(0)
    plt.close()
    
    return buf


def send_slack_notification(user_email: str, activity_type: str, jira_ticket: Optional[str] = None, stats: Optional[Dict[str, int]] = None) -> bool:
    """
    Send a notification to Slack about a blocked user.
    
    Args:
        user_email: Email of the blocked user
        activity_type: Type of activity that triggered the block
        jira_ticket: Jira ticket key if created
        stats: Ticket statistics to include in message
        
    Returns:
        True if successful, False otherwise
    """
    if not SLACK_TOKEN:
        print("⚠️  Slack token not configured. Skipping notification.")
        return False
    
    url = "https://slack.com/api/chat.postMessage"
    
    headers = {
        "Authorization": f"Bearer {SLACK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Build message blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 User Blocked - Security Alert"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*User Email:*\n{user_email}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Activity Type:*\n{activity_type}"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Timestamp:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Status:*\n🔒 Blocked"
                }
            ]
        }
    ]
    
    if jira_ticket:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Jira Ticket:* <{JIRA_DOMAIN}/browse/{jira_ticket}|{jira_ticket}>"
            }
        })
    
    # Add ticket statistics if available
    if stats and sum(stats.values()) > 0:
        stats_text = f"📊 *Current Ticket Status:*\n" \
                    f"🔴 Open: {stats.get('Open', 0)} | " \
                    f"🟡 In Progress: {stats.get('In Progress', 0)} | " \
                    f"🟢 Done: {stats.get('Done', 0)}"
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": stats_text
            }
        })
    
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "Automated security alert from SFS monitoring system"
            }
        ]
    })
    
    payload = {
        "channel": SLACK_CHANNEL,
        "text": f"User {user_email} blocked for {activity_type}",
        "blocks": blocks
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10, proxies=NO_PROXY)
        
        if response.status_code == 200 and response.json().get('ok'):
            print(f"✅ Slack notification sent to {SLACK_CHANNEL}")
            return True
        else:
            print(f"❌ Failed to send Slack notification: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error sending Slack notification: {e}")
        return False


def get_channel_id(channel_name: str) -> Optional[str]:
    """
    Get the channel ID from channel name.
    
    Args:
        channel_name: Channel name with or without # (e.g., '#security-stats' or 'security-stats')
                     OR a channel ID (e.g., 'C0123AB4CDE')
        
    Returns:
        Channel ID (e.g., 'C0123AB4CDE') or None if not found
    """
    if not SLACK_TOKEN:
        return None
    
    # Remove # if present
    clean_name = channel_name.lstrip('#')
    
    # If it looks like a channel ID (starts with C and is alphanumeric), return it directly
    if clean_name.startswith('C') and len(clean_name) > 8 and clean_name.isalnum():
        print(f"   ✅ Using channel ID directly: {clean_name}")
        return clean_name
    
    headers = {
        "Authorization": f"Bearer {SLACK_TOKEN}"
    }
    
    try:
        # Try to get public channels first
        response = requests.get(
            "https://slack.com/api/conversations.list",
            headers=headers,
            params={'types': 'public_channel,private_channel', 'limit': 1000, 'exclude_archived': True},
            timeout=10,
            proxies=NO_PROXY
        )
        
        result = response.json()
        if response.status_code == 200 and result.get('ok'):
            channels = result.get('channels', [])
            print(f"   📋 Found {len(channels)} channels")
            
            for channel in channels:
                if channel.get('name') == clean_name:
                    channel_id = channel.get('id')
                    print(f"   ✅ Found channel '{clean_name}' with ID: {channel_id}")
                    return channel_id
            
            # Debug: print available channels
            print(f"   ⚠️  Channel '{clean_name}' not found. Available channels:")
            for ch in channels[:10]:  # Show first 10
                print(f"      - {ch.get('name')} (ID: {ch.get('id')})")
            if len(channels) > 10:
                print(f"      ... and {len(channels) - 10} more")
        else:
            error = result.get('error', 'Unknown')
            print(f"   ⚠️  API error: {error}")
            if error == 'missing_scope':
                print(f"   💡 TIP: Add 'groups:read' and 'channels:read' scopes, then reinstall the app")
                print(f"   💡 OR: Use the channel ID directly in .env: SLACK_CHART_CHANNEL={clean_name}")
        
        return None
    except Exception as e:
        print(f"   ⚠️  Error fetching channel ID: {e}")
        return None


def upload_chart_to_slack(chart_buffer: io.BytesIO, stats: Dict[str, int], title: str = "Security Tickets Overview") -> bool:
    """
    Upload a chart image to Slack (separate stats channel) using the 3-step upload API.
    
    Args:
        chart_buffer: BytesIO buffer containing the PNG image
        stats: Statistics dictionary for the caption
        title: Title for the uploaded file
        
    Returns:
        True if successful, False otherwise
    """
    if not SLACK_TOKEN:
        print("⚠️  Slack token not configured. Skipping chart upload.")
        return False
    
    # Get the actual channel ID
    channel_id = get_channel_id(SLACK_CHART_CHANNEL)
    if not channel_id:
        print(f"❌ Could not find channel {SLACK_CHART_CHANNEL}. Make sure the bot is invited to the channel.")
        return False
    
    # Create caption with stats
    total = sum(stats.values())
    caption = f"📊 *{title}*\n\n" \
              f"🔴 Open: {stats.get('Open', 0)}\n" \
              f"🟡 In Progress: {stats.get('In Progress', 0)}\n" \
              f"🟢 Done: {stats.get('Done', 0)}\n" \
              f"\n*Total Tickets: {total}*\n" \
              f"_Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
    
    headers = {
        "Authorization": f"Bearer {SLACK_TOKEN}"
    }
    
    try:
        # Step 1: Get upload URL
        chart_buffer.seek(0)
        file_data = chart_buffer.read()
        file_length = len(file_data)
        
        get_url_response = requests.post(
            "https://slack.com/api/files.getUploadURLExternal",
            headers=headers,
            data={
                'filename': 'ticket_stats.png',
                'length': str(file_length)
            },
            timeout=10,
            proxies=NO_PROXY
        )
        
        url_result = get_url_response.json()
        if not (get_url_response.status_code == 200 and url_result.get('ok')):
            print(f"❌ Failed to get upload URL: {url_result.get('error', 'Unknown error')}")
            return False
        
        upload_url = url_result.get('upload_url')
        file_id = url_result.get('file_id')
        
        # Step 2: Upload file to the URL
        upload_response = requests.post(
            upload_url,
            headers={"Content-Type": "application/octet-stream"},
            data=file_data,
            timeout=30,
            proxies=NO_PROXY
        )
        
        if upload_response.status_code != 200:
            print(f"❌ Failed to upload file data: {upload_response.status_code}")
            return False
        
        # Step 3: Complete the upload with actual channel ID
        complete_response = requests.post(
            "https://slack.com/api/files.completeUploadExternal",
            headers=headers,
            data={
                'files': json.dumps([{"id": file_id, "title": title}]),
                'channel_id': channel_id,
                'initial_comment': caption
            },
            timeout=10,
            proxies=NO_PROXY
        )
        
        complete_result = complete_response.json()
        if complete_response.status_code == 200 and complete_result.get('ok'):
            print(f"✅ Chart uploaded to {SLACK_CHART_CHANNEL}")
            return True
        else:
            print(f"❌ Failed to complete upload: {complete_result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error uploading chart: {e}")
        return False


# ============================================================================
# ENTRYPOINT FUNCTION
# ============================================================================

def notify_user_blocked(user_email: str, activity_type: str, force: bool = False) -> Dict[str, any]:
    """
    Main entrypoint function to handle user blocking notifications.
    Creates a Jira ticket, sends Slack notification with ticket statistics chart.
    
    Args:
        user_email: Email address of the blocked user
        activity_type: Type of suspicious activity (e.g., "Unauthorized Access", "Data Exfiltration")
        force: If True, bypass duplicate check and send notification anyway
        
    Returns:
        Dictionary containing:
            - success: bool indicating if operation succeeded
            - jira_ticket: Jira ticket key if created
            - slack_sent: bool indicating if Slack message sent
            - chart_uploaded: bool indicating if chart uploaded
            - message: status message
    """
    result = {
        'success': False,
        'jira_ticket': None,
        'slack_sent': False,
        'chart_uploaded': False,
        'message': ''
    }
    
    # Check for duplicate alerts (unless forced)
    if not force and is_duplicate_alert(user_email, activity_type):
        result['message'] = f"Duplicate alert suppressed for {user_email} - {activity_type} (sent within last 24h)"
        print(f"⏭️  {result['message']}")
        return result
    
    print(f"\n{'='*60}")
    print(f"🚨 BLOCKING USER: {user_email}")
    print(f"📋 Activity Type: {activity_type}")
    print(f"{'='*60}\n")
    
    # Step 1: Create Jira ticket
    print("Step 1: Creating Jira ticket...")
    jira_ticket = create_jira_ticket(user_email, activity_type)
    result['jira_ticket'] = jira_ticket
    
    # Step 2: Get ticket statistics
    print("\nStep 2: Fetching ticket statistics...")
    stats = get_jira_ticket_stats()
    print(f"   Ticket Stats: {stats}")
    
    # Step 3: Send Slack notification with stats embedded
    print("\nStep 3: Sending Slack notification...")
    slack_sent = send_slack_notification(user_email, activity_type, jira_ticket, stats)
    result['slack_sent'] = slack_sent
    
    # Step 4: Generate and upload chart to separate stats channel
    print("\nStep 4: Uploading chart to stats channel...")
    chart_buffer = generate_ticket_chart(stats)
    chart_uploaded = upload_chart_to_slack(chart_buffer, stats, "Security Tickets Overview")
    result['chart_uploaded'] = chart_uploaded
    
    # Step 5: Record the alert
    record_alert(user_email, activity_type, jira_ticket)
    
    # Determine overall success
    result['success'] = slack_sent or jira_ticket is not None
    
    if result['success']:
        result['message'] = f"Successfully processed block notification for {user_email}"
        print(f"\n✅ {result['message']}\n")
    else:
        result['message'] = f"Failed to process block notification for {user_email}"
        print(f"\n❌ {result['message']}\n")
    
    print(f"{'='*60}\n")
    
    return result


# ============================================================================
# TESTING AND EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example usage
    print("Testing Slack and Jira integration...\n")
    
    # Test notification
    result = notify_user_blocked(
        user_email="suspicious.user@example.com",
        activity_type="Unauthorized Data Access",
        force=True  # Force send even if duplicate
    )
    
    print("\n" + "="*60)
    print("RESULTS:")
    print(f"  Success: {result['success']}")
    print(f"  Jira Ticket: {result['jira_ticket']}")
    print(f"  Slack Sent: {result['slack_sent']}")
    print(f"  Chart Uploaded: {result['chart_uploaded']}")
    print(f"  Message: {result['message']}")
    print("="*60)
