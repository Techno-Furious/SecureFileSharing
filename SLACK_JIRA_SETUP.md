# Slack & Jira Setup Guide

This guide will walk you through setting up Slack and Jira integration for the Juniper Phase 2 security monitoring system.

---

## 🟢 Part 1: Slack Workspace Setup

### Step 1: Create a Slack App

1. Go to https://api.slack.com/apps
2. Click **"Create New App"**
3. Select **"From scratch"**
4. Enter the following:
   - **App Name**: `Juniper Security Bot`
   - **Workspace**: Select your workspace
5. Click **"Create App"**

### Step 2: Configure Bot Permissions

1. In your app settings, go to **"OAuth & Permissions"** (left sidebar)
2. Scroll down to **"Scopes"** section
3. Under **"Bot Token Scopes"**, click **"Add an OAuth Scope"** and add:
   - `chat:write` - Post messages to channels
   - `chat:write.public` - Post to public channels without joining
   - `files:write` - Upload files and charts
   - `files:read` - Read uploaded files (required for v2 upload API)
   - `channels:read` - View basic channel information

### Step 3: Install App to Workspace

1. Scroll to the top of the **"OAuth & Permissions"** page
2. Click **"Install to Workspace"**
3. Review the permissions and click **"Allow"**
4. Copy the **Bot User OAuth Token** (starts with `xoxb-`)
   - Save this - you'll need it for your `.env` file

### Step 4: Create a Security Alerts Channel

1. In your Slack workspace, create a new channel:
   - Click the **+** next to "Channels"
   - Name it: `#security-alerts` (for main alerts)
   - Make it public or private as needed
2. Create another channel for statistics:
   - Name it: `#security-stats` (for charts and statistics)
3. Invite the bot to both channels:
   - Open each channel
   - Type: `/invite @Juniper Security Bot`
   - Press Enter

### Step 5: Update Environment Variables

Add these to your `.env` file in the `webhooks` folder:

```bash
# Slack Configuration
SLACK_TOKEN=xoxb-your-token-here
SLACK_CHANNEL=#security-alerts
SLACK_CHART_CHANNEL=#security-stats
```

---

## 🔵 Part 2: Jira Setup

### Step 1: Get Your Jira Domain

Your Jira domain is typically:
- `https://your-company.atlassian.net`

If you don't have a Jira instance:
1. Go to https://www.atlassian.com/software/jira
2. Sign up for a free account
3. Create a new site (e.g., `yourcompany.atlassian.net`)

### Step 2: Create a Jira Project

1. Log into your Jira instance
2. Click **"Projects"** → **"Create project"**
3. Select **"Team-managed"** → **"Task tracking"**
4. Enter project details:
   - **Name**: `Security Incidents`
   - **Key**: `SEC` (or your preferred 3-4 letter key)
5. Click **"Create"**

### Step 3: Generate an API Token

1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click **"Create API token"**
3. Enter a label: `Juniper Integration`
4. Click **"Create"**
5. **Copy the token** - you won't be able to see it again!

### Step 4: Update Environment Variables

Add these to your `.env` file:

```bash
# Jira Configuration
JIRA_DOMAIN=https://your-company.atlassian.net
JIRA_EMAIL=your-email@domain.com
JIRA_API_TOKEN=your-api-token-here
JIRA_PROJECT_KEY=SEC
```

---

## 📋 Part 3: Testing the Integration

### Step 1: Install Required Packages

Make sure you have all dependencies installed:

```bash
pip install requests python-dotenv matplotlib
```

### Step 2: Test the Integration

Run the utility script directly:

```bash
cd webhooks
python slack_jira_utils.py
```

This will:
- Create a test Jira ticket
- Send a notification to Slack
- Generate and upload a ticket statistics chart

### Step 3: Use in Your Code

```python
from slack_jira_utils import notify_user_blocked

# When you detect suspicious activity and block a user:
result = notify_user_blocked(
    user_email="user@example.com",
    activity_type="Unauthorized Data Access"
)

if result['success']:
    print(f"✅ Notification sent! Jira ticket: {result['jira_ticket']}")
else:
    print(f"❌ Failed: {result['message']}")
```

---

## 🔧 Troubleshooting

### Slack Issues

**Error: "not_in_channel"**
- Solution: Invite the bot to your channel using `/invite @Juniper Security Bot`

**Error: "invalid_auth"**
- Solution: Check that your `SLACK_TOKEN` is correct and starts with `xoxb-`

**Error: "channel_not_found"**
- Solution: Ensure your `SLACK_CHANNEL` includes the `#` symbol (e.g., `#security-alerts`)

### Jira Issues

**Error: "Unauthorized"**
- Solution: Verify your `JIRA_EMAIL` and `JIRA_API_TOKEN` are correct

**Error: "Project does not exist"**
- Solution: Check that your `JIRA_PROJECT_KEY` matches your project (case-sensitive)

**Error: "Field 'priority' cannot be set"**
- Solution: Your project might not have priority field enabled. The script will handle this gracefully.

---

## 🎨 Customization

### Change Slack Message Format

Edit the `send_slack_notification()` function in `slack_jira_utils.py` to customize the message blocks.

### Change Chart Style

Edit the `generate_ticket_chart()` function to modify colors, layout, or add more statistics.

### Add More Activity Types

Simply pass different activity type strings when calling `notify_user_blocked()`:
- `"Unauthorized Data Access"`
- `"Data Exfiltration Attempt"`
- `"Policy Violation"`
- `"Suspicious File Sharing"`
- etc.

---

## 📊 Features

### Automatic Deduplication
- Prevents spam by checking if the same user/activity was already reported in the last 24 hours
- Use `force=True` parameter to bypass this check

### Ticket Statistics Chart
- Automatically generates a bar chart showing:
  - Open tickets
  - In Progress tickets
  - Completed tickets
- Uploads to Slack with each notification

### Alert History
- All alerts are logged in `alerts_log.json`
- Includes timestamp, email, activity type, and Jira ticket reference

---

## 🔐 Security Best Practices

1. **Never commit your `.env` file** - It's already in `.gitignore`
2. **Rotate API tokens regularly** - Update tokens every 90 days
3. **Use restricted bot permissions** - Only grant necessary scopes
4. **Monitor bot activity** - Check Slack/Jira audit logs periodically
5. **Use private channels** - Consider making `#security-alerts` a private channel

---

## 📞 Support

If you encounter issues:
1. Check the console output for detailed error messages
2. Verify all environment variables are set correctly
3. Test Slack/Jira connectivity independently
4. Review the troubleshooting section above

---

**Setup Complete!** 🎉

You're now ready to receive automated security notifications whenever users are blocked for suspicious activity.
