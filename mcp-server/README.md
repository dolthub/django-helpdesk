# Django Helpdesk MCP Server

This MCP (Model Context Protocol) server exposes the django-helpdesk API to AI agents, allowing them to interact with helpdesk tickets programmatically and manage agent sessions.

## Features

The server provides the following tools for AI agents:

### Core Ticket Management
- **list_tickets** - List and filter tickets by status, queue, assignment, etc.
- **get_ticket** - Get detailed information about a specific ticket
- **create_ticket** - Create new tickets with title, description, priority, etc.
- **add_followup** - Add follow-up comments to existing tickets
- **update_ticket** - Update ticket properties like status, priority, assignment
- **get_queues** - List available ticket queues
- **get_users** - List users that can be assigned to tickets

### Agent Session Management
- **get_agent_session_info** - Get current agent session information (branch name, intent, etc.)
- **set_agent_intent** - Set session intent for context tracking (max 512 characters)
- **finish_agent_session** - Complete session with cleanup and logout

## Installation

### Prerequisites

- Python 3.8 or higher
- A running django-helpdesk instance with API enabled
- Valid authentication credentials for the API

### Install Dependencies

```bash
cd mcp-server
pip install -e .
```

Or with uv:

```bash
cd mcp-server
uv sync
```

## Configuration

The MCP server can be configured using environment variables:

### Environment Variables

- `HELPDESK_BASE_URL` - Base URL of your django-helpdesk instance (default: `http://localhost:8080`)
- `HELPDESK_USERNAME` - Username for session authentication (required)
- `HELPDESK_PASSWORD` - Password for session authentication (required)
- `HELPDESK_API_TOKEN` - API token for authentication (deprecated, use session auth)

### Authentication Method

The server uses **session-based authentication** (required for agent features):

```bash
export HELPDESK_USERNAME="your-agent-username"
export HELPDESK_PASSWORD="your-password"
export HELPDESK_BASE_URL="http://localhost:8080"
```

**Note**: For full agent functionality, ensure your user account has `is_agent=True` in the Django Helpdesk user settings.

## Usage

### Running the Server

```bash
python helpdesk.py
```

Or using the installed script:

```bash
django-helpdesk-mcp
```

### MCP Client Configuration

Add this server to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "django-helpdesk": {
      "command": "python",
      "args": ["/path/to/mcp-server/helpdesk.py"],
      "env": {
        "HELPDESK_BASE_URL": "https://your-helpdesk.example.com",
        "HELPDESK_USERNAME": "your-agent-username",
        "HELPDESK_PASSWORD": "your-password"
      }
    }
  }
}
```

## API Tool Reference

### list_tickets

List tickets with optional filtering.

**Parameters:**
- `status` (string, optional) - Filter by status (e.g., "Open", "Resolved", "Closed"). Comma-separated for multiple.
- `queue_id` (integer, optional) - Filter by queue ID
- `assigned_to` (integer, optional) - Filter by assigned user ID
- `page` (integer, optional) - Page number for pagination
- `page_size` (integer, optional) - Results per page (max 25)

**Example:**
```json
{
  "status": "Open,In Progress",
  "page": 1,
  "page_size": 10
}
```

### get_ticket

Get detailed information about a specific ticket.

**Parameters:**
- `ticket_id` (integer, required) - ID of the ticket to retrieve

### create_ticket

Create a new ticket.

**Parameters:**
- `queue` (integer, required) - Queue ID for the ticket
- `title` (string, required) - Title of the ticket  
- `description` (string, required) - Description/body of the ticket
- `submitter_email` (string, required) - Email of the ticket submitter
- `priority` (integer, optional) - Priority level (1-5, 1 = highest)
- `assigned_to` (integer, optional) - User ID to assign to
- `due_date` (string, optional) - Due date in YYYY-MM-DD format

### add_followup

Add a follow-up comment to an existing ticket.

**Parameters:**
- `ticket_id` (integer, required) - ID of the ticket
- `comment` (string, required) - The follow-up comment text
- `title` (string, optional) - Title of the follow-up
- `public` (boolean, optional) - Whether visible to public (default: true)
- `new_status` (integer, optional) - New status to set for the ticket
- `time_spent` (string, optional) - Time spent (minutes or HH:MM format)

### update_ticket

Update properties of an existing ticket.

**Parameters:**
- `ticket_id` (integer, required) - ID of the ticket to update
- `title` (string, optional) - New title
- `description` (string, optional) - New description
- `status` (integer, optional) - New status
- `priority` (integer, optional) - New priority level (1-5)
- `assigned_to` (integer, optional) - User ID to assign to
- `due_date` (string, optional) - New due date (YYYY-MM-DD)

### get_queues

List all available ticket queues. No parameters required.

### get_users

List users that can be assigned to tickets.

**Parameters:**
- `page` (integer, optional) - Page number for pagination

### get_agent_session_info

Get current agent session information including branch name, intent, and session details.

**Parameters:** None

**Returns:**
- User ID and username
- Agent status
- Current branch name (automatically generated)
- Session intent (if set)
- Session key and authentication method

### set_agent_intent

Set the intent for the current agent session for context tracking.

**Parameters:**
- `intent` (string, required) - The intent to set (max 512 characters)

**Example:**
```json
{
  "intent": "Resolving customer billing issues for Q4 2024"
}
```

### finish_agent_session

Finish the current agent session and perform cleanup operations.

**Parameters:** None

**Actions:**
- Calls session cleanup handlers
- Invokes database stored procedures
- Clears session data (branch name, intent)
- Logs out the user
- Requires re-authentication for future requests

## Django Helpdesk Setup

Ensure your django-helpdesk instance has the REST API enabled:

### 1. Install Django REST Framework

```bash
pip install djangorestframework
```

### 2. Add to Django Settings

```python
INSTALLED_APPS = [
    # ... other apps
    'rest_framework',
    'helpdesk',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        # Token authentication is deprecated for agent features
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# Required middleware for agent session management
MIDDLEWARE = [
    # ... other middleware ...
    'helpdesk.middleware.AgentBranchNameMiddleware',
    'helpdesk.middleware.AgentSessionTimeoutMiddleware', 
    'helpdesk.middleware.AgentAccessControlMiddleware',
]
```

### 3. Add API URLs

In your main `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    # ... other URLs
    path('api/', include('helpdesk.urls_api')),
]
```

### 4. Create Agent User

Create a user with agent privileges:

```bash
python manage.py createsuperuser
# Then in Django admin or shell:
from django.contrib.auth.models import User
from helpdesk.models import UserSettings

user = User.objects.get(username='your-agent-username')
user.is_staff = True
user.save()

# Create or update user settings to mark as agent
settings, created = UserSettings.objects.get_or_create(user=user)
settings.is_agent = True
settings.save()
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Verify `HELPDESK_BASE_URL` is correct
   - Ensure django-helpdesk is running and accessible

2. **Authentication Failed**
   - Check your username/password credentials
   - Verify the user has `is_staff=True` and `is_agent=True` permissions
   - Ensure session-based authentication is configured

3. **API Not Found (404)**
   - Ensure the REST API is properly configured
   - Check that `api/` URLs are included
   - Verify agent-specific endpoints are available

4. **Permission Denied**
   - Verify the authenticated user has staff permissions
   - For agent features, ensure `is_agent=True` in user settings
   - Check that required middleware is installed

5. **Agent Session Issues**
   - Ensure user is marked as agent (`is_agent=True`)
   - Check that session middleware is properly configured
   - Verify database supports required stored procedures

### Debug Mode

Set environment variable for detailed logging:

```bash
export MCP_DEBUG=1
python helpdesk.py
```

## Development

### Testing

To test the MCP server locally:

1. Start your django-helpdesk instance
2. Set environment variables
3. Run the server: `python helpdesk.py`
4. Use an MCP-compatible client to interact with the tools

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This MCP server follows the same license as django-helpdesk.