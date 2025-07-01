# Interactive Django-Helpdesk API Client Demo

## Overview

The `api_login.py` script has been enhanced to provide an interactive command line interface for the Django-Helpdesk API. After authentication, users can make various API calls through an intuitive menu system.

## Features

### 🔐 Authentication
- CSRF token handling
- Session management
- Secure credential handling

### 🎯 Interactive Menu System
- Numbered menu options
- Clear descriptions for each endpoint
- Parameter validation and prompts

### 📡 Comprehensive API Coverage
- **Tickets**: List, Create, Get, Update, Delete
- **User Tickets**: List current user's tickets
- **Follow-ups**: List and Create
- **Health Check**: API status monitoring

### 🛠️ Smart Parameter Handling
- **Required vs Optional**: Clear indication of mandatory fields
- **Type Validation**: Automatic validation for integers, booleans, strings
- **Path Parameters**: Automatic URL path substitution (e.g., `/tickets/{id}/`)
- **Query Parameters**: For GET requests
- **Request Body**: For POST/PUT requests

## Usage

### Starting the Client

```bash
python api_login.py <host> <port> <username> <password>
```

**Examples:**
```bash
# Local development
python api_login.py localhost 8000 admin admin123

# Remote server
python api_login.py api.helpdesk.com 443 user@company.com mypassword
```

### Interactive Menu

After successful authentication, you'll see:

```
============================================================
🚀 Django-Helpdesk API Interactive Client
============================================================
Available API endpoints:

 1. Tickets - List
    List all tickets
    Method: GET | Path: tickets/

 2. Tickets - Create
    Create a new ticket
    Method: POST | Path: tickets/

 3. Tickets - Get
    Get ticket details
    Method: GET | Path: tickets/{id}/

 4. Tickets - Update
    Update a ticket
    Method: PUT | Path: tickets/{id}/

 5. Tickets - Delete
    Delete a ticket
    Method: DELETE | Path: tickets/{id}/

 6. User_tickets - List
    List current user's tickets
    Method: GET | Path: user_tickets/

 7. Followups - List
    List all follow-ups
    Method: GET | Path: followups/

 8. Followups - Create
    Create a follow-up
    Method: POST | Path: followups/

 9. Health - Check
    Health check endpoint
    Method: GET | Path: health/

10. Quit

Select an option (number):
```

## Example API Calls

### 1. Create a New Ticket

Select option 2 (Tickets - Create):

```
📝 Collecting parameters for: Create a new ticket
--------------------------------------------------
title (required) - Ticket title: Server Down
description (required) - Ticket description: Main web server is not responding
queue (required) - Queue ID: 1
priority (optional) - Priority (1-5): 1
submitter_email (optional) - Submitter email: admin@company.com

🔍 Ready to make API call:
Endpoint: POST tickets/
Parameters:
  Body: {'title': 'Server Down', 'description': 'Main web server is not responding', 'queue': 1, 'priority': 1, 'submitter_email': 'admin@company.com'}

Proceed with API call? (y/N): y

🌐 Making API call...
Method: POST
URL: http://localhost:8000/api/tickets/
Headers: {
  "Content-Type": "application/json",
  "X-CSRFToken": "abc123def456..."
}
Request Body: {
  "title": "Server Down",
  "description": "Main web server is not responding",
  "queue": 1,
  "priority": 1,
  "submitter_email": "admin@company.com"
}

📡 Response:
Status Code: 201
Response Body: {
  "id": 123,
  "title": "Server Down",
  "description": "Main web server is not responding",
  "queue": 1,
  "status": 1,
  "priority": 1,
  "created": "2024-01-15T10:30:00Z"
}
✅ API call successful!
```

### 2. List Tickets with Filtering

Select option 1 (Tickets - List):

```
📝 Collecting parameters for: List all tickets
--------------------------------------------------
status (optional) - Filter by status (comma-separated): 1,2
page (optional) - Page number: 1
page_size (optional) - Items per page: 5

🌐 Making API call...
Method: GET
URL: http://localhost:8000/api/tickets/
Query Params: {
  "status": "1,2",
  "page": 1,
  "page_size": 5
}

📡 Response:
Status Code: 200
Response Body: {
  "count": 15,
  "next": "http://localhost:8000/api/tickets/?page=2",
  "previous": null,
  "results": [...]
}
✅ API call successful!
```

### 3. Get Specific Ticket

Select option 3 (Tickets - Get):

```
📝 Collecting parameters for: Get ticket details
--------------------------------------------------
id (required) - Ticket ID: 123

🌐 Making API call...
Method: GET
URL: http://localhost:8000/api/tickets/123/

📡 Response:
Status Code: 200
Response Body: {
  "id": 123,
  "title": "Server Down",
  "status": 1,
  "followup_set": [...]
}
✅ API call successful!
```

### 4. Create Follow-up

Select option 8 (Followups - Create):

```
📝 Collecting parameters for: Create a follow-up
--------------------------------------------------
ticket (required) - Ticket ID: 123
title (optional) - Follow-up title: Status Update
comment (required) - Follow-up comment: Working on the issue, ETA 2 hours
public (optional) - Is public (true/false): true
new_status (optional) - New status (1-5): 
time_spent (optional) - Time spent (e.g., PT2H30M): PT1H30M

🌐 Making API call...
Method: POST
URL: http://localhost:8000/api/followups/
Request Body: {
  "ticket": 123,
  "title": "Status Update",
  "comment": "Working on the issue, ETA 2 hours",
  "public": true,
  "time_spent": "PT1H30M"
}

📡 Response:
Status Code: 201
Response Body: {
  "id": 456,
  "ticket": 123,
  "title": "Status Update",
  "comment": "Working on the issue, ETA 2 hours",
  "public": true,
  "time_spent": "PT1H30M",
  "date": "2024-01-15T11:30:00Z"
}
✅ API call successful!
```

## Parameter Types and Validation

### String Parameters
- Simple text input
- Required fields must have a value
- Optional fields can be left empty

### Integer Parameters
- Validates numeric input
- Shows error for invalid numbers
- Used for IDs, priorities, status codes

### Boolean Parameters
- Accepts: `true`, `yes`, `1`, `on` for true
- Accepts: `false`, `no`, `0`, `off` for false
- Case insensitive

### Path Parameters
- Automatically substituted in URL paths
- Example: `{id}` in `/tickets/{id}/` becomes `/tickets/123/`

## Error Handling

### Authentication Errors
```
❌ Login failed with status 401
💥 Authentication failed!
```

### Validation Errors
```
❌ This field is required. Please enter a value.
❌ Invalid int value. Please try again.
```

### API Errors
```
⚠️ API call completed with status 400
Response Body: {
  "queue": ["This field is required."]
}
```

### Network Errors
```
❌ API call failed: Connection refused
```

## Advanced Features

### Session Persistence
- Maintains authentication across multiple API calls
- Automatically includes CSRF tokens and session cookies
- No need to re-authenticate for each request

### Request/Response Logging
- Shows complete HTTP request details
- Displays response headers and body
- JSON formatting for better readability

### Interactive Flow Control
- Confirmation before making destructive operations
- Option to continue or quit after each API call
- Graceful handling of Ctrl+C interruption

## Status Code Reference

- **200-299**: ✅ Success
- **400-499**: ⚠️ Client Error (bad request, unauthorized, not found)
- **500-599**: ❌ Server Error

## Tips for Usage

1. **Start with Health Check**: Use option 9 to verify API connectivity
2. **List Before Modify**: Use list endpoints to find valid IDs
3. **Check Required Fields**: Pay attention to required vs optional parameters
4. **Use Filtering**: Leverage query parameters for efficient data retrieval
5. **Time Tracking**: Use ISO 8601 duration format (PT2H30M = 2 hours 30 minutes)

This interactive client makes it easy to explore and test the Django-Helpdesk API without writing custom scripts or using complex curl commands.