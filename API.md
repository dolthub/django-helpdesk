# Django-Helpdesk REST API Documentation

## Overview

Django-helpdesk provides a REST API built with Django REST Framework for external integrations and programmatic access to tickets, follow-ups, and user management.

**Base URL:** `/api/`

## Authentication

- **Staff endpoints** require `IsAdminUser` permission (Django admin users)
- **User endpoints** require `IsAuthenticated` permission
- Uses Django's standard authentication (session, token, etc.)

## Pagination

All list endpoints use `ConservativePagination`:
- Default page size: 25 items
- Query parameter: `?page_size=N` (customize page size)
- Query parameter: `?page=N` (page number)

## Endpoints

### Tickets

#### `GET /api/tickets/` - List All Tickets (Admin)
**Permission:** Admin users only

**Query Parameters:**
- `status` - Filter by status (comma-separated). Examples:
  - `?status=1` (Open tickets only)
  - `?status=1,2` (Open and Reopened tickets)
  - `?status=Open,Resolved` (by status name)

**Response:** Array of ticket objects with full details including follow-ups

#### `POST /api/tickets/` - Create Ticket (Admin)
**Permission:** Admin users only

**Request Body:**
```json
{
  "queue": 1,
  "title": "Issue with login",
  "description": "Cannot log into the system",
  "submitter_email": "user@example.com",
  "priority": 3,
  "assigned_to": 2,
  "attachment": "<file_upload>"
}
```

**Response:** Created ticket object

#### `GET /api/tickets/{id}/` - Get Ticket Details (Admin)
**Permission:** Admin users only

**Response:** Full ticket object with follow-ups and custom fields

#### `PUT /api/tickets/{id}/` - Update Ticket (Admin)
**Permission:** Admin users only

**Request Body:** Same as POST, all fields optional

#### `DELETE /api/tickets/{id}/` - Delete Ticket (Admin)
**Permission:** Admin users only

### User Tickets

#### `GET /api/user_tickets/` - List Current User's Tickets
**Permission:** Authenticated users

Returns tickets submitted by the current user (matched by email address).

**Response:** Array of public ticket objects (sensitive fields filtered out)

#### `GET /api/user_tickets/{id}/` - Get User's Ticket Details
**Permission:** Authenticated users

**Response:** Public ticket object without sensitive admin fields

### Follow-ups

#### `GET /api/followups/` - List All Follow-ups (Admin)
**Permission:** Admin users only

#### `POST /api/followups/` - Create Follow-up (Admin)
**Permission:** Admin users only

**Request Body:**
```json
{
  "ticket": 1,
  "title": "Status Update",
  "comment": "Working on the issue",
  "public": true,
  "new_status": 1,
  "time_spent": "PT2H30M",
  "attachments": ["<file1>", "<file2>"]
}
```

**Notes:**
- `time_spent` uses ISO 8601 duration format (PT2H30M = 2 hours 30 minutes)
- `attachments` accepts multiple file uploads
- `user` is automatically set to the requesting user

#### `GET /api/followups/{id}/` - Get Follow-up Details (Admin)
#### `PUT /api/followups/{id}/` - Update Follow-up (Admin)
#### `DELETE /api/followups/{id}/` - Delete Follow-up (Admin)

### Follow-up Attachments

#### `GET /api/followups-attachments/` - List All Attachments (Admin)
#### `POST /api/followups-attachments/` - Upload Attachment (Admin)
#### `GET /api/followups-attachments/{id}/` - Get Attachment Details (Admin)
#### `PUT /api/followups-attachments/{id}/` - Update Attachment (Admin)
#### `DELETE /api/followups-attachments/{id}/` - Delete Attachment (Admin)

### Users

#### `POST /api/users/` - Create User (Admin)
**Permission:** Admin users only

**Request Body:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "password": "securepassword"
}
```

**Response:** Created user object (password excluded)

## Data Models

### Ticket Status Values
- `1` - Open
- `2` - Reopened  
- `3` - Resolved
- `4` - Closed
- `5` - Duplicate

### Priority Values
- `1` - Critical
- `2` - High
- `3` - Normal
- `4` - Low
- `5` - Very Low

### Ticket Object (Full)
```json
{
  "id": 1,
  "queue": 1,
  "title": "Login Issue",
  "description": "Cannot access account",
  "resolution": "Reset password resolved the issue",
  "submitter_email": "user@example.com",
  "assigned_to": 2,
  "status": 1,
  "on_hold": false,
  "priority": 3,
  "due_date": "2024-01-15T10:00:00Z",
  "merged_to": null,
  "followup_set": [
    {
      "id": 1,
      "title": "Initial Response",
      "comment": "Looking into this issue",
      "public": true,
      "new_status": null,
      "time_spent": "PT1H",
      "date": "2024-01-10T14:30:00Z",
      "user": 1,
      "followupattachment_set": []
    }
  ],
  "custom_field_name": "custom_value"
}
```

### Public Ticket Object
```json
{
  "id": 1,
  "ticket": "1 Login Issue",
  "title": "Login Issue", 
  "queue": {"id": 1, "title": "Support"},
  "status": "Open",
  "created": "2 days ago",
  "due_date": "in 5 days",
  "submitter": "user@example.com",
  "kbitem": "",
  "secret_key": "abc123def456",
  "custom_field_name": "custom_value"
}
```

## Custom Fields

The API automatically includes custom fields defined in the admin interface:
- Field names are prefixed with `custom_`
- Example: A custom field named "department" appears as `custom_department`
- Supported types: boolean, date, time, datetime, email, url, ipaddress, slug

## Error Responses

### 400 Bad Request
```json
{
  "field_name": ["Error message"],
  "non_field_errors": ["General error message"]
}
```

### 401 Unauthorized
```json
{
  "detail": "Authentication credentials were not provided."
}
```

### 403 Forbidden
```json
{
  "detail": "You do not have permission to perform this action."
}
```

### 404 Not Found
```json
{
  "detail": "Not found."
}
```

## Example Usage

### List Open Tickets
```bash
curl -X GET "http://localhost:8000/api/tickets/?status=Open" \
  -H "Authorization: Token your-api-token"
```

### Create a Ticket
```bash
curl -X POST "http://localhost:8000/api/tickets/" \
  -H "Authorization: Token your-api-token" \
  -H "Content-Type: application/json" \
  -d '{
    "queue": 1,
    "title": "Server Down",
    "description": "Main server is not responding",
    "submitter_email": "admin@company.com",
    "priority": 1
  }'
```

### Add Follow-up with Time Tracking
```bash
curl -X POST "http://localhost:8000/api/followups/" \
  -H "Authorization: Token your-api-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ticket": 1,
    "title": "Investigation Complete",
    "comment": "Found the root cause, deploying fix",
    "public": true,
    "new_status": 3,
    "time_spent": "PT3H45M"
  }'
```

### Get Current User's Tickets
```bash
curl -X GET "http://localhost:8000/api/user_tickets/" \
  -H "Authorization: Token your-api-token"
```