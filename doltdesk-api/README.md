# DoltDesk API

A Go HTTP server for the DoltDesk API service with username/password authentication and session management.

## Features

- HTTP server with JSON responses
- Username/password authentication
- Session-based authentication with cookies
- Protected routes requiring authentication
- In-memory user and session storage
- Automatic session cleanup
- Health check endpoint
- Configurable port via environment variable
- RESTful API structure

## Getting Started

### Prerequisites

- Go 1.21 or higher

### Installation

1. Install dependencies:
```bash
go mod tidy
```

2. Run the server:
```bash
go run main.go
```

The server will start on port 8080 by default, or use the `PORT` environment variable.

### Default Credentials

- **Username:** admin
- **Password:** admin123

## Endpoints

### Public Endpoints

- `GET /` - Root endpoint with welcome message
- `GET /api/v1/` - API root endpoint
- `GET /api/v1/health` - Health check endpoint
- `POST /api/v1/login` - User login
- `POST /api/v1/logout` - User logout

### Protected Endpoints (Require Authentication)

- `GET /api/v1/profile` - Get current user profile
- `GET /api/v1/protected` - Example protected endpoint

## Authentication

### Login

```bash
# Login
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  -c cookies.txt

# Response
{
  "message": "Login successful",
  "user": {
    "id": "...",
    "username": "admin",
    "created_at": "2024-01-01T10:00:00Z",
    "last_login": "2024-01-01T10:00:00Z"
  }
}
```

### Access Protected Endpoints

```bash
# Use cookies from login
curl http://localhost:8080/api/v1/profile -b cookies.txt

# Or access protected endpoint
curl http://localhost:8080/api/v1/protected -b cookies.txt
```

### Logout

```bash
# Logout
curl -X POST http://localhost:8080/api/v1/logout -b cookies.txt

# Response
{
  "message": "Logout successful",
  "status": "ok"
}
```

## Session Management

- Sessions expire after 24 hours
- Sessions are stored in memory (not persistent across restarts)
- Automatic cleanup of expired sessions runs every hour
- Sessions use HTTP-only cookies for security

## Environment Variables

- `PORT` - Server port (default: 8080)

## Development

### Project Structure

```
doltdesk-api/
├── main.go       # Main server and routing
├── auth.go       # Authentication and session management
├── context.go    # Request context utilities
├── errors.go     # Error definitions
├── go.mod        # Go module dependencies
└── README.md     # This file
```

### Example Usage

```bash
# Start server
go run main.go
# Output: Starting DoltDesk API server on port 8080
#         Default admin user: admin / admin123

# Health check
curl http://localhost:8080/api/v1/health

# Login and save session
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  -c session.txt

# Access protected endpoint
curl http://localhost:8080/api/v1/profile -b session.txt

# Logout
curl -X POST http://localhost:8080/api/v1/logout -b session.txt
```