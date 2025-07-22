# Django Helpdesk MCP Server (TypeScript)

A Model Context Protocol (MCP) server written in TypeScript that provides access to the Django Helpdesk API.

## Features

- **Tool-based API access** - Expose Django Helpdesk functionality as MCP tools
- **Authentication support** - Session-based authentication with CSRF protection
- **Comprehensive logging** - Detailed request/response logging for debugging
- **Type safety** - Full TypeScript implementation with proper typing
- **HTTP interceptors** - Automatic request/response logging with Axios

## Available Tools

- `authenticate` - Authenticate with django-helpdesk using Django session login (same as api_client.py)
- `list_tickets` - List tickets with optional filtering by status, queue, etc.
- `get_ticket` - Get detailed information about a specific ticket
- `create_ticket` - Create a new ticket
- `add_followup` - Add a follow-up comment to an existing ticket
- `update_ticket` - Update an existing ticket's properties
- `get_queues` - List all available ticket queues
- `get_users` - List users that can be assigned to tickets
- `get_agent_session_info` - Get current agent session information
- `set_agent_intent` - Set the intent for the current agent session
- `finish_agent_session` - Finish the current agent session and perform cleanup

## Installation

1. Install dependencies:
```bash
npm install
```

2. Build the TypeScript code:
```bash
npm run build
```

## Usage

### Development
Run in development mode with hot reloading:
```bash
npm run dev
```

### Production
Build and run:
```bash
npm run build
npm start
```

### Command Line Options

- `--log-file <PATH>` - Write all logs to a file instead of stderr

Example with log file:
```bash
npm run build
node dist/index.js --log-file mcp-server.log
```

### Environment Variables

- `HELPDESK_BASE_URL` - Base URL of the Django Helpdesk instance (default: `http://127.0.0.1:8080`)

## Configuration

The server can be configured via environment variables:

```bash
export HELPDESK_BASE_URL=http://your-helpdesk-instance.com
npm start
```

**Note**: The server defaults to `http://127.0.0.1:8080` instead of `http://localhost:8080` to avoid potential IPv6 resolution issues with Node.js.

## MCP Client Configuration

Add this server to your MCP client configuration:

```json
{
  "mcpServers": {
    "django-helpdesk-ts": {
      "command": "node",
      "args": ["/path/to/django-helpdesk/mcp-server-ts/dist/index.js"]
    }
  }
}
```

## Logging

The server provides detailed logging for both MCP protocol messages and HTTP API requests:

### MCP Protocol Logging
- Request/response headers and bodies
- Tool execution details
- Error handling

### HTTP API Logging
- Full request/response details
- Django session authentication flow (identical to api_client.py)
- Enhanced 403 debugging with CSRF token status and detailed error information

### Log Output Options
- **Default**: Logs to stderr (does not contaminate MCP stdout protocol)
- **File logging**: Use `--log-file <path>` to write all logs to a file
- **Timestamped**: All log entries include ISO timestamps

## Architecture

- **TypeScript** - Full type safety and modern JavaScript features
- **@modelcontextprotocol/sdk** - Official MCP SDK for TypeScript
- **Django Session Authentication** - Uses same login flow as api_client.py with CSRF tokens
- **Full Compatibility** - Works with both regular staff users and agent users
- **ESM modules** - Modern module system

## Development

### Scripts

- `npm run dev` - Development mode with tsx
- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Run built JavaScript
- `npm run clean` - Clean build directory

### Project Structure

```
mcp-server-ts/
├── src/
│   └── index.ts          # Main server implementation
├── dist/                 # Built JavaScript (created by build)
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
└── README.md            # This file
```

## Error Handling

The server includes comprehensive error handling for:
- Authentication failures
- API request errors with enhanced 403 debugging
- MCP protocol errors
- Network connectivity issues

### Enhanced 403 Debugging

When a 403 Forbidden error occurs, the server logs detailed debugging information including:
- Request URL and method
- Request headers and authentication status
- CSRF token status
- Current cookie jar contents
- Detailed error response from Django
- API request configuration details

All errors are logged with detailed information and returned as proper MCP error responses.