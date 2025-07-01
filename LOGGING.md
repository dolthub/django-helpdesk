# Django-Helpdesk Request/Response Logging

This document describes the request/response logging middleware implemented for django-helpdesk.

## Overview

The `RequestResponseLoggingMiddleware` logs HTTP requests and responses for django-helpdesk and its API endpoints, providing detailed information for debugging, monitoring, and audit purposes.

## Features

- **Request Logging**: Method, path, user info, IP address, headers, and body
- **Response Logging**: Status code, headers, body, and processing time
- **Security**: Filters sensitive headers (authorization, cookies, etc.)
- **Performance**: Configurable body size limits and selective path logging
- **Flexible Output**: Console and file logging with detailed formatting

## Configuration

### Settings

Add these settings to your Django `settings.py`:

```python
# Paths to log (default: ['/api/', '/helpdesk/'])
HELPDESK_LOG_PATHS = [
    '/api/',
    '/helpdesk/',
]

# Sensitive headers to filter from logs
HELPDESK_LOG_SENSITIVE_HEADERS = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
]

# Maximum request/response body size to log in bytes (default: 10000)
HELPDESK_LOG_MAX_BODY_SIZE = 10000

# Whether to log request/response bodies (default: True)
HELPDESK_LOG_BODIES = True
```

### Middleware Installation

Add the middleware to your `MIDDLEWARE` setting:

```python
MIDDLEWARE = [
    # ... other middleware
    "helpdesk.middleware.RequestResponseLoggingMiddleware",
]
```

### Logging Configuration

Configure logging in your `settings.py`:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s\n'
                     'Method: %(method)s | Path: %(path)s | User: %(user)s | IP: %(client_ip)s\n'
                     'Status: %(status_code)s | Time: %(processing_time_ms)s ms\n'
                     'Headers: %(headers)s\n'
                     'Body: %(body)s\n'
                     '---'
        },
    },
    'handlers': {
        'request_console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'detailed',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/helpdesk_requests.log',
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'detailed',
        },
    },
    'loggers': {
        'helpdesk.requests': {
            'handlers': ['request_console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
```

## Log Output Examples

### Request Log
```
2024-01-15 10:30:45 helpdesk.requests INFO Request: POST /api/tickets/
Method: POST | Path: /api/tickets/ | User: {'id': 1, 'username': 'admin'} | IP: 127.0.0.1
Status: None | Time: None ms
Headers: {'Content-Type': 'application/json', 'Authorization': '[FILTERED]'}
Body: {'title': 'Test Ticket', 'description': 'Test description', 'queue': 1}
---
```

### Response Log
```
2024-01-15 10:30:45 helpdesk.requests INFO Response: 201 for POST /api/tickets/
Method: POST | Path: /api/tickets/ | User: None | IP: None
Status: 201 | Time: 234.56 ms
Headers: {'Content-Type': 'application/json'}
Body: {'id': 123, 'title': 'Test Ticket', 'status': 1}
---
```

## Log Levels

- **INFO**: Successful requests (2xx responses)
- **WARNING**: Client errors (4xx responses)
- **ERROR**: Server errors (5xx responses)

## Security Features

### Sensitive Data Filtering

- **Headers**: Authorization, cookies, and API keys are filtered and shown as `[FILTERED]`
- **Body Size Limits**: Large request/response bodies are truncated
- **Content Types**: Only logs text-based content types (JSON, HTML, etc.)

### User Information

Logged user data includes:
- User ID and username
- Email address
- Staff and superuser status
- Authentication status

## Performance Considerations

### Selective Logging
- Only logs requests to configured paths (`HELPDESK_LOG_PATHS`)
- Configurable body size limits to prevent large logs
- Option to disable body logging entirely

### File Rotation
- Uses rotating file handler to prevent disk space issues
- Configurable file size limits and backup count
- Separate log files for different components

## Troubleshooting

### Common Issues

1. **Log files not created**: Ensure the `logs/` directory exists and is writable
2. **Large log files**: Adjust `HELPDESK_LOG_MAX_BODY_SIZE` or disable body logging
3. **Performance impact**: Reduce log level or limit logged paths

### Debug Mode

For development, you can increase logging verbosity:

```python
LOGGING['loggers']['helpdesk.requests']['level'] = 'DEBUG'
```

## Integration with External Systems

### Log Aggregation

The middleware outputs structured data that can be easily parsed by log aggregation systems like:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Fluentd
- Splunk
- AWS CloudWatch

### Metrics and Monitoring

Log data includes:
- Response times for performance monitoring
- Status codes for error tracking
- User activity for audit trails
- API usage patterns

## Example Usage

After implementing the middleware, you'll see detailed logs for all helpdesk and API requests:

```bash
# Start the Django development server
python manage.py runserver

# Make API requests
curl -X POST http://localhost:8000/api/tickets/ \
  -H "Authorization: Token your-token" \
  -H "Content-Type: application/json" \
  -d '{"title": "Test", "description": "Test ticket"}'

# Check logs
tail -f logs/helpdesk_requests.log
```

The middleware will automatically log all matching requests and responses with full details for debugging and monitoring purposes.