# Django-Helpdesk Session Authentication Setup

## Overview

The Django-Helpdesk demo has been configured to use **session authentication** as the primary method for the REST framework API, with token authentication as a fallback option.

## Changes Made

### 1. REST Framework Configuration

The `REST_FRAMEWORK` settings now prioritize session authentication:

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',  # Primary
        'rest_framework.authentication.TokenAuthentication',    # Fallback
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}
```

### 2. CSRF and Session Settings

Added settings to support API access with sessions:

```python
# CSRF settings for API access
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_USE_SESSIONS = False     # Use cookie-based CSRF tokens
CSRF_COOKIE_SAMESITE = 'Lax'  # Allow cross-site requests with CSRF token

# Session settings for API access  
SESSION_COOKIE_HTTPONLY = False  # Allow API clients to access session
SESSION_COOKIE_SAMESITE = 'Lax'  # Allow cross-site requests with session
```

### 3. Enhanced API Client

The `api_client.py` script now:
- **Attempts Django session login first** via `/helpdesk/login/`
- **Extracts CSRF tokens** from forms and cookies
- **Uses proper form submission** for Django authentication
- **Includes CSRF tokens** in API request headers
- **Falls back to token authentication** if session login fails

## Usage

### Running the Interactive API Client

```bash
python api_client.py localhost 8000 admin admin123
```

The client will now:
1. Attempt to log in via Django's login form at `/helpdesk/login/`
2. Extract and use session cookies and CSRF tokens
3. Use session authentication for all API calls
4. Provide fallback to token authentication if needed

### Testing Session Authentication

Use the provided test script:

```bash
python test_session_auth.py
```

This will:
- Test login via Django form
- Verify session cookies are set
- Test API calls with session authentication
- Test both health and tickets endpoints

### Manual Testing with curl

```bash
# Step 1: Get login page and extract CSRF token
curl -c cookies.txt http://localhost:8000/helpdesk/login/

# Step 2: Extract CSRF token from response (manual step)
# Look for: <input type="hidden" name="csrfmiddlewaretoken" value="TOKEN_HERE">

# Step 3: Login with form data
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:8000/helpdesk/login/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://localhost:8000/helpdesk/login/" \
  -d "username=admin&password=admin123&csrfmiddlewaretoken=TOKEN_HERE"

# Step 4: Make API call with session
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRFToken: TOKEN_HERE" \
  -H "Referer: http://localhost:8000/api/tickets/" \
  http://localhost:8000/api/tickets/
```

## How Session Authentication Works

### 1. Login Process
1. **GET** `/helpdesk/login/` to get login form and CSRF token
2. **POST** form data with credentials and CSRF token to `/helpdesk/login/`
3. Django sets `sessionid` and `csrftoken` cookies
4. Successful login redirects to dashboard

### 2. API Requests
1. Include `sessionid` cookie (automatic with requests.Session)
2. Include `X-CSRFToken` header with CSRF token value
3. Include `Referer` header pointing to the API endpoint
4. Django REST Framework validates session and CSRF token

### 3. Authentication Flow
```
Client -> GET /helpdesk/login/ -> Extract CSRF token
Client -> POST /helpdesk/login/ -> Django sets session cookies
Client -> GET /api/tickets/ (with session + CSRF) -> API response
```

## Benefits of Session Authentication

### 1. **Simpler for Web Applications**
- No need to manage separate API tokens
- Integrates with Django's built-in authentication
- Works with existing user permissions

### 2. **Better Security**
- CSRF protection prevents cross-site attacks
- Session expiration handled automatically
- Integrates with Django's security middleware

### 3. **Easier Development**
- Same authentication as web interface
- No additional token management
- Works with Django admin and regular views

## Troubleshooting

### Common Issues

#### 1. **403 Forbidden (CSRF verification failed)**

**Cause:** Missing or invalid CSRF token

**Solution:**
- Ensure `X-CSRFToken` header is included
- Verify CSRF token value is correct
- Include `Referer` header

#### 2. **401 Unauthorized**

**Cause:** No valid session or user not authenticated

**Solution:**
- Verify login was successful (check for redirects)
- Ensure `sessionid` cookie is included
- Check user credentials and account status

#### 3. **Session cookies not set**

**Cause:** Login form submission failed

**Solution:**
- Check form data format (use `application/x-www-form-urlencoded`)
- Verify CSRF token in form data
- Check for error messages in login response

### Debugging Tips

1. **Enable Django Debug Mode**
   ```python
   DEBUG = True
   ```

2. **Check Django Logs**
   - Look for authentication errors
   - CSRF verification failures
   - Session middleware issues

3. **Inspect Cookies**
   ```bash
   curl -v -c cookies.txt http://localhost:8000/helpdesk/login/
   cat cookies.txt
   ```

4. **Test with Browser Developer Tools**
   - Network tab to see request/response headers
   - Application tab to inspect cookies
   - Console for JavaScript errors

## Migration from Token Auth

If you were previously using token authentication:

1. **Existing tokens still work** (fallback authentication)
2. **New clients can use session auth** for simpler integration
3. **Web applications benefit most** from session authentication
4. **API-only clients** might still prefer token authentication

## Security Considerations

### Production Settings

For production deployment, consider:

```python
# More secure settings for production
CSRF_COOKIE_SECURE = True      # HTTPS only
SESSION_COOKIE_SECURE = True   # HTTPS only
CSRF_COOKIE_HTTPONLY = True    # Prevent XSS
SESSION_COOKIE_HTTPONLY = True # Prevent XSS
```

### CORS Considerations

If using from different domains, configure CORS properly:

```python
# Install django-cors-headers
pip install django-cors-headers

# Add to INSTALLED_APPS
INSTALLED_APPS = [
    'corsheaders',
    # ...
]

# Add to MIDDLEWARE
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    # ...
]

# Configure CORS
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # Your frontend domain
]
```

This setup provides a robust, secure, and easy-to-use authentication system for the Django-Helpdesk API that integrates seamlessly with the existing Django authentication framework.