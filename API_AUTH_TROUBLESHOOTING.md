# Django-Helpdesk API Authentication Troubleshooting

## Problem: 401 "Authentication credentials were not provided"

This error occurs when the Django REST Framework API requires token authentication but no valid token is provided.

## Solution Options

### Option 1: Create Token via Provided Script (Recommended)

```bash
# Run the token creation script
python create_token.py admin

# Output will show:
# ✅ New token created for admin
# 🔑 Token: abc123def456...
```

### Option 2: Create Token via Django Shell

```bash
# Open Django shell
python demo/manage.py shell

# Run these commands in the shell:
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

# Get user (replace 'admin' with your username)
user = User.objects.get(username='admin')

# Create or get token
token, created = Token.objects.get_or_create(user=user)

# Display token
print(f'Token: {token.key}')
```

### Option 3: Create Token via Django Admin

1. Start Django server: `python demo/manage.py runserver`
2. Go to http://localhost:8000/admin/
3. Login with your admin credentials
4. Navigate to **Authentication and Authorization** → **Tokens**
5. Click **Add Token**
6. Select your user from the dropdown
7. Click **Save** - the token will be generated automatically

### Option 4: Use Token Endpoint (if available)

```bash
# Test if token endpoint is working
curl -X POST http://localhost:8000/api-token-auth/ \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "admin123"}'

# Should return:
# {"token": "abc123def456..."}
```

## Using the Token

### With the Interactive API Client

1. Run the client: `python api_login.py localhost 8000 admin admin123`
2. When prompted "Do you have an authentication token to enter manually? (y/N):", type `y`
3. Enter your token when prompted
4. The client will use token authentication for all API calls

### With curl

```bash
# Use the token in Authorization header
curl -H "Authorization: Token abc123def456..." \
  http://localhost:8000/api/tickets/
```

### With Python requests

```python
import requests

headers = {
    'Authorization': 'Token abc123def456...',
    'Content-Type': 'application/json'
}

response = requests.get('http://localhost:8000/api/tickets/', headers=headers)
print(response.json())
```

## Verifying Token Works

Test your token with a simple API call:

```bash
# Replace 'your_token_here' with your actual token
curl -H "Authorization: Token your_token_here" \
  http://localhost:8000/api/health/

# Should return:
# {"status":"healthy","timestamp":"...","service":"doltdesk-api"}
```

## Common Issues and Solutions

### Issue: "User not found" when creating token

**Problem:** The user doesn't exist in the database.

**Solution:** Create the user first:
```bash
python demo/manage.py createsuperuser
# Follow prompts to create admin user
```

### Issue: Token endpoint returns 404

**Problem:** The token endpoint isn't configured.

**Solution:** The `/api-token-auth/` endpoint has been added to the demo URLs. Make sure you're using the correct URL.

### Issue: Token authentication still fails

**Problem:** Token might be invalid or user might not have proper permissions.

**Solutions:**
1. **Regenerate token:**
   ```python
   # In Django shell
   from rest_framework.authtoken.models import Token
   from django.contrib.auth.models import User
   
   user = User.objects.get(username='admin')
   Token.objects.filter(user=user).delete()  # Delete old token
   token = Token.objects.create(user=user)   # Create new token
   print(f'New token: {token.key}')
   ```

2. **Check user permissions:**
   ```python
   # In Django shell
   user = User.objects.get(username='admin')
   print(f'Is staff: {user.is_staff}')
   print(f'Is superuser: {user.is_superuser}')
   print(f'Is active: {user.is_active}')
   
   # Make user staff if needed
   user.is_staff = True
   user.save()
   ```

### Issue: CSRF token errors

**Problem:** Mixing token auth with session auth.

**Solution:** Use token authentication exclusively for API calls. The interactive client now prioritizes token auth over session auth.

## Environment Setup Checklist

Ensure your Django environment is properly configured:

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run migrations:**
   ```bash
   python demo/manage.py migrate
   ```

3. **Create superuser (if needed):**
   ```bash
   python demo/manage.py createsuperuser
   ```

4. **Start server:**
   ```bash
   python demo/manage.py runserver
   ```

5. **Create token:**
   ```bash
   python create_token.py admin
   ```

## API Client Usage Flow

1. **Authentication:** The client tries multiple authentication methods in order:
   - Token endpoint discovery (`/api-token-auth/`, etc.)
   - Manual token entry (if user provides)
   - Session-based fallback (limited compatibility)

2. **API Calls:** All API requests include:
   - `Authorization: Token <token>` header (if token available)
   - `Content-Type: application/json` header
   - Proper HTTP methods (GET, POST, PUT, DELETE)

3. **Error Handling:** The client shows detailed error messages and response codes to help diagnose issues.

## Testing Authentication

### Quick Test Script

```python
#!/usr/bin/env python3
import requests

# Replace with your token
TOKEN = "abc123def456..."
BASE_URL = "http://localhost:8000"

headers = {
    'Authorization': f'Token {TOKEN}',
    'Content-Type': 'application/json'
}

# Test health endpoint
response = requests.get(f"{BASE_URL}/api/health/", headers=headers)
print(f"Health check: {response.status_code} - {response.text}")

# Test tickets endpoint  
response = requests.get(f"{BASE_URL}/api/tickets/", headers=headers)
print(f"Tickets: {response.status_code} - {len(response.json().get('results', []))} tickets")
```

Save this as `test_auth.py` and run: `python test_auth.py`

## Getting Help

If you're still having issues:

1. **Check Django logs:** Look for error messages in the Django console
2. **Enable debug mode:** Set `DEBUG = True` in Django settings
3. **Test with curl:** Use curl commands to isolate the issue
4. **Check user permissions:** Ensure the user has appropriate staff/admin privileges

The enhanced interactive API client now provides better error messages and guidance to help resolve authentication issues.