#!/usr/bin/env python3
"""
Simple API test to isolate permission issues.
"""

import requests
import json
from urllib.parse import urljoin


def test_simple_api(base_url="http://localhost:8000", username="agent1", password="3125four"):
    """Test API with minimal complexity."""
    
    print("🧪 Simple API Permission Test")
    print("=" * 50)
    
    session = requests.Session()
    
    # Step 1: Login via helpdesk form
    print("1. Logging in via Django form...")
    login_url = urljoin(base_url, "/api/auth/login/")
    
    # Get login page for CSRF
    login_page = session.get(login_url)
    csrf_token = session.cookies.get('csrftoken', '')
    
    # Submit login
    login_data = {
        'username': username,
        'password': password,
        'csrfmiddlewaretoken': csrf_token
    }
    
    login_response = session.post(login_url, data=login_data, allow_redirects=False)
    
    if login_response.status_code in [200, 302]:
        print("   ✅ Login successful")
        print(f"   Session ID: {session.cookies.get('sessionid', 'None')[:20]}...")
    else:
        print(f"   ❌ Login failed: {login_response.status_code}")
        return False
    
    # Step 2: Test user_tickets endpoint (should work for any authenticated user)
    print("\n2. Testing user_tickets endpoint...")
    user_tickets_url = urljoin(base_url, "/api/user_tickets/")
    
    headers = {
        'X-CSRFToken': session.cookies.get('csrftoken', ''),
        'Referer': user_tickets_url,
    }
    
    user_response = session.get(user_tickets_url, headers=headers)
    print(f"   Status: {user_response.status_code}")
    
    if user_response.status_code == 200:
        print("   ✅ User tickets accessible")
        try:
            data = user_response.json()
            print(f"   Found {len(data.get('results', []))} user tickets")
        except:
            print("   Response not JSON")
    else:
        print(f"   ❌ User tickets failed")
        print(f"   Response: {user_response.text[:200]}...")
    
    # Step 3: Test admin tickets endpoint
    print("\n3. Testing admin tickets endpoint...")
    tickets_url = urljoin(base_url, "/api/tickets/")
    
    tickets_response = session.get(tickets_url, headers=headers)
    print(f"   Status: {tickets_response.status_code}")
    
    if tickets_response.status_code == 200:
        print("   ✅ Admin tickets accessible")
        try:
            data = tickets_response.json()
            print(f"   Found {len(data.get('results', []))} total tickets")
        except:
            print("   Response not JSON")
        return True
    else:
        print(f"   ❌ Admin tickets failed")
        print(f"   Response: {tickets_response.text[:200]}...")
        
        # Check specific error types
        if 'permission' in tickets_response.text.lower():
            print("   🔍 This appears to be a permission issue")
        if 'csrf' in tickets_response.text.lower():
            print("   🔍 This appears to be a CSRF issue")
        if tickets_response.status_code == 403:
            print("   🔍 403 means authenticated but not authorized")
            
        return False
    
    # Step 4: Try different approaches if main test failed
    print("\n4. Trying alternative approaches...")
    
    # Try without CSRF token
    print("   a) Trying without CSRF token...")
    simple_response = session.get(tickets_url)
    print(f"      Status: {simple_response.status_code}")
    
    # Try with different headers
    print("   b) Trying with minimal headers...")
    minimal_headers = {'Accept': 'application/json'}
    minimal_response = session.get(tickets_url, headers=minimal_headers)
    print(f"      Status: {minimal_response.status_code}")
    
    return False


def main():
    """Run the simple test."""
    import sys
    
    if len(sys.argv) >= 4:
        base_url = f"http://{sys.argv[1]}"
        username = sys.argv[2]
        password = sys.argv[3]
    else:
        base_url = "http://localhost:8000"
        username = "agent1"
        password = "3125four"
    
    print(f"Testing: {base_url}")
    print(f"User: {username}")
    print(f"Password: {'*' * len(password)}")
    print()
    
    success = test_simple_api(base_url, username, password)
    
    if not success:
        print("\n" + "="*50)
        print("TROUBLESHOOTING SUGGESTIONS:")
        print("1. Check user permissions:")
        print("   python demo/manage.py shell")
        print("   >>> from django.contrib.auth.models import User")
        print(f"   >>> user = User.objects.get(username='{username}')")
        print("   >>> print(f'Staff: {user.is_staff}, Admin: {user.is_superuser}')")
        print("   >>> user.is_staff = True")
        print("   >>> user.save()")
        print()
        print("2. Check Django logs for detailed errors")
        print("3. Verify teams mode is disabled")
        print("4. Check if migrations are up to date")
    
    return success


if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)
