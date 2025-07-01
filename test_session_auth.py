#!/usr/bin/env python3
"""
Test Session Authentication for Django-Helpdesk API

This script tests that session authentication works with the REST framework API.
"""

import requests
import re
import json
from urllib.parse import urljoin


def test_session_auth(base_url="http://localhost:8000", username="admin", password="admin123"):
    """Test session authentication with Django-Helpdesk API."""
    
    session = requests.Session()
    
    print(f"Testing session authentication at {base_url}")
    print(f"Username: {username}")
    print("-" * 50)
    
    # Step 1: Get login page and CSRF token
    login_url = urljoin(base_url, "/helpdesk/login/")
    print(f"1. Getting login page: {login_url}")
    
    try:
        login_page = session.get(login_url)
        login_page.raise_for_status()
        print(f"   Status: {login_page.status_code}")
        
        # Extract CSRF token
        csrf_token = None
        if 'csrfmiddlewaretoken' in login_page.text:
            csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', login_page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                print(f"   CSRF token: {csrf_token[:20]}...")
        
        if 'csrftoken' in session.cookies:
            csrf_token = session.cookies['csrftoken']
            print(f"   CSRF cookie: {csrf_token[:20]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Step 2: Login via Django form
    print(f"\n2. Logging in via Django form")
    
    login_data = {
        'username': username,
        'password': password,
    }
    
    if csrf_token:
        login_data['csrfmiddlewaretoken'] = csrf_token
    
    headers = {
        'Referer': login_url,
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    if csrf_token:
        headers['X-CSRFToken'] = csrf_token
    
    try:
        login_response = session.post(
            login_url,
            data=login_data,
            headers=headers,
            allow_redirects=False
        )
        
        print(f"   Status: {login_response.status_code}")
        
        if login_response.status_code in [302, 301]:
            print("   ✅ Login successful (redirect)")
        elif login_response.status_code == 200:
            print("   ✅ Login successful (200)")
        else:
            print(f"   ❌ Login failed")
            return False
            
        # Check session cookie
        if 'sessionid' in session.cookies:
            print(f"   Session ID: {session.cookies['sessionid'][:20]}...")
        else:
            print("   ⚠️  No session ID found")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Step 3: Test API call with session
    print(f"\n3. Testing API call with session authentication")
    
    api_url = urljoin(base_url, "/api/health/")
    print(f"   Testing: {api_url}")
    
    api_headers = {
        'Content-Type': 'application/json',
    }
    
    # Add CSRF token for API calls
    if 'csrftoken' in session.cookies:
        api_headers['X-CSRFToken'] = session.cookies['csrftoken']
        api_headers['Referer'] = api_url
    
    try:
        api_response = session.get(api_url, headers=api_headers)
        print(f"   Status: {api_response.status_code}")
        
        if api_response.status_code == 200:
            try:
                data = api_response.json()
                print(f"   Response: {json.dumps(data, indent=4)}")
                print("   ✅ API call successful!")
                return True
            except json.JSONDecodeError:
                print(f"   Response text: {api_response.text}")
                return api_response.status_code == 200
        else:
            print(f"   ❌ API call failed")
            print(f"   Response: {api_response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_tickets_endpoint(base_url="http://localhost:8000", username="admin", password="admin123"):
    """Test the tickets endpoint specifically."""
    
    session = requests.Session()
    
    print(f"\n4. Testing tickets endpoint")
    
    # Login first (simplified)
    login_url = urljoin(base_url, "/helpdesk/login/")
    login_page = session.get(login_url)
    
    csrf_token = None
    if 'csrftoken' in session.cookies:
        csrf_token = session.cookies['csrftoken']
    
    login_data = {
        'username': username,
        'password': password,
        'csrfmiddlewaretoken': csrf_token
    }
    
    session.post(login_url, data=login_data, headers={'Referer': login_url})
    
    # Test tickets API
    tickets_url = urljoin(base_url, "/api/tickets/")
    print(f"   Testing: {tickets_url}")
    
    headers = {
        'Content-Type': 'application/json',
        'X-CSRFToken': session.cookies.get('csrftoken', ''),
        'Referer': tickets_url,
    }
    
    try:
        response = session.get(tickets_url, headers=headers)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   Found {len(data.get('results', []))} tickets")
            print("   ✅ Tickets API working!")
            return True
        else:
            print(f"   ❌ Failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def main():
    """Run all tests."""
    print("🧪 Testing Django-Helpdesk Session Authentication")
    print("=" * 60)
    
    success1 = test_session_auth()
    success2 = test_tickets_endpoint()
    
    print("\n" + "=" * 60)
    if success1 and success2:
        print("🎉 All tests passed! Session authentication is working.")
    else:
        print("❌ Some tests failed. Check the output above.")
    
    return success1 and success2


if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)