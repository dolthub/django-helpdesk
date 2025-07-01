#!/usr/bin/env python3
"""
Interactive Django-Helpdesk API Client

This script provides an interactive command line interface for the Django-Helpdesk API:
1. Authenticates with CSRF token and credentials
2. Provides interactive menu for API calls
3. Prompts for required and optional parameters
4. Makes authenticated API requests

Usage:
    python api_client.py <host> <port> <username> <password>

Example:
    python api_client.py localhost 8000 admin admin123
"""

import argparse
import json
import re
import requests
import sys
from datetime import datetime
from urllib.parse import urljoin


class DjangoAPIClient:
    """Interactive Django API client with CSRF token authentication."""
    
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"http://{host}:{port}"
        self.login_url = urljoin(self.base_url, "/api/auth/login/")
        self.django_login_url = urljoin(self.base_url, "/helpdesk/login/")
        self.api_base_url = urljoin(self.base_url, "/api/")
        self.session = requests.Session()
        self.authenticated = False
        self.auth_token = None
        
        # Define available API endpoints with their parameters
        self.api_endpoints = {
            'tickets': {
                'list': {
                    'method': 'GET',
                    'path': 'tickets/',
                    'description': 'List all tickets',
                    'params': {
                        'status': {'type': 'string', 'required': False, 'description': 'Filter by status (comma-separated)'},
                        'page': {'type': 'int', 'required': False, 'description': 'Page number'},
                        'page_size': {'type': 'int', 'required': False, 'description': 'Items per page'}
                    }
                },
                'create': {
                    'method': 'POST',
                    'path': 'tickets/',
                    'description': 'Create a new ticket',
                    'params': {
                        'title': {'type': 'string', 'required': True, 'description': 'Ticket title'},
                        'description': {'type': 'string', 'required': True, 'description': 'Ticket description'},
                        'queue': {'type': 'int', 'required': True, 'description': 'Queue ID'},
                        'priority': {'type': 'int', 'required': False, 'description': 'Priority (1-5)'},
                        'submitter_email': {'type': 'string', 'required': False, 'description': 'Submitter email'}
                    }
                },
                'get': {
                    'method': 'GET',
                    'path': 'tickets/{id}/',
                    'description': 'Get ticket details',
                    'params': {
                        'id': {'type': 'int', 'required': True, 'description': 'Ticket ID'}
                    }
                },
                'update': {
                    'method': 'PUT',
                    'path': 'tickets/{id}/',
                    'description': 'Update a ticket',
                    'params': {
                        'id': {'type': 'int', 'required': True, 'description': 'Ticket ID'},
                        'title': {'type': 'string', 'required': False, 'description': 'Ticket title'},
                        'description': {'type': 'string', 'required': False, 'description': 'Ticket description'},
                        'status': {'type': 'int', 'required': False, 'description': 'Status (1-5)'},
                        'priority': {'type': 'int', 'required': False, 'description': 'Priority (1-5)'}
                    }
                },
                'delete': {
                    'method': 'DELETE',
                    'path': 'tickets/{id}/',
                    'description': 'Delete a ticket',
                    'params': {
                        'id': {'type': 'int', 'required': True, 'description': 'Ticket ID'}
                    }
                }
            },
            'user_tickets': {
                'list': {
                    'method': 'GET',
                    'path': 'user_tickets/',
                    'description': 'List current user\'s tickets',
                    'params': {
                        'page': {'type': 'int', 'required': False, 'description': 'Page number'}
                    }
                }
            },
            'followups': {
                'list': {
                    'method': 'GET',
                    'path': 'followups/',
                    'description': 'List all follow-ups',
                    'params': {
                        'page': {'type': 'int', 'required': False, 'description': 'Page number'}
                    }
                },
                'create': {
                    'method': 'POST',
                    'path': 'followups/',
                    'description': 'Create a follow-up',
                    'params': {
                        'ticket': {'type': 'int', 'required': True, 'description': 'Ticket ID'},
                        'title': {'type': 'string', 'required': False, 'description': 'Follow-up title'},
                        'comment': {'type': 'string', 'required': True, 'description': 'Follow-up comment'},
                        'public': {'type': 'bool', 'required': False, 'description': 'Is public (true/false)'},
                        'new_status': {'type': 'int', 'required': False, 'description': 'New status (1-5)'},
                        'time_spent': {'type': 'string', 'required': False, 'description': 'Time spent (e.g., PT2H30M)'}
                    }
                }
            },
            'health': {
                'check': {
                    'method': 'GET',
                    'path': 'health/',
                    'description': 'Health check endpoint',
                    'params': {}
                }
            }
        }
        
    def get_csrf_token(self):
        """Get CSRF token from the login endpoint."""
        print(f"Getting CSRF token from: {self.login_url}")
        
        try:
            response = self.session.get(self.login_url)
            response.raise_for_status()
            
            print(f"GET Response Status: {response.status_code}")
            print(f"GET Response Headers: {dict(response.headers)}")
            
            # Try to extract CSRF token from cookies
            csrf_token = None
            if 'csrftoken' in response.cookies:
                csrf_token = response.cookies['csrftoken']
                print(f"CSRF token found in cookies: {csrf_token}")
            
            # Also try to extract from HTML meta tag or form
            if not csrf_token:
                csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                    print(f"CSRF token found in HTML: {csrf_token}")
            
            # Try to extract from response headers
            if not csrf_token and 'X-CSRFToken' in response.headers:
                csrf_token = response.headers['X-CSRFToken']
                print(f"CSRF token found in headers: {csrf_token}")
                
            if not csrf_token:
                print("Warning: No CSRF token found in response")
                print(f"Response content: {response.text[:500]}...")
                
            return csrf_token
            
        except requests.exceptions.RequestException as e:
            print(f"Error getting CSRF token: {e}")
            return None
    
    def get_auth_token(self):
        """Get authentication token using Django REST Framework token endpoint."""
        token_url = urljoin(self.base_url, "/api-auth-token/")
        
        # Try different token endpoints
        token_endpoints = [
            "/api-token-auth/",
            "/api-auth-token/",
            "/api/auth-token/", 
            "/auth/token/",
            "/api/token/"
        ]
        
        for endpoint in token_endpoints:
            url = urljoin(self.base_url, endpoint)
            print(f"Trying token endpoint: {url}")
            
            try:
                response = self.session.post(
                    url,
                    json={
                        'username': self.username,
                        'password': self.password
                    },
                    headers={'Content-Type': 'application/json'}
                )
                
                print(f"Token endpoint response: {response.status_code}")
                
                if response.status_code == 200:
                    try:
                        token_data = response.json()
                        if 'token' in token_data:
                            self.auth_token = token_data['token']
                            print(f"✅ Token obtained: {self.auth_token[:20]}...")
                            return True
                    except json.JSONDecodeError:
                        pass
                        
            except requests.exceptions.RequestException as e:
                print(f"Error trying {url}: {e}")
                continue
        
        return False

    def show_token_creation_help(self):
        """Show instructions for creating authentication tokens."""
        print("\n" + "="*60)
        print("🔑 AUTHENTICATION TOKEN REQUIRED")
        print("="*60)
        print("The Django-Helpdesk API requires token authentication.")
        print("Here are several ways to create an authentication token:")
        print()
        print("METHOD 1: Using the provided script")
        print("  python create_token.py admin")
        print()
        print("METHOD 2: Using Django shell")
        print("  python demo/manage.py shell")
        print("  >>> from django.contrib.auth.models import User")
        print("  >>> from rest_framework.authtoken.models import Token")
        print("  >>> user = User.objects.get(username='admin')")
        print("  >>> token, created = Token.objects.get_or_create(user=user)")
        print("  >>> print(f'Token: {token.key}')")
        print()
        print("METHOD 3: Using Django admin")
        print("  1. Go to http://localhost:8000/admin/")
        print("  2. Navigate to Authentication and Authorization > Tokens")
        print("  3. Click 'Add Token' and select your user")
        print()
        print("METHOD 4: Using curl (if token endpoint is available)")
        print(f"  curl -X POST {self.base_url}/api-token-auth/ \\")
        print("    -H 'Content-Type: application/json' \\")
        print(f"    -d '{{\"username\": \"{self.username}\", \"password\": \"your_password\"}}'")
        print()
        print("Once you have a token, you can use it directly:")
        print("  curl -H 'Authorization: Token your_token_here' \\")
        print(f"    {self.base_url}/api/tickets/")
        print("="*60)

    def django_session_login(self):
        """Perform Django session login via the helpdesk login form."""
        print("🔑 Attempting Django session authentication...")
        
        # First get the login page to extract CSRF token
        try:
            login_page_response = self.session.get(self.django_login_url)
            login_page_response.raise_for_status()
            
            # Extract CSRF token from the login form
            csrf_token = None
            if 'csrfmiddlewaretoken' in login_page_response.text:
                import re
                csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', login_page_response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                    print(f"CSRF token extracted from login form: {csrf_token[:20]}...")
            
            # Also get CSRF token from cookies
            if 'csrftoken' in self.session.cookies:
                csrf_token = self.session.cookies['csrftoken']
                print(f"CSRF token from cookies: {csrf_token[:20]}...")
            
            if not csrf_token:
                print("⚠️  No CSRF token found, proceeding without it")
            
            # Prepare login data
            login_data = {
                'username': self.username,
                'password': self.password,
            }
            
            if csrf_token:
                login_data['csrfmiddlewaretoken'] = csrf_token
            
            # Prepare headers
            headers = {
                'Referer': self.django_login_url,
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            if csrf_token:
                headers['X-CSRFToken'] = csrf_token
            
            print(f"Submitting login form to: {self.django_login_url}")
            
            # Submit login form
            login_response = self.session.post(
                self.django_login_url,
                data=login_data,  # Use form data, not JSON
                headers=headers,
                allow_redirects=False  # Don't follow redirects automatically
            )
            
            print(f"Login response status: {login_response.status_code}")
            print(f"Response headers: {dict(login_response.headers)}")
            
            # Check for successful login (usually a redirect)
            if login_response.status_code in [302, 301]:
                print("✅ Login successful (redirect detected)")
                
                # Check for session cookie
                if 'sessionid' in self.session.cookies:
                    print(f"Session ID: {self.session.cookies['sessionid'][:20]}...")
                
                return True
            elif login_response.status_code == 200:
                # Check if we're still on login page (login failed) or redirected to dashboard
                if 'login' in login_response.url.lower() or 'password' in login_response.text.lower():
                    print("❌ Login failed - still on login page")
                    return False
                else:
                    print("✅ Login successful (200 response)")
                    return True
            else:
                print(f"❌ Login failed with status {login_response.status_code}")
                print(f"Response: {login_response.text[:200]}...")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Error during session login: {e}")
            return False

    def login(self, csrf_token):
        """Perform login with CSRF token and credentials."""
        # Try Django session authentication first (for DRF session auth)
        if self.django_session_login():
            print("🎉 Using session authentication for API calls")
            return True
            
        # Fall back to token authentication if session login fails
        print("\n🔑 Session login failed, attempting token authentication...")
        if self.get_auth_token():
            return True
        
        # Show token creation help if no token endpoint found
        self.show_token_creation_help()
        
        # Ask user if they want to enter a token manually
        manual_token = input("\nDo you have an authentication token to enter manually? (y/N): ").strip().lower()
        if manual_token in ('y', 'yes'):
            token = input("Enter your authentication token: ").strip()
            if token:
                self.auth_token = token
                print(f"✅ Token set: {token[:20]}...")
                return True
            
        # Final fallback to old session method
        print("\n🔑 Trying alternative session authentication...")
        return self.old_session_login(csrf_token)
    
    def old_session_login(self, csrf_token):
        """Original session login method as fallback."""
        headers = {
            'Content-Type': 'application/json',
            'Referer': self.login_url,  # Required by Django CSRF protection
        }
        
        # Add CSRF token to headers if available
        if csrf_token:
            headers['X-CSRFToken'] = csrf_token
        
        # Prepare login data
        login_data = {
            'username': self.username,
            'password': self.password
        }
        
        # Add CSRF token to data if available
        if csrf_token:
            login_data['csrfmiddlewaretoken'] = csrf_token
        
        print(f"\nMaking POST request to: {self.login_url}")
        print(f"Headers: {headers}")
        print(f"Data: {json.dumps(login_data, indent=2)}")
        
        try:
            response = self.session.post(
                self.login_url,
                json=login_data,
                headers=headers
            )
            
            print(f"\nPOST Response Status: {response.status_code}")
            print(f"POST Response Headers: {dict(response.headers)}")
            
            # Print response content
            try:
                response_json = response.json()
                print(f"POST Response JSON: {json.dumps(response_json, indent=2)}")
                
                # Check if response contains a token
                if 'token' in response_json:
                    self.auth_token = response_json['token']
                    print(f"✅ Token found in response: {self.auth_token[:20]}...")
                    return True
                    
            except json.JSONDecodeError:
                print(f"POST Response Text: {response.text}")
            
            # Check for successful login
            if response.status_code == 200:
                print("\n✅ Session login successful!")
                
                # Extract any tokens or session info
                if 'sessionid' in response.cookies:
                    print(f"Session ID: {response.cookies['sessionid']}")
                
                return True
            else:
                print(f"\n❌ Login failed with status {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Error during login: {e}")
            return False
    
    def authenticate(self):
        """Complete authentication flow."""
        print(f"Authenticating to Django API at {self.base_url}")
        print(f"Username: {self.username}")
        print("-" * 50)
        
        # Step 1: Get CSRF token
        csrf_token = self.get_csrf_token()
        
        # Step 2: Login with credentials and CSRF token
        success = self.login(csrf_token)
        
        if success:
            print("\n🎉 Authentication completed successfully!")
            print("Session cookies and tokens are now available for API calls.")
            
            # Show available cookies
            if self.session.cookies:
                print("\nAvailable cookies:")
                for cookie in self.session.cookies:
                    print(f"  {cookie.name}: {cookie.value}")
        else:
            print("\n💥 Authentication failed!")
            
        return success
    
    def display_menu(self):
        """Display available API endpoints."""
        print("\n" + "="*60)
        print("🚀 Django-Helpdesk API Interactive Client")
        print("="*60)
        print("Available API endpoints:")
        print()
        
        menu_items = []
        for category, endpoints in self.api_endpoints.items():
            for action, details in endpoints.items():
                menu_items.append((category, action, details))
        
        for i, (category, action, details) in enumerate(menu_items, 1):
            print(f"{i:2d}. {category.title()} - {action.title()}")
            print(f"    {details['description']}")
            print(f"    Method: {details['method']} | Path: {details['path']}")
            print()
        
        print(f"{len(menu_items) + 1:2d}. Quit")
        print()
        return menu_items
    
    def get_user_input(self, param_name, param_info):
        """Get user input for a parameter with validation."""
        prompt = f"{param_name}"
        if param_info['required']:
            prompt += " (required)"
        else:
            prompt += " (optional)"
        
        prompt += f" - {param_info['description']}: "
        
        while True:
            value = input(prompt).strip()
            
            # Handle optional parameters
            if not value and not param_info['required']:
                return None
            
            # Validate required parameters
            if not value and param_info['required']:
                print("❌ This field is required. Please enter a value.")
                continue
            
            # Type validation
            try:
                if param_info['type'] == 'int':
                    return int(value)
                elif param_info['type'] == 'bool':
                    return value.lower() in ('true', 'yes', '1', 'on')
                else:  # string
                    return value
            except ValueError:
                print(f"❌ Invalid {param_info['type']} value. Please try again.")
                continue
    
    def collect_parameters(self, endpoint_info):
        """Collect parameters for an API endpoint."""
        print(f"\n📝 Collecting parameters for: {endpoint_info['description']}")
        print("-" * 50)
        
        params = {}
        path_params = {}
        query_params = {}
        
        for param_name, param_info in endpoint_info['params'].items():
            value = self.get_user_input(param_name, param_info)
            
            if value is not None:
                # Check if it's a path parameter
                if '{' + param_name + '}' in endpoint_info['path']:
                    path_params[param_name] = value
                else:
                    # For GET requests, use query parameters
                    if endpoint_info['method'] == 'GET':
                        query_params[param_name] = value
                    else:
                        # For POST/PUT/PATCH, use request body
                        params[param_name] = value
        
        return params, path_params, query_params
    
    def make_api_call(self, endpoint_info, params, path_params, query_params):
        """Make the actual API call."""
        # Build the URL
        path = endpoint_info['path']
        for param_name, param_value in path_params.items():
            path = path.replace('{' + param_name + '}', str(param_value))
        
        url = urljoin(self.api_base_url, path)
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
        }
        
        # Add authentication - prefer session auth, fallback to token auth
        if 'sessionid' in self.session.cookies and 'csrftoken' in self.session.cookies:
            headers['X-CSRFToken'] = self.session.cookies['csrftoken']
            headers['Referer'] = url  # Required for CSRF protection
            print(f"Using session authentication with CSRF token: {self.session.cookies['csrftoken'][:20]}...")
            print(f"Session ID: {self.session.cookies['sessionid'][:20]}...")
        elif self.auth_token:
            headers['Authorization'] = f'Token {self.auth_token}'
            print(f"Using Token authentication: Token {self.auth_token[:20]}...")
        else:
            print("⚠️  No authentication credentials available")
        
        print(f"\n🌐 Making API call...")
        print(f"Method: {endpoint_info['method']}")
        print(f"URL: {url}")
        print(f"Headers: {json.dumps(headers, indent=2)}")
        
        if query_params:
            print(f"Query Params: {json.dumps(query_params, indent=2)}")
        
        if params:
            print(f"Request Body: {json.dumps(params, indent=2)}")
        
        try:
            # Make the request
            if endpoint_info['method'] == 'GET':
                response = self.session.get(url, params=query_params, headers=headers)
            elif endpoint_info['method'] == 'POST':
                response = self.session.post(url, json=params, params=query_params, headers=headers)
            elif endpoint_info['method'] == 'PUT':
                response = self.session.put(url, json=params, params=query_params, headers=headers)
            elif endpoint_info['method'] == 'DELETE':
                response = self.session.delete(url, params=query_params, headers=headers)
            else:
                print(f"❌ Unsupported HTTP method: {endpoint_info['method']}")
                return False
            
            # Display response
            print(f"\n📡 Response:")
            print(f"Status Code: {response.status_code}")
            print(f"Headers: {json.dumps(dict(response.headers), indent=2)}")
            
            # Try to display JSON response
            try:
                response_data = response.json()
                print(f"Response Body: {json.dumps(response_data, indent=2)}")
            except json.JSONDecodeError:
                print(f"Response Text: {response.text}")
            
            # Success indicator
            if 200 <= response.status_code < 300:
                print("✅ API call successful!")
                return True
            else:
                print(f"⚠️  API call completed with status {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ API call failed: {e}")
            return False
    
    def interactive_mode(self):
        """Run the interactive API client."""
        if not self.authenticated:
            print("❌ Not authenticated. Please run authentication first.")
            return
        
        while True:
            try:
                menu_items = self.display_menu()
                
                # Get user choice
                while True:
                    try:
                        choice = input("Select an option (number): ").strip()
                        choice_num = int(choice)
                        
                        if choice_num == len(menu_items) + 1:
                            print("\n👋 Goodbye!")
                            return
                        
                        if 1 <= choice_num <= len(menu_items):
                            break
                        else:
                            print(f"❌ Please enter a number between 1 and {len(menu_items) + 1}")
                    except ValueError:
                        print("❌ Please enter a valid number")
                
                # Get selected endpoint
                category, action, endpoint_info = menu_items[choice_num - 1]
                
                print(f"\n🎯 Selected: {category.title()} - {action.title()}")
                
                # Collect parameters
                params, path_params, query_params = self.collect_parameters(endpoint_info)
                
                # Confirm action
                print(f"\n🔍 Ready to make API call:")
                print(f"Endpoint: {endpoint_info['method']} {endpoint_info['path']}")
                if params or path_params or query_params:
                    print("Parameters:")
                    if path_params:
                        print(f"  Path: {path_params}")
                    if query_params:
                        print(f"  Query: {query_params}")
                    if params:
                        print(f"  Body: {params}")
                
                confirm = input("\nProceed with API call? (y/N): ").strip().lower()
                if confirm in ('y', 'yes'):
                    self.make_api_call(endpoint_info, params, path_params, query_params)
                else:
                    print("❌ API call cancelled.")
                
                # Ask if user wants to continue
                continue_choice = input("\nMake another API call? (Y/n): ").strip().lower()
                if continue_choice in ('n', 'no'):
                    print("\n👋 Goodbye!")
                    break
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Unexpected error: {e}")
                continue


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Interactive Django-Helpdesk API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool provides an interactive command line interface for the Django-Helpdesk API.
After authentication, you can make various API calls through an interactive menu.

Examples:
  %(prog)s localhost 8000 admin admin123
  %(prog)s 127.0.0.1 8080 user@example.com mypassword
  %(prog)s api.example.com 443 staff_user secure_pass

Available API Operations:
  - List/Create/Update/Delete tickets
  - List user tickets
  - Create follow-ups
  - Health check
        """
    )
    
    parser.add_argument('host', help='API server hostname or IP address')
    parser.add_argument('port', type=int, help='API server port number')
    parser.add_argument('username', help='Username for authentication')
    parser.add_argument('password', help='Password for authentication')
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate port range
    if not (1 <= args.port <= 65535):
        print("Error: Port must be between 1 and 65535")
        sys.exit(1)
    
    # Create API client and authenticate
    try:
        client = DjangoAPIClient(args.host, args.port, args.username, args.password)
        success = client.authenticate()
        
        if success:
            client.authenticated = True
            # Start interactive mode
            client.interactive_mode()
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Authentication failed
            
    except KeyboardInterrupt:
        print("\n\nAuthentication interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()