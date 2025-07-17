#!/usr/bin/env python3
"""
Test script to verify connection to django-helpdesk API

Usage:
    python test_connection.py

Make sure to set environment variables or create .env file first.
"""

import asyncio
import os
from helpdesk import HelpdeskMCPServer


async def test_connection():
    """Test basic connection to the django-helpdesk API"""
    server = HelpdeskMCPServer()
    
    print(f"Testing connection to: {server.config.base_url}")
    
    # Get credentials from environment for testing
    username = os.getenv("HELPDESK_USERNAME")
    password = os.getenv("HELPDESK_PASSWORD")
    
    if not username or not password:
        print("❌ No credentials provided. Please set HELPDESK_USERNAME and HELPDESK_PASSWORD environment variables for testing")
        return False
    
    print(f"Authentication method: Session (username: {username})")
    print()
    
    # Set credentials manually for testing
    server.credentials["username"] = username
    server.credentials["password"] = password
    
    try:
        # Test basic API connectivity
        print("Testing API connectivity...")
        tickets = await server._make_request("GET", "tickets/", params={"page_size": 1})
        print(f"✓ Successfully connected! Found {tickets.get('count', 0)} total tickets")
        print()
        
        # Test queues endpoint
        print("Testing queues endpoint...")
        try:
            queues = await server._make_request("GET", "queues/")
            print(f"✓ Queues endpoint working: found {len(queues.get('results', queues if isinstance(queues, list) else []))} queues")
        except Exception as e:
            print(f"⚠ Queues endpoint not available: {str(e)}")
            print("  This is expected if there's no dedicated queues API endpoint")
        print()
        
        # Test users endpoint  
        print("Testing users endpoint...")
        try:
            users = await server._make_request("GET", "users/", params={"page_size": 1})
            print(f"✓ Users endpoint working: found users")
        except Exception as e:
            print(f"⚠ Users endpoint not available: {str(e)}")
            print("  This is expected if there's no dedicated users API endpoint")
        print()
        
        print("🎉 Connection test completed successfully!")
        
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")
        print()
        print("Troubleshooting tips:")
        print("1. Check that HELPDESK_BASE_URL is correct")
        print("2. Verify django-helpdesk is running")
        print("3. Ensure API authentication is configured")
        print("4. Check that the REST API is enabled in Django settings")
        return False
    
    finally:
        await server.client.aclose()
    
    return True


if __name__ == "__main__":
    # Load .env file if it exists
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("Loaded .env file")
    except ImportError:
        print("python-dotenv not installed, using environment variables directly")
    
    asyncio.run(test_connection())