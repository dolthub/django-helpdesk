#!/usr/bin/env python3
"""
Test script for the Django Helpdesk MCP Server

This script tests the MCP server functionality with a running Django Helpdesk instance.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpdesk import HelpdeskMCPServer


async def test_authentication():
    """Test authentication and basic connectivity"""
    print("Testing authentication and connectivity...")
    
    server = HelpdeskMCPServer()
    
    try:
        # Test authentication
        auth_success = await server._authenticate()
        if auth_success:
            print("✅ Authentication successful")
            
            # Test getting session info if user is an agent
            session_info = await server._get_session_info()
            if session_info:
                print(f"✅ Agent session info retrieved: {session_info.get('branch_name', 'N/A')}")
            else:
                print("ℹ️  User is not an agent or session info not available")
            
            return True
        else:
            print("❌ Authentication failed")
            return False
            
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return False
    finally:
        await server.client.aclose()


async def test_basic_api_calls():
    """Test basic API functionality"""
    print("\nTesting basic API calls...")
    
    server = HelpdeskMCPServer()
    
    try:
        # Test get_queues
        print("Testing get_queues...")
        queues_result = await server._get_queues({})
        print(f"✅ Queues retrieved: {len(queues_result.content)} characters")
        
        # Test list_tickets
        print("Testing list_tickets...")
        tickets_result = await server._list_tickets({"page_size": 5})
        print(f"✅ Tickets listed: {len(tickets_result.content)} characters")
        
        # Test get_users
        print("Testing get_users...")
        users_result = await server._get_users({"page": 1})
        print(f"✅ Users retrieved: {len(users_result.content)} characters")
        
        return True
        
    except Exception as e:
        print(f"❌ API call error: {e}")
        return False
    finally:
        await server.client.aclose()


async def test_agent_features():
    """Test agent-specific features"""
    print("\nTesting agent-specific features...")
    
    server = HelpdeskMCPServer()
    
    try:
        # Test get_agent_session_info
        print("Testing get_agent_session_info...")
        session_result = await server._get_agent_session_info({})
        print(f"✅ Session info retrieved: {len(session_result.content)} characters")
        
        # Test set_agent_intent
        print("Testing set_agent_intent...")
        intent_result = await server._set_agent_intent({"intent": "Testing MCP server functionality"})
        print(f"✅ Intent set: {len(intent_result.content)} characters")
        
        # Test get_agent_session_info again to verify intent was set
        print("Testing get_agent_session_info after setting intent...")
        session_result2 = await server._get_agent_session_info({})
        print(f"✅ Session info with intent: {len(session_result2.content)} characters")
        
        return True
        
    except Exception as e:
        print(f"❌ Agent features error: {e}")
        return False
    finally:
        await server.client.aclose()


async def test_session_cleanup():
    """Test session cleanup functionality"""
    print("\nTesting session cleanup...")
    
    server = HelpdeskMCPServer()
    
    try:
        # Test finish_agent_session
        print("Testing finish_agent_session...")
        finish_result = await server._finish_agent_session({})
        print(f"✅ Session finished: {len(finish_result.content)} characters")
        
        # Verify that subsequent calls require re-authentication
        print("Testing that re-authentication is required...")
        try:
            # This should fail or require re-authentication
            session_result = await server._get_agent_session_info({})
            print("ℹ️  Session info still accessible (may have re-authenticated)")
        except Exception as e:
            print(f"✅ Re-authentication required as expected: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Session cleanup error: {e}")
        return False
    finally:
        await server.client.aclose()


def check_environment():
    """Check if required environment variables are set"""
    print("Checking environment variables...")
    
    required_vars = ['HELPDESK_USERNAME', 'HELPDESK_PASSWORD']
    optional_vars = ['HELPDESK_BASE_URL']
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set the following environment variables:")
        print("export HELPDESK_USERNAME='your-agent-username'")
        print("export HELPDESK_PASSWORD='your-password'")
        print("export HELPDESK_BASE_URL='http://localhost:8080'  # Optional")
        return False
    
    print("✅ Required environment variables are set")
    
    # Show current configuration
    print(f"Base URL: {os.getenv('HELPDESK_BASE_URL', 'http://localhost:8080')}")
    print(f"Username: {os.getenv('HELPDESK_USERNAME')}")
    print(f"Password: {'*' * len(os.getenv('HELPDESK_PASSWORD', ''))}")
    
    return True


async def main():
    """Run all tests"""
    print("Django Helpdesk MCP Server Test Suite")
    print("=" * 50)
    
    # Check environment
    if not check_environment():
        return False
    
    # Run tests
    tests = [
        ("Authentication", test_authentication),
        ("Basic API Calls", test_basic_api_calls),
        ("Agent Features", test_agent_features),
        ("Session Cleanup", test_session_cleanup),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print(f"\n{'='*50}")
    print("TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nPassed: {passed}/{len(results)}")
    
    if passed == len(results):
        print("🎉 All tests passed! MCP server is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Test suite failed with error: {e}")
        sys.exit(1)