#!/usr/bin/env python3
"""
Django Helpdesk MCP Server

This MCP server exposes the django-helpdesk API to AI agents, providing tools for:
- Listing and filtering tickets
- Creating new tickets  
- Adding follow-ups to tickets
- Managing ticket status and assignments
- Retrieving ticket details
- Agent session management (branch names, intents, session lifecycle)
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urljoin
import re

import httpx
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    ListToolsResult,
    TextContent,
    Tool,
    ServerCapabilities,
)
from pydantic import BaseModel, Field


class HelpdeskConfig(BaseModel):
    """Configuration for the Django Helpdesk API"""
    
    base_url: str = Field(
        default="http://localhost:8080",
        description="Base URL of the Django Helpdesk instance"
    )


class HelpdeskMCPServer:
    """MCP Server for Django Helpdesk integration"""
    
    def __init__(self):
        self.server = Server("django-helpdesk")
        self.config = self._load_config()
        self.client = httpx.AsyncClient()
        self.authenticated = False
        self.session_info = None
        self.csrf_token = None
        self.credentials = {"username": None, "password": None}
        self.client_id = None
        self._setup_logging()
        self._setup_handlers()
    
    def _setup_logging(self):
        """Set up logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self) -> HelpdeskConfig:
        """Load configuration from environment variables"""
        return HelpdeskConfig(
            base_url=os.getenv("HELPDESK_BASE_URL", "http://localhost:8080"),
        )
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        headers = {"Content-Type": "application/json"}
        
        # Add CSRF token if we have it
        if self.csrf_token:
            headers["X-CSRFToken"] = self.csrf_token
            headers["Referer"] = self.config.base_url
        
        return headers
    
    async def _authenticate(self) -> bool:
        """Perform session-based authentication"""
        if self.authenticated:
            return True
            
        # Check if credentials are available
        username = self.credentials.get("username")
        password = self.credentials.get("password")
        
        if not username or not password:
            raise Exception("Username and password must be provided via the authenticate tool")
        
        self.logger.info(f"🔑 Attempting authentication for user: {username}")
        
        try:
            # Get login page to extract CSRF token
            login_url = urljoin(self.config.base_url.rstrip("/") + "/", "login/")
            response = await self.client.get(login_url)
            response.raise_for_status()
            
            # Extract CSRF token from login form or cookies
            csrf_token = None
            if 'csrftoken' in self.client.cookies:
                csrf_token = self.client.cookies['csrftoken']
            else:
                # Try to extract from HTML
                csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
            
            if not csrf_token:
                raise Exception("Could not extract CSRF token")
                
            self.csrf_token = csrf_token
            
            # Perform login
            login_data = {
                'username': username,
                'password': password,
                'csrfmiddlewaretoken': csrf_token,
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': csrf_token,
                'Referer': login_url,
            }
            
            response = await self.client.post(
                login_url,
                data=login_data,
                headers=headers,
                follow_redirects=False
            )
            
            # Check for successful login (redirect or 200 with session)
            if response.status_code in [200, 302] and 'sessionid' in self.client.cookies:
                self.authenticated = True
                self.logger.info(f"✅ Successfully authenticated user: {username}")
                
                # Get session info if user is an agent
                try:
                    session_info = await self._get_session_info()
                    if session_info:
                        self.session_info = session_info
                        self.logger.info(f"👤 User {username} is an agent with branch: {session_info.get('branch_name', 'N/A')}")
                except Exception:
                    # Not an agent or session info not available
                    self.logger.info(f"👤 User {username} authenticated (not an agent)")
                    pass
                    
                return True
            else:
                self.logger.error(f"❌ Authentication failed for user {username}: status {response.status_code}")
                raise Exception(f"Login failed with status {response.status_code}")
                
        except Exception as e:
            raise Exception(f"Authentication failed: {str(e)}")
    
    async def _get_session_info(self) -> Optional[Dict]:
        """Get agent session information"""
        try:
            response = await self.client.get(
                urljoin(self.config.base_url.rstrip("/") + "/", "api/agent-session-info/"),
                headers=self._get_auth_headers()
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make an authenticated API request"""
        # Ensure we're authenticated
        if not await self._authenticate():
            raise Exception("Authentication required")
            
        url = urljoin(self.config.base_url.rstrip("/") + "/", f"api/{endpoint.lstrip('/')}")
        
        self.logger.info(f"🌐 API Request: {method} {endpoint} {f'(params: {params})' if params else ''}")
        
        try:
            response = await self.client.request(
                method=method,
                url=url,
                headers=self._get_auth_headers(),
                params=params,
                json=json_data,
                timeout=30.0,
            )
            response.raise_for_status()
            result = response.json()
            self.logger.info(f"✅ API Response: {method} {endpoint} -> {response.status_code}")
            return result
        except httpx.HTTPError as e:
            self.logger.error(f"❌ API Request failed: {method} {endpoint} -> {str(e)}")
            raise Exception(f"API request failed: {str(e)}")
    
    def _setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_tools()
        async def list_tools() -> ListToolsResult:
            """List available tools"""
            return ListToolsResult([
                Tool(
                    name="authenticate",
                    description="Authenticate with django-helpdesk using username and password",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "username": {
                                "type": "string",
                                "description": "Username for authentication"
                            },
                            "password": {
                                "type": "string",
                                "description": "Password for authentication"
                            }
                        },
                        "required": ["username", "password"]
                    }
                ),
                Tool(
                    name="list_tickets",
                    description="List tickets with optional filtering by status, queue, or other criteria",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "status": {
                                "type": "string",
                                "description": "Filter by ticket status (e.g., 'Open', 'Resolved', 'Closed'). Can be comma-separated for multiple statuses."
                            },
                            "queue_id": {
                                "type": "integer",
                                "description": "Filter by queue ID"
                            },
                            "assigned_to": {
                                "type": "integer",
                                "description": "Filter by assigned user ID"
                            },
                            "page": {
                                "type": "integer",
                                "description": "Page number for pagination (default: 1)"
                            },
                            "page_size": {
                                "type": "integer",
                                "description": "Number of results per page (default: 25)"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_ticket",
                    description="Get detailed information about a specific ticket",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ticket_id": {
                                "type": "integer",
                                "description": "The ID of the ticket to retrieve"
                            }
                        },
                        "required": ["ticket_id"]
                    }
                ),
                Tool(
                    name="create_ticket",
                    description="Create a new ticket",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "queue": {
                                "type": "integer",
                                "description": "Queue ID for the ticket"
                            },
                            "title": {
                                "type": "string",
                                "description": "Title of the ticket"
                            },
                            "description": {
                                "type": "string",
                                "description": "Description/body of the ticket"
                            },
                            "submitter_email": {
                                "type": "string",
                                "description": "Email address of the ticket submitter"
                            },
                            "priority": {
                                "type": "integer",
                                "description": "Priority level (1-5, where 1 is highest priority)"
                            },
                            "assigned_to": {
                                "type": "integer",
                                "description": "User ID to assign the ticket to (optional)"
                            },
                            "due_date": {
                                "type": "string",
                                "format": "date",
                                "description": "Due date in YYYY-MM-DD format (optional)"
                            }
                        },
                        "required": ["queue", "title", "description", "submitter_email"]
                    }
                ),
                Tool(
                    name="add_followup",
                    description="Add a follow-up comment to an existing ticket",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ticket_id": {
                                "type": "integer",
                                "description": "The ID of the ticket to add a follow-up to"
                            },
                            "title": {
                                "type": "string",
                                "description": "Title of the follow-up"
                            },
                            "comment": {
                                "type": "string",
                                "description": "The follow-up comment text"
                            },
                            "public": {
                                "type": "boolean",
                                "description": "Whether this follow-up is visible to the public (default: true)"
                            },
                            "new_status": {
                                "type": "integer",
                                "description": "New status to set for the ticket (optional)"
                            },
                            "time_spent": {
                                "type": "string",
                                "description": "Time spent on this follow-up (in minutes or HH:MM format)"
                            }
                        },
                        "required": ["ticket_id", "comment"]
                    }
                ),
                Tool(
                    name="update_ticket",
                    description="Update an existing ticket's properties",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ticket_id": {
                                "type": "integer",
                                "description": "The ID of the ticket to update"
                            },
                            "title": {
                                "type": "string",
                                "description": "New title for the ticket"
                            },
                            "description": {
                                "type": "string",
                                "description": "New description for the ticket"
                            },
                            "status": {
                                "type": "integer",
                                "description": "New status for the ticket"
                            },
                            "priority": {
                                "type": "integer",
                                "description": "New priority level (1-5)"
                            },
                            "assigned_to": {
                                "type": "integer",
                                "description": "User ID to assign the ticket to"
                            },
                            "due_date": {
                                "type": "string",
                                "format": "date",
                                "description": "New due date in YYYY-MM-DD format"
                            }
                        },
                        "required": ["ticket_id"]
                    }
                ),
                Tool(
                    name="get_queues",
                    description="List all available ticket queues",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="get_users",
                    description="List users that can be assigned to tickets",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "page": {
                                "type": "integer",
                                "description": "Page number for pagination"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_agent_session_info",
                    description="Get current agent session information (branch name, intent, etc.)",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="set_agent_intent",
                    description="Set the intent for the current agent session",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "intent": {
                                "type": "string",
                                "description": "The intent to set for the session (max 512 characters)"
                            }
                        },
                        "required": ["intent"]
                    }
                ),
                Tool(
                    name="finish_agent_session",
                    description="Finish the current agent session and perform cleanup",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ])
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Handle tool calls"""
            
            # Log tool calls but mask sensitive information
            safe_args = arguments.copy() if arguments else {}
            if name == "authenticate" and "password" in safe_args:
                safe_args["password"] = "***"
            self.logger.info(f"🔧 Tool called: {name} {f'(args: {safe_args})' if safe_args else ''}")
            
            try:
                if name == "authenticate":
                    result = await self._authenticate_user(arguments)
                elif name == "list_tickets":
                    result = await self._list_tickets(arguments)
                elif name == "get_ticket":
                    result = await self._get_ticket(arguments)
                elif name == "create_ticket":
                    result = await self._create_ticket(arguments)
                elif name == "add_followup":
                    result = await self._add_followup(arguments)
                elif name == "update_ticket":
                    result = await self._update_ticket(arguments)
                elif name == "get_queues":
                    result = await self._get_queues(arguments)
                elif name == "get_users":
                    result = await self._get_users(arguments)
                elif name == "get_agent_session_info":
                    result = await self._get_agent_session_info(arguments)
                elif name == "set_agent_intent":
                    result = await self._set_agent_intent(arguments)
                elif name == "finish_agent_session":
                    result = await self._finish_agent_session(arguments)
                else:
                    self.logger.warning(f"⚠️ Unknown tool requested: {name}")
                    return CallToolResult([
                        TextContent(type="text", text=f"Unknown tool: {name}")
                    ])
                
                self.logger.info(f"✅ Tool completed: {name}")
                return result
            except Exception as e:
                self.logger.error(f"❌ Tool error: {name} -> {str(e)}")
                return CallToolResult([
                    TextContent(type="text", text=f"Error calling {name}: {str(e)}")
                ])
    
    async def _authenticate_user(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Authenticate user with provided credentials"""
        username = arguments["username"]
        password = arguments["password"]
        
        # Store credentials for this session
        self.credentials["username"] = username
        self.credentials["password"] = password
        
        # Reset authentication state to force re-authentication
        self.authenticated = False
        self.csrf_token = None
        
        try:
            # Attempt to authenticate
            if await self._authenticate():
                result_text = f"✓ Successfully authenticated as {username}\n"
                
                # Try to get session info if available
                if self.session_info:
                    result_text += f"  User ID: {self.session_info.get('user_id', 'N/A')}\n"
                    result_text += f"  Is Agent: {self.session_info.get('is_agent', 'N/A')}\n"
                    result_text += f"  Branch: {self.session_info.get('branch_name', 'N/A')}\n"
                
                result_text += "\nYou can now use other tools to interact with the helpdesk system."
                
                return CallToolResult([
                    TextContent(type="text", text=result_text)
                ])
            else:
                return CallToolResult([
                    TextContent(type="text", text="❌ Authentication failed")
                ])
        except Exception as e:
            return CallToolResult([
                TextContent(type="text", text=f"❌ Authentication failed: {str(e)}")
            ])
    
    async def _list_tickets(self, arguments: Dict[str, Any]) -> CallToolResult:
        """List tickets with optional filtering"""
        params = {}
        
        if "status" in arguments:
            params["status"] = arguments["status"]
        if "page" in arguments:
            params["page"] = arguments["page"]
        if "page_size" in arguments:
            params["page_size"] = arguments["page_size"]
        
        data = await self._make_request("GET", "tickets/", params=params)
        
        result_text = f"Found {data.get('count', 0)} tickets"
        if data.get('results'):
            result_text += ":\n\n"
            for ticket in data['results']:
                result_text += f"#{ticket['id']}: {ticket['title']}\n"
                result_text += f"  Status: {ticket.get('status', 'Unknown')}\n"
                result_text += f"  Queue: {ticket.get('queue', {}).get('title', 'Unknown')}\n"
                result_text += f"  Created: {ticket.get('created', 'Unknown')}\n"
                if ticket.get('assigned_to'):
                    result_text += f"  Assigned to: {ticket['assigned_to']}\n"
                result_text += "\n"
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _get_ticket(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Get detailed ticket information"""
        ticket_id = arguments["ticket_id"]
        
        data = await self._make_request("GET", f"tickets/{ticket_id}/")
        
        result_text = f"Ticket #{data['id']}: {data['title']}\n"
        result_text += f"Status: {data.get('status', 'Unknown')}\n"
        result_text += f"Priority: {data.get('priority', 'Unknown')}\n"
        result_text += f"Queue: {data.get('queue', 'Unknown')}\n"
        result_text += f"Submitter: {data.get('submitter_email', 'Unknown')}\n"
        if data.get('assigned_to'):
            result_text += f"Assigned to: {data['assigned_to']}\n"
        if data.get('due_date'):
            result_text += f"Due date: {data['due_date']}\n"
        result_text += f"\nDescription:\n{data.get('description', 'No description')}\n"
        
        if data.get('followup_set'):
            result_text += f"\nFollow-ups ({len(data['followup_set'])}):\n"
            for followup in data['followup_set']:
                result_text += f"- {followup.get('date', 'Unknown date')}: {followup.get('title', 'No title')}\n"
                if followup.get('comment'):
                    result_text += f"  {followup['comment'][:100]}{'...' if len(followup['comment']) > 100 else ''}\n"
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _create_ticket(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Create a new ticket"""
        ticket_data = {
            "queue": arguments["queue"],
            "title": arguments["title"],
            "description": arguments["description"],
            "submitter_email": arguments["submitter_email"],
        }
        
        # Add optional fields if provided
        for field in ["priority", "assigned_to", "due_date"]:
            if field in arguments:
                ticket_data[field] = arguments[field]
        
        data = await self._make_request("POST", "tickets/", json_data=ticket_data)
        
        result_text = f"Created ticket #{data['id']}: {data['title']}\n"
        result_text += f"Status: {data.get('status', 'Unknown')}\n"
        result_text += f"Queue: {data.get('queue', 'Unknown')}\n"
        result_text += f"Submitter: {data.get('submitter_email', 'Unknown')}\n"
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _add_followup(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Add a follow-up to a ticket"""
        ticket_id = arguments["ticket_id"]
        
        followup_data = {
            "ticket": ticket_id,
            "comment": arguments["comment"],
            "public": arguments.get("public", True),
        }
        
        # Add optional fields if provided
        for field in ["title", "new_status", "time_spent"]:
            if field in arguments:
                followup_data[field] = arguments[field]
        
        data = await self._make_request("POST", "followups/", json_data=followup_data)
        
        result_text = f"Added follow-up to ticket #{ticket_id}\n"
        result_text += f"Follow-up ID: {data['id']}\n"
        result_text += f"Date: {data.get('date', 'Unknown')}\n"
        if data.get('title'):
            result_text += f"Title: {data['title']}\n"
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _update_ticket(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Update an existing ticket"""
        ticket_id = arguments["ticket_id"]
        
        # Remove ticket_id from update data
        update_data = {k: v for k, v in arguments.items() if k != "ticket_id"}
        
        data = await self._make_request("PATCH", f"tickets/{ticket_id}/", json_data=update_data)
        
        result_text = f"Updated ticket #{data['id']}: {data['title']}\n"
        result_text += f"Status: {data.get('status', 'Unknown')}\n"
        result_text += f"Priority: {data.get('priority', 'Unknown')}\n"
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _get_queues(self, arguments: Dict[str, Any]) -> CallToolResult:
        """List all available queues"""
        # Note: This assumes there's a queues endpoint. If not, we'll need to extract from ticket data
        try:
            data = await self._make_request("GET", "queues/")
            result_text = "Available queues:\n\n"
            for queue in data.get('results', data if isinstance(data, list) else []):
                result_text += f"ID {queue['id']}: {queue['title']}\n"
                if queue.get('slug'):
                    result_text += f"  Slug: {queue['slug']}\n"
                result_text += "\n"
        except Exception:
            # Fallback: extract queue info from tickets
            data = await self._make_request("GET", "tickets/", params={"page_size": 100})
            queues = {}
            for ticket in data.get('results', []):
                queue = ticket.get('queue', {})
                if queue and queue.get('id'):
                    queues[queue['id']] = queue
            
            result_text = "Available queues (extracted from tickets):\n\n"
            for queue in queues.values():
                result_text += f"ID {queue['id']}: {queue['title']}\n"
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _get_users(self, arguments: Dict[str, Any]) -> CallToolResult:
        """List users that can be assigned to tickets"""
        params = {}
        if "page" in arguments:
            params["page"] = arguments["page"]
        
        try:
            data = await self._make_request("GET", "users/", params=params)
            result_text = "Available users for assignment:\n\n"
            for user in data.get('results', data if isinstance(data, list) else []):
                result_text += f"ID {user['id']}: {user.get('username', 'Unknown')}\n"
                if user.get('first_name') or user.get('last_name'):
                    name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
                    result_text += f"  Name: {name}\n"
                if user.get('email'):
                    result_text += f"  Email: {user['email']}\n"
                result_text += "\n"
        except Exception as e:
            result_text = f"Could not retrieve users list: {str(e)}\n"
            result_text += "Note: User assignment may require extracting user IDs from existing ticket assignments."
        
        return CallToolResult([
            TextContent(type="text", text=result_text)
        ])
    
    async def _get_agent_session_info(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Get current agent session information"""
        try:
            data = await self._make_request("GET", "agent-session-info/")
            
            result_text = "Agent Session Information:\n\n"
            result_text += f"User ID: {data.get('user_id', 'N/A')}\n"
            result_text += f"Username: {data.get('username', 'N/A')}\n"
            result_text += f"Is Agent: {data.get('is_agent', 'N/A')}\n"
            result_text += f"Branch Name: {data.get('branch_name', 'Not set')}\n"
            intent = data.get('intent')
            result_text += f"Intent: {'Not set' if intent is None else intent}\n"
            result_text += f"Session Key: {data.get('session_key', 'N/A')}\n"
            result_text += f"Authentication: {data.get('authentication_method', 'N/A')}\n"
            
            if data.get('branch_name'):
                result_text += f"\nBranch Usage Examples:\n"
                result_text += f"  Database context: Working in branch '{data['branch_name']}'\n"
                result_text += f"  Isolation: Changes are isolated to this branch\n"
                
            return CallToolResult([
                TextContent(type="text", text=result_text)
            ])
            
        except Exception as e:
            return CallToolResult([
                TextContent(type="text", text=f"Error getting session info: {str(e)}")
            ])
    
    async def _set_agent_intent(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Set the intent for the current agent session"""
        intent = arguments["intent"]
        
        if len(intent) > 512:
            return CallToolResult([
                TextContent(type="text", text="Error: Intent must be 512 characters or less")
            ])
        
        try:
            data = await self._make_request("POST", "set-agent-intent/", json_data={"intent": intent})
            
            result_text = "Agent Intent Set Successfully\n\n"
            result_text += f"Intent: {data.get('intent', 'Unknown')}\n"
            result_text += f"User: {data.get('username', 'Unknown')}\n"
            result_text += f"Branch: {data.get('branch_name', 'Unknown')}\n"
            result_text += f"Session: {data.get('session_key', 'Unknown')}\n"
            
            return CallToolResult([
                TextContent(type="text", text=result_text)
            ])
            
        except Exception as e:
            return CallToolResult([
                TextContent(type="text", text=f"Error setting intent: {str(e)}")
            ])
    
    async def _finish_agent_session(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Finish the current agent session and perform cleanup"""
        try:
            data = await self._make_request("POST", "finish-agent-session/")
            
            result_text = "Agent Session Finished Successfully\n\n"
            result_text += f"User: {data.get('username', 'Unknown')}\n"
            result_text += f"Branch: {data.get('branch_name', 'Unknown')}\n"
            result_text += f"Intent: {data.get('intent', 'Not set')}\n"
            result_text += f"Session: {data.get('session_key', 'Unknown')}\n"
            result_text += f"\nSession cleanup completed and user logged out.\n"
            result_text += f"You will need to re-authenticate for further API calls.\n"
            
            # Mark as no longer authenticated since the session was finished
            self.authenticated = False
            self.session_info = None
            
            return CallToolResult([
                TextContent(type="text", text=result_text)
            ])
            
        except Exception as e:
            return CallToolResult([
                TextContent(type="text", text=f"Error finishing session: {str(e)}")
            ])
    
    async def run(self):
        """Run the MCP server"""
        self.logger.info("🚀 Starting Django Helpdesk MCP Server...")
        self.logger.info(f"📡 Server version: 0.2.0")
        self.logger.info(f"🔗 Django Helpdesk URL: {self.config.base_url}")
        self.logger.info("⚡ Server ready - waiting for client connections...")
        
        async with stdio_server() as (read_stream, write_stream):
            self.logger.info("🔌 Client connected to MCP server")
            await self.server.run(
                read_stream, 
                write_stream, 
                InitializationOptions(
                    server_name="django-helpdesk",
                    server_version="0.2.0",
                    capabilities=ServerCapabilities(
                        tools={},
                    ),
                )
            )


def main():
    """Main entry point"""
    print("🎯 Django Helpdesk MCP Server")
    print("=" * 50)
    server = HelpdeskMCPServer()
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        try:
            server.logger.info("🛑 Server shutdown requested")
        except:
            pass
        print("\n👋 Server stopped gracefully")
    except Exception as e:
        try:
            server.logger.error(f"💥 Server error: {str(e)}")
        except:
            pass
        print(f"\n❌ Server error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()