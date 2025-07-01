#!/usr/bin/env python3
"""
Django Helpdesk MCP Server

This MCP server exposes the django-helpdesk API to AI agents, providing tools for:
- Listing and filtering tickets
- Creating new tickets  
- Adding follow-ups to tickets
- Managing ticket status and assignments
- Retrieving ticket details
"""

import asyncio
import json
import os
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urljoin

import httpx
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    ListToolsResult,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field


class HelpdeskConfig(BaseModel):
    """Configuration for the Django Helpdesk API"""
    
    base_url: str = Field(
        default="http://localhost:8080",
        description="Base URL of the Django Helpdesk instance"
    )
    api_token: Optional[str] = Field(
        default=None,
        description="API token for authentication (if using token auth)"
    )
    username: Optional[str] = Field(
        default=None,
        description="Username for basic auth"
    )
    password: Optional[str] = Field(
        default=None,
        description="Password for basic auth"
    )


class HelpdeskMCPServer:
    """MCP Server for Django Helpdesk integration"""
    
    def __init__(self):
        self.server = Server("django-helpdesk")
        self.config = self._load_config()
        self.client = httpx.AsyncClient()
        self._setup_handlers()
    
    def _load_config(self) -> HelpdeskConfig:
        """Load configuration from environment variables"""
        return HelpdeskConfig(
            base_url=os.getenv("HELPDESK_BASE_URL", "http://localhost:8080"),
            api_token=os.getenv("HELPDESK_API_TOKEN"),
            username=os.getenv("HELPDESK_USERNAME"),
            password=os.getenv("HELPDESK_PASSWORD"),
        )
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        headers = {"Content-Type": "application/json"}
        
        if self.config.api_token:
            headers["Authorization"] = f"Token {self.config.api_token}"
        
        return headers
    
    def _get_auth(self) -> Optional[tuple]:
        """Get basic auth credentials if configured"""
        if self.config.username and self.config.password:
            return (self.config.username, self.config.password)
        return None
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make an authenticated API request"""
        url = urljoin(self.config.base_url.rstrip("/") + "/", f"api/{endpoint.lstrip('/')}")
        
        try:
            response = await self.client.request(
                method=method,
                url=url,
                headers=self._get_auth_headers(),
                auth=self._get_auth(),
                params=params,
                json=json_data,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise Exception(f"API request failed: {str(e)}")
    
    def _setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_tools()
        async def list_tools() -> ListToolsResult:
            """List available tools"""
            return ListToolsResult([
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
                )
            ])
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Handle tool calls"""
            
            try:
                if name == "list_tickets":
                    return await self._list_tickets(arguments)
                elif name == "get_ticket":
                    return await self._get_ticket(arguments)
                elif name == "create_ticket":
                    return await self._create_ticket(arguments)
                elif name == "add_followup":
                    return await self._add_followup(arguments)
                elif name == "update_ticket":
                    return await self._update_ticket(arguments)
                elif name == "get_queues":
                    return await self._get_queues(arguments)
                elif name == "get_users":
                    return await self._get_users(arguments)
                else:
                    return CallToolResult([
                        TextContent(type="text", text=f"Unknown tool: {name}")
                    ])
            except Exception as e:
                return CallToolResult([
                    TextContent(type="text", text=f"Error calling {name}: {str(e)}")
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
    
    async def run(self):
        """Run the MCP server"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, 
                write_stream, 
                InitializationOptions(
                    server_name="django-helpdesk",
                    server_version="0.1.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=None,
                        experimental_capabilities=None,
                    ),
                )
            )


def main():
    """Main entry point"""
    server = HelpdeskMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()