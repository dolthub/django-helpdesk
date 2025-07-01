#!/usr/bin/env python3
"""
Django Helpdesk MCP Server Entry Point

This is an alternative entry point that imports and runs the MCP server.
Use this if you prefer to run via `python main.py` instead of `python helpdesk.py`.
"""

from helpdesk import main

if __name__ == "__main__":
    main()
