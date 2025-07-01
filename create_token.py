#!/usr/bin/env python3
"""
Create Django REST Framework Auth Token

This script creates an authentication token for a user via Django shell.
Run this from the django-helpdesk directory.

Usage:
    python create_token.py <username>

Example:
    python create_token.py admin
"""

import os
import sys
import django

# Setup Django environment
sys.path.append('demo')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'demodesk.config.settings')
django.setup()

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


def create_token(username):
    """Create or get token for the specified user."""
    try:
        user = User.objects.get(username=username)
        print(f"Found user: {user.username} (ID: {user.id})")
        
        # Create or get token
        token, created = Token.objects.get_or_create(user=user)
        
        if created:
            print(f"✅ New token created for {username}")
        else:
            print(f"✅ Existing token found for {username}")
            
        print(f"🔑 Token: {token.key}")
        print(f"\nYou can now use this token for API authentication:")
        print(f"curl -H 'Authorization: Token {token.key}' http://localhost:8000/api/tickets/")
        
        return token.key
        
    except User.DoesNotExist:
        print(f"❌ User '{username}' not found")
        print("Available users:")
        for user in User.objects.all():
            print(f"  - {user.username}")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python create_token.py <username>")
        print("Example: python create_token.py admin")
        sys.exit(1)
    
    username = sys.argv[1]
    token = create_token(username)
    
    if token:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()