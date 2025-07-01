# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Quick Setup & Demo
```bash
# Setup development environment
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Run demo server (localhost:8080, admin:admin/Test1234)
make rundemo
```

### Testing
```bash
# Run full test suite
make test

# Quick development testing
python quicktest.py

# Run specific test
python quicktest.py helpdesk.tests.test_tickets
```

### Code Quality
```bash
# Auto-format code
make format

# Check formatting without changes
make checkformat

# Manual linting
ruff check helpdesk/
```

### Database
```bash
# Create and apply migrations
python demo/manage.py makemigrations helpdesk
python demo/manage.py migrate
```

## Architecture Overview

**Django-helpdesk** is a ticket tracking system with three deployment modes:
1. **Library mode** - Integrate into existing Django projects
2. **Demo mode** - Development/testing (`demo/` directory)
3. **Standalone mode** - Production Docker deployment (`standalone/` directory)

### Core Structure

**Main Application** (`helpdesk/`):
- `models.py` - Monolithic model file with core entities (Ticket, Queue, FollowUp, etc.)
- `views/` - Split by interface: `staff.py` (admin), `public.py` (customer), `api.py` (REST)
- `management/commands/` - Email polling, escalation, permission setup commands

**Key Models**:
- `Queue` - Business areas for organizing tickets
- `Ticket` - Main entity with workflow states and assignments
- `FollowUp` - Conversation tracking with public/private visibility
- `KBItem`/`KBCategory` - Knowledge base functionality

### Email Integration

The system can create tickets from email via:
- POP3/IMAP polling (via management command `get_email`)
- Direct email forwarding to Django views
- Configuration in `HELPDESK_EMAIL_*` settings

### API & Permissions

- REST API via Django REST Framework (`views/api.py`)
- Team-based permissions using pinax-teams (when `HELPDESK_TEAMS_MODE_ENABLED`)
- Queue-level access control for staff users

### Configuration Settings

Key settings in `helpdesk/settings.py` prefixed with `HELPDESK_*`:
- `HELPDESK_DEFAULT_SETTINGS` - Default user preferences
- `HELPDESK_TEAMS_MODE_ENABLED` - Enable team-based permissions
- `HELPDESK_EMAIL_*` - Email integration configuration
- `HELPDESK_KB_*` - Knowledge base settings

### Testing Approach

- Comprehensive test suite in `helpdesk/tests/`
- Email processing tests use fixture files in `test_files/`
- Use `quicktest.py` for rapid development testing
- Full CI via tox for multiple Python/Django versions

### Database Migrations

Migration files track feature evolution. Recent additions:
- Checklist functionality (0038+)
- KB item ordering improvements (0040)
- Team integration features

When adding models/fields, always create migrations via the demo project:
```bash
cd demo && python manage.py makemigrations helpdesk
```