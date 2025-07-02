"""
Custom authentication backends for django-helpdesk.
"""
from django.contrib.auth.backends import ModelBackend


class HelpdeskAuthenticationBackend(ModelBackend):
    """
    Custom authentication backend that prevents agents (is_agent=True) 
    from logging in through the web interface while allowing API access.
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user with additional agent restrictions for web login.
        """
        # First, use the standard authentication
        user = super().authenticate(request, username, password, **kwargs)
        
        if user is None:
            return None
            
        # Check if this is a web login attempt (not API)
        if request and self._is_web_login_attempt(request):
            # Check if user is an agent
            if self._is_agent(user):
                # Prevent web login for agents
                return None
                
        return user
    
    def _is_web_login_attempt(self, request):
        """
        Determine if this is a web login attempt vs API authentication.
        """
        if not request:
            return False
            
        # Check if it's an API request
        path = request.path_info
        
        # API requests start with /api/
        if path.startswith('/api/'):
            return False

        return True
            
    def _is_agent(self, user):
        """
        Check if user is marked as an agent.
        """
        try:
            return user.usersettings_helpdesk.is_agent
        except AttributeError:
            # UserSettings not created yet, default to False
            return False