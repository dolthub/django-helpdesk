from django.contrib.auth import get_user_model, logout
from helpdesk.models import FollowUp, FollowUpAttachment, Ticket
from helpdesk.serializers import (
    FollowUpAttachmentSerializer,
    FollowUpSerializer,
    TicketSerializer,
    UserSerializer,
    PublicTicketListingSerializer,
)
from rest_framework import viewsets
from rest_framework.mixins import CreateModelMixin
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth.models import Permission
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


def _get_session_identifier(request):
    """
    Get a session identifier that works with both database and signed cookie sessions.
    """
    from django.conf import settings
    if settings.SESSION_ENGINE == 'django.contrib.sessions.backends.signed_cookies':
        # For signed cookies, use user ID + branch name as identifier
        branch_name = request.session.get('branch_name')
        return f"cookie_{request.user.id}_{branch_name}" if branch_name else f"cookie_{request.user.id}"
    else:
        # For database sessions, use the actual session key
        return request.session.session_key


class IsStaffUser(IsAuthenticated):
    """
    Allows access only to staff users (is_staff=True).
    Less restrictive than IsAdminUser which requires superuser.
    """
    def has_permission(self, request, view):
        return (
            super().has_permission(request, view) and
            request.user and
            request.user.is_staff
        )
from rest_framework.viewsets import GenericViewSet
from rest_framework.pagination import PageNumberPagination

from helpdesk import settings as helpdesk_settings


class ConservativePagination(PageNumberPagination):
    page_size = 25
    page_size_query_param = "page_size"


class UserTicketViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A list of all the tickets submitted by the current user

    The view is paginated by default
    """

    serializer_class = PublicTicketListingSerializer
    pagination_class = ConservativePagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        tickets = Ticket.objects.filter(
            submitter_email=self.request.user.email
        ).order_by("-created")
        for ticket in tickets:
            ticket.set_custom_field_values()
        return tickets


class TicketViewSet(viewsets.ModelViewSet):
    """
    A viewset that provides the standard actions to handle Ticket

    You can filter the tickets by status using the `status` query parameter. For example:

    `/api/tickets/?status=Open,Resolved` will return all the tickets that are Open or Resolved.
    """

    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    pagination_class = ConservativePagination
    permission_classes = [IsStaffUser]  # Less restrictive than IsAdminUser
    
    def dispatch(self, request, *args, **kwargs):
        """Add debug logging for permission issues."""
        import logging
        logger = logging.getLogger('helpdesk.api')
        
        logger.info(f"API Request: {request.method} {request.path}")
        logger.info(f"User: {request.user} (authenticated: {request.user.is_authenticated})")
        
        if request.user.is_authenticated:
            logger.info(f"User permissions: staff={request.user.is_staff}, admin={request.user.is_superuser}")
        
        # Log headers for debugging
        csrf_token = request.META.get('HTTP_X_CSRFTOKEN', 'Not provided')
        logger.info(f"CSRF Token: {csrf_token[:20] if csrf_token != 'Not provided' else csrf_token}")
        
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        tickets = Ticket.objects.all()

        # filter by status
        status = self.request.query_params.get("status", None)
        if status:
            statuses = status.split(",") if status else []
            status_choices = helpdesk_settings.TICKET_STATUS_CHOICES
            number_statuses = []
            for status in statuses:
                for choice in status_choices:
                    if str(choice[0]) == status:
                        number_statuses.append(choice[0])
            if number_statuses:
                tickets = tickets.filter(status__in=number_statuses)

        for ticket in tickets:
            ticket.set_custom_field_values()
        return tickets

    def get_object(self):
        ticket = super().get_object()
        ticket.set_custom_field_values()
        return ticket


class FollowUpViewSet(viewsets.ModelViewSet):
    queryset = FollowUp.objects.all()
    serializer_class = FollowUpSerializer
    pagination_class = ConservativePagination
    permission_classes = [IsStaffUser]  # Less restrictive than IsAdminUser

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class FollowUpAttachmentViewSet(viewsets.ModelViewSet):
    queryset = FollowUpAttachment.objects.all()
    serializer_class = FollowUpAttachmentSerializer
    pagination_class = ConservativePagination
    permission_classes = [IsStaffUser]  # Less restrictive than IsAdminUser


class CreateUserView(CreateModelMixin, GenericViewSet):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsStaffUser]  # Less restrictive than IsAdminUser


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def agent_session_info(request):
    """
    API endpoint to get session information for agent users.
    
    Returns the branch_name if the user is an agent and has one set in session.
    This is automatically created when an agent user starts a new session.
    Now optimized for session-based authentication only.
    """
    # Check if user is an agent
    try:
        is_agent = request.user.usersettings_helpdesk.is_agent
    except AttributeError:
        is_agent = False
    
    if not is_agent:
        return Response({
            'error': 'Not an agent user',
            'message': 'This endpoint is only available for agent users.'
        }, status=403)
    
    # Get session information
    branch_name = None
    session_key = None
    session_available = False
    
    if hasattr(request, 'session'):
        session_available = True
        session_key = _get_session_identifier(request)
        
        # The middleware should have already created the branch name
        # But if not, we can trigger it manually
        if 'branch_name' not in request.session:
            from helpdesk.middleware import AgentBranchNameMiddleware
            middleware = AgentBranchNameMiddleware(None)
            middleware.process_request(request)
        
        branch_name = request.session.get('branch_name')
    
    # Get intent from session
    intent = request.session.get('intent') if hasattr(request, 'session') else None
    
    return Response({
        'user_id': request.user.id,
        'username': request.user.username,
        'is_agent': is_agent,
        'branch_name': branch_name,
        'intent': intent,
        'session_key': session_key,
        'session_available': session_available,
        'authentication_method': 'session',
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_agent_intent(request):
    """
    API endpoint to set the intent session variable for agent users.
    
    Accepts:
    - intent: string (max 512 characters)
    
    Only available for agent users.
    """
    # Check if user is an agent
    try:
        is_agent = request.user.usersettings_helpdesk.is_agent
    except AttributeError:
        is_agent = False
    
    if not is_agent:
        return Response({
            'error': 'Not an agent user',
            'message': 'This endpoint is only available for agent users.'
        }, status=403)
    
    # Check if session is available
    if not hasattr(request, 'session'):
        return Response({
            'error': 'Session not available',
            'message': 'Session is required to set intent.'
        }, status=400)
    
    # Get intent from request data
    intent = request.data.get('intent')
    
    if intent is None:
        return Response({
            'error': 'Intent required',
            'message': 'The intent field is required.'
        }, status=400)
    
    # Validate intent is a string
    if not isinstance(intent, str):
        return Response({
            'error': 'Invalid intent type',
            'message': 'Intent must be a string.'
        }, status=400)
    
    # Validate intent length (max 512 characters)
    if len(intent) > 512:
        return Response({
            'error': 'Intent too long',
            'message': 'Intent must be 512 characters or less.'
        }, status=400)
    
    # Set intent in session
    request.session['intent'] = intent
    request.session.modified = True
    
    return Response({
        'success': True,
        'message': 'Intent set successfully',
        'intent': intent,
        'user_id': request.user.id,
        'username': request.user.username,
        'branch_name': request.session.get('branch_name'),
        'session_key': _get_session_identifier(request)
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def finish_agent_session(request):
    """
    API endpoint to manually finish an agent session.
    
    This will call the on_session_finished method to perform cleanup
    and then clear the session data.
    
    Only available for agent users.
    """
    # Check if user is an agent
    try:
        is_agent = request.user.usersettings_helpdesk.is_agent
    except AttributeError:
        is_agent = False
    
    if not is_agent:
        return Response({
            'error': 'Not an agent user',
            'message': 'This endpoint is only available for agent users.'
        }, status=403)
    
    # Check if session is available
    if not hasattr(request, 'session'):
        return Response({
            'error': 'Session not available',
            'message': 'No active session found.'
        }, status=400)
    
    # Get session data before clearing
    branch_name = request.session.get('branch_name')
    intent = request.session.get('intent')
    session_key = _get_session_identifier(request)
    
    # Call the session finished handler
    try:
        on_session_finished(request.user, session_key, branch_name, intent)
        
        # Clear session data
        if 'branch_name' in request.session:
            del request.session['branch_name']
        if 'intent' in request.session:
            del request.session['intent']
        request.session.modified = True
        
        # Prepare response data before logout
        response_data = {
            'success': True,
            'message': 'Session finished successfully',
            'user_id': request.user.id,
            'username': request.user.username,
            'session_key': session_key,
            'branch_name': branch_name,
            'intent': intent
        }
        
        # Log out the user
        logout(request)
        
        return Response(response_data)
        
    except Exception as e:
        return Response({
            'error': 'Session finish failed',
            'message': f'Error during session cleanup: {str(e)}'
        }, status=500)


def on_session_finished(user, session_key, branch_name=None, intent=None):
    """
    Handler called when an agent session is finished (manually or via timeout).
    
    This method performs cleanup operations when an agent session ends.
    
    Args:
        user: The User object
        session_key: The session key that was finished
        branch_name: The branch name that was used (if any)
        intent: The intent that was set (if any)
    """
    import logging
    logger = logging.getLogger('helpdesk.requests')
    
    try:
        # Check if user is an agent
        try:
            is_agent = user.usersettings_helpdesk.is_agent
        except AttributeError:
            is_agent = False
        
        if not is_agent:
            return  # Not an agent, nothing to do
        
        # Log session finish
        logger.info(
            f"Agent session finished for user '{user.username}'",
            extra={
                'method': 'SESSION_FINISH',
                'path': '/api/session-finish',
                'user': f"{user.username} (ID: {user.id})",
                'client_ip': 'session_timeout',
                'headers': {},
                'user_id': user.id,
                'username': user.username,
                'session_key': session_key,
                'branch_name': branch_name,
                'intent': intent,
                'operation': 'agent_session_finished'
            }
        )
        
        _call_finish_session_stored_proc(branch_name, intent)
        
        # For now, we'll just log the completion
        logger.info(
            f"Session cleanup completed for agent '{user.username}' with branch '{branch_name}'",
            extra={
                'method': 'SESSION_CLEANUP',
                'path': '/api/session-cleanup',
                'user': f"{user.username} (ID: {user.id})",
                'client_ip': 'session_timeout',
                'headers': {},
                'user_id': user.id,
                'username': user.username,
                'session_key': session_key,
                'branch_name': branch_name,
                'intent': intent,
                'operation': 'agent_session_cleanup_completed'
            }
        )
        
    except Exception as e:
        logger.error(
            f"Error during session cleanup for user '{user.username}': {e}",
            extra={
                'method': 'SESSION_CLEANUP_ERROR',
                'path': '/api/session-cleanup',
                'user': f"{user.username} (ID: {user.id})",
                'client_ip': 'session_timeout',
                'headers': {},
                'user_id': user.id,
                'username': user.username,
                'session_key': session_key,
                'branch_name': branch_name,
                'intent': intent,
                'error': str(e),
                'operation': 'agent_session_cleanup_failed'
            }
        )

def _call_finish_session_stored_proc(branch_name, intent):
    import logging
    from django.db import connection

    logger = logging.getLogger('helpdesk.requests')

    try:
        with connection.cursor() as cursor:
            sql = 'CALL FinishSession(%s, %s)'
            cursor.execute(sql, [branch_name, intent])

            logger.info(
                "Successfully finished session  for branch " + branch_name,
                extra={
                    'method': 'STORED_PROC',
                    'path': '/dolt/finish-session',
                    'user': 'System',
                    'client_ip': 'localhost',
                    'headers': {},
                    'branch_name': branch_name,
                    'intent': intent,
                    'operation': 'Call FinishSession stored procedure'
                }
            )

    except Exception as e:
        logger.error(
            f"Failed to create Dolt branch '{branch_name}': {e}",
            extra={
                'method': 'STORED_PROC_ERROR',
                'path': '/dolt/finish-session',
                'user': 'System',
                'client_ip': 'localhost',
                'headers': {},
                'branch_name': branch_name,
                'error': str(e),
                'operation': 'dolt_branch_creation_failed'
            }
        )

        raise e