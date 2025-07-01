from django.contrib.auth import get_user_model
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
from django.contrib.auth.models import Permission
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


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
