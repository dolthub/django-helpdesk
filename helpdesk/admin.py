from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from helpdesk import settings as helpdesk_settings
from helpdesk.models import (
    Checklist,
    ChecklistTask,
    ChecklistTemplate,
    CustomField,
    EmailTemplate,
    EscalationExclusion,
    FollowUp,
    FollowUpAttachment,
    IgnoreEmail,
    KBIAttachment,
    PreSetReply,
    Queue,
    Ticket,
    TicketChange,
    UserSettings,
)


if helpdesk_settings.HELPDESK_KB_ENABLED:
    from helpdesk.models import KBCategory, KBItem


@admin.register(Queue)
class QueueAdmin(admin.ModelAdmin):
    list_display = ("title", "slug", "email_address", "locale", "time_spent")
    prepopulated_fields = {"slug": ("title",)}

    def time_spent(self, q):
        if q.dedicated_time:
            return "{} / {}".format(q.time_spent, q.dedicated_time)
        elif q.time_spent:
            return q.time_spent
        else:
            return "-"

    def delete_queryset(self, request, queryset):
        for queue in queryset:
            queue.delete()


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "status",
        "assigned_to",
        "queue",
        "hidden_submitter_email",
        "time_spent",
    )
    date_hierarchy = "created"
    list_filter = ("queue", "assigned_to", "status")
    search_fields = ("id", "title")

    @admin.display(description=_("Submitter E-Mail"))
    def hidden_submitter_email(self, ticket):
        if ticket.submitter_email:
            username, domain = ticket.submitter_email.split("@")
            username = username[:2] + "*" * (len(username) - 2)
            domain = domain[:1] + "*" * (len(domain) - 2) + domain[-1:]
            return "%s@%s" % (username, domain)
        else:
            return ticket.submitter_email

    def time_spent(self, ticket):
        return ticket.time_spent


class TicketChangeInline(admin.StackedInline):
    model = TicketChange
    extra = 0


class FollowUpAttachmentInline(admin.StackedInline):
    model = FollowUpAttachment
    extra = 0


class KBIAttachmentInline(admin.StackedInline):
    model = KBIAttachment
    extra = 0


@admin.register(FollowUp)
class FollowUpAdmin(admin.ModelAdmin):
    inlines = [TicketChangeInline, FollowUpAttachmentInline]
    list_display = (
        "ticket_get_ticket_for_url",
        "title",
        "date",
        "ticket",
        "user",
        "new_status",
        "time_spent",
    )
    list_filter = ("user", "date", "new_status")

    @admin.display(description=_("Slug"))
    def ticket_get_ticket_for_url(self, obj):
        return obj.ticket.ticket_for_url


if helpdesk_settings.HELPDESK_KB_ENABLED:

    @admin.register(KBItem)
    class KBItemAdmin(admin.ModelAdmin):
        list_display = ("category", "title", "last_updated", "team", "order", "enabled")
        inlines = [KBIAttachmentInline]
        readonly_fields = ("voted_by", "downvoted_by")

        list_display_links = ("title",)

    if helpdesk_settings.HELPDESK_KB_ENABLED:

        @admin.register(KBCategory)
        class KBCategoryAdmin(admin.ModelAdmin):
            list_display = ("name", "title", "slug", "public")


@admin.register(CustomField)
class CustomFieldAdmin(admin.ModelAdmin):
    list_display = ("name", "label", "data_type")


@admin.register(EmailTemplate)
class EmailTemplateAdmin(admin.ModelAdmin):
    list_display = ("template_name", "heading", "locale")
    list_filter = ("locale",)


@admin.register(IgnoreEmail)
class IgnoreEmailAdmin(admin.ModelAdmin):
    list_display = ("name", "queue_list", "email_address", "keep_in_mailbox")


@admin.register(ChecklistTemplate)
class ChecklistTemplateAdmin(admin.ModelAdmin):
    list_display = ("name", "task_list")
    search_fields = ("name", "task_list")


class ChecklistTaskInline(admin.TabularInline):
    model = ChecklistTask


@admin.register(Checklist)
class ChecklistAdmin(admin.ModelAdmin):
    list_display = ("name", "ticket")
    search_fields = ("name", "ticket__id", "ticket__title")
    autocomplete_fields = ("ticket",)
    list_select_related = ("ticket",)
    inlines = (ChecklistTaskInline,)


admin.site.register(PreSetReply)
admin.site.register(EscalationExclusion)


class UserSettingsInline(admin.StackedInline):
    model = UserSettings
    can_delete = False
    verbose_name_plural = _("Helpdesk Settings")
    fields = (
        'login_view_ticketlist',
        'email_on_ticket_change', 
        'email_on_ticket_assign',
        'tickets_per_page',
        'use_email_as_submitter',
        'is_agent',
    )


class HelpdeskUserAdmin(UserAdmin):
    inlines = (UserSettingsInline,)


# Unregister the default User admin and register our custom one
User = get_user_model()
admin.site.unregister(User)
admin.site.register(User, HelpdeskUserAdmin)
