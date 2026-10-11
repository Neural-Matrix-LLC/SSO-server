"""Read-only admin listing of the application.* permissions (design A1).

Grants are assigned with the stock User / Group admin ("user permissions" / "group permissions").
"""
from django.contrib import admin

from .models import ApplicationPermission, ApplicationPermissionRecord


@admin.register(ApplicationPermission)
class ApplicationPermissionAdmin(admin.ModelAdmin):
    list_display = ["codename", "name", "users_with_direct_grant", "groups_with_grant"]
    search_fields = ["codename", "name"]
    ordering = ["codename"]

    def get_queryset(self, request):
        return super().get_queryset(request).filter(content_type__app_label="application",
                                                    content_type__model="applicationaccess")

    @admin.display(description="users (direct)")
    def users_with_direct_grant(self, obj):
        return obj.user_set.count()

    @admin.display(description="groups")
    def groups_with_grant(self, obj):
        return obj.group_set.count()

    def has_add_permission(self, request):
        return False  # use: manage.py create_app_permission

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ApplicationPermissionRecord)
class ApplicationPermissionRecordAdmin(admin.ModelAdmin):
    list_display = ["codename", "name", "permission_id", "created"]
    readonly_fields = list_display

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
