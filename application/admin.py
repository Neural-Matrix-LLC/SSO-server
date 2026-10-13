"""Admin for the application.* (service) permissions (design A1, v1.2a §5).

* Add / rename go through ``ensure_permission`` (anchor content type + registry record), like the
  ``create_app_permission`` command. The codename cannot be changed after creation.
* Delete (one at a time, with a confirmation page listing the affected users and groups) removes the
  permission, its grants and its registry record. Code-defined permissions (``app1``) cannot be deleted:
  ``migrate`` would recreate them, without their grants.
* Grants are assigned with the User / Group admin actions "Grant app access" / "Revoke app access" (sso admin)
  or the stock "user permissions" / "group permissions" fields.
"""
import json
import logging

from django import forms
from django.contrib import admin
from django.core.exceptions import ValidationError

from .models import CODENAME_RE, ApplicationPermission, ApplicationPermissionRecord
from .permissions import (
    PREFIX,
    anchor_content_type,
    code_defined_codenames,
    delete_permission,
    ensure_permission,
    users_with_access,
    validate_codename,
)

audit = logging.getLogger("sso.admin")


def audit_log(request, event: str, **fields) -> None:
    audit.info(json.dumps({"event": event, "admin": request.user.get_username(), **fields}, sort_keys=True))


class ApplicationPermissionForm(forms.ModelForm):
    codename = forms.RegexField(regex=CODENAME_RE, max_length=63,
                                help_text="Lower case, e.g. app2. Becomes the permission application.<codename>.")

    class Meta:
        model = ApplicationPermission
        fields = ["codename", "name"]

    def clean_codename(self):
        code = self.cleaned_data["codename"]
        if self.instance.pk is None:
            try:
                validate_codename(code)
            except ValueError as exc:  # pragma: no cover - RegexField already enforces the rule
                raise ValidationError(str(exc)) from None
            if ApplicationPermission.objects.filter(content_type=anchor_content_type(), codename=code).exists():
                raise ValidationError(f"{PREFIX}{code} already exists.")
        return code


@admin.register(ApplicationPermission)
class ApplicationPermissionAdmin(admin.ModelAdmin):
    form = ApplicationPermissionForm
    list_display = ["codename", "name", "users_with_direct_grant", "groups_with_grant", "active_users_with_access"]
    search_fields = ["codename", "name"]
    ordering = ["codename"]
    actions = None  # no bulk delete: one at a time, with the affected users and groups listed

    def get_queryset(self, request):
        return super().get_queryset(request).filter(content_type__app_label="application",
                                                    content_type__model="applicationaccess")

    def get_readonly_fields(self, request, obj=None):
        return ["codename"] if obj is not None else []

    @admin.display(description="users (direct)")
    def users_with_direct_grant(self, obj):
        return obj.user_set.count()

    @admin.display(description="groups")
    def groups_with_grant(self, obj):
        return obj.group_set.count()

    @admin.display(description="active users with access")
    def active_users_with_access(self, obj):
        return users_with_access(obj).count()

    def save_model(self, request, obj, form, change):
        perm, created = ensure_permission(obj.codename, form.cleaned_data["name"])
        obj.pk, obj.content_type_id, obj.name = perm.pk, perm.content_type_id, perm.name
        obj._state.adding = False
        audit_log(request, "app_permission.created" if created else "app_permission.renamed",
                  permission=PREFIX + perm.codename)

    def has_delete_permission(self, request, obj=None):
        if obj is not None and obj.codename in code_defined_codenames():
            return False
        return super().has_delete_permission(request, obj)

    def delete_model(self, request, obj):
        audit_log(request, "app_permission.deleted", permission=PREFIX + obj.codename,
                  users=obj.user_set.count(), groups=obj.group_set.count())
        delete_permission(obj)

    def render_delete_form(self, request, context):
        obj = context.get("object")
        if obj is not None:
            context["affected_users"] = list(obj.user_set.order_by("username").values_list("username", flat=True))
            context["affected_groups"] = list(obj.group_set.order_by("name").values_list("name", flat=True))
            context["affected_via_groups"] = users_with_access(obj).count()
        return super().render_delete_form(request, context)


@admin.register(ApplicationPermissionRecord)
class ApplicationPermissionRecordAdmin(admin.ModelAdmin):
    list_display = ["codename", "name", "permission_id", "created"]
    readonly_fields = list_display

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
