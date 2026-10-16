"""Admin: ServiceClient (service registry, v1.2a §3/§5), revocation markers, and User / Group admin actions.

User / Group admin are the stock ones plus actions (design §5, v1.2a):
* Users: "Suspend" / "Unsuspend" (``save()`` per user, so the suspend signal revokes all tokens),
  "Grant app access…" / "Revoke app access…" (intermediate page to pick an ``application.*`` permission).
* Groups: "Grant app access…" / "Revoke app access…".
Every action writes a Django ``LogEntry`` and an ``sso.admin`` JSON log line.
"""
from __future__ import annotations

import django
from django import forms
from django.contrib import admin, messages
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.html import format_html

from application.admin import audit_log
from application.permissions import PREFIX, app_permissions, users_with_access

from .models import AdminAuditLog, RevokedSession, ServiceClient, UserTokenRevocation


# --------------------------------------------------------------------------- ServiceClient
class HttpsURLFormField(forms.URLField):
    """URLField that refuses schemeless input instead of guessing one (Django 4.2 assumes http, 5.x
    assume_scheme): the same rule as the model / ``register_service`` (``URLValidator(schemes=["https"])``)."""

    def to_python(self, value):
        value = (value or "").strip()
        if value and "://" not in value:
            raise ValidationError("Enter a full URL including the scheme, e.g. https://example.com/hook.",
                                  code="invalid")
        return super().to_python(value)


class ServiceClientForm(forms.ModelForm):
    notify_url = HttpsURLFormField(
        required=False, max_length=500, label="Notify URL",
        help_text="HTTPS webhook endpoint (v1.4; stored only, nothing is sent yet).",
        **({"assume_scheme": "https"} if django.VERSION >= (5, 0) else {}))
    regenerate_secret = forms.BooleanField(
        required=False,
        help_text="Generate a new client secret. It is shown ONCE after saving; only its hash is stored.",
    )

    class Meta:
        model = ServiceClient
        fields = ["client_id", "name", "is_active", "app_codename", "notify_url", "allowed_origins", "redirect_uris"]

    def clean_app_codename(self):
        code = (self.cleaned_data.get("app_codename") or "").strip()
        if code.startswith(PREFIX):
            code = code[len(PREFIX):]
        if code and not app_permissions().filter(codename=code).exists():
            raise ValidationError(f"{PREFIX}{code} does not exist; create it under Application permissions first.")
        return code or None

    def clean_notify_url(self):
        return self.cleaned_data.get("notify_url") or None


@admin.register(ServiceClient)
class ServiceClientAdmin(admin.ModelAdmin):
    form = ServiceClientForm
    list_display = ["client_id", "name", "is_active", "app_permission", "users_with_access", "created"]
    list_filter = ["is_active"]
    search_fields = ["client_id", "name", "app_codename"]
    readonly_fields = ["created", "users_with_access"]

    def _perm(self, obj):
        return app_permissions().filter(codename=obj.app_codename).first() if obj.app_codename else None

    @admin.display(description="app permission")
    def app_permission(self, obj):
        perm = self._perm(obj)
        if perm is None:
            return obj.app_codename and f"{PREFIX}{obj.app_codename} (missing)" or "-"
        url = reverse("admin:application_applicationpermission_change", args=[perm.pk])
        return format_html('<a href="{}">{}{}</a>', url, PREFIX, perm.codename)

    @admin.display(description="users with access")
    def users_with_access(self, obj):
        perm = self._perm(obj) if obj and obj.pk else None
        return users_with_access(perm).count() if perm else "-"

    def save_model(self, request, obj, form, change):
        if not change or form.cleaned_data.get("regenerate_secret"):
            secret = ServiceClient.generate_secret()
            obj.set_secret(secret)
            if change:  # v1.3a: service tokens issued before the rotation become inactive
                from django.utils import timezone

                obj.secret_rotated_at = timezone.now()
            messages.warning(
                request,
                f"Client secret for '{obj.client_id}': {secret} -- copy it now, it will not be shown again.",
            )
            audit_log(request, "service_client.secret_issued", client_id=obj.client_id)
        super().save_model(request, obj, form, change)


@admin.register(AdminAuditLog)
class AdminAuditLogAdmin(admin.ModelAdmin):
    """v1.3a audit trail: read-only."""

    list_display = ["ts", "actor_type", "actor_id", "action", "target_type", "target_id", "result", "stepup"]
    list_filter = ["action", "result", "actor_type"]
    search_fields = ["actor_id", "target_id", "request_id"]

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in AdminAuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(UserTokenRevocation)
class UserTokenRevocationAdmin(admin.ModelAdmin):
    list_display = ["user", "revoked_at"]
    search_fields = ["user__username", "user__email"]
    raw_id_fields = ["user"]


@admin.register(RevokedSession)
class RevokedSessionAdmin(admin.ModelAdmin):
    list_display = ["user", "reason", "revoked_at"]
    list_filter = ["reason"]
    search_fields = ["user__username", "user__email"]
    readonly_fields = ["sid", "user", "reason", "revoked_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# --------------------------------------------------------------------------- app access actions
class AppAccessForm(forms.Form):
    permission = forms.ModelChoiceField(queryset=app_permissions(), label="Application permission")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["permission"].queryset = app_permissions()  # fresh each request
        self.fields["permission"].label_from_instance = lambda p: f"{PREFIX}{p.codename} ({p.name})"


def _app_access_action(modeladmin, request, queryset, *, grant: bool, kind: str):
    """Intermediate page: choose the permission, then grant or revoke it on every selected user/group."""
    if "apply" in request.POST:
        form = AppAccessForm(request.POST)
        if form.is_valid():
            perm = form.cleaned_data["permission"]
            name = PREFIX + perm.codename
            for obj in queryset:
                rel = obj.user_permissions if kind == "user" else obj.permissions
                (rel.add if grant else rel.remove)(perm)
                modeladmin.log_change(request, obj, f"{'Granted' if grant else 'Revoked'} {name}")
            audit_log(request, "app_access.granted" if grant else "app_access.revoked", permission=name,
                      **{f"{kind}_ids": sorted(o.pk for o in queryset)})
            modeladmin.message_user(
                request, f"{'Granted' if grant else 'Revoked'} {name} {'to' if grant else 'from'} "
                         f"{queryset.count()} {kind}(s). Services that query the SSO see it at once; "
                         f"perms in existing access tokens update on the next refresh (≤ 15 min).",
                messages.SUCCESS)
            return None
    else:
        form = AppAccessForm()
    return TemplateResponse(request, "admin/sso/app_access_action.html", {
        **modeladmin.admin_site.each_context(request),
        "title": f"{'Grant' if grant else 'Revoke'} app access",
        "objects": queryset, "form": form, "action": request.POST.get("action"), "grant": grant, "kind": kind,
        "opts": modeladmin.model._meta, "action_checkbox_name": admin.helpers.ACTION_CHECKBOX_NAME,
    })


def _suspend(modeladmin, request, queryset, *, active: bool):
    changed = 0
    for user in queryset:
        if user.pk == request.user.pk and not active:
            modeladmin.message_user(request, "You cannot suspend yourself.", messages.ERROR)
            continue
        if user.is_active == active:
            continue
        user.is_active = active
        user.save(update_fields=["is_active"])  # fires the suspend signal: all tokens revoked
        modeladmin.log_change(request, user, "Unsuspended" if active else "Suspended (all tokens revoked)")
        changed += 1
    audit_log(request, "user.unsuspend_action" if active else "user.suspend_action", count=changed)
    modeladmin.message_user(
        request, f"{'Unsuspended' if active else 'Suspended'} {changed} user(s)"
                 + ("" if active else "; all their tokens are revoked."), messages.SUCCESS)


class SSOUserAdmin(UserAdmin):
    actions = ["suspend_users", "unsuspend_users", "grant_app_access", "revoke_app_access"]

    def get_form(self, request, obj=None, **kwargs):
        """V12A-01: an admin cannot untick is_active on their OWN change form (the Suspend action has the
        same guard in ``_suspend``). The error lands on is_active and nothing is saved."""
        form = super().get_form(request, obj, **kwargs)
        if obj is None or obj.pk != request.user.pk or "is_active" not in form.base_fields:
            return form

        class SelfGuardForm(form):
            def clean_is_active(self):
                active = self.cleaned_data.get("is_active")
                if not active:
                    raise ValidationError("You cannot suspend yourself.", code="self_suspend")
                return active

        return SelfGuardForm

    def get_changelist_formset(self, request, **kwargs):
        """V12A-01: same guard if is_active is ever made list_editable."""
        formset = super().get_changelist_formset(request, **kwargs)

        class SelfGuardFormSet(formset):
            def clean(self):
                super().clean()
                for f in self.forms:
                    if (f.instance.pk == request.user.pk and "is_active" in f.cleaned_data
                            and not f.cleaned_data["is_active"]):
                        f.add_error("is_active", ValidationError("You cannot suspend yourself.",
                                                                 code="self_suspend"))

        return SelfGuardFormSet

    @admin.action(description="Suspend selected users (revokes all their tokens)", permissions=["change"])
    def suspend_users(self, request, queryset):
        _suspend(self, request, queryset, active=False)

    @admin.action(description="Unsuspend selected users", permissions=["change"])
    def unsuspend_users(self, request, queryset):
        _suspend(self, request, queryset, active=True)

    @admin.action(description="Grant app access…", permissions=["change"])
    def grant_app_access(self, request, queryset):
        return _app_access_action(self, request, queryset, grant=True, kind="user")

    @admin.action(description="Revoke app access…", permissions=["change"])
    def revoke_app_access(self, request, queryset):
        return _app_access_action(self, request, queryset, grant=False, kind="user")


class SSOGroupAdmin(GroupAdmin):
    actions = ["grant_app_access", "revoke_app_access"]

    @admin.action(description="Grant app access…", permissions=["change"])
    def grant_app_access(self, request, queryset):
        return _app_access_action(self, request, queryset, grant=True, kind="group")

    @admin.action(description="Revoke app access…", permissions=["change"])
    def revoke_app_access(self, request, queryset):
        return _app_access_action(self, request, queryset, grant=False, kind="group")


for _model, _admin in ((User, SSOUserAdmin), (Group, SSOGroupAdmin)):
    if admin.site.is_registered(_model):
        admin.site.unregister(_model)
    admin.site.register(_model, _admin)
