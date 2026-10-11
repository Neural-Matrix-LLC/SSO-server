"""Permission anchor for central application access (design A1).

Every application that uses the SSO gets one permission on the ``application.applicationaccess`` content
type, e.g. ``application.app1`` for llm-wiki-svc. Grant it to users or groups with the stock admin.

WARNING: ``django_content_type`` and ``auth_permission`` are shared with myFinance. Running
``remove_stale_contenttypes`` in myFinance deletes this content type and CASCADE-deletes every grant.
See README "Application permissions".
"""
from __future__ import annotations

from django.contrib.auth.models import Permission
from django.db import models

#: codename rule for create_app_permission (design A1)
CODENAME_RE = r"^[a-z][a-z0-9_]{1,62}$"


class ApplicationAccess(models.Model):
    """Never holds rows: it exists so its content type can carry ``application.*`` permissions."""

    class Meta:
        managed = True
        default_permissions = ()
        permissions = [("app1", "Can use app1 (llm-wiki-svc)")]
        verbose_name = "application access"
        db_table = "sso_application_access"  # SSO-owned tables share the sso_ prefix in dcWebUsers


class ApplicationPermissionRecord(models.Model):
    """SSO-side registry of every ``application.*`` permission (design A3).

    Lives in an SSO-owned table, so it survives a ``remove_stale_contenttypes`` run in myFinance. After
    each ``migrate``, missing permissions are recreated from it. ``permission_id`` is a plain integer (no
    foreign key, so it is not cascade-deleted); a mismatch means the permission row was deleted and
    recreated, i.e. the grants were lost, and is logged loudly.
    """

    codename = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=255)
    permission_id = models.BigIntegerField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        default_permissions = ()
        verbose_name = "application permission record"
        db_table = "sso_application_permission_record"
        ordering = ["codename"]

    def __str__(self) -> str:
        return f"application.{self.codename}"


class ApplicationPermission(Permission):
    """Proxy over auth.Permission for the filtered, read-only admin list (no table of its own)."""

    class Meta:
        proxy = True
        default_permissions = ()
        verbose_name = "application permission"
