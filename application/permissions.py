"""Helpers for ``application.*`` permissions: create, sync after migrate, and the per-user list."""
from __future__ import annotations

import logging
import re

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from .models import CODENAME_RE, ApplicationAccess, ApplicationPermissionRecord

logger = logging.getLogger("sso.application")
PREFIX = "application."


def anchor_content_type(using: str = "default") -> ContentType:
    return ContentType.objects.db_manager(using).get_for_model(ApplicationAccess, for_concrete_model=True)


def validate_codename(codename: str) -> str:
    if not re.fullmatch(CODENAME_RE, codename or ""):
        raise ValueError(f"invalid codename {codename!r}: must match {CODENAME_RE}")
    return codename


def ensure_permission(codename: str, name: str, using: str = "default") -> tuple[Permission, bool]:
    """Create (or keep) ``application.<codename>`` and record it. Idempotent. Returns (permission, created)."""
    validate_codename(codename)
    with transaction.atomic(using=using):
        ct = anchor_content_type(using)
        perm, created = Permission.objects.db_manager(using).get_or_create(
            content_type=ct, codename=codename, defaults={"name": name[:255]})
        if not created and name and perm.name != name[:255]:
            perm.name = name[:255]
            perm.save(update_fields=["name"])
        rec, _ = ApplicationPermissionRecord.objects.db_manager(using).get_or_create(
            codename=codename, defaults={"name": perm.name, "permission_id": perm.pk})
        if rec.permission_id != perm.pk or rec.name != perm.name:
            rec.permission_id, rec.name = perm.pk, perm.name
            rec.save(update_fields=["permission_id", "name"])
    return perm, created


def sync_permissions(using: str = "default") -> list[str]:
    """Recreate missing ``application.*`` permissions from the model Meta and the SSO-side registry.

    Returns the codenames whose permission row had to be (re)created after it was known before, i.e. whose
    grants were lost. Each one is logged as an error.
    """
    wanted = {code: name for code, name in ApplicationAccess._meta.permissions}
    records = {r.codename: r for r in ApplicationPermissionRecord.objects.using(using).all()}
    for code, rec in records.items():
        wanted.setdefault(code, rec.name)
    lost = []
    ct = anchor_content_type(using)
    for code, name in sorted(wanted.items()):
        before = records.get(code)
        perm, created = ensure_permission(code, name, using=using)
        if before is not None and before.permission_id is not None and before.permission_id != perm.pk:
            lost.append(code)
    if lost:
        logger.error(
            "application permissions %s were deleted and have been recreated (content type id %s). ALL GRANTS OF "
            "THESE PERMISSIONS WERE LOST and must be re-assigned. Likely cause: remove_stale_contenttypes run in "
            "myFinance on the shared dcWebUsers database (README 'Application permissions').",
            ", ".join(PREFIX + c for c in lost), ct.pk)
    return lost


def sync_after_migrate(sender, using="default", **kwargs) -> None:
    """post_migrate receiver: runs after Django has created the content type and the Meta permissions."""
    sync_permissions(using=using)


def user_app_perms(user) -> list[str]:
    """Sorted ``application.*`` permissions of a user (direct + groups; superuser = all; inactive = none)."""
    if user is None or not getattr(user, "is_active", False):
        return []
    return sorted(p for p in user.get_all_permissions() if p.startswith(PREFIX))
