"""Helpers for ``application.*`` permissions: create, sync after migrate, and the per-user list."""
from __future__ import annotations

import logging
import re

from django.conf import settings
from django.contrib.auth.models import Permission
from django.db.models import Q
from django.contrib.contenttypes.models import ContentType
from django.db import connections, transaction

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
    """After migrate: recreate the code-defined permissions (``ApplicationAccess.Meta.permissions``,
    i.e. app1) and report every ``application.*`` permission that was lost (design v1.1 item 8).

    Command-created permissions (``create_app_permission``) are NOT recreated: they are reported, and their
    registry record is dropped so the report appears once; re-run ``create_app_permission`` to restore one.
    Returns the codenames whose permission row had been deleted (their grants are gone). Logged as ERROR.
    """
    code_defined = {code: name for code, name in ApplicationAccess._meta.permissions}
    records = {r.codename: r for r in ApplicationPermissionRecord.objects.using(using).all()}
    ct = anchor_content_type(using)
    lost, not_recreated = [], []
    for code, name in sorted(code_defined.items()):
        before = records.get(code)
        perm, _ = ensure_permission(code, name, using=using)
        if before is not None and before.permission_id is not None and before.permission_id != perm.pk:
            lost.append(code)
    existing = set(Permission.objects.db_manager(using).filter(content_type=ct).values_list("codename", flat=True))
    for code, rec in sorted(records.items()):
        if code in code_defined or code in existing:
            continue
        lost.append(code)
        not_recreated.append(code)
        rec.delete()
    if lost:
        logger.error(
            "application permissions %s were deleted (content type id %s now). ALL GRANTS OF THESE PERMISSIONS "
            "WERE LOST and must be re-assigned. Recreated: %s. Not recreated (command-created; run "
            "manage.py create_app_permission again if still wanted): %s. Likely cause: "
            "remove_stale_contenttypes run in myFinance on the shared dcWebUsers database "
            "(README 'Application permissions').",
            ", ".join(PREFIX + c for c in lost), ct.pk,
            ", ".join(PREFIX + c for c in lost if c not in not_recreated) or "-",
            ", ".join(PREFIX + c for c in not_recreated) or "-")
    return lost


def _required_tables() -> set[str]:
    """Tables sync_permissions reads or writes: our own two, plus auth_permission and django_content_type."""
    return {ApplicationPermissionRecord._meta.db_table, ApplicationAccess._meta.db_table,
            Permission._meta.db_table, ContentType._meta.db_table}


def sync_after_migrate(sender, using="default", **kwargs) -> None:
    """post_migrate receiver: runs after Django has created the content type and the Meta permissions.

    Django sends post_migrate for every installed app after *any* migrate run, including
    ``migrate contenttypes`` on an empty database (README §7 dev sequence), before our tables exist.
    Skip quietly until they do; the run that creates them (a full ``migrate``) syncs.
    """
    with connections[using].cursor() as cursor:
        present = set(connections[using].introspection.table_names(cursor))
    missing = sorted(_required_tables() - present)
    if missing:
        logger.debug("application permission sync skipped on %r: tables not created yet: %s",
                     using, ", ".join(missing))
        return
    sync_permissions(using=using)


def user_app_perms(user) -> list[str]:
    """Sorted ``application.*`` permissions of a user, from real permission rows: the user's own
    ``user_permissions`` plus those of their groups, filtered to the ``application`` app. Inactive
    users (and None) get none.

    Superusers are for administering users, not for app access (decision relayed 2026-10-11): by
    default a superuser gets exactly their explicit grants like everybody else. Django's
    ``get_all_permissions()`` / ``has_perm()`` are deliberately not used, since both return
    everything for a superuser. ``SSO_SUPERUSER_ALL_APPS=true`` (opt-in, default false) restores
    the old rule: an active superuser gets every ``application.*`` permission.
    """
    if user is None or not getattr(user, "is_active", False):
        return []
    perms = Permission.objects.filter(content_type__app_label="application")
    if not (user.is_superuser and getattr(settings, "SSO_SUPERUSER_ALL_APPS", False)):
        perms = perms.filter(Q(user=user) | Q(group__user=user))
    return sorted({PREFIX + c for c in perms.values_list("codename", flat=True)})
