"""Bulk import of an application's permissions from its ``sso_permissions.py`` (DESIGN-v1.3a §5).

Never deletes: permissions of the app that the payload no longer lists are marked deprecated
(``ApplicationPermissionRecord.deprecated_at``) and keep working.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from django.contrib.auth.models import Permission
from django.db import transaction
from django.utils import timezone

from .models import CODENAME_RE, Application, ApplicationPermissionRecord
from .permissions import anchor_content_type, ensure_permission

APP_CODENAME_RE = r"^[a-z][a-z0-9_]{1,40}$"


class ImportError_(ValueError):
    """Payload is invalid (400)."""


class VersionTooOld(Exception):
    def __init__(self, stored: int, given: int):
        super().__init__(f"stored version {stored} is newer than {given}")
        self.stored, self.given = stored, given


@dataclass
class ImportResult:
    app: str
    version: int
    dry_run: bool
    created: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    deprecated: list = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.created or self.updated or self.deprecated)

    def as_dict(self) -> dict:
        return {"app": self.app, "version": self.version, "dry_run": self.dry_run, "created": self.created,
                "updated": self.updated, "unchanged": self.unchanged, "missing": self.missing,
                "deprecated": self.deprecated}


def validate_payload(app: str, data) -> tuple[str, str, int, list[tuple[str, str, str]]]:
    if not re.fullmatch(APP_CODENAME_RE, app or ""):
        raise ImportError_(f"app codename must match {APP_CODENAME_RE}")
    if not isinstance(data, dict):
        raise ImportError_("body must be a JSON object")
    if "app_codename" in data and data["app_codename"] != app:
        raise ImportError_(f"app_codename {data['app_codename']!r} does not match the URL ({app!r})")
    app_name = data.get("app_name")
    if not isinstance(app_name, str) or not app_name.strip() or len(app_name) > 200:
        raise ImportError_("app_name: required string, max 200 characters")
    description = data.get("description", "") or ""
    if not isinstance(description, str) or len(description) > 1000:
        raise ImportError_("description: string, max 1000 characters")
    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ImportError_("version: required integer >= 1")
    perms = data.get("permissions")
    if not isinstance(perms, list) or len(perms) > 500:
        raise ImportError_("permissions: required list (max 500)")
    seen, out = set(), []
    for i, p in enumerate(perms):
        if not isinstance(p, dict):
            raise ImportError_(f"permissions[{i}]: must be an object")
        code, name, desc = p.get("codename"), p.get("name"), p.get("description", "") or ""
        if not isinstance(code, str) or not re.fullmatch(CODENAME_RE, code):
            raise ImportError_(f"permissions[{i}].codename: must match {CODENAME_RE}")
        if not code.startswith(app + "_"):
            raise ImportError_(f"permissions[{i}].codename {code!r} must start with {app + '_'!r}")
        if code in seen:
            raise ImportError_(f"permissions[{i}].codename {code!r} is listed twice")
        if not isinstance(name, str) or not name.strip() or len(name) > 255:
            raise ImportError_(f"permissions[{i}].name: required string, max 255 characters")
        if not isinstance(desc, str) or len(desc) > 1000:
            raise ImportError_(f"permissions[{i}].description: string, max 1000 characters")
        seen.add(code)
        out.append((code, name.strip(), desc))
    return app_name.strip(), description, version, out


def import_permissions(app: str, data, *, dry_run: bool = False, force: bool = False) -> ImportResult:
    """Validate and apply (or preview) an import. Raises ImportError_ / VersionTooOld. One transaction."""
    app_name, app_desc, version, listed = validate_payload(app, data)
    result = ImportResult(app=app, version=version, dry_run=dry_run)
    with transaction.atomic():
        existing_app = Application.objects.select_for_update().filter(app_codename=app).first()
        if existing_app and version < existing_app.version and not force:
            raise VersionTooOld(existing_app.version, version)
        ct = anchor_content_type()
        perms = {p.codename: p for p in Permission.objects.filter(content_type=ct)}
        records = {r.codename: r for r in ApplicationPermissionRecord.objects.filter(
            codename__in=[c for c, _, _ in listed] + [app])}
        own = {r.codename: r for r in ApplicationPermissionRecord.objects.filter(app_codename=app)}
        # the implicit app-access permission application.<app> is ensured, never reported as missing
        entries = [(app, f"Can use {app_name}", app_desc)] + listed
        now = timezone.now()
        for code, name, desc in entries:
            perm, rec = perms.get(code), records.get(code) or own.get(code)
            if perm is None:
                result.created.append(code)
                if not dry_run:
                    ensure_permission(code, name)
                    ApplicationPermissionRecord.objects.filter(codename=code).update(
                        description=desc, app_codename=app, deprecated_at=None)
                continue
            changed = (perm.name != name[:255] or rec is None or rec.description != desc
                       or rec.app_codename != app or rec.deprecated_at is not None)
            if changed:
                result.updated.append(code)
                if not dry_run:
                    ensure_permission(code, name)
                    ApplicationPermissionRecord.objects.filter(codename=code).update(
                        description=desc, app_codename=app, deprecated_at=None)
            else:
                result.unchanged.append(code)
        listed_codes = {c for c, _, _ in entries}
        for code, rec in sorted(own.items()):
            if code in listed_codes:
                continue
            result.missing.append(code)
            if rec.deprecated_at is None:
                result.deprecated.append(code)
                if not dry_run:
                    ApplicationPermissionRecord.objects.filter(pk=rec.pk).update(deprecated_at=now)
        if not dry_run:
            Application.objects.update_or_create(
                app_codename=app, defaults={"name": app_name, "description": app_desc, "version": version})
    return result
