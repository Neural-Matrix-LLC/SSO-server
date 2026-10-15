"""Step-up re-authentication for destructive admin actions (DESIGN-v1.3a §3.3).

``POST /api/v1/admin/reauth`` issues a random token (only its SHA-256 is stored) bound to the user, the access
token's ``sid`` and the client IP, valid ``SSO_ADMIN_REAUTH_SECONDS``. Destructive endpoints call
``require_stepup()`` which checks ``X-SSO-Reauth``.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .errors import ReauthRequired
from .logs import client_ip
from .models import AdminReauth

HEADER = "X-SSO-Reauth"


def _sid(request) -> str:
    token = getattr(request, "auth", None)
    try:
        return str(token.get("sid") or "") if token is not None else ""
    except AttributeError:
        return ""


def issue(request) -> tuple[str, int]:
    raw = secrets.token_urlsafe(32)
    ttl = int(settings.SSO_ADMIN_REAUTH_SECONDS)
    AdminReauth.objects.create(token_hash=AdminReauth.hash_token(raw), user=request.user, sid=_sid(request),
                               ip=client_ip(request) or "", expires_at=timezone.now() + timedelta(seconds=ttl))
    return raw, ttl


def is_valid(request) -> bool:
    raw = request.headers.get(HEADER, "")
    if not raw or len(raw) > 128:
        return False
    row = AdminReauth.objects.filter(token_hash=AdminReauth.hash_token(raw)).first()
    if row is None or row.expires_at <= timezone.now():
        return False
    return (row.user_id == request.user.pk and row.sid == _sid(request)
            and row.ip == (client_ip(request) or ""))


def require_stepup(request) -> None:
    if not is_valid(request):
        raise ReauthRequired()


def prune_expired() -> int:
    return AdminReauth.objects.filter(expires_at__lte=timezone.now()).delete()[0]
