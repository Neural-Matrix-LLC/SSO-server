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
# v1.3d admin web UI: the request carries this attribute (set by adminui middleware) = the per-login UI session id.
# The proof is then an AdminReauth row bound to user + "ui:<id>" + IP; the UI never sees a reauth token.
UI_ATTR = "sso_adminui_sid"
UI_SID_PREFIX = "ui:"


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


def _ui_sid(request) -> str | None:
    django_request = getattr(request, "_request", request)
    value = getattr(django_request, UI_ATTR, None)
    return UI_SID_PREFIX + value if value else None


def issue_for_session(request) -> int:
    """UI step-up: store a proof bound to the admin, this UI login and this IP. Returns the window (s)."""
    ui = _ui_sid(request)
    if not ui:  # pragma: no cover - only called from adminui views
        raise ReauthRequired()
    ttl = int(settings.SSO_ADMIN_REAUTH_SECONDS)
    AdminReauth.objects.create(token_hash=AdminReauth.hash_token(secrets.token_urlsafe(32)), user=request.user,
                               sid=ui, ip=client_ip(request) or "", expires_at=timezone.now() + timedelta(seconds=ttl))
    return ttl


def session_expiry(request):
    """End of the current UI step-up window, or None."""
    ui = _ui_sid(request)
    if not ui:
        return None
    row = (AdminReauth.objects.filter(user=request.user, sid=ui, ip=client_ip(request) or "",
                                      expires_at__gt=timezone.now()).order_by("-expires_at").first())
    return row.expires_at if row else None


def drop_session(request) -> int:
    ui = _ui_sid(request)
    return AdminReauth.objects.filter(sid=ui).delete()[0] if ui else 0


def reauth_error(request):
    return ReauthRequired("This action needs a recent password confirmation.") if _ui_sid(request) else ReauthRequired()


def is_valid(request) -> bool:
    if _ui_sid(request):
        return session_expiry(request) is not None
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
