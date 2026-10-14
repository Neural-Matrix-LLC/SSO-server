"""Revoking tokens: whole user (logout-all, suspend, password change) or one session (sid family).

* User: ``UserTokenRevocation`` marker (every token with an earlier ``iat`` is dead: access tokens at
  introspect / ``/me``, refresh tokens at ``/refresh``) plus all outstanding refresh tokens blacklisted.
* Session (design §4.2): a login starts a session id ``sid`` carried by every token issued from it,
  through every refresh. Revoking it records ``RevokedSession`` (access tokens of the session fail at
  introspect / ``/me``) and blacklists the session's outstanding refresh tokens.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from .models import RevokedSession, UserTokenRevocation

logger = logging.getLogger("sso.auth")


def _live_outstanding(user):
    return (OutstandingToken.objects.filter(user=user, expires_at__gt=timezone.now())
            .filter(blacklistedtoken__isnull=True))


def blacklist_all(user) -> int:
    tokens = list(_live_outstanding(user))
    BlacklistedToken.objects.bulk_create([BlacklistedToken(token=t) for t in tokens], ignore_conflicts=True)
    return len(tokens)


def revoke_user_tokens(user) -> None:
    """Every token of ``user`` issued up to now becomes invalid. One transaction."""
    with transaction.atomic():
        blacklist_all(user)
        UserTokenRevocation.revoke(user)


def token_sid(raw: str) -> str | None:
    """``sid`` of a stored (already verified when issued) token string; None for pre-v1.2a tokens."""
    try:
        return jwt.decode(raw, options={"verify_signature": False}).get("sid")
    except jwt.PyJWTError:
        return None


def _session_key(sid: str) -> str:
    return "revoked_sid:" + sid[:64]


def _revoked_ttl() -> int:
    return int(settings.SSO_REFRESH_TTL.total_seconds()) + 86400


def is_session_revoked(sid: str | None) -> bool:
    """Shared cache first (Redis in production, v1.2b): "revoked" is cached for the refresh lifetime + 1 day
    (the row's own retention), "not revoked" only ``SSO_REVOKED_SESSION_CACHE_SECONDS``. ``revoke_session``
    writes the cache at once. A cache error falls back to the database."""
    if not sid:
        return False
    key = _session_key(sid)
    try:
        hit = cache.get(key)
    except Exception:  # noqa: BLE001 - cache down: the DB is the authority
        hit = None
    if hit is not None:
        return hit == 1
    revoked = RevokedSession.objects.filter(sid=sid).exists()
    ttl = _revoked_ttl() if revoked else settings.SSO_REVOKED_SESSION_CACHE_SECONDS
    if ttl > 0:
        try:
            cache.set(key, 1 if revoked else 0, ttl)
        except Exception:  # noqa: BLE001
            pass
    return revoked


def _cache_revoked(sid: str) -> None:
    try:
        cache.set(_session_key(sid), 1, _revoked_ttl())
    except Exception:  # noqa: BLE001 - DB row is written; the negative entry expires within seconds
        logger.warning(json.dumps({"event": "revoked_session_cache_error"}))


def prune_revoked_sessions(*, dry_run: bool = False) -> int:
    """Delete ``RevokedSession`` rows older than the refresh lifetime + 1 day: every refresh token of such a
    session has expired, and its access tokens long before. Returns the number of rows (to be) deleted."""
    cutoff = timezone.now() - settings.SSO_REFRESH_TTL - timedelta(days=1)
    old = RevokedSession.objects.filter(revoked_at__lt=cutoff)
    if dry_run:
        return old.count()
    return old.delete()[0]


def revoke_session(user, sid: str, reason: str) -> int:
    """Revoke the session ``sid`` of ``user``: mark it and blacklist its outstanding refresh tokens.

    Idempotent. Returns the number of refresh tokens newly blacklisted.
    """
    with transaction.atomic():
        try:
            with transaction.atomic():
                RevokedSession.objects.create(sid=sid, user=user, reason=reason)
        except IntegrityError:
            pass  # already revoked
        family = [t for t in _live_outstanding(user) if token_sid(t.token) == sid]
        BlacklistedToken.objects.bulk_create([BlacklistedToken(token=t) for t in family], ignore_conflicts=True)
    _cache_revoked(sid)
    logger.warning(json.dumps({"event": "session_revoked", "reason": reason, "user_id": user.pk,
                               "tokens_blacklisted": len(family)}, sort_keys=True))
    return len(family)
