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

import jwt
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


def is_session_revoked(sid: str | None) -> bool:
    return bool(sid) and RevokedSession.objects.filter(sid=sid).exists()


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
    logger.warning(json.dumps({"event": "session_revoked", "reason": reason, "user_id": user.pk,
                               "tokens_blacklisted": len(family)}, sort_keys=True))
    return len(family)
