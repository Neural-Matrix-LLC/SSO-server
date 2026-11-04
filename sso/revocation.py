"""Revoking tokens: whole user (logout-all, suspend, password change) or one session (sid family: logout,
refresh-token reuse, IP mismatch).

* User: ``UserTokenRevocation`` marker (every token with an earlier ``iat`` is dead: access tokens at
  introspect / ``/me``, refresh tokens at ``/refresh``) plus all outstanding refresh tokens blacklisted.
* Session (design §4.2): a login starts a session id ``sid`` carried by every token issued from it,
  through every refresh. Revoking it records ``RevokedSession`` (access tokens of the session fail at
  introspect / ``/me``) and blacklists the session's outstanding refresh tokens.
* v1.3f "log out, keep my jobs" (DESIGN-v1.3e §6): the session ends exactly like a logout, but the row's reason is
  ``logout_keep_jobs``: ``token.revoked`` carries ``keep_jobs: true``, the session-status sweep answers ``detached``
  (until a later user-wide revocation), and the row is kept past the normal retention while it is still detached.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.db.models import F, Q
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


def revoke_user_tokens(user, reason: str | None = "revoked") -> None:
    """Every token of ``user`` issued up to now becomes invalid. One transaction. ``reason`` (v1.3c) is sent as
    ``token.revoked``; None = no event (the caller emits a more specific one, e.g. ``user.deleted``)."""
    with transaction.atomic():
        blacklist_all(user)
        UserTokenRevocation.revoke(user)
        drop_reauth(user)
        if reason:
            from .webhooks import emit

            emit("token.revoked", sub=str(user.pk), reason=reason)


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
    # v1.3f: a keep-jobs logout row is what tells the sweep "detached" for the jobs that outlived the session; keep it
    # until a later user-wide revocation (logout-all, password change, suspend) has ended those jobs. Deleting the
    # user deletes it (cascade).
    still_detached = Q(reason=LOGOUT_KEEP_JOBS) & (
        Q(user__sso_token_revocation__isnull=True)
        | Q(user__sso_token_revocation__revoked_at__lte=F("revoked_at")))
    old = RevokedSession.objects.filter(revoked_at__lt=cutoff).exclude(still_detached)
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
            new = True
        except IntegrityError:
            new = False  # already revoked (e.g. a token replayed after logout): keep the first reason
        family = [t for t in _live_outstanding(user) if token_sid(t.token) == sid]
        BlacklistedToken.objects.bulk_create([BlacklistedToken(token=t) for t in family], ignore_conflicts=True)
        drop_reauth(user, sid)
        if new:  # v1.3e: one token.revoked per session end; services stop the session's jobs on it
            from .webhooks import emit

            if reason == LOGOUT_KEEP_JOBS:  # v1.3f: services detach the jobs instead (older ones stop them: safe)
                emit("token.revoked", sub=str(user.pk), sid=sid, reason="logout", keep_jobs=True)
            else:
                emit("token.revoked", sub=str(user.pk), sid=sid, reason=reason)
    _cache_revoked(sid)
    # a user's own logout is routine (v1.3e); every other session revocation is a security signal
    log = logger.info if reason in ROUTINE_SESSION_REASONS else logger.warning
    log(json.dumps({"event": "session_revoked", "reason": reason, "user_id": user.pk,
                    "tokens_blacklisted": len(family)}, sort_keys=True))
    return len(family)


LOGOUT_KEEP_JOBS = "logout_keep_jobs"  # v1.3f RevokedSession reason (fits max_length=32; no migration)
DETACHED = "detached"  # v1.3f session-status reason for a keep-jobs logout
ROUTINE_SESSION_REASONS = frozenset({"logout", LOGOUT_KEEP_JOBS})


def _claims(raw: str) -> dict:
    try:
        out = jwt.decode(raw, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}
    return out if isinstance(out, dict) else {}


def session_states(user, sids) -> dict[str, str | None]:
    """v1.3e: state of each login session ``sid`` of ``user``. ``None`` = the session is alive; otherwise the
    reason it ended: the ``RevokedSession`` reason (``logout``, ``refresh_reuse``, ``ip_mismatch``, …),
    ``revoked`` (every token of the user revoked: logout-all, password change, admin), or ``expired`` (no live
    refresh token left: idle past the refresh lifetime, or an unknown sid). The caller checks the user itself.

    v1.3f: a keep-jobs logout answers ``detached`` (the jobs outlive the session) until a later user-wide
    revocation, which answers ``revoked`` (it ends the detached jobs too).

    A session is alive while it has a refresh token that is unexpired, not blacklisted and issued after the
    user's revocation epoch; refresh keeps the ``sid``, so a session lives as long as the client keeps refreshing.
    """
    from .tokens import revocation_epoch

    wanted = set(sids)
    out: dict[str, str | None] = dict.fromkeys(wanted, "expired")
    epoch = revocation_epoch(user)
    user_rev = getattr(user, "sso_token_revocation", None)
    revoked = {}
    for sid, reason, at in RevokedSession.objects.filter(user=user, sid__in=wanted).values_list(
            "sid", "reason", "revoked_at"):
        if reason == LOGOUT_KEEP_JOBS:  # a later logout-all / password change ends the detached jobs too
            reason = "revoked" if user_rev is not None and user_rev.revoked_at > at else DETACHED
        revoked[sid] = reason
    rows = (OutstandingToken.objects.filter(user=user, expires_at__gt=timezone.now())
            .values_list("token", "blacklistedtoken__id"))
    for raw, blacklisted in rows:
        c = _claims(raw)
        sid = c.get("sid")
        if sid not in wanted or sid in revoked or out[sid] is None:
            continue
        iat = c.get("iat")
        if epoch is not None and (not isinstance(iat, (int, float)) or iat < epoch):
            out[sid] = "revoked"
        elif not blacklisted:
            out[sid] = None
    out.update(revoked)
    return out


def drop_reauth(user, sid: str | None = None) -> int:
    """v1.3a step-up tokens die with the user's tokens / the session (logout, logout-all, suspend, reuse)."""
    from .models import AdminReauth

    qs = AdminReauth.objects.filter(user=user)
    if sid is not None:
        qs = qs.filter(sid=sid)
    return qs.delete()[0]
