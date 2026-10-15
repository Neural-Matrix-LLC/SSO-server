"""Token classes and a key-id aware token backend (spec §5, §9.3, addendum B.6/B.7).

* Every JWT we sign carries ``kid`` in its header (the signing key's id).
* Verification picks the public key by ``kid`` among *all* published keys, so tokens signed
  with a previous key keep working during rotation. Only RS256 is accepted.
* ``iss`` and ``aud`` are added on encode and enforced on decode (simplejwt TokenBackend).
"""
from __future__ import annotations

import math
import secrets
import time
from functools import lru_cache
from typing import Any

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import TokenBackendError, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from application.permissions import user_app_perms


#: session id claim (design §4.2): one value per login, kept through every refresh
SID_CLAIM = "sid"


class KidTokenBackend(TokenBackend):
    def __init__(self, keyset, **kwargs):
        super().__init__(
            "RS256",
            signing_key=keyset.signing_pem,
            verifying_key=keyset.signing_public.pem,
            **kwargs,
        )
        self.keyset = keyset

    def encode(self, payload: dict[str, Any]) -> str:
        jwt_payload = payload.copy()
        jwt_payload["aud"] = self.audience
        jwt_payload["iss"] = self.issuer
        return jwt.encode(
            jwt_payload,
            self.prepared_signing_key,
            algorithm="RS256",
            headers={"kid": self.keyset.signing_kid},
        )

    def get_verifying_key(self, token) -> Any:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenBackendError("Token is invalid") from exc
        if header.get("alg") != "RS256":
            raise TokenBackendError("Invalid algorithm specified")
        pk = self.keyset.by_kid(header.get("kid") or "")
        if pk is None:
            raise TokenBackendError("Token is invalid")
        return pk.key


@lru_cache(maxsize=1)
def get_token_backend() -> KidTokenBackend:
    return KidTokenBackend(
        settings.SSO_KEYSET,
        audience=settings.SSO_AUDIENCE,
        issuer=settings.SSO_ISSUER,
        leeway=settings.SIMPLE_JWT.get("LEEWAY", 30),
    )


class _SSOBackendMixin:
    @property
    def token_backend(self) -> KidTokenBackend:  # overrides simplejwt's global backend
        return get_token_backend()


class SSOAccessToken(_SSOBackendMixin, AccessToken):
    pass


class SSORefreshToken(_SSOBackendMixin, RefreshToken):
    access_token_class = SSOAccessToken
    # Refresh tokens carry only the standard claims plus ``sid``; profile claims go on the access token.

    @classmethod
    def for_session(cls, user: User, sid: str, cip: str | None = None) -> "SSORefreshToken":
        """Like simplejwt's ``for_user`` (blacklist app: records an OutstandingToken) but with ``sid`` (and the
        v1.2b ``cip`` binding) set BEFORE the token string is stored, so a session's refresh tokens can be found
        by their claim. The access token copies both claims."""
        token = cls()
        token[api_settings.USER_ID_CLAIM] = str(getattr(user, api_settings.USER_ID_FIELD))
        token[SID_CLAIM] = sid
        if cip:
            token["cip"] = cip
        OutstandingToken.objects.create(
            user=user, jti=token[api_settings.JTI_CLAIM], token=str(token), created_at=token.current_time,
            expires_at=datetime_from_epoch(token["exp"]))
        return token


class _ReplayProbeRefreshToken(SSORefreshToken):
    """Full validation (signature by kid, iss, aud, exp, type) EXCEPT the blacklist: used only to classify a
    token that SSORefreshToken rejected, i.e. to recognise a replayed (already used) refresh token."""

    def check_blacklist(self) -> None:
        return None


def replayed_refresh(raw: str) -> "SSORefreshToken | None":
    """The token, if ``raw`` is a genuine, unexpired refresh token of ours that is blacklisted; else None."""
    try:
        token = _ReplayProbeRefreshToken(raw)
    except TokenError:
        return None
    if not BlacklistedToken.objects.filter(token__jti=token[api_settings.JTI_CLAIM]).exists():
        return None
    return token


def new_sid() -> str:
    return secrets.token_urlsafe(16)


def user_groups(user: User) -> list[str]:
    return sorted(user.groups.values_list("name", flat=True))


def revocation_epoch(user: User) -> int | None:
    """Integer epoch second from which tokens are valid again, or None if never revoked.

    ``revoked_at`` is rounded *up* to the next second: any token whose integer ``iat`` is
    below it was issued no later than the revocation.
    """
    rev = getattr(user, "sso_token_revocation", None)
    if rev is None:
        return None
    return math.ceil(rev.revoked_at.timestamp())


def is_revoked(user: User, iat: int | float | None) -> bool:
    epoch = revocation_epoch(user)
    if epoch is None:
        return False
    if iat is None:
        return True
    return iat < epoch


def _wait_past_revocation(user: User) -> None:
    """New tokens issued in the same second as a revocation would look revoked; wait (<1 s)."""
    epoch = revocation_epoch(user)
    if epoch is None:
        return
    delay = epoch - time.time()
    if 0 < delay <= 1.0:
        time.sleep(delay + 0.001)


def issue_token_pair(user: User, sid: str | None = None, cip: str | None = None
                     ) -> tuple[SSORefreshToken, SSOAccessToken]:
    """Create a refresh token (recorded as outstanding) and an access token with profile claims.

    ``sid``: the session id; a login passes None (new session), a refresh passes the old token's ``sid``.
    ``cip``: IP binding (design §4.2), None in NOIP mode. Both tokens carry them (the access token inherits
    them from the refresh token).
    """
    _wait_past_revocation(user)
    refresh = SSORefreshToken.for_session(user, sid or new_sid(), cip)
    access = refresh.access_token
    access["username"] = user.get_username()
    access["email"] = user.email or ""
    access["is_staff"] = bool(user.is_staff)
    access["groups"] = user_groups(user)
    # application.* permissions only (design A2); recomputed on every refresh
    access["perms"] = user_app_perms(user)
    return refresh, access


def access_ttl_seconds() -> int:
    return int(settings.SSO_ACCESS_TTL.total_seconds())


def refresh_ttl_seconds() -> int:
    return int(settings.SSO_REFRESH_TTL.total_seconds())



# --------------------------------------------------------------------------- v1.3a service tokens
SERVICE_TOKEN_TYPE = "service"


class SSOServiceToken(_SSOBackendMixin, AccessToken):
    """Client-credentials token of a ServiceClient (DESIGN-v1.3a §6): ``token_type="service"``, so it is never
    accepted where a user access token is expected (``SSOAccessToken`` checks ``token_type="access"``)."""

    token_type = SERVICE_TOKEN_TYPE

    @property
    def lifetime(self):  # type: ignore[override]
        from datetime import timedelta

        return timedelta(seconds=settings.SSO_SERVICE_TOKEN_TTL_SECONDS)


def service_client_perms(client) -> list[str]:
    """Sorted ``application.*`` permissions granted to a ServiceClient."""
    return sorted("application." + c for c in client.permissions.filter(
        content_type__app_label="application").values_list("codename", flat=True))


def issue_service_token(client) -> SSOServiceToken:
    token = SSOServiceToken()
    if getattr(client, "kind", "service") == "device":  # v1.3b: device token, acts as a pipe (no perms)
        token["sub"] = f"dev:{client.client_id}"
        token["typ"] = "device"
        token["client_id"] = client.client_id
        token["owner"] = str(client.owner_id)
        token["app"] = client.app_codename or None
        token["perms"] = []
        token["rot"] = secret_generation(client)
        return token
    token["sub"] = f"svc:{client.client_id}"
    token["typ"] = SERVICE_TOKEN_TYPE
    token["client_id"] = client.client_id
    token["app"] = client.app_codename or None
    token["perms"] = service_client_perms(client)
    token["rot"] = secret_generation(client)  # secret generation: a rotation makes older tokens inactive
    return token


def secret_generation(client) -> int:
    rotated = getattr(client, "secret_rotated_at", None)
    return int(rotated.timestamp() * 1_000_000) if rotated else 0


def service_token_ttl_seconds() -> int:
    return int(settings.SSO_SERVICE_TOKEN_TTL_SECONDS)
