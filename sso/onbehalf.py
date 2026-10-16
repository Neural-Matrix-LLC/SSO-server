"""v1.3b on-behalf-of (DESIGN-v1.3b §5): a service (Bearer service token) passes the user's token and the browser IP.

    Authorization: Bearer <service token>   X-SSO-User-Token: <user access token>   X-SSO-Client-IP: <browser IP>
"""
from __future__ import annotations

from django.contrib.auth.models import User
from rest_framework_simplejwt.exceptions import TokenError

from .clientip import normalize_ip
from .errors import TokenInvalid
from .ipbinding import CIP_CLAIM, ip_matches, log_mismatch, mode as ip_mode
from .revocation import is_session_revoked, revoke_session
from .tokens import SID_CLAIM, SSOAccessToken, is_revoked

USER_HEADER = "X-SSO-User-Token"
IP_HEADER = "X-SSO-Client-IP"


def check_user_token(raw: str | None, raw_ip: str | None, *, where: str, client_id: str | None = None):
    """(user, token, ip, ip_match) for an active, unrevoked user token checked against ``raw_ip``; else TokenInvalid.
    ENFORCE mismatch revokes the session (v1.2b rule)."""
    if not raw:
        raise TokenInvalid("User token missing.")
    try:
        token = SSOAccessToken(raw)
        user = User.objects.select_related("sso_token_revocation").filter(pk=token.get("sub")).first()
    except (TokenError, TypeError, ValueError, OverflowError):
        raise TokenInvalid() from None
    if (user is None or not user.is_active or is_revoked(user, token.get("iat"))
            or is_session_revoked(token.get(SID_CLAIM))):
        raise TokenInvalid()
    ip = normalize_ip(raw_ip) if isinstance(raw_ip, str) and len(raw_ip) <= 128 else None
    match = ip_matches(token.get(CIP_CLAIM), ip)
    if match is False:
        log_mismatch(where, user_id=user.pk, ip=ip, client_id=client_id)
        if ip_mode() == "ENFORCE":
            if token.get(SID_CLAIM):
                revoke_session(user, token[SID_CLAIM], "ip_mismatch")
            raise TokenInvalid()
    return user, token, ip, match


def from_headers(request, client_id: str):
    return check_user_token(request.headers.get(USER_HEADER), request.headers.get(IP_HEADER),
                            where="on_behalf_of", client_id=client_id)
