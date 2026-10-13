"""DRF authentication classes used by the SSO server's own endpoints."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from django.contrib.auth.hashers import make_password
from rest_framework import authentication, exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication

from .errors import InvalidClient
from .models import ServiceClient
from .revocation import is_session_revoked
from .tokens import SID_CLAIM, is_revoked


class SSOAccessTokenAuthentication(JWTAuthentication):
    """``Authorization: Bearer <access token>`` for /me and /logout-all.

    On top of simplejwt's checks (signature by kid, iss, aud, exp, token_type=access, active
    user) the SSO server itself also honours ``UserTokenRevocation`` here.
    """

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None
        user, token = result
        if is_revoked(user, token.get("iat")) or is_session_revoked(token.get(SID_CLAIM)):
            raise exceptions.AuthenticationFailed("Token has been revoked.", code="token_revoked")
        return user, token

    def authenticate_header(self, request) -> str:
        return 'Bearer realm="sso", error="invalid_token"'


@dataclass
class ServicePrincipal:
    client: ServiceClient
    is_authenticated: bool = True

    @property
    def client_id(self) -> str:
        return self.client.client_id


_DUMMY_SECRET_HASH = None


def _dummy_check(secret: str) -> None:
    global _DUMMY_SECRET_HASH
    if _DUMMY_SECRET_HASH is None:
        _DUMMY_SECRET_HASH = make_password("dummy-service-secret")
    from django.contrib.auth.hashers import check_password

    check_password(secret, _DUMMY_SECRET_HASH)


class ServiceClientBasicAuthentication(authentication.BaseAuthentication):
    """HTTP Basic ``client_id:client_secret`` of an active ``ServiceClient`` (spec §6.6)."""

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).split()
        if not header or header[0].lower() != b"basic":
            return None
        if len(header) != 2:
            raise InvalidClient()
        try:
            client_id, _, secret = base64.b64decode(header[1], validate=True).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            raise InvalidClient() from None
        client = ServiceClient.objects.filter(client_id=client_id, is_active=True).first()
        if client is None:
            _dummy_check(secret)
            raise InvalidClient()
        if not client.check_secret(secret):
            raise InvalidClient()
        return ServicePrincipal(client=client), None

    def authenticate_header(self, request) -> str:
        return 'Basic realm="sso-introspect"'
