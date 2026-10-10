"""Reference token verifier for back-end services (spec §8.1/§8.2), PyJWT only.

Configuration (env): SSO_ISSUER, SSO_JWKS_URL, SSO_AUDIENCE (default myfin-services).
Services need no private key and no SSO database access.
"""
from __future__ import annotations

import os

import jwt
from jwt import PyJWKClient


class TokenInvalid(Exception):
    """Token missing, malformed, badly signed, expired, wrong iss/aud, or not an access token."""


class SSOVerifier:
    def __init__(self, jwks_url: str, issuer: str, audience: str = "myfin-services", leeway: int = 30,
                 jwks_client: PyJWKClient | None = None):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        # cache the JWKS for 1 h; PyJWKClient re-fetches on an unknown kid
        self.jwks = jwks_client or PyJWKClient(jwks_url, cache_keys=True, lifespan=3600)

    def verify_access_token(self, token: str) -> dict:
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token, key, algorithms=["RS256"],
                audience=self.audience, issuer=self.issuer, leeway=self.leeway,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenInvalid(str(exc)) from exc
        if claims.get("token_type") != "access":
            raise TokenInvalid("not an access token")
        return claims


_default: SSOVerifier | None = None


def default_verifier() -> SSOVerifier:
    global _default
    if _default is None:
        _default = SSOVerifier(
            jwks_url=os.environ["SSO_JWKS_URL"],
            issuer=os.environ["SSO_ISSUER"],
            audience=os.environ.get("SSO_AUDIENCE", "myfin-services"),
        )
    return _default


def verify_access_token(token: str) -> dict:
    """Spec §8.2 function signature, using env configuration."""
    return default_verifier().verify_access_token(token)
