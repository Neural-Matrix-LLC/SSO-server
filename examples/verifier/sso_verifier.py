"""Reference token verifier for back-end services (spec §8.1/§8.2), PyJWT only.

Configuration (env): SSO_ISSUER, SSO_JWKS_URL, SSO_AUDIENCE (default myfin-services).
Services need no private key and no SSO database access.

JWKS caching (spec §8.1): keys are cached for ``lifespan`` seconds (1 h). A token with an unknown
``kid`` triggers a refetch, but **at most once per ``min_refetch_interval`` (60 s)**, so tokens with
made-up kids cannot make every service hammer the SSO's /.well-known/jwks.json. A failed fetch keeps
the old keys and counts against the same limit.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from typing import Callable

import jwt


class TokenInvalid(Exception):
    """Token missing, malformed, badly signed, expired, wrong iss/aud, or not an access token."""


def _http_fetch(url: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sso-verifier"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (configured https URL)
        return json.load(resp)


class JWKSCache:
    """kid -> public key, with a rate-limited refetch on unknown kids. Thread-safe."""

    def __init__(self, jwks_url: str, *, lifespan: float = 3600, min_refetch_interval: float = 60,
                 fetch: Callable[[str], dict] | None = None, clock: Callable[[], float] = time.monotonic):
        self.jwks_url = jwks_url
        self.lifespan = lifespan
        self.min_refetch_interval = min_refetch_interval
        self._fetch = fetch or _http_fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, object] = {}
        self._fetched_at: float | None = None   # last successful fetch
        self._attempted_at: float | None = None  # last fetch attempt (success or failure)
        self.fetch_count = 0

    def _refresh(self, now: float) -> None:
        self._attempted_at = now
        self.fetch_count += 1
        try:
            data = self._fetch(self.jwks_url)
            keys = {}
            for jwk in data.get("keys", []):
                if jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig" or not jwk.get("kid"):
                    continue
                keys[jwk["kid"]] = jwt.PyJWK.from_dict(jwk, algorithm="RS256").key
        except Exception as exc:  # network, JSON or key errors: keep what we have
            if not self._keys:
                raise jwt.PyJWKClientConnectionError(f"cannot fetch JWKS: {exc}") from exc
            return
        if keys:
            self._keys = keys
            self._fetched_at = now

    def _may_refetch(self, now: float) -> bool:
        return self._attempted_at is None or now - self._attempted_at >= self.min_refetch_interval

    def get_key(self, kid: str | None):
        if not kid:
            raise jwt.InvalidTokenError("token has no kid header")
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at >= self.lifespan
            if stale and self._may_refetch(now):
                self._refresh(now)
            if kid not in self._keys and self._may_refetch(now):
                self._refresh(now)  # unknown kid: maybe a rotation, refetch (rate-limited)
            key = self._keys.get(kid)
        if key is None:
            raise jwt.InvalidTokenError(f"unknown signing key (kid={kid[:64]!r})")
        return key


class SSOVerifier:
    def __init__(self, jwks_url: str, issuer: str, audience: str = "myfin-services", leeway: int = 30,
                 jwks: JWKSCache | None = None):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.jwks = jwks or JWKSCache(jwks_url)

    def verify_access_token(self, token: str) -> dict:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                raise jwt.InvalidAlgorithmError("only RS256 is accepted")
            key = self.jwks.get_key(header.get("kid"))
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
