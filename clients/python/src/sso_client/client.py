"""SSOClient / AsyncSSOClient: the SSO permission query (design v1.2 §4.4, library design §5-§6).

``check(token, client_ip, require=())`` POSTs ``{"token", "ip", "require"}`` to ``/api/v1/auth/introspect``
with the service's Basic credentials and returns a CheckResult.

* Cache: only active answers, ``sha256(token):ip``, at most 30 s and never past ``exp``.
* Fail closed: timeouts, connection errors, 5xx and 429 (after retries) raise SSOUnavailable (adapters: 503).
  Retries (default 1, backoff 0.1 s + jitter; timeout default 2 s) only for connect errors, timeouts and 502/503/504.
* Raises TokenInactive for ``active:false``, PermissionDenied when a required permission is missing.
* Tokens, secrets and Authorization headers are never logged (tokens as sha256[:12] only).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
from collections.abc import Sequence

import httpx

from .cache import TTLCache, cache_key
from .config import SSOConfig
from .errors import NotAuthenticated, PermissionDenied, SSOProtocolError, SSOUnavailable, TokenInactive
from .ip import normalize_ip
from .models import CheckResult

logger = logging.getLogger("sso_client")
RETRY_STATUS = {502, 503, 504}
BACKOFF = (0.1, 0.3)


def _tok(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


class _Base:
    def __init__(self, config: SSOConfig | None = None, *, cache: TTLCache | None = None):
        self.config = config or SSOConfig.from_env()
        self.cache = cache if cache is not None else TTLCache(self.config.cache_ttl, self.config.cache_size)
        self._auth = httpx.BasicAuth(self.config.client_id, self.config.client_secret)
        self._timeout = httpx.Timeout(self.config.timeout, connect=self.config.connect_timeout)

    @staticmethod
    def _prepare(token: str, client_ip: str | None, require: Sequence[str] | str) -> tuple[dict, str | None, list]:
        if not token or not isinstance(token, str):
            raise NotAuthenticated("no token")
        req = [require] if isinstance(require, str) else list(require)
        ip = normalize_ip(client_ip)
        body: dict = {"token": token}
        if ip is not None:
            body["ip"] = ip  # missing IP is sent as absent: a mismatch when the token is bound
        if req:
            body["require"] = req
        return body, ip, req

    def _parse(self, resp: httpx.Response, ip: str | None) -> CheckResult:
        if resp.status_code == 429 or resp.status_code >= 500:
            raise SSOUnavailable(f"SSO answered {resp.status_code}")
        if resp.status_code != 200:
            raise SSOProtocolError(f"SSO answered {resp.status_code}", resp.status_code)  # 401: bad credentials
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            raise SSOProtocolError("SSO answered non-JSON") from None
        if not isinstance(body, dict) or "active" not in body:
            raise SSOProtocolError("SSO answer has no 'active'")
        return CheckResult.from_response(body, ip)

    def _finish(self, token: str, result: CheckResult, req: list, *, cached: bool, attempts: int, started: float):
        logger.debug(json.dumps({"event": "sso_check", "token": _tok(token), "active": result.active,
                                 "cache_hit": cached, "attempts": attempts,
                                 "ms": round((time.monotonic() - started) * 1000, 1)}))
        if result.active and result.ip_match is False:
            logger.info(json.dumps({"event": "ip_mismatch", "token": _tok(token), "ip": result.client_ip,
                                    "mode": result.ip_binding}))
        if not result.active:
            raise TokenInactive(result.reason or "inactive")
        missing = [p for p in req if p not in result.permissions]
        if missing:
            raise PermissionDenied(missing)
        return result

    def _key(self, token, ip, req):
        return cache_key(token, ip)  # permissions are checked locally against the cached set


class SSOClient(_Base):
    def __init__(self, config: SSOConfig | None = None, *, http: httpx.Client | None = None,
                 cache: TTLCache | None = None):
        super().__init__(config, cache=cache)
        self.http = http or httpx.Client()

    def check(self, token: str, client_ip: str | None, require: Sequence[str] | str = ()) -> CheckResult:
        started = time.monotonic()
        body, ip, req = self._prepare(token, client_ip, require)
        key = self._key(token, ip, req)
        hit = self.cache.get(key)
        if hit is not None:
            return self._finish(token, hit, req, cached=True, attempts=0, started=started)
        body.pop("require", None)  # cache-friendly: compare permissions locally
        attempts = 0
        while True:
            attempts += 1
            try:
                resp = self.http.post(self.config.introspect_url, json=body, auth=self._auth, timeout=self._timeout)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempts <= self.config.retries:
                    time.sleep(BACKOFF[min(attempts - 1, 1)] + random.uniform(0, 0.05))
                    continue
                raise SSOUnavailable(f"SSO unreachable: {type(exc).__name__}") from None
            if resp.status_code in RETRY_STATUS and attempts <= self.config.retries:
                time.sleep(BACKOFF[min(attempts - 1, 1)] + random.uniform(0, 0.05))
                continue
            break
        result = self._parse(resp, ip)
        self.cache.set(key, result)
        return self._finish(token, result, req, cached=False, attempts=attempts, started=started)

    def close(self) -> None:
        self.http.close()


class AsyncSSOClient(_Base):
    def __init__(self, config: SSOConfig | None = None, *, http: httpx.AsyncClient | None = None,
                 cache: TTLCache | None = None):
        super().__init__(config, cache=cache)
        self.http = http or httpx.AsyncClient()

    async def check(self, token: str, client_ip: str | None, require: Sequence[str] | str = ()) -> CheckResult:
        started = time.monotonic()
        body, ip, req = self._prepare(token, client_ip, require)
        key = self._key(token, ip, req)
        hit = self.cache.get(key)
        if hit is not None:
            return self._finish(token, hit, req, cached=True, attempts=0, started=started)
        body.pop("require", None)
        attempts = 0
        while True:
            attempts += 1
            try:
                resp = await self.http.post(self.config.introspect_url, json=body, auth=self._auth,
                                            timeout=self._timeout)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempts <= self.config.retries:
                    await asyncio.sleep(BACKOFF[min(attempts - 1, 1)] + random.uniform(0, 0.05))
                    continue
                raise SSOUnavailable(f"SSO unreachable: {type(exc).__name__}") from None
            if resp.status_code in RETRY_STATUS and attempts <= self.config.retries:
                await asyncio.sleep(BACKOFF[min(attempts - 1, 1)] + random.uniform(0, 0.05))
                continue
            break
        result = self._parse(resp, ip)
        self.cache.set(key, result)
        return self._finish(token, result, req, cached=False, attempts=attempts, started=started)

    async def aclose(self) -> None:
        await self.http.aclose()


def bearer_token(authorization: str | None) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` header, else None."""
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    return parts[1]
