"""Test utilities (library design §11): an in-memory fake SSO that plugs in as an httpx transport.

    fake = FakeSSO()
    token = fake.issue("alice", perms=["application.app1"], ip="203.0.113.7")
    client = fake.client()                 # SSOClient wired to the fake (or fake.async_client())
    fake.revoke(token); fake.down()        # inactive / SSO unreachable (503 in adapters)

Also registered as a pytest plugin (``fake_sso`` and ``sso_client`` fixtures).
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, field

import httpx

from .cache import TTLCache
from .client import AsyncSSOClient, SSOClient
from .config import SSOConfig
from .ip import normalize_ip

BASE_URL = "https://sso.fake.test"
CLIENT_ID, CLIENT_SECRET = "fake-service", "fake-secret"


@dataclass
class _Tok:
    sub: str
    username: str
    perms: list[str]
    ip: str | None
    sid: str
    exp: int
    email: str = ""
    groups: list[str] = field(default_factory=list)
    active: bool = True


class FakeSSO:
    """Speaks the v1.2b introspect contract. ``mode``: NOIP | WARNING | ENFORCE (binding on the issued ``ip``)."""

    def __init__(self, mode: str = "NOIP", *, client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET):
        self.mode = mode
        self.client_id, self.client_secret = client_id, client_secret
        self.tokens: dict[str, _Tok] = {}
        self.calls: list[dict] = []
        self.status: int | None = None   # force an HTTP status (e.g. 500, 429)
        self.error: Exception | None = None  # raise a transport error (down())
        self.transport = httpx.MockTransport(self._handle)
        self.async_transport = httpx.MockTransport(self._handle)

    # -------------------------------------------------------------- control
    def issue(self, user: str = "alice", *, perms=(), ip: str | None = None, ttl: int = 900, sub: str | None = None,
              email: str = "", groups=()) -> str:
        token = "fake." + secrets.token_urlsafe(24)
        self.tokens[token] = _Tok(sub or str(abs(hash(user)) % 10_000), user, list(perms), normalize_ip(ip),
                                  secrets.token_urlsafe(8), int(time.time()) + ttl, email, list(groups))
        return token

    def revoke(self, token: str) -> None:
        self.tokens[token].active = False

    def grant(self, token: str, *perms: str) -> None:
        self.tokens[token].perms.extend(perms)

    def down(self, exc: Exception | None = None) -> None:
        self.error = exc or httpx.ConnectError("fake SSO is down")

    def up(self) -> None:
        self.error, self.status = None, None

    def config(self, **kw) -> SSOConfig:
        return SSOConfig(BASE_URL, self.client_id, self.client_secret, **kw)

    def client(self, **kw) -> SSOClient:
        cfg = self.config(**kw)
        return SSOClient(cfg, http=httpx.Client(transport=self.transport), cache=TTLCache(cfg.cache_ttl))

    def async_client(self, **kw) -> AsyncSSOClient:
        cfg = self.config(**kw)
        return AsyncSSOClient(cfg, http=httpx.AsyncClient(transport=self.async_transport),
                              cache=TTLCache(cfg.cache_ttl))

    # -------------------------------------------------------------- server side
    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.error is not None:
            raise self.error
        if self.status is not None:
            return httpx.Response(self.status, json={"error": "forced"})
        if request.url.path != "/api/v1/auth/introspect" or request.method != "POST":
            return httpx.Response(404, json={"error": "not_found"})
        expected = "Basic " + base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return httpx.Response(401, json={"error": "invalid_client"})
        body = json.loads(request.content or b"{}")
        self.calls.append(body)
        tok = self.tokens.get(body.get("token", ""))
        if tok is None or not tok.active or tok.exp <= time.time():
            return httpx.Response(200, json={"active": False})
        ip = normalize_ip(body.get("ip"))
        match = None if self.mode == "NOIP" or tok.ip is None else (ip == tok.ip)
        if match is False and self.mode == "ENFORCE":
            tok.active = False  # session revoked
            return httpx.Response(200, json={"active": False})
        out = {"active": True, "sub": tok.sub, "username": tok.username, "email": tok.email, "is_staff": False,
               "groups": tok.groups, "perms": tok.perms, "sid": tok.sid, "ip_binding": self.mode, "ip_match": match,
               "token_type": "access", "iat": tok.exp - 900, "exp": tok.exp, "client_id": self.client_id}
        if "require" in body:
            req = [body["require"]] if isinstance(body["require"], str) else body["require"]
            out["allowed"] = set(req) <= set(tok.perms)
        return httpx.Response(200, json=out)


def wsgi_environ(peer: str = "127.0.0.1", xff: str | None = None, token: str | None = None, **extra) -> dict:
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "REMOTE_ADDR": peer, "SERVER_NAME": "t", "SERVER_PORT": "80",
           "wsgi.url_scheme": "http"}
    if xff is not None:
        env["HTTP_X_FORWARDED_FOR"] = xff
    if token is not None:
        env["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    env.update(extra)
    return env


def asgi_scope(peer: str = "127.0.0.1", xff: str | None = None, token: str | None = None) -> dict:
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    return {"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 5555)}


try:  # pytest plugin (entry point "sso_client")
    import pytest

    @pytest.fixture
    def fake_sso() -> FakeSSO:
        return FakeSSO()

    @pytest.fixture
    def sso_client(fake_sso: FakeSSO) -> SSOClient:
        return fake_sso.client()
except ImportError:  # pragma: no cover
    pass
