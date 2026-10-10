"""Black-box fixtures for the SSO server QA suite.

Configuration is via environment variables only (see README.md). Nothing here talks to
the server at import/collection time.
"""
from __future__ import annotations

import itertools
import os
import shlex
import subprocess
from dataclasses import dataclass, field

import pytest
import requests

import jwt_forge
import testdata
from sso_client import JWKS, DISCOVERY, SSOClient


def _env(name, default=None):
    v = os.environ.get(name)
    return default if v is None else v


def _verify_setting():
    v = _env("SSO_VERIFY_TLS", "1")
    if v.lower() in ("0", "false", "no"):
        import urllib3
        urllib3.disable_warnings()
        return False
    if v.lower() in ("1", "true", "yes"):
        return True
    return v  # path to a CA bundle


@dataclass
class Config:
    base_url: str = field(default_factory=lambda: _env("SSO_BASE_URL", "http://localhost:8000"))
    verify: object = field(default_factory=_verify_setting)
    issuer: str | None = field(default_factory=lambda: _env("SSO_ISSUER"))
    audience: str = field(default_factory=lambda: _env("SSO_AUDIENCE", "myfin-services"))
    access_ttl_s: int = field(default_factory=lambda: int(_env("SSO_ACCESS_TTL_MIN", "15")) * 60)
    refresh_ttl_s: int = field(default_factory=lambda: int(_env("SSO_REFRESH_TTL_DAYS", "7")) * 86400)
    # Must be in the server's SSO_CORS_ALLOWED_ORIGINS. SSO_ALLOWED_ORIGIN is a legacy alias.
    allowed_origin: str = field(default_factory=lambda: _env(
        "SSO_TEST_ALLOWED_ORIGIN", _env("SSO_ALLOWED_ORIGIN", "https://example.com")))
    # None = don't check Domain attr; "" = expect host-only cookie (no Domain attribute)
    cookie_domain: str | None = field(default_factory=lambda: _env("SSO_COOKIE_DOMAIN"))
    private_key_path: str | None = field(default_factory=lambda: _env("SSO_TEST_PRIVATE_KEY_PATH"))
    manage_cmd: str | None = field(default_factory=lambda: _env("SSO_MANAGE_CMD"))
    repo_dir: str = field(default_factory=lambda: _env(
        "SSO_REPO_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))))
    verifier_url: str | None = field(default_factory=lambda: _env("VERIFIER_BASE_URL"))
    verifier_path: str = field(default_factory=lambda: _env("VERIFIER_PROTECTED_PATH", "/me"))
    verifier_group_path: str | None = field(default_factory=lambda: _env("VERIFIER_GROUP_PATH"))
    verifier_group: str = field(default_factory=lambda: _env("VERIFIER_GROUP_NAME", "qa_trader"))
    rate_login_ip: int = field(default_factory=lambda: int(_env("SSO_TEST_RATE_LOGIN_IP", "10")))
    rate_login_user: int = field(default_factory=lambda: int(_env("SSO_TEST_RATE_LOGIN_USER", "5")))
    rate_refresh: int = field(default_factory=lambda: int(_env("SSO_TEST_RATE_REFRESH", "60")))
    max_throttle_wait: float = field(default_factory=lambda: float(_env("SSO_TEST_MAX_THROTTLE_WAIT", "240")))


@pytest.fixture(scope="session")
def cfg() -> Config:
    return Config()


@pytest.fixture(scope="session")
def base_url(cfg) -> str:
    return cfg.base_url.rstrip("/")


@pytest.fixture(scope="session")
def sso(cfg, base_url) -> SSOClient:
    client = SSOClient(base_url, cfg.verify, max_throttle_wait=cfg.max_throttle_wait)
    try:
        requests.get(client.url("/healthz"), verify=cfg.verify, timeout=10)
    except requests.RequestException as e:
        pytest.exit(f"SSO server not reachable at {base_url}: {e}", returncode=3)
    return client


@pytest.fixture(scope="session")
def jwks(sso) -> dict:
    r = sso.get(JWKS)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="session")
def discovery(sso) -> dict:
    r = sso.get(DISCOVERY)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="session")
def issuer(cfg, discovery) -> str:
    return cfg.issuer or discovery["issuer"]


@pytest.fixture(scope="session")
def jwks_public_key(jwks):
    """First published public key (the signing key unless rotation is in progress)."""
    return jwt_forge.jwk_to_public_key(jwks["keys"][0])


@pytest.fixture(scope="session")
def service_auth():
    return (testdata.SERVICE_CLIENT_ID, testdata.SERVICE_CLIENT_SECRET)


@pytest.fixture(scope="session")
def signing_key(cfg):
    if not cfg.private_key_path:
        pytest.skip("SSO_TEST_PRIVATE_KEY_PATH not set (test-env signing key needed)")
    return jwt_forge.load_private_key(cfg.private_key_path)


_pool = itertools.cycle(testdata.POOL)


@pytest.fixture
def pool_user():
    """(username, password, attrs) of an interchangeable active user; spreads the
    per-username login throttle across 12 accounts."""
    name = next(_pool)
    return name, testdata.USERS[name]["password"], testdata.USERS[name]


@pytest.fixture(scope="session")
def alice_session(sso):
    """One native login for qa_alice reused by read-only tests. Never log it out."""
    u = testdata.USERS["qa_alice"]
    return sso.login_ok("qa_alice", u["password"]).json()


@pytest.fixture
def native_session(sso, pool_user):
    name, pw, attrs = pool_user
    body = sso.login_ok(name, pw).json()
    body["_username"] = name
    return body


@pytest.fixture(scope="session")
def real_kid(alice_session) -> str:
    return jwt_forge.header(alice_session["access_token"])["kid"]


class Manage:
    """Runs Python in the server's Django shell (white-box helper for a few cases)."""

    def __init__(self, cmd: str, cwd: str):
        self.cmd, self.cwd = cmd, cwd

    def shell(self, code: str) -> str:
        argv = shlex.split(self.cmd) + ["shell", "-c", code]
        p = subprocess.run(argv, cwd=self.cwd, capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr[-2000:]
        return p.stdout.strip()

    def user_field(self, username: str, field_name: str) -> str:
        return self.shell(
            "from django.contrib.auth.models import User;"
            f"print(getattr(User.objects.get(username={username!r}), {field_name!r}))"
        ).splitlines()[-1]

    def set_user(self, username: str, **fields):
        assigns = ";".join(f"u.{k}={v!r}" for k, v in fields.items())
        self.shell("from django.contrib.auth.models import User;"
                   f"u=User.objects.get(username={username!r});{assigns};u.save()")


@pytest.fixture(scope="session")
def manage(cfg) -> Manage:
    if not cfg.manage_cmd:
        pytest.skip("SSO_MANAGE_CMD not set (e.g. 'docker compose exec -T web python manage.py')")
    return Manage(cfg.manage_cmd, cfg.repo_dir)


@pytest.fixture(scope="session")
def verifier(cfg):
    if not cfg.verifier_url:
        pytest.skip("VERIFIER_BASE_URL not set (examples/verifier demo not running)")
    return cfg.verifier_url.rstrip("/")
