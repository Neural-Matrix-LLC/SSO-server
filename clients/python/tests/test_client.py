import asyncio
import logging

import httpx
import pytest

from sso_client import (
    CheckResult, NotAuthenticated, PermissionDenied, SSOConfig, SSOConfigError, SSOProtocolError, SSOUnavailable,
    TTLCache, TokenInactive, bearer_token, error_response,
)
from sso_client.testing import FakeSSO

A, B = "203.0.113.7", "198.51.100.9"


def test_check_active_and_permissions():
    fake = FakeSSO()
    tok = fake.issue("alice", perms=["application.app1"], ip=A, groups=["g"])
    c = fake.client()
    r = c.check(tok, A, require=["application.app1"])
    assert r.active and r.user.username == "alice" and r.user.groups == ("g",)
    assert r.permissions == {"application.app1"} and r.has("application.app1") and not r.has("application.x")
    assert r.ip_binding == "NOIP" and r.ip_match is None and r.session_id and r.expires_at
    assert fake.calls[-1] == {"token": tok, "ip": A}  # require is checked locally (cacheable)
    with pytest.raises(PermissionDenied) as e:
        c.check(tok, A, require="application.app2")
    assert e.value.missing == ("application.app2",)


def test_ip_normalised_and_missing_ip_absent():
    fake = FakeSSO()
    tok = fake.issue(ip=A)
    c = fake.client()
    c.check(tok, f"[::ffff:{A}]:443")
    assert fake.calls[-1]["ip"] == A
    c.check(tok, None)
    assert "ip" not in fake.calls[-1]


def test_inactive_raises_and_is_never_cached():
    fake = FakeSSO()
    tok = fake.issue()
    c = fake.client()
    fake.revoke(tok)
    for _ in range(2):
        with pytest.raises(TokenInactive):
            c.check(tok, A)
    assert len(fake.calls) == 2
    with pytest.raises(TokenInactive):
        c.check("unknown", A)
    with pytest.raises(NotAuthenticated):
        c.check("", A)


def test_cache_active_30s_keyed_by_ip():
    fake = FakeSSO()
    tok = fake.issue(perms=["p"])
    c = fake.client()
    c.check(tok, A), c.check(tok, A)
    assert len(fake.calls) == 1
    c.check(tok, B)  # other IP: other key
    assert len(fake.calls) == 2
    fake.revoke(tok)
    assert c.check(tok, A).active  # served from cache within the TTL (documented trade-off)
    with pytest.raises(PermissionDenied):
        c.check(tok, A, require=["q"])  # permissions checked against the cached set


def test_cache_ttl_capped_and_respects_exp():
    now = [1000.0]
    cache = TTLCache(ttl=30, clock=lambda: now[0])
    from datetime import datetime, timezone
    r = CheckResult(active=True, expires_at=datetime.fromtimestamp(1010, tz=timezone.utc))
    cache.set("k", r)
    now[0] = 1009
    assert cache.get("k") is r
    now[0] = 1010
    assert cache.get("k") is None
    cache.set("k2", CheckResult(active=True))
    now[0] = 1039.9
    assert cache.get("k2") is not None
    now[0] = 1040.1
    assert cache.get("k2") is None
    cache.set("dead", CheckResult(active=False))
    assert cache.get("dead") is None
    cache.set("past", CheckResult(active=True, expires_at=datetime.fromtimestamp(5, tz=timezone.utc)))
    assert cache.get("past") is None
    small = TTLCache(ttl=30, maxsize=2)
    for k in "abc":
        small.set(k, CheckResult(active=True))
    assert small.get("a") is None and small.get("c") is not None
    small.clear()
    assert small.get("c") is None
    assert SSOConfig("https://x", "i", "s", cache_ttl=300).cache_ttl == 30.0
    assert TTLCache(ttl=0).get("x") is None


def test_cache_disabled():
    fake = FakeSSO()
    tok = fake.issue()
    c = fake.client(cache_ttl=0)
    c.check(tok, A), c.check(tok, A)
    assert len(fake.calls) == 2


@pytest.mark.parametrize("mode", ["WARNING", "ENFORCE"])
def test_ip_binding_modes(mode, caplog):
    fake = FakeSSO(mode)
    tok = fake.issue(ip=A)
    c = fake.client(cache_ttl=0)
    assert c.check(tok, A).ip_match is True
    caplog.set_level(logging.INFO, logger="sso_client")
    if mode == "WARNING":
        r = c.check(tok, B)
        assert r.active and r.ip_match is False
        assert any("ip_mismatch" in m for m in caplog.messages) and tok not in caplog.text
    else:
        with pytest.raises(TokenInactive):
            c.check(tok, B)
        with pytest.raises(TokenInactive):
            c.check(tok, A)  # session revoked


def test_fail_closed_and_retries():
    fake = FakeSSO()
    tok = fake.issue()
    c = fake.client(retries=2)
    fake.down()
    with pytest.raises(SSOUnavailable):
        c.check(tok, A)
    fake.up()
    for status in (500, 502, 429):
        fake.status = status
        with pytest.raises(SSOUnavailable):
            c.check(tok, A)
    fake.status = 401
    with pytest.raises(SSOProtocolError) as e:
        c.check(tok, A)
    assert e.value.status_code == 401
    fake.up()
    assert c.check(tok, A).active


def test_retry_then_success_and_timeout():
    seen = []

    def handler(request):
        seen.append(1)
        if len(seen) == 1:
            raise httpx.ConnectTimeout("t")
        if len(seen) == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"active": True, "sub": "1", "perms": []})

    from sso_client import SSOClient
    c = SSOClient(SSOConfig("https://sso.t", "i", "s"), http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert c.check("t", A).active and len(seen) == 3
    c.close()


@pytest.mark.parametrize("resp", [httpx.Response(200, text="nope"), httpx.Response(200, json=[1]),
                                  httpx.Response(404, json={})])
def test_protocol_errors(resp):
    from sso_client import SSOClient
    c = SSOClient(SSOConfig("https://sso.t", "i", "s"),
                  http=httpx.Client(transport=httpx.MockTransport(lambda r: resp)))
    with pytest.raises(SSOProtocolError):
        c.check("t", A)


def test_wrong_credentials():
    fake = FakeSSO()
    tok = fake.issue()
    from sso_client import SSOClient
    c = SSOClient(SSOConfig("https://sso.fake.test", "fake-service", "wrong"),
                  http=httpx.Client(transport=fake.transport))
    with pytest.raises(SSOProtocolError):
        c.check(tok, A)


def test_async_client():
    fake = FakeSSO("ENFORCE")
    tok = fake.issue(perms=["p"], ip=A)

    async def run():
        c = fake.async_client()
        r = await c.check(tok, A, require=["p"])
        await c.check(tok, A)
        assert len(fake.calls) == 1
        with pytest.raises(PermissionDenied):
            await c.check(tok, A, require=["q"])
        fake.down()
        with pytest.raises(SSOUnavailable):
            await c.check(fake.issue(), A)
        fake.up()
        fake.status = 503
        with pytest.raises(SSOUnavailable):
            await c.check(fake.issue(), A)
        await c.aclose()
        return r

    assert asyncio.run(run()).active


def test_config_from_env(tmp_path):
    f = tmp_path / "s"
    f.write_text("file-secret\n")
    cfg = SSOConfig.from_env({"SSO_BASE_URL": "https://sso.x/", "SSO_CLIENT_ID": "svc", "SSO_CLIENT_SECRET_FILE": str(f),
                              "SSO_TRUSTED_PROXIES": "10.0.0.0/8", "SSO_TIMEOUT": "1.5", "SSO_CACHE_TTL": "10"})
    assert cfg.base_url == "https://sso.x" and cfg.client_secret == "file-secret" and cfg.timeout == 1.5
    assert cfg.introspect_url == "https://sso.x/api/v1/auth/introspect" and str(cfg.trusted_proxies[0]) == "10.0.0.0/8"
    assert "file-secret" not in repr(cfg)
    for env in ({}, {"SSO_BASE_URL": "http://sso.x", "SSO_CLIENT_ID": "a", "SSO_CLIENT_SECRET": "b"},
                {"SSO_BASE_URL": "https://sso.x", "SSO_CLIENT_ID": "a", "SSO_CLIENT_SECRET": "b", "SSO_TIMEOUT": "x"},
                {"SSO_BASE_URL": "https://sso.x", "SSO_CLIENT_ID": "a", "SSO_CLIENT_SECRET": "b",
                 "SSO_TRUSTED_PROXIES": "0.0.0.0/0"},
                {"SSO_BASE_URL": "https://sso.x", "SSO_CLIENT_ID": "a", "SSO_CLIENT_SECRET_FILE": "/nonexistent"},
                {"SSO_BASE_URL": "https://sso.x", "SSO_CLIENT_ID": "a", "SSO_CLIENT_SECRET": "b", "SSO_RETRIES": "-1"}):
        with pytest.raises(SSOConfigError):
            SSOConfig.from_env(env)
    assert SSOConfig.from_env({"SSO_BASE_URL": "http://l", "SSO_CLIENT_ID": "a", "SSO_CLIENT_SECRET": "b",
                               "SSO_ALLOW_HTTP": "true"}).base_url == "http://l"


def test_bearer_and_error_response():
    assert bearer_token("Bearer abc") == "abc" and bearer_token("bearer abc") == "abc"
    assert bearer_token(None) is None and bearer_token("Basic x") is None and bearer_token("Bearer") is None
    assert error_response(NotAuthenticated())[0] == 401
    assert error_response(TokenInactive("x"))[1] == {"detail": "token_inactive", "reason": "x"}
    assert error_response(PermissionDenied(["p"]))[:2] == (403, {"detail": "permission_denied", "missing": ["p"]})
    assert error_response(SSOUnavailable()) == (503, {"detail": "sso_unavailable"}, {"Retry-After": "5"})


def test_pytest_plugin_fixtures(fake_sso, sso_client):
    tok = fake_sso.issue(perms=["p"])
    assert sso_client.check(tok, A, ["p"]).active
