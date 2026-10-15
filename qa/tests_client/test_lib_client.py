"""LIB-CHK / LIB-CACHE / LIB-FAIL: SSOClient + AsyncSSOClient against a live SSO (and stub servers for failures)."""
from __future__ import annotations

import asyncio
import http.server
import logging
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from conftest import SVC, login
from sso_client import AsyncSSOClient, CheckResult, SSOClient, SSOConfig
from sso_client.cache import TTLCache
from sso_client.errors import (NotAuthenticated, PermissionDenied, SSOConfigError, SSOProtocolError,
                               SSOUnavailable, TokenInactive)

STUB, CLOSED = 8067, 8068


class Counter:
    def __init__(self):
        self.n = 0

    def __call__(self, request):
        self.n += 1


def client(base, *, counter=None, cache=None, **kw):
    hooks = {"request": [counter]} if counter else {}
    cfg = SSOConfig(base_url=base, client_id=SVC[0], client_secret=SVC[1], allow_http=True, **kw)
    return SSOClient(cfg, http=httpx.Client(event_hooks=hooks), cache=cache)


# --------------------------------------------------------------------------- check()
def test_V12B_LIB_CHK_01_active_bound_and_require(sso_enf, mk_user):
    name = mk_user("chk", perms=["app1"])
    tok = login(sso_enf, name, xff="203.0.113.80")["access_token"]
    c = client(sso_enf)
    r = c.check(tok, "203.0.113.80", require=["application.app1"])
    assert r.active and r.ip_match is True and r.ip_binding == "ENFORCE" and r.user.username == name
    assert r.has("application.app1") and r.session_id and r.expires_at > datetime.now(timezone.utc)
    with pytest.raises(PermissionDenied) as e:
        c.check(tok, "203.0.113.80", require="application.app2")
    assert e.value.missing == ("application.app2",)


def test_V12B_LIB_CHK_02_enforce_mismatch_inactive_and_missing_ip(sso_enf, mk_user):
    name = mk_user("chk2")
    tok = login(sso_enf, name, xff="203.0.113.81")["access_token"]
    with pytest.raises(TokenInactive):
        client(sso_enf).check(tok, "198.51.100.81")
    with pytest.raises(TokenInactive):            # session revoked: the right IP is now inactive too
        client(sso_enf).check(tok, "203.0.113.81")
    tok2 = login(sso_enf, name, xff="203.0.113.81")["access_token"]
    with pytest.raises(TokenInactive):            # no client IP -> sent as absent -> mismatch
        client(sso_enf).check(tok2, None)


def test_V12B_LIB_CHK_03_noip_and_bad_inputs(sso_noip, mk_user):
    name = mk_user("chk3")
    tok = login(sso_noip, name)["access_token"]
    r = client(sso_noip).check(tok, None)
    assert r.active and r.ip_match is None and r.ip_binding == "NOIP"
    for bad in ("", None):
        with pytest.raises(NotAuthenticated):
            client(sso_noip).check(bad, "1.2.3.4")
    with pytest.raises(TokenInactive):
        client(sso_noip).check("garbage", "1.2.3.4")


def test_V12B_LIB_CHK_04_async_client_same_semantics(sso_enf, mk_user):
    name = mk_user("achk", perms=["app1"])
    tok = login(sso_enf, name, xff="203.0.113.82")["access_token"]

    async def go():
        cfg = SSOConfig(base_url=sso_enf, client_id=SVC[0], client_secret=SVC[1], allow_http=True)
        ac = AsyncSSOClient(cfg)
        try:
            r = await ac.check(tok, "203.0.113.82", "application.app1")
            assert r.active and r.ip_match is True
            with pytest.raises(PermissionDenied):
                await ac.check(tok, "203.0.113.82", "application.app2")
        finally:
            await ac.aclose()
    asyncio.run(go())


def test_V12B_LIB_CHK_05_wrong_service_secret_fails_closed(sso_noip, mk_user):
    tok = login(sso_noip, mk_user("sec"))["access_token"]
    cfg = SSOConfig(base_url=sso_noip, client_id=SVC[0], client_secret="wrong", allow_http=True)
    with pytest.raises(SSOProtocolError) as e:
        SSOClient(cfg).check(tok, None)
    assert e.value.status_code == 401          # c4a3fde: bad credentials distinguishable


# --------------------------------------------------------------------------- cache
def test_V12B_LIB_CACHE_01_active_cached_require_checked_locally(sso_enf, mk_user):
    name = mk_user("cache", perms=["app1"])
    tok = login(sso_enf, name, xff="203.0.113.83")["access_token"]
    cnt = Counter()
    c = client(sso_enf, counter=cnt)
    c.check(tok, "203.0.113.83")
    c.check(tok, "203.0.113.83", require="application.app1")
    with pytest.raises(PermissionDenied):
        c.check(tok, "203.0.113.83", require="application.app2")
    assert cnt.n == 1
    c.check(tok, "::ffff:203.0.113.83")          # normalised -> same key
    assert cnt.n == 1


def test_V12B_LIB_CACHE_02_inactive_never_cached(sso_noip, mk_user):
    cnt = Counter()
    c = client(sso_noip, counter=cnt)
    for _ in range(3):
        with pytest.raises(TokenInactive):
            c.check("garbage", None)
    assert cnt.n == 3


def test_V12B_LIB_CACHE_03_ttl_30s_cap_and_clock(sso_noip, mk_user):
    tok = login(sso_noip, mk_user("ttl"))["access_token"]
    now = [time.time()]
    cnt = Counter()
    cfg_ttl = SSOConfig(base_url=sso_noip, client_id=SVC[0], client_secret=SVC[1], allow_http=True, cache_ttl=300)
    assert cfg_ttl.cache_ttl == 30
    c = client(sso_noip, counter=cnt, cache=TTLCache(30, clock=lambda: now[0]))
    c.check(tok, None)
    now[0] += 29.9
    c.check(tok, None)
    assert cnt.n == 1
    now[0] += 0.2
    c.check(tok, None)
    assert cnt.n == 2
    c0 = client(sso_noip, counter=cnt, cache_ttl=0)
    c0.check(tok, None); c0.check(tok, None)
    assert cnt.n == 4


def test_V12B_LIB_CACHE_04_never_past_exp():
    now = [1_000_000.0]
    cache = TTLCache(30, clock=lambda: now[0])
    r = CheckResult(active=True, expires_at=datetime.fromtimestamp(now[0] + 5, tz=timezone.utc))
    cache.set("k", r)
    now[0] += 4.9
    assert cache.get("k") is r
    now[0] += 0.2
    assert cache.get("k") is None
    cache.set("e", CheckResult(active=True, expires_at=datetime.fromtimestamp(now[0] - 1, tz=timezone.utc)))
    assert cache.get("e") is None
    cache.set("i", CheckResult(active=False))
    assert cache.get("i") is None


def test_V12B_LIB_CACHE_05_other_ip_is_a_miss_cached_good_ip_stale_up_to_ttl(sso_enf, mk_user):
    """Documented trade-off: after an ENFORCE revocation the service's own cached active answer for the
    legitimate IP lives on for <= 30 s; the other IP is a separate key and reaches the SSO."""
    tok = login(sso_enf, mk_user("stale"), xff="203.0.113.84")["access_token"]
    cnt = Counter()
    c = client(sso_enf, counter=cnt)
    c.check(tok, "203.0.113.84")
    with pytest.raises(TokenInactive):
        c.check(tok, "198.51.100.84")
    assert cnt.n == 2
    assert c.check(tok, "203.0.113.84").active          # cached (stale) for <= 30 s
    with pytest.raises(TokenInactive):
        client(sso_enf).check(tok, "203.0.113.84")      # fresh client: revoked


# --------------------------------------------------------------------------- fail closed
class Stub(http.server.BaseHTTPRequestHandler):
    status, hits, sleep = 500, 0, 0.0

    def do_POST(self):
        type(self).hits += 1
        if type(self).sleep:
            time.sleep(type(self).sleep)
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"x"}' if type(self).status != 200 else b'not json')

    def log_message(self, *a):
        pass


@pytest.fixture
def stub():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", STUB), Stub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    Stub.hits, Stub.sleep = 0, 0.0
    yield Stub
    srv.shutdown(); srv.server_close()


@pytest.mark.parametrize("status,hits,exc", [(500, 1, SSOUnavailable), (502, 2, SSOUnavailable),
                                             (503, 2, SSOUnavailable), (504, 2, SSOUnavailable),
                                             (429, 1, SSOUnavailable), (400, 1, SSOProtocolError),
                                             (200, 1, SSOProtocolError)])
def test_V12B_LIB_FAIL_01_status_handling(stub, status, hits, exc):
    stub.status = status
    c = client(f"http://127.0.0.1:{STUB}")
    with pytest.raises(exc):
        c.check("tok", "1.2.3.4")
    assert stub.hits == hits, stub.hits


def test_V12B_LIB_FAIL_02_connection_refused_retries_then_unavailable():
    with socket.socket() as s:
        assert s.connect_ex(("127.0.0.1", CLOSED)) != 0, "port 8068 must be closed"
    t0 = time.monotonic()
    with pytest.raises(SSOUnavailable):
        client(f"http://127.0.0.1:{CLOSED}").check("tok", "1.2.3.4")
    assert 0.08 < time.monotonic() - t0 < 2, "1 retry (b3dbd2a default, accepted) with 0.1 s backoff + jitter"


def test_V12B_LIB_FAIL_03_timeout_bounded(stub):
    stub.status, stub.sleep = 200, 3.0
    t0 = time.monotonic()
    with pytest.raises(SSOUnavailable):
        client(f"http://127.0.0.1:{STUB}", timeout=0.5, retries=1).check("tok", "1.2.3.4")
    took = time.monotonic() - t0
    assert stub.hits == 2 and took < 2.5, (stub.hits, took)


def test_V12B_LIB_FAIL_04_no_secrets_in_logs(sso_noip, mk_user, caplog):
    tok = login(sso_noip, mk_user("log"))["access_token"]
    with caplog.at_level(logging.DEBUG):
        client(sso_noip).check(tok, None)
        with pytest.raises(SSOUnavailable):
            client(f"http://127.0.0.1:{CLOSED}").check(tok, None)
    text = caplog.text
    assert tok not in text and SVC[1] not in text and "Basic " not in text
    assert "sso_check" in text


@pytest.mark.parametrize("kw", [dict(base_url="http://x"), dict(base_url=""), dict(client_secret=""),
                                dict(trusted_proxies="0.0.0.0/0"), dict(timeout=0), dict(retries=-1)])
def test_V12B_LIB_CFG_01_invalid_config(kw):
    base = dict(base_url="https://sso.example.test", client_id="c", client_secret="s")
    with pytest.raises(SSOConfigError):
        SSOConfig(**{**base, **kw})


def test_V12B_LIB_CFG_02_from_env_and_secret_file(tmp_path):
    f = tmp_path / "secret"; f.write_text("file-secret\n")
    cfg = SSOConfig.from_env({"SSO_BASE_URL": "https://sso.example.test/", "SSO_CLIENT_ID": "c",
                              "SSO_CLIENT_SECRET_FILE": str(f), "SSO_TRUSTED_PROXIES": "10.0.0.0/8",
                              "SSO_CACHE_TTL": "45"})
    assert cfg.client_secret == "file-secret" and cfg.base_url == "https://sso.example.test"
    assert cfg.cache_ttl == 30 and len(cfg.trusted_proxies) == 1
    assert "file-secret" not in repr(cfg)
