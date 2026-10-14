"""v1.2b: client-IP derivation (§4.5), IP binding (§4.2), introspect permission query (§4.4), revoked-session
cache and pruning."""
from __future__ import annotations

import io
import json
import logging
from datetime import timedelta

import jwt
import pytest
from django.core.cache import cache
from django.core.management import call_command
from django.test import RequestFactory
from django.utils import timezone

from sso.clientip import normalize_ip, parse_trusted, request_ip, walk_forwarded
from sso.ipbinding import cip_for
from sso.models import RevokedSession
from sso.revocation import is_session_revoked, prune_revoked_sessions, revoke_session

from .conftest import login
from .test_introspect import basic, service  # noqa: F401  (fixture)

pytestmark = pytest.mark.django_db
A, B = "203.0.113.7", "198.51.100.9"


# --------------------------------------------------------------------------- normalisation and XFF walk
@pytest.mark.parametrize("raw,want", [
    ("1.2.3.4", "1.2.3.4"), (" 1.2.3.4:5678 ", "1.2.3.4"), ("::ffff:1.2.3.4", "1.2.3.4"),
    ("[::FFFF:1.2.3.4]:80", "1.2.3.4"), ("2001:DB8:0:0::1", "2001:db8::1"), ("[2001:db8::1]:443", "2001:db8::1"),
    ("fe80::1%eth0", "fe80::1"), ('"10.0.0.1"', "10.0.0.1"), (("::1", 80, 0, 0), "::1"),
    ("", None), ("nope", None), (None, None), ("1.2.3.4.5", None), ("[::1", None), (42, None),
])
def test_normalize_ip(raw, want):
    assert normalize_ip(raw) == want


def test_parse_trusted():
    nets = parse_trusted("127.0.0.1, 172.18.0.0/16,,::ffff:10.0.0.0/104")
    assert [str(n) for n in nets] == ["127.0.0.1/32", "172.18.0.0/16", "10.0.0.0/8"]
    assert parse_trusted(None) == () and parse_trusted(nets) == nets
    with pytest.raises(ValueError):
        parse_trusted("0.0.0.0/0")
    with pytest.raises(ValueError):
        parse_trusted("bogus")


TRUSTED = parse_trusted("127.0.0.1,172.18.0.0/16")


@pytest.mark.parametrize("peer,xff,want", [
    (A, ["10.9.9.9"], A),                                   # untrusted peer: header ignored (spoof)
    ("127.0.0.1", [], "127.0.0.1"),                          # trusted, no header
    ("127.0.0.1", [f"10.9.9.9, {A}"], A),                    # rightmost untrusted wins, spoofed left ignored
    ("127.0.0.1", [f"{A}, 172.18.0.5"], A),                  # skip trusted hops
    ("127.0.0.1", ["172.18.0.5", "172.18.0.6"], "172.18.0.5"),  # all trusted: leftmost
    ("127.0.0.1", [f"{A}, junk, 172.18.0.5"], "172.18.0.5"),  # malformed: last good
    ("::ffff:127.0.0.1", [f"::ffff:{A}"], A),                 # mapped forms
    (None, [A], None),
])
def test_walk_forwarded(peer, xff, want):
    assert walk_forwarded(peer, xff, TRUSTED) == want


def test_request_ip_trusted_and_deprecated_fallback(settings):
    rf = RequestFactory()
    req = rf.get("/", REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR=f"10.1.1.1, {A}")
    settings.SSO_TRUSTED_PROXIES_PARSED = TRUSTED
    assert request_ip(req) == A
    req2 = rf.get("/", REMOTE_ADDR=B, HTTP_X_FORWARDED_FOR="10.1.1.1")
    assert request_ip(req2) == B
    settings.SSO_TRUSTED_PROXIES_PARSED = ()  # NUM_PROXIES=1 (settings_test): DRF hop count
    assert request_ip(req) == A


def test_request_ip_custom_header(settings):
    rf = RequestFactory()
    settings.SSO_TRUSTED_PROXIES_PARSED = TRUSTED
    settings.SSO_CLIENT_IP_HEADER = "cf-connecting-ip"
    assert request_ip(rf.get("/", REMOTE_ADDR="127.0.0.1", HTTP_CF_CONNECTING_IP=A,
                             HTTP_X_FORWARDED_FOR="9.9.9.9")) == A
    assert request_ip(rf.get("/", REMOTE_ADDR="127.0.0.1", HTTP_CF_CONNECTING_IP="bad",
                             HTTP_X_FORWARDED_FOR=B)) == B  # no valid IP in the header: XFF logic
    assert request_ip(rf.get("/", REMOTE_ADDR=B, HTTP_CF_CONNECTING_IP=A)) == B  # untrusted peer
    settings.SSO_CLIENT_IP_HEADER = "X-Forwarded-For"
    assert request_ip(rf.get("/", REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR=A)) == A


def test_deprecation_warning_w002(settings):
    from sso.checks import deprecated_num_proxies

    settings.SSO_TRUSTED_PROXIES_PARSED = ()
    assert [w.id for w in deprecated_num_proxies(None)] == ["sso.W002"]
    settings.SSO_TRUSTED_PROXIES_PARSED = TRUSTED
    assert deprecated_num_proxies(None) == []


# --------------------------------------------------------------------------- binding helpers
def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def _login(api, ip=A):
    r = login(api, REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR=ip)
    assert r.status_code == 200, r.content
    return r.json()


def _introspect(api, token, ip=None, **extra):
    body = {"token": token, **extra}
    if ip is not None:
        body["ip"] = ip
    return api.post("/api/v1/auth/introspect", body, format="json", **basic())


def _refresh(api, rt, ip):
    return api.post("/api/v1/auth/refresh", {"refresh_token": rt}, format="json",
                    REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR=ip)


def test_cip_is_keyed_hmac(settings):
    c = cip_for(A)
    assert c and "=" not in c and len(c) == 43 and cip_for("::ffff:" + A) == c and cip_for(B) != c
    assert cip_for(None) is None and cip_for("x") is None
    settings.SSO_IP_BINDING_KEY = b"other"
    assert cip_for(A) != c


def test_noip_default_no_cip_and_null_match(api, user, service):
    t = _login(api)
    assert "cip" not in _claims(t["access_token"]) and "cip" not in _claims(t["refresh_token"])
    body = _introspect(api, t["access_token"], B).json()
    assert body["active"] is True and body["ip_binding"] == "NOIP" and body["ip_match"] is None
    assert body["sid"] == _claims(t["access_token"])["sid"]


@pytest.mark.parametrize("mode", ["WARNING", "ENFORCE"])
def test_bound_token_matching_ip(api, user, service, settings, mode):
    settings.SSO_IP_BINDING_MODE = mode
    t = _login(api)
    assert _claims(t["access_token"])["cip"] == _claims(t["refresh_token"])["cip"] == cip_for(A)
    body = _introspect(api, t["access_token"], "::ffff:" + A).json()
    assert body["active"] is True and body["ip_binding"] == mode and body["ip_match"] is True
    r = _refresh(api, t["refresh_token"], A)
    assert r.status_code == 200 and _claims(r.json()["access_token"])["cip"] == cip_for(A)


def test_warning_mismatch_allowed_and_logged(api, user, service, settings, caplog):
    settings.SSO_IP_BINDING_MODE = "WARNING"
    caplog.set_level(logging.WARNING, logger="sso.auth")
    t = _login(api)
    for ip in (B, None, "garbage"):
        body = _introspect(api, t["access_token"], ip).json()
        assert body["active"] is True and body["ip_match"] is False
    events = [json.loads(r.getMessage()) for r in caplog.records if "ip_mismatch" in r.getMessage()]
    assert len(events) == 3 and events[0]["where"] == "introspect" and events[0]["client_id"] == "rebalance-api"
    r = _refresh(api, t["refresh_token"], B)  # allowed, binding kept (no rebind)
    assert r.status_code == 200 and _claims(r.json()["access_token"])["cip"] == cip_for(A)
    assert not RevokedSession.objects.exists()


@pytest.mark.parametrize("ip", [B, None])
def test_enforce_introspect_mismatch_revokes_session(api, user, service, settings, ip):
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    t = _login(api)
    other = _login(api)  # another session of the same user survives
    assert _introspect(api, t["access_token"], ip).json() == {"active": False}
    rs = RevokedSession.objects.get()
    assert rs.reason == "ip_mismatch" and rs.sid == _claims(t["access_token"])["sid"]
    assert _introspect(api, t["access_token"], A).json() == {"active": False}  # session dead, also from A
    assert _refresh(api, t["refresh_token"], A).status_code == 401
    assert _introspect(api, other["access_token"], A).json()["active"] is True


def test_enforce_refresh_mismatch_revokes_session(api, user, service, settings):
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    t = _login(api)
    r = _refresh(api, t["refresh_token"], B)
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"
    assert RevokedSession.objects.get().reason == "ip_mismatch"
    assert _introspect(api, t["access_token"], A).json() == {"active": False}


def test_noip_token_gets_bound_on_refresh_after_switch(api, user, service, settings):
    t = _login(api)  # NOIP: unbound
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    assert _introspect(api, t["access_token"], B).json()["ip_match"] is None  # unbound until it expires
    r = _refresh(api, t["refresh_token"], B)
    assert r.status_code == 200 and _claims(r.json()["refresh_token"])["cip"] == cip_for(B)
    settings.SSO_IP_BINDING_MODE = "NOIP"
    r2 = _refresh(api, r.json()["refresh_token"], A)
    assert r2.status_code == 200 and "cip" not in _claims(r2.json()["access_token"])


def test_delegated_login_binds_browser_ip(api, user, service, settings):
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    r = api.post("/api/v1/auth/login", {"username": "thomas", "password": "Correct-Horse-9", "client": "native",
                                        "client_ip": "[2001:DB8::7]:5"}, format="json",
                 REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="10.0.0.5", **basic())
    assert r.status_code == 200
    assert _claims(r.json()["access_token"])["cip"] == cip_for("2001:db8::7")


def test_introspect_require(api, user, service):
    from application.permissions import ensure_permission

    user.user_permissions.add(ensure_permission("app2", "Can use app2")[0])
    t = _login(api)
    assert _introspect(api, t["access_token"], require="application.app2").json()["allowed"] is True
    assert _introspect(api, t["access_token"], require=["application.app2", "application.app9"]).json()[
        "allowed"] is False
    assert "allowed" not in _introspect(api, t["access_token"]).json()
    for bad in ([], 5, [""], {"a": 1}):
        assert _introspect(api, t["access_token"], require=bad).status_code == 400


def test_introspect_throttle_per_client(api, user, service, monkeypatch):
    from sso.throttles import IntrospectThrottle

    monkeypatch.setattr(IntrospectThrottle, "THROTTLE_RATES", {"introspect": "2/min"})
    t = _login(api)
    assert [_introspect(api, t["access_token"]).status_code for _ in range(3)] == [200, 200, 429]
    # no Basic auth: no throttle key, 401 as before
    assert api.post("/api/v1/auth/introspect", {"token": "x"}, format="json").status_code == 401


def test_introspect_rate_setting():
    from rest_framework.settings import api_settings

    assert api_settings.DEFAULT_THROTTLE_RATES["introspect"] == "6000/min"


# --------------------------------------------------------------------------- revoked sessions: cache + prune
def test_revoked_session_cache(user, django_assert_num_queries):
    assert is_session_revoked("s-1") is False
    with django_assert_num_queries(0):
        assert is_session_revoked("s-1") is False  # negative answer cached briefly
    revoke_session(user, "s-1", "test")  # writes the cache at once
    with django_assert_num_queries(0):
        assert is_session_revoked("s-1") is True
    assert is_session_revoked(None) is False and is_session_revoked("") is False


def test_revoked_session_cache_errors_fall_back_to_db(user, monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("redis down")

    monkeypatch.setattr(cache, "get", boom)
    monkeypatch.setattr(cache, "set", boom)
    revoke_session(user, "s-2", "test")
    assert is_session_revoked("s-2") is True and is_session_revoked("s-3") is False


def test_negative_cache_can_be_disabled(user, settings, django_assert_num_queries):
    settings.SSO_REVOKED_SESSION_CACHE_SECONDS = 0
    assert is_session_revoked("s-4") is False
    with django_assert_num_queries(1):
        assert is_session_revoked("s-4") is False


def test_prune_in_sweep(user, settings):
    old = timezone.now() - settings.SSO_REFRESH_TTL - timedelta(days=1, minutes=1)
    RevokedSession.objects.create(sid="old", user=user, reason="x", revoked_at=old)
    RevokedSession.objects.create(sid="edge", user=user, reason="x",
                                  revoked_at=timezone.now() - settings.SSO_REFRESH_TTL)
    out = io.StringIO()
    call_command("revoke_inactive_users", "--dry-run", stdout=out)
    assert "would prune 1 expired revoked-session row(s)" in out.getvalue()
    assert RevokedSession.objects.count() == 2
    out = io.StringIO()
    call_command("revoke_inactive_users", stdout=out)
    assert "pruned 1 expired" in out.getvalue()
    assert list(RevokedSession.objects.values_list("sid", flat=True)) == ["edge"]
    assert prune_revoked_sessions() == 0


@pytest.mark.parametrize("over", [{"exp": "9999999999"}, {"sub": "not-a-number"}, {"iat": "x"}])
def test_introspect_malformed_claims_are_inactive_not_500(api, user, service, over):
    from .conftest import claims, sign

    r = _introspect(api, sign(claims(user.pk, **over)))
    assert r.status_code == 200 and r.json() == {"active": False}
