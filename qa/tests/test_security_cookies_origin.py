"""SEC-20..SEC-28: refresh cookie flags, Origin/CSRF check for cookie mode (addendum B9), CORS."""
import pytest

from helpers import assert_error
from sso_client import LOGIN, REFRESH, refresh_cookie

BAD_ORIGINS = ["https://evil.example", "null"]  # plus variants derived from the allowed origin below


def _bad_origins(cfg):
    out = [o for o in BAD_ORIGINS if o != cfg.allowed_origin]
    if cfg.allowed_origin.startswith("https://"):
        out.append("http://" + cfg.allowed_origin[len("https://"):])
    out.append(cfg.allowed_origin + ".evil.example")              # suffix attack
    host = cfg.allowed_origin.split("://", 1)[-1]
    scheme = cfg.allowed_origin.split("://", 1)[0]
    out.append(f"{scheme}://evil{host}")                           # prefix attack
    if ":" not in host:
        out.append(f"{cfg.allowed_origin}:4444")                   # port mismatch
    out.append(cfg.allowed_origin + "/")                           # not an exact origin string
    return sorted(set(o for o in out if o != cfg.allowed_origin))


@pytest.fixture
def browser_cookie(sso, cfg, pool_user):
    name, pw, _ = pool_user
    r = sso.login_ok(name, pw, client="browser", origin=cfg.allowed_origin)
    return refresh_cookie(r)


def _assert_flags(c, cfg):
    assert c is not None
    assert c.httponly, f"HttpOnly missing: {c.raw}"
    assert c.secure, f"Secure missing: {c.raw}"
    assert c.attrs.get("samesite", "").lower() == "lax", c.raw
    assert c.attrs.get("path") == "/api/v1/auth/", c.raw
    assert int(c.attrs.get("max-age", -1)) == cfg.refresh_ttl_s, c.raw
    if cfg.cookie_domain is not None:
        if cfg.cookie_domain == "":
            assert "domain" not in c.attrs, c.raw
        else:
            assert c.attrs.get("domain", "").lstrip(".") == cfg.cookie_domain.lstrip("."), c.raw


def test_SEC_20_login_cookie_flags(browser_cookie, cfg):
    _assert_flags(browser_cookie, cfg)


def test_SEC_21_rotated_cookie_flags(sso, cfg, browser_cookie):
    r = sso.refresh_cookie(browser_cookie.value, origin=cfg.allowed_origin)
    assert r.status_code == 200
    _assert_flags(refresh_cookie(r), cfg)


def test_SEC_22_cookie_refresh_without_origin_403(sso, cfg, browser_cookie):
    assert_error(sso.refresh_cookie(browser_cookie.value), 403, "origin_not_allowed")
    # rejected request must not consume/rotate the token
    assert sso.refresh_cookie(browser_cookie.value, origin=cfg.allowed_origin).status_code == 200


def test_SEC_23_cookie_refresh_with_bad_origin_403(sso, cfg, browser_cookie):
    for origin in _bad_origins(cfg):
        assert_error(sso.refresh_cookie(browser_cookie.value, origin=origin), 403, "origin_not_allowed")
    assert sso.refresh_cookie(browser_cookie.value, origin=cfg.allowed_origin).status_code == 200


def test_SEC_24_referer_is_not_a_substitute_for_origin(sso, cfg, browser_cookie):
    r = sso.post(REFRESH, json={}, cookie=browser_cookie.value, headers={"Referer": cfg.allowed_origin + "/"})
    assert_error(r, 403, "origin_not_allowed")


def test_SEC_25_cookie_logout_origin_check(sso, cfg, browser_cookie):
    assert_error(sso.logout_cookie(browser_cookie.value), 403, "origin_not_allowed")
    for origin in _bad_origins(cfg):
        assert_error(sso.logout_cookie(browser_cookie.value, origin=origin), 403, "origin_not_allowed")
    # session survived the forged logouts
    assert sso.refresh_cookie(browser_cookie.value, origin=cfg.allowed_origin).status_code == 200


def test_SEC_26_body_token_requests_skip_origin_check(sso, native_session):
    r = sso.refresh_native(native_session["refresh_token"])  # no Origin
    assert r.status_code == 200, r.text
    r = sso.refresh_native(r.json()["refresh_token"], origin="https://evil.example")
    assert r.status_code == 200, r.text
    assert sso.logout_native(r.json()["refresh_token"], origin="https://evil.example").status_code == 204


def test_SEC_27_cors_preflight(sso, cfg):
    for path in (LOGIN, REFRESH):
        ok = sso.request("OPTIONS", path, headers={
            "Origin": cfg.allowed_origin, "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type"})
        assert ok.status_code in (200, 204)
        assert ok.headers.get("Access-Control-Allow-Origin") == cfg.allowed_origin
        assert ok.headers.get("Access-Control-Allow-Credentials") == "true"
        assert "content-type" in ok.headers.get("Access-Control-Allow-Headers", "").lower()
        bad = sso.request("OPTIONS", path, headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        assert bad.headers.get("Access-Control-Allow-Origin") not in ("https://evil.example", "*")


def test_SEC_28_cors_on_actual_response(sso, cfg, pool_user):
    name, pw, _ = pool_user
    r = sso.login_ok(name, pw, client="browser", origin=cfg.allowed_origin)
    assert r.headers.get("Access-Control-Allow-Origin") == cfg.allowed_origin
    assert r.headers.get("Access-Control-Allow-Credentials") == "true"
    r = sso.login("qa_alice", "nope", origin="https://evil.example")
    assert r.headers.get("Access-Control-Allow-Origin") not in ("https://evil.example", "*")
