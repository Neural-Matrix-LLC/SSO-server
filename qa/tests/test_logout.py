"""LOGOUT-xx: POST /api/v1/auth/logout (spec 6.3, addendum B9)."""
import pytest

from helpers import assert_error
from sso_client import LOGOUT, refresh_cookie


def test_LOGOUT_01_native_logout_204_and_blacklists(sso, native_session):
    r = sso.logout_native(native_session["refresh_token"])
    assert r.status_code == 204, r.text
    assert r.content in (b"", None)
    assert_error(sso.refresh_native(native_session["refresh_token"]), 401, "token_invalid")


def test_LOGOUT_02_cookie_logout_clears_cookie_and_blacklists(sso, cfg, pool_user):
    name, pw, _ = pool_user
    c = refresh_cookie(sso.login_ok(name, pw, client="browser", origin=cfg.allowed_origin))
    r = sso.logout_cookie(c.value, origin=cfg.allowed_origin)
    assert r.status_code == 204, r.text
    cleared = refresh_cookie(r)
    assert cleared is not None, "logout must send a Set-Cookie that clears sso_refresh"
    assert cleared.value == ""
    max_age = cleared.attrs.get("max-age")
    expires = cleared.attrs.get("expires", "")
    assert (max_age is not None and int(max_age) <= 0) or "1970" in expires, cleared.raw
    assert cleared.attrs.get("path") == "/api/v1/auth/", "clearing cookie must use the same Path"
    if cfg.cookie_domain:
        assert cleared.attrs.get("domain", "").lstrip(".") == cfg.cookie_domain.lstrip(".")
    assert_error(sso.refresh_cookie(c.value, origin=cfg.allowed_origin), 401, "token_invalid")


def test_LOGOUT_03_access_token_still_valid_after_logout(sso, native_session):
    """Spec 6.3: issued access tokens stay valid until expiry (<= 15 min)."""
    assert sso.logout_native(native_session["refresh_token"]).status_code == 204
    assert sso.me(native_session["access_token"]).status_code == 200


def test_LOGOUT_04_access_token_rejected_at_logout(sso, native_session):
    assert_error(sso.logout_native(native_session["access_token"]), 401, "token_invalid")
    # and the session's refresh token is untouched
    assert sso.refresh_native(native_session["refresh_token"]).status_code == 200


def test_LOGOUT_05_no_token(sso, cfg):
    """Q-05 resolved (Philip, 2026-10-10): cookie-mode logout without a token is idempotent ->
    204 and the sso_refresh cookie is cleared."""
    r = sso.post(LOGOUT, json={}, origin=cfg.allowed_origin)
    assert r.status_code == 204, r.text
    assert r.content in (b"", None)
    cleared = refresh_cookie(r)
    assert cleared is not None and cleared.value == "", "logout must clear sso_refresh"
    max_age = cleared.attrs.get("max-age")
    assert (max_age is not None and int(max_age) <= 0) or "1970" in cleared.attrs.get("expires", ""), cleared.raw
    assert cleared.attrs.get("path") == "/api/v1/auth/"


def test_LOGOUT_05b_no_token_without_origin_still_origin_checked(sso):
    """Cookie mode (no body token) is Origin-checked before the idempotent 204 (addendum B9)."""
    assert_error(sso.post(LOGOUT, json={}), 403, "origin_not_allowed")


def test_LOGOUT_06_garbage_token(sso):
    assert_error(sso.logout_native("garbage"), 401, "token_invalid")


@pytest.mark.skip(reason="Q-06: spec does not say whether a second logout with an already-blacklisted "
                         "token is 204 (idempotent) or 401 token_invalid")
def test_LOGOUT_07_double_logout(sso, native_session):
    assert sso.logout_native(native_session["refresh_token"]).status_code == 204
    r = sso.logout_native(native_session["refresh_token"])
    assert r.status_code in (204, 401)


def test_LOGOUT_08_logout_only_affects_that_session(sso, pool_user):
    name, pw, _ = pool_user
    a = sso.login_ok(name, pw).json()
    b = sso.login_ok(name, pw).json()
    assert sso.logout_native(a["refresh_token"]).status_code == 204
    assert sso.refresh_native(b["refresh_token"]).status_code == 200
