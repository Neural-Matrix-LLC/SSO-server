"""REFRESH-xx: POST /api/v1/auth/refresh (spec 6.2, addendum B8/B9)."""
import time

import pytest

import jwt_forge
import testdata
from helpers import assert_error, assert_token_response
from sso_client import REFRESH, refresh_cookie


def test_REFRESH_01_native_refresh_returns_new_pair(sso, cfg, native_session):
    r = sso.refresh_native(native_session["refresh_token"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert_token_response(body, expect_refresh_in_body=True, access_ttl_s=cfg.access_ttl_s)
    assert body["refresh_token"] != native_session["refresh_token"], "refresh token must rotate"
    assert body["access_token"] != native_session["access_token"]
    assert body["user"]["username"] == native_session["_username"]
    assert refresh_cookie(r) is None


def test_REFRESH_02_reuse_of_rotated_token_rejected(sso, native_session):
    old = native_session["refresh_token"]
    assert sso.refresh_native(old).status_code == 200
    assert_error(sso.refresh_native(old), 401, "token_invalid")


def test_REFRESH_03_rotation_chain(sso, native_session):
    tok = native_session["refresh_token"]
    for _ in range(3):
        r = sso.refresh_native(tok)
        assert r.status_code == 200, r.text
        tok = r.json()["refresh_token"]


def test_REFRESH_04_cookie_refresh_with_allowed_origin(sso, cfg, pool_user):
    name, pw, _ = pool_user
    login = sso.login_ok(name, pw, client="browser", origin=cfg.allowed_origin)
    c1 = refresh_cookie(login)
    r = sso.refresh_cookie(c1.value, origin=cfg.allowed_origin)
    assert r.status_code == 200, r.text
    assert_token_response(r.json(), expect_refresh_in_body=False, access_ttl_s=cfg.access_ttl_s)
    c2 = refresh_cookie(r)
    assert c2 is not None and c2.value != c1.value, "cookie must carry the rotated refresh token"


def test_REFRESH_05_cookie_reuse_after_rotation_rejected(sso, cfg, pool_user):
    name, pw, _ = pool_user
    c1 = refresh_cookie(sso.login_ok(name, pw, client="browser", origin=cfg.allowed_origin))
    assert sso.refresh_cookie(c1.value, origin=cfg.allowed_origin).status_code == 200
    assert_error(sso.refresh_cookie(c1.value, origin=cfg.allowed_origin), 401, "token_invalid")


def test_REFRESH_06_access_token_rejected_at_refresh(sso, native_session):
    assert_error(sso.refresh_native(native_session["access_token"]), 401, "token_invalid")


@pytest.mark.parametrize("bad", ["garbage", "a.b.c", "", "eyJhbGciOiJSUzI1NiJ9.e30.AAAA"])
def test_REFRESH_07_malformed_refresh_token(sso, bad):
    r = sso.refresh_native(bad)
    # empty string is arguably a missing field (400); anything else is a bad token (401)
    if bad == "":
        assert_error(r, (400, 401), codes={"invalid_request", "token_invalid"})
    else:
        assert_error(r, 401, "token_invalid")


def test_REFRESH_08_no_token_no_cookie(sso, cfg):
    r = sso.post(REFRESH, json={}, origin=cfg.allowed_origin)
    # OPEN QUESTION Q-05: 400 invalid_request vs 401 token_invalid
    assert_error(r, (400, 401), codes={"invalid_request", "token_invalid"})


@pytest.mark.needs_manage
def test_REFRESH_09_disabled_user_refresh_403(sso, manage):
    u = testdata.USERS["qa_disable"]
    tok = sso.login_ok("qa_disable", u["password"]).json()["refresh_token"]
    manage.set_user("qa_disable", is_active=False)
    try:
        assert_error(sso.refresh_native(tok), 403, "account_inactive")
    finally:
        manage.set_user("qa_disable", is_active=True)


def test_REFRESH_10_revoked_by_logout_all(sso):
    time.sleep(1.1)
    u = testdata.USERS["qa_revoke"]
    s = sso.login_ok("qa_revoke", u["password"]).json()
    time.sleep(1.1)  # make iat strictly older than revoked_at at second granularity
    assert sso.logout_all(s["access_token"]).status_code == 204
    assert_error(sso.refresh_native(s["refresh_token"]), 401, "token_invalid")


@pytest.mark.needs_private_key
def test_REFRESH_11_refresh_with_iat_before_revoked_at_rejected_even_if_not_blacklisted(
        sso, signing_key, real_kid):
    """Addendum B8: /refresh rejects iat < UserTokenRevocation.revoked_at independent of the
    blacklist. A refresh token minted with the real key (so not in OutstandingToken) and an iat
    before a logout-all must be refused."""
    time.sleep(1.1)  # keep clear of a previous test's logout-all on the same user
    u = testdata.USERS["qa_revoke"]
    s = sso.login_ok("qa_revoke", u["password"]).json()
    pl = jwt_forge.payload(s["refresh_token"])
    pl.update(jti="qa" + str(time.time_ns()), iat=pl["iat"] - 60)
    forged = jwt_forge.sign(pl, signing_key, real_kid)
    time.sleep(1.1)
    assert sso.logout_all(s["access_token"]).status_code == 204
    assert_error(sso.refresh_native(forged), 401, "token_invalid")


def test_REFRESH_12_response_has_no_cache(sso, native_session):
    r = sso.refresh_native(native_session["refresh_token"])
    assert r.status_code == 200
    cc = r.headers.get("Cache-Control", "")
    if "no-store" not in cc:
        pytest.xfail("token responses should send Cache-Control: no-store (RFC 6749 5.1); not in spec - Q-14")
