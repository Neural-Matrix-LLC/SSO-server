"""LOGIN-xx: POST /api/v1/auth/login (spec 6.1, addendum B4/B5)."""
import time

import pytest

import jwt_forge
import testdata
from helpers import assert_error, assert_token_response, assert_user_obj
from sso_client import LOGIN, refresh_cookie

U = testdata.USERS


def test_LOGIN_01_native_login_returns_token_pair(sso, cfg):
    r = sso.login_ok("qa_alice", U["qa_alice"]["password"], client="native")
    assert r.headers["Content-Type"].startswith("application/json")
    body = r.json()
    assert_token_response(body, expect_refresh_in_body=True, access_ttl_s=cfg.access_ttl_s)
    assert refresh_cookie(r) is None, "native mode must not set the sso_refresh cookie"


def test_LOGIN_02_browser_login_sets_cookie_and_omits_refresh(sso, cfg):
    r = sso.login_ok("qa_alice", U["qa_alice"]["password"], client="browser", origin=cfg.allowed_origin)
    assert_token_response(r.json(), expect_refresh_in_body=False, access_ttl_s=cfg.access_ttl_s)
    c = refresh_cookie(r)
    assert c is not None and c.value.count(".") == 2


def test_LOGIN_03_client_defaults_to_browser(sso, cfg, pool_user):
    name, pw, _ = pool_user
    r = sso.login(name, pw, omit_client=True, origin=cfg.allowed_origin)
    assert r.status_code == 200, r.text
    assert "refresh_token" not in r.json()
    assert refresh_cookie(r) is not None


def test_LOGIN_04_access_token_header_and_claims(alice_session, cfg, issuer):
    tok = alice_session["access_token"]
    h, p = jwt_forge.header(tok), jwt_forge.payload(tok)
    assert h["alg"] == "RS256"
    assert h.get("typ") == "JWT"
    assert isinstance(h.get("kid"), str) and len(h["kid"]) == 16
    assert p["iss"] == issuer
    aud = p["aud"] if isinstance(p["aud"], list) else [p["aud"]]
    assert cfg.audience in aud
    assert p["sub"] == str(alice_session["user"]["id"]) and isinstance(p["sub"], str)
    assert p["token_type"] == "access"
    assert p.get("jti")
    assert p["exp"] - p["iat"] == cfg.access_ttl_s
    assert abs(p["iat"] - time.time()) < 300
    assert p["username"] == "qa_alice"
    assert p["email"] == U["qa_alice"]["email"]
    assert p["is_staff"] is False
    assert sorted(p["groups"]) == sorted(U["qa_alice"]["groups"])
    for leak in ("password", "first_name", "last_name", "permissions", "user_permissions"):
        assert leak not in p, f"token must stay small / no extra PII: {leak}"


def test_LOGIN_05_refresh_token_claims(alice_session, cfg, issuer):
    p = jwt_forge.payload(alice_session["refresh_token"])
    assert jwt_forge.header(alice_session["refresh_token"])["alg"] == "RS256"
    assert p["token_type"] == "refresh"
    assert p["exp"] - p["iat"] == cfg.refresh_ttl_s
    assert p.get("jti") and p["jti"] != jwt_forge.payload(alice_session["access_token"])["jti"]
    aud = p.get("aud") if isinstance(p.get("aud"), list) else [p.get("aud")]
    assert cfg.audience in aud  # addendum B7: refresh tokens also carry aud


def test_LOGIN_06_user_object(alice_session):
    assert_user_obj(alice_session["user"], "qa_alice", U["qa_alice"])


def test_LOGIN_07_wrong_password(sso):
    r = sso.login("qa_alice", "wrong-" + U["qa_alice"]["password"])
    assert_error(r, 401, "invalid_credentials", forbidden_substrings=["wrong-" + U["qa_alice"]["password"]])


def test_LOGIN_08_unknown_user_same_response_as_wrong_password(sso):
    wrong = sso.login("qa_bob", "definitely-wrong")
    unknown = sso.login("qa_no_such_user_xyz", "definitely-wrong")
    b1 = assert_error(wrong, 401, "invalid_credentials")
    b2 = assert_error(unknown, 401, "invalid_credentials")
    assert b1 == b2, "unknown user must be indistinguishable from wrong password"


def test_LOGIN_09_inactive_user_correct_password(sso):
    r = sso.login("qa_inactive", U["qa_inactive"]["password"])
    assert_error(r, 403, "account_inactive")


def test_LOGIN_10_inactive_user_wrong_password_does_not_leak(sso):
    r = sso.login("qa_inactive", "definitely-wrong")
    assert_error(r, 401, "invalid_credentials")


def test_LOGIN_11_email_login_case_insensitive(sso):
    r = sso.login_ok("qa.carol@example.test", U["qa_carol"]["password"])
    assert r.json()["user"]["username"] == "qa_carol"
    r = sso.login_ok("QA.CAROL@EXAMPLE.TEST", U["qa_carol"]["password"])
    assert r.json()["user"]["username"] == "qa_carol"


def test_LOGIN_12_email_shared_by_two_users_rejected(sso):
    r = sso.login("qa_dup@example.test", U["qa_dup1"]["password"])
    assert_error(r, 401, "invalid_credentials")


def test_LOGIN_13_unknown_email_and_bare_at(sso):
    assert_error(sso.login("nobody-qa@example.test", "x"), 401, "invalid_credentials")
    # empty emails must never match (B5): "@" must not log in qa_noemail or anyone else
    assert_error(sso.login("@", U["qa_noemail"]["password"]), (400, 401))


@pytest.mark.parametrize("body", [
    {"password": "x", "client": "native"},
    {"username": "qa_alice", "client": "native"},
    {"username": "", "password": "x", "client": "native"},
    {"username": "qa_alice", "password": "", "client": "native"},
    {},
])
def test_LOGIN_14_missing_or_empty_fields(sso, body):
    assert_error(sso.post(LOGIN, json=body, retry_on_429=True), 400, "invalid_request")


def test_LOGIN_15_invalid_client_value(sso):
    r = sso.post(LOGIN, json={"username": "qa_alice", "password": "x", "client": "spaceship"},
                 retry_on_429=True)
    assert_error(r, 400, "invalid_request")


def test_LOGIN_16_staff_flag_and_empty_groups(sso):
    body = sso.login_ok("qa_bob", U["qa_bob"]["password"]).json()
    p = jwt_forge.payload(body["access_token"])
    assert p["is_staff"] is True and p["groups"] == []
    assert_user_obj(body["user"], "qa_bob", U["qa_bob"])


@pytest.mark.needs_manage
def test_LOGIN_17_last_login_updated(sso, manage, pool_user):
    name, pw, _ = pool_user
    before = manage.user_field(name, "last_login")
    time.sleep(1.1)
    sso.login_ok(name, pw)
    after = manage.user_field(name, "last_login")
    assert after != "None" and after != before


def test_LOGIN_18_each_login_issues_distinct_tokens(sso, pool_user):
    name, pw, _ = pool_user
    a = sso.login_ok(name, pw).json()
    b = sso.login_ok(name, pw).json()
    assert a["access_token"] != b["access_token"] and a["refresh_token"] != b["refresh_token"]


def test_LOGIN_19_form_encoded_login_rejected(sso):
    """Spec 6: all bodies are JSON. Accepting form-encoded logins (DRF FormParser) would allow
    cross-site HTML-form login CSRF that plants an attacker session cookie (Q-15)."""
    r = sso.post(LOGIN, data={"username": "qa_alice", "password": U["qa_alice"]["password"], "client": "browser"},
                 retry_on_429=True)
    assert_error(r, (400, 415))
    assert refresh_cookie(r) is None
