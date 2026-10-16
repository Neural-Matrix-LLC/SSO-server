"""INTRO-xx: POST /api/v1/auth/introspect (spec 6.6, 9.2)."""
import time

import pytest

import jwt_forge
import testdata
from helpers import assert_error
from sso_client import INTROSPECT


def test_INTRO_01_active_access_token(sso, service_auth, alice_session):
    r = sso.introspect(alice_session["access_token"], service_auth)
    assert r.status_code == 200, r.text
    body = r.json()
    p = jwt_forge.payload(alice_session["access_token"])
    assert body["active"] is True
    assert body["sub"] == p["sub"]
    assert body["username"] == "qa_alice"
    assert sorted(body["groups"]) == sorted(testdata.USERS["qa_alice"]["groups"])
    assert body["exp"] == p["exp"]


def test_INTRO_02_no_client_auth(sso, alice_session):
    r = sso.post(INTROSPECT, json={"token": alice_session["access_token"]})
    assert_error(r, 401)  # Q-10: error code for client-auth failure not defined


def test_INTRO_03_wrong_client_secret(sso, alice_session):
    r = sso.introspect(alice_session["access_token"], (testdata.SERVICE_CLIENT_ID, "wrong-secret"))
    assert_error(r, 401, forbidden_substrings=["wrong-secret"])


def test_INTRO_04_unknown_client(sso, alice_session):
    assert_error(sso.introspect(alice_session["access_token"], ("qa-nope", "x")), 401)


def test_INTRO_05_inactive_client(sso, alice_session):
    auth = (testdata.INACTIVE_SERVICE_CLIENT_ID, testdata.INACTIVE_SERVICE_CLIENT_SECRET)
    assert_error(sso.introspect(alice_session["access_token"], auth), 401)


def test_INTRO_06_user_bearer_token_is_not_client_auth(sso, alice_session):
    r = sso.post(INTROSPECT, json={"token": alice_session["access_token"]}, bearer=alice_session["access_token"])
    assert_error(r, 401)


def test_INTRO_07_refresh_token_inactive(sso, service_auth, alice_session):
    r = sso.introspect(alice_session["refresh_token"], service_auth)
    assert r.status_code == 200 and r.json() == {"active": False}


@pytest.mark.parametrize("tok", ["garbage", "a.b.c", "eyJhbGciOiJub25lIn0.e30."])
def test_INTRO_08_garbage_token_inactive_not_error(sso, service_auth, tok):
    r = sso.introspect(tok, service_auth)
    assert r.status_code == 200 and r.json() == {"active": False}


def test_INTRO_09_missing_token_field(sso, service_auth):
    assert_error(sso.post(INTROSPECT, json={}, auth=service_auth), 400, "invalid_request")


@pytest.mark.needs_manage
def test_INTRO_10_inactive_user_inactive(sso, service_auth, manage):
    u = testdata.USERS["qa_disable"]
    s = sso.login_ok("qa_disable", u["password"]).json()
    manage.set_user("qa_disable", is_active=False)
    try:
        assert sso.introspect(s["access_token"], service_auth).json() == {"active": False}
    finally:
        manage.set_user("qa_disable", is_active=True)


@pytest.mark.needs_private_key
def test_INTRO_11_expired_token_inactive(sso, service_auth, signing_key, real_kid, alice_session):
    now = int(time.time())
    pl = jwt_forge.claims_like(alice_session["access_token"], iat=now - 3600, exp=now - 120)
    r = sso.introspect(jwt_forge.sign(pl, signing_key, real_kid), service_auth)
    assert r.json() == {"active": False}


def test_INTRO_12_forged_tokens_inactive(sso, service_auth, alice_session, jwks_public_key, real_kid):
    pl = jwt_forge.claims_like(alice_session["access_token"])
    forged = [jwt_forge.alg_none(pl, kid=real_kid),
              jwt_forge.tamper_signature(alice_session["access_token"]),
              jwt_forge.sign(pl, jwt_forge.new_rsa_key(), real_kid)]
    forged += [jwt_forge.hs256_with_secret(pl, s, kid=real_kid)
               for s in jwt_forge.public_key_secret_variants(jwks_public_key).values()]
    for tok in forged:
        r = sso.introspect(tok, service_auth)
        assert r.status_code == 200 and r.json() == {"active": False}, tok[:40]


def test_INTRO_13_inactive_response_leaks_nothing(sso, service_auth, alice_session):
    body = sso.introspect(alice_session["refresh_token"], service_auth).json()
    assert set(body) == {"active"}


def test_INTRO_14_get_not_allowed(sso, service_auth):
    assert_error(sso.get(INTROSPECT, auth=service_auth), 405)
