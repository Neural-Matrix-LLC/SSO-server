"""ME-xx: GET /api/v1/auth/me (spec 6.5)."""
import time

import pytest

import testdata
from helpers import assert_error, assert_user_obj
from sso_client import ME


def test_ME_01_returns_user_object(sso, alice_session):
    r = sso.me(alice_session["access_token"])
    assert r.status_code == 200, r.text
    assert r.headers["Content-Type"].startswith("application/json")
    assert_user_obj(r.json(), "qa_alice", testdata.USERS["qa_alice"])
    assert r.json() == alice_session["user"]


def test_ME_02_no_authorization_header(sso):
    assert_error(sso.get(ME), 401, codes={"token_invalid"})  # Q-07


@pytest.mark.parametrize("hdr", ["Basic cWE6cWE=", "Bearer", "Bearer ", "Token abc", "bearer garbage"])
def test_ME_03_bad_authorization_header(sso, hdr):
    assert_error(sso.get(ME, headers={"Authorization": hdr}), 401)


def test_ME_04_refresh_token_rejected(sso, alice_session):
    assert_error(sso.me(alice_session["refresh_token"]), 401, "token_invalid")


def test_ME_05_post_not_allowed(sso, alice_session):
    assert_error(sso.post(ME, bearer=alice_session["access_token"]), 405)


@pytest.mark.needs_manage
def test_ME_06_read_fresh_from_db(sso, manage):
    u = testdata.USERS["qa_fresh"]
    s = sso.login_ok("qa_fresh", u["password"]).json()
    new = f"Fresh{int(time.time())}"
    manage.set_user("qa_fresh", first_name=new)
    try:
        assert sso.me(s["access_token"]).json()["first_name"] == new
    finally:
        manage.set_user("qa_fresh", first_name=u["first_name"])


@pytest.mark.needs_private_key
def test_ME_07_token_for_nonexistent_user(sso, signing_key, real_kid, alice_session):
    import jwt_forge
    pl = jwt_forge.claims_like(alice_session["access_token"], sub="987654321", username="ghost")
    assert_error(sso.me(jwt_forge.sign(pl, signing_key, real_kid)), 401)
