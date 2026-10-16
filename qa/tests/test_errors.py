"""ERR-xx: spec 6.0 error envelope on every endpoint (addendum B10)."""
import pytest

import testdata
from helpers import assert_error
from sso_client import LOGIN, LOGOUT_ALL, ME, REFRESH


def test_ERR_01_invalid_request_shape(sso):
    assert_error(sso.post(LOGIN, json={"client": "native"}, retry_on_429=True), 400, "invalid_request")


def test_ERR_02_malformed_json(sso):
    r = sso.post(LOGIN, data='{"username": "qa_alice", "password": ', retry_on_429=True,
                 headers={"Content-Type": "application/json"})
    assert_error(r, 400, "invalid_request")


@pytest.mark.parametrize("body", ['[]', '"str"', '123', 'null'])
def test_ERR_03_non_object_json(sso, body):
    r = sso.post(LOGIN, data=body, headers={"Content-Type": "application/json"}, retry_on_429=True)
    assert_error(r, 400, "invalid_request")


@pytest.mark.parametrize("body", [
    {"username": ["qa_alice"], "password": "x", "client": "native"},
    {"username": "qa_alice", "password": None, "client": "native"},
    {"username": {"a": 1}, "password": "x", "client": "native"},
])
def test_ERR_04_wrong_field_types(sso, body):
    assert_error(sso.post(LOGIN, json=body, retry_on_429=True), 400, "invalid_request")


def test_ERR_05_oversized_input_no_500(sso):
    r = sso.post(LOGIN, json={"username": "a" * 10000, "password": "b" * 10000, "client": "native"},
                 retry_on_429=True)
    assert_error(r, (400, 401), codes={"invalid_request", "invalid_credentials"})


def test_ERR_06_unsupported_content_type(sso):
    r = sso.post(LOGIN, data="username=qa_alice", headers={"Content-Type": "text/plain"}, retry_on_429=True)
    assert_error(r, (400, 415))


def test_ERR_07_401_invalid_credentials_shape(sso):
    b = assert_error(sso.login("qa_alice", "nope"), 401, "invalid_credentials")
    assert b["detail"]


def test_ERR_08_401_token_invalid_shape(sso):
    assert_error(sso.get(ME, bearer="garbage"), 401, "token_invalid")
    assert_error(sso.post(LOGOUT_ALL, bearer="garbage"), 401, "token_invalid")
    assert_error(sso.post(REFRESH, json={"refresh_token": "garbage"}), 401, "token_invalid")


def test_ERR_09_403_account_inactive_shape(sso):
    assert_error(sso.login("qa_inactive", testdata.USERS["qa_inactive"]["password"]), 403, "account_inactive")


@pytest.mark.parametrize("path", ["/api/v1/auth/nope", "/api/v1/", "/api/v1/auth/token", "/sso/authorize"])
def test_ERR_10_404_uses_envelope(sso, path):
    """Includes phase-5 paths that must not exist yet (addendum A/B2)."""
    assert_error(sso.get(path), 404)


@pytest.mark.parametrize("method,path", [("GET", LOGIN), ("GET", REFRESH), ("PUT", LOGIN),
                                         ("DELETE", "/api/v1/auth/logout"), ("GET", LOGOUT_ALL)])
def test_ERR_11_405_uses_envelope(sso, alice_session, method, path):
    # Bearer-protected views authenticate before the method check (DRF), so send a valid token there.
    bearer = alice_session["access_token"] if path == LOGOUT_ALL else None
    r = sso.request(method, path, bearer=bearer)
    assert_error(r, 405)
    assert "POST" in r.headers.get("Allow", "")


def test_ERR_12_secrets_never_echoed(sso):
    secret_pw = "Sup3r-Secret-Pw-For-Echo-Test"
    assert_error(sso.login("qa_alice", secret_pw), 401, forbidden_substrings=[secret_pw])
    fake_tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXNlY3JldA"
    assert_error(sso.refresh_native(fake_tok), 401, forbidden_substrings=[fake_tok, "c2lnbmF0dXJlLXNlY3JldA"])
    assert_error(sso.get(ME, bearer=fake_tok), 401, forbidden_substrings=[fake_tok])


def test_ERR_13_no_trailing_slash_redirects(sso):
    """Spec paths have no trailing slash; POSTing to them must not 301/500 (Django APPEND_SLASH)."""
    r = sso.post(LOGIN, json={"username": "qa_alice", "password": "nope", "client": "native"}, retry_on_429=True)
    assert r.status_code not in (301, 302, 307, 308, 500)
