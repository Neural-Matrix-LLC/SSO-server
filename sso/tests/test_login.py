"""Spec §11: login ok / wrong password / unknown user / inactive user / email login / throttling."""
from __future__ import annotations

import jwt
import pytest
from django.contrib.auth.models import User

from sso.keys import compute_kid
from .conftest import AUDIENCE, ISSUER, PASSWORD, login

pytestmark = pytest.mark.django_db


def test_login_ok_native_with_legacy_django41_hash(api, user):
    assert user.password.startswith("pbkdf2_sha256$390000$")
    assert user.last_login is None
    r = login(api)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert body["refresh_token"]
    assert "sso_refresh" not in r.cookies  # native: no cookie
    assert body["user"] == {"id": user.pk, "username": "thomas", "email": "thomas@example.org",
                            "first_name": "Tom", "last_name": "Choi", "is_staff": False,
                            "groups": ["beta", "trader"]}
    assert r["Cache-Control"] == "no-store"
    user.refresh_from_db()
    assert user.last_login is not None
    # Django re-hashes with its current iteration count; format stays pbkdf2_sha256 (myFinance 4.1 can verify)
    algo, iterations, _salt, _hash = user.password.split("$")
    assert algo == "pbkdf2_sha256" and int(iterations) > 390000
    assert user.check_password(PASSWORD)


def test_access_token_claims_and_header(api, user, settings):
    body = login(api).json()
    header = jwt.get_unverified_header(body["access_token"])
    assert header["alg"] == "RS256" and header["typ"] == "JWT"
    assert header["kid"] == settings.SSO_KEYSET.signing_kid
    c = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert c["iss"] == ISSUER and c["aud"] == AUDIENCE
    assert c["sub"] == str(user.pk) and isinstance(c["sub"], str)
    assert c["token_type"] == "access"
    assert c["exp"] - c["iat"] == 900
    assert c["username"] == "thomas" and c["email"] == "thomas@example.org"
    assert c["is_staff"] is False and c["groups"] == ["beta", "trader"]
    assert c["jti"]
    r = jwt.decode(body["refresh_token"], options={"verify_signature": False})
    assert r["token_type"] == "refresh" and r["aud"] == AUDIENCE and r["iss"] == ISSUER
    assert r["exp"] - r["iat"] == 7 * 86400
    assert "groups" not in r and "username" not in r
    assert jwt.get_unverified_header(body["refresh_token"])["kid"] == compute_kid(
        settings.SSO_KEYSET.signing_public.key)


def test_login_wrong_password(api, user):
    r = login(api, password="nope")
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_credentials", "detail": "Username or password is incorrect."}


def test_login_unknown_user_same_error_and_runs_dummy_hash(api, db, monkeypatch):
    calls = []
    orig = User.set_password

    def spy(self, raw):
        calls.append(raw)
        return orig(self, raw)

    monkeypatch.setattr(User, "set_password", spy)
    r = login(api, username="ghost")
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_credentials"
    assert calls, "ModelBackend must run a dummy hash for unknown users (timing safety)"


def test_login_unknown_email_runs_dummy_hash(api, user, monkeypatch):
    calls = []
    import sso.serializers as s

    orig = s._dummy_hash
    monkeypatch.setattr(s, "_dummy_hash", lambda pw: (calls.append(1), orig(pw)))
    r = login(api, username="nobody@example.org")
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"
    assert calls == [1]


def test_login_inactive_user(api, make_user):
    make_user(is_active=False)
    r = login(api)
    assert r.status_code == 403
    assert r.json()["error"] == "account_inactive"


def test_login_inactive_user_wrong_password_does_not_leak(api, make_user):
    make_user(is_active=False)
    r = login(api, password="wrong")
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"


def test_login_by_email_case_insensitive(api, user):
    r = login(api, username="THOMAS@Example.ORG")
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "thomas"


def test_login_by_email_duplicate_rejected(api, make_user):
    make_user(username="a", email="dup@example.org")
    make_user(username="b", email="DUP@example.org")
    r = login(api, username="dup@example.org")
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"


def test_empty_email_never_matches(api, make_user):
    make_user(username="noemail", email="")
    # '@' forces the email path; an empty email must never match
    r = login(api, username="@")
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"


def test_username_with_at_sign_goes_through_email_path(api, make_user):
    make_user(username="weird@name", email="other@example.org")
    assert login(api, username="weird@name").status_code == 401
    assert login(api, username="other@example.org").status_code == 200


@pytest.mark.parametrize("body", [{}, {"username": "thomas"}, {"password": "x"}, {"username": "", "password": "x"},
                                  {"username": "thomas", "password": "x", "client": "tv"}])
def test_login_invalid_request(api, db, body):
    r = api.post("/api/v1/auth/login", body, format="json")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"
    assert "x" not in r.json()["detail"].split()  # never echoes values


def test_login_json_array_body(api, db):
    r = api.post("/api/v1/auth/login", [1, 2], format="json")
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"


def test_login_malformed_json(api, db):
    r = api.post("/api/v1/auth/login", "{bad", content_type="application/json")
    assert r.status_code == 400 and r.json() == {"error": "invalid_request", "detail": "Malformed JSON body."}


def test_login_form_encoded_rejected(api, db):
    r = api.post("/api/v1/auth/login", "username=a&password=b", content_type="application/x-www-form-urlencoded")
    assert r.status_code == 415 and r.json()["error"] == "unsupported_media_type"


def test_throttle_per_ip(api, db):
    for i in range(10):
        r = login(api, username=f"user{i}", password="x")
        assert r.status_code == 401
    r = login(api, username="user-final", password="x")
    assert r.status_code == 429
    assert r.json()["error"] == "rate_limited"
    assert int(r["Retry-After"]) > 0
    assert "Try again in" in r.json()["detail"]


def test_throttle_per_username_across_ips(api, user):
    for i in range(5):
        r = login(api, username="Thomas", password="x", REMOTE_ADDR=f"10.0.0.{i}")
        assert r.status_code == 401
    # same username (case-insensitive), yet another IP: blocked even with the right password
    r = login(api, username="thomas", REMOTE_ADDR="10.0.0.99")
    assert r.status_code == 429 and r.json()["error"] == "rate_limited" and r["Retry-After"]
    # a different user from a fresh IP is unaffected
    assert login(api, username="other", password="x", REMOTE_ADDR="10.0.1.1").status_code == 401


def test_throttle_uses_x_forwarded_for_with_one_proxy(api, db):
    # NUM_PROXIES=1: the right-most X-Forwarded-For entry (set by nginx) is the client
    for i in range(10):
        assert login(api, username=f"u{i}", password="x", HTTP_X_FORWARDED_FOR="203.0.113.7").status_code == 401
    assert login(api, username="z", password="x", HTTP_X_FORWARDED_FOR="203.0.113.7").status_code == 429
    assert login(api, username="z", password="x", HTTP_X_FORWARDED_FOR="203.0.113.8").status_code == 401


def test_login_get_not_allowed(api, db):
    r = api.get("/api/v1/auth/login")
    assert r.status_code == 405
    assert r.json() == {"error": "method_not_allowed", "detail": "Method not allowed."}


# QA LEGACY-06: same hash shapes as qa/tests/testdata.py (password_hash_for "malformed" / "truncated")
@pytest.mark.parametrize("username,bad_hash", [
    ("qa_malformed", "pbkdf2_sha256$notanumber$qasaltqa_malformed$AAAA"),
    ("qa_truncated", "pbkdf2_sha256$390000$qasaltqa_truncated"),
])
@pytest.mark.parametrize("via_email", [False, True])
def test_login_corrupt_stored_hash_is_401_not_500(api, make_user, monkeypatch, caplog, username, bad_hash, via_email):
    import json
    import logging

    import sso.serializers as s

    make_user(username=username, email=f"{username}@example.test", password_hash=bad_hash)
    calls = []
    orig = s._dummy_hash
    monkeypatch.setattr(s, "_dummy_hash", lambda pw: (calls.append(1), orig(pw)))
    caplog.set_level(logging.INFO, logger="sso.auth")
    secret = "Some-Password-42"
    r = login(api, username=f"{username}@example.test" if via_email else username, password=secret)
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_credentials", "detail": "Username or password is incorrect."}
    assert calls == [1]  # timing: one dummy hash on this path
    events = [json.loads(rec.getMessage()) for rec in caplog.records if rec.name == "sso.auth"]
    assert {"event": "login", "result": "stored_hash_invalid", "username": username, "ip": "127.0.0.1"} in events
    assert [e["result"] for e in events if e["event"] == "login"][-1] == "invalid_credentials"
    assert secret not in caplog.text and bad_hash not in caplog.text
    # the stored row is left untouched (no rehash/overwrite of the shared table)
    from django.contrib.auth.models import User
    assert User.objects.get(username=username).password == bad_hash


def test_x_forwarded_for_ignored_with_zero_proxies(api, db, settings):
    """QA defect 4: with SSO_NUM_PROXIES=0 (the default) a client-chosen X-Forwarded-For cannot dodge the IP throttle."""
    rf = dict(settings.REST_FRAMEWORK)
    rf["NUM_PROXIES"] = 0
    settings.REST_FRAMEWORK = rf
    for i in range(10):
        assert login(api, username=f"u{i}", password="x", HTTP_X_FORWARDED_FOR=f"198.51.100.{i}").status_code == 401
    r = login(api, username="z", password="x", HTTP_X_FORWARDED_FOR="198.51.100.200")
    assert r.status_code == 429
