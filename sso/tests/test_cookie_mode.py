"""Spec §11: cookie mode sets HttpOnly/Secure and checks Origin (addendum B.9); CORS (spec §7.1)."""
from __future__ import annotations

import pytest

from .conftest import ORIGIN, login

pytestmark = pytest.mark.django_db


def browser_login(api):
    r = login(api, client="browser", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 200
    return r


def test_browser_login_sets_hardened_cookie_and_omits_body_token(api, user):
    r = browser_login(api)
    assert "refresh_token" not in r.json()
    c = r.cookies["sso_refresh"]
    assert c.value
    assert c["httponly"] is True
    assert c["secure"] is True
    assert c["samesite"] == "Lax"
    assert c["path"] == "/api/v1/auth/"
    assert c["domain"] == ".example.test"
    assert int(c["max-age"]) == 7 * 86400
    # CORS: allowed origin echoed with credentials
    assert r["Access-Control-Allow-Origin"] == ORIGIN
    assert r["Access-Control-Allow-Credentials"] == "true"


def test_default_client_is_browser(api, user):
    r = api.post("/api/v1/auth/login", {"username": "thomas", "password": "Correct-Horse-9"}, format="json")
    assert r.status_code == 200 and "refresh_token" not in r.json() and "sso_refresh" in r.cookies


def test_cookie_refresh_with_allowed_origin_rotates_cookie(api, user):
    first = browser_login(api).cookies["sso_refresh"].value
    r = api.post("/api/v1/auth/refresh", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 200
    assert "refresh_token" not in r.json()
    second = r.cookies["sso_refresh"].value
    assert second and second != first
    # replaying the first cookie fails (rotation + blacklist)
    api.cookies["sso_refresh"] = first
    r = api.post("/api/v1/auth/refresh", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


@pytest.mark.parametrize("origin", [None, "https://evil.example", "null", ORIGIN + ".evil.example"])
def test_cookie_refresh_requires_allowed_origin(api, user, origin):
    browser_login(api)
    extra = {"HTTP_ORIGIN": origin} if origin else {}
    r = api.post("/api/v1/auth/refresh", {}, format="json", **extra)
    assert r.status_code == 403
    assert r.json() == {"error": "origin_not_allowed", "detail": "Request origin is not allowed."}


def test_cookie_refresh_without_cookie(api, db):
    r = api.post("/api/v1/auth/refresh", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_cookie_refresh_empty_body_no_content_type(api, user):
    # auth.js always sends JSON, but an empty body must also work
    browser_login(api)
    r = api.generic("POST", "/api/v1/auth/refresh", "", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 200


def test_cookie_logout_checks_origin_then_clears_cookie(api, user):
    browser_login(api)
    assert api.post("/api/v1/auth/logout", {}, format="json").status_code == 403
    r = api.post("/api/v1/auth/logout", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 204
    assert r.cookies["sso_refresh"].value == ""
    assert r.cookies["sso_refresh"]["max-age"] == 0
    # the cookie token is now blacklisted
    r = api.post("/api/v1/auth/refresh", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 401


def test_cookie_logout_without_cookie_is_noop(api, db):
    r = api.post("/api/v1/auth/logout", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 204


def test_cookie_logout_with_invalid_cookie_clears_it(api, db):
    api.cookies["sso_refresh"] = "garbage"
    r = api.post("/api/v1/auth/logout", {}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"
    assert r.cookies["sso_refresh"].value == ""


def test_cors_preflight_allowed_and_denied(api, db):
    r = api.options("/api/v1/auth/login", HTTP_ORIGIN=ORIGIN, HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
                    HTTP_ACCESS_CONTROL_REQUEST_HEADERS="content-type")
    assert r["Access-Control-Allow-Origin"] == ORIGIN
    assert r["Access-Control-Allow-Credentials"] == "true"
    r = api.options("/api/v1/auth/login", HTTP_ORIGIN="https://evil.example",
                    HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST")
    assert "Access-Control-Allow-Origin" not in r


def test_cookie_respects_settings(api, user, settings):
    settings.SSO_COOKIE_DOMAIN = None
    settings.SSO_COOKIE_SECURE = False
    c = browser_login(api).cookies["sso_refresh"]
    assert c["domain"] == "" and not c["secure"]
