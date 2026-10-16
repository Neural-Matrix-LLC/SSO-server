"""Assertion helpers shared by the test modules."""
from __future__ import annotations

import re

KNOWN_ERRORS = {"invalid_request", "invalid_credentials", "token_invalid", "account_inactive",
                "rate_limited", "origin_not_allowed"}

USER_KEYS = {"id", "username", "email", "first_name", "last_name", "is_staff", "groups"}


def assert_error(resp, status, code=None, *, codes=None, forbidden_substrings=()):
    """Spec 6.0 / addendum B10 error envelope: {"error": "...", "detail": "..."} as JSON."""
    if isinstance(status, (tuple, list, set)):
        assert resp.status_code in status, f"expected {status}, got {resp.status_code}: {resp.text[:300]}"
    else:
        assert resp.status_code == status, f"expected {status}, got {resp.status_code}: {resp.text[:300]}"
    ctype = resp.headers.get("Content-Type", "")
    assert ctype.startswith("application/json"), f"error content-type {ctype!r}: {resp.text[:200]}"
    body = resp.json()
    assert isinstance(body, dict), body
    assert isinstance(body.get("error"), str) and body["error"], f"missing 'error': {body}"
    assert isinstance(body.get("detail"), str), f"missing 'detail': {body}"
    assert re.fullmatch(r"[a-z][a-z0-9_]*", body["error"]), f"error code not snake_case: {body['error']}"
    if code is not None:
        assert body["error"] == code, f"expected error={code}, got {body}"
    if codes is not None:
        assert body["error"] in codes, f"expected error in {codes}, got {body}"
    text = resp.text
    assert "Traceback" not in text and 'File "' not in text, "stack trace leaked"
    for s in forbidden_substrings:
        if s:
            assert s not in text, "secret echoed in error response"
    return body


def assert_user_obj(user: dict, expected_username: str, expected: dict):
    assert USER_KEYS <= set(user), f"user object missing keys: {USER_KEYS - set(user)}"
    assert isinstance(user["id"], int)
    assert user["username"] == expected_username
    assert user["email"] == expected["email"]
    assert user["first_name"] == expected["first_name"]
    assert user["last_name"] == expected["last_name"]
    assert user["is_staff"] is expected["is_staff"]
    assert sorted(user["groups"]) == sorted(expected["groups"])
    assert "password" not in user


def assert_token_response(body: dict, *, expect_refresh_in_body: bool, access_ttl_s: int):
    assert isinstance(body.get("access_token"), str) and body["access_token"].count(".") == 2
    assert body.get("token_type") == "Bearer"
    assert body.get("expires_in") == access_ttl_s
    if expect_refresh_in_body:
        assert isinstance(body.get("refresh_token"), str) and body["refresh_token"].count(".") == 2
    else:
        assert "refresh_token" not in body, "browser mode must omit refresh_token from the body"
    assert isinstance(body.get("user"), dict)
