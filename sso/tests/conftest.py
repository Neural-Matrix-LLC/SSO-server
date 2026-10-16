from __future__ import annotations

import os
import time
import uuid

import jwt
import pytest
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.contrib.auth.models import Group, User
from django.core.cache import cache
from rest_framework.test import APIClient

from sso.keys import compute_kid, load_private_key

PASSWORD = "Correct-Horse-9"
ORIGIN = "https://fin.example.test"
ISSUER = "https://sso.test"
AUDIENCE = "myfin-services"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture(scope="session")
def legacy_hash() -> str:
    """A Django 4.1-format hash: pbkdf2_sha256$390000$<salt>$<hash> (addendum B.14)."""
    h = PBKDF2PasswordHasher().encode(PASSWORD, "legacysalt0123456789ab", iterations=390000)
    assert h.startswith("pbkdf2_sha256$390000$")
    return h


@pytest.fixture
def make_user(db, legacy_hash):
    def _make(username="thomas", email="thomas@example.org", is_active=True, groups=("trader", "beta"),
              is_staff=False, password_hash=None, **extra):
        u = User.objects.create(username=username, email=email, is_active=is_active, is_staff=is_staff,
                                first_name=extra.pop("first_name", "Tom"), last_name=extra.pop("last_name", "Choi"),
                                password=password_hash or legacy_hash, **extra)
        for g in groups:
            u.groups.add(Group.objects.get_or_create(name=g)[0])
        return u
    return _make


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def api():
    return APIClient()


def login(api, username="thomas", password=PASSWORD, client="native", **extra):
    return api.post("/api/v1/auth/login", {"username": username, "password": password, "client": client},
                    format="json", **extra)


@pytest.fixture
def tokens(api, user):
    r = login(api)
    assert r.status_code == 200, r.content
    return r.json()


def bearer(token: str) -> dict:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def sign(payload: dict, private_path: str | None = None, *, kid: str | None = "auto", alg="RS256",
         headers: dict | None = None) -> str:
    """Forge a token with an arbitrary key/claims for negative tests."""
    private_path = private_path or os.environ["SSO_TEST_CURRENT_PRIVATE"]
    key = load_private_key(private_path)
    hdrs = dict(headers or {})
    if kid == "auto":
        hdrs["kid"] = compute_kid(key.public_key())
    elif kid is not None:
        hdrs["kid"] = kid
    return jwt.encode(payload, key, algorithm=alg, headers=hdrs)


def claims(user_id, token_type="access", **over) -> dict:
    now = int(time.time())
    c = {"iss": ISSUER, "aud": AUDIENCE, "sub": str(user_id), "token_type": token_type, "jti": uuid.uuid4().hex,
         "iat": now, "exp": now + 900, "username": "thomas", "groups": []}
    c.update(over)
    return c
