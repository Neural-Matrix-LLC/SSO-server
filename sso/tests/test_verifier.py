"""examples/verifier: spec §8.2 verifier + FastAPI demo. Spec §11: refresh token rejected by the verifier."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from jwt import PyJWKClient

import sso_verifier
import verifier_app
from .conftest import claims, login, sign

pytestmark = pytest.mark.django_db


@pytest.fixture
def verifier(api, monkeypatch):
    """A verifier whose JWKS is fetched from our real /.well-known/jwks.json view."""
    jwks = api.get("/.well-known/jwks.json").json()
    client = PyJWKClient("https://sso.test/.well-known/jwks.json")
    monkeypatch.setattr(client, "fetch_data", lambda: jwks)
    v = sso_verifier.SSOVerifier("https://sso.test/.well-known/jwks.json", "https://sso.test", jwks_client=client)
    monkeypatch.setattr(sso_verifier, "_default", v)
    return v


def test_verifier_accepts_access_token(verifier, tokens, user):
    c = verifier.verify_access_token(tokens["access_token"])
    assert c["sub"] == str(user.pk) and c["groups"] == ["beta", "trader"]
    assert sso_verifier.verify_access_token(tokens["access_token"])["username"] == "thomas"


def test_verifier_rejects_refresh_token(verifier, tokens):
    with pytest.raises(sso_verifier.TokenInvalid, match="not an access token"):
        verifier.verify_access_token(tokens["refresh_token"])


@pytest.mark.parametrize("over", [{"exp": 1_000_000, "iat": 999_000}, {"aud": "other"}, {"iss": "https://evil"}])
def test_verifier_rejects_expired_wrong_aud_iss(verifier, user, over):
    with pytest.raises(sso_verifier.TokenInvalid):
        verifier.verify_access_token(sign(claims(user.pk, **over)))


def test_verifier_rejects_unpublished_key(verifier, user):
    with pytest.raises(sso_verifier.TokenInvalid):
        verifier.verify_access_token(sign(claims(user.pk), os.environ["SSO_TEST_ROGUE_PRIVATE"]))


def test_verifier_accepts_old_published_key(verifier, user):
    assert verifier.verify_access_token(sign(claims(user.pk), os.environ["SSO_TEST_OLD_PRIVATE"]))["sub"]


def test_default_verifier_from_env(monkeypatch):
    monkeypatch.setattr(sso_verifier, "_default", None)
    monkeypatch.setenv("SSO_JWKS_URL", "https://sso.test/.well-known/jwks.json")
    monkeypatch.setenv("SSO_ISSUER", "https://sso.test")
    v = sso_verifier.default_verifier()
    assert v.issuer == "https://sso.test" and v.audience == "myfin-services"


def test_fastapi_demo(verifier, api, make_user):
    make_user(username="staffer", email="s@example.org", is_staff=True, groups=("admin",))
    make_user(username="plain", email="p@example.org", groups=())
    staff = login(api, username="staffer").json()["access_token"]
    plain = login(api, username="plain").json()["access_token"]
    c = TestClient(verifier_app.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/me")
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert c.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401
    r = c.get("/me", headers={"Authorization": f"Bearer {staff}"})
    assert r.status_code == 200 and r.json()["username"] == "staffer"
    assert c.get("/group/admin", headers={"Authorization": f"Bearer {staff}"}).status_code == 200
    assert c.get("/group/admin", headers={"Authorization": f"Bearer {plain}"}).status_code == 403
    assert c.get("/staff", headers={"Authorization": f"Bearer {staff}"}).status_code == 200
    assert c.get("/staff", headers={"Authorization": f"Bearer {plain}"}).status_code == 403
