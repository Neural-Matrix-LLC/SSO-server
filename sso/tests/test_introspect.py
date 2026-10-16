"""Spec §6.6 introspection + spec §11 "logout-all and introspect after revocation"."""
from __future__ import annotations

import base64

import pytest

from sso.models import ServiceClient
from .conftest import bearer, claims, login, sign

pytestmark = pytest.mark.django_db


@pytest.fixture
def service(db):
    c = ServiceClient(client_id="rebalance-api", name="Rebalance")
    c.set_secret("s3cr3t-value")
    c.save()
    return c


def basic(cid="rebalance-api", secret="s3cr3t-value"):
    return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()}


def introspect(api, token, **auth):
    return api.post("/api/v1/auth/introspect", {"token": token}, format="json", **(auth or basic()))


def test_introspect_active(api, service, tokens, user):
    r = introspect(api, tokens["access_token"])
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["sub"] == str(user.pk) and body["username"] == "thomas"
    assert body["groups"] == ["beta", "trader"] and body["exp"] > body["iat"]
    assert body["client_id"] == "rebalance-api"
    assert r["Cache-Control"] == "no-store"


def test_introspect_inactive_after_logout_all(api, service, user):
    t = login(api).json()
    assert introspect(api, t["access_token"]).json()["active"] is True
    assert api.post("/api/v1/auth/logout-all", **bearer(t["access_token"])).status_code == 204
    assert introspect(api, t["access_token"]).json() == {"active": False}


@pytest.mark.parametrize("case", ["refresh", "garbage", "expired", "inactive_user", "deleted_user", "wrong_aud"])
def test_introspect_inactive_cases(api, service, tokens, user, case):
    token = tokens["access_token"]
    if case == "refresh":
        token = tokens["refresh_token"]
    elif case == "garbage":
        token = "abc.def.ghi"
    elif case == "expired":
        token = sign(claims(user.pk, iat=1_000_000, exp=1_000_900))
    elif case == "wrong_aud":
        token = sign(claims(user.pk, aud="someone-else"))
    elif case == "inactive_user":
        user.is_active = False
        user.save()
    elif case == "deleted_user":
        user.delete()
    assert introspect(api, token).json() == {"active": False}


@pytest.mark.parametrize("auth", [
    {},
    basic(secret="wrong"),
    basic(cid="unknown"),
    {"HTTP_AUTHORIZATION": "Basic !!notbase64"},
    {"HTTP_AUTHORIZATION": "Basic a b"},
    {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(b"\xff\xfe").decode()},
])
def test_introspect_client_auth_failures(api, service, tokens, auth):
    r = api.post("/api/v1/auth/introspect", {"token": tokens["access_token"]}, format="json", **auth)
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"


def test_introspect_bearer_is_not_client_auth(api, service, tokens):
    r = api.post("/api/v1/auth/introspect", {"token": tokens["access_token"]}, format="json",
                 **bearer(tokens["access_token"]))
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_introspect_inactive_client(api, service, tokens):
    service.is_active = False
    service.save()
    assert introspect(api, tokens["access_token"]).status_code == 401


def test_introspect_bad_body(api, service):
    r = api.post("/api/v1/auth/introspect", {}, format="json", **basic())
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    r = api.post("/api/v1/auth/introspect", ["x"], format="json", **basic())
    assert r.status_code == 400


def test_service_client_secret_helpers(db):
    c = ServiceClient(client_id="x", name="X")
    assert c.check_secret("anything") is False  # no hash yet
    c.set_secret("abc")
    assert c.check_secret("abc") and not c.check_secret("abd")
    assert str(c) == "x (X)"
    assert len(ServiceClient.generate_secret()) >= 40
