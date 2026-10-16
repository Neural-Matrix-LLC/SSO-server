"""JWKS / discovery / healthz (spec §6.7, addendum B.2, B.6) and the uniform error shape (B.10)."""
from __future__ import annotations

import jwt
import pytest
from django.db import DatabaseError
from django.test import RequestFactory

from sso import errors
from sso.keys import compute_kid, load_public_key
from .conftest import bearer, login

pytestmark = pytest.mark.django_db


def test_jwks_lists_all_public_keys_and_kid_matches_token_header(api, user, settings):
    import os
    r = api.get("/.well-known/jwks.json")
    assert r.status_code == 200
    assert r["Cache-Control"] == "public, max-age=3600"
    keys = r.json()["keys"]
    kids = [k["kid"] for k in keys]
    expected = [compute_kid(load_public_key(os.environ["SSO_TEST_CURRENT_PUBLIC"])),
                compute_kid(load_public_key(os.environ["SSO_TEST_OLD_PUBLIC"]))]
    assert kids == expected
    for k in keys:
        assert k["kty"] == "RSA" and k["use"] == "sig" and k["alg"] == "RS256" and k["e"] == "AQAB" and k["n"]
    token = login(api).json()["access_token"]
    header_kid = jwt.get_unverified_header(token)["kid"]
    assert header_kid in kids
    # and the JWK with that kid verifies the token
    jwk = next(k for k in keys if k["kid"] == header_kid)
    key = jwt.PyJWK(jwk).key
    jwt.decode(token, key, algorithms=["RS256"], audience="myfin-services", issuer="https://sso.test")


def test_discovery_document(api, db):
    r = api.get("/.well-known/openid-configuration")
    assert r.status_code == 200
    d = r.json()
    assert d["issuer"] == "https://sso.test"
    assert d["jwks_uri"] == "https://sso.test/.well-known/jwks.json"
    assert d["token_endpoint"] == "https://sso.test/api/v1/auth/login"
    assert "authorization_endpoint" not in d
    assert "/api/v1/auth/token" not in str(d)
    assert d["id_token_signing_alg_values_supported"] == ["RS256"]


def test_healthz_ok(api, db):
    r = api.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_healthz_db_down(api, db, monkeypatch):
    from django.db import connection

    def boom():
        raise DatabaseError("connection refused to 10.0.0.1")

    monkeypatch.setattr(connection, "cursor", boom)
    r = api.get("/healthz")
    assert r.status_code == 503
    assert r.json() == {"error": "unhealthy", "detail": "database"}


def test_healthz_not_throttled(api, db):
    for _ in range(80):
        assert api.get("/healthz").status_code == 200


def test_unknown_url_is_json_404(api, db):
    r = api.get("/api/v1/nope")
    assert r.status_code == 404
    assert r.json() == {"error": "not_found", "detail": "Not found."}


def test_unhandled_exception_is_uniform_500_without_details(api, tokens, monkeypatch, caplog):
    from sso import views

    def explode(self, request):
        raise RuntimeError("secret internals " + tokens["access_token"])

    monkeypatch.setattr(views.MeView, "get", explode)
    r = api.get("/api/v1/auth/me", **bearer(tokens["access_token"]))
    assert r.status_code == 500
    assert r.json() == {"error": "server_error", "detail": "Internal server error."}
    assert "secret internals" not in r.content.decode()


def test_django_level_handlers_return_uniform_json():
    rf = RequestFactory().get("/")
    for fn, code in [(errors.handler400, 400), (errors.handler403, 403), (errors.handler404, 404)]:
        resp = fn(rf, Exception())
        assert resp.status_code == code and b'"error"' in resp.content
    resp = errors.handler500(rf)
    assert resp.status_code == 500 and b"server_error" in resp.content


def test_classify_fallbacks():
    from rest_framework import exceptions

    assert errors._classify(exceptions.NotAcceptable(), 406)[0] == "not_acceptable"
    assert errors._classify(exceptions.PermissionDenied(), 403)[0] == "forbidden"
    assert errors._classify(exceptions.APIException(), 418) == ("error", "Request failed.")
    assert errors._classify(exceptions.ValidationError(["bad"]), 400)[1] == "Missing or malformed fields."
    t = exceptions.Throttled(wait=None)
    assert errors._classify(t, 429) == ("rate_limited", "Too many attempts. Try again later.")
