"""Spec §11: refresh rotation, logout blacklists, logout-all + revocation, access token rejected at /refresh,
expired / wrong aud / wrong iss rejected; addendum B.6 (kid, rotation) and B.8 (revocation at refresh)."""
from __future__ import annotations

import os
from datetime import timedelta

import jwt
import pytest
from django.contrib.auth.models import Group
from django.utils import timezone

from sso import tokens as sso_tokens
from sso.keys import load_keyset
from sso.models import UserTokenRevocation
from .conftest import ORIGIN, bearer, claims, login, sign

pytestmark = pytest.mark.django_db


def refresh(api, token, **extra):
    return api.post("/api/v1/auth/refresh", {"refresh_token": token}, format="json", **extra)


def test_refresh_rotation_old_token_rejected_on_reuse(api, tokens):
    r1 = refresh(api, tokens["refresh_token"])
    assert r1.status_code == 200
    new = r1.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert new["access_token"] and new["user"]["username"] == "thomas"
    reuse = refresh(api, tokens["refresh_token"])
    assert reuse.status_code == 401 and reuse.json()["error"] == "token_invalid"
    assert refresh(api, new["refresh_token"]).status_code == 200


def test_refresh_picks_up_fresh_groups(api, tokens, user):
    user.groups.add(Group.objects.create(name="admin"))
    c = jwt.decode(refresh(api, tokens["refresh_token"]).json()["access_token"],
                   options={"verify_signature": False})
    assert "admin" in c["groups"]


def test_access_token_rejected_at_refresh(api, tokens):
    r = refresh(api, tokens["access_token"])
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_refresh_garbage_and_missing(api, db):
    assert refresh(api, "not-a-jwt").json()["error"] == "token_invalid"
    r = api.post("/api/v1/auth/refresh", {"refresh_token": ""}, format="json")
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"


def test_refresh_inactive_user(api, tokens, user):
    user.is_active = False
    user.save()
    r = refresh(api, tokens["refresh_token"])
    assert r.status_code == 403 and r.json()["error"] == "account_inactive"


def test_refresh_deleted_user(api, tokens, user):
    user.delete()
    assert refresh(api, tokens["refresh_token"]).json()["error"] == "token_invalid"


def test_refresh_rejected_after_revocation_even_if_not_blacklisted(api, tokens, user):
    # B.8: revocation checked independently of the blacklist
    UserTokenRevocation.objects.create(user=user, revoked_at=timezone.now() + timedelta(seconds=2))
    r = refresh(api, tokens["refresh_token"])
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


@pytest.mark.parametrize("over", [
    {"exp": 1_000_000, "iat": 999_000},             # expired long ago
    {"aud": "other-audience"},
    {"iss": "https://evil.example"},
    {"token_type": "access"},
])
def test_refresh_rejects_bad_claims(api, user, over):
    tok = sign(claims(user.pk, **{"token_type": "refresh", **over}))
    r = refresh(api, tok)
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_refresh_rejects_unknown_kid_and_unpublished_key(api, user):
    c = claims(user.pk, token_type="refresh")
    assert refresh(api, sign(c, os.environ["SSO_TEST_ROGUE_PRIVATE"])).status_code == 401
    assert refresh(api, sign(c, kid=None)).status_code == 401
    # right key bytes but a kid we never published
    assert refresh(api, sign(c, kid="0000000000000000")).status_code == 401


def test_refresh_rejects_hs256_and_none(api, user, settings):
    c = claims(user.pk, token_type="refresh")
    import base64, hashlib, hmac, json
    # PyJWT refuses to HMAC with a PEM, so hand-craft the classic alg-confusion token
    def b64(d):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": settings.SSO_KEYSET.signing_kid}).encode())
    body = b64(json.dumps(c).encode())
    sig = hmac.new(settings.SSO_KEYSET.signing_public.pem.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    hs = f"{head}.{body}.{b64(sig)}"
    assert refresh(api, hs).status_code == 401
    none = jwt.encode(c, None, algorithm="none", headers={"kid": settings.SSO_KEYSET.signing_kid})
    assert refresh(api, none).status_code == 401


def test_rotation_refresh_token_signed_with_old_key_still_refreshes(api, user, monkeypatch, settings):
    """Deployment plan R14: issue with key A, switch signing to key B, refresh still works."""
    old = load_keyset(os.environ["SSO_TEST_OLD_PRIVATE"], [os.environ["SSO_TEST_CURRENT_PUBLIC"]])
    backend_a = sso_tokens.KidTokenBackend(old, audience=settings.SSO_AUDIENCE, issuer=settings.SSO_ISSUER, leeway=30)
    monkeypatch.setattr(sso_tokens, "get_token_backend", lambda: backend_a)
    tok = login(api).json()
    assert jwt.get_unverified_header(tok["refresh_token"])["kid"] == old.signing_kid
    monkeypatch.undo()  # signing switches to the current key (B)
    r = refresh(api, tok["refresh_token"])
    assert r.status_code == 200
    assert jwt.get_unverified_header(r.json()["access_token"])["kid"] == settings.SSO_KEYSET.signing_kid
    assert settings.SSO_KEYSET.signing_kid != old.signing_kid
    # old-key access token also accepted by /me during the overlap
    assert api.get("/api/v1/auth/me", **bearer(tok["access_token"])).status_code == 200


def test_logout_blacklists_refresh_token(api, tokens):
    r = api.post("/api/v1/auth/logout", {"refresh_token": tokens["refresh_token"]}, format="json")
    assert r.status_code == 204
    assert refresh(api, tokens["refresh_token"]).json()["error"] == "token_invalid"


def test_logout_invalid_token_native(api, db):
    r = api.post("/api/v1/auth/logout", {"refresh_token": "garbage"}, format="json")
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_logout_all_blacklists_everything_and_revokes(api, user):
    t1 = login(api).json()
    t2 = login(api).json()
    r = api.post("/api/v1/auth/logout-all", **bearer(t1["access_token"]))
    assert r.status_code == 204
    for t in (t1, t2):
        assert refresh(api, t["refresh_token"]).json()["error"] == "token_invalid"
    assert UserTokenRevocation.objects.filter(user=user).exists()
    # the SSO server itself no longer accepts pre-revocation access tokens
    assert api.get("/api/v1/auth/me", **bearer(t2["access_token"])).status_code == 401
    # a fresh login right after logout-all works (same-second revocation edge case)
    t3 = login(api).json()
    assert api.get("/api/v1/auth/me", **bearer(t3["access_token"])).status_code == 200
    assert refresh(api, t3["refresh_token"]).status_code == 200


def test_logout_all_requires_access_token(api, tokens):
    assert api.post("/api/v1/auth/logout-all").status_code == 401
    r = api.post("/api/v1/auth/logout-all", **bearer(tokens["refresh_token"]))
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_me_fresh_from_db(api, tokens, user):
    user.first_name = "Thomas"
    user.save()
    r = api.get("/api/v1/auth/me", **bearer(tokens["access_token"]))
    assert r.status_code == 200 and r.json()["first_name"] == "Thomas"


def test_me_unauthenticated_uniform_error(api, db):
    r = api.get("/api/v1/auth/me")
    assert r.status_code == 401
    assert r.json()["error"] == "token_invalid"
    assert r["WWW-Authenticate"].startswith("Bearer")


@pytest.mark.parametrize("over", [{"exp": 1_000_000, "iat": 999_000}, {"aud": "x"}, {"iss": "https://x"}])
def test_me_rejects_expired_wrong_aud_iss(api, user, over):
    r = api.get("/api/v1/auth/me", **bearer(sign(claims(user.pk, **over))))
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_me_inactive_user_gets_account_inactive(api, tokens, user):
    user.is_active = False
    user.save()
    r = api.get("/api/v1/auth/me", **bearer(tokens["access_token"]))
    assert r.status_code == 403 and r.json()["error"] == "account_inactive"


def test_password_change_revokes_but_login_rehash_does_not(api, user):
    t = login(api).json()  # this login re-hashes the legacy hash
    assert not UserTokenRevocation.objects.filter(user=user).exists()
    user.refresh_from_db()
    user.set_password(user.password and "Brand-New-Pass-77")
    user.save()
    assert UserTokenRevocation.objects.filter(user=user).exists()
    assert refresh(api, t["refresh_token"]).json()["error"] == "token_invalid"


def test_setting_same_password_does_not_revoke(api, user):
    from .conftest import PASSWORD
    user.set_password(PASSWORD)
    user.save()
    assert not UserTokenRevocation.objects.filter(user=user).exists()
    user.first_name = "x"
    user.save(update_fields=["first_name"])
    assert not UserTokenRevocation.objects.filter(user=user).exists()


def test_cookie_refresh_does_not_need_origin_when_body_token(api, tokens):
    # native body token: Origin check skipped (B.9)
    r = refresh(api, tokens["refresh_token"], HTTP_ORIGIN="https://evil.example")
    assert r.status_code == 200 and "refresh_token" in r.json()
    assert ORIGIN  # imported constant used elsewhere
