"""v1.2a: ``sid`` session claim, refresh-token reuse revokes the session (family), concurrency grace."""
from __future__ import annotations

import base64
import threading
from datetime import timedelta
from unittest import mock

import jwt
import pytest
from django.db import connection
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from sso.models import RevokedSession, ServiceClient
from sso.revocation import revoke_session, token_sid
from .conftest import bearer, claims, login, sign

pytestmark = pytest.mark.django_db


def payload(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def refresh(api, token):
    return api.post("/api/v1/auth/refresh", {"refresh_token": token}, format="json")


@pytest.fixture
def service(db):
    c = ServiceClient(client_id="svc", name="Svc")
    c.set_secret("svc-secret-value")
    c.save()
    return c


def introspect(api, token):
    auth = "Basic " + base64.b64encode(b"svc:svc-secret-value").decode()
    return api.post("/api/v1/auth/introspect", {"token": token}, format="json", HTTP_AUTHORIZATION=auth).json()


def _age_blacklist(token: str, seconds: int) -> None:
    jti = payload(token)["jti"]
    BlacklistedToken.objects.filter(token__jti=jti).update(blacklisted_at=timezone.now() - timedelta(seconds=seconds))


def test_login_starts_a_session_and_refresh_keeps_it(api, user):
    t1 = login(api).json()
    sid = payload(t1["refresh_token"])["sid"]
    assert sid and payload(t1["access_token"])["sid"] == sid
    t2 = refresh(api, t1["refresh_token"]).json()
    assert payload(t2["refresh_token"])["sid"] == sid and payload(t2["access_token"])["sid"] == sid
    # the stored outstanding token string carries the sid (the family can be found by claim)
    assert token_sid(OutstandingToken.objects.get(jti=payload(t2["refresh_token"])["jti"]).token) == sid
    t3 = login(api).json()
    assert payload(t3["refresh_token"])["sid"] != sid  # a new login is a new session


def test_cookie_mode_carries_sid(api, user, settings):
    r = login(api, client="browser", HTTP_ORIGIN="https://fin.example.test")
    raw = r.cookies[settings.SSO_COOKIE_NAME].value
    assert payload(raw)["sid"] == payload(r.json()["access_token"])["sid"]


def test_reuse_after_grace_revokes_the_whole_session(api, user, service):
    t1 = login(api).json()
    other = login(api).json()  # a second session of the same user
    t2 = refresh(api, t1["refresh_token"]).json()
    _age_blacklist(t1["refresh_token"], 3600)  # the old token was used an hour ago
    r = refresh(api, t1["refresh_token"])  # replay (stolen copy)
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"
    sid = payload(t1["refresh_token"])["sid"]
    assert RevokedSession.objects.filter(sid=sid, user=user, reason="refresh_reuse").exists()
    # the legitimate holder's newer tokens of that session are dead too
    assert refresh(api, t2["refresh_token"]).status_code == 401
    assert introspect(api, t2["access_token"]) == {"active": False}
    assert api.get("/api/v1/auth/me", **bearer(t2["access_token"])).status_code == 401
    # the other session is untouched
    assert introspect(api, other["access_token"])["active"] is True
    assert refresh(api, other["refresh_token"]).status_code == 200
    # and the user can log in again
    assert refresh(api, login(api).json()["refresh_token"]).status_code == 200


def test_reuse_within_grace_is_401_but_keeps_the_session(api, user, service, caplog):
    t1 = login(api).json()
    t2 = refresh(api, t1["refresh_token"]).json()
    r = refresh(api, t1["refresh_token"])  # the slower of two tabs, a moment later
    assert r.status_code == 401
    assert not RevokedSession.objects.exists()
    assert introspect(api, t2["access_token"])["active"] is True
    assert refresh(api, t2["refresh_token"]).status_code == 200
    assert "reuse_within_grace" in caplog.text


def test_grace_zero_revokes_on_any_reuse(api, user, settings):
    settings.SSO_REFRESH_REUSE_GRACE_SECONDS = 0
    t1 = login(api).json()
    t2 = refresh(api, t1["refresh_token"]).json()
    assert refresh(api, t1["refresh_token"]).status_code == 401
    assert refresh(api, t2["refresh_token"]).status_code == 401


def test_lost_race_does_not_revoke(api, user, settings):
    """Two requests passed validation together; the blacklist insert decides: the loser gets 401, no revocation."""
    settings.SSO_REFRESH_REUSE_GRACE_SECONDS = 10
    t1 = login(api).json()
    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken as BT

    real = BT.objects.get_or_create

    def already(**kw):
        obj, _ = real(**kw)
        return obj, False

    with mock.patch.object(BT.objects, "get_or_create", side_effect=already):
        assert refresh(api, t1["refresh_token"]).status_code == 401
    assert not RevokedSession.objects.exists()


def test_interleaved_concurrent_refresh_does_not_revoke(api, user):
    """Deterministic interleaving of two concurrent refreshes of one token: request A has validated the token;
    request B (another tab) runs completely; then A tries to use it. A gets 401, the session is NOT revoked
    and B's new tokens keep working (the loss of A's tab is accepted: TODOS 'cross-tab refresh coordination')."""
    from sso import views

    t1 = login(api).json()
    real, other = views.load_refresh, {}

    def interleaved(raw, **kw):
        result = real(raw, **kw)
        if not other:
            with mock.patch.object(views, "load_refresh", real):
                other["r"] = refresh(APIClient(), raw)  # tab B, start to finish
        return result

    with mock.patch.object(views, "load_refresh", interleaved):
        a = refresh(api, t1["refresh_token"])
    b = other["r"]
    assert b.status_code == 200 and a.status_code == 401
    assert not RevokedSession.objects.exists()
    assert introspect_ok(b.json()["access_token"]) and refresh(api, b.json()["refresh_token"]).status_code == 200


def introspect_ok(access: str) -> bool:
    return APIClient().get("/api/v1/auth/me", **bearer(access)).status_code == 200


@pytest.mark.django_db(transaction=True)
def test_concurrent_legit_refreshes_do_not_revoke_the_session(user):
    """Real threads (MySQL only: SQLite serialises writers with 'database is locked'). N clients refresh the same
    token at once: exactly one wins, the rest get 401, and the session is NOT revoked, so the winner goes on."""
    if connection.vendor == "sqlite":
        pytest.skip("needs a server database for concurrent writers (docker-compose.test.yml runs it on MySQL)")
    t1 = login(APIClient()).json()
    n, barrier, results = 4, threading.Barrier(4), []
    lock = threading.Lock()

    def worker():
        c = APIClient()
        barrier.wait()
        try:
            r = refresh(c, t1["refresh_token"])
            with lock:
                results.append((r.status_code, r.json()))
        finally:
            connection.close()

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    codes = sorted(code for code, _ in results)
    assert codes.count(200) == 1 and codes.count(401) == n - 1, results
    winner = next(body for code, body in results if code == 200)
    assert not RevokedSession.objects.exists()
    assert refresh(APIClient(), winner["refresh_token"]).status_code == 200


def test_pre_v12a_token_without_sid_is_rejected_on_reuse_without_revocation(api, user):
    from sso.tokens import SSORefreshToken

    old = SSORefreshToken.for_user(user)  # issued like v1.1: no sid
    assert "sid" not in old.payload
    t = refresh(api, str(old)).json()
    assert payload(t["refresh_token"])["sid"]  # refreshing a legacy token starts a session
    _age_blacklist(str(old), 3600)
    assert refresh(api, str(old)).status_code == 401
    assert not RevokedSession.objects.exists()


def test_forged_or_expired_tokens_are_not_treated_as_reuse(api, user):
    forged = sign(claims(user.pk, token_type="refresh", sid="x"), kid=None)
    assert refresh(api, forged).status_code == 401
    expired = sign(claims(user.pk, token_type="refresh", sid="x", exp=1, iat=0))
    assert refresh(api, expired).status_code == 401
    assert not RevokedSession.objects.exists()


def test_revoke_session_is_idempotent_and_logs_no_token(user, caplog):
    assert revoke_session(user, "abc", "test") == 0
    assert revoke_session(user, "abc", "test") == 0
    assert RevokedSession.objects.count() == 1
    assert "abc" not in caplog.text
    assert token_sid("not-a-jwt") is None


def test_logout_of_a_reused_session_token_still_ok(api, user):
    t1 = login(api).json()
    t2 = refresh(api, t1["refresh_token"]).json()
    assert api.post("/api/v1/auth/logout", {"refresh_token": t2["refresh_token"]}, format="json").status_code == 204
