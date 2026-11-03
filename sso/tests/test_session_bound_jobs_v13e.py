"""v1.3e: long-running jobs are bound to the login session that started them (DESIGN-v1.3e-session-bound-jobs.md).

* Logout ends the whole session (sid): access tokens of the session fail at once, ``token.revoked {sub, sid,
  reason: logout}`` is emitted. Other sessions of the same user keep working.
* Password change ends every session: ``token.revoked {sub, reason: password_change}`` (no sid).
* ``POST /api/v1/service/sessions/status`` is the backstop sweep: which ``(sub, sid)`` are still alive.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

import jwt
import pytest
from django.core.management import call_command
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from sso import webhooks
from sso.models import RevokedSession, ServiceClient, WebhookDelivery, WebhookEvent
from sso.webhook_secrets import encrypt

from .conftest import ORIGIN, PASSWORD, bearer, claims, login, sign
from .test_admin_api_v13a import A, H, admin_user, at, basic, reauth  # noqa: F401

pytestmark = pytest.mark.django_db

STATUS = "/api/v1/service/sessions/status"
NEW_PASSWORD = "Brand-New-Pass-77"


# ------------------------------------------------------------------ helpers / fixtures
@pytest.fixture
def svc(db):
    """SGMCP-like service: introspects user tokens, subscribes to webhooks, sweeps session status."""
    c = ServiceClient(client_id="sgmcp", name="sgmcp", app_codename="app1", notify_url="https://sgmcp.example/hook")
    c.set_secret("sec")
    c.notify_secret_enc = encrypt("whsec")
    c.save()
    return c


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(webhooks, "http_post", lambda url, body, headers: calls.append((url, body, headers)) or 200)
    return calls


def introspect(api, token):
    return api.post("/api/v1/auth/introspect", {"token": token}, format="json", **basic("sgmcp", "sec")).json()


def refresh(api, token):
    return api.post("/api/v1/auth/refresh", {"refresh_token": token}, format="json")


def logout(api, token):
    return api.post("/api/v1/auth/logout", {"refresh_token": token}, format="json")


def sid_of(token: str) -> str:
    return jwt.decode(token, options={"verify_signature": False})["sid"]


def revoked_sent(sent):
    return [c for c in sent if c[2]["X-SSO-Event-Type"] == "token.revoked"]


def revoked_events():
    return [e.data for e in WebhookEvent.objects.filter(type="token.revoked").order_by("pk")]


def status(api, *pairs, auth=None):
    body = {"sessions": [{"sub": s, "sid": d} for s, d in pairs]}
    return api.post(STATUS, body, format="json", **(auth if auth is not None else basic("sgmcp", "sec")))


def one(api, sub, sid) -> dict:
    r = status(api, (sub, sid))
    assert r.status_code == 200, r.content
    return r.json()["sessions"][0]


def start_job(api, access_token) -> dict:
    """What a service records when a user starts a long-running job: owner_sub + sid from introspect."""
    body = introspect(api, access_token)
    assert body["active"] is True and body["sid"]
    return {"owner_sub": body["sub"], "sid": body["sid"]}


# ------------------------------------------------------------------ logout
def test_logout_ends_the_session_but_not_other_sessions(api, svc, user):
    t1, t2 = login(api).json(), login(api).json()
    job1, job2 = start_job(api, t1["access_token"]), start_job(api, t2["access_token"])
    assert job1["sid"] != job2["sid"]

    assert logout(api, t1["refresh_token"]).status_code == 204

    assert introspect(api, t1["access_token"]) == {"active": False}  # before v1.3e: active until exp
    me = api.get("/api/v1/auth/me", **bearer(t1["access_token"]))
    assert me.status_code == 401 and me.json()["error"] == "token_invalid"
    assert refresh(api, t1["refresh_token"]).status_code == 401
    assert RevokedSession.objects.get(sid=job1["sid"]).reason == "logout"
    # the other session (other device / tab) is untouched
    assert introspect(api, t2["access_token"])["active"] is True
    assert refresh(api, t2["refresh_token"]).status_code == 200


def test_logout_emits_token_revoked_with_sid_and_delivers_it(api, svc, sent, user):
    t = login(api).json()
    job = start_job(api, t["access_token"])
    assert logout(api, t["refresh_token"]).status_code == 204

    assert revoked_events() == [{"sub": str(user.pk), "sid": job["sid"], "reason": "logout"}]
    call_command("run_webhook_worker", "--once")
    assert WebhookDelivery.objects.get(client=svc, event__type="token.revoked").status == "delivered"
    url, body, headers = revoked_sent(sent)[0]
    payload = json.loads(body)
    assert url == svc.notify_url and payload["type"] == "token.revoked"
    assert (payload["sub"], payload["sid"], payload["reason"]) == (job["owner_sub"], job["sid"], "logout")
    assert headers["X-SSO-Signature"] == webhooks.sign("whsec", int(headers["X-SSO-Timestamp"]), body)


def test_logout_after_refresh_ends_the_whole_session_family(api, svc, user):
    t1 = login(api).json()
    t2 = refresh(api, t1["refresh_token"]).json()  # same sid, rotated
    assert sid_of(t2["refresh_token"]) == sid_of(t1["refresh_token"])
    assert logout(api, t2["refresh_token"]).status_code == 204
    for access in (t1["access_token"], t2["access_token"]):
        assert introspect(api, access) == {"active": False}
    assert [e["sid"] for e in revoked_events()] == [sid_of(t1["refresh_token"])]


def test_cookie_mode_logout_ends_the_session(api, svc, user):
    r = login(api, client="browser", HTTP_ORIGIN=ORIGIN)
    access = r.json()["access_token"]
    sid = sid_of(access)
    assert api.post("/api/v1/auth/logout", {}, format="json", HTTP_ORIGIN=ORIGIN).status_code == 204
    assert introspect(api, access) == {"active": False}
    assert revoked_events() == [{"sub": str(user.pk), "sid": sid, "reason": "logout"}]


def test_second_logout_is_rejected_and_emits_once(api, svc, user):
    t = login(api).json()
    assert logout(api, t["refresh_token"]).status_code == 204
    r = logout(api, t["refresh_token"])
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"
    assert len(revoked_events()) == 1


def test_logout_of_a_token_without_sid_only_blacklists(api, svc, user):
    """Tokens issued before sessions existed (v1.2a) carry no sid: nothing to bind a job to, no event."""
    legacy = sign(claims(user.pk, token_type="refresh", exp=int(timezone.now().timestamp()) + 3600))
    assert logout(api, legacy).status_code == 204
    assert refresh(api, legacy).status_code == 401
    assert revoked_events() == [] and not RevokedSession.objects.exists()


def test_logout_log_line_is_info_and_has_no_token(api, svc, user, caplog):
    t = login(api).json()
    with caplog.at_level(logging.INFO, logger="sso.auth"):
        assert logout(api, t["refresh_token"]).status_code == 204
    rec = [r for r in caplog.records if '"session_revoked"' in r.getMessage()]
    assert len(rec) == 1 and rec[0].levelno == logging.INFO and '"reason": "logout"' in rec[0].getMessage()
    assert t["refresh_token"] not in caplog.text and t["access_token"] not in caplog.text
    assert sid_of(t["refresh_token"]) not in caplog.text


def test_session_revocations_other_than_logout_still_warn(user, caplog):
    from sso.revocation import revoke_session

    with caplog.at_level(logging.INFO, logger="sso.auth"):
        revoke_session(user, "s-reuse", "refresh_reuse")
    assert [r.levelno for r in caplog.records if "session_revoked" in r.getMessage()] == [logging.WARNING]


def test_logout_rolls_back_without_event_if_revocation_fails(api, svc, user, monkeypatch):
    """Outbox: the session revocation and its event are one transaction."""
    from sso import revocation

    t = login(api).json()

    def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(revocation, "drop_reauth", boom)
    assert logout(api, t["refresh_token"]).status_code == 500
    assert revoked_events() == [] and not RevokedSession.objects.exists()


# ------------------------------------------------------------------ password change
def test_password_change_ends_every_session_and_emits_without_sid(api, svc, sent, user):
    t1, t2 = login(api).json(), login(api).json()
    user.refresh_from_db()
    user.set_password(NEW_PASSWORD)
    user.save()

    assert revoked_events() == [{"sub": str(user.pk), "reason": "password_change"}]  # no sid: all sessions
    for t in (t1, t2):
        assert introspect(api, t["access_token"]) == {"active": False}
        assert refresh(api, t["refresh_token"]).status_code == 401
    call_command("run_webhook_worker", "--once")
    assert json.loads(revoked_sent(sent)[0][1])["reason"] == "password_change"
    # the user logs in with the new password: a new session, alive
    t3 = login(api, password=NEW_PASSWORD).json()
    assert introspect(api, t3["access_token"])["active"] is True


def test_admin_set_password_ends_the_users_sessions(api, svc, at, reauth, user):  # noqa: F811
    t = login(api).json()
    r = api.post(f"{A}/users/{user.pk}/set-password", {"password": NEW_PASSWORD}, format="json", **H(at, reauth))
    assert r.status_code == 204
    assert {"sub": str(user.pk), "reason": "password_change"} in revoked_events()
    assert introspect(api, t["access_token"]) == {"active": False}
    assert one(api, str(user.pk), sid_of(t["refresh_token"])) == {
        "sub": str(user.pk), "sid": sid_of(t["refresh_token"]), "active": False, "reason": "revoked"}


def test_same_password_and_login_rehash_emit_nothing(api, svc, user):
    t = login(api).json()  # re-hashes the legacy PBKDF2 hash: not a password change
    user.refresh_from_db()
    user.set_password(PASSWORD)  # same password again
    user.save()
    assert revoked_events() == []
    assert introspect(api, t["access_token"])["active"] is True


# ------------------------------------------------------------------ session status (backstop sweep)
def test_status_alive_after_login_and_across_refresh(api, svc, user):
    t1 = login(api).json()
    sub, sid = str(user.pk), sid_of(t1["refresh_token"])
    assert one(api, sub, sid) == {"sub": sub, "sid": sid, "active": True}
    t2 = refresh(api, t1["refresh_token"]).json()
    refresh(api, t2["refresh_token"])
    r = status(api, (sub, sid))
    assert r.json()["sessions"][0]["active"] is True and r["Cache-Control"] == "no-store"


def test_status_after_logout(api, svc, user):
    t = login(api).json()
    sid = sid_of(t["refresh_token"])
    logout(api, t["refresh_token"])
    assert one(api, str(user.pk), sid) == {"sub": str(user.pk), "sid": sid, "active": False, "reason": "logout"}


@pytest.mark.parametrize("how", ["password_change", "logout_all"])
def test_status_after_user_wide_revocation(api, svc, user, how):
    t = login(api).json()
    if how == "password_change":
        user.refresh_from_db()
        user.set_password(NEW_PASSWORD)
        user.save()
    else:
        assert api.post("/api/v1/auth/logout-all", **bearer(t["access_token"])).status_code == 204
    t_new = login(api, password=NEW_PASSWORD if how == "password_change" else PASSWORD).json()
    r = status(api, (str(user.pk), sid_of(t["refresh_token"])), (str(user.pk), sid_of(t_new["refresh_token"])))
    old, new = r.json()["sessions"]
    assert old["active"] is False and old["reason"] == "revoked"
    assert new["active"] is True


def test_status_after_refresh_reuse(api, svc, user, settings):
    settings.SSO_REFRESH_REUSE_GRACE_SECONDS = 0
    t1 = login(api).json()
    refresh(api, t1["refresh_token"])
    assert refresh(api, t1["refresh_token"]).status_code == 401  # reuse of a rotated token = theft
    assert one(api, str(user.pk), sid_of(t1["refresh_token"]))["reason"] == "refresh_reuse"


def test_status_expired_idle_session_and_unknown_sid(api, svc, user):
    t = login(api).json()
    sid = sid_of(t["refresh_token"])
    OutstandingToken.objects.filter(user=user).update(expires_at=timezone.now() - timedelta(seconds=1))
    assert one(api, str(user.pk), sid)["reason"] == "expired"  # idle past the refresh lifetime: no webhook
    assert one(api, str(user.pk), "no-such-sid")["reason"] == "expired"


def test_status_inactive_and_deleted_users(api, svc, user, make_user):
    t = login(api).json()
    sid = sid_of(t["refresh_token"])
    user.is_active = False
    user.save()
    assert one(api, str(user.pk), sid)["reason"] == "user_inactive"
    pk = user.pk
    user.delete()
    assert one(api, str(pk), sid)["reason"] == "user_deleted"


def test_status_many_users_keeps_request_order(api, svc, user, make_user):
    other = make_user(username="ann", email="ann@example.org")
    ta, tb = login(api).json(), login(api, username="ann").json()
    logout(api, ta["refresh_token"])
    pairs = [(str(other.pk), sid_of(tb["refresh_token"])), (str(user.pk), sid_of(ta["refresh_token"])),
             (str(other.pk), sid_of(ta["refresh_token"]))]  # a sid of another user is not alive for this user
    got = status(api, *pairs).json()["sessions"]
    assert [(g["sub"], g["sid"]) for g in got] == pairs
    assert [g["active"] for g in got] == [True, False, False]
    assert got[1]["reason"] == "logout"


def test_status_auth(api, svc, user):
    t = login(api).json()
    pair = (str(user.pk), sid_of(t["refresh_token"]))
    r = status(api, pair, auth={})
    assert r.status_code == 401 and r["WWW-Authenticate"].startswith("Basic")
    assert status(api, pair, auth=basic("sgmcp", "wrong")).status_code == 401
    assert status(api, pair, auth=bearer(t["access_token"])).status_code == 401  # a user token is not a service
    st = api.post("/api/v1/auth/service-token", {"grant_type": "client_credentials"}, format="json",
                  **basic("sgmcp", "sec")).json()["access_token"]
    assert status(api, pair, auth=bearer(st)).json()["sessions"][0]["active"] is True


@pytest.mark.parametrize("body", [
    {}, {"sessions": []}, {"sessions": "x"}, {"sessions": [{"sub": "1"}]}, {"sessions": [{"sid": "a"}]},
    {"sessions": [{"sub": 1, "sid": "a"}]}, {"sessions": [{"sub": "-1", "sid": "a"}]},
    {"sessions": [{"sub": "1", "sid": ""}]}, {"sessions": [{"sub": "1", "sid": "x" * 65}]},
    {"sessions": ["1:a"]}, {"sessions": [{"sub": "1", "sid": "a"}] * 101}, [1, 2],
])
def test_status_validation(api, svc, body):
    r = api.post(STATUS, body, format="json", **basic("sgmcp", "sec"))
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"


def test_replay_after_logout_does_not_emit_a_second_event(api, svc, user, settings):
    """A refresh token replayed after logout is handled as reuse, but the session already ended: no second
    token.revoked, and the recorded reason stays ``logout``."""
    settings.SSO_REFRESH_REUSE_GRACE_SECONDS = 0
    t = login(api).json()
    assert logout(api, t["refresh_token"]).status_code == 204
    assert refresh(api, t["refresh_token"]).status_code == 401
    assert [e["reason"] for e in revoked_events()] == ["logout"]
    assert RevokedSession.objects.get(sid=sid_of(t["refresh_token"])).reason == "logout"
