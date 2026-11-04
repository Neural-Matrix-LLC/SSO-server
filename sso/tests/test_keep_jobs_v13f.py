"""v1.3f: "log out, keep my jobs running" (DESIGN-v1.3e-session-bound-jobs.md §6).

``POST /api/v1/auth/logout {"keep_jobs": true}`` ends the session exactly like a logout (access and refresh tokens of
the sid dead at once), but ``token.revoked`` carries ``keep_jobs: true`` and the session-status sweep answers
``detached``: job services detach the session's jobs instead of stopping them. Detached jobs are still stopped by
everything that ends every session of the user (logout-all, password change, admin) and stopped + deleted by
suspend / delete. The first half checks the SSO, the second half drives the dummy job service end to end.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from sso.models import RevokedSession, UserTokenRevocation, WebhookDelivery
from sso.revocation import prune_revoked_sessions, revoke_user_tokens

from .conftest import ORIGIN, bearer, claims, login, sign
from .dummy_job_service import DELETED, RUNNING, STOPPED, JobRefused
from .test_admin_api_v13a import A, H, admin_user, at, basic, perm, reauth  # noqa: F401
from .test_dummy_jobs_v13e import change_password, deliver, jobsvc, user_login  # noqa: F401
from .test_session_bound_jobs_v13e import (  # noqa: F401
    NEW_PASSWORD, introspect, one, refresh, revoked_events, revoked_sent, sent, sid_of, svc,
)

pytestmark = pytest.mark.django_db

LOGOUT = "/api/v1/auth/logout"


def logout(api, token, **extra):
    return api.post(LOGOUT, {"refresh_token": token, **extra}, format="json")


def keep_jobs_logout(api, token):
    r = logout(api, token, keep_jobs=True)
    assert r.status_code == 204, r.content
    return r


# ================================================================== SSO side
def test_keep_jobs_logout_ends_the_session_like_a_logout(api, svc, user):
    laptop, phone = login(api).json(), login(api).json()
    keep_jobs_logout(api, laptop["refresh_token"])
    # the session itself is over: no token of it works, it cannot be refreshed or logged out twice
    assert introspect(api, laptop["access_token"]) == {"active": False}
    assert api.get("/api/v1/auth/me", **bearer(laptop["access_token"])).json()["error"] == "token_invalid"
    assert refresh(api, laptop["refresh_token"]).status_code == 401
    assert logout(api, laptop["refresh_token"], keep_jobs=True).status_code == 401
    # other sessions of the user are untouched
    assert introspect(api, phone["access_token"])["active"] is True
    assert RevokedSession.objects.get(sid=sid_of(laptop["refresh_token"])).reason == "logout_keep_jobs"


def test_keep_jobs_logout_emits_token_revoked_with_keep_jobs(api, svc, sent, user):
    t = login(api).json()
    keep_jobs_logout(api, t["refresh_token"])
    sid = sid_of(t["refresh_token"])
    # reason stays "logout": a v1.3e service that does not know keep_jobs stops the jobs (safe fallback)
    assert revoked_events() == [{"sub": str(user.pk), "sid": sid, "reason": "logout", "keep_jobs": True}]
    deliver()
    body = json.loads(revoked_sent(sent)[0][1])
    assert body["keep_jobs"] is True and body["sid"] == sid and body["reason"] == "logout"


def test_plain_logout_and_keep_jobs_false_carry_no_keep_jobs(api, svc, user):
    t1, t2 = login(api).json(), login(api).json()
    assert logout(api, t1["refresh_token"]).status_code == 204
    assert logout(api, t2["refresh_token"], keep_jobs=False).status_code == 204
    assert [e.get("keep_jobs") for e in revoked_events()] == [None, None]
    assert {e["reason"] for e in revoked_events()} == {"logout"}
    assert set(RevokedSession.objects.values_list("reason", flat=True)) == {"logout"}


def test_keep_jobs_logout_in_browser_cookie_mode(api, svc, user):
    login(api, client="browser", HTTP_ORIGIN=ORIGIN)
    r = api.post(LOGOUT, {"keep_jobs": True}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 204
    assert r.cookies["sso_refresh"].value == ""  # cookie cleared as for every logout
    assert [e.get("keep_jobs") for e in revoked_events()] == [True]


@pytest.mark.parametrize("value", ["true", 1, 0, "yes", None, [], {}])
def test_keep_jobs_must_be_a_json_boolean_and_nothing_is_consumed(api, svc, user, value):
    t = login(api).json()
    r = logout(api, t["refresh_token"], keep_jobs=value)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    # the bad request did not log the user out
    assert introspect(api, t["access_token"])["active"] is True
    assert refresh(api, t["refresh_token"]).status_code == 200
    assert revoked_events() == []


def test_keep_jobs_validated_in_cookie_mode_without_a_cookie(api, svc):
    r = api.post(LOGOUT, {"keep_jobs": "true"}, format="json", HTTP_ORIGIN=ORIGIN)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    assert api.post(LOGOUT, {"keep_jobs": True}, format="json", HTTP_ORIGIN=ORIGIN).status_code == 204


def test_keep_jobs_logout_of_a_token_without_sid_only_blacklists(api, svc, user):
    legacy = sign(claims(user.pk, token_type="refresh", exp=int(timezone.now().timestamp()) + 3600))
    assert logout(api, legacy, keep_jobs=True).status_code == 204
    assert refresh(api, legacy).status_code == 401
    assert revoked_events() == [] and not RevokedSession.objects.exists()


def test_keep_jobs_logout_log_line_is_info_without_token_or_sid(api, svc, user, caplog):
    t = login(api).json()
    with caplog.at_level(logging.INFO, logger="sso.auth"):
        keep_jobs_logout(api, t["refresh_token"])
    rec = [r for r in caplog.records if '"session_revoked"' in r.getMessage()]
    assert len(rec) == 1 and rec[0].levelno == logging.INFO
    assert '"reason": "logout_keep_jobs"' in rec[0].getMessage()
    for secret in (t["refresh_token"], t["access_token"], sid_of(t["refresh_token"])):
        assert secret not in caplog.text


def test_replay_after_keep_jobs_logout_keeps_the_reason_and_emits_once(api, svc, user, settings):
    settings.SSO_REFRESH_REUSE_GRACE_SECONDS = 0
    t = login(api).json()
    keep_jobs_logout(api, t["refresh_token"])
    assert refresh(api, t["refresh_token"]).status_code == 401
    assert len(revoked_events()) == 1
    assert RevokedSession.objects.get(sid=sid_of(t["refresh_token"])).reason == "logout_keep_jobs"


# ------------------------------------------------------------------ session status: detached
def test_status_detached_after_keep_jobs_logout(api, svc, user):
    t, other = login(api).json(), login(api).json()
    keep_jobs_logout(api, t["refresh_token"])
    assert one(api, str(user.pk), sid_of(t["refresh_token"])) == {
        "sub": str(user.pk), "sid": sid_of(t["refresh_token"]), "active": False, "reason": "detached"}
    assert one(api, str(user.pk), sid_of(other["refresh_token"]))["active"] is True


def test_status_detached_survives_the_refresh_lifetime(api, svc, user):
    """The jobs outlive the session: once its refresh tokens have expired the sid must still say detached."""
    t = login(api).json()
    keep_jobs_logout(api, t["refresh_token"])
    OutstandingToken.objects.filter(user=user).update(expires_at=timezone.now() - timedelta(seconds=1))
    assert one(api, str(user.pk), sid_of(t["refresh_token"]))["reason"] == "detached"


@pytest.mark.parametrize("how", ["password_change", "logout_all", "admin"])
def test_status_revoked_once_every_session_of_the_user_ends(api, svc, user, how):
    t = login(api).json()
    keep_jobs_logout(api, t["refresh_token"])
    later = login(api).json()
    if how == "password_change":
        change_password(user)
    elif how == "logout_all":
        assert api.post("/api/v1/auth/logout-all", **bearer(later["access_token"])).status_code == 204
    else:
        revoke_user_tokens(user, "admin")
    assert one(api, str(user.pk), sid_of(t["refresh_token"]))["reason"] == "revoked"


def test_status_detached_when_the_user_wide_revocation_came_before(api, svc, user):
    """An older logout-all does not cancel a keep-jobs logout made after it."""
    revoke_user_tokens(user, "logout_all")
    user.refresh_from_db()
    t = login(api).json()  # a new session after the logout-all (iat >= epoch)
    UserTokenRevocation.objects.filter(user=user).update(revoked_at=timezone.now() - timedelta(minutes=5))
    keep_jobs_logout(api, t["refresh_token"])
    assert one(api, str(user.pk), sid_of(t["refresh_token"]))["reason"] == "detached"


def test_status_suspended_and_deleted_user_after_keep_jobs_logout(api, svc, user):
    t = login(api).json()
    keep_jobs_logout(api, t["refresh_token"])
    sid = sid_of(t["refresh_token"])
    user.is_active = False
    user.save()
    assert one(api, str(user.pk), sid)["reason"] == "user_inactive"
    pk = user.pk
    user.delete()
    assert one(api, str(pk), sid)["reason"] == "user_deleted"


# ------------------------------------------------------------------ retention (prune)
def _aged(user, sid, reason, settings):
    old = timezone.now() - settings.SSO_REFRESH_TTL - timedelta(days=2)
    return RevokedSession.objects.create(sid=sid, user=user, reason=reason, revoked_at=old)


def test_prune_keeps_detached_rows_until_a_later_user_wide_revocation(user, make_user, settings):
    other = make_user(username="ann", email="ann@example.org")
    _aged(user, "plain", "logout", settings)
    detached = _aged(user, "kept", "logout_keep_jobs", settings)
    _aged(other, "ann-kept", "logout_keep_jobs", settings)
    # ann's older revocation came before her keep-jobs logout: still detached
    UserTokenRevocation.objects.create(user=other, revoked_at=detached.revoked_at - timedelta(days=1))

    assert prune_revoked_sessions(dry_run=True) == 1
    assert prune_revoked_sessions() == 1
    assert set(RevokedSession.objects.values_list("sid", flat=True)) == {"kept", "ann-kept"}

    revoke_user_tokens(user, "password_change")  # ends thomas's detached jobs: the row may go now
    assert prune_revoked_sessions() == 1
    assert list(RevokedSession.objects.values_list("sid", flat=True)) == ["ann-kept"]
    other.delete()  # cascade
    assert not RevokedSession.objects.exists()


# ================================================================== dummy job service, end to end
def test_dummy_keep_jobs_logout_detaches_the_sessions_jobs(api, jobsvc, user):
    laptop, phone = user_login(api), user_login(api)
    jobsvc.start_job(laptop["access_token"], name="laptop-1")
    jobsvc.start_job(laptop["access_token"], name="laptop-2")
    jobsvc.start_job(phone["access_token"], name="phone-1")

    keep_jobs_logout(api, laptop["refresh_token"])
    deliver()
    for _ in range(3):
        jobsvc.tick_all()

    assert {s for s, _, _ in jobsvc.states().values()} == {RUNNING}
    assert {j.name: j.detached for j in jobsvc.jobs.values()} == {"laptop-1": True, "laptop-2": True,
                                                                   "phone-1": False}
    assert all(j.ticks == 3 for j in jobsvc.jobs.values())  # the work goes on
    assert (str(user.pk), "job laptop-1 keeps running after logout") in jobsvc.notifications
    assert jobsvc.sweep() == []  # the sweep agrees: detached, not stopped
    # the logged-out session itself is over: its token cannot start new jobs
    with pytest.raises(JobRefused, match="token_inactive"):
        jobsvc.start_job(laptop["access_token"], name="late")


def test_dummy_keep_jobs_in_cookie_mode(api, jobsvc, user):
    r = login(api, client="browser", HTTP_ORIGIN=ORIGIN)
    jobsvc.start_job(r.json()["access_token"], name="spa-job")
    assert api.post(LOGOUT, {"keep_jobs": True}, format="json", HTTP_ORIGIN=ORIGIN).status_code == 204
    deliver()
    job = jobsvc.jobs[1]
    assert job.state == RUNNING and job.detached


def test_dummy_plain_logout_still_stops(api, jobsvc, user):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="j")
    assert logout(api, t["refresh_token"], keep_jobs=False).status_code == 204
    deliver()
    assert jobsvc.states()["j"] == (STOPPED, "logout", "webhook")


def test_dummy_other_sessions_logout_does_not_touch_detached_jobs(api, jobsvc, user):
    first = user_login(api)
    jobsvc.start_job(first["access_token"], name="kept")
    keep_jobs_logout(api, first["refresh_token"])
    second = user_login(api)  # the user comes back, starts another job, logs out normally
    jobsvc.start_job(second["access_token"], name="normal")
    assert logout(api, second["refresh_token"]).status_code == 204
    deliver()
    assert jobsvc.states() == {"kept": (RUNNING, None, None), "normal": (STOPPED, "logout", "webhook")}
    assert jobsvc.sweep() == []


@pytest.mark.parametrize("how,reason", [("password_change", "password_change"), ("logout_all", "logout_all")])
def test_dummy_detached_jobs_stop_when_every_session_ends(api, jobsvc, user, how, reason):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="kept")
    keep_jobs_logout(api, t["refresh_token"])
    deliver()
    assert jobsvc.jobs[1].detached and jobsvc.jobs[1].state == RUNNING
    if how == "password_change":
        change_password(user)
    else:
        later = user_login(api)
        assert api.post("/api/v1/auth/logout-all", **bearer(later["access_token"])).status_code == 204
    deliver()
    assert jobsvc.states()["kept"] == (STOPPED, reason, "webhook")


def test_dummy_admin_set_password_stops_detached_jobs(api, jobsvc, user, at, reauth):  # noqa: F811
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="kept")
    keep_jobs_logout(api, t["refresh_token"])
    deliver()
    r = api.post(f"{A}/users/{user.pk}/set-password", {"password": NEW_PASSWORD}, format="json", **H(at, reauth))
    assert r.status_code == 204, r.content
    deliver()
    assert jobsvc.states()["kept"] == (STOPPED, "password_change", "webhook")


def test_dummy_suspend_and_delete_still_delete_detached_jobs(api, jobsvc, user, make_user):
    ann = make_user(username="ann", email="ann@example.org")
    t, a = user_login(api), user_login(api, username="ann")
    jobsvc.start_job(t["access_token"], name="thomas")
    jobsvc.start_job(a["access_token"], name="ann")
    keep_jobs_logout(api, t["refresh_token"])
    keep_jobs_logout(api, a["refresh_token"])
    deliver()
    user.is_active = False
    user.save()
    ann.delete()
    deliver()
    assert jobsvc.jobs[1].state == DELETED and jobsvc.jobs[1].stop_reason == "suspended"
    assert jobsvc.jobs[2].state == DELETED and jobsvc.jobs[2].stop_reason == "deleted"


def test_dummy_lost_keep_jobs_webhook_sweep_detaches_and_late_retry_is_harmless(api, jobsvc, user):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="kept")
    jobsvc.network_up = False
    keep_jobs_logout(api, t["refresh_token"])
    deliver()  # lost
    assert not jobsvc.jobs[1].detached
    assert jobsvc.sweep() == []  # the sweep says "detached": keep running
    assert jobsvc.jobs[1].detached and jobsvc.jobs[1].state == RUNNING
    jobsvc.network_up = True
    WebhookDelivery.objects.update(next_attempt_at=timezone.now())
    deliver()  # the retried webhook arrives late: changes nothing, one notification only
    assert jobsvc.jobs[1].state == RUNNING
    assert [m for _, m in jobsvc.notifications] == ["job kept keeps running after logout"]


def test_dummy_lost_password_change_webhook_sweep_stops_detached_jobs(api, jobsvc, user):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="kept")
    keep_jobs_logout(api, t["refresh_token"])
    deliver()
    jobsvc.network_up = False
    change_password(user)
    deliver()  # lost
    assert jobsvc.jobs[1].state == RUNNING
    [stopped] = jobsvc.sweep()
    assert stopped.name == "kept" and jobsvc.states()["kept"] == (STOPPED, "revoked", "sweep")


def test_dummy_detached_jobs_outlive_the_refresh_lifetime(api, jobsvc, user, settings):
    """Days later: the session's refresh tokens have expired and the prune has run; the jobs keep running."""
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="kept")
    keep_jobs_logout(api, t["refresh_token"])
    deliver()
    OutstandingToken.objects.filter(user=user).update(expires_at=timezone.now() - timedelta(seconds=1))
    RevokedSession.objects.update(revoked_at=timezone.now() - settings.SSO_REFRESH_TTL - timedelta(days=2))
    assert prune_revoked_sessions() == 0
    jobsvc.tick_all()
    assert jobsvc.sweep() == [] and jobsvc.states()["kept"] == (RUNNING, None, None)


# ------------------------------------------------------------------ dummy jobs: the user signs in again
def _detached_job(api, jobsvc, name="kept"):
    t = user_login(api)
    job = jobsvc.start_job(t["access_token"], name=name)
    keep_jobs_logout(api, t["refresh_token"])
    deliver()
    assert job.detached and job.state == RUNNING
    return job, t


def test_dummy_new_session_sees_detached_jobs_by_user_id(api, jobsvc, user, make_user):
    make_user(username="ann", email="ann@example.org")
    job, _ = _detached_job(api, jobsvc)
    ann_job = jobsvc.start_job(user_login(api, username="ann")["access_token"], name="ann")
    again = user_login(api)  # new session, new sid
    mine = jobsvc.list_jobs(again["access_token"])
    assert [(j.id, j.detached) for j in mine] == [(job.id, True)]  # the user's own jobs only
    assert ann_job not in mine


def test_dummy_new_session_can_stop_a_detached_job(api, jobsvc, user):
    job, _ = _detached_job(api, jobsvc)
    again = user_login(api)
    jobsvc.stop_job(again["access_token"], job.id)
    jobsvc.tick_all()
    assert jobsvc.states()["kept"] == (STOPPED, "user", "user") and job.ticks == 0
    assert jobsvc.sweep() == []  # nothing left running


def test_dummy_reattach_binds_the_job_to_the_new_session(api, jobsvc, user):
    job, _ = _detached_job(api, jobsvc)
    again = user_login(api)
    jobsvc.attach_job(again["access_token"], job.id)
    assert job.owner_sid == sid_of(again["refresh_token"]) and not job.detached
    assert jobsvc.sweep() == []  # the new session is alive
    # session rules apply again: a plain logout of the new session stops it
    assert logout(api, again["refresh_token"]).status_code == 204
    deliver()
    assert jobsvc.states()["kept"] == (STOPPED, "logout", "webhook")


def test_dummy_reattach_then_keep_jobs_logout_detaches_again(api, jobsvc, user):
    job, _ = _detached_job(api, jobsvc)
    again = user_login(api)
    jobsvc.attach_job(again["access_token"], job.id)
    keep_jobs_logout(api, again["refresh_token"])
    deliver()
    assert job.state == RUNNING and job.detached and job.owner_sid == sid_of(again["refresh_token"])
    assert jobsvc.sweep() == []


def test_dummy_job_control_is_refused_to_others_and_dead_sessions(api, jobsvc, user, make_user):
    make_user(username="ann", email="ann@example.org")
    job, old = _detached_job(api, jobsvc)
    ann = user_login(api, username="ann")
    for call in (jobsvc.stop_job, jobsvc.attach_job):
        with pytest.raises(JobRefused, match="not_found"):  # another user's job: as if it did not exist
            call(ann["access_token"], job.id)
        with pytest.raises(JobRefused, match="token_inactive"):  # the logged-out session cannot take it back
            call(old["access_token"], job.id)
    with pytest.raises(JobRefused, match="not_found"):
        jobsvc.stop_job(user_login(api)["access_token"], 999)
    assert job.state == RUNNING and job.detached


def test_dummy_stopped_job_cannot_be_reattached(api, jobsvc, user):
    job, _ = _detached_job(api, jobsvc)
    again = user_login(api)
    jobsvc.stop_job(again["access_token"], job.id)
    with pytest.raises(JobRefused, match="not_running"):
        jobsvc.attach_job(again["access_token"], job.id)
