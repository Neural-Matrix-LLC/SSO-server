"""v1.3e end to end with a "dummy job" service (``dummy_job_service.py``): the testing client logs in, starts
long-running jobs, logs out / changes the password / goes idle / is suspended, and the tests check what happens to
the dummy jobs. Webhooks travel through the real outbox + worker with real signatures; the sweep calls the real
``/service/sessions/status`` endpoint.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from sso import webhooks
from sso.models import ServiceClient, WebhookDelivery, WebhookEvent
from sso.webhook_secrets import encrypt

from .conftest import ORIGIN, PASSWORD, bearer, login
from .dummy_job_service import DELETED, RUNNING, STOPPED, DummyJobService, JobRefused
from .test_admin_api_v13a import A, H, admin_user, at, basic, perm, reauth  # noqa: F401

pytestmark = pytest.mark.django_db

SECRET = "whsec-dummy-jobs"
NEW_PASSWORD = "Brand-New-Pass-77"


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def jobsvc(db, monkeypatch):
    """The dummy job service, registered at the SSO as ServiceClient ``jobs`` with a webhook subscription.
    Its SSO calls go through its own HTTP client (Basic auth); the SSO worker's POSTs land in receive_webhook."""
    c = ServiceClient(client_id="jobs", name="dummy jobs", app_codename="app1", notify_url="https://jobs.example/hook",
                      can_delegate=True)
    c.set_secret("jobs-secret")
    c.notify_secret_enc = encrypt(SECRET)
    c.save()
    http = APIClient()

    def sso(path, body):
        r = http.post(path, body, format="json", **basic("jobs", "jobs-secret"))
        return r.status_code, r.json()

    svc = DummyJobService(sso=sso, webhook_secret=SECRET)
    svc.network_up = True

    def http_post(url, body, headers):  # the SSO webhook worker -> the service's endpoint
        if not svc.network_up:
            raise OSError("connection refused")
        return svc.receive_webhook(body, headers)

    monkeypatch.setattr(webhooks, "http_post", http_post)
    return svc


def deliver():
    """One run of the SSO webhook worker (``run_webhook_worker --once``)."""
    call_command("run_webhook_worker", "--once")


def user_login(api, username="thomas", password=PASSWORD):
    r = login(api, username=username, password=password)
    assert r.status_code == 200, r.content
    return r.json()


def logout(api, refresh_token):
    assert api.post("/api/v1/auth/logout", {"refresh_token": refresh_token}, format="json").status_code == 204


def change_password(user, new=NEW_PASSWORD):
    user.refresh_from_db()
    user.set_password(new)
    user.save()


# ------------------------------------------------------------------ logout
def test_logout_stops_only_the_jobs_of_that_session(api, jobsvc, user):
    laptop, phone = user_login(api), user_login(api)
    jobsvc.start_job(laptop["access_token"], name="laptop-1")
    jobsvc.start_job(laptop["access_token"], name="laptop-2")
    jobsvc.start_job(phone["access_token"], name="phone-1")
    jobsvc.tick_all()

    logout(api, laptop["refresh_token"])
    deliver()
    jobsvc.tick_all()

    assert jobsvc.states() == {"laptop-1": (STOPPED, "logout", "webhook"), "laptop-2": (STOPPED, "logout", "webhook"),
                               "phone-1": (RUNNING, None, None)}
    ticks = {j.name: j.ticks for j in jobsvc.jobs.values()}
    assert ticks == {"laptop-1": 1, "laptop-2": 1, "phone-1": 2}  # stopped jobs do no more work
    assert (str(user.pk), "job laptop-1 stopped: session ended (logout)") in jobsvc.notifications
    assert jobsvc.sweep() == []  # the sweep agrees: phone session alive, nothing more to stop


def test_logout_in_browser_cookie_mode_stops_the_sessions_jobs(api, jobsvc, user):
    r = login(api, client="browser", HTTP_ORIGIN=ORIGIN)
    jobsvc.start_job(r.json()["access_token"], name="spa-job")
    assert api.post("/api/v1/auth/logout", {}, format="json", HTTP_ORIGIN=ORIGIN).status_code == 204
    deliver()
    assert jobsvc.states()["spa-job"] == (STOPPED, "logout", "webhook")


def test_jobs_keep_running_while_the_front_end_stays_signed_in(api, jobsvc, user):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="long")
    for _ in range(5):  # the SPA refreshes every 15 min for days: same session, jobs untouched
        t = api.post("/api/v1/auth/refresh", {"refresh_token": t["refresh_token"]}, format="json").json()
        jobsvc.tick_all()
        assert jobsvc.sweep() == []
    deliver()
    assert jobsvc.states()["long"] == (RUNNING, None, None) and jobsvc.jobs[1].ticks == 5


def test_job_started_after_refresh_is_stopped_by_logout_of_the_same_session(api, jobsvc, user):
    t1 = user_login(api)
    jobsvc.start_job(t1["access_token"], name="before-refresh")
    t2 = api.post("/api/v1/auth/refresh", {"refresh_token": t1["refresh_token"]}, format="json").json()
    jobsvc.start_job(t2["access_token"], name="after-refresh")
    logout(api, t2["refresh_token"])
    deliver()
    assert {s for s, _, _ in jobsvc.states().values()} == {STOPPED}


# ------------------------------------------------------------------ password change / logout-all
def test_password_change_stops_every_job_of_the_user_only(api, jobsvc, user, make_user):
    make_user(username="ann", email="ann@example.org")
    a1, a2, b = user_login(api), user_login(api), user_login(api, username="ann")
    jobsvc.start_job(a1["access_token"], name="thomas-1")
    jobsvc.start_job(a2["access_token"], name="thomas-2")
    jobsvc.start_job(b["access_token"], name="ann-1")

    change_password(user)
    deliver()

    assert jobsvc.states() == {"thomas-1": (STOPPED, "password_change", "webhook"),
                               "thomas-2": (STOPPED, "password_change", "webhook"),
                               "ann-1": (RUNNING, None, None)}
    # signed in again with the new password: new session, new jobs run
    fresh = user_login(api, password=NEW_PASSWORD)
    assert jobsvc.start_job(fresh["access_token"], name="thomas-3").state == RUNNING
    assert jobsvc.sweep() == []


def test_admin_set_password_stops_the_users_jobs(api, jobsvc, at, reauth, user):  # noqa: F811
    jobsvc.start_job(user_login(api)["access_token"], name="j")
    r = api.post(f"{A}/users/{user.pk}/set-password", {"password": NEW_PASSWORD}, format="json", **H(at, reauth))
    assert r.status_code == 204
    deliver()
    assert jobsvc.states()["j"] == (STOPPED, "password_change", "webhook")


def test_same_password_or_login_rehash_keeps_jobs_running(api, jobsvc, user):
    jobsvc.start_job(user_login(api)["access_token"], name="j")  # this login re-hashed the legacy hash
    change_password(user, PASSWORD)
    deliver()
    assert jobsvc.sweep() == [] and jobsvc.states()["j"] == (RUNNING, None, None)


def test_logout_all_stops_every_job(api, jobsvc, user):
    t1, t2 = user_login(api), user_login(api)
    jobsvc.start_job(t1["access_token"], name="a")
    jobsvc.start_job(t2["access_token"], name="b")
    assert api.post("/api/v1/auth/logout-all", **bearer(t1["access_token"])).status_code == 204
    deliver()
    assert jobsvc.states() == {"a": (STOPPED, "logout_all", "webhook"), "b": (STOPPED, "logout_all", "webhook")}


# ------------------------------------------------------------------ sweep backstop
def test_lost_webhook_is_caught_by_the_sweep(api, jobsvc, user):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="j")
    jobsvc.network_up = False
    logout(api, t["refresh_token"])
    deliver()  # delivery fails, the SSO will retry later
    assert jobsvc.states()["j"] == (RUNNING, None, None)
    assert WebhookDelivery.objects.filter(event__type="token.revoked", status="pending").exists()

    assert [j.name for j in jobsvc.sweep()] == ["j"]
    assert jobsvc.states()["j"] == (STOPPED, "logout", "sweep")

    jobsvc.network_up = True  # the retried webhook arrives later: idempotent, nothing changes
    WebhookDelivery.objects.update(next_attempt_at=timezone.now())
    deliver()
    assert jobsvc.states()["j"] == (STOPPED, "logout", "sweep") and len(jobsvc.notifications) == 1


def test_sweep_after_lost_password_change_webhook(api, jobsvc, user):
    jobsvc.start_job(user_login(api)["access_token"], name="j")
    change_password(user)  # no deliver(): the webhook never arrives
    jobsvc.sweep()
    assert jobsvc.states()["j"] == (STOPPED, "revoked", "sweep")


def test_idle_session_expiry_has_no_webhook_only_the_sweep_stops_jobs(api, jobsvc, user):
    jobsvc.start_job(user_login(api)["access_token"], name="j")
    # the browser was closed without logout and never refreshed again: the refresh token runs out (7 days)
    OutstandingToken.objects.filter(user=user).update(expires_at=timezone.now() - timedelta(seconds=1))
    deliver()
    assert not WebhookEvent.objects.filter(type="token.revoked").exists()  # expiry sends nothing
    assert jobsvc.states()["j"] == (RUNNING, None, None)
    jobsvc.sweep()
    assert jobsvc.states()["j"] == (STOPPED, "expired", "sweep")


def test_sweep_batches_and_sso_outage(api, jobsvc, user, make_user, monkeypatch):
    jobsvc.sweep_batch = 2
    sessions = [user_login(api) for _ in range(5)]
    for i, t in enumerate(sessions):
        jobsvc.start_job(t["access_token"], name=f"j{i}")
    for t in sessions[:3]:
        logout(api, t["refresh_token"])
    calls = []
    real = jobsvc.sso

    def counting(path, body):
        calls.append(len(body.get("sessions", [])))
        return real(path, body)

    jobsvc.sso = counting
    assert sorted(j.name for j in jobsvc.sweep()) == ["j0", "j1", "j2"]
    assert calls == [2, 2, 1]
    jobsvc.sso = lambda path, body: (503, {"error": "unavailable"})  # SSO down: keep running, retry next round
    logout(api, sessions[3]["refresh_token"])
    assert jobsvc.sweep() == [] and jobsvc.states()["j3"][0] == RUNNING


# ------------------------------------------------------------------ suspend / delete (stop AND delete)
def test_suspend_stops_and_deletes_and_reactivate_does_not_restart(api, jobsvc, user):
    jobsvc.start_job(user_login(api)["access_token"], name="j")
    user.is_active = False
    user.save()
    deliver()  # token.revoked(suspended) and user.suspended, any order
    job = jobsvc.jobs[1]
    assert job.state == DELETED and job.stop_reason == "suspended"
    user.is_active = True
    user.save()
    deliver()
    assert jobsvc.jobs[1].state == DELETED


def test_user_deleted_deletes_jobs(api, jobsvc, user):
    jobsvc.start_job(user_login(api)["access_token"], name="j")
    user.delete()
    deliver()
    assert jobsvc.jobs[1].state == DELETED and jobsvc.jobs[1].stop_reason == "deleted"


# ------------------------------------------------------------------ webhook transport
def test_duplicate_delivery_is_applied_once(api, jobsvc, user, at, reauth):  # noqa: F811
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="j")
    logout(api, t["refresh_token"])
    deliver()
    d = WebhookDelivery.objects.get(client__client_id="jobs", event__type="token.revoked")
    assert api.post(f"{A}/webhooks/deliveries/{d.pk}/redeliver", **H(at)).status_code == 200
    deliver()
    assert len(jobsvc.notifications) == 1


def test_badly_signed_webhook_is_rejected_and_retried(api, jobsvc, user):
    t = user_login(api)
    jobsvc.start_job(t["access_token"], name="j")
    real_secret = jobsvc._rx.secrets
    jobsvc._rx.secrets = ["some-other-secret"]  # e.g. the SSO rotated notify_secret, service not updated yet
    logout(api, t["refresh_token"])
    deliver()
    assert jobsvc.states()["j"][0] == RUNNING
    assert WebhookDelivery.objects.get(client__client_id="jobs", event__type="token.revoked").status == "pending"
    jobsvc._rx.secrets = real_secret
    WebhookDelivery.objects.update(next_attempt_at=timezone.now())
    deliver()
    assert jobsvc.states()["j"] == (STOPPED, "logout", "webhook")


# ------------------------------------------------------------------ starting jobs
def test_start_refused_for_logged_out_session_and_missing_permission(api, jobsvc, user):
    t = user_login(api)
    with pytest.raises(JobRefused, match="forbidden"):
        jobsvc.start_job(t["access_token"], require="application.app1")  # user lacks app1
    user.user_permissions.add(perm("app1"))
    assert jobsvc.start_job(t["access_token"], require="application.app1").state == RUNNING
    logout(api, t["refresh_token"])
    with pytest.raises(JobRefused, match="token_inactive"):
        jobsvc.start_job(t["access_token"])  # the access token of a logged-out session is dead at once


def test_job_started_by_an_agent_on_behalf_of_the_user_is_bound_to_the_users_session(api, jobsvc, user):
    t = user_login(api)
    st = api.post("/api/v1/auth/service-token", {"grant_type": "client_credentials"}, format="json",
                  **basic("jobs", "jobs-secret")).json()["access_token"]
    job = jobsvc.start_job(t["access_token"], name="agent-job", actor_token=st)
    assert job.owner_sub == str(user.pk)
    logout(api, t["refresh_token"])
    deliver()
    assert jobsvc.states()["agent-job"] == (STOPPED, "logout", "webhook")
