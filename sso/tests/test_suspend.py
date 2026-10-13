"""v1.2a decision 6: suspending a user (is_active=False) revokes all of the user's tokens immediately."""
from __future__ import annotations

import base64
import io
import json
import logging

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from sso.models import ServiceClient, UserTokenRevocation
from .conftest import bearer, login

pytestmark = pytest.mark.django_db


@pytest.fixture
def service(db):
    c = ServiceClient(client_id="svc", name="Svc")
    c.set_secret("svc-secret-value")
    c.save()
    return c


def introspect(api, token):
    auth = "Basic " + base64.b64encode(b"svc:svc-secret-value").decode()
    return api.post("/api/v1/auth/introspect", {"token": token}, format="json", HTTP_AUTHORIZATION=auth).json()


def refresh(api, token):
    return api.post("/api/v1/auth/refresh", {"refresh_token": token}, format="json")


def _live(user):
    return OutstandingToken.objects.filter(user=user, blacklistedtoken__isnull=True).count()


def _assert_dead(api, t, refresh_status=401):
    assert introspect(api, t["access_token"]) == {"active": False}
    assert api.get("/api/v1/auth/me", **bearer(t["access_token"])).status_code == 401
    assert refresh(api, t["refresh_token"]).status_code == refresh_status


@pytest.mark.parametrize("how", ["save", "save_update_fields", "refresh_from_db_then_save"])
def test_save_suspend_revokes_everything_at_once(api, user, service, how, caplog):
    caplog.set_level(logging.INFO, logger="sso.admin")
    a, b = login(api).json(), login(api).json()
    assert _live(user) == 2
    if how == "save":
        user.is_active = False
        user.save()
    elif how == "save_update_fields":
        user.is_active = False
        user.save(update_fields=["is_active"])
    else:
        u = User.objects.get(pk=user.pk)
        u.is_active = False
        u.save()
    assert _live(user) == 0 and UserTokenRevocation.objects.filter(user=user).exists()
    for t in (a, b):
        assert introspect(api, t["access_token"]) == {"active": False}
        r = refresh(api, t["refresh_token"])
        assert r.status_code == 403 and r.json()["error"] == "account_inactive"
    assert login(api).json()["error"] == "account_inactive"
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "sso.admin"]
    assert events == [{"event": "user.suspended", "tokens_revoked": True, "user_id": user.pk}]


def test_unrelated_saves_do_not_revoke(api, user):
    login(api)
    user.first_name = "Other"
    user.save()
    user.save(update_fields=["first_name"])
    user.is_active = False
    user.save(update_fields=["first_name"])  # is_active not written: no change in the DB, no revocation
    assert _live(user) == 1 and not UserTokenRevocation.objects.filter(user=user).exists()


def test_unsuspend_new_logins_work_and_old_tokens_stay_dead(api, user, service, caplog):
    caplog.set_level(logging.INFO, logger="sso.admin")
    old = login(api).json()
    user.is_active = False
    user.save()
    user.is_active = True
    user.save()
    _assert_dead(api, old)
    new = login(api).json()
    assert introspect(api, new["access_token"])["active"] is True
    assert refresh(api, new["refresh_token"]).status_code == 200
    assert "user.reactivated" in caplog.text


def test_queryset_update_suspend_is_caught_on_use_and_stays_dead_after_update_unsuspend(api, user, service):
    """QuerySet.update() sends no signals. Every check rejects the inactive user, and the first check that
    sees a still-valid token revokes the user, so a later update(is_active=True) does not revive tokens."""
    t = login(api).json()
    User.objects.filter(pk=user.pk).update(is_active=False)
    assert introspect(api, t["access_token"]) == {"active": False}  # revokes on sight
    assert UserTokenRevocation.objects.filter(user=user).exists() and _live(user) == 0
    User.objects.filter(pk=user.pk).update(is_active=True)
    _assert_dead(api, t)
    assert login(api).status_code == 200


def test_queryset_update_suspend_caught_by_refresh(api, user):
    t = login(api).json()
    User.objects.filter(pk=user.pk).update(is_active=False)
    r = refresh(api, t["refresh_token"])
    assert r.status_code == 403 and r.json()["error"] == "account_inactive"
    User.objects.filter(pk=user.pk).update(is_active=True)
    assert refresh(api, t["refresh_token"]).status_code == 401


def test_update_suspend_then_save_unsuspend_kills_old_tokens(api, user, service):
    t = login(api).json()
    User.objects.filter(pk=user.pk).update(is_active=False)  # nobody uses the token meanwhile
    u = User.objects.get(pk=user.pk)
    u.is_active = True
    u.save()  # reactivation through save() revokes too
    _assert_dead(api, t)


def test_revoke_inactive_users_command(api, user, make_user):
    t = login(api).json()
    other = make_user(username="bob", email="bob@example.org")
    login(api, username="bob")
    User.objects.filter(pk__in=[user.pk, other.pk]).update(is_active=False)
    out = io.StringIO()
    call_command("revoke_inactive_users", "--dry-run", stdout=out)
    assert "would revoke tokens of 2 inactive user(s)" in out.getvalue() and _live(user) == 1
    call_command("revoke_inactive_users", stdout=out)
    assert "revoked tokens of 2 inactive user(s)" in out.getvalue()
    assert _live(user) == 0 and _live(other) == 0
    out = io.StringIO()
    call_command("revoke_inactive_users", stdout=out)  # idempotent: nothing left
    assert "revoked tokens of 0 inactive user(s)" in out.getvalue()
    User.objects.filter(pk=user.pk).update(is_active=True)
    assert refresh(api, t["refresh_token"]).status_code == 401


def test_new_user_creation_does_not_revoke(make_user):
    u = make_user(is_active=False)
    assert not UserTokenRevocation.objects.filter(user=u).exists()


def test_fixture_loading_raw_save_is_ignored(user):
    from sso.signals import note_is_active_change, revoke_on_is_active_change

    user.is_active = False
    note_is_active_change(User, user, raw=True)
    revoke_on_is_active_change(User, user, raw=True)
    assert not UserTokenRevocation.objects.filter(user=user).exists()
