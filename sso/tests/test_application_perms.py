"""Design A1-A4: application.* permissions, the perms claim, the command and the shared-table safety net."""
from __future__ import annotations

import base64
import logging

import jwt
import pytest
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import CommandError, call_command

from application.models import ApplicationAccess, ApplicationPermissionRecord
from application.permissions import ensure_permission, sync_permissions, user_app_perms
from sso.models import ServiceClient
from .conftest import bearer, login

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _fresh_content_type_cache():
    """Tests below delete/recreate the content type inside a rolled-back transaction; Django's process-wide
    ContentType cache would otherwise hand a rolled-back id to the next test."""
    ContentType.objects.clear_cache()
    yield
    ContentType.objects.clear_cache()


def app_perm(codename="app1") -> Permission:
    return Permission.objects.get(content_type__app_label="application", codename=codename)


def access_claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def refresh(api, token):
    return api.post("/api/v1/auth/refresh", {"refresh_token": token}, format="json")


# ---------------------------------------------------------------- model / migrate
def test_app1_permission_created_by_migrate():
    p = app_perm()
    assert p.name == "Can use app1 (llm-wiki-svc)"
    assert p.content_type == ContentType.objects.get(app_label="application", model="applicationaccess")
    assert ApplicationAccess.objects.count() == 0  # anchor table never holds rows
    # no add/change/delete/view noise on the anchor content type
    assert set(Permission.objects.filter(content_type=p.content_type).values_list("codename", flat=True)) == {"app1"}
    # recorded in the SSO-side registry by the post-migrate step
    rec = ApplicationPermissionRecord.objects.get(codename="app1")
    assert rec.permission_id == p.pk and str(rec) == "application.app1"


# ---------------------------------------------------------------- who has the permission
def test_perm_via_user(make_user):
    u = make_user()
    assert user_app_perms(u) == []
    u.user_permissions.add(app_perm())
    u = type(u).objects.get(pk=u.pk)  # drop Django's permission cache
    assert user_app_perms(u) == ["application.app1"]


def test_perm_via_group_and_sorted(make_user):
    ensure_permission("app2", "Can use app2")
    u = make_user(groups=("readers",))
    Group.objects.get(name="readers").permissions.add(app_perm("app2"), app_perm("app1"))
    assert user_app_perms(u) == ["application.app1", "application.app2"]


def test_superuser_without_grants_gets_no_perms(make_user):
    """Default (SSO_SUPERUSER_ALL_APPS=false): superusers administer users, no automatic app access."""
    from django.conf import settings

    assert settings.SSO_SUPERUSER_ALL_APPS is False
    ensure_permission("app2", "Can use app2")
    u = make_user(is_superuser=True, is_staff=True)
    assert u.has_perm("application.app1")  # Django's rule, which perms must NOT follow
    assert user_app_perms(u) == []


def _service_basic() -> dict:
    c = ServiceClient(client_id="wiki", name="llm-wiki")
    c.set_secret("s3cr3t-value")
    c.save()
    return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(b"wiki:s3cr3t-value").decode()}


def test_superuser_with_no_grants_is_denied_in_token_me_and_introspect(api, make_user):
    make_user(is_superuser=True, is_staff=True)
    r = login(api)
    body = r.json()
    assert body["user"]["perms"] == []
    assert access_claims(body["access_token"])["perms"] == []
    assert api.get("/api/v1/auth/me", **bearer(body["access_token"])).json()["perms"] == []
    r = api.post("/api/v1/auth/introspect", {"token": body["access_token"]}, format="json",
                 **_service_basic())
    assert r.status_code == 200 and r.json()["active"] is True and r.json()["perms"] == []
    new = refresh(api, body["refresh_token"]).json()["access_token"]
    assert access_claims(new)["perms"] == []


@pytest.mark.parametrize("via", ["user", "group"])
def test_superuser_with_an_explicit_grant_gets_exactly_that(make_user, api, via):
    ensure_permission("app2", "Can use app2")
    ensure_permission("app3", "Can use app3")
    u = make_user(is_superuser=True, groups=("wiki",))
    if via == "user":
        u.user_permissions.add(app_perm("app2"))
    else:
        Group.objects.get(name="wiki").permissions.add(app_perm("app2"))
    assert user_app_perms(type(u).objects.get(pk=u.pk)) == ["application.app2"]
    assert access_claims(login(api).json()["access_token"])["perms"] == ["application.app2"]


def test_superuser_grants_via_user_and_group_are_merged_once(make_user):
    u = make_user(is_superuser=True, groups=("wiki", "other"))
    Group.objects.get(name="wiki").permissions.add(app_perm())
    Group.objects.get(name="other").permissions.add(app_perm())
    u.user_permissions.add(app_perm())
    u.user_permissions.add(Permission.objects.get(codename="change_user"))  # not application.*
    assert user_app_perms(type(u).objects.get(pk=u.pk)) == ["application.app1"]


def test_flag_true_restores_all_apps_for_superusers(api, make_user, settings):
    settings.SSO_SUPERUSER_ALL_APPS = True
    ensure_permission("app2", "Can use app2")
    u = make_user(is_superuser=True)
    assert user_app_perms(u) == ["application.app1", "application.app2"]  # no auth.*/sso.* permissions
    assert access_claims(login(api).json()["access_token"])["perms"] == [
        "application.app1", "application.app2"]
    settings.SSO_SUPERUSER_ALL_APPS = False
    assert access_claims(login(api).json()["access_token"])["perms"] == []


@pytest.mark.parametrize("flag", [True, False])
def test_normal_users_are_unaffected_by_the_flag(make_user, settings, flag):
    settings.SSO_SUPERUSER_ALL_APPS = flag
    ensure_permission("app2", "Can use app2")
    u = make_user(groups=("readers",))
    assert user_app_perms(u) == []
    Group.objects.get(name="readers").permissions.add(app_perm("app2"))
    u.user_permissions.add(app_perm("app1"))
    u = type(u).objects.get(pk=u.pk)
    assert user_app_perms(u) == ["application.app1", "application.app2"]
    assert user_app_perms(u) == sorted(p for p in u.get_all_permissions() if p.startswith("application."))


@pytest.mark.parametrize("flag", [True, False])
def test_inactive_superuser_gets_none(make_user, settings, flag):
    settings.SSO_SUPERUSER_ALL_APPS = flag
    u = make_user(is_active=False, is_superuser=True)
    u.user_permissions.add(app_perm())
    assert user_app_perms(u) == []


def test_inactive_user_gets_none(make_user):
    u = make_user(is_active=False, is_superuser=True)
    u.user_permissions.add(app_perm())
    assert user_app_perms(u) == []
    assert user_app_perms(None) == []


def test_non_application_permissions_not_exported(make_user):
    u = make_user()
    u.user_permissions.add(Permission.objects.get(codename="change_user"))
    assert user_app_perms(u) == []


# ---------------------------------------------------------------- claims and responses
def test_perms_claim_present_and_in_user_object(api, make_user):
    u = make_user()
    u.user_permissions.add(app_perm())
    r = login(api)
    assert r.status_code == 200
    body = r.json()
    assert access_claims(body["access_token"])["perms"] == ["application.app1"]
    assert body["user"]["perms"] == ["application.app1"]
    assert access_claims(body["refresh_token"]).get("perms") is None  # profile claims only on the access token


def test_perms_claim_empty_without_grant(api, make_user):
    make_user()
    body = login(api).json()
    assert access_claims(body["access_token"])["perms"] == []
    assert body["user"]["perms"] == []


def test_refresh_picks_up_new_grant_and_drops_revoked(api, make_user):
    u = make_user()
    t0 = login(api).json()
    assert access_claims(t0["access_token"])["perms"] == []
    u.user_permissions.add(app_perm())
    t1 = refresh(api, t0["refresh_token"]).json()
    assert access_claims(t1["access_token"])["perms"] == ["application.app1"]
    assert t1["user"]["perms"] == ["application.app1"]
    u.user_permissions.remove(app_perm())
    t2 = refresh(api, t1["refresh_token"]).json()
    assert access_claims(t2["access_token"])["perms"] == []


def test_refresh_drops_group_grant_when_user_leaves_group(api, make_user):
    u = make_user(groups=("wiki",))
    Group.objects.get(name="wiki").permissions.add(app_perm())
    t0 = login(api).json()
    assert access_claims(t0["access_token"])["perms"] == ["application.app1"]
    u.groups.remove(Group.objects.get(name="wiki"))
    t1 = refresh(api, t0["refresh_token"]).json()
    assert access_claims(t1["access_token"])["perms"] == []


def test_me_shows_fresh_perms(api, make_user):
    u = make_user()
    access = login(api).json()["access_token"]
    assert api.get("/api/v1/auth/me", **bearer(access)).json()["perms"] == []
    u.user_permissions.add(app_perm())
    assert api.get("/api/v1/auth/me", **bearer(access)).json()["perms"] == ["application.app1"]


def test_introspect_shows_fresh_perms(api, make_user):
    c = ServiceClient(client_id="wiki", name="llm-wiki")
    c.set_secret("s3cr3t-value")
    c.save()
    auth = {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(b"wiki:s3cr3t-value").decode()}
    u = make_user()
    access = login(api).json()["access_token"]
    r = api.post("/api/v1/auth/introspect", {"token": access}, format="json", **auth)
    assert r.json()["active"] is True and r.json()["perms"] == []
    u.user_permissions.add(app_perm())
    r = api.post("/api/v1/auth/introspect", {"token": access}, format="json", **auth)
    assert r.json()["perms"] == ["application.app1"]


# ---------------------------------------------------------------- management command
def test_create_app_permission_idempotent(capsys, make_user):
    call_command("create_app_permission", "app2", "Can use app2 (reports)")
    out = capsys.readouterr().out
    assert "application.app2 created" in out
    p = app_perm("app2")
    u = make_user()
    u.user_permissions.add(p)
    call_command("create_app_permission", "app2", "Can use app2 (reporting)")
    assert "already exists" in capsys.readouterr().out
    p2 = app_perm("app2")
    assert p2.pk == p.pk and p2.name == "Can use app2 (reporting)"
    assert Permission.objects.filter(content_type__app_label="application", codename="app2").count() == 1
    assert user_app_perms(type(u).objects.get(pk=u.pk)) == ["application.app2"]  # grant kept
    rec = ApplicationPermissionRecord.objects.get(codename="app2")
    assert rec.permission_id == p.pk and rec.name == "Can use app2 (reporting)"


@pytest.mark.parametrize("codename", ["", "a", "App2", "2app", "app-2", "app 2", "app.2", "a" * 64, "ä_app"])
def test_create_app_permission_rejects_bad_codenames(codename):
    with pytest.raises(CommandError, match="invalid codename"):
        call_command("create_app_permission", codename, "x")
    assert not Permission.objects.filter(content_type__app_label="application", codename=codename).exists()


def test_create_app_permission_accepts_boundary_codenames():
    call_command("create_app_permission", "ab", "two chars")
    call_command("create_app_permission", "a" + "b" * 62, "63 chars")
    assert app_perm("ab") and app_perm("a" + "b" * 62)


def test_create_app_permission_rejects_empty_description():
    with pytest.raises(CommandError, match="description"):
        call_command("create_app_permission", "app3", "   ")


# ---------------------------------------------------------------- A3: remove_stale_contenttypes in myFinance
def test_sync_recreates_only_code_defined_permissions_after_content_type_deleted(make_user, caplog):
    """v1.1 item 8 (Q-13): app1 (Meta) is recreated; command-created app2 is reported, not recreated."""
    ensure_permission("app2", "Can use app2")
    u = make_user()
    u.user_permissions.add(app_perm("app1"), app_perm("app2"))
    # what myFinance's remove_stale_contenttypes does: delete the content type -> cascades to perms + grants
    ContentType.objects.filter(app_label="application", model="applicationaccess").delete()
    ContentType.objects.clear_cache()
    assert not Permission.objects.filter(content_type__app_label="application").exists()
    caplog.set_level(logging.ERROR, logger="sso.application")
    lost = sync_permissions()
    assert lost == ["app1", "app2"]
    assert app_perm("app1")
    assert not Permission.objects.filter(content_type__app_label="application", codename="app2").exists()
    assert "ALL GRANTS OF THESE PERMISSIONS WERE LOST" in caplog.text
    assert "Not recreated (command-created; run manage.py create_app_permission again" in caplog.text
    assert "application.app2" in caplog.text
    assert not ApplicationPermissionRecord.objects.filter(codename="app2").exists()  # reported once
    assert user_app_perms(type(u).objects.get(pk=u.pk)) == []  # grants are gone; must be re-assigned
    # a second run is quiet
    caplog.clear()
    assert sync_permissions() == []
    assert caplog.text == ""
    call_command("create_app_permission", "app2", "Can use app2")  # the documented way back
    assert app_perm("app2")


def test_sync_keeps_existing_command_created_permissions(make_user):
    ensure_permission("app2", "Can use app2")
    assert sync_permissions() == []
    assert app_perm("app2") and ApplicationPermissionRecord.objects.filter(codename="app2").exists()


def test_migrate_runs_the_sync(make_user, caplog):
    ensure_permission("app2", "Can use app2")
    ContentType.objects.filter(app_label="application", model="applicationaccess").delete()
    ContentType.objects.clear_cache()
    caplog.set_level(logging.ERROR, logger="sso.application")
    call_command("migrate", "application", verbosity=0)
    assert app_perm("app1")
    assert not Permission.objects.filter(content_type__app_label="application", codename="app2").exists()
    assert "application.app1, application.app2 were deleted" in caplog.text


def test_admin_lists_only_application_permissions(make_user, client):
    ensure_permission("app2", "Can use app2")
    admin = make_user(username="root", email="root@example.org", is_staff=True, is_superuser=True)
    client.force_login(admin)
    from django.conf import settings

    base = "/" + settings.SSO_ADMIN_PATH
    r = client.get(base + "application/applicationpermission/")
    assert r.status_code == 200
    html = r.content.decode()
    assert "app1" in html and "app2" in html and "change_user" not in html
    assert client.get(base + "application/applicationpermission/add/").status_code == 403
    r = client.get(base + "application/applicationpermissionrecord/")
    assert r.status_code == 200 and "app2" in r.content.decode()
