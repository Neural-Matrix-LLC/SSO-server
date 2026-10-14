"""v1.2a admin: suspend/unsuspend, grant/revoke app access (users, groups), service permission CRUD,
ServiceClient app link; register_service command."""
from __future__ import annotations

import io
import json
import logging

import pytest
from django.contrib.admin.models import LogEntry
from django.contrib.auth.models import Group, Permission, User
from django.core.management import CommandError, call_command
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from application.models import ApplicationPermissionRecord
from application.permissions import ensure_permission, user_app_perms
from sso.models import ServiceClient, UserTokenRevocation
from .conftest import login

pytestmark = pytest.mark.django_db


@pytest.fixture
def base(settings):
    return "/" + settings.SSO_ADMIN_PATH


@pytest.fixture
def admin_user(db):
    return User.objects.create_superuser("root", "root@example.org", "Adm1n-pass-123")


@pytest.fixture
def admin_client(client, admin_user):
    client.force_login(admin_user)
    return client


@pytest.fixture
def app2(db):
    return ensure_permission("app2", "Can use app2 (reporting)")[0]


def _sel(objs):
    return [str(o.pk) for o in objs]


def _audit(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "sso.admin"]


# --------------------------------------------------------------------------- suspend
def test_suspend_action_revokes_and_unsuspend_restores_login(admin_client, base, api, user, caplog):
    caplog.set_level(logging.INFO, logger="sso.admin")
    t = login(api).json()
    r = admin_client.post(base + "auth/user/", {"action": "suspend_users", "_selected_action": _sel([user])},
                          follow=True)
    assert r.status_code == 200
    user.refresh_from_db()
    assert not user.is_active and UserTokenRevocation.objects.filter(user=user).exists()
    assert not OutstandingToken.objects.filter(user=user, blacklistedtoken__isnull=True).exists()
    assert LogEntry.objects.filter(object_id=str(user.pk), change_message__startswith="Suspended").exists()
    assert {"event": "user.suspended", "tokens_revoked": True, "user_id": user.pk} in _audit(caplog)
    admin_client.post(base + "auth/user/", {"action": "unsuspend_users", "_selected_action": _sel([user])})
    user.refresh_from_db()
    assert user.is_active
    assert api.post("/api/v1/auth/refresh", {"refresh_token": t["refresh_token"]}, format="json").status_code == 401
    assert login(api).status_code == 200


def test_admin_cannot_suspend_self_and_skips_unchanged(admin_client, base, admin_user, make_user):
    inactive = make_user(username="gone", email="gone@example.org", is_active=False)
    r = admin_client.post(base + "auth/user/", {"action": "suspend_users",
                                                "_selected_action": _sel([admin_user, inactive])}, follow=True)
    msgs = [str(m) for m in r.context["messages"]]
    assert "You cannot suspend yourself." in msgs and "Suspended 0 user(s); all their tokens are revoked." in msgs
    admin_user.refresh_from_db()
    assert admin_user.is_active


def test_user_form_edit_unticking_active_revokes(admin_client, base, api, user):
    login(api)
    r = admin_client.get(base + f"auth/user/{user.pk}/change/")
    assert r.status_code == 200
    data = {"username": user.username, "email": user.email, "first_name": "Tom", "last_name": "Choi",
            "date_joined_0": "2026-01-01", "date_joined_1": "00:00:00", "initial-date_joined_0": "2026-01-01",
            "initial-date_joined_1": "00:00:00", "groups": [g.pk for g in user.groups.all()]}
    r = admin_client.post(base + f"auth/user/{user.pk}/change/", data)  # is_active omitted = unticked
    assert r.status_code == 302, r.content[:2000]
    user.refresh_from_db()
    assert not user.is_active and UserTokenRevocation.objects.filter(user=user).exists()



def test_admin_cannot_untick_own_is_active_on_change_form(admin_client, base, admin_user):
    """V12A-01: the change-form path is guarded too; error on is_active, nothing saved."""
    data = {"username": admin_user.username, "email": admin_user.email, "first_name": "Changed", "last_name": "",
            "is_staff": "on", "is_superuser": "on",
            "date_joined_0": "2026-01-01", "date_joined_1": "00:00:00", "initial-date_joined_0": "2026-01-01",
            "initial-date_joined_1": "00:00:00"}
    r = admin_client.post(base + f"auth/user/{admin_user.pk}/change/", data)  # is_active omitted = unticked
    assert r.status_code == 200 and b"You cannot suspend yourself." in r.content
    assert "is_active" in r.context["adminform"].form.errors
    admin_user.refresh_from_db()
    assert admin_user.is_active and admin_user.first_name != "Changed"
    r = admin_client.post(base + f"auth/user/{admin_user.pk}/change/", {**data, "is_active": "on"})
    assert r.status_code == 302
    admin_user.refresh_from_db()
    assert admin_user.is_active and admin_user.first_name == "Changed"


def test_changelist_formset_refuses_self_suspend(rf, admin_user, make_user):
    """V12A-01: guard for is_active if it is ever list_editable."""
    from django.contrib import admin as dj_admin

    other = make_user(username="other", email="other@example.org")
    ma = dj_admin.site._registry[User]
    ma.list_editable = ["is_active"]
    try:
        request = rf.post("/")
        request.user = admin_user
        FS = ma.get_changelist_formset(request)
        qs = User.objects.filter(pk__in=[admin_user.pk, other.pk]).order_by("pk")
        data = {"form-TOTAL_FORMS": "2", "form-INITIAL_FORMS": "2",
                "form-0-id": str(qs[0].pk), "form-1-id": str(qs[1].pk)}  # both unticked
        fs = FS(data, queryset=qs)
        assert not fs.is_valid()
        errs = {f.instance.pk: f.errors for f in fs.forms}
        assert "is_active" in errs[admin_user.pk] and not errs[other.pk]
    finally:
        ma.list_editable = ()
    admin_user.refresh_from_db()
    assert admin_user.is_active


# --------------------------------------------------------------------------- grant / revoke
def test_grant_and_revoke_app_access_to_users(admin_client, base, user, make_user, app2, caplog):
    caplog.set_level(logging.INFO, logger="sso.admin")
    bob = make_user(username="bob", email="bob@example.org")
    sel = _sel([user, bob])
    r = admin_client.post(base + "auth/user/", {"action": "grant_app_access", "_selected_action": sel})
    assert r.status_code == 200 and b"application.app2" in r.content  # intermediate page
    r = admin_client.post(base + "auth/user/", {"action": "grant_app_access", "_selected_action": sel,
                                                "apply": "1", "permission": str(app2.pk)}, follow=True)
    assert any("Granted application.app2 to 2 user(s)" in str(m) for m in r.context["messages"])
    assert user_app_perms(user) == ["application.app2"] and user_app_perms(bob) == ["application.app2"]
    assert LogEntry.objects.filter(change_message="Granted application.app2").count() == 2
    admin_client.post(base + "auth/user/", {"action": "revoke_app_access", "_selected_action": _sel([bob]),
                                            "apply": "1", "permission": str(app2.pk)})
    assert user_app_perms(bob) == [] and user_app_perms(user) == ["application.app2"]
    ev = _audit(caplog)
    assert {"event": "app_access.granted", "admin": "root", "permission": "application.app2",
            "user_ids": sorted([user.pk, bob.pk])} in ev
    assert any(e["event"] == "app_access.revoked" for e in ev)


def test_grant_rejects_non_application_permission(admin_client, base, user):
    other = Permission.objects.get(codename="change_user")
    r = admin_client.post(base + "auth/user/", {"action": "grant_app_access", "_selected_action": _sel([user]),
                                                "apply": "1", "permission": str(other.pk)})
    assert r.status_code == 200 and b"Select a valid choice" in r.content
    assert not user.user_permissions.exists()


def test_grant_and_revoke_app_access_to_groups(admin_client, base, user, app2):
    trader = Group.objects.get(name="trader")
    admin_client.post(base + "auth/group/", {"action": "grant_app_access", "_selected_action": _sel([trader]),
                                             "apply": "1", "permission": str(app2.pk)})
    assert user_app_perms(user) == ["application.app2"]
    r = admin_client.post(base + "auth/group/", {"action": "revoke_app_access", "_selected_action": _sel([trader])})
    assert r.status_code == 200 and b"Revoke app access" in r.content
    admin_client.post(base + "auth/group/", {"action": "revoke_app_access", "_selected_action": _sel([trader]),
                                             "apply": "1", "permission": str(app2.pk)})
    assert user_app_perms(user) == []


# --------------------------------------------------------------------------- service permission CRUD
def test_add_rename_and_delete_service_permission(admin_client, base, user, caplog):
    caplog.set_level(logging.INFO, logger="sso.admin")
    r = admin_client.post(base + "application/applicationpermission/add/",
                          {"codename": "app3", "name": "Can use app3 (trading)"})
    assert r.status_code == 302
    perm = Permission.objects.get(content_type__app_label="application", codename="app3")
    assert ApplicationPermissionRecord.objects.get(codename="app3").permission_id == perm.pk
    # duplicate and bad codenames are refused
    r = admin_client.post(base + "application/applicationpermission/add/", {"codename": "app3", "name": "x"})
    assert r.status_code == 200 and b"already exists" in r.content
    r = admin_client.post(base + "application/applicationpermission/add/", {"codename": "App-3", "name": "x"})
    assert r.status_code == 200 and not Permission.objects.filter(codename="App-3").exists()
    # rename: codename is read-only
    r = admin_client.post(base + f"application/applicationpermission/{perm.pk}/change/",
                          {"codename": "hacked", "name": "Can use app3 (trading desk)"})
    assert r.status_code == 302
    perm.refresh_from_db()
    assert perm.codename == "app3" and perm.name == "Can use app3 (trading desk)"
    assert ApplicationPermissionRecord.objects.get(codename="app3").name == "Can use app3 (trading desk)"
    # delete: confirmation lists the affected users and groups
    user.user_permissions.add(perm)
    Group.objects.get(name="beta").permissions.add(perm)
    r = admin_client.get(base + f"application/applicationpermission/{perm.pk}/delete/")
    html = r.content.decode()
    assert r.status_code == 200 and "Access that will be lost" in html and "thomas" in html and "beta" in html
    r = admin_client.post(base + f"application/applicationpermission/{perm.pk}/delete/", {"post": "yes"})
    assert r.status_code == 302
    assert not Permission.objects.filter(pk=perm.pk).exists()
    assert not ApplicationPermissionRecord.objects.filter(codename="app3").exists()
    assert user_app_perms(user) == []
    events = [e["event"] for e in _audit(caplog)]
    assert events == ["app_permission.created", "app_permission.renamed", "app_permission.deleted"]


def test_code_defined_permission_cannot_be_deleted(admin_client, base):
    app1 = Permission.objects.get(content_type__app_label="application", codename="app1")
    assert admin_client.get(base + f"application/applicationpermission/{app1.pk}/delete/").status_code == 403
    assert admin_client.post(base + f"application/applicationpermission/{app1.pk}/delete/",
                             {"post": "yes"}).status_code == 403
    assert Permission.objects.filter(pk=app1.pk).exists()
    from application.permissions import delete_permission

    with pytest.raises(ValueError, match="defined in code"):
        delete_permission(app1)


def test_permission_list_has_no_bulk_delete(admin_client, base):
    r = admin_client.get(base + "application/applicationpermission/")
    assert r.status_code == 200 and b"delete_selected" not in r.content


# --------------------------------------------------------------------------- ServiceClient admin
def test_service_client_admin_links_app_and_counts_users(admin_client, base, user, make_user, app2):
    user.user_permissions.add(app2)
    make_user(username="bob", email="bob@example.org", is_active=False).user_permissions.add(app2)
    r = admin_client.post(base + "sso/serviceclient/add/", {
        "client_id": "reporting", "name": "Reporting", "is_active": "on", "app_codename": "application.app2",
        "notify_url": "https://reporting.example.test/sso/events", "allowed_origins": "[]", "redirect_uris": "[]"},
        follow=True)
    assert r.status_code == 200
    c = ServiceClient.objects.get(client_id="reporting")
    assert c.app_codename == "app2" and c.notify_url == "https://reporting.example.test/sso/events"
    html = admin_client.get(base + "sso/serviceclient/").content.decode()
    assert "application.app2" in html
    page = admin_client.get(base + f"sso/serviceclient/{c.pk}/change/").content.decode()
    assert "users with access" in page.lower()
    assert ServiceClientAdminCount(c) == 1  # bob is inactive


def ServiceClientAdminCount(c):
    from django.contrib import admin as dj_admin

    return dj_admin.site._registry[ServiceClient].users_with_access(c)


def test_service_client_admin_validation(admin_client, base):
    data = {"client_id": "svc", "name": "S", "is_active": "on", "allowed_origins": "[]", "redirect_uris": "[]"}
    r = admin_client.post(base + "sso/serviceclient/add/", {**data, "app_codename": "nope"})
    assert r.status_code == 200 and b"application.nope does not exist" in r.content
    r = admin_client.post(base + "sso/serviceclient/add/", {**data, "notify_url": "http://insecure.example.test/x"})
    assert r.status_code == 200 and not ServiceClient.objects.exists()
    for schemeless in ("reporting.example.test/hook", "//reporting.example.test/hook"):
        r = admin_client.post(base + "sso/serviceclient/add/", {**data, "notify_url": schemeless})
        assert r.status_code == 200 and "notify_url" in r.context["adminform"].form.errors, schemeless
        assert not ServiceClient.objects.exists()
    r = admin_client.post(base + "sso/serviceclient/add/", data, follow=True)
    c = ServiceClient.objects.get()
    assert c.app_codename is None and c.notify_url is None
    assert "-" in admin_client.get(base + "sso/serviceclient/").content.decode()
    c.app_codename = "ghost"
    c.save()
    assert "application.ghost (missing)" in admin_client.get(base + "sso/serviceclient/").content.decode()


def test_revoked_session_admin_is_read_only(admin_client, base, user):
    from sso.models import RevokedSession

    rs = RevokedSession.objects.create(sid="s1", user=user, reason="refresh_reuse")
    assert admin_client.get(base + "sso/revokedsession/").status_code == 200
    assert admin_client.get(base + "sso/revokedsession/add/").status_code == 403
    assert admin_client.get(base + f"sso/revokedsession/{rs.pk}/change/").status_code == 200  # view only


# --------------------------------------------------------------------------- register_service
def _kv(out: str) -> dict:
    return dict(line.split("=", 1) for line in out.split())


def test_register_service_creates_permission_and_client():
    out, err = io.StringIO(), io.StringIO()
    call_command("register_service", "reporting", "--name", "Reporting", "--app", "app2",
                 "--notify-url", "https://reporting.example.test/hook", "--origin", "https://r.example.test",
                 stdout=out, stderr=err)
    kv = _kv(out.getvalue())
    c = ServiceClient.objects.get(client_id="reporting")
    assert kv["permission"] == "application.app2" and c.check_secret(kv["client_secret"])
    assert c.app_codename == "app2" and c.notify_url == "https://reporting.example.test/hook"
    assert c.allowed_origins == ["https://r.example.test"]
    perm = Permission.objects.get(content_type__app_label="application", codename="app2")
    assert perm.name == "Can use app2 (Reporting)" and "Created permission" in err.getvalue()
    assert kv["client_secret"] not in c.client_secret_hash
    with pytest.raises(CommandError, match="exists"):
        call_command("register_service", "reporting", "--app", "app2", stdout=io.StringIO(), stderr=io.StringIO())


def test_register_service_reuses_existing_permission_and_validates():
    ensure_permission("app4", "Can use app4")
    err = io.StringIO()
    call_command("register_service", "svc4", "--app", "application.app4", stdout=io.StringIO(), stderr=err)
    assert "Using existing permission application.app4" in err.getvalue()
    assert Permission.objects.get(codename="app4").name == "Can use app4"  # description kept
    call_command("register_service", "svc4b", "--app", "app4", "--app-name", "Can use app4 (new)",
                 stdout=io.StringIO(), stderr=io.StringIO())
    assert Permission.objects.get(codename="app4").name == "Can use app4 (new)"
    with pytest.raises(CommandError, match="invalid codename"):
        call_command("register_service", "svc5", "--app", "Bad-Name", stdout=io.StringIO(), stderr=io.StringIO())
    with pytest.raises(CommandError, match="notify_url"):
        call_command("register_service", "svc6", "--app", "app6", "--notify-url", "http://x.example.test/",
                     stdout=io.StringIO(), stderr=io.StringIO())
    assert not ServiceClient.objects.filter(client_id__in=["svc5", "svc6"]).exists()
    assert not Permission.objects.filter(codename="app6").exists()  # nothing created on a refused call


def test_create_service_client_app_option(app2):
    out = io.StringIO()
    call_command("create_service_client", "svc-x", "--app", "app2", stdout=out, stderr=io.StringIO())
    assert ServiceClient.objects.get(client_id="svc-x").app_codename == "app2"
    with pytest.raises(CommandError, match="does not exist"):
        call_command("create_service_client", "svc-y", "--app", "ghost", stdout=io.StringIO(), stderr=io.StringIO())
