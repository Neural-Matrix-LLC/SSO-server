"""v1.3a admin REST API (docs/DESIGN-v1.3a-admin-api.md)."""
from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from django.contrib.auth.models import Group, Permission, User
from django.utils import timezone

from application.permissions import ensure_permission
from sso.models import AdminAuditLog, AdminReauth, ServiceClient

from .conftest import PASSWORD, bearer, login

A = "/api/v1/admin"


def perm(code):
    return Permission.objects.get(content_type__app_label="application", codename=code)


@pytest.fixture
def admin_user(make_user):
    u = make_user(username="admin", email="admin@example.org", groups=(), is_staff=True)
    u.user_permissions.add(perm("sso_admin"))
    return u


@pytest.fixture
def at(api, admin_user):
    r = login(api, username="admin")
    assert r.status_code == 200, r.content
    return r.json()["access_token"]


def H(at, reauth=None, **extra):
    h = bearer(at)
    if reauth:
        h["HTTP_X_SSO_REAUTH"] = reauth
    h.update(extra)
    return h


@pytest.fixture
def reauth(api, at):
    r = api.post(f"{A}/reauth", {"password": PASSWORD}, format="json", **H(at))
    assert r.status_code == 200, r.content
    assert r.json()["expires_in"] == 300
    return r.json()["reauth_token"]


def basic(cid, secret):
    return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()}


# ------------------------------------------------------------------ auth matrix
def test_sso_admin_is_code_defined(db):
    assert perm("sso_admin").name.startswith("SSO administrator")


def test_anonymous_401(api, db):
    r = api.get(f"{A}/users")
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


def test_non_admin_403_and_denied_write_audited(api, user, tokens):
    r = api.get(f"{A}/users", **bearer(tokens["access_token"]))
    assert r.status_code == 403 and r.json()["error"] == "admin_forbidden"
    r = api.post(f"{A}/groups", {"name": "x"}, format="json", **bearer(tokens["access_token"]))
    assert r.status_code == 403
    assert AdminAuditLog.objects.filter(result="denied", action="admin.denied").count() == 1


def test_token_perms_not_trusted_db_checked(api, admin_user, at):
    assert api.get(f"{A}/users", **H(at)).status_code == 200
    admin_user.user_permissions.remove(perm("sso_admin"))
    assert api.get(f"{A}/users", **H(at)).status_code == 403


def test_superuser_is_admin(api, make_user):
    make_user(username="root", email="r@x.org", groups=(), is_superuser=True, is_staff=True)
    t = login(api, username="root").json()["access_token"]
    assert api.get(f"{A}/users", **H(t)).status_code == 200


def test_admin_via_group(api, make_user):
    u = make_user(username="ga", email="ga@x.org", groups=("admins",), is_staff=True)
    Group.objects.get(name="admins").permissions.add(perm("sso_admin"))
    t = login(api, username="ga").json()["access_token"]
    assert api.get(f"{A}/users", **H(t)).status_code == 200
    assert u.pk


def test_request_id_echoed(api, at):
    r = api.get(f"{A}/users", **H(at, HTTP_X_REQUEST_ID="abc-123"))
    assert r["X-Request-ID"] == "abc-123"
    assert r["Cache-Control"] == "no-store"


def test_ip_binding_enforce_applies(api, admin_user, settings):
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    t = login(api, username="admin", REMOTE_ADDR="198.51.100.7").json()["access_token"]
    assert api.get(f"{A}/users", **H(t), REMOTE_ADDR="198.51.100.7").status_code == 200
    r = api.get(f"{A}/users", **H(t), REMOTE_ADDR="198.51.100.8")
    assert r.status_code == 401
    # session revoked: even the original IP fails now
    assert api.get(f"{A}/users", **H(t), REMOTE_ADDR="198.51.100.7").status_code == 401


# ------------------------------------------------------------------ step-up
def test_reauth_wrong_password(api, at):
    r = api.post(f"{A}/reauth", {"password": "nope"}, format="json", **H(at))
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"
    assert AdminAuditLog.objects.filter(action="reauth", result="denied").exists()


def test_reauth_throttled(api, at):
    codes = [api.post(f"{A}/reauth", {"password": "nope"}, format="json", **H(at)).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_stepup_required_then_ok(api, at, make_user, reauth):
    victim = make_user(username="v", email="v@x.org", groups=())
    r = api.post(f"{A}/users/{victim.pk}/suspend", {}, format="json", **H(at))
    assert r.status_code == 401 and r.json()["error"] == "reauth_required"
    assert AdminAuditLog.objects.filter(action="user.suspend", result="denied", stepup=True).exists()
    r = api.post(f"{A}/users/{victim.pk}/suspend", {}, format="json", **H(at, reauth))
    assert r.status_code == 200 and r.json()["is_active"] is False
    row = AdminAuditLog.objects.get(action="user.suspend", result="ok")
    assert row.stepup and row.before == {"is_active": True} and row.target_id == str(victim.pk)
    # reusable within the window
    other = make_user(username="w", email="w@x.org", groups=())
    assert api.post(f"{A}/users/{other.pk}/suspend", {}, format="json", **H(at, reauth)).status_code == 200


def test_stepup_expired(api, at, reauth, make_user):
    AdminReauth.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    v = make_user(username="v", email="v@x.org", groups=())
    assert api.delete(f"{A}/users/{v.pk}", **H(at, reauth)).status_code == 401


def test_stepup_bound_to_session(api, at, reauth, make_user):
    t2 = login(api, username="admin").json()["access_token"]  # new login = new sid
    v = make_user(username="v", email="v@x.org", groups=())
    assert api.delete(f"{A}/users/{v.pk}", **H(t2, reauth)).status_code == 401
    assert api.delete(f"{A}/users/{v.pk}", **H(at, reauth)).status_code == 204


def test_stepup_bound_to_ip(api, at, reauth, make_user):
    v = make_user(username="v", email="v@x.org", groups=())
    assert api.delete(f"{A}/users/{v.pk}", **H(at, reauth), REMOTE_ADDR="203.0.113.99").status_code == 401


def test_reauth_token_stored_hashed(api, reauth):
    row = AdminReauth.objects.get()
    assert row.token_hash == AdminReauth.hash_token(reauth) and reauth not in row.token_hash


# ------------------------------------------------------------------ users
def test_user_crud(api, at, reauth):
    r = api.post(f"{A}/users", {"username": "amy", "email": "amy@x.org", "password": "Very-Long-Pass-77"},
                 format="json", **H(at))
    assert r.status_code == 201, r.content
    uid = r.json()["id"]
    assert api.post(f"{A}/users", {"username": "AMY"}, format="json", **H(at)).json()["error"] == "conflict"
    assert api.get(f"{A}/users?q=amy", **H(at)).json()["count"] == 1
    assert api.get(f"{A}/users?active=false", **H(at)).json()["count"] == 0
    r = api.patch(f"{A}/users/{uid}", {"first_name": "Amy"}, format="json", **H(at))
    assert r.status_code == 200 and r.json()["first_name"] == "Amy"
    assert api.patch(f"{A}/users/{uid}", {"is_superuser": True}, format="json", **H(at)).status_code == 400
    assert login(api, username="amy", password="Very-Long-Pass-77").status_code == 200
    assert api.delete(f"{A}/users/{uid}", **H(at, reauth)).status_code == 204
    assert not User.objects.filter(pk=uid).exists()
    assert api.get(f"{A}/users/{uid}", **H(at)).json()["error"] == "not_found"
    actions = list(AdminAuditLog.objects.filter(result="ok").values_list("action", flat=True))
    assert {"user.create", "user.update", "user.delete"} <= set(actions)


def test_user_create_weak_password_and_no_password(api, at):
    assert api.post(f"{A}/users", {"username": "b", "password": "123"}, format="json", **H(at)).status_code == 400
    r = api.post(f"{A}/users", {"username": "c"}, format="json", **H(at))
    assert r.status_code == 201
    assert not User.objects.get(username="c").has_usable_password()


def test_self_guards(api, admin_user, at, reauth):
    r = api.post(f"{A}/users/{admin_user.pk}/suspend", {}, format="json", **H(at, reauth))
    assert r.status_code == 409 and r.json()["error"] == "self_action_forbidden"
    assert api.delete(f"{A}/users/{admin_user.pk}", **H(at, reauth)).json()["error"] == "self_action_forbidden"
    r = api.delete(f"{A}/users/{admin_user.pk}/permissions/sso_admin", **H(at, reauth))
    assert r.json()["error"] == "self_action_forbidden"


def test_removing_own_admin_via_group_rolls_back(api, make_user):
    u = make_user(username="ga", email="ga@x.org", groups=("admins",), is_staff=True)
    Group.objects.get(name="admins").permissions.add(perm("sso_admin"))
    t = login(api, username="ga").json()["access_token"]
    rt = api.post(f"{A}/reauth", {"password": PASSWORD}, format="json", **H(t)).json()["reauth_token"]
    r = api.put(f"{A}/users/{u.pk}/groups", {"groups": []}, format="json", **H(t, rt))
    assert r.status_code == 409
    assert list(u.groups.values_list("name", flat=True)) == ["admins"]  # rolled back
    assert not AdminAuditLog.objects.filter(action="user.groups", result="ok").exists()


def test_last_admin_guard_service_import_cannot_break(api, admin_user, at, reauth, make_user):
    other = make_user(username="o", email="o@x.org", groups=(), is_staff=True)
    other.user_permissions.add(perm("sso_admin"))
    # other admin can be suspended (admin remains)
    assert api.post(f"{A}/users/{other.pk}/suspend", {}, format="json", **H(at, reauth)).status_code == 200


def test_suspend_revokes_tokens_and_unsuspend(api, at, reauth, user, tokens):
    assert api.get("/api/v1/auth/me", **bearer(tokens["access_token"])).status_code == 200
    api.post(f"{A}/users/{user.pk}/suspend", {}, format="json", **H(at, reauth))
    assert api.get("/api/v1/auth/me", **bearer(tokens["access_token"])).status_code in (401, 403)
    r = api.post("/api/v1/auth/refresh", {"refresh_token": tokens["refresh_token"]}, format="json")
    assert r.status_code in (401, 403)
    assert api.post(f"{A}/users/{user.pk}/unsuspend", {}, format="json", **H(at)).json()["is_active"] is True
    # old tokens stay dead
    assert api.get("/api/v1/auth/me", **bearer(tokens["access_token"])).status_code == 401
    assert login(api).status_code == 200


def test_logout_all_and_set_password(api, at, reauth, user, tokens):
    assert api.post(f"{A}/users/{user.pk}/logout-all", {}, format="json", **H(at)).status_code == 204
    assert api.get("/api/v1/auth/me", **bearer(tokens["access_token"])).status_code == 401
    r = api.post(f"{A}/users/{user.pk}/set-password", {"password": "Another-Long-Pass-88"}, format="json", **H(at))
    assert r.status_code == 401
    r = api.post(f"{A}/users/{user.pk}/set-password", {"password": "Another-Long-Pass-88"}, format="json",
                 **H(at, reauth))
    assert r.status_code == 204
    assert login(api, password="Another-Long-Pass-88").status_code == 200
    row = AdminAuditLog.objects.get(action="user.set_password", result="ok")
    assert row.after == {"password": "changed"} and "Another" not in str(row.before) + str(row.after)


def test_user_permissions_and_groups(api, at, reauth, user):
    assert api.post(f"{A}/users/{user.pk}/permissions/application.app1", **H(at)).status_code == 204
    r = api.get(f"{A}/users/{user.pk}/permissions", **H(at)).json()
    assert r["direct"] == ["application.app1"] and "application.app1" in r["effective"]
    assert set(r["via_groups"]) == {"trader", "beta"}
    # granting sso_admin needs step-up
    assert api.post(f"{A}/users/{user.pk}/permissions/sso_admin", **H(at)).status_code == 401
    assert api.post(f"{A}/users/{user.pk}/permissions/sso_admin", **H(at, reauth)).status_code == 204
    assert api.post(f"{A}/users/{user.pk}/permissions/nope", **H(at)).status_code == 404
    assert api.delete(f"{A}/users/{user.pk}/permissions/app1", **H(at)).status_code == 204
    r = api.put(f"{A}/users/{user.pk}/groups", {"groups": ["trader"]}, format="json", **H(at))
    assert r.status_code == 200 and r.json()["groups"] == ["trader"]
    assert api.put(f"{A}/users/{user.pk}/groups", {"groups": ["ghost"]}, format="json", **H(at)).status_code == 400


# ------------------------------------------------------------------ groups
def test_groups(api, at, reauth, user):
    r = api.post(f"{A}/groups", {"name": "ops"}, format="json", **H(at))
    gid = r.json()["id"]
    assert r.status_code == 201
    assert api.post(f"{A}/groups", {"name": "ops"}, format="json", **H(at)).status_code == 409
    assert api.patch(f"{A}/groups/{gid}", {"name": "ops2"}, format="json", **H(at)).json()["name"] == "ops2"
    assert api.post(f"{A}/groups/{gid}/permissions/app1", **H(at)).status_code == 204
    r = api.put(f"{A}/groups/{gid}/members", {"user_ids": [user.pk]}, format="json", **H(at))
    assert r.json()["members"] == [user.pk] and r.json()["perms"] == ["application.app1"]
    assert api.post(f"{A}/groups/{gid}/permissions/sso_admin", **H(at)).status_code == 401
    assert api.delete(f"{A}/groups/{gid}", **H(at)).status_code == 401
    assert api.delete(f"{A}/groups/{gid}", **H(at, reauth)).status_code == 204
    assert api.get(f"{A}/groups?q=ops", **H(at)).json()["count"] == 0


# ------------------------------------------------------------------ permissions
def test_permissions(api, at, reauth, user):
    r = api.post(f"{A}/permissions", {"codename": "reports", "name": "Reports", "description": "d"}, format="json",
                 **H(at))
    assert r.status_code == 201 and r.json()["perm"] == "application.reports" and r.json()["description"] == "d"
    assert api.post(f"{A}/permissions", {"codename": "Bad-Code", "name": "x"}, format="json", **H(at)).status_code == 400
    assert api.post(f"{A}/permissions", {"codename": "reports", "name": "x"}, format="json", **H(at)).status_code == 409
    assert api.patch(f"{A}/permissions/reports", {"codename": "x"}, format="json", **H(at)).status_code == 409
    r = api.patch(f"{A}/permissions/reports", {"name": "Reports 2"}, format="json", **H(at))
    assert r.json()["name"] == "Reports 2"
    user.user_permissions.add(perm("reports"))
    assert api.delete(f"{A}/permissions/reports", **H(at, reauth)).status_code == 409
    assert api.delete(f"{A}/permissions/reports?revoke_all=true", **H(at)).status_code == 401
    assert api.delete(f"{A}/permissions/reports?revoke_all=true", **H(at, reauth)).status_code == 204
    assert api.delete(f"{A}/permissions/app1?revoke_all=true", **H(at, reauth)).status_code == 409
    assert api.delete(f"{A}/permissions/sso_admin?revoke_all=true", **H(at, reauth)).status_code == 409
    codes = [p["codename"] for p in api.get(f"{A}/permissions", **H(at)).json()["results"]]
    assert "app1" in codes and "sso_admin" in codes and "reports" not in codes


# ------------------------------------------------------------------ services
def test_services(api, at, reauth):
    r = api.post(f"{A}/services", {"client_id": "sgmcp", "name": "SGMCP", "app_codename": "app1",
                                   "perms": ["application.app1"]}, format="json", **H(at))
    assert r.status_code == 201, r.content
    secret = r.json()["client_secret"]
    assert r.json()["perms"] == ["application.app1"]
    sc = ServiceClient.objects.get(client_id="sgmcp")
    assert sc.check_secret(secret) and secret not in str(AdminAuditLog.objects.values_list("after", flat=True)[0])
    assert api.post(f"{A}/services", {"client_id": "sgmcp", "name": "x"}, format="json", **H(at)).status_code == 409
    assert "client_secret" not in api.get(f"{A}/services/sgmcp", **H(at)).json()
    assert api.patch(f"{A}/services/sgmcp", {"name": "SG"}, format="json", **H(at)).json()["name"] == "SG"
    assert api.patch(f"{A}/services/sgmcp", {"notify_url": "http://x"}, format="json", **H(at)).status_code == 400
    assert api.patch(f"{A}/services/sgmcp", {"is_active": False}, format="json", **H(at)).status_code == 401
    assert api.patch(f"{A}/services/sgmcp", {"is_active": False}, format="json", **H(at, reauth)).status_code == 200
    assert api.post(f"{A}/services/sgmcp/rotate-secret", **H(at)).status_code == 401
    r = api.post(f"{A}/services/sgmcp/rotate-secret", **H(at, reauth))
    assert r.status_code == 200 and r.json()["client_secret"] != secret
    sc.refresh_from_db()
    assert sc.secret_rotated_at and not sc.check_secret(secret)
    assert api.delete(f"{A}/services/sgmcp", **H(at, reauth)).status_code == 204
    assert api.get(f"{A}/services", **H(at)).json()["count"] == 0


# ------------------------------------------------------------------ audit
def test_audit_list_filters(api, at, admin_user):
    api.post(f"{A}/groups", {"name": "g1"}, format="json", **H(at))
    api.post(f"{A}/groups", {"name": "g2"}, format="json", **H(at))
    r = api.get(f"{A}/audit?action=group.create", **H(at)).json()
    assert r["count"] == 2 and r["results"][0]["after"] == {"name": "g2"}  # newest first
    assert r["results"][0]["actor_id"] == str(admin_user.pk) and r["results"][0]["actor_ip"]
    assert api.get(f"{A}/audit?since=bad", **H(at)).status_code == 400
    future = (timezone.now() + timedelta(hours=1)).isoformat()
    assert api.get(f"{A}/audit", {"since": future}, **H(at)).json()["count"] == 0
    assert api.get(f"{A}/audit?page_size=1&page=2", **H(at)).json()["results"][0]["after"] == {"name": "g1"}


def test_change_rolled_back_when_audit_write_fails(api, at, monkeypatch):
    """Change and audit row share one transaction: if the audit write fails, the change is rolled back."""
    from sso import audit

    def boom(*a, **k):
        raise RuntimeError("audit down")

    monkeypatch.setattr(audit, "record", boom)
    api.raise_request_exception = False
    r = api.post(f"{A}/groups", {"name": "zz"}, format="json", **H(at))
    assert r.status_code == 500 and r.json()["error"] == "server_error"
    assert not Group.objects.filter(name="zz").exists()


def test_service_token_not_accepted_on_admin(api, at):
    c = ServiceClient(client_id="s1", name="s1")
    c.set_secret("sec")
    c.save()
    t = api.post("/api/v1/auth/service-token", {"grant_type": "client_credentials"}, format="json",
                 **basic("s1", "sec")).json()["access_token"]
    assert api.get(f"{A}/users", **bearer(t)).status_code == 401
    assert api.get("/api/v1/auth/me", **bearer(t)).status_code == 401


def test_ensure_permission_unaffected(db):
    p, created = ensure_permission("zz_x", "x")
    assert created and p.codename == "zz_x"


def test_is_staff_required(api, make_user):
    """Thomas 2026-10-15: active + is_staff + (sso_admin or superuser)."""
    u = make_user(username="ns", email="ns@x.org", groups=(), is_staff=False)
    u.user_permissions.add(perm("sso_admin"))
    make_user(username="su", email="su@x.org", groups=(), is_superuser=True, is_staff=False)
    for name in ("ns", "su"):
        t = login(api, username=name).json()["access_token"]
        assert api.get(f"{A}/users", **H(t)).json()["error"] == "admin_forbidden"
    User.objects.filter(username="ns").update(is_staff=True)
    t = login(api, username="ns").json()["access_token"]
    assert api.get(f"{A}/users", **H(t)).status_code == 200


def test_plain_logout_kills_reauth(api, admin_user, make_user):
    r = login(api, username="admin").json()
    t, refresh = r["access_token"], r["refresh_token"]
    rt = api.post(f"{A}/reauth", {"password": PASSWORD}, format="json", **H(t)).json()["reauth_token"]
    assert api.post("/api/v1/auth/logout", {"refresh_token": refresh}, format="json").status_code == 204
    assert not AdminReauth.objects.exists()
    v = make_user(username="v", email="v@x.org", groups=())
    assert api.delete(f"{A}/users/{v.pk}", **H(t, rt)).json()["error"] == "reauth_required"


def test_logout_all_kills_reauth(api, at, reauth, admin_user):
    assert api.post("/api/v1/auth/logout-all", **H(at)).status_code == 204
    assert not AdminReauth.objects.exists()
