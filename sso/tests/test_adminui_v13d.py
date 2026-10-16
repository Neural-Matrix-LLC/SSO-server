"""v1.3d admin web UI (docs/DESIGN-v1.3d-admin-ui.md §16 test plan)."""
from __future__ import annotations

import io
import re
import time

import pytest
from django.conf import settings
from django.contrib.auth.models import Group, Permission, User
from django.test import Client, override_settings

from application.models import ApplicationPermissionRecord
from sso.models import AdminAuditLog, AdminReauth, ServiceClient

from .conftest import PASSWORD, bearer, login

UI = "/" + settings.SSO_ADMIN_UI_PATH
IP = "203.0.113.5"
COOKIE = settings.SSO_ADMIN_UI_COOKIE


def perm(code):
    return Permission.objects.get(content_type__app_label="application", codename=code)


@pytest.fixture
def admin_user(make_user):
    u = make_user(username="admin", email="admin@example.org", groups=(), is_staff=True)
    u.user_permissions.add(perm("sso_admin"))
    return u


@pytest.fixture
def admin2(make_user):
    u = make_user(username="admin2", email="admin2@example.org", groups=(), is_staff=True)
    u.user_permissions.add(perm("sso_admin"))
    return u


def ui_client(**kw) -> Client:
    return Client(REMOTE_ADDR=IP, **kw)


def ui_login(c: Client, username="admin", password=PASSWORD, **extra):
    return c.post(UI + "login/", {"username": username, "password": password}, **extra)


@pytest.fixture
def c(admin_user):
    c = ui_client()
    r = ui_login(c)
    assert r.status_code == 302 and r["Location"] == UI, r.content
    return c


def elevate(c, password=PASSWORD, **extra):
    return c.post(UI + "reauth/", {"password": password, "next": UI}, **extra)


# ------------------------------------------------------------------ access matrix (§4)
def test_anonymous_redirects_to_login(db):
    r = ui_client().get(UI + "users/")
    assert r.status_code == 302 and r["Location"].startswith(UI + "login/?next=")


def test_login_page_renders_with_headers(db):
    r = ui_client().get(UI + "login/")
    assert r.status_code == 200 and b"sign in" in r.content.lower()
    assert "script-src 'self'" in r["Content-Security-Policy"] and "frame-ancestors 'none'" in r[
        "Content-Security-Policy"]
    assert r["Cache-Control"] == "no-store" and r["X-Frame-Options"] == "DENY"
    assert r["Referrer-Policy"] == "same-origin" and r["Cross-Origin-Opener-Policy"] == "same-origin"


@pytest.mark.parametrize("kind,ok", [
    ("staff_admin", True), ("superuser_staff", True), ("admin_not_staff", False), ("staff_no_perm", False),
    ("inactive_admin", False), ("superuser_not_staff", False), ("plain", False),
])
def test_access_matrix(make_user, kind, ok):
    flags = {"staff_admin": dict(is_staff=True), "superuser_staff": dict(is_staff=True, is_superuser=True),
             "admin_not_staff": dict(is_staff=False), "staff_no_perm": dict(is_staff=True),
             "inactive_admin": dict(is_staff=True, is_active=False),
             "superuser_not_staff": dict(is_superuser=True), "plain": {}}[kind]
    u = make_user(username="x", email="x@example.org", groups=(), **flags)
    if kind in ("staff_admin", "admin_not_staff", "inactive_admin"):
        u.user_permissions.add(perm("sso_admin"))
    c = ui_client()
    r = ui_login(c, "x")
    if ok:
        assert r.status_code == 302 and c.get(UI + "users/").status_code == 200
        assert AdminAuditLog.objects.filter(action="ui.login", result="ok", channel="ui").count() == 1
    else:
        assert r.status_code == 200 and b"Invalid username or password, or no admin access" in r.content
        row = AdminAuditLog.objects.get(action="ui.login", result="denied")
        assert row.channel == "ui" and row.after["reason"] in ("not_staff", "no_sso_admin", "inactive",
                                                                "invalid_credentials")
        assert c.get(UI + "users/").status_code == 302


def test_wrong_password_generic_message(admin_user):
    r = ui_login(ui_client(), password="nope")
    assert b"Invalid username or password, or no admin access" in r.content
    assert AdminAuditLog.objects.get(action="ui.login").after == {"reason": "invalid_credentials"}


def test_login_throttle(admin_user):
    c = ui_client()
    codes = [ui_login(c, password="bad").status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429  # 5/min per username


def test_login_ip_throttle(make_user, db):
    c = ui_client()
    codes = [ui_login(c, username=f"u{i}", password="bad").status_code for i in range(11)]
    assert codes[-1] == 429 and codes[9] == 200  # 10/min per IP


def test_session_cookie_flags_and_no_tokens(admin_user):
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

    c = ui_client()
    c.get(UI + "login/")
    r = ui_login(c)
    m = r.cookies[COOKIE]
    assert COOKIE.startswith("__Host-")
    assert m["httponly"] and m["secure"] and m["samesite"] == "Strict" and m["path"] == "/" and not m["domain"]
    assert not m["max-age"]  # browser-session cookie
    assert "sessionid" not in r.cookies and OutstandingToken.objects.count() == 0
    csrf = c.cookies[settings.CSRF_COOKIE_NAME]
    assert settings.CSRF_COOKIE_NAME == "__Host-sso_admin_csrf" and csrf["samesite"] == "Strict" and csrf["httponly"]


def test_login_open_redirect_blocked(admin_user):
    c = ui_client()
    r = c.post(UI + "login/", {"username": "admin", "password": PASSWORD, "next": "https://evil.example/"})
    assert r["Location"] == UI
    c2 = ui_client()
    r = c2.post(UI + "login/", {"username": "admin", "password": PASSWORD, "next": UI + "audit/"})
    assert r["Location"] == UI + "audit/"


def test_ui_session_not_valid_for_django_admin(c):
    r = c.get("/" + settings.SSO_ADMIN_PATH)
    assert r.status_code == 302 and "login" in r["Location"]  # Django admin has its own login


def test_django_admin_session_not_valid_for_ui(admin_user):
    admin_user.is_superuser = True
    admin_user.save()
    c = ui_client()
    c.force_login(admin_user)  # a Django-admin style session (sessionid cookie)
    assert c.get(UI + "users/").status_code == 302


# ------------------------------------------------------------------ session guard (§5)
def _age(c, **fields):
    s = c.session
    for k, v in fields.items():
        s[k] = v
    s.save()


def test_session_lives_under_ui_cookie(c):
    assert COOKIE in c.cookies


def test_idle_timeout(c):
    s = c.session  # test client reads SESSION_COOKIE_NAME; use the store directly
    from django.contrib.sessions.backends.db import SessionStore

    store = SessionStore(c.cookies[COOKIE].value)
    store["adminui_seen"] = time.time() - settings.SSO_ADMIN_UI_IDLE_SECONDS - 5
    store.save()
    r = c.get(UI + "users/")
    assert r.status_code == 302 and "m=expired" in r["Location"]
    assert c.get(UI).status_code == 302
    del s


def test_absolute_timeout(c):
    from django.contrib.sessions.backends.db import SessionStore

    store = SessionStore(c.cookies[COOKIE].value)
    store["adminui_login_at"] = time.time() - settings.SSO_ADMIN_UI_MAX_AGE_SECONDS - 5
    store.save()
    assert "m=expired" in c.get(UI).get("Location", "")


@pytest.mark.parametrize("mode,kept", [("ENFORCE", False), ("WARNING", True), ("NOIP", True)])
def test_ip_binding(c, mode, kept):
    with override_settings(SSO_ADMIN_UI_IP_BINDING=mode):
        r = c.get(UI + "users/", REMOTE_ADDR="198.51.100.9")
    if kept:
        assert r.status_code == 200
    else:
        assert r.status_code == 302 and "m=ip" in r["Location"]
        assert AdminAuditLog.objects.filter(action="ui.session_ip_mismatch", result="denied").exists()
        assert c.get(UI).status_code == 302


def test_access_lost_mid_session(c, admin_user):
    admin_user.user_permissions.remove(perm("sso_admin"))
    r = c.get(UI)
    assert "m=lost" in r["Location"]
    assert AdminAuditLog.objects.filter(action="ui.access_lost").exists()


def test_logout(c):
    r = c.post(UI + "logout/")
    assert r.status_code == 302 and "m=out" in r["Location"]
    assert AdminAuditLog.objects.filter(action="ui.logout", channel="ui").exists()
    assert c.get(UI).status_code == 302


def test_logout_everywhere_kills_ui_sessions_and_tokens(c, admin_user, api):
    other = ui_client()
    ui_login(other)
    tok = login(api, username="admin").json()["access_token"]
    time.sleep(0.01)
    assert c.post(UI + "logout-everywhere/").status_code == 302
    assert "m=revoked" in other.get(UI).get("Location", "")
    assert api.get("/api/v1/admin/users", **bearer(tok)).status_code == 401


def test_suspend_of_admin_by_other_admin_ends_ui_session(c, admin2):
    c2 = ui_client()
    ui_login(c2, "admin2")
    elevate(c2)
    time.sleep(0.01)
    from django.contrib.auth.models import User as U
    assert c2.post(f"{UI}users/{U.objects.get(username='admin').pk}/suspend").status_code == 302
    r = c.get(UI)
    assert r.status_code == 302 and "login" in r["Location"]


def test_password_change_ends_ui_session(c, admin_user):
    admin_user.set_password("Another-Horse-77")
    admin_user.save()
    assert c.get(UI).status_code == 302


# ------------------------------------------------------------------ CSRF (§5.1)
def test_csrf_enforced(admin_user):
    c = ui_client(enforce_csrf_checks=True)
    r = c.post(UI + "login/", {"username": "admin", "password": PASSWORD})
    assert r.status_code == 403 and b"form expired" in r.content
    page = c.get(UI + "login/")
    token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', page.content).group(1).decode()
    r = c.post(UI + "login/", {"username": "admin", "password": PASSWORD, "csrfmiddlewaretoken": token})
    assert r.status_code == 302
    r = c.post(UI + "groups/new/", {"name": "g1"})  # no token
    assert r.status_code == 403 and not Group.objects.filter(name="g1").exists()
    page = c.get(UI + "groups/")
    token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', page.content).group(1).decode()
    assert c.post(UI + "groups/new/", {"name": "g1", "csrfmiddlewaretoken": token}).status_code == 302


def test_api_unaffected_by_csrf(api, admin_user):
    tok = login(api, username="admin").json()["access_token"]
    assert api.post("/api/v1/admin/groups", {"name": "z"}, format="json", **bearer(tok)).status_code == 201


# ------------------------------------------------------------------ step-up (§6)
def test_stepup_flow_suspend(c, user):
    r = c.post(f"{UI}users/{user.pk}/suspend")
    assert r.status_code == 302 and r["Location"].startswith(UI + "reauth/?next=")
    user.refresh_from_db()
    assert user.is_active
    denied = AdminAuditLog.objects.get(action="user.suspend", result="denied")
    assert denied.channel == "ui" and denied.after == {"reason": "reauth_required"}
    assert c.get(f"{UI}users/{user.pk}/suspend").status_code == 302  # confirm page also needs elevation
    r = elevate(c)
    assert r.status_code == 302
    row = AdminReauth.objects.get()
    assert row.sid.startswith("ui:") and row.ip == IP
    page = c.get(f"{UI}users/{user.pk}/suspend")
    assert page.status_code == 200 and b"Suspend and log out all sessions" in page.content
    assert b"Elevated" in page.content
    assert c.post(f"{UI}users/{user.pk}/suspend").status_code == 302
    user.refresh_from_db()
    assert not user.is_active
    ok = AdminAuditLog.objects.get(action="user.suspend", result="ok")
    assert ok.channel == "ui" and ok.stepup


def test_stepup_wrong_password_and_throttle(c):
    codes = [elevate(c, "bad").status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    assert AdminAuditLog.objects.filter(action="reauth", result="denied").count() == 5


def test_stepup_bound_to_session_and_ip(c, admin_user, user):
    elevate(c)
    other = ui_client()
    ui_login(other)
    assert other.post(f"{UI}users/{user.pk}/suspend").status_code == 302  # not elevated
    user.refresh_from_db()
    assert user.is_active
    with override_settings(SSO_ADMIN_UI_IP_BINDING="WARNING"):
        r = c.post(f"{UI}users/{user.pk}/suspend", REMOTE_ADDR="198.51.100.9")
    assert r["Location"].startswith(UI + "reauth/")
    user.refresh_from_db()
    assert user.is_active


def test_stepup_expires_and_drop(c, user):
    elevate(c)
    AdminReauth.objects.update(expires_at=AdminReauth.objects.get().created)
    assert c.post(f"{UI}users/{user.pk}/suspend")["Location"].startswith(UI + "reauth/")
    elevate(c)
    c.post(UI + "reauth/drop/", {"back": UI})
    assert not AdminReauth.objects.exists()
    assert AdminAuditLog.objects.filter(action="reauth.drop").exists()


def test_reauth_token_from_api_not_usable_in_ui(c, api, admin_user, user):
    tok = login(api, username="admin").json()["access_token"]
    api.post("/api/v1/admin/reauth", {"password": PASSWORD}, format="json", **bearer(tok))
    assert c.post(f"{UI}users/{user.pk}/suspend")["Location"].startswith(UI + "reauth/")


def test_reauth_next_open_redirect_blocked(c):
    r = c.post(UI + "reauth/", {"password": PASSWORD, "next": "//evil.example/x"})
    assert r["Location"] == UI


def test_delete_requires_typed_name(c, user):
    elevate(c)
    r = c.post(f"{UI}users/{user.pk}/delete", {"confirm": "wrong"})
    assert r.status_code == 400 and User.objects.filter(pk=user.pk).exists()
    assert c.post(f"{UI}users/{user.pk}/delete", {"confirm": user.username}).status_code == 302
    assert not User.objects.filter(pk=user.pk).exists()


def test_grant_sso_admin_needs_stepup(c, user):
    r = c.post(f"{UI}users/{user.pk}/permissions", {"op": "grant", "codename": "sso_admin",
                                                     "back": f"{UI}users/{user.pk}/"})
    assert r["Location"] == f"{UI}reauth/?next=" + f"{UI}users/{user.pk}/".replace("/", "%2F")
    assert not user.user_permissions.filter(codename="sso_admin").exists()
    c.post(f"{UI}users/{user.pk}/permissions", {"op": "grant", "codename": "app1"})
    assert user.user_permissions.filter(codename="app1").exists()  # ordinary grant: no step-up


# ------------------------------------------------------------------ guards (§4)
def test_self_suspend_409(c, admin_user):
    elevate(c)
    r = c.post(f"{UI}users/{admin_user.pk}/suspend")
    assert r.status_code == 409 and b"cannot suspend yourself" in r.content


def test_remove_own_admin_409(c, admin_user):
    elevate(c)
    r = c.post(f"{UI}users/{admin_user.pk}/permissions", {"op": "revoke", "codename": "sso_admin"})
    assert r.status_code == 409
    assert admin_user.user_permissions.filter(codename="sso_admin").exists()


def test_last_admin_via_group(c, admin_user):
    g = Group.objects.create(name="admins")
    g.permissions.add(perm("sso_admin"))
    admin_user.groups.add(g)
    admin_user.user_permissions.remove(perm("sso_admin"))
    elevate(c)
    r = c.post(f"{UI}groups/{g.pk}/permissions", {"op": "revoke", "codename": "sso_admin"})
    assert r.status_code == 409 and g.permissions.filter(codename="sso_admin").exists()


def test_code_defined_permission_not_deletable(c):
    elevate(c)
    r = c.post(f"{UI}permissions/sso_admin/delete")
    assert r.status_code == 409


# ------------------------------------------------------------------ audit channel (§13)
def test_audit_channel_api_vs_ui(c, api, admin_user):
    c.post(UI + "groups/new/", {"name": "from-ui"})
    tok = login(api, username="admin").json()["access_token"]
    api.post("/api/v1/admin/groups", {"name": "from-api"}, format="json", **bearer(tok))
    assert AdminAuditLog.objects.get(action="group.create", after={"name": "from-ui"}).channel == "ui"
    assert AdminAuditLog.objects.get(action="group.create", after={"name": "from-api"}).channel == "api"
    r = api.get("/api/v1/admin/audit?channel=ui", **bearer(tok))
    assert r.status_code == 200 and {x["channel"] for x in r.json()["results"]} == {"ui"}
    assert api.get("/api/v1/admin/audit?channel=bogus", **bearer(tok)).status_code == 400


# ------------------------------------------------------------------ import (§8.2)
EVIL = b'import os\nos.system("touch /tmp/sso-adminui-pwned")\nAPP_CODENAME = "gw"\n'
GOOD = b'"""perms"""\nAPP_CODENAME = "gw"\nAPP_NAME = "Gateway"\nPERMISSIONS_VERSION = 2\n' \
       b'PERMISSIONS = [("gw_trade", "Trade"), ("gw_read", "Read", "read only")]\n'


def _upload(c, content, name="sso_permissions.py", **extra):
    f = io.BytesIO(content)
    f.name = name
    return c.post(UI + "apps/import/", {"file": f, **extra})


def test_import_never_executes(c, tmp_path):
    import os

    r = _upload(c, EVIL)
    assert r.status_code == 200 and b"only NAME = &lt;literal&gt; assignments" in r.content
    assert not os.path.exists("/tmp/sso-adminui-pwned")
    r = _upload(c, b'APP_CODENAME = __import__("os").getcwd()\n')
    assert b"must be a literal" in r.content


def test_import_preview_apply_and_deprecate(c):
    r = _upload(c, GOOD)
    assert r.status_code == 200 and b"Preview: gw" in r.content
    assert not ApplicationPermissionRecord.objects.filter(app_codename="gw").exists()  # dry run
    payload = re.search(rb'name="payload" value="([^"]+)"', r.content).group(1).decode().replace("&quot;", '"')
    digest = re.search(rb'name="digest" value="([^"]+)"', r.content).group(1).decode()
    bad = c.post(UI + "apps/import/apply", {"payload": payload.replace("Trade", "Hack"), "digest": digest,
                                            "force": "0"})
    assert b"payload changed" in bad.content
    assert c.post(UI + "apps/import/apply", {"payload": payload, "digest": digest, "force": "0"}).status_code == 302
    assert set(ApplicationPermissionRecord.objects.filter(app_codename="gw").values_list("codename", flat=True)) \
        >= {"gw_trade", "gw_read"}  # plus the app-access record
    row = AdminAuditLog.objects.get(action="app.import")
    assert row.channel == "ui"
    # v3 drops gw_read -> deprecated, never deleted
    r = c.post(UI + "apps/import/", {"json": '{"app_codename":"gw","app_name":"Gateway","version":3,'
                                             '"permissions":[{"codename":"gw_trade","name":"Trade"}]}'})
    assert b"gw_read" in r.content
    payload = re.search(rb'name="payload" value="([^"]+)"', r.content).group(1).decode().replace("&quot;", '"')
    digest = re.search(rb'name="digest" value="([^"]+)"', r.content).group(1).decode()
    c.post(UI + "apps/import/apply", {"payload": payload, "digest": digest, "force": "0"})
    rec = ApplicationPermissionRecord.objects.get(codename="gw_read")
    assert rec.deprecated_at is not None and Permission.objects.filter(codename="gw_read").exists()


def test_import_size_cap(c):
    r = _upload(c, b"#" * (64 * 1024 + 10))
    assert b"larger than 64 KiB" in r.content


# ------------------------------------------------------------------ services, secrets once
def test_service_secret_shown_once(c):
    r = c.post(UI + "services/new/", {"client_id": "svc1", "name": "Svc"})
    assert r.status_code == 200 and r["Cache-Control"] == "no-store"
    secret = re.search(rb'<code id="secret">([^<]+)</code>', r.content).group(1)
    client = ServiceClient.objects.get(client_id="svc1")
    assert client.check_secret(secret.decode())
    page = c.get(UI + "services/svc1/")
    assert secret not in page.content
    assert secret not in b"".join(str(a.after).encode() for a in AdminAuditLog.objects.all())


def test_service_deactivate_needs_stepup(c):
    c.post(UI + "services/new/", {"client_id": "svc2", "name": "Svc"})
    r = c.post(UI + "services/svc2/", {"name": "Svc", "back": UI + "services/svc2/"})  # is_active unticked
    assert r["Location"].startswith(UI + "reauth/")
    assert ServiceClient.objects.get(client_id="svc2").is_active
    elevate(c)
    c.post(UI + "services/svc2/", {"name": "Svc"})
    assert not ServiceClient.objects.get(client_id="svc2").is_active


def test_rotate_secret_and_delete(c):
    c.post(UI + "services/new/", {"client_id": "svc3", "name": "Svc"})
    elevate(c)
    r = c.post(UI + "services/svc3/rotate-secret")
    secret = re.search(rb'<code id="secret">([^<]+)</code>', r.content).group(1).decode()
    assert ServiceClient.objects.get(client_id="svc3").check_secret(secret)
    assert c.post(UI + "services/svc3/delete", {"confirm": "svc3"}).status_code == 302
    assert not ServiceClient.objects.filter(client_id="svc3").exists()


# ------------------------------------------------------------------ pages, exports, misc
def test_all_pages_render(c, user, admin_user):
    g = Group.objects.create(name="g")
    c.post(UI + "services/new/", {"client_id": "svc", "name": "Svc"})
    for path in ["", "me/", "users/", f"users/{user.pk}/", "users/new/", "groups/", f"groups/{g.pk}/",
                 "permissions/", "permissions/app1/", "apps/", "apps/import/", "services/", "services/new/",
                 "services/svc/", "devices/", "webhooks/", "webhooks/deliveries/", "audit/",
                 f"audit/{AdminAuditLog.objects.first().pk}/", "users/?active=false&q=th&page=2"]:
        r = c.get(UI + path)
        assert r.status_code == 200, (path, r.status_code)
        assert "default-src 'none'" in r["Content-Security-Policy"] and r["Cache-Control"] == "no-store"
        assert b"<script>" not in r.content and b" style=" not in r.content  # CSP: no inline script/style


def test_404_is_html_under_ui_json_elsewhere(c):
    r = c.get(UI + "users/999999/")
    assert r.status_code == 404 and b"<html" in r.content
    r = c.get("/api/v1/nope")
    assert r.status_code == 404 and r.json()["error"] == "not_found"


def test_csv_export_formula_safe(c, make_user):
    make_user(username="evil", email="evil@example.org", first_name="=HYPERLINK(1)", groups=())
    r = c.get(UI + "users/export.csv")
    assert r.status_code == 200 and b"'=HYPERLINK(1)" in r.content
    assert AdminAuditLog.objects.filter(action="ui.export", channel="ui").exists()
    r = c.get(UI + "audit/export.csv?channel=ui")
    assert r.status_code == 200 and b"ui.login" in r.content


def test_admin_hostname_enforced(c):
    with override_settings(SSO_ADMIN_UI_HOSTNAME="admin.sso.test", ALLOWED_HOSTS=["testserver", "admin.sso.test"]):
        assert c.get(UI + "login/").status_code == 404
        assert ui_client().get(UI + "login/", HTTP_HOST="admin.sso.test").status_code == 200


def test_create_staff_only_by_superuser(c):
    r = c.post(UI + "users/new/", {"username": "s1", "is_staff": "on"})
    assert r.status_code == 200 and b"Only a superuser" in r.content and not User.objects.filter(username="s1").exists()
    r = c.post(UI + "users/new/", {"username": "s2", "password": "Strong-Pass-123", "password2": "Strong-Pass-123"})
    assert r.status_code == 302 and User.objects.get(username="s2").check_password("Strong-Pass-123")


def test_group_members_and_profile_edit(c, user):
    g = Group.objects.create(name="team")
    c.post(f"{UI}groups/{g.pk}/members", {"usernames": "thomas"})
    assert list(g.user_set.values_list("username", flat=True)) == ["thomas"]
    r = c.post(f"{UI}groups/{g.pk}/members", {"usernames": "ghost"})
    assert r.status_code == 400
    c.post(f"{UI}users/{user.pk}/", {"email": "new@example.org", "first_name": "T", "last_name": "C"})
    user.refresh_from_db()
    assert user.email == "new@example.org"


def test_settings_validation():
    import subprocess
    import sys

    code = "import ssoproject.settings_test"
    env = {"PATH": "/usr/bin:/bin", "SSO_ADMIN_UI_PATH": "sso-admin/", "PYTHONPATH": "."}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert "SSO_ADMIN_UI_PATH must be" in out.stderr
