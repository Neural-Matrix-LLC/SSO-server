"""V12A-xx: SSO-server v1.2a (docs/DESIGN-v1.2-requirements.md §3.2/§3.3/§4.2 "Session"/§5/§10).

Black-box over HTTP (API and the Django admin UI with a test superuser) plus manage.py / Django-shell steps where
the case needs them (QuerySet.update(), the sweep command, DB state). Every test creates its own throw-away users
(prefix qa12_) so cases are independent and re-runnable.

Env (set by qa/harness/run_v12a_round.sh):
  SSO_BASE_URL     main instance (default grace 10 s)
  SSO_GRACE0_URL   second instance on the same DB with SSO_REFRESH_REUSE_GRACE_SECONDS=0
  SSO_ADMIN_URL    instance on the same DB with SSO_SECURE_COOKIES=False (admin session/CSRF cookies over http)
  SSO_SERVER_LOG / SSO_GRACE0_LOG   combined server logs (log-line checks)
  SSO_MANAGE_CMD   qa/harness/manage.sh (QA DB only)
"""
from __future__ import annotations

import html
import itertools
import json
import os
import re
import shlex
import sqlite3
import subprocess
import time
import uuid

import jwt
import pytest
import requests

import testdata
from sso_client import SSOClient

pytestmark = [pytest.mark.v12a, pytest.mark.needs_manage]

PW = "Qa12-Passw0rd!xyz"
GRACE = int(os.environ.get("SSO_TEST_REUSE_GRACE", "10"))
SVC = (testdata.SERVICE_CLIENT_ID, testdata.SERVICE_CLIENT_SECRET)
_n = itertools.count()


def _uniq(tag: str) -> str:
    return f"qa12_{tag}_{uuid.uuid4().hex[:6]}"


def claims(tok: str) -> dict:
    return jwt.decode(tok, options={"verify_signature": False})


def _log(var: str) -> str:
    p = os.environ.get(var)
    if not p:
        pytest.skip(f"{var} not set")
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _log_events(var: str, user_id: int) -> list[dict]:
    out = []
    for line in _log(var).splitlines():
        m = re.search(r"(\{.*\})\s*$", line)
        if m:
            try:
                d = json.loads(m.group(1))
            except ValueError:
                continue
            if d.get("user_id") == user_id:
                out.append(d)
    return out


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def mk_user(manage):
    def make(tag: str, *, staff=False, superuser=False) -> tuple[str, int]:
        name = _uniq(tag)
        pk = manage.shell(
            "from django.contrib.auth.models import User;"
            f"u=User.objects.create_user({name!r}, password={PW!r}, is_staff={staff!r}, is_superuser={superuser!r});"
            "print(u.pk)").splitlines()[-1]
        return name, int(pk)
    return make


@pytest.fixture(scope="module")
def grace0():
    url = os.environ.get("SSO_GRACE0_URL")
    if not url:
        pytest.skip("SSO_GRACE0_URL not set")
    return SSOClient(url, True)


@pytest.fixture(scope="module")
def admin_url():
    url = os.environ.get("SSO_ADMIN_URL")
    if not url:
        pytest.skip("SSO_ADMIN_URL not set (instance with SSO_SECURE_COOKIES=False)")
    return url.rstrip("/") + "/sso-admin"


def _session(sso, name):
    b = sso.login_ok(name, PW).json()
    return b["access_token"], b["refresh_token"]


def _dead(sso, access, refresh, *, refresh_status=(401,), refresh_code=None):
    """All dead. For a suspended user, refresh AND /me answer 403 account_inactive (sso/errors.py maps simplejwt's
    user_inactive); for revoked tokens of an active user both answer 401."""
    r = sso.refresh_native(refresh, retry_on_429=True)
    assert r.status_code in refresh_status, (r.status_code, r.text)
    if refresh_code:
        assert r.json().get("error") == refresh_code, r.text
    me = sso.me(access)
    if refresh_code == "account_inactive":
        assert me.status_code == 403 and me.json().get("error") == "account_inactive", me.text
    else:
        assert me.status_code == 401, me.text
    i = sso.introspect(access, SVC)
    assert i.status_code == 200 and i.json() == {"active": False}, i.text


def _alive(sso, access):
    assert sso.me(access).status_code == 200
    assert sso.introspect(access, SVC).json().get("active") is True


def _live_refresh_count(manage, pk) -> int:
    return int(manage.shell(
        "from django.utils import timezone;"
        "from rest_framework_simplejwt.token_blacklist.models import OutstandingToken as O;"
        f"print(O.objects.filter(user_id={pk}, expires_at__gt=timezone.now(), blacklistedtoken__isnull=True).count())"
    ).splitlines()[-1])


class Admin:
    """Logged-in Django admin session (requests), CSRF handled."""

    def __init__(self, base, username):
        self.base, self.s = base, requests.Session()
        r = self.s.get(f"{base}/login/", timeout=15)
        assert r.status_code == 200, r.status_code
        r = self.s.post(f"{base}/login/?next=/sso-admin/", timeout=15, allow_redirects=False,
                        data={"username": username, "password": PW, "csrfmiddlewaretoken": self.csrf(r.text),
                              "next": "/sso-admin/"}, headers={"Referer": f"{base}/login/"})
        assert r.status_code == 302, (r.status_code, r.text[:500])

    @staticmethod
    def csrf(text):
        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', text)
        assert m, "no csrf token in page"
        return m.group(1)

    def get(self, path):
        return self.s.get(self.base + path, timeout=15, allow_redirects=False)

    def post(self, path, data, *, page=None):
        page = page or self.get(path)
        data = {"csrfmiddlewaretoken": self.csrf(page.text), **data}
        return self.s.post(self.base + path, data=data, timeout=15, allow_redirects=False,
                           headers={"Referer": self.base + path})

    def action(self, changelist, action, pks, **extra):
        return self.post(changelist, {"action": action, "index": "0", "select_across": "0",
                                      "_selected_action": [str(p) for p in pks], **extra})

    @staticmethod
    def messages(text):
        return [html.unescape(re.sub("<[^>]+>", "", m)).strip()
                for m in re.findall(r'<li class="(?:success|error|warning|info)">(.*?)</li>', text, re.S)]


@pytest.fixture(scope="module")
def admin(admin_url, mk_user):
    name, pk = mk_user("admin", staff=True, superuser=True)
    a = Admin(admin_url, name)
    a.username, a.pk = name, pk
    return a


def _user_change_form(admin, pk):
    page = admin.get(f"/auth/user/{pk}/change/")
    assert page.status_code == 200
    t = page.text
    def val(n):
        m = re.search(rf'name="{n}"[^>]*value="([^"]*)"', t)
        return html.unescape(m.group(1)) if m else ""
    data = {"username": val("username"), "first_name": val("first_name"), "last_name": val("last_name"),
            "email": val("email"), "date_joined_0": val("date_joined_0"), "date_joined_1": val("date_joined_1"),
            "initial-date_joined_0": val("initial-date_joined_0"), "initial-date_joined_1": val("initial-date_joined_1"),
            "last_login_0": val("last_login_0"), "last_login_1": val("last_login_1"), "_save": "Save"}
    for flag in ("is_staff", "is_superuser"):
        if re.search(rf'name="{flag}"[^>]*checked', t):
            data[flag] = "on"
    return page, data


# =========================================================================== suspend (decision 6)
def test_V12A_SUSP_01_admin_action_suspend_revokes_everything(sso, admin, mk_user):
    name, pk = mk_user("susp1")
    a1, r1 = _session(sso, name)
    a2, r2 = _session(sso, name)
    r = admin.action("/auth/user/", "suspend_users", [pk])
    assert r.status_code == 302, r.text[:500]
    for a, rf in ((a1, r1), (a2, r2)):
        _dead(sso, a, rf, refresh_status=(403,), refresh_code="account_inactive")
    assert sso.login(name, PW, retry_on_429=True).status_code in (401, 403)
    ev = [e for e in _log_events("SSO_SERVER_LOG", pk) if e.get("event") == "user.suspended"] or \
         [e for e in _log_events("SSO_ADMIN_LOG", pk) if e.get("event") == "user.suspended"]
    assert ev, "sso.admin user.suspended line missing"


def test_V12A_SUSP_02_model_save_in_shell_revokes(sso, manage, mk_user):
    name, pk = mk_user("susp2")
    a, rf = _session(sso, name)
    manage.set_user(name, is_active=False)
    _dead(sso, a, rf, refresh_status=(403,), refresh_code="account_inactive")
    assert _live_refresh_count(manage, pk) == 0


def test_V12A_SUSP_03_admin_change_form_untick_is_active_revokes(sso, admin, mk_user):
    name, pk = mk_user("susp3")
    a, rf = _session(sso, name)
    page, data = _user_change_form(admin, pk)
    r = admin.post(f"/auth/user/{pk}/change/", data, page=page)      # is_active omitted = unticked
    assert r.status_code == 302, r.text[:1500]
    _dead(sso, a, rf, refresh_status=(403,), refresh_code="account_inactive")


def test_V12A_SUSP_04_unsuspend_restores_login_old_tokens_stay_dead(sso, admin, manage, mk_user):
    name, pk = mk_user("susp4")
    a, rf = _session(sso, name)
    assert admin.action("/auth/user/", "suspend_users", [pk]).status_code == 302
    assert admin.action("/auth/user/", "unsuspend_users", [pk]).status_code == 302
    assert manage.user_field(name, "is_active") == "True"
    _dead(sso, a, rf)                                   # active again, but the old pair is revoked: 401
    a2, r2 = _session(sso, name)
    _alive(sso, a2)
    assert sso.refresh_native(r2).status_code == 200


def test_V12A_SUSP_05_save_update_fields_without_is_active_does_not_revoke(sso, manage, mk_user):
    name, pk = mk_user("susp5")
    a, rf = _session(sso, name)
    manage.shell("from django.contrib.auth.models import User;"
                 f"u=User.objects.get(pk={pk}); u.first_name='x'; u.save(update_fields=['first_name'])")
    _alive(sso, a)
    assert sso.refresh_native(rf).status_code == 200


# =========================================================================== update() gap + sweep
def _qs_update(manage, pk, active: bool):
    manage.shell(f"from django.contrib.auth.models import User; User.objects.filter(pk={pk}).update(is_active={active!r})")


def _manage_cmd(*args):
    argv = shlex.split(os.environ["SSO_MANAGE_CMD"]) + list(args)
    return subprocess.run(argv, capture_output=True, text=True, timeout=120)


def test_V12A_UPD_01_update_bypasses_signal_sweep_catches_it(sso, manage, mk_user):
    name, pk = mk_user("upd1")
    a, rf = _session(sso, name)
    _qs_update(manage, pk, False)
    assert _live_refresh_count(manage, pk) == 1, "update() must not have fired the signal (nothing blacklisted)"
    dry = _manage_cmd("revoke_inactive_users", "--dry-run")
    assert dry.returncode == 0 and re.search(r"would revoke tokens of [1-9]\d* inactive user", dry.stdout), dry.stdout
    assert _live_refresh_count(manage, pk) == 1, "--dry-run must not revoke"
    run = _manage_cmd("revoke_inactive_users")
    assert run.returncode == 0 and re.search(r"revoked tokens of [1-9]\d* inactive user", run.stdout), run.stdout
    assert _live_refresh_count(manage, pk) == 0
    again = _manage_cmd("revoke_inactive_users", "--dry-run")
    assert name not in again.stdout
    _qs_update(manage, pk, True)                        # reactivate, also without signal
    _dead(sso, a, rf)                                    # swept tokens stay dead


def test_V12A_UPD_01b_sweep_is_idempotent_and_skips_revoked_users(manage, mk_user, sso):
    name, pk = mk_user("upd1b")
    _session(sso, name)
    _qs_update(manage, pk, False)
    _manage_cmd("revoke_inactive_users")
    out = _manage_cmd("revoke_inactive_users", "--dry-run").stdout
    # the same user is not counted again: run twice, the count does not include it (compare with a fresh run)
    n1 = int(re.search(r"(\d+) inactive", out).group(1))
    n2 = int(re.search(r"(\d+) inactive", _manage_cmd("revoke_inactive_users", "--dry-run").stdout).group(1))
    assert n1 == n2


def test_V12A_UPD_02_first_use_after_update_revokes_on_sight(sso, manage, mk_user):
    name, pk = mk_user("upd2")
    a, rf = _session(sso, name)
    _qs_update(manage, pk, False)
    assert sso.introspect(a, SVC).json() == {"active": False}       # sees the inactive user -> revokes
    assert _live_refresh_count(manage, pk) == 0
    _qs_update(manage, pk, True)
    _dead(sso, a, rf)


def test_V12A_UPD_02b_refresh_after_update_is_403_and_revokes(sso, manage, mk_user):
    name, pk = mk_user("upd2b")
    a, rf = _session(sso, name)
    _qs_update(manage, pk, False)
    r = sso.refresh_native(rf)
    assert r.status_code == 403 and r.json()["error"] == "account_inactive", r.text
    _qs_update(manage, pk, True)
    _dead(sso, a, rf)


def test_V12A_UPD_03_documented_residual_gap(sso, manage, mk_user):
    """§10 'Residual gap': suspended and reactivated with update() both times, no token use, no sweep ->
    pre-suspension tokens survive. Pinned so a change is noticed (accepted by design)."""
    name, pk = mk_user("upd3")
    a, rf = _session(sso, name)
    _qs_update(manage, pk, False)
    _qs_update(manage, pk, True)
    _alive(sso, a)
    assert sso.refresh_native(rf).status_code == 200


# =========================================================================== sid
def test_V12A_SID_01_sid_on_login_kept_on_refresh(sso, mk_user):
    name, _ = mk_user("sid1")
    b = sso.login_ok(name, PW).json()
    sa, sr = claims(b["access_token"]).get("sid"), claims(b["refresh_token"]).get("sid")
    assert sa and sa == sr and len(sa) >= 16
    rf = b["refresh_token"]
    for _ in range(3):
        nb = sso.refresh_native(rf).json()
        assert claims(nb["access_token"])["sid"] == sa == claims(nb["refresh_token"])["sid"]
        rf = nb["refresh_token"]
    i = sso.introspect(b["access_token"], SVC).json()
    assert i["active"] is True


def test_V12A_SID_02_different_logins_different_sids(sso, mk_user):
    name, _ = mk_user("sid2")
    sids = {claims(sso.login_ok(name, PW).json()["access_token"])["sid"] for _ in range(4)}
    assert len(sids) == 4


def test_V12A_SID_03_cookie_mode_carries_sid(sso, cfg, mk_user):
    from sso_client import refresh_cookie
    name, _ = mk_user("sid3")
    r = sso.login_ok(name, PW, client="browser", origin=cfg.allowed_origin)
    sid = claims(r.json()["access_token"])["sid"]
    c = refresh_cookie(r)
    assert c is not None and claims(c.value)["sid"] == sid
    r2 = sso.refresh_cookie(c.value, origin=cfg.allowed_origin)
    assert r2.status_code == 200 and claims(r2.json()["access_token"])["sid"] == sid


# =========================================================================== refresh reuse
def test_V12A_REUSE_01_within_grace_only_logged(sso, mk_user):
    name, pk = mk_user("reuse1")
    a, r1 = _session(sso, name)
    b = sso.refresh_native(r1).json()
    rep = sso.refresh_native(r1)
    assert rep.status_code == 401 and "access_token" not in rep.text
    _alive(sso, b["access_token"])
    assert sso.refresh_native(b["refresh_token"]).status_code == 200      # session kept
    time.sleep(0.5)
    ev = [e for e in _log_events("SSO_SERVER_LOG", pk) if e.get("event") in ("refresh", "session_revoked")]
    assert any(e.get("result") == "reuse_within_grace" for e in ev), ev
    assert not any(e.get("event") == "session_revoked" for e in ev), ev


def test_V12A_REUSE_02_after_grace_revokes_session_only(sso, manage, mk_user):
    name, pk = mk_user("reuse2")
    a1, r1 = _session(sso, name)            # session A (will be revoked)
    a_other, r_other = _session(sso, name)  # session B of the same user (must survive)
    b = sso.refresh_native(r1).json()
    time.sleep(GRACE + 1.5)
    rep = sso.refresh_native(r1)
    assert rep.status_code == 401
    # the whole family of session A is dead: newest refresh and its access token, and the original access token
    _dead(sso, b["access_token"], b["refresh_token"])
    assert sso.me(a1).status_code == 401
    # session B unaffected
    _alive(sso, a_other)
    assert sso.refresh_native(r_other).status_code == 200
    sid = claims(a1)["sid"]
    row = manage.shell("from sso.models import RevokedSession as R;"
                       f"r=R.objects.get(sid={sid!r}); print(r.reason, r.user_id)").splitlines()[-1]
    assert row == f"refresh_reuse {pk}"
    time.sleep(0.5)
    ev = _log_events("SSO_SERVER_LOG", pk)
    assert any(e.get("result") == "reuse_detected" for e in ev), ev
    sr = [e for e in ev if e.get("event") == "session_revoked"]
    assert sr and sr[-1]["reason"] == "refresh_reuse" and sr[-1]["tokens_blacklisted"] >= 1, sr
    text = _log("SSO_SERVER_LOG")
    for t in (r1, b["refresh_token"], a1):
        assert t not in text, "token string logged"


def test_V12A_REUSE_03_grace_zero_revokes_on_first_reuse(grace0, mk_user):
    name, pk = mk_user("reuse3")
    b0 = grace0.login_ok(name, PW).json()
    b1 = grace0.refresh_native(b0["refresh_token"]).json()
    rep = grace0.refresh_native(b0["refresh_token"])
    assert rep.status_code == 401
    assert grace0.refresh_native(b1["refresh_token"]).status_code == 401
    assert grace0.me(b1["access_token"]).status_code == 401
    time.sleep(0.5)
    ev = _log_events("SSO_GRACE0_LOG", pk)
    assert any(e.get("result") == "reuse_detected" for e in ev) and any(e.get("event") == "session_revoked" for e in ev), ev


def test_V12A_REUSE_04_replay_after_logout_revokes_ended_session(sso, manage, mk_user):
    """§10: replays of tokens blacklisted by logout also revoke the (already ended) session (harmless)."""
    name, pk = mk_user("reuse4")
    a, rf = _session(sso, name)
    assert sso.logout_native(rf).status_code in (200, 204)
    time.sleep(GRACE + 1.5)
    assert sso.refresh_native(rf).status_code == 401
    sid = claims(a)["sid"]
    assert manage.shell(f"from sso.models import RevokedSession as R; print(R.objects.filter(sid={sid!r}).count())"
                        ).splitlines()[-1] == "1"


def test_V12A_REUSE_05_suspended_user_replay_no_session_row(sso, manage, mk_user):
    name, pk = mk_user("reuse5")
    a, rf = _session(sso, name)
    sso.refresh_native(rf)
    manage.set_user(name, is_active=False)
    time.sleep(GRACE + 1.5)
    r = sso.refresh_native(rf)
    assert r.status_code == 403 and r.json()["error"] == "account_inactive"
    assert manage.shell(f"from sso.models import RevokedSession as R; print(R.objects.filter(user_id={pk}).count())"
                        ).splitlines()[-1] == "0"


def test_V12A_REUSE_06_garbage_refresh_no_side_effects(sso, mk_user):
    """A token that is not a genuine (signed by us) blacklisted refresh token must not revoke anything.
    (A validly signed token with an unknown jti is accepted by /refresh: simplejwt checks only the blacklist, so
    only the signing key holder can mint one; not a v1.2a finding.)"""
    name, pk = mk_user("reuse6")
    a, rf = _session(sso, name)
    head, body, sig = rf.split(".")
    for t in ("garbage", f"{head}.{body}.{sig[:-4]}AAAA", f"{head}.{body}"):
        assert sso.refresh_native(t).status_code == 401
    _alive(sso, a)
    assert sso.refresh_native(rf).status_code == 200


# =========================================================================== admin guards (HTTP UI)
def test_V12A_ADM_01_no_self_suspend_via_action(admin, manage):
    r = admin.action("/auth/user/", "suspend_users", [admin.pk])
    assert r.status_code == 302
    page = admin.get("/auth/user/")
    assert page.status_code == 200, "admin session must still work"
    assert any("cannot suspend yourself" in m for m in Admin.messages(page.text)), Admin.messages(page.text)
    assert manage.user_field(admin.username, "is_active") == "True"


def test_V12A_ADM_01b_self_suspend_via_change_form(admin_url, mk_user, manage):
    """The guard covers the action; is unticking is_active on one's OWN change form also refused?"""
    name, pk = mk_user("selfsusp", staff=True, superuser=True)
    a = Admin(admin_url, name)
    page, data = _user_change_form(a, pk)
    data["is_staff"] = data["is_superuser"] = "on"
    r = a.post(f"/auth/user/{pk}/change/", data, page=page)
    active = manage.user_field(name, "is_active")
    assert active == "True", (f"V12A-01: a superuser suspended THEMSELF via the change form (status {r.status_code}); "
                              "the action guard does not cover the form")


def test_V12A_ADM_02_code_defined_app1_cannot_be_deleted(admin, manage):
    pk = int(manage.shell("from application.permissions import app_permissions;"
                          "print(app_permissions().get(codename='app1').pk)").splitlines()[-1])
    g = admin.get(f"/application/applicationpermission/{pk}/delete/")
    assert g.status_code == 403
    page = admin.get(f"/application/applicationpermission/{pk}/change/")
    r = admin.post(f"/application/applicationpermission/{pk}/delete/", {"post": "yes"}, page=page)
    assert r.status_code == 403
    assert manage.shell("from application.permissions import app_permissions;"
                        "print(app_permissions().filter(codename='app1').exists())").splitlines()[-1] == "True"
    assert 'deletelink' not in page.text


def _mk_perm(manage, code, name="QA v12a perm"):
    return int(manage.shell("from application.permissions import ensure_permission;"
                            f"p,_=ensure_permission({code!r}, {name!r}); print(p.pk)").splitlines()[-1])


def test_V12A_ADM_03_codename_cannot_be_changed(admin, manage):
    code = "qa12" + uuid.uuid4().hex[:6]
    pk = _mk_perm(manage, code)
    page = admin.get(f"/application/applicationpermission/{pk}/change/")
    assert page.status_code == 200 and 'name="codename"' not in page.text, "codename must be read-only"
    r = admin.post(f"/application/applicationpermission/{pk}/change/",
                   {"codename": "hijacked", "name": "Renamed by QA", "_save": "Save"}, page=page)
    assert r.status_code == 302, r.text[:800]
    got = manage.shell(f"from django.contrib.auth.models import Permission as P; p=P.objects.get(pk={pk});"
                       "print(p.codename + '|' + p.name)").splitlines()[-1]
    assert got == f"{code}|Renamed by QA"


def test_V12A_ADM_04_no_bulk_delete_of_permissions(admin, manage):
    pks = [_mk_perm(manage, "qa12" + uuid.uuid4().hex[:6]) for _ in range(2)]
    page = admin.get("/application/applicationpermission/")
    assert page.status_code == 200 and 'name="action"' not in page.text, "no action dropdown expected"
    r = admin.action("/application/applicationpermission/", "delete_selected", pks, post="yes")
    assert r.status_code in (200, 302, 400, 403)
    n = manage.shell("from django.contrib.auth.models import Permission as P;"
                     f"print(P.objects.filter(pk__in={pks!r}).count())").splitlines()[-1]
    assert n == "2", "bulk delete went through"


def test_V12A_ADM_05_single_delete_lists_affected_and_removes_grants(admin, manage, mk_user, sso):
    code = "qa12" + uuid.uuid4().hex[:6]
    pk = _mk_perm(manage, code)
    name, upk = mk_user("delperm")
    gname = _uniq("grp")
    manage.shell("from django.contrib.auth.models import User, Group, Permission as P;"
                 f"p=P.objects.get(pk={pk}); u=User.objects.get(pk={upk}); u.user_permissions.add(p);"
                 f"g=Group.objects.create(name={gname!r}); g.permissions.add(p)")
    a, _ = _session(sso, name)
    assert f"application.{code}" in sso.introspect(a, SVC).json()["perms"]
    page = admin.get(f"/application/applicationpermission/{pk}/delete/")
    assert page.status_code == 200 and name in page.text and gname in page.text, page.text[:1500]
    r = admin.post(f"/application/applicationpermission/{pk}/delete/", {"post": "yes"}, page=page)
    assert r.status_code == 302
    assert f"application.{code}" not in sso.introspect(a, SVC).json()["perms"]


def test_V12A_ADM_06_grant_and_revoke_app_access_actions(admin, manage, mk_user, sso):
    code = "qa12" + uuid.uuid4().hex[:6]
    ppk = _mk_perm(manage, code)
    name, upk = mk_user("grant")
    a, _ = _session(sso, name)
    perm = f"application.{code}"
    r = admin.action("/auth/user/", "grant_app_access", [upk])
    assert r.status_code == 200 and 'name="permission"' in r.text
    # non-application perms are not offered
    assert "auth.add_user" not in r.text and "Can add user" not in r.text
    r = admin.post("/auth/user/", {"action": "grant_app_access", "index": "0", "apply": "1",
                                   "_selected_action": str(upk), "permission": str(ppk)}, page=r)
    assert r.status_code == 302, r.text[:800]
    assert perm in sso.introspect(a, SVC).json()["perms"]            # at once for querying services
    assert perm not in claims(a).get("perms", [])                     # not in the existing access token
    page = admin.get("/auth/user/")
    r = admin.post("/auth/user/", {"action": "revoke_app_access", "index": "0", "apply": "1",
                                   "_selected_action": str(upk), "permission": str(ppk)}, page=page)
    assert r.status_code == 302
    assert perm not in sso.introspect(a, SVC).json()["perms"]
    # groups
    gname = _uniq("ggrp")
    gpk = int(manage.shell(f"from django.contrib.auth.models import Group, User; g=Group.objects.create(name={gname!r});"
                           f"User.objects.get(pk={upk}).groups.add(g); print(g.pk)").splitlines()[-1])
    page = admin.get("/auth/group/")
    r = admin.post("/auth/group/", {"action": "grant_app_access", "index": "0", "apply": "1",
                                    "_selected_action": str(gpk), "permission": str(ppk)}, page=page)
    assert r.status_code == 302
    assert perm in sso.introspect(a, SVC).json()["perms"]


def test_V12A_ADM_06b_grant_with_non_app_permission_id_rejected(admin, manage, mk_user):
    name, upk = mk_user("grantbad")
    other = int(manage.shell("from django.contrib.auth.models import Permission as P;"
                             "print(P.objects.get(codename='add_user').pk)").splitlines()[-1])
    page = admin.get("/auth/user/")
    r = admin.post("/auth/user/", {"action": "grant_app_access", "index": "0", "apply": "1",
                                   "_selected_action": str(upk), "permission": str(other)}, page=page)
    assert r.status_code == 200  # form re-rendered with an error
    assert manage.shell(f"from django.contrib.auth.models import User; print(User.objects.get(pk={upk})"
                        ".user_permissions.count())").splitlines()[-1] == "0"


def _svc_add(admin, data):
    page = admin.get("/sso/serviceclient/add/")
    assert page.status_code == 200
    base = {"client_id": "", "name": "QA", "is_active": "on", "app_codename": "", "notify_url": "",
            "allowed_origins": "[]", "redirect_uris": "[]", "_save": "Save"}
    return admin.post("/sso/serviceclient/add/", {**base, **data}, page=page)


@pytest.mark.parametrize("url,ok", [
    ("https://svc.example.test/sso/events", True),
    ("http://svc.example.test/sso/events", False),
    ("javascript:alert(1)", False),
    ("ftp://svc.example.test/x", False),
    ("svc.example.test/sso/events", None),      # missing scheme: recorded (Django 5 assume_scheme=https)
])
def test_V12A_ADM_07_service_client_admin_notify_url(admin, manage, url, ok):
    cid = "qa12-" + uuid.uuid4().hex[:8]
    r = _svc_add(admin, {"client_id": cid, "notify_url": url})
    stored = manage.shell(f"from sso.models import ServiceClient as S; c=S.objects.filter(client_id={cid!r}).first();"
                          "print(repr(c.notify_url) if c else 'NONE')").splitlines()[-1]
    if ok is True:
        assert r.status_code == 302 and stored == repr(url), (r.status_code, stored)
    elif ok is False:
        assert r.status_code == 200 and stored == "NONE", (r.status_code, stored)
    else:
        print(f"ADM-07 missing scheme -> status {r.status_code}, stored {stored}")
        assert stored in ("NONE", repr("https://" + url)), stored


def test_V12A_ADM_07b_service_client_admin_app_codename(admin, manage):
    cid = "qa12-" + uuid.uuid4().hex[:8]
    r = _svc_add(admin, {"client_id": cid, "app_codename": "qa12nosuchapp"})
    assert r.status_code == 200 and "does not exist" in html.unescape(r.text)
    r = _svc_add(admin, {"client_id": cid, "app_codename": "application.app1"})
    assert r.status_code == 302
    assert manage.shell(f"from sso.models import ServiceClient as S; print(S.objects.get(client_id={cid!r}).app_codename)"
                        ).splitlines()[-1] == "app1"
    r = _svc_add(admin, {"client_id": cid})
    assert r.status_code == 200, "duplicate client_id must be refused in the admin"


# =========================================================================== commands
def _secret(out: str) -> str:
    return re.search(r"^client_secret=(\S+)$", out, re.M).group(1)


def test_V12A_CMD_01_register_service_creates_perm_and_client(sso, manage):
    cid, app = "qa12-" + uuid.uuid4().hex[:8], "qa12" + uuid.uuid4().hex[:6]
    p = _manage_cmd("register_service", cid, "--name", "QA Reporting", "--app", app,
                    "--notify-url", "https://r.example.test/sso/events", "--origin", "https://r.example.test")
    assert p.returncode == 0, p.stderr
    assert re.search(rf"^client_id={cid}$", p.stdout, re.M) and re.search(rf"^permission=application\.{app}$", p.stdout, re.M)
    secret = _secret(p.stdout)
    assert "Created permission" in p.stderr and secret not in p.stderr
    row = manage.shell(f"from sso.models import ServiceClient as S; c=S.objects.get(client_id={cid!r});"
                       "print(c.app_codename, c.notify_url, c.allowed_origins, c.client_secret_hash.startswith('pbkdf2') or c.client_secret_hash[:6])"
                       ).splitlines()[-1]
    assert row.startswith(f"{app} https://r.example.test/sso/events ['https://r.example.test']")
    assert secret not in manage.shell(f"from sso.models import ServiceClient as S; print(S.objects.get(client_id={cid!r}).__dict__)")
    # the new client can introspect
    name = "qa_alice"
    a = sso.login_ok(name, testdata.USERS[name]["password"]).json()["access_token"]
    assert sso.introspect(a, (cid, secret)).json()["active"] is True


def test_V12A_CMD_02_duplicate_client_id_refused(manage):
    cid, app = "qa12-" + uuid.uuid4().hex[:8], "qa12" + uuid.uuid4().hex[:6]
    first = _manage_cmd("register_service", cid, "--app", app)
    assert first.returncode == 0
    h1 = manage.shell(f"from sso.models import ServiceClient as S; print(S.objects.get(client_id={cid!r}).client_secret_hash)")
    for argv in (("register_service", cid, "--app", app), ("register_service", cid, "--app", "qa12other"),
                 ("create_service_client", cid)):
        p = _manage_cmd(*argv)
        assert p.returncode != 0 and "exists" in p.stderr and "Traceback" not in p.stderr, (argv, p.stderr)
    assert manage.shell(f"from sso.models import ServiceClient as S; print(S.objects.get(client_id={cid!r}).client_secret_hash)") == h1
    assert manage.shell("from application.permissions import app_permissions;"
                        "print(app_permissions().filter(codename='qa12other').exists())").splitlines()[-1] == "False"


@pytest.mark.parametrize("url", ["http://r.example.test/x", "r.example.test/x", "javascript:alert(1)",
                                 "ftp://r.example.test/x", "https://"])
def test_V12A_CMD_03_register_service_notify_url_must_be_https(manage, url):
    cid, app = "qa12-" + uuid.uuid4().hex[:8], "qa12" + uuid.uuid4().hex[:6]
    p = _manage_cmd("register_service", cid, "--app", app, "--notify-url", url)
    assert p.returncode != 0 and "notify_url" in p.stderr and "Traceback" not in p.stderr, p.stderr
    out = manage.shell("from sso.models import ServiceClient as S; from application.permissions import app_permissions;"
                       f"print(S.objects.filter(client_id={cid!r}).exists(), app_permissions().filter(codename={app!r}).exists())")
    assert out.splitlines()[-1] == "False False", "nothing may be created on a refused registration"


def test_V12A_CMD_04_create_service_client_app(manage):
    cid = "qa12-" + uuid.uuid4().hex[:8]
    p = _manage_cmd("create_service_client", cid, "--app", "qa12nosuchapp")
    assert p.returncode != 0 and "does not exist" in p.stderr
    p = _manage_cmd("create_service_client", cid, "--app", "application.app1")
    assert p.returncode == 0, p.stderr
    assert manage.shell(f"from sso.models import ServiceClient as S; print(S.objects.get(client_id={cid!r}).app_codename)"
                        ).splitlines()[-1] == "app1"
    p = _manage_cmd("create_service_client", cid, "--rotate-secret", "--app", "app1")
    assert p.returncode == 0


def test_V12A_CMD_05_register_service_reuses_existing_perm_description(manage):
    app = "qa12" + uuid.uuid4().hex[:6]
    _mk_perm(manage, app, "Original description")
    p = _manage_cmd("register_service", "qa12-" + uuid.uuid4().hex[:8], "--app", f"application.{app}")
    assert p.returncode == 0 and "Using existing permission" in p.stderr
    assert manage.shell(f"from application.permissions import app_permissions; print(app_permissions().get(codename={app!r}).name)"
                        ).splitlines()[-1] == "Original description"
    p = _manage_cmd("register_service", "qa12-" + uuid.uuid4().hex[:8], "--app", app, "--app-name", "New text")
    assert p.returncode == 0
    assert manage.shell(f"from application.permissions import app_permissions; print(app_permissions().get(codename={app!r}).name)"
                        ).splitlines()[-1] == "New text"


@pytest.mark.parametrize("bad", ["App2", "app-2", "", "app 2", "../x"])
def test_V12A_CMD_06_register_service_bad_codename(manage, bad):
    p = _manage_cmd("register_service", "qa12-" + uuid.uuid4().hex[:8], "--app", bad)
    assert p.returncode != 0 and "Traceback" not in p.stderr, p.stderr


# =========================================================================== migration 0002
def _schema(db):
    con = sqlite3.connect(db)
    rows = con.execute("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
                       "ORDER BY type, name").fetchall()
    con.close()
    return {(t, n): (tbl, s) for t, n, tbl, s in rows}


def test_V12A_MIG_01_additive_reversible_no_shared_tables(tmp_path):
    run = os.path.join(os.environ["SSO_REPO_DIR"], "qa", "run")
    db = os.path.join(run, f"mig-{uuid.uuid4().hex[:6]}.sqlite3")
    env = {**os.environ, "SSO_SQLITE_PATH": db}
    def m(*a):
        p = subprocess.run(shlex.split(os.environ["SSO_MANAGE_CMD"]) + list(a), env=env, capture_output=True,
                           text=True, timeout=300)
        assert p.returncode == 0, (a, p.stdout[-800:], p.stderr[-1500:])
        return p.stdout
    try:
        m("migrate", "--noinput")
        m("migrate", "sso", "0001", "--noinput")
        s1 = _schema(db)
        m("migrate", "sso", "0002", "--noinput")
        s2 = _schema(db)
        m("migrate", "sso", "0001", "--noinput")
        s1b = _schema(db)
        m("migrate", "--noinput")
        s2b = _schema(db)
        assert s1 == s1b, "backward migration must restore the 0001 schema exactly"
        assert s2 == s2b
        changed = {k for k in set(s1) | set(s2) if s1.get(k) != s2.get(k)}
        tables = {s2.get(k, s1.get(k))[0] for k in changed}
        assert tables and all(t.startswith("sso_") for t in tables), tables
        assert tables <= {"sso_serviceclient", "sso_revokedsession"}, tables
        for shared in ("auth_user", "auth_group", "auth_permission", "auth_user_groups", "auth_user_user_permissions",
                       "django_content_type", "django_session"):
            assert s1.get(("table", shared)) == s2.get(("table", shared)), shared
        new_cols = s2[("table", "sso_serviceclient")][1]
        assert re.search(r'"app_codename" varchar\(63\) NULL', new_cols) and re.search(r'"notify_url" varchar\(500\) NULL', new_cols)
        sql = m("sqlmigrate", "sso", "0002")
        touched = set(re.findall(r'(?:TABLE|INTO|INDEX)\s+"?(\w+)"?', sql))
        assert all(t.startswith(("sso_", "new__sso_")) or t.endswith(("_sid_key", "_user_id")) or "sso_" in t
                   for t in touched), touched
        # rollback-safety: an old-style INSERT without the new columns works on the migrated schema
        con = sqlite3.connect(db)
        con.execute("INSERT INTO sso_serviceclient (client_id, name, client_secret_hash, redirect_uris, allowed_origins,"
                    " is_active, created) VALUES ('old', 'old', 'x', '[]', '[]', 1, '2026-01-01')")
        con.commit(); con.close()
    finally:
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(db + suffix)
            except FileNotFoundError:
                pass


def test_V12A_MIG_02_no_pending_migrations(manage):
    p = _manage_cmd("makemigrations", "--check", "--dry-run")
    assert p.returncode == 0, p.stdout + p.stderr


def test_V12A_REUSE_07_parallel_http_refresh_same_token_keeps_session(sso, mk_user):
    """Black-box variant of the developer's skipped MySQL thread test: 4 clients refresh the same token at once over
    HTTP. Exactly one gets a new pair, the others 401 without tokens, and the session survives (grace path).
    Against a 1-worker gunicorn on SQLite the requests are serialised by the server, so this is NOT the
    real-concurrency DB race (that stays BLOCKED on MySQL/Docker)."""
    from concurrent.futures import ThreadPoolExecutor
    name, pk = mk_user("par")
    a, rf = _session(sso, name)
    with ThreadPoolExecutor(4) as ex:
        res = list(ex.map(lambda _: sso.refresh_native(rf, retry_on_429=True), range(4)))
    ok = [r for r in res if r.status_code == 200]
    assert len(ok) == 1 and sorted(r.status_code for r in res) == [200, 401, 401, 401], [r.status_code for r in res]
    win = ok[0].json()
    _alive(sso, win["access_token"])
    assert sso.refresh_native(win["refresh_token"]).status_code == 200
