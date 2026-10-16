"""v1.3d admin web UI views (DESIGN-v1.3d-admin-ui.md §5-§10).

Server-rendered Django templates. Every change goes through ``sso.admin_ops`` (same rules as the REST API); the
middleware has already enforced the session guard and the admin check. Post/Redirect/Get on success; form errors
re-render with 200; guard violations render the error page with 409; throttles 429.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import time
import uuid
from functools import wraps
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import Group, User
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import transaction
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import render as dj_render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme, urlencode
from django.views.decorators.http import require_http_methods, require_POST

from application.models import Application
from application.permfile import PermFileError, parse as parse_permfile
from application.permissions import PREFIX
from sso import admin_ops as ops
from sso import audit, stepup
from sso.errors import (AdminForbidden, Conflict, InvalidCredentials, InvalidRequest, NotFound, ReauthRequired,
                        SSOError)
from sso.logs import client_ip
from sso.models import AdminAuditLog, ServiceClient
from sso.serializers import check_credentials

from .middleware import (SESSION_IP, SESSION_LOGIN_AT, SESSION_SEEN, SESSION_SID, SESSION_UID, end_session,
                         ui_prefix)

PAGE_SIZE = 50
LOGIN_FAILED = "Invalid username or password, or no admin access."
NOTES = {
    "expired": "Your admin session timed out. Please sign in again.",
    "ip": "Your network address changed; please sign in again.",
    "revoked": "Your sessions were ended (log out everywhere, suspend or password change). Please sign in again.",
    "lost": "Your admin access ended.",
    "out": "You are signed out.",
}


# --------------------------------------------------------------------------- helpers
def u(path: str = "") -> str:
    return ui_prefix() + path


def safe_next(request, value, default=None) -> str:
    default = default or u()
    if not value or not isinstance(value, str) or not value.startswith(ui_prefix()) or "\\" in value:
        return default
    if not url_has_allowed_host_and_scheme(value, allowed_hosts={request.get_host()}, require_https=False):
        return default
    return value


def render(request, template, ctx=None, status=200):
    ctx = dict(ctx or {})
    ctx.setdefault("ui", ui_prefix())
    if getattr(request.user, "is_authenticated", False):
        ctx.setdefault("elevated_until", stepup.session_expiry(request))
    ctx.setdefault("tz", settings.SSO_ADMIN_UI_TIME_ZONE)
    return dj_render(request, "adminui/" + template, ctx, status=status)


def error_page(request, exc: SSOError, back=None):
    status = getattr(exc, "status_code", 400)
    return render(request, "error.html", {"status": status, "code": getattr(exc, "error_code", "error"),
                                          "detail": str(exc.detail), "back": back}, status=status)


def _referer_path(request) -> str:
    ref = request.headers.get("Referer", "")
    if not ref or not url_has_allowed_host_and_scheme(ref, allowed_hosts={request.get_host()}, require_https=False):
        return u()
    parts = urlsplit(ref)
    return parts.path + ("?" + parts.query if parts.query else "")


def ui_view(fn):
    """SSO errors -> pages: reauth_required -> the step-up page; 404; 400/403/409 -> error page."""
    @wraps(fn)
    def wrapper(request, *args, **kwargs):
        try:
            return fn(request, *args, **kwargs)
        except ReauthRequired:
            # after a POST, come back to the page the form was on (the POST-only URL would answer 405 to a GET)
            nxt = request.get_full_path() if request.method == "GET" else (request.POST.get("back")
                                                                            or _referer_path(request))
            return HttpResponseRedirect(u("reauth/") + "?" + urlencode({"next": safe_next(request, nxt)}))
        except NotFound:
            raise Http404() from None
        except SSOError as exc:
            return error_page(request, exc, back=safe_next(request, request.POST.get("back") or request.path))
    return wrapper


def page(request, qs):
    p = Paginator(qs, PAGE_SIZE)
    try:
        return p.get_page(int(request.GET.get("page", 1)))
    except ValueError:
        return p.get_page(1)


def qstring(request, **drop) -> str:
    q = {k: v for k, v in request.GET.items() if k != "page" and v}
    return urlencode(q)


def require_elevation(request):
    if stepup.session_expiry(request) is None:
        raise ReauthRequired()


def _rate(name: str) -> tuple[int, int]:
    num, per = name.split("/")
    return int(num), {"s": 1, "m": 60, "h": 3600, "d": 86400}[per[0]]


def throttled(key: str, rate: str) -> bool:
    """Fixed-window counter in the shared cache (Redis). True = over the limit."""
    limit, window = _rate(rate)
    bucket = f"adminui:{key}:{int(time.time() // window)}"
    if cache.add(bucket, 1, window + 1):
        count = 1
    else:
        try:
            count = cache.incr(bucket)
        except ValueError:  # the key expired between add() and incr()
            cache.add(bucket, 1, window + 1)
            count = 1
    return count > limit


def csv_response(filename, header, rows):
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    w = csv.writer(resp)
    w.writerow(header)
    for row in rows:
        w.writerow([_csv_cell(v) for v in row])
    return resp


def _csv_cell(v):
    s = "" if v is None else (json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else str(v))
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _back(request, default):
    return safe_next(request, request.POST.get("back"), default)


# --------------------------------------------------------------------------- session
@require_http_methods(["GET", "POST"])
def login_view(request):
    note = NOTES.get(request.GET.get("m", ""))
    nxt = safe_next(request, request.GET.get("next") or request.POST.get("next"))
    if request.method == "GET":
        return render(request, "login.html", {"note": note, "next": nxt})
    username = (request.POST.get("username") or "").strip()[:254]
    password = request.POST.get("password") or ""
    ip = client_ip(request) or ""
    if (throttled("login_ip:" + ip, settings.SSO_THROTTLE_ADMIN_UI_LOGIN_IP)
            or throttled("login_user:" + username.lower(), settings.SSO_THROTTLE_ADMIN_UI_LOGIN_USER)):
        audit.record_denied(request, "ui.login", "user", username, reason="throttled")
        return render(request, "login.html", {"error": "Too many attempts. Wait a minute and try again.",
                                              "next": nxt, "username": username}, status=429)
    user = check_credentials(request, username, password) if username and password and len(password) <= 4096 \
        else None
    reason = None
    if user is None:
        reason = "invalid_credentials"
    elif not ops.is_sso_admin(user):
        reason = ("inactive" if not user.is_active else "not_staff" if not user.is_staff
                  else "no_sso_admin")
    if reason:
        audit.record_denied(request, "ui.login", "user", user.pk if user else username, reason=reason)
        return render(request, "login.html", {"error": LOGIN_FAILED, "next": nxt, "username": username})
    auth_login(request, user)  # backend set by authenticate(); cycles the session key
    now = time.time()
    s = request.session
    s[SESSION_UID] = user.pk
    s[SESSION_SID] = uuid.uuid4().hex
    s[SESSION_IP] = ip
    s[SESSION_LOGIN_AT] = now
    s[SESSION_SEEN] = now
    s.set_expiry(settings.SSO_ADMIN_UI_MAX_AGE_SECONDS)  # server-side row lifetime; cookie stays session-only
    with transaction.atomic():
        audit.record(request, "ui.login", "user", user.pk)
    return HttpResponseRedirect(nxt)


@require_POST
def logout_view(request):
    with transaction.atomic():
        audit.record(request, "ui.logout", "user", request.user.pk)
    end_session(request)
    return HttpResponseRedirect(u("login/?m=out"))


@require_POST
@ui_view
def logout_everywhere(request):
    ops.logout_all_user(request, request.user.pk)  # bumps the revocation epoch: tokens and every UI session
    end_session(request)
    return HttpResponseRedirect(u("login/?m=out"))


@require_http_methods(["GET", "POST"])
def reauth_view(request):
    nxt = safe_next(request, request.GET.get("next") or request.POST.get("next"))
    if request.method == "GET":
        return render(request, "reauth.html", {"next": nxt})
    rate = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]["admin_reauth"]
    if throttled(f"reauth:{request.user.pk}", rate):
        return render(request, "reauth.html", {"next": nxt, "error": "Too many attempts. Wait a minute."},
                      status=429)
    password = request.POST.get("password") or ""
    ok = check_credentials(request, request.user.get_username(), password) if 0 < len(password) <= 4096 else None
    if ok is None or ok.pk != request.user.pk:
        audit.record_denied(request, "reauth", "user", request.user.pk, reason="invalid_credentials")
        return render(request, "reauth.html", {"next": nxt, "error": "Password is incorrect."})
    with transaction.atomic():
        stepup.issue_for_session(request)
        audit.record(request, "reauth", "user", request.user.pk)
    request.session.cycle_key()
    return HttpResponseRedirect(nxt)


@require_POST
def reauth_drop(request):
    with transaction.atomic():
        stepup.drop_session(request)
        audit.record(request, "reauth.drop", "user", request.user.pk)
    return HttpResponseRedirect(_back(request, u()))


def csrf_failure(request, reason=""):
    resp = dj_render(request, "adminui/error.html", {
        "ui": ui_prefix(), "status": 403, "code": "csrf",
        "detail": "The form expired or was sent from another site. Reload the page and try again."}, status=403)
    return resp


# --------------------------------------------------------------------------- dashboard, me
def dashboard(request):
    from sso.models import WebhookDelivery

    since = timezone.now() - timezone.timedelta(hours=24)
    keyset = settings.SSO_KEYSET
    ctx = {
        "users_active": User.objects.filter(is_active=True).count(),
        "users_suspended": User.objects.filter(is_active=False).count(),
        "admins": ops.admins_qs().count(),
        "services": ServiceClient.objects.filter(kind="service").count(),
        "devices": ServiceClient.objects.filter(kind="device").count(),
        "failed_24h": WebhookDelivery.objects.filter(status="failed", event__created__gte=since).count(),
        "audit": AdminAuditLog.objects.all()[:20],
        "signing_kid": keyset.signing_kid,
        "published_kids": [pk.kid for pk in keyset.public_keys],
    }
    return render(request, "dashboard.html", ctx)


def me(request):
    return render(request, "me.html", {"login_at": request.adminui_login_at})


# --------------------------------------------------------------------------- users
def _users_filtered(request):
    g = request.GET
    return ops.users_qs(g.get("q"), ops.bool_param(g.get("active")), g.get("group"), ops.bool_param(g.get("staff")))


@ui_view
def users(request):
    return render(request, "users.html", {"page": page(request, _users_filtered(request)), "qs": qstring(request),
                                          "groups": Group.objects.order_by("name"), "f": request.GET})


@ui_view
def users_export(request):
    rows = ((x.pk, x.username, x.email, x.first_name, x.last_name, x.is_active, x.is_staff,
             ";".join(sorted(g.name for g in x.groups.all())), ops.iso(x.last_login))
            for x in _users_filtered(request).prefetch_related("groups"))
    with transaction.atomic():
        audit.record(request, "ui.export", "user", "", after={"what": "users", "filters": dict(request.GET.items())})
    return csv_response("users.csv", ["id", "username", "email", "first_name", "last_name", "is_active",
                                      "is_staff", "groups", "last_login"], rows)


@require_http_methods(["GET", "POST"])
@ui_view
def user_new(request):
    groups = Group.objects.order_by("name")
    if request.method == "GET":
        return render(request, "user_new.html", {"groups": groups, "f": {}})
    p = request.POST
    data = {"username": p.get("username", ""), "email": p.get("email", ""), "first_name": p.get("first_name", ""),
            "last_name": p.get("last_name", ""), "groups": p.getlist("groups"), "is_active": True,
            "is_staff": p.get("is_staff") == "on"}
    if p.get("password"):
        if p.get("password") != p.get("password2"):
            return render(request, "user_new.html", {"groups": groups, "f": p, "error": "Passwords differ."})
        data["password"] = p["password"]
    try:
        user = ops.create_user(request, data)
    except (InvalidRequest, Conflict, AdminForbidden) as exc:
        return render(request, "user_new.html", {"groups": groups, "f": p, "error": str(exc.detail)})
    messages.success(request, f"User {user.username} created.")
    return HttpResponseRedirect(u(f"users/{user.pk}/"))


def _user_ctx(user):
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

    sessions = (OutstandingToken.objects.filter(user=user, expires_at__gt=timezone.now())
                .filter(blacklistedtoken__isnull=True).count())
    from application.permissions import app_permissions

    return {"u": user, "perms": ops.user_permissions(user.pk), "all_groups": Group.objects.order_by("name"),
            "user_groups": set(user.groups.values_list("name", flat=True)),
            "all_perms": app_permissions().order_by("codename"), "sessions": sessions,
            "devices": ServiceClient.objects.filter(kind="device", owner=user).order_by("client_id"),
            "audit": AdminAuditLog.objects.filter(target_type="user", target_id=str(user.pk))[:20],
            "is_admin": ops.is_sso_admin(user)}


@require_http_methods(["GET", "POST"])
@ui_view
def user_detail(request, pk):
    user = ops.get_user(pk)
    if request.method == "POST":
        p = request.POST
        try:
            ops.update_user(request, pk, {"email": p.get("email", ""), "first_name": p.get("first_name", ""),
                                          "last_name": p.get("last_name", "")})
        except InvalidRequest as exc:
            return render(request, "user_detail.html", {**_user_ctx(user), "error": str(exc.detail)})
        messages.success(request, "Profile saved.")
        return HttpResponseRedirect(u(f"users/{pk}/"))
    return render(request, "user_detail.html", _user_ctx(user))


def _confirm(request, *, title, effect, action_url, button, target_name=None, back, extra=None, danger=True):
    return render(request, "confirm.html", {"title": title, "effect": effect, "action_url": action_url,
                                            "button": button, "target_name": target_name, "back": back,
                                            "extra": extra or [], "danger": danger})


@require_http_methods(["GET", "POST"])
@ui_view
def user_suspend(request, pk):
    user = ops.get_user(pk)
    if request.method == "GET":
        require_elevation(request)
        ctx = _user_ctx(user)
        return _confirm(request, title=f"Suspend {user.username}", button="Suspend and log out all sessions",
                        effect=[f"{ctx['sessions']} active session(s) end now.",
                                f"{ctx['devices'].count()} device client(s) are revoked.",
                                "Services are notified (webhook user.suspended)."],
                        action_url=u(f"users/{pk}/suspend"), back=u(f"users/{pk}/"))
    ops.suspend_user(request, pk)
    messages.success(request, f"{user.username} suspended; all sessions ended.")
    return HttpResponseRedirect(u(f"users/{pk}/"))


@require_POST
@ui_view
def user_unsuspend(request, pk):
    user = ops.unsuspend_user(request, pk)
    messages.success(request, f"{user.username} unsuspended (old sessions stay ended).")
    return HttpResponseRedirect(u(f"users/{pk}/"))


@require_POST
@ui_view
def user_logout_all(request, pk):
    ops.logout_all_user(request, pk)
    if int(pk) == request.user.pk:
        end_session(request)
        return HttpResponseRedirect(u("login/?m=revoked"))
    messages.success(request, "All sessions of this user ended.")
    return HttpResponseRedirect(u(f"users/{pk}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def user_password(request, pk):
    user = ops.get_user(pk)
    if request.method == "GET":
        require_elevation(request)
        return render(request, "password.html", {"u": user})
    p = request.POST
    if p.get("password") != p.get("password2"):
        return render(request, "password.html", {"u": user, "error": "Passwords differ."})
    try:
        ops.set_user_password(request, pk, p.get("password") or "")
    except InvalidRequest as exc:
        return render(request, "password.html", {"u": user, "error": str(exc.detail)})
    if int(pk) == request.user.pk:
        end_session(request)
        return HttpResponseRedirect(u("login/?m=revoked"))
    messages.success(request, "Password set; all sessions of this user ended.")
    return HttpResponseRedirect(u(f"users/{pk}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def user_delete(request, pk):
    user = ops.get_user(pk)
    if request.method == "GET":
        require_elevation(request)
        return _confirm(request, title=f"Delete {user.username}", button="Delete user permanently",
                        effect=["Prefer Suspend: deleting cannot be undone.", "All tokens are revoked.",
                                "Audit rows and trade history are kept."],
                        target_name=user.username, action_url=u(f"users/{pk}/delete"), back=u(f"users/{pk}/"))
    if request.POST.get("confirm") != user.username:
        raise InvalidRequest("Type the username exactly to confirm.")
    ops.delete_user(request, pk)
    messages.success(request, f"User {user.username} deleted.")
    return HttpResponseRedirect(u("users/"))


@require_POST
@ui_view
def user_permissions(request, pk):
    op = request.POST.get("op")
    if op not in ("grant", "revoke"):
        raise InvalidRequest("op must be grant or revoke.")
    ops.change_user_permission(request, pk, request.POST.get("codename", ""), op == "grant")
    messages.success(request, f"Permission {op}ed.")
    return HttpResponseRedirect(u(f"users/{pk}/"))


@require_POST
@ui_view
def user_groups(request, pk):
    ops.set_user_groups(request, pk, request.POST.getlist("groups"))
    messages.success(request, "Groups saved.")
    return HttpResponseRedirect(u(f"users/{pk}/"))


# --------------------------------------------------------------------------- groups
@ui_view
def groups(request):
    return render(request, "groups.html", {"page": page(request, ops.groups_qs(request.GET.get("q"))),
                                           "qs": qstring(request), "f": request.GET})


@require_POST
@ui_view
def group_new(request):
    g = ops.create_group(request, request.POST.get("name", ""))
    messages.success(request, f"Group {g.name} created.")
    return HttpResponseRedirect(u(f"groups/{g.pk}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def group_detail(request, pk):
    g = ops.get_group(pk)
    if request.method == "POST":
        ops.rename_group(request, pk, request.POST.get("name", ""))
        messages.success(request, "Group renamed.")
        return HttpResponseRedirect(u(f"groups/{pk}/"))
    from application.permissions import app_permissions

    return render(request, "group_detail.html", {
        "g": g, "members": g.user_set.order_by("username"), "perms": ops.ser_group(g)["perms"],
        "all_perms": app_permissions().order_by("codename"), "is_admin_group": g.pk in ops.admin_group_ids()})


@require_POST
@ui_view
def group_members(request, pk):
    names = [n.strip() for n in (request.POST.get("usernames") or "").replace("\n", ",").split(",") if n.strip()]
    found = dict(User.objects.filter(username__in=names).values_list("username", "pk"))
    unknown = sorted(set(names) - set(found))
    if unknown:
        raise InvalidRequest("Unknown username(s): " + ", ".join(unknown[:10]))
    ops.set_group_members(request, pk, sorted(set(found.values())))
    messages.success(request, "Members saved.")
    return HttpResponseRedirect(u(f"groups/{pk}/"))


@require_POST
@ui_view
def group_permissions(request, pk):
    op = request.POST.get("op")
    if op not in ("grant", "revoke"):
        raise InvalidRequest("op must be grant or revoke.")
    ops.change_group_permission(request, pk, request.POST.get("codename", ""), op == "grant")
    messages.success(request, f"Permission {op}ed.")
    return HttpResponseRedirect(u(f"groups/{pk}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def group_delete(request, pk):
    g = ops.get_group(pk)
    if request.method == "GET":
        require_elevation(request)
        return _confirm(request, title=f"Delete group {g.name}", button="Delete group",
                        effect=[f"{g.user_set.count()} member(s) lose the group's permissions."],
                        target_name=g.name, action_url=u(f"groups/{pk}/delete"), back=u(f"groups/{pk}/"))
    if request.POST.get("confirm") != g.name:
        raise InvalidRequest("Type the group name exactly to confirm.")
    ops.delete_group(request, pk)
    messages.success(request, f"Group {g.name} deleted.")
    return HttpResponseRedirect(u("groups/"))


# --------------------------------------------------------------------------- permissions
@ui_view
def permissions(request):
    rows = [ops.ser_permission(p, r) for p, r in
            ops.permissions_list(request.GET.get("app"), ops.bool_param(request.GET.get("deprecated")))]
    return render(request, "permissions.html", {"page": page(request, rows), "qs": qstring(request),
                                                "f": request.GET, "apps": Application.objects.all()})


@require_POST
@ui_view
def permission_new(request):
    p = request.POST
    perm = ops.create_permission(request, {"codename": p.get("codename", ""), "name": p.get("name", ""),
                                           "description": p.get("description", "")})
    messages.success(request, f"{PREFIX}{perm.codename} created.")
    return HttpResponseRedirect(u(f"permissions/{perm.codename}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def permission_detail(request, codename):
    perm = ops.get_permission(codename)
    if request.method == "POST":
        ops.update_permission(request, codename, {"name": request.POST.get("name", ""),
                                                  "description": request.POST.get("description", "")})
        messages.success(request, "Permission saved.")
        return HttpResponseRedirect(u(f"permissions/{perm.codename}/"))
    return render(request, "permission_detail.html", {"p": ops.ser_permission(perm)})


@require_http_methods(["GET", "POST"])
@ui_view
def permission_delete(request, codename):
    perm = ops.get_permission(codename)
    if request.method == "GET":
        require_elevation(request)
        s = ops.ser_permission(perm)
        return _confirm(request, title=f"Delete {s['perm']}", button="Delete permission",
                        effect=[f"Granted to {s['users']} user(s) and {s['groups']} group(s).",
                                "Tick 'revoke from everyone' if it is still granted."],
                        action_url=u(f"permissions/{perm.codename}/delete"),
                        back=u(f"permissions/{perm.codename}/"), extra=["revoke_all"])
    ops.delete_permission_op(request, codename, request.POST.get("revoke_all") == "on")
    messages.success(request, f"{PREFIX}{perm.codename} deleted.")
    return HttpResponseRedirect(u("permissions/"))


# --------------------------------------------------------------------------- applications + import
@ui_view
def apps(request):
    return render(request, "apps.html", {"apps": [ops.ser_app(a) for a in Application.objects.all()]})


@ui_view
def app_detail(request, app):
    return render(request, "app_detail.html", {"a": ops.ser_app(ops.get_app(app), with_perms=True)})


def _digest(payload_json: str, force: bool) -> str:
    key = hashlib.sha256(("adminui-import" + settings.SECRET_KEY).encode()).digest()
    return hmac.new(key, (payload_json + ("|force" if force else "")).encode(), "sha256").hexdigest()


@require_http_methods(["GET", "POST"])
@ui_view
def app_import(request):
    if request.method == "GET":
        return render(request, "import.html", {})
    upload = request.FILES.get("file")
    text = request.POST.get("json", "").strip()
    force = request.POST.get("force") == "on"
    try:
        if upload is not None:
            if upload.size > 64 * 1024:
                raise PermFileError("file is larger than 64 KiB")
            raw = upload.read(64 * 1024 + 1).decode("utf-8")
            payload = json.loads(raw) if upload.name.endswith(".json") else parse_permfile(raw)
        elif text:
            if len(text) > 64 * 1024:
                raise PermFileError("JSON is larger than 64 KiB")
            payload = json.loads(text)
        else:
            raise PermFileError("upload sso_permissions.py or paste the JSON payload")
    except (PermFileError, ValueError, UnicodeDecodeError) as exc:
        return render(request, "import.html", {"error": str(exc)[:300], "json": text})
    app = payload.get("app_codename") if isinstance(payload, dict) else None
    if not isinstance(app, str) or not app:
        return render(request, "import.html", {"error": "The payload has no app_codename.", "json": text})
    try:
        result = ops.import_app(request, app, payload, dry_run=True, force=force)
    except (InvalidRequest, Conflict) as exc:
        return render(request, "import.html", {"error": str(exc.detail), "json": text})
    pj = json.dumps(payload, sort_keys=True)
    return render(request, "import_preview.html", {"app": app, "r": result.as_dict(), "payload": pj,
                                                   "digest": _digest(pj, force), "force": force})


@require_POST
@ui_view
def app_import_apply(request):
    pj = request.POST.get("payload", "")
    force = request.POST.get("force") == "1"
    if not hmac.compare_digest(_digest(pj, force), request.POST.get("digest", "")):
        return render(request, "import.html", {"error": "The previewed payload changed; preview it again.",
                                               "json": pj[:65536]})
    payload = json.loads(pj)
    result = ops.import_app(request, payload["app_codename"], payload, dry_run=False, force=force)
    r = result.as_dict()
    messages.success(request, f"Imported {payload['app_codename']}: {len(r['created'])} created, "
                              f"{len(r['updated'])} updated, {len(r['deprecated'])} deprecated.")
    return HttpResponseRedirect(u(f"apps/{payload['app_codename']}/"))


# --------------------------------------------------------------------------- services
@ui_view
def services(request):
    return render(request, "services.html", {"page": page(request, ops.services_qs("service")),
                                             "qs": qstring(request)})


def _service_form_data(request, *, create: bool) -> dict:
    p = request.POST
    data = {"name": p.get("name", ""), "app_codename": p.get("app_codename") or None,
            "notify_url": p.get("notify_url") or None, "perms": p.getlist("perms")}
    if create:
        data["client_id"] = p.get("client_id", "")
    else:
        from sso.webhooks import EVENT_TYPES

        data["is_active"] = p.get("is_active") == "on"
        data["can_delegate"] = p.get("can_delegate") == "on"
        data["can_register_devices"] = p.get("can_register_devices") == "on"
        data["notify_events"] = [e for e in p.getlist("notify_events") if e in EVENT_TYPES]
    return data


def _secret_page(request, title, label, client_id, secret, back):
    resp = render(request, "secret.html", {"title": title, "label": label, "client_id": client_id,
                                           "secret": secret, "back": back})
    resp["Cache-Control"] = "no-store"
    return resp


@require_http_methods(["GET", "POST"])
@ui_view
def service_new(request):
    from application.permissions import app_permissions

    all_perms = app_permissions().order_by("codename")
    if request.method == "GET":
        return render(request, "service_new.html", {"all_perms": all_perms, "f": {}})
    try:
        client, secret = ops.create_service(request, _service_form_data(request, create=True))
    except (InvalidRequest, Conflict) as exc:
        return render(request, "service_new.html", {"all_perms": all_perms, "f": request.POST,
                                                    "error": str(exc.detail)})
    return _secret_page(request, f"Service {client.client_id} registered", "client_secret", client.client_id,
                        secret, u(f"services/{client.client_id}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def service_detail(request, client_id):
    from application.permissions import app_permissions
    from sso.webhooks import EVENT_TYPES

    client = ops.get_service(client_id)
    if client.kind != "service":
        return HttpResponseRedirect(u(f"devices/{client_id}/"))
    if request.method == "POST":
        ops.update_service(request, client_id, _service_form_data(request, create=False))
        messages.success(request, "Service saved.")
        return HttpResponseRedirect(u(f"services/{client_id}/"))
    return render(request, "service_detail.html", {
        "c": ops.ser_service(client), "all_perms": app_permissions().order_by("codename"),
        "event_types": EVENT_TYPES,
        "deliveries": ops.deliveries_qs(client_id=client_id).order_by("-pk")[:20]})


@require_http_methods(["GET", "POST"])
@ui_view
def service_rotate(request, client_id):
    ops.get_service(client_id)
    if request.method == "GET":
        require_elevation(request)
        return _confirm(request, title=f"Rotate secret of {client_id}", button="Rotate client secret",
                        effect=["The old secret stops working immediately.", "The new secret is shown once."],
                        action_url=u(f"services/{client_id}/rotate-secret"), back=u(f"services/{client_id}/"))
    secret = ops.rotate_service_secret(request, client_id)
    return _secret_page(request, f"New secret for {client_id}", "client_secret", client_id, secret,
                        u(f"services/{client_id}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def service_rotate_notify(request, client_id):
    ops.get_service(client_id)
    if request.method == "GET":
        require_elevation(request)
        return _confirm(request, title=f"Rotate webhook secret of {client_id}", button="Rotate notify secret",
                        effect=["Webhooks are signed with the new secret from now on.",
                                "The new secret is shown once."],
                        action_url=u(f"services/{client_id}/rotate-notify-secret"),
                        back=u(f"services/{client_id}/"))
    secret = ops.rotate_notify_secret(request, client_id)
    return _secret_page(request, f"New webhook secret for {client_id}", "notify_secret", client_id, secret,
                        u(f"services/{client_id}/"))


@require_http_methods(["GET", "POST"])
@ui_view
def service_delete(request, client_id):
    ops.get_service(client_id)
    if request.method == "GET":
        require_elevation(request)
        return _confirm(request, title=f"Delete service {client_id}", button="Delete service client",
                        effect=["Its credentials stop working immediately."], target_name=client_id,
                        action_url=u(f"services/{client_id}/delete"), back=u(f"services/{client_id}/"))
    if request.POST.get("confirm") != client_id:
        raise InvalidRequest("Type the client_id exactly to confirm.")
    ops.delete_service(request, client_id)
    messages.success(request, f"Service {client_id} deleted.")
    return HttpResponseRedirect(u("services/"))


# --------------------------------------------------------------------------- devices
@ui_view
def devices(request):
    qs = ops.devices_qs(request.GET.get("owner")).select_related("owner")
    return render(request, "devices.html", {"page": page(request, qs), "qs": qstring(request), "f": request.GET})


@ui_view
def device_detail(request, client_id):
    from sso.devices import ser_device

    dev = ops.get_device(client_id)
    return render(request, "device_detail.html", {"d": ser_device(dev), "owner": dev.owner})


@require_http_methods(["GET", "POST"])
@ui_view
def device_revoke(request, client_id):
    dev = ops.get_device(client_id)
    if request.method == "GET":
        require_elevation(request)
        return _confirm(request, title=f"Revoke device {client_id}", button="Revoke device",
                        effect=["The PC can no longer connect; the owner must pair again."],
                        action_url=u(f"devices/{client_id}/revoke"), back=u(f"devices/{client_id}/"))
    owner = dev.owner_id
    ops.delete_device(request, client_id)
    messages.success(request, f"Device {client_id} revoked.")
    return HttpResponseRedirect(u(f"users/{owner}/") if owner else u("devices/"))


# --------------------------------------------------------------------------- webhooks
@ui_view
def webhooks(request):
    qs = ops.events_qs(request.GET.get("type") or None).order_by("-pk")
    from sso.webhooks import EVENT_TYPES

    return render(request, "webhooks.html", {"page": page(request, qs), "qs": qstring(request),
                                             "f": request.GET, "event_types": EVENT_TYPES})


@ui_view
def deliveries(request):
    from sso.models import WebhookDelivery

    g = request.GET
    qs = ops.deliveries_qs(g.get("status") or None, g.get("client_id") or None, g.get("event") or None)
    return render(request, "deliveries.html", {"page": page(request, qs.order_by("-pk")), "qs": qstring(request),
                                               "f": g, "statuses": WebhookDelivery.STATUSES})


@require_POST
@ui_view
def redeliver(request, pk):
    ops.redeliver(request, pk)
    messages.success(request, f"Delivery {pk} queued again.")
    return HttpResponseRedirect(_back(request, u("webhooks/deliveries/")))


# --------------------------------------------------------------------------- audit
def _audit_filtered(request):
    g = request.GET
    return ops.audit_qs(actor=g.get("actor"), action=g.get("action"), target_type=g.get("target_type"),
                        target_id=g.get("target_id"), since=g.get("since") or None, channel=g.get("channel"),
                        result=g.get("result"))


@ui_view
def audit_list(request):
    return render(request, "audit.html", {"page": page(request, _audit_filtered(request)), "qs": qstring(request),
                                          "f": request.GET, "channels": ops.AUDIT_CHANNELS})


@ui_view
def audit_detail(request, pk):
    row = AdminAuditLog.objects.filter(pk=pk).first()
    if row is None:
        raise Http404()
    pretty = {k: json.dumps(getattr(row, k), indent=2, sort_keys=True) if getattr(row, k) is not None else ""
              for k in ("before", "after")}
    return render(request, "audit_detail.html", {"a": row, "pretty": pretty})


@ui_view
def audit_export(request):
    qs = _audit_filtered(request)[:50000]
    rows = ((a.pk, ops.iso(a.ts), a.actor_type, a.actor_id, a.actor_ip, a.action, a.target_type, a.target_id,
             a.result, a.stepup, a.channel, a.request_id, a.before, a.after) for a in qs)
    with transaction.atomic():
        audit.record(request, "ui.export", "audit", "", after={"what": "audit", "filters": dict(request.GET.items())})
    return csv_response("audit.csv", ["id", "ts", "actor_type", "actor_id", "actor_ip", "action", "target_type",
                                      "target_id", "result", "stepup", "channel", "request_id", "before", "after"],
                        rows)


# --------------------------------------------------------------------------- error handlers
def _html_error(request, status, code, detail):
    return dj_render(request, "adminui/error.html", {"ui": ui_prefix(), "status": status, "code": code,
                                                     "detail": detail}, status=status)


def handler404(request, exception=None):
    from sso import errors

    if request.path_info.startswith(ui_prefix()) and settings.SSO_ADMIN_UI_ENABLED:
        return _html_error(request, 404, "not_found", "This page does not exist.")
    return errors.handler404(request, exception)


def handler403(request, exception=None):
    from sso import errors

    if request.path_info.startswith(ui_prefix()) and settings.SSO_ADMIN_UI_ENABLED:
        return _html_error(request, 403, "forbidden", "Forbidden.")
    return errors.handler403(request, exception)


def handler500(request):
    from sso import errors

    if request.path_info.startswith(ui_prefix()) and settings.SSO_ADMIN_UI_ENABLED:
        return HttpResponse("<!doctype html><title>Server error</title><h1>Server error</h1>", status=500)
    return errors.handler500(request)
