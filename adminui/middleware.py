"""v1.3d admin UI middleware (DESIGN-v1.3d-admin-ui.md §5, §8.1, §12).

``SessionMiddleware``: Django's, except that under ``/<SSO_ADMIN_UI_PATH>`` the session lives in its own cookie
(``__Host-sso_admin_sid``: HttpOnly, Secure, SameSite=Strict, Path=/, no Domain, browser-session lifetime). Django
admin keeps ``sessionid``; the two logins are independent and neither cookie is read on the other's paths.

``AdminUIGuardMiddleware`` runs after authentication, for UI paths only: optional admin-host check, audit channel
``ui``, display time zone, the session guard (absolute + idle timeout, IP binding, token/session revocation, admin
access re-checked in the DB on every request) and the security headers.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.contrib.sessions.middleware import SessionMiddleware as DjangoSessionMiddleware
from django.http import Http404, HttpResponseRedirect
from django.utils import timezone
from django.utils.cache import patch_vary_headers
from django.utils.http import urlencode

from sso import audit, stepup
from sso.admin_ops import is_sso_admin
from sso.logs import client_ip

logger = logging.getLogger("sso.admin")

PUBLIC = ("login/",)
SESSION_UID = "adminui_uid"
SESSION_SID = "adminui_sid"
SESSION_IP = "adminui_ip"
SESSION_LOGIN_AT = "adminui_login_at"
SESSION_SEEN = "adminui_seen"

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
                                "base-uri 'none'"),
    "Cache-Control": "no-store",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}


def ui_prefix() -> str:
    return "/" + settings.SSO_ADMIN_UI_PATH


def is_ui_path(request) -> bool:
    return bool(settings.SSO_ADMIN_UI_ENABLED) and request.path_info.startswith(ui_prefix())


class SessionMiddleware(DjangoSessionMiddleware):
    def process_request(self, request):
        if not is_ui_path(request):
            return super().process_request(request)
        request.session = self.SessionStore(request.COOKIES.get(settings.SSO_ADMIN_UI_COOKIE))

    def process_response(self, request, response):
        if not is_ui_path(request):
            return super().process_response(request, response)
        name = settings.SSO_ADMIN_UI_COOKIE
        try:
            accessed, modified, empty = (request.session.accessed, request.session.modified,
                                         request.session.is_empty())
        except AttributeError:
            return response
        if name in request.COOKIES and empty:
            response.delete_cookie(name, path="/", samesite="Strict")
            patch_vary_headers(response, ("Cookie",))
            return response
        if accessed:
            patch_vary_headers(response, ("Cookie",))
        if modified and not empty and response.status_code < 500:
            try:
                request.session.save()
            except UpdateError:
                raise SessionInterrupted("The admin session was deleted before the request completed.") from None
            response.set_cookie(name, request.session.session_key, max_age=None, path="/",
                                secure=settings.SESSION_COOKIE_SECURE or None, httponly=True, samesite="Strict")
        return response


def _host_ok(request) -> bool:
    want = settings.SSO_ADMIN_UI_HOSTNAME
    if not want:
        return True
    return request.get_host().rsplit(":", 1)[0].lower() == want


def end_session(request, action: str | None = None, reason: str = "") -> None:
    """Flush the UI session (and its step-up proof); audit why, when it is security-relevant."""
    if action and getattr(request.user, "pk", None):
        audit.record_denied(request, action, "user", request.user.pk, reason=reason)
    stepup.drop_session(request)
    auth_logout(request)  # flushes the session, cycles the key, request.user = AnonymousUser


def _login_redirect(request, note: str = "") -> HttpResponseRedirect:
    q = {"next": request.get_full_path()} if request.method == "GET" else {}
    if note:
        q["m"] = note
    return HttpResponseRedirect(ui_prefix() + "login/" + ("?" + urlencode(q) if q else ""))


def _revoked_since(user, login_at: float) -> bool:
    from sso.models import UserTokenRevocation

    row = UserTokenRevocation.objects.filter(user_id=user.pk).values_list("revoked_at", flat=True).first()
    return bool(row and row.timestamp() > login_at)


class AdminUIGuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not is_ui_path(request):
            return self.get_response(request)
        if not _host_ok(request):
            raise Http404()
        setattr(request, audit.CHANNEL_ATTR, "ui")
        timezone.activate(settings.SSO_ADMIN_UI_TIME_ZONE)
        try:
            early = self._guard(request)
            response = early if early is not None else self.get_response(request)
        finally:
            timezone.deactivate()
        for k, v in SECURITY_HEADERS.items():
            response[k] = v
        return response

    def _guard(self, request):
        sub = request.path_info[len(ui_prefix()):]
        user = request.user
        s = request.session
        authed = getattr(user, "is_authenticated", False) and s.get(SESSION_UID) == user.pk
        if not authed:
            if getattr(user, "is_authenticated", False):  # a Django login without our markers: not a UI session
                auth_logout(request)
            return None if sub in PUBLIC else _login_redirect(request)
        now = time.time()
        login_at = float(s.get(SESSION_LOGIN_AT, 0))
        ip = client_ip(request) or ""
        if now - login_at > settings.SSO_ADMIN_UI_MAX_AGE_SECONDS or now - float(s.get(SESSION_SEEN, 0)) \
                > settings.SSO_ADMIN_UI_IDLE_SECONDS:
            logger.info('{"event": "admin_ui_session_expired", "user_id": %d}', user.pk)
            end_session(request)
            return _login_redirect(request, "expired")
        if s.get(SESSION_IP) != ip:
            mode = settings.SSO_ADMIN_UI_IP_BINDING
            if mode == "ENFORCE":
                end_session(request, "ui.session_ip_mismatch", reason=f"login ip {s.get(SESSION_IP)}")
                return _login_redirect(request, "ip")
            if mode == "WARNING":
                logger.warning('{"event": "admin_ui_ip_mismatch", "user_id": %d, "mode": "WARNING"}', user.pk)
        if _revoked_since(user, login_at):
            end_session(request, "ui.session_revoked", reason="tokens and sessions revoked")
            return _login_redirect(request, "revoked")
        if not is_sso_admin(user):
            end_session(request, "ui.access_lost", reason="no longer active staff sso_admin")
            return _login_redirect(request, "lost")
        if now - float(s.get(SESSION_SEEN, 0)) > 30:  # keep idle tracking cheap (one write per 30 s)
            s[SESSION_SEEN] = now
        setattr(request, stepup.UI_ATTR, s.get(SESSION_SID))
        request.adminui_login_at = datetime.fromtimestamp(login_at, tz=timezone.get_current_timezone())
        if sub in PUBLIC:
            return HttpResponseRedirect(ui_prefix())
        return None
