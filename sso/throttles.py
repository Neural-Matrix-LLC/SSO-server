"""Login / refresh throttles (spec §6.1, addendum B.3).

DRF has no per-username throttle, so ``LoginUserThrottle`` keys the cache on the lowercased
username/email from the JSON body. Uses Django's cache: LocMem by default (per process); set
``SSO_CACHE_URL`` to Redis or a DB cache when running more than one gunicorn worker.
"""
from __future__ import annotations

from rest_framework.throttling import SimpleRateThrottle

from .logs import client_ip, log_login


class _LoggingThrottle(SimpleRateThrottle):
    def throttle_failure(self) -> bool:
        if getattr(self, "log_failures", False) and getattr(self, "_request", None) is not None:
            log_login(self._request, _body_username(self._request), "rate_limited")
        return False

    def allow_request(self, request, view) -> bool:
        self._request = request
        return super().allow_request(request, view)


def _body_username(request) -> str:
    data = request.data  # ParseError / UnsupportedMediaType propagate -> uniform 400 / 415
    if not isinstance(data, dict):
        return ""
    value = data.get("username")
    return value.strip().lower() if isinstance(value, str) else ""


class LoginIPThrottle(_LoggingThrottle):
    """10/min per client IP (scope ``login``)."""

    scope = "login"
    log_failures = True

    def get_cache_key(self, request, view):
        # the end user's IP when a ServiceClient delegates it (v1.1 item 4), else the caller's
        return self.cache_format % {"scope": self.scope, "ident": client_ip(request)}


class LoginUserThrottle(_LoggingThrottle):
    """5/min per lowercased username or email (scope ``login_user``), from any IP."""

    scope = "login_user"
    log_failures = True

    def get_cache_key(self, request, view):
        username = _body_username(request)
        if not username:
            return None  # nothing to key on; the serializer will reject the request
        return self.cache_format % {"scope": self.scope, "ident": username[:254]}


class RefreshThrottle(_LoggingThrottle):
    """60/min per client IP for /refresh and /logout (scope ``refresh``)."""

    scope = "refresh"

    def get_cache_key(self, request, view):
        # the end user's IP when a ServiceClient delegates it (v1.1 item 4), else the caller's
        return self.cache_format % {"scope": self.scope, "ident": client_ip(request)}
