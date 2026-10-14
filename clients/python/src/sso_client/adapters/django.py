"""Django adapter.

    MIDDLEWARE = [..., "sso_client.adapters.django.SSOMiddleware"]
    SSO_CLIENT = {"BASE_URL": "https://sso.example.com", "CLIENT_ID": "...", "CLIENT_SECRET": "...",
                  "TRUSTED_PROXIES": ["172.18.0.0/16"]}          # or the SSO_* environment variables

``request.client_ip`` (socket peer REMOTE_ADDR + trusted-proxy walk), lazy ``request.sso`` (CheckResult; raises
SSOError subclasses), and ``@require_permission("application.app2")`` answering 401 / 403 / 503 as JSON.
Do not combine with middleware that rewrites REMOTE_ADDR from headers.
"""
from __future__ import annotations

import functools

from django.http import JsonResponse
from django.utils.functional import SimpleLazyObject

from ..client import SSOClient, bearer_token
from ..config import SSOConfig
from ..errors import NotAuthenticated, SSOError
from ..ip import get_client_ip
from ..responses import error_response

_client: SSOClient | None = None


def get_client() -> SSOClient:
    global _client
    if _client is None:
        from django.conf import settings

        conf = getattr(settings, "SSO_CLIENT", None)
        if conf:
            kw = {k.lower(): v for k, v in conf.items()}
            cfg = SSOConfig.from_env(**kw) if not {"base_url", "client_id", "client_secret"} <= kw.keys() \
                else SSOConfig(**kw)
        else:
            cfg = SSOConfig.from_env()
        _client = SSOClient(cfg)
    return _client


def set_client(client: SSOClient | None) -> None:
    """Use a specific client (tests: ``FakeSSO().client()``)."""
    global _client
    _client = client


def request_client_ip(request, trusted=None, client_ip_header=None) -> str | None:
    cfg = get_client().config
    trusted = cfg.trusted_proxies if trusted is None else trusted
    header = cfg.client_ip_header if client_ip_header is None else client_ip_header
    return get_client_ip(request.META.get("REMOTE_ADDR"), request.headers, trusted, header)


def check_request(request, require=()):
    token = bearer_token(request.META.get("HTTP_AUTHORIZATION"))
    if token is None:
        raise NotAuthenticated("no bearer token")
    return get_client().check(token, getattr(request, "client_ip", None) or request_client_ip(request), require)


class SSOMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.client_ip = request_client_ip(request)
        # evaluated (one SSO call) on first attribute access; raises SSOError subclasses
        request.sso = SimpleLazyObject(lambda: check_request(request))
        return self.get_response(request)


def _json_error(exc: SSOError) -> JsonResponse:
    status, body, headers = error_response(exc)
    resp = JsonResponse(body, status=status)
    for k, v in headers.items():
        resp[k] = v
    return resp


def require_permission(*perms: str):
    """View decorator: valid token for this client IP and every permission in ``perms``; sets ``request.sso``."""

    def deco(view):
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            try:
                result = check_request(request, perms)
            except SSOError as exc:
                return _json_error(exc)
            request.sso = result
            return view(request, *args, **kwargs)

        return wrapper

    return deco
