"""Flask adapter.

    sso = SSO(app)                       # SSOClient from SSO_* env (or SSO(app, client=...))

    @app.get("/report")
    @sso.require_permission("application.app2")
    def report(): return {"user": g.sso.user.username}

The peer is ``request.environ["REMOTE_ADDR"]``; do not wrap the app in Werkzeug ``ProxyFix`` (or configure it
for exactly the same proxies).
"""
from __future__ import annotations

import functools

from flask import g, jsonify, request

from ..client import SSOClient, bearer_token
from ..config import SSOConfig
from ..errors import NotAuthenticated, SSOError
from ..ip import get_client_ip
from ..responses import error_response


class SSO:
    def __init__(self, app=None, *, client: SSOClient | None = None):
        self.client = client
        if app is not None:
            self.init_app(app)

    def init_app(self, app) -> None:
        if self.client is None:
            self.client = SSOClient(SSOConfig.from_env())
        app.extensions["sso_client"] = self
        app.before_request(self._set_ip)
        app.register_error_handler(SSOError, self._error)

    def _set_ip(self):
        g.client_ip = get_client_ip(request.environ.get("REMOTE_ADDR"), request.headers,
                                    self.client.config.trusted_proxies)

    @staticmethod
    def _error(exc: SSOError):
        status, body, headers = error_response(exc)
        resp = jsonify(body)
        resp.status_code = status
        resp.headers.update(headers)
        return resp

    def check(self, require=()):
        token = bearer_token(request.headers.get("Authorization"))
        if token is None:
            raise NotAuthenticated("no bearer token")
        if "client_ip" not in g:
            self._set_ip()
        return self.client.check(token, g.client_ip, require)

    def require_permission(self, *perms: str):
        def deco(view):
            @functools.wraps(view)
            def wrapper(*args, **kwargs):
                g.sso = self.check(perms)
                return view(*args, **kwargs)

            return wrapper

        return deco
