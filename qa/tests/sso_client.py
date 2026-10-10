"""Thin black-box HTTP client for the SSO server (requests based).

Cookies are handled by hand (parsed from raw Set-Cookie headers and sent back as an
explicit Cookie header) so the `Secure` flag does not stop the cookie being replayed
when the test server is plain http, and so tests can inspect every cookie attribute.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from http.cookies import SimpleCookie

import requests

LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
LOGOUT = "/api/v1/auth/logout"
LOGOUT_ALL = "/api/v1/auth/logout-all"
ME = "/api/v1/auth/me"
INTROSPECT = "/api/v1/auth/introspect"
JWKS = "/.well-known/jwks.json"
DISCOVERY = "/.well-known/openid-configuration"
HEALTHZ = "/healthz"

COOKIE_NAME = "sso_refresh"


@dataclass
class ParsedCookie:
    name: str
    value: str
    attrs: dict          # lower-cased attribute name -> value ("" for flags absent)
    raw: str

    @property
    def httponly(self) -> bool:
        return "httponly" in self.raw.lower()

    @property
    def secure(self) -> bool:
        return any(p.strip().lower() == "secure" for p in self.raw.split(";"))


def set_cookies(resp: requests.Response) -> list[ParsedCookie]:
    raw_headers = resp.raw.headers.getlist("Set-Cookie") if resp.raw is not None else []
    out = []
    for raw in raw_headers:
        c = SimpleCookie()
        c.load(raw)
        for name, morsel in c.items():
            attrs = {k: morsel[k] for k in morsel.keys() if morsel[k] not in ("", None)}
            out.append(ParsedCookie(name, morsel.value, attrs, raw))
    return out


def refresh_cookie(resp: requests.Response) -> ParsedCookie | None:
    for c in set_cookies(resp):
        if c.name == COOKIE_NAME:
            return c
    return None


class SSOClient:
    def __init__(self, base_url: str, verify, timeout: float = 15.0, max_throttle_wait: float = 240.0):
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.max_throttle_wait = max_throttle_wait

    def url(self, path: str) -> str:
        return self.base_url + path

    def request(self, method, path, *, json=None, data=None, headers=None, cookie=None,
                origin=None, bearer=None, auth=None, retry_on_429=False, allow_redirects=False):
        h = dict(headers or {})
        if cookie is not None:
            h["Cookie"] = f"{COOKIE_NAME}={cookie}"
        if origin is not None:
            h["Origin"] = origin
        if bearer is not None:
            h["Authorization"] = f"Bearer {bearer}"
        waited = 0.0
        while True:
            r = requests.request(method, self.url(path), json=json, data=data, headers=h, auth=auth,
                                 verify=self.verify, timeout=self.timeout, allow_redirects=allow_redirects)
            if r.status_code != 429 or not retry_on_429 or waited >= self.max_throttle_wait:
                return r
            delay = float(r.headers.get("Retry-After", "10") or 10) + 1
            time.sleep(delay)
            waited += delay

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    # ---- API helpers -------------------------------------------------------------
    def login(self, username, password, client="native", origin=None, retry_on_429=True, omit_client=False):
        body = {"username": username, "password": password}
        if not omit_client:
            body["client"] = client
        return self.post(LOGIN, json=body, origin=origin, retry_on_429=retry_on_429)

    def login_ok(self, username, password, client="native", origin=None) -> requests.Response:
        r = self.login(username, password, client=client, origin=origin)
        assert r.status_code == 200, f"login {username} failed: {r.status_code} {r.text[:300]}"
        return r

    def refresh_native(self, refresh_token, retry_on_429=True, origin=None):
        return self.post(REFRESH, json={"refresh_token": refresh_token}, origin=origin, retry_on_429=retry_on_429)

    def refresh_cookie(self, cookie_value, origin=None, retry_on_429=True):
        return self.post(REFRESH, json={}, cookie=cookie_value, origin=origin, retry_on_429=retry_on_429)

    def logout_native(self, refresh_token, origin=None):
        return self.post(LOGOUT, json={"refresh_token": refresh_token}, origin=origin)

    def logout_cookie(self, cookie_value, origin=None):
        return self.post(LOGOUT, json={}, cookie=cookie_value, origin=origin)

    def logout_all(self, access_token):
        return self.post(LOGOUT_ALL, json={}, bearer=access_token)

    def me(self, access_token):
        return self.get(ME, bearer=access_token)

    def introspect(self, token, auth):
        return self.post(INTROSPECT, json={"token": token}, auth=auth)
