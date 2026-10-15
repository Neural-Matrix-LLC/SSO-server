"""LIB-ADP: Django / FastAPI / Flask adapters, in-process apps against the live ENFORCE SSO (trusts 127.0.0.1).
Each app: /open (any active token), /app1 (require application.app1), /app2 (require application.app2)."""
from __future__ import annotations

from fastapi import Request  # module level: string annotations must resolve

import asyncio

import httpx
import pytest

from conftest import SVC, login
from sso_client import SSOClient, SSOConfig, AsyncSSOClient

USER_IP = "203.0.113.90"
CLOSED = "http://127.0.0.1:8068"


def cfg(base, trusted="", header=""):
    return SSOConfig(base_url=base, client_id=SVC[0], client_secret=SVC[1], allow_http=True, trusted_proxies=trusted,
                     retries=0, client_ip_header=header)


# ---------------------------------------------------------------- Django
def django_app(base, trusted="", header=""):
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(DEBUG=False, ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__ + "_urls", SECRET_KEY="qa",
                           MIDDLEWARE=["sso_client.adapters.django.SSOMiddleware"], INSTALLED_APPS=[])
        django.setup()
    import sys, types
    from django.http import JsonResponse
    from django.urls import path
    from sso_client.adapters import django as dj

    @dj.require_permission()
    def open_(request):
        return JsonResponse({"user": request.sso.user.username, "ip": request.client_ip})

    @dj.require_permission("application.app1")
    def app1(request):
        return JsonResponse({"user": request.sso.user.username})

    @dj.require_permission("application.app2")
    def app2(request):
        return JsonResponse({})

    def lazy(request):  # request.sso lazily evaluated (no decorator)
        return JsonResponse({"active": request.sso.active})

    mod = types.ModuleType(__name__ + "_urls")
    mod.urlpatterns = [path("open", open_), path("app1", app1), path("app2", app2), path("lazy", lazy)]
    sys.modules[mod.__name__] = mod
    from django.urls import clear_url_caches
    clear_url_caches()
    dj.set_client(SSOClient(cfg(base, trusted, header)))
    from django.test import Client

    def call(p, tok=None, peer=USER_IP, xff=None, hdr=None):
        extra = {"REMOTE_ADDR": peer}
        if hdr:
            extra["HTTP_CF_CONNECTING_IP"] = hdr
        if tok:
            extra["HTTP_AUTHORIZATION"] = f"Bearer {tok}"
        if xff:
            extra["HTTP_X_FORWARDED_FOR"] = xff
        r = Client(raise_request_exception=False).get("/" + p, **extra)
        return r.status_code, (r.json() if r.get("Content-Type", "").startswith("application/json") else {}), r
    return call


# ---------------------------------------------------------------- FastAPI
def fastapi_app(base, trusted="", header=""):
    from fastapi import Depends, FastAPI
    from sso_client.adapters.fastapi import SSO
    app = FastAPI()
    sso = SSO(AsyncSSOClient(cfg(base, trusted, header)))
    sso.install(app)

    @app.get("/open")
    async def open_(request: Request, u=Depends(sso.user)):
        return {"user": u.user.username, "ip": request.state.client_ip}

    @app.get("/app1")
    async def app1(u=Depends(sso.require_permission("application.app1"))):
        return {"user": u.user.username}

    @app.get("/app2")
    async def app2(u=Depends(sso.require_permission("application.app2"))):
        return {}

    def call(p, tok=None, peer=USER_IP, xff=None, hdr=None):
        h = {"CF-Connecting-IP": hdr} if hdr else {}
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        if xff:
            h["X-Forwarded-For"] = xff

        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 40000)),
                                         base_url="http://t") as c:
                return await c.get("/" + p, headers=h)
        r = asyncio.run(go())
        return r.status_code, r.json(), r
    return call


# ---------------------------------------------------------------- Flask
def flask_app(base, trusted="", header=""):
    from flask import Flask, g
    from sso_client.adapters.flask import SSO
    app = Flask("qa")
    sso = SSO(app, client=SSOClient(cfg(base, trusted, header)))

    @app.get("/open")
    @sso.require_permission()
    def open_():
        return {"user": g.sso.user.username, "ip": g.client_ip}

    @app.get("/app1")
    @sso.require_permission("application.app1")
    def app1():
        return {"user": g.sso.user.username}

    @app.get("/app2")
    @sso.require_permission("application.app2")
    def app2():
        return {}

    def call(p, tok=None, peer=USER_IP, xff=None, hdr=None):
        h = {"CF-Connecting-IP": hdr} if hdr else {}
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        if xff:
            h["X-Forwarded-For"] = xff
        r = app.test_client().get("/" + p, headers=h, environ_base={"REMOTE_ADDR": peer})
        return r.status_code, r.get_json(silent=True) or {}, r
    return call


APPS = {"django": django_app, "fastapi": fastapi_app, "flask": flask_app}


@pytest.fixture(params=list(APPS))
def make(request):
    return APPS[request.param]


def _hdr(r, name):
    return r.headers.get(name) if hasattr(r, "headers") else r[name]


def test_V12B_LIB_ADP_01_require_permission_matrix(make, sso_enf, mk_user):
    call = make(sso_enf)
    name = mk_user("adp", perms=["app1"])
    tok = login(sso_enf, name, xff=USER_IP)["access_token"]
    st, body, r = call("open")
    assert st == 401 and body == {"detail": "not_authenticated"} and _hdr(r, "WWW-Authenticate") == "Bearer"
    st, body, _ = call("open", tok)
    assert st == 200 and body["user"] == name and body["ip"] == USER_IP
    assert call("app1", tok)[0] == 200
    st, body, _ = call("app2", tok)
    assert st == 403 and body == {"detail": "permission_denied", "missing": ["application.app2"]}
    st, body, r = call("open", "garbage")
    assert st == 401 and body["detail"] == "token_inactive"


def test_V12B_LIB_ADP_02_ip_mismatch_401_and_session_dead(make, sso_enf, mk_user):
    call = make(sso_enf)
    tok = login(sso_enf, mk_user("adpip", perms=["app1"]), xff=USER_IP)["access_token"]
    st, body, _ = call("app1", tok, peer="198.51.100.90")
    assert st == 401 and body["detail"] == "token_inactive"
    call2 = make(sso_enf)           # new client (no cache): the legitimate IP is revoked too
    assert call2("app1", tok)[0] == 401


def test_V12B_LIB_ADP_03_trusted_proxy_xff_and_spoof(make, sso_enf, mk_user):
    call = make(sso_enf, trusted="10.0.0.0/8")
    tok = login(sso_enf, mk_user("adpx"), xff=USER_IP)["access_token"]
    st, body, _ = call("open", tok, peer="10.0.0.5", xff=f"198.51.100.1, {USER_IP}")
    assert st == 200 and body["ip"] == USER_IP
    tok2 = login(sso_enf, mk_user("adps"), xff=USER_IP)["access_token"]
    st, body, _ = call("open", tok2, peer="198.51.100.91", xff=USER_IP)    # untrusted peer spoofs XFF
    assert st == 401


def test_V12B_LIB_ADP_04_sso_down_503(make, mk_user, sso_enf):
    call = make(CLOSED)
    st, body, r = call("open", "sometoken")
    assert st == 503 and body == {"detail": "sso_unavailable"} and _hdr(r, "Retry-After") == "5"


def test_V12B_LIB_ADP_05_django_lazy_request_sso(sso_enf, mk_user):
    call = django_app(sso_enf)
    tok = login(sso_enf, mk_user("lazy"), xff=USER_IP)["access_token"]
    st, body, _ = call("lazy", tok)
    assert st == 200 and body == {"active": True}
    st, _, r = call("lazy")       # V12B-02 fix (b3dbd2a): no token -> JSON 401, not 500
    assert st == 401, st
    down = django_app(CLOSED)     # SSO unreachable through the lazy object -> JSON 503 + Retry-After
    st, body, r = down("lazy", tok)
    assert st == 503 and body == {"detail": "sso_unavailable"} and _hdr(r, "Retry-After") == "5", (st, body)


def test_V12B_LIB_ADP_06_custom_header_through_adapters(make, sso_enf, mk_user):
    import inspect
    sig = inspect.signature(make)
    call = make(sso_enf, trusted="10.0.0.0/8", **({"header": "cf-connecting-ip"} if "header" in sig.parameters else {}))
    tok = login(sso_enf, mk_user("adph"), xff=USER_IP)["access_token"]
    st, body, _ = call("open", tok, peer="10.0.0.5", xff="198.51.100.1", hdr=USER_IP)
    assert st == 200 and body["ip"] == USER_IP, body
    tok2 = login(sso_enf, mk_user("adph2"), xff=USER_IP)["access_token"]
    st, body, _ = call("open", tok2, peer="198.51.100.93", hdr=USER_IP)       # untrusted peer: header ignored
    assert st == 401
