import json

import pytest

from sso_client.testing import FakeSSO, asgi_scope, wsgi_environ

A, B = "203.0.113.7", "198.51.100.9"


# --------------------------------------------------------------------------- Django
@pytest.fixture(scope="module")
def django_setup():
    django = pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=False, ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__, SECRET_KEY="x",
                           MIDDLEWARE=[], INSTALLED_APPS=[])
        django.setup()
    return settings


def test_django_adapter(django_setup):
    from django.http import JsonResponse
    from django.test import RequestFactory

    from sso_client.adapters import django as adapter

    fake = FakeSSO("ENFORCE")
    adapter.set_client(fake.client(trusted_proxies="127.0.0.1"))
    try:
        tok = fake.issue("alice", perms=["application.app2"], ip=A)

        @adapter.require_permission("application.app2")
        def view(request):
            return JsonResponse({"user": request.sso.user.username, "ip": request.client_ip})

        mw = adapter.SSOMiddleware(view)
        rf = RequestFactory()
        r = mw(rf.get("/", REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR=A, HTTP_AUTHORIZATION=f"Bearer {tok}"))
        assert r.status_code == 200 and json.loads(r.content) == {"user": "alice", "ip": A}

        r = view(rf.get("/", REMOTE_ADDR=B))  # no token
        assert r.status_code == 401 and r["WWW-Authenticate"] == "Bearer"
        other = fake.issue("bob", perms=[], ip=A)
        assert view(rf.get("/", REMOTE_ADDR=A, HTTP_AUTHORIZATION=f"Bearer {other}")).status_code == 403
        # spoofed XFF from an untrusted peer: B is used -> ENFORCE mismatch -> 401
        r = view(rf.get("/", REMOTE_ADDR=B, HTTP_X_FORWARDED_FOR=A, HTTP_AUTHORIZATION=f"Bearer {tok}"))
        assert r.status_code == 401 and json.loads(r.content)["detail"] == "token_inactive"
        fake.down()
        r = view(rf.get("/", REMOTE_ADDR=A, HTTP_AUTHORIZATION=f"Bearer {fake.issue(ip=A)}"))
        assert r.status_code == 503 and r["Retry-After"] == "5"
        fake.up()

        # lazy request.sso via middleware only
        seen = {}

        def plain(request):
            seen["user"] = request.sso.user.username
            return JsonResponse({})

        t2 = fake.issue("carol", ip=A)
        adapter.SSOMiddleware(plain)(rf.get("/", REMOTE_ADDR=A, HTTP_AUTHORIZATION=f"Bearer {t2}"))
        assert seen["user"] == "carol"
    finally:
        adapter.set_client(None)


def test_django_get_client_from_settings(django_setup, monkeypatch):
    from sso_client.adapters import django as adapter

    adapter.set_client(None)
    monkeypatch.setattr(django_setup, "SSO_CLIENT", {"BASE_URL": "https://sso.x", "CLIENT_ID": "a",
                                                     "CLIENT_SECRET": "b", "TRUSTED_PROXIES": ["10.0.0.0/8"]},
                        raising=False)
    try:
        c = adapter.get_client()
        assert c.config.base_url == "https://sso.x" and str(c.config.trusted_proxies[0]) == "10.0.0.0/8"
        assert adapter.get_client() is c
        adapter.set_client(None)
        monkeypatch.setattr(django_setup, "SSO_CLIENT", {"TRUSTED_PROXIES": "10.0.0.0/8"})
        monkeypatch.setenv("SSO_BASE_URL", "https://sso.env")
        monkeypatch.setenv("SSO_CLIENT_ID", "e")
        monkeypatch.setenv("SSO_CLIENT_SECRET", "s")
        assert adapter.get_client().config.base_url == "https://sso.env"
        adapter.set_client(None)
        monkeypatch.setattr(django_setup, "SSO_CLIENT", None)
        assert adapter.get_client().config.client_id == "e"
    finally:
        adapter.set_client(None)


# --------------------------------------------------------------------------- FastAPI
def test_fastapi_adapter():
    fastapi = pytest.importorskip("fastapi")
    from fastapi import Depends
    from fastapi.testclient import TestClient

    from sso_client import CheckResult
    from sso_client.adapters.fastapi import SSO

    fake = FakeSSO("ENFORCE")
    sso = SSO(fake.async_client(trusted_proxies="testclient,127.0.0.1".split(",")[1:]))
    app = fastapi.FastAPI()
    sso.install(app)

    @app.get("/pages")
    async def pages(u: CheckResult = Depends(sso.require_permission("application.app1"))):
        return {"user": u.user.username, "ip": u.client_ip}

    @app.get("/me")
    async def me(u: CheckResult = Depends(sso.user), ip: str = Depends(sso.client_ip)):
        return {"user": u.user.username, "ip": ip}

    tok = fake.issue("alice", perms=["application.app1"], ip=A)
    c = TestClient(app, client=("127.0.0.1", 5000))
    r = c.get("/pages", headers={"Authorization": f"Bearer {tok}", "X-Forwarded-For": A})
    assert r.status_code == 200 and r.json() == {"user": "alice", "ip": A}
    assert c.get("/me", headers={"Authorization": f"Bearer {tok}", "X-Forwarded-For": A}).json()["ip"] == A
    assert c.get("/pages").status_code == 401
    bob = fake.issue("bob", ip=A)
    r = c.get("/pages", headers={"Authorization": f"Bearer {bob}", "X-Forwarded-For": A})
    assert r.status_code == 403 and r.json()["missing"] == ["application.app1"]
    fake.down()
    r = c.get("/pages", headers={"Authorization": f"Bearer {fake.issue(ip=A)}", "X-Forwarded-For": A})
    assert r.status_code == 503 and r.headers["Retry-After"] == "5"
    fake.up()
    untrusted = TestClient(app, client=(B, 5000))
    r = untrusted.get("/pages", headers={"Authorization": f"Bearer {tok}", "X-Forwarded-For": A})
    assert r.status_code == 401  # spoof ignored -> B -> ENFORCE mismatch


def test_fastapi_from_env(monkeypatch):
    pytest.importorskip("fastapi")
    from sso_client.adapters.fastapi import SSO

    monkeypatch.setenv("SSO_BASE_URL", "https://sso.env")
    monkeypatch.setenv("SSO_CLIENT_ID", "e")
    monkeypatch.setenv("SSO_CLIENT_SECRET", "s")
    assert SSO.from_env(timeout=3.0).client.config.timeout == 3.0


# --------------------------------------------------------------------------- Flask
def test_flask_adapter(monkeypatch):
    flask = pytest.importorskip("flask")
    from flask import g

    from sso_client.adapters.flask import SSO

    fake = FakeSSO("ENFORCE")
    app = flask.Flask(__name__)
    sso = SSO(app, client=fake.client(trusted_proxies="127.0.0.1"))

    @app.get("/report")
    @sso.require_permission("application.app2")
    def report():
        return {"user": g.sso.user.username, "ip": g.client_ip}

    tok = fake.issue("alice", perms=["application.app2"], ip=A)
    c = app.test_client()
    r = c.get("/report", headers={"Authorization": f"Bearer {tok}", "X-Forwarded-For": A},
              environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert r.status_code == 200 and r.get_json() == {"user": "alice", "ip": A}
    assert c.get("/report").status_code == 401
    r = c.get("/report", headers={"Authorization": f"Bearer {fake.issue(ip=A)}"}, environ_base={"REMOTE_ADDR": A})
    assert r.status_code == 403
    fake.down()
    r = c.get("/report", headers={"Authorization": f"Bearer {fake.issue(ip=A)}"}, environ_base={"REMOTE_ADDR": A})
    assert r.status_code == 503  # (a cached active answer for tok would still be served)
    fake.up()
    with app.test_request_context("/", headers={"Authorization": f"Bearer {tok}"}, environ_base={"REMOTE_ADDR": A}):
        assert sso.check(["application.app2"]).active  # without before_request having run

    monkeypatch.setenv("SSO_BASE_URL", "https://sso.env")
    monkeypatch.setenv("SSO_CLIENT_ID", "e")
    monkeypatch.setenv("SSO_CLIENT_SECRET", "s")
    lazy = SSO()
    lazy.init_app(flask.Flask("x"))
    assert lazy.client.config.client_id == "e"


def test_helpers():
    env = wsgi_environ("127.0.0.1", xff=A, token="t")
    assert env["HTTP_X_FORWARDED_FOR"] == A and env["HTTP_AUTHORIZATION"] == "Bearer t"
    from sso_client import get_client_ip
    scope = asgi_scope("127.0.0.1", xff=A, token="t")
    assert get_client_ip(scope["client"], scope["headers"], "127.0.0.1") == A


def test_adapters_honour_client_ip_header(django_setup):
    from django.test import RequestFactory
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    import flask

    from sso_client.adapters import django as dj
    from sso_client.adapters.fastapi import SSO as FastSSO
    from sso_client.adapters.flask import SSO as FlaskSSO

    fake = FakeSSO()
    kw = dict(trusted_proxies="127.0.0.1", client_ip_header="cf-connecting-ip")
    dj.set_client(fake.client(**kw))
    try:
        rf = RequestFactory()
        assert dj.request_client_ip(rf.get("/", REMOTE_ADDR="127.0.0.1", HTTP_CF_CONNECTING_IP=A)) == A
        assert dj.request_client_ip(rf.get("/", REMOTE_ADDR=B, HTTP_CF_CONNECTING_IP=A)) == B
    finally:
        dj.set_client(None)

    sso = FastSSO(fake.async_client(**kw))
    app = FastAPI()

    @app.get("/ip")
    async def ip(v: str = Depends(sso.client_ip)):
        return {"ip": v}

    assert TestClient(app, client=("127.0.0.1", 1)).get("/ip", headers={"CF-Connecting-IP": A}).json() == {"ip": A}
    assert TestClient(app, client=(B, 1)).get("/ip", headers={"CF-Connecting-IP": A}).json() == {"ip": B}

    fapp = flask.Flask("hdr")
    FlaskSSO(fapp, client=fake.client(**kw))

    @fapp.get("/ip")
    def fip():
        return {"ip": flask.g.client_ip}

    c = fapp.test_client()
    assert c.get("/ip", headers={"CF-Connecting-IP": A}, environ_base={"REMOTE_ADDR": "127.0.0.1"}).get_json() == {"ip": A}
    assert c.get("/ip", headers={"CF-Connecting-IP": A}, environ_base={"REMOTE_ADDR": B}).get_json() == {"ip": B}


@pytest.mark.parametrize("state,status", [("down", 503), ("revoked", 401), ("none", 401)])
def test_django_lazy_request_sso_without_decorator_is_json_not_500(django_setup, state, status):
    """V12B-02: through Django's real handler (process_exception), not a hand-called middleware."""
    from django.test import Client, override_settings

    from sso_client.adapters import django as adapter

    fake = FakeSSO()
    adapter.set_client(fake.client(retries=0))
    try:
        tok = fake.issue("alice", ip=A)
        headers = {} if state == "none" else {"HTTP_AUTHORIZATION": f"Bearer {tok}"}
        if state == "down":
            fake.down()
        if state == "revoked":
            fake.revoke(tok)
        with override_settings(ROOT_URLCONF="tests.dj_lazy_urls",
                               MIDDLEWARE=["sso_client.adapters.django.SSOMiddleware"]):
            c = Client(raise_request_exception=False)
            r = c.get("/plain", REMOTE_ADDR=A, **headers)
            assert r.status_code == status and r["Content-Type"] == "application/json", r.content
            if status == 503:
                assert r["Retry-After"] == "5" and json.loads(r.content) == {"detail": "sso_unavailable"}
            fake.up()
            assert c.get("/boom", REMOTE_ADDR=A, **headers).status_code == 500  # other errors untouched
    finally:
        adapter.set_client(None)


def test_default_timeout_and_retries():
    from sso_client import SSOConfig

    cfg = SSOConfig(base_url="https://sso.example", client_id="c", client_secret="s")
    assert cfg.timeout == 2.0 and cfg.retries == 1
    env = SSOConfig.from_env({"SSO_BASE_URL": "https://sso.example", "SSO_CLIENT_ID": "c",
                              "SSO_CLIENT_SECRET": "s"})
    assert env.timeout == 2.0 and env.retries == 1


def test_default_retry_count_on_a_dead_sso():
    """One retry by default: two attempts, then SSOUnavailable."""
    import httpx

    from sso_client import SSOClient, SSOConfig, SSOUnavailable

    hits = []

    def handler(request):
        hits.append(1)
        raise httpx.ConnectError("refused", request=request)

    c = SSOClient(SSOConfig(base_url="https://sso.example", client_id="c", client_secret="s"),
                  http=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(SSOUnavailable):
        c.check("tok", A)
    assert len(hits) == 2


def test_every_adapter_503_carries_retry_after():
    from sso_client import SSOProtocolError, SSOUnavailable, error_response

    for exc in (SSOUnavailable("x"), SSOProtocolError("y", 500)):
        status, _, headers = error_response(exc)
        assert status == 503 and headers["Retry-After"] == "5"
