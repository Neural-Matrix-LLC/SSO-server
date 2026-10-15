"""sso-client 0.2: service tokens, device tokens, on-behalf-of (SSO design v1.3b)."""
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from sso_client import (
    DeviceTokenSource, PermissionDenied, ServiceTokenSource, TokenInactive, generate_device_key, on_behalf_of_headers,
    resolve_request,
)
from sso_client.testing import BASE_URL, FakeSSO

IP = "203.0.113.7"


def test_service_token_source_caches_and_renews(monkeypatch):
    fake = FakeSSO()
    fake.register_service("svc-a", "s3cret", perms=["application.app1"])
    from sso_client import SSOConfig
    cfg = SSOConfig(BASE_URL, "svc-a", "s3cret")
    src = ServiceTokenSource(cfg, http=httpx.Client(transport=fake.transport))
    t1 = src.get()
    assert src.get() == t1  # cached
    src._exp = 0
    assert src.get() != t1  # renewed
    bad = ServiceTokenSource(SSOConfig(BASE_URL, "svc-a", "no"),
                             http=httpx.Client(transport=fake.transport))
    with pytest.raises(Exception):
        bad.get()


def test_check_service():
    fake = FakeSSO()
    t = fake.issue_service("relay", perms=["application.app1"])
    r = fake.client().check_service(t)
    assert r.client_id == "relay" and r.has("application.app1") and r.typ == "service"
    d = fake.issue_service("dev_1", typ="device", owner="42")
    assert fake.client().check_service(d).owner == "42"
    fake.revoke(t)
    with pytest.raises(TokenInactive):
        fake.client().check_service(t)
    with pytest.raises(TokenInactive):
        fake.client().check_service(fake.issue("alice"))  # a user token is not a service token


def test_on_behalf_of_check():
    fake = FakeSSO()
    ut = fake.issue("alice", perms=["application.app1"], ip=IP)
    actor = fake.issue_service("auto", can_delegate=True)
    r = fake.client().check(ut, IP, require=["application.app1"], actor_token=actor)
    assert r.via == "svc:auto" and r.delegation_allowed is True and fake.calls[-1]["actor_token"] == actor
    nodel = fake.issue_service("nodel")
    with pytest.raises(PermissionDenied):
        fake.client().check(ut, IP, actor_token=nodel)
    with pytest.raises(TokenInactive):
        fake.client().check(ut, IP, actor_token="bogus")


def test_on_behalf_of_headers_and_resolve():
    h = on_behalf_of_headers("S", "U", "[::ffff:203.0.113.7]:443")
    assert h == {"Authorization": "Bearer S", "X-SSO-User-Token": "U", "X-SSO-Client-IP": IP}
    assert resolve_request(h["Authorization"], h, "10.0.0.1") == ("U", IP, "S")
    assert resolve_request("Bearer U", {}, "10.0.0.1") == ("U", "10.0.0.1", None)
    # user-token header without a bearer actor: ignored (own peer IP, no delegation)
    assert resolve_request(None, {"X-SSO-User-Token": "U"}, "10.0.0.1") == (None, "10.0.0.1", None)


def test_device_token_source_assertion():
    priv, pub = generate_device_key()
    seen = {}

    def handler(request):
        import json

        body = json.loads(request.content)
        seen.update(body)
        return httpx.Response(200, json={"access_token": "devtok", "expires_in": 300})

    src = DeviceTokenSource(BASE_URL, "dev_1", priv, http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert src.get() == "devtok" and src.get() == "devtok"
    key = serialization.load_pem_public_key(pub.encode())
    c = jwt.decode(seen["client_assertion"], key, algorithms=["EdDSA"], audience=BASE_URL + "/api/v1/auth/service-token")
    assert c["iss"] == c["sub"] == "dev_1" and c["exp"] - c["iat"] == 120 and c["jti"]
    assert seen["client_assertion_type"].endswith("jwt-bearer")
    with pytest.raises(Exception):
        DeviceTokenSource("http://plain", "dev_1", priv)


def test_flask_adapter_on_behalf():
    from flask import Flask, g

    from sso_client.adapters.flask import SSO

    fake = FakeSSO()
    ut = fake.issue("alice", perms=["application.app1"], ip=IP)
    actor = fake.issue_service("auto", can_delegate=True)
    app = Flask("t")
    sso = SSO(app, client=fake.client())

    @app.get("/x")
    @sso.require_permission("application.app1")
    def x():
        return {"via": g.sso.via, "user": g.sso.user.username}

    r = app.test_client().get("/x", headers=on_behalf_of_headers(actor, ut, IP))
    assert r.status_code == 200 and r.json == {"via": "svc:auto", "user": "alice"}
    assert fake.calls[-1]["ip"] == IP
    r = app.test_client().get("/x", headers=on_behalf_of_headers(fake.issue_service("nodel"), ut, IP))
    assert r.status_code == 403
