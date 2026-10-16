"""v1.3b: device clients (private_key_jwt), on-behalf-of (DESIGN-v1.3b-devices-on-behalf-of.md)."""
from __future__ import annotations

import base64
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth.models import User

from sso.models import AdminAuditLog, ServiceClient

from .conftest import ISSUER, bearer, login
from .test_admin_api_v13a import A, H, admin_user, at, basic, perm, reauth  # noqa: F401

ST = "/api/v1/auth/service-token"
AUD = ISSUER + "/api/v1/auth/service-token"
ASSERT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
IP = "203.0.113.7"


def relay(cid="relay", secret="rsec", app="app1", reg=True, delegate=False):
    c = ServiceClient(client_id=cid, name=cid, app_codename=app, can_register_devices=reg, can_delegate=delegate)
    c.set_secret(secret)
    c.save()
    return c


def svc_token(api, cid="relay", secret="rsec"):
    return api.post(ST, {"grant_type": "client_credentials"}, format="json", **basic(cid, secret)).json()["access_token"]


def keypair():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pub.decode()


def user_token(api, username="thomas"):
    return login(api, username=username, REMOTE_ADDR=IP).json()["access_token"]


def register(api, st, ut, pub, name="pc1", ip=IP):
    return api.post("/api/v1/devices", {"device_name": name, "public_key": pub}, format="json",
                    HTTP_AUTHORIZATION=f"Bearer {st}", HTTP_X_SSO_USER_TOKEN=ut, HTTP_X_SSO_CLIENT_IP=ip)


def assertion(key, cid, **over):
    now = int(time.time())
    c = {"iss": cid, "sub": cid, "aud": AUD, "iat": now, "exp": now + 120, "jti": uuid.uuid4().hex}
    c.update(over)
    return jwt.encode(c, key, algorithm="EdDSA")


def device_token(api, key, cid, **over):
    return api.post(ST, {"grant_type": "client_credentials", "client_assertion_type": ASSERT_TYPE,
                         "client_assertion": assertion(key, cid, **over)}, format="json")


@pytest.fixture
def paired(api, user):
    user.user_permissions.add(perm("app1"))
    relay()
    key, pub = keypair()
    r = register(api, svc_token(api), user_token(api), pub)
    assert r.status_code == 201, r.content
    return key, r.json()["client_id"]


def introspect(api, token, **extra):
    if not ServiceClient.objects.filter(client_id="rcv").exists():
        c = ServiceClient(client_id="rcv", name="rcv")
        c.set_secret("x")
        c.save()
    return api.post("/api/v1/auth/introspect", {"token": token, **extra}, format="json", **basic("rcv", "x")).json()


# ------------------------------------------------------------------ registration
def test_register_device(api, user, paired):
    key, cid = paired
    dev = ServiceClient.objects.get(client_id=cid)
    assert dev.kind == "device" and dev.owner == user and dev.app_codename == "app1" and cid.startswith("dev_")
    assert not dev.check_secret("") and dev.public_key.startswith("-----BEGIN PUBLIC KEY")
    row = AdminAuditLog.objects.get(action="device.create")
    assert row.actor_id == "svc:relay" and row.after["owner"] == str(user.pk)


def test_register_requires_flag_user_token_ip_and_app(api, user, settings):
    key, pub = keypair()
    relay(reg=False)
    st = svc_token(api)
    ut = user_token(api)
    assert register(api, st, ut, pub).status_code == 403  # no can_register_devices
    ServiceClient.objects.filter(client_id="relay").update(can_register_devices=True)
    assert register(api, st, ut, pub).status_code == 403  # user lacks application.app1
    user.user_permissions.add(perm("app1"))
    r = api.post("/api/v1/devices", {"device_name": "x", "public_key": pub}, format="json",
                 HTTP_AUTHORIZATION=f"Bearer {st}")
    assert r.status_code == 401  # no user token
    assert register(api, st, "garbage", pub).status_code == 401
    assert register(api, st, ut, "not-a-key").status_code == 400
    # user token as Bearer (no service token) -> 401 invalid_client
    r = api.post("/api/v1/devices", {"device_name": "x", "public_key": pub}, format="json", **bearer(ut))
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    ut2 = user_token(api)
    assert register(api, st, ut2, pub, ip="198.51.100.1").status_code == 401
    ut3 = user_token(api)
    assert register(api, st, ut3, pub).status_code == 201
    assert register(api, st, ut3, pub).status_code == 409  # same key twice


def test_raw_base64_key_and_limit(api, user, settings):
    settings.SSO_DEVICE_MAX_PER_USER = 1
    user.user_permissions.add(perm("app1"))
    relay()
    st, ut = svc_token(api), user_token(api)
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,
                                                                 serialization.PublicFormat.Raw)
    assert register(api, st, ut, base64.urlsafe_b64encode(raw).decode().rstrip("=")).status_code == 201
    assert register(api, st, ut, keypair()[1]).status_code == 409


# ------------------------------------------------------------------ device tokens
def test_device_token_and_introspect(api, user, paired):
    key, cid = paired
    r = device_token(api, key, cid)
    assert r.status_code == 200, r.content
    t = r.json()["access_token"]
    c = jwt.decode(t, options={"verify_signature": False})
    assert c["typ"] == "device" and c["sub"] == f"dev:{cid}" and c["owner"] == str(user.pk) and c["perms"] == []
    assert "cip" not in c
    body = introspect(api, t)
    assert body["active"] and body["typ"] == "device" and body["owner"] == str(user.pk) and body["owner_active"]
    assert ServiceClient.objects.get(client_id=cid).last_used is not None


@pytest.mark.parametrize("over", [
    {"aud": "https://other/api"}, {"exp": int(time.time()) - 100, "iat": int(time.time()) - 200},
    {"exp": int(time.time()) + 3600}, {"sub": "dev_other"}, {"iat": int(time.time()) + 600},
])
def test_bad_assertions(api, paired, over):
    key, cid = paired
    r = device_token(api, key, cid, **over)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_assertion_wrong_key_and_replay(api, paired):
    key, cid = paired
    assert device_token(api, Ed25519PrivateKey.generate(), cid).status_code == 401
    a = assertion(key, cid)
    body = {"grant_type": "client_credentials", "client_assertion_type": ASSERT_TYPE, "client_assertion": a}
    assert api.post(ST, body, format="json").status_code == 200
    assert api.post(ST, body, format="json").status_code == 401  # jti replay
    assert api.post(ST, {**body, "client_assertion_type": "x"}, format="json").status_code == 401
    # RS256 / alg none never accepted
    assert api.post(ST, {**body, "client_assertion": jwt.encode({"iss": cid}, "k", algorithm="HS256")},
                    format="json").status_code == 401


def test_owner_suspend_cuts_devices_and_they_stay_off(api, user, paired, at, reauth):
    key, cid = paired
    t = device_token(api, key, cid).json()["access_token"]
    assert api.post(f"{A}/users/{user.pk}/suspend", {}, format="json", **H(at, reauth)).status_code == 200
    assert introspect(api, t) == {"active": False}
    assert device_token(api, key, cid).status_code == 401
    assert not ServiceClient.objects.get(client_id=cid).is_active
    api.post(f"{A}/users/{user.pk}/unsuspend", {}, format="json", **H(at))
    assert device_token(api, key, cid).status_code == 401  # re-pair needed


def test_owner_inactive_via_queryset_update_still_blocks(api, user, paired):
    key, cid = paired
    t = device_token(api, key, cid).json()["access_token"]
    User.objects.filter(pk=user.pk).update(is_active=False)  # bypasses signals (myFinance-style)
    assert introspect(api, t) == {"active": False}
    assert device_token(api, key, cid).status_code == 401


def test_owner_deleted_deletes_devices(api, user, paired):
    key, cid = paired
    user.delete()
    assert not ServiceClient.objects.filter(client_id=cid).exists()


def test_own_device_list_and_delete(api, user, paired, make_user):
    key, cid = paired
    ut = user_token(api)
    r = api.get("/api/v1/devices", **bearer(ut))
    assert [d["client_id"] for d in r.json()["results"]] == [cid] and "public_key" not in r.json()["results"][0]
    other = make_user(username="eve", email="eve@x.org", groups=())
    assert other
    et = user_token(api, "eve")
    assert api.delete(f"/api/v1/devices/{cid}", **bearer(et)).status_code == 404
    t = device_token(api, key, cid).json()["access_token"]
    assert api.delete(f"/api/v1/devices/{cid}", **bearer(ut)).status_code == 204
    assert introspect(api, t) == {"active": False}


def test_admin_devices(api, user, paired, at, reauth):
    key, cid = paired
    r = api.get(f"{A}/devices?owner={user.pk}", **H(at))
    assert r.json()["count"] == 1
    assert api.delete(f"{A}/devices/{cid}", **H(at)).status_code == 401
    assert api.delete(f"{A}/devices/{cid}", **H(at, reauth)).status_code == 204


def test_basic_auth_with_device_id_fails(api, paired):
    key, cid = paired
    assert api.post(ST, {"grant_type": "client_credentials"}, format="json", **basic(cid, "")).status_code == 401


# ------------------------------------------------------------------ on-behalf-of
def test_on_behalf_of_introspect(api, user):
    user.user_permissions.add(perm("app1"))
    relay("auto", "asec", delegate=True)
    relay("nodel", "nsec", delegate=False)
    ut = user_token(api)
    st = svc_token(api, "auto", "asec")
    body = introspect(api, ut, ip=IP, actor_token=st, require=["application.app1"])
    assert body["active"] and body["act"] == {"sub": "svc:auto", "client_id": "auto"}
    assert body["delegation_allowed"] is True and body["allowed"] is True
    nt = svc_token(api, "nodel", "nsec")
    body = introspect(api, ut, ip=IP, actor_token=nt, require=["application.app1"])
    assert body["active"] and body["delegation_allowed"] is False and body["allowed"] is False
    assert introspect(api, ut, ip=IP, actor_token="garbage") == {"active": False}
    # without actor: unchanged v1.2b answer
    body = introspect(api, ut, ip=IP)
    assert "act" not in body and "delegation_allowed" not in body


def test_service_flags_need_stepup(api, at, reauth):
    relay("x1", "s", reg=False)
    assert api.patch(f"{A}/services/x1", {"can_delegate": True}, format="json", **H(at)).status_code == 401
    r = api.patch(f"{A}/services/x1", {"can_delegate": True}, format="json", **H(at, reauth))
    assert r.status_code == 200 and r.json()["can_delegate"] is True
    assert api.patch(f"{A}/services/x1", {"can_delegate": False}, format="json", **H(at)).status_code == 200
