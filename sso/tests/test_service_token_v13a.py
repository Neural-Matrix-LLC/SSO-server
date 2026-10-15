"""v1.3a per-service credentials: service tokens, introspect, inactive-users feed."""
from __future__ import annotations

import jwt
from django.utils import timezone

from sso.models import ServiceClient

from .conftest import bearer
from .test_admin_api_v13a import A, H, admin_user, at, basic, perm, reauth  # noqa: F401

ST = "/api/v1/auth/service-token"


def client(cid="sgmcp", secret="sec", app="app1", perms=("app1",)):
    c = ServiceClient(client_id=cid, name=cid, app_codename=app)
    c.set_secret(secret)
    c.save()
    for p in perms:
        c.permissions.add(perm(p))
    return c


def get_token(api, cid="sgmcp", secret="sec"):
    return api.post(ST, {"grant_type": "client_credentials"}, format="json", **basic(cid, secret))


def test_issue_claims(api, db):
    client()
    r = get_token(api)
    assert r.status_code == 200 and r.json()["expires_in"] == 300 and r["Cache-Control"] == "no-store"
    c = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert c["sub"] == "svc:sgmcp" and c["token_type"] == "service" and c["typ"] == "service"
    assert c["perms"] == ["application.app1"] and c["app"] == "app1"
    assert "cip" not in c and "sid" not in c and c["exp"] - c["iat"] == 300
    assert jwt.get_unverified_header(r.json()["access_token"])["kid"]


def test_bad_client_and_grant(api, db):
    client()
    assert get_token(api, secret="x").status_code == 401
    r = api.post(ST, {"grant_type": "password"}, format="json", **basic("sgmcp", "sec"))
    assert r.status_code == 400 and r.json()["error"] == "unsupported_grant_type"
    assert api.post(ST, {"grant_type": "client_credentials"}, format="json").status_code == 401


def test_throttle(api, db, settings):
    client()
    from sso.service_auth import ServiceTokenThrottle

    ServiceTokenThrottle.THROTTLE_RATES = {**ServiceTokenThrottle.THROTTLE_RATES, "service_token": "2/min"}
    try:
        codes = [get_token(api).status_code for _ in range(3)]
    finally:
        ServiceTokenThrottle.THROTTLE_RATES = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
    assert codes == [200, 200, 429]


def _introspect(api, token):
    return api.post("/api/v1/auth/introspect", {"token": token, "ip": "198.51.100.1"}, format="json",
                    **basic("rcv", "rsec")).json()


def test_introspect_service_token_no_ip_binding(api, db, settings):
    settings.SSO_IP_BINDING_MODE = "ENFORCE"
    client()
    client("rcv", "rsec", perms=())
    t = get_token(api).json()["access_token"]
    body = _introspect(api, t)
    assert body["active"] is True and body["token_type"] == "service" and body["sub"] == "svc:sgmcp"
    assert body["subject_client_id"] == "sgmcp" and body["perms"] == ["application.app1"]
    assert body["ip_binding"] == "NOIP" and body["client_id"] == "rcv"


def test_introspect_inactive_after_deactivate_rotate_delete(api, db):
    c = client()
    client("rcv", "rsec", perms=())
    t = get_token(api).json()["access_token"]
    c.is_active = False
    c.save()
    assert _introspect(api, t) == {"active": False}
    assert get_token(api).status_code == 401
    c.is_active = True
    c.save()
    assert _introspect(api, t)["active"] is True
    c.secret_rotated_at = timezone.now()
    c.save()
    assert _introspect(api, t) == {"active": False}
    t2 = get_token(api).json()["access_token"]
    assert _introspect(api, t2)["active"] is True
    c.delete()
    assert _introspect(api, t2) == {"active": False}


def test_forged_service_token_inactive(api, db):
    from .conftest import claims, sign

    client("rcv", "rsec", perms=())
    client()
    forged = sign(claims("svc:sgmcp", token_type="service", client_id="sgmcp"), kid=None)
    assert _introspect(api, forged) == {"active": False}
    rogue = sign(claims("svc:sgmcp", token_type="service", client_id="sgmcp"),
                 private_path=__import__("os").environ["SSO_TEST_ROGUE_PRIVATE"])
    assert _introspect(api, rogue) == {"active": False}


def test_inactive_feed(api, at, reauth, make_user):  # noqa: F811
    client()
    since = timezone.now().isoformat()
    a = make_user(username="a1", email="a1@x.org", groups=())
    b = make_user(username="b1", email="b1@x.org", groups=())
    api.post(f"{A}/users/{a.pk}/suspend", {}, format="json", **H(at, reauth))
    api.delete(f"{A}/users/{b.pk}", **H(at, reauth))
    r = api.get("/api/v1/service/users/inactive", {"since": since}, **basic("sgmcp", "sec"))
    assert r.status_code == 200
    events = [(u["username"], u["event"]) for u in r.json()["users"]]
    assert events == [("a1", "suspended"), ("b1", "deleted")]
    nxt = r.json()["next_since"]
    t = get_token(api).json()["access_token"]
    r = api.get("/api/v1/service/users/inactive", {"since": nxt}, **bearer(t))
    assert r.status_code == 200 and r.json()["users"] == []
    assert api.get("/api/v1/service/users/inactive", **basic("sgmcp", "sec")).status_code == 400
    assert api.get("/api/v1/service/users/inactive", {"since": since}).status_code == 401


def test_inactive_feed_includes_users_deleted_outside_the_api(api, make_user):
    client()
    since = timezone.now().isoformat()
    u = make_user(username="gone", email="g@x.org", groups=())
    u.delete()  # e.g. Django admin or shell
    r = api.get("/api/v1/service/users/inactive", {"since": since}, **basic("sgmcp", "sec")).json()
    assert [(x["username"], x["event"]) for x in r["users"]] == [("gone", "deleted")]
