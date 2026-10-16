"""v1.1 item 4: ServiceClient Basic auth + client_ip on /login and /refresh (per-IP throttle of the end user)."""
from __future__ import annotations

import base64
import json
import logging

import pytest

from sso.delegation import delegated_client_ip
from sso.models import ServiceClient
from .conftest import PASSWORD

pytestmark = pytest.mark.django_db
RATES = {"login": "3/min", "login_user": "100/min", "refresh": "3/min"}


@pytest.fixture
def wiki_client(db):
    c = ServiceClient(client_id="llm-wiki", name="llm-wiki-svc")
    c.set_secret("wiki-s3cret-value")
    c.save()
    return c


def basic(cid="llm-wiki", secret="wiki-s3cret-value"):
    return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()}


def post_login(api, ip, auth=None, username="thomas", password="wrong"):
    body = {"username": username, "password": password, "client": "native"}
    if ip is not None:
        body["client_ip"] = ip
    return api.post("/api/v1/auth/login", body, format="json", **(auth or {}))


@pytest.fixture
def rates(settings):
    from rest_framework.settings import api_settings

    rf = dict(settings.REST_FRAMEWORK)
    rf["DEFAULT_THROTTLE_RATES"] = {**rf["DEFAULT_THROTTLE_RATES"], **RATES}
    settings.REST_FRAMEWORK = rf
    from rest_framework.throttling import SimpleRateThrottle

    old = SimpleRateThrottle.THROTTLE_RATES
    SimpleRateThrottle.THROTTLE_RATES = rf["DEFAULT_THROTTLE_RATES"]
    yield
    SimpleRateThrottle.THROTTLE_RATES = old
    api_settings.reload()


def test_valid_basic_auth_throttles_per_client_ip(api, user, wiki_client, rates):
    # three end users behind the same app server: each has its own per-IP budget
    for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        for _ in range(3):
            assert post_login(api, ip, basic()).status_code == 401
    assert post_login(api, "203.0.113.1", basic()).status_code == 429
    assert post_login(api, "203.0.113.4", basic()).status_code == 401  # a new user is not blocked


def test_without_basic_auth_client_ip_is_ignored(api, user, rates):
    for i in range(3):
        assert post_login(api, f"203.0.113.{i + 1}").status_code == 401
    # all counted against the caller's own address (127.0.0.1), whatever client_ip says
    assert post_login(api, "198.51.100.77").status_code == 429


@pytest.mark.parametrize("auth", [basic(secret="wrong"), basic(cid="unknown"), {"HTTP_AUTHORIZATION": "Basic !!"},
                                  {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(b"nocolon").decode()},
                                  {"HTTP_AUTHORIZATION": "Basic"}])
@pytest.mark.parametrize("path", ["login", "refresh", "logout"])
def test_invalid_basic_auth_is_401_invalid_client(api, user, wiki_client, auth, path, caplog):
    """v1.2 (C-19): wrong service credentials are refused, no silent fallback to the caller's IP."""
    body = {"username": "thomas", "password": PASSWORD, "client": "native", "refresh_token": "x.y.z",
            "client_ip": "203.0.113.1"}
    r = api.post(f"/api/v1/auth/{path}", body, format="json", **auth)
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"
    assert r["WWW-Authenticate"].startswith("Basic")
    assert "invalid_client" in caplog.text


def test_inactive_service_client_is_invalid_client(api, user, wiki_client):
    wiki_client.is_active = False
    wiki_client.save()
    r = post_login(api, "203.0.113.1", basic(), password=PASSWORD)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_login_with_basic_auth_still_works_and_logs_the_end_user_ip(api, user, wiki_client, caplog):
    caplog.set_level(logging.INFO, logger="sso.auth")
    r = post_login(api, "2001:db8::1", basic(), password=PASSWORD)
    assert r.status_code == 200 and r.json()["refresh_token"]
    events = [json.loads(rec.getMessage()) for rec in caplog.records if rec.getMessage().startswith("{")]
    assert any(e.get("event") == "login" and e["ip"] == "2001:db8::1" and e["result"] == "success" for e in events)
    assert "wiki-s3cret-value" not in caplog.text


@pytest.mark.parametrize("bad", ["not-an-ip", "", "203.0.113.1, 10.0.0.1", 12345, ["1.2.3.4"]])
def test_bad_client_ip_with_valid_credentials_is_400(api, user, wiki_client, caplog, bad):
    """v1.2 (Q-28): invalid client_ip with valid service credentials -> 400 invalid_request."""
    caplog.set_level(logging.INFO, logger="sso.auth")
    r = post_login(api, bad, basic(), password=PASSWORD)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    assert "bad_client_ip" in caplog.text
    r = api.post("/api/v1/auth/refresh", {"refresh_token": "x.y.z", "client_ip": bad}, format="json", **basic())
    assert r.status_code == 400


def test_valid_credentials_without_client_ip_use_the_caller(api, user, wiki_client, caplog):
    caplog.set_level(logging.INFO, logger="sso.auth")
    assert post_login(api, None, basic(), password=PASSWORD).status_code == 200
    assert '"ip": "127.0.0.1"' in caplog.text


def test_refresh_throttle_uses_client_ip_with_basic_auth(api, user, wiki_client, rates):
    def refresh(ip, auth=None):
        return api.post("/api/v1/auth/refresh", {"refresh_token": "x.y.z", "client_ip": ip}, format="json",
                        **(auth or {}))

    for ip in ("203.0.113.1", "203.0.113.2"):
        for _ in range(3):
            assert refresh(ip, basic()).status_code == 401
    assert refresh("203.0.113.1", basic()).status_code == 429
    assert refresh("203.0.113.9", basic()).status_code == 401
    for _ in range(3):
        refresh("203.0.113.5")
    assert refresh("203.0.113.6").status_code == 429  # no Basic: the caller's address


def test_refresh_with_basic_auth_rotates_normally(api, user, wiki_client):
    rt = post_login(api, None, basic(), password=PASSWORD).json()["refresh_token"]
    r = api.post("/api/v1/auth/refresh", {"refresh_token": rt, "client_ip": "203.0.113.8"}, format="json",
                 **basic())
    assert r.status_code == 200 and r.json()["refresh_token"] != rt


def test_delegated_ip_is_cached_per_request(rf, wiki_client, django_assert_num_queries):
    from rest_framework.parsers import JSONParser
    from rest_framework.request import Request

    raw = rf.post("/x", data=json.dumps({"client_ip": "203.0.113.5"}), content_type="application/json", **basic())
    req = Request(raw, parsers=[JSONParser()])
    assert delegated_client_ip(req) == "203.0.113.5"
    with django_assert_num_queries(0):
        assert delegated_client_ip(req) == "203.0.113.5"
    assert delegated_client_ip(Request(rf.post("/x"), parsers=[JSONParser()])) is None


def test_non_dict_body_with_basic_auth(rf, wiki_client):
    from rest_framework.parsers import JSONParser
    from rest_framework.request import Request

    raw = rf.post("/x", data="[1]", content_type="application/json", **basic())
    assert delegated_client_ip(Request(raw, parsers=[JSONParser()])) is None  # no client_ip field
