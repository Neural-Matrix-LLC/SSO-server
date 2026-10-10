"""ServiceClient registration (admin + command), structured login logging (B.13), model helpers."""
from __future__ import annotations

import io
import json
import logging

import pytest
from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.utils import timezone

from sso.models import AuthorizationCode, ServiceClient, UserTokenRevocation
from .conftest import PASSWORD, login

pytestmark = pytest.mark.django_db


def test_create_service_client_command():
    out, err = io.StringIO(), io.StringIO()
    call_command("create_service_client", "rebalance-api", "--name", "Rebalance", "--origin",
                 "https://fin.example.test", stdout=out, stderr=err)
    secret = dict(line.split("=", 1) for line in out.getvalue().split())["client_secret"]
    c = ServiceClient.objects.get(client_id="rebalance-api")
    assert c.name == "Rebalance" and c.allowed_origins == ["https://fin.example.test"]
    assert c.check_secret(secret) and secret not in c.client_secret_hash
    with pytest.raises(CommandError, match="exists"):
        call_command("create_service_client", "rebalance-api", stdout=io.StringIO(), stderr=io.StringIO())
    out2 = io.StringIO()
    call_command("create_service_client", "rebalance-api", "--rotate-secret", stdout=out2, stderr=io.StringIO())
    new_secret = dict(line.split("=", 1) for line in out2.getvalue().split())["client_secret"]
    c.refresh_from_db()
    assert c.check_secret(new_secret) and not c.check_secret(secret)
    with pytest.raises(CommandError, match="does not exist"):
        call_command("create_service_client", "ghost", "--rotate-secret", stdout=io.StringIO(), stderr=io.StringIO())


@pytest.fixture
def admin_client(client, settings):
    u = User.objects.create_superuser("root", "root@example.org", "Adm1n-pass-123")
    client.force_login(u)
    return client


def test_admin_registers_client_and_shows_secret_once(admin_client, settings):
    base = "/" + settings.SSO_ADMIN_PATH
    r = admin_client.post(base + "sso/serviceclient/add/",
                          {"client_id": "svc-a", "name": "Service A", "is_active": "on",
                           "allowed_origins": "[]", "redirect_uris": "[]"}, follow=True)
    assert r.status_code == 200
    msgs = [str(m) for m in r.context["messages"]]
    assert any("Client secret for 'svc-a'" in m for m in msgs)
    secret = msgs[0].split(": ", 1)[1].split(" ", 1)[0]
    c = ServiceClient.objects.get(client_id="svc-a")
    assert c.check_secret(secret)
    # editing without "regenerate" keeps the secret; with it, rotates
    r = admin_client.post(base + f"sso/serviceclient/{c.pk}/change/",
                          {"client_id": "svc-a", "name": "Renamed", "is_active": "on",
                           "allowed_origins": "[]", "redirect_uris": "[]"}, follow=True)
    c.refresh_from_db()
    assert c.name == "Renamed" and c.check_secret(secret)
    admin_client.post(base + f"sso/serviceclient/{c.pk}/change/",
                      {"client_id": "svc-a", "name": "Renamed", "is_active": "on", "regenerate_secret": "on",
                       "allowed_origins": "[]", "redirect_uris": "[]"}, follow=True)
    c.refresh_from_db()
    assert not c.check_secret(secret)
    # list + revocation admin render
    assert admin_client.get(base + "sso/serviceclient/").status_code == 200
    assert admin_client.get(base + "sso/usertokenrevocation/").status_code == 200


def test_admin_is_not_at_default_path(client):
    assert client.get("/admin/").status_code == 404


def _events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "sso.auth"]


def test_login_logging_is_structured_and_secret_free(api, user, caplog):
    caplog.set_level(logging.INFO, logger="sso.auth")
    ok = login(api, HTTP_X_FORWARDED_FOR="198.51.100.4").json()
    login(api, password="Wrong-Password-1", HTTP_X_FORWARDED_FOR="198.51.100.4")
    login(api, username="ghost@example.org", password="Wrong-Password-2")
    api.post("/api/v1/auth/refresh", {"refresh_token": ok["refresh_token"]}, format="json")
    ev = _events(caplog)
    logins = [e for e in ev if e["event"] == "login"]
    assert [e["result"] for e in logins] == ["success", "invalid_credentials", "invalid_credentials"]
    assert logins[0]["username"] == "thomas" and logins[0]["ip"] == "198.51.100.4"
    assert logins[0]["user_id"] == user.pk and logins[0]["client"] == "native"
    assert any(e["event"] == "refresh" and e["result"] == "success" for e in ev)
    text = caplog.text
    for secret in (PASSWORD, "Wrong-Password-1", "Wrong-Password-2", ok["access_token"], ok["refresh_token"]):
        assert secret not in text


def test_inactive_and_throttle_are_logged(api, make_user, caplog):
    caplog.set_level(logging.INFO, logger="sso.auth")
    make_user(is_active=False)
    login(api)
    for _ in range(5):
        login(api, password="x")
    results = [e["result"] for e in _events(caplog)]
    assert "account_inactive" in results and "rate_limited" in results


def test_model_strs_and_helpers(user):
    rev = UserTokenRevocation.revoke(user)
    assert str(user.pk) in str(rev)
    c = ServiceClient.objects.create(client_id="c1", name="C1", client_secret_hash="x")
    code = AuthorizationCode.objects.create(
        code_hash=AuthorizationCode.hash_code("raw"), client=c, user=user, redirect_uri="https://a.example/cb",
        code_challenge="abc", expires_at=timezone.now())
    assert len(code.code_hash) == 64
    assert str(code).startswith("code for")
