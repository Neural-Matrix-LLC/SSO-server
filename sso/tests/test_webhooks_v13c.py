"""v1.3c: signed webhooks (DESIGN-v1.3c-webhooks.md)."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.utils import timezone

from sso import webhooks
from sso.models import ServiceClient, WebhookDelivery, WebhookEvent
from sso.webhook_secrets import decrypt, encrypt

from .conftest import login
from .test_admin_api_v13a import A, H, admin_user, at, perm, reauth  # noqa: F401

SECRET = "whsec-test"


@pytest.fixture
def sub(db):
    webhooks.check_keys()  # keys.rotated baseline before the subscriber exists
    c = ServiceClient(client_id="hooks", name="hooks", app_codename="app1", notify_url="https://hooks.example/cb")
    c.set_secret("s")
    c.notify_secret_enc = encrypt(SECRET)
    c.save()
    return c


@pytest.fixture
def sent(monkeypatch):
    calls, codes = [], []

    def fake(url, body, headers):
        calls.append((url, body, headers))
        return codes.pop(0) if codes else 200

    monkeypatch.setattr(webhooks, "http_post", fake)
    return calls, codes


def events(t):
    return list(WebhookEvent.objects.filter(type=t))


def test_secret_roundtrip_and_tamper(db):
    tok = encrypt("x")
    assert decrypt(tok) == "x" and decrypt(tok[:-2] + "AA") is None and decrypt(None) is None


def test_suspend_reactivate_emit_and_deliver_signed(sub, sent, make_user):
    calls, _ = sent
    u = make_user(username="w1", email="w1@x.org")
    u.is_active = False
    u.save()
    assert events("user.suspended")[0].data["sub"] == str(u.pk)
    assert any(e.data.get("reason") == "suspended" for e in events("token.revoked"))
    u.is_active = True
    u.save()
    assert events("user.reactivated")
    counts = webhooks.process_once()
    assert counts.get("delivered", 0) >= 3
    url, body, h = calls[0]
    assert url == sub.notify_url
    assert h["X-SSO-Signature"] == webhooks.sign(SECRET, int(h["X-SSO-Timestamp"]), body)
    payload = json.loads(body)
    assert payload["id"] == int(h["X-SSO-Event-Id"]) and payload["type"] == h["X-SSO-Event-Type"]
    assert not WebhookDelivery.objects.exclude(status="delivered").exists()


def test_delete_emits_user_deleted_no_token_revoked(sub, make_user):
    u = make_user(username="w2", email="w2@x.org")
    pk = u.pk
    WebhookEvent.objects.all().delete()
    u.delete()
    assert [e.type for e in WebhookEvent.objects.all()] == ["user.deleted"]
    assert events("user.deleted")[0].data["sub"] == str(pk)


def test_permission_changed_m2m(sub, make_user):
    u = make_user(username="w3", email="w3@x.org", groups=())
    g = Group.objects.create(name="wg")
    WebhookEvent.objects.all().delete()
    u.groups.add(g)
    u.user_permissions.add(perm("sso_admin"))
    g.permissions.add(perm("sso_admin"))
    assert len(events("permission.changed")) >= 3


def test_retry_backoff_then_fail_after_window(sub, sent, make_user, settings):
    _, codes = sent
    codes.extend([500, 500])
    webhooks.emit("permission.changed", sub="1")
    d = WebhookDelivery.objects.get()
    assert webhooks.process_once() == {"retrying": 1}
    d.refresh_from_db()
    assert d.status == "pending" and d.attempts == 1 and d.last_status == 500 and d.next_attempt_at > timezone.now()
    WebhookDelivery.objects.filter(pk=d.pk).update(next_attempt_at=timezone.now(),
                                                   window_start=timezone.now() - timedelta(hours=25))
    assert webhooks.process_once() == {"failed": 1}


def test_network_error_and_refused(sub, monkeypatch, settings):
    settings.SSO_WEBHOOK_ALLOW_LOOPBACK = False
    ServiceClient.objects.filter(pk=sub.pk).update(notify_url="https://127.0.0.1:9/x")
    webhooks.emit("permission.changed", sub="1")
    assert webhooks.process_once() == {"retrying": 1}
    assert WebhookDelivery.objects.get().last_error == "refused:address_refused"
    with pytest.raises(webhooks.Refused):
        webhooks.check_address("http://hooks.example/")


def test_filter_and_inactive_skip(sub, sent):
    ServiceClient.objects.filter(pk=sub.pk).update(notify_events=["user.deleted"])
    webhooks.emit("permission.changed", sub="1")
    assert not WebhookDelivery.objects.exists()
    webhooks.emit("user.deleted", sub="1")
    ServiceClient.objects.filter(pk=sub.pk).update(is_active=False)
    assert webhooks.process_once() == {"skipped": 1}


def test_keys_rotated_baseline_once(db):
    assert webhooks.check_keys() is not None
    assert webhooks.check_keys() is None


def test_prune_keeps_pending(sub):
    old = timezone.now() - timedelta(days=400)
    webhooks.emit("user.deleted", sub="1")
    e2 = webhooks.emit("user.deleted", sub="2")
    WebhookEvent.objects.update(created=old)
    WebhookDelivery.objects.exclude(event=e2).update(status="delivered")
    webhooks.prune(30)
    left = set(WebhookEvent.objects.values_list("type", "pk"))
    assert ("user.deleted", e2.pk) in left and len(left) == 2  # + the last keys.rotated baseline (kept)


def test_worker_command_once(sub, sent):
    webhooks.emit("user.deleted", sub="1")
    call_command("run_webhook_worker", "--once")
    assert WebhookDelivery.objects.get().status == "delivered"


# ------------------------------------------------------------------ admin API
def test_admin_rotate_notify_secret_needs_stepup(api, at, reauth, sub):
    url = f"{A}/services/hooks/rotate-notify-secret"
    assert api.post(url, **H(at)).status_code == 401
    r = api.post(url, **H(at, reauth=reauth))
    assert r.status_code == 200, r.content
    sub.refresh_from_db()
    assert decrypt(sub.notify_secret_enc) == r.json()["notify_secret"] != SECRET
    s = api.get(f"{A}/services/hooks", **H(at)).json()
    assert s["has_notify_secret"] is True and "notify_secret" not in s


def test_admin_patch_notify_events(api, at, sub):
    u = f"{A}/services/hooks"
    assert api.patch(u, {"notify_events": ["nope"]}, format="json", **H(at)).status_code == 400
    r = api.patch(u, {"notify_events": ["user.deleted", "user.deleted"]}, format="json", **H(at))
    assert r.status_code == 200 and r.json()["notify_events"] == ["user.deleted"]


def test_admin_events_deliveries_redeliver(api, at, sub, sent):
    _, codes = sent
    codes.append(500)
    ev = webhooks.emit("user.deleted", sub="9")
    webhooks.process_once()
    r = api.get(f"{A}/webhooks/events?type=user.deleted", **H(at))
    assert r.status_code == 200 and any(x["id"] == ev.pk for x in r.json()["results"])
    r = api.get(f"{A}/webhooks/deliveries?client_id=hooks&event={ev.pk}", **H(at))
    d = r.json()["results"][0]
    assert d["status"] == "pending" and d["attempts"] == 1 and d["last_status"] == 500
    assert api.get(f"{A}/webhooks/deliveries?status=bogus", **H(at)).status_code == 400
    r = api.post(f"{A}/webhooks/deliveries/{d['id']}/redeliver", **H(at))
    assert r.status_code == 200 and r.json()["attempts"] == 0
    assert api.post(f"{A}/webhooks/deliveries/999999/redeliver", **H(at)).status_code == 404


def test_admin_group_delete_and_import_emit(api, at, reauth, sub, make_user):
    u = make_user(username="w4", email="w4@x.org", groups=())
    g = Group.objects.create(name="gone")
    u.groups.add(g)
    gid = g.pk
    WebhookEvent.objects.all().delete()
    r = api.delete(f"{A}/groups/{gid}", **H(at, reauth=reauth))
    assert r.status_code in (200, 204), r.content
    assert any(e.data.get("group") == "gone" and e.data.get("granted") is False for e in events("permission.changed"))
