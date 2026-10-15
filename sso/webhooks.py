"""v1.3c signed webhooks (DESIGN-v1.3c-webhooks.md): outbox ``emit()`` and the delivery worker.

``emit()`` writes the event and one delivery per subscribed service client in the CURRENT transaction (outbox),
so a rolled-back change sends nothing and a committed one is never lost. The worker (``run_webhook_worker``) signs
and POSTs due deliveries: ``X-SSO-Signature: v1=hex(HMAC-SHA256(secret, ts + "." + body))``. At-least-once.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import random
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import ServiceClient, WebhookDelivery, WebhookEvent

logger = logging.getLogger("sso.webhooks")
EVENT_TYPES = ("user.suspended", "user.reactivated", "user.deleted", "token.revoked", "permission.changed",
               "keys.rotated")
MAX_BACKOFF = 600
STALE_CLAIM = 60


def _iso(dt) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def subscribers(event_type: str):
    out = []
    for c in ServiceClient.objects.filter(kind="service", is_active=True).exclude(notify_url__isnull=True).exclude(
            notify_url="").exclude(notify_secret_enc__isnull=True).exclude(notify_secret_enc=""):
        events = c.notify_events or []
        if not events or event_type in events:
            out.append(c)
    return out


def emit(event_type: str, **data) -> WebhookEvent:
    assert event_type in EVENT_TYPES, event_type
    with transaction.atomic():
        ev = WebhookEvent.objects.create(type=event_type, data=data)
        WebhookDelivery.objects.bulk_create([WebhookDelivery(event=ev, client=c) for c in subscribers(event_type)])
    logger.info(json.dumps({"event": "webhook_emitted", "id": ev.pk, "type": event_type}))
    return ev


def body_of(ev: WebhookEvent) -> bytes:
    payload = {"id": ev.pk, "type": ev.type, "time": _iso(ev.created), **ev.data}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign(secret: str, ts: int, body: bytes) -> str:
    return "v1=" + hmac.new(secret.encode("utf-8"), str(ts).encode() + b"." + body, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- sending
class Refused(Exception):
    pass


def check_address(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise Refused("not_https")
    if settings.SSO_WEBHOOK_ALLOW_LOOPBACK:
        return
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise Refused("dns_error") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback)):
            raise Refused("address_refused")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener():
    ctx = ssl.create_default_context()
    if settings.SSO_WEBHOOK_CA_FILE:
        ctx.load_verify_locations(settings.SSO_WEBHOOK_CA_FILE)
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())


def http_post(url: str, body: bytes, headers: dict) -> int:
    """Returns the HTTP status; raises Refused / OSError on network errors. Tests replace this function."""
    check_address(url)
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with _opener().open(req, timeout=settings.SSO_WEBHOOK_TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def backoff(attempts: int) -> float:
    return min(2 ** max(attempts - 1, 0), MAX_BACKOFF) * (1 + random.uniform(0, 0.25))


def claim_due(limit: int = 50) -> list[WebhookDelivery]:
    now = timezone.now()
    with transaction.atomic():
        qs = (WebhookDelivery.objects.select_for_update(skip_locked=True)
              .filter(Q(status="pending", next_attempt_at__lte=now)
                      | Q(status="sending", claimed_at__lt=now - timedelta(seconds=STALE_CLAIM)))
              .order_by("next_attempt_at")[:limit])
        rows = list(qs)
        WebhookDelivery.objects.filter(pk__in=[r.pk for r in rows]).update(status="sending", claimed_at=now)
    return rows


def deliver(d: WebhookDelivery) -> str:
    from .webhook_secrets import decrypt

    d = WebhookDelivery.objects.select_related("event", "client").get(pk=d.pk)
    client = d.client
    secret = decrypt(client.notify_secret_enc)
    if not client.is_active or not client.notify_url or secret is None:
        WebhookDelivery.objects.filter(pk=d.pk).update(status="skipped", last_error="client_inactive_or_no_secret")
        return "skipped"
    body = body_of(d.event)
    ts = int(time.time())
    headers = {"Content-Type": "application/json", "User-Agent": "sso-webhooks/1", "X-SSO-Event-Id": str(d.event_id),
               "X-SSO-Event-Type": d.event.type, "X-SSO-Timestamp": str(ts), "X-SSO-Signature": sign(secret, ts, body)}
    attempts = d.attempts + 1
    status, error = None, ""
    try:
        status = http_post(client.notify_url, body, headers)
    except Refused as exc:
        error = f"refused:{exc}"
    except (OSError, ValueError) as exc:
        error = type(exc).__name__
    now = timezone.now()
    if status is not None and 200 <= status < 300:
        WebhookDelivery.objects.filter(pk=d.pk).update(status="delivered", attempts=attempts, last_status=status,
                                                       last_error="", delivered_at=now)
        result = "delivered"
    elif now - d.window_start > timedelta(hours=settings.SSO_WEBHOOK_MAX_AGE_HOURS):
        WebhookDelivery.objects.filter(pk=d.pk).update(status="failed", attempts=attempts, last_status=status,
                                                       last_error=(error or f"http_{status}")[:200])
        result = "failed"
    else:
        WebhookDelivery.objects.filter(pk=d.pk).update(
            status="pending", attempts=attempts, last_status=status, last_error=(error or f"http_{status}")[:200],
            next_attempt_at=now + timedelta(seconds=backoff(attempts)))
        result = "retrying"
    level = logging.INFO if result == "delivered" else logging.WARNING
    logger.log(level, json.dumps({"event": "webhook_delivery", "delivery": d.pk, "event_id": d.event_id,
                                  "type": d.event.type, "client_id": client.client_id, "result": result,
                                  "status": status, "error": error, "attempt": attempts}, sort_keys=True))
    return result


def check_keys() -> WebhookEvent | None:
    """Emit ``keys.rotated`` when the published kid set differs from the last event's (first run: baseline)."""
    kids = sorted(k["kid"] for k in settings.SSO_KEYSET.jwks().get("keys", []))
    last = WebhookEvent.objects.filter(type="keys.rotated").order_by("-id").first()
    if last is not None and last.data.get("kids") == kids:
        return None
    return emit("keys.rotated", kids=kids)


def process_once(limit: int = 50) -> dict:
    counts: dict[str, int] = {}
    check_keys()
    for d in claim_due(limit):
        r = deliver(d)
        counts[r] = counts.get(r, 0) + 1
    return counts


def prune(days: int | None = None) -> int:
    cutoff = timezone.now() - timedelta(days=days if days is not None else settings.SSO_WEBHOOK_RETENTION_DAYS)
    old = WebhookEvent.objects.filter(created__lt=cutoff).exclude(deliveries__status__in=["pending", "sending"])
    keep_last_keys = WebhookEvent.objects.filter(type="keys.rotated").order_by("-id").values_list("pk", flat=True)[:1]
    return old.exclude(pk__in=list(keep_last_keys)).delete()[0]
