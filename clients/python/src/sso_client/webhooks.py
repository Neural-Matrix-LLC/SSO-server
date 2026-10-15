"""v1.3c: verify SSO webhooks (docs/DESIGN-v1.3c-webhooks.md §5).

Signature: ``X-SSO-Signature: v1=<hex HMAC-SHA256(secret, ts + "." + raw_body)>`` with ``X-SSO-Timestamp`` (unix
seconds). Accept several secrets during a rotation. Deliveries are at-least-once: dedupe on ``id``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Iterable, Mapping
from typing import Any

import threading
from collections import OrderedDict
from .errors import SSOError

TOLERANCE = 300


class WebhookVerificationError(SSOError):
    """Bad or missing signature, stale timestamp or malformed body: answer 400/401, do not process."""


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def verify_webhook(body: bytes, headers: Mapping[str, str], secrets: str | Iterable[str],
                   tolerance: int = TOLERANCE, now: float | None = None) -> dict[str, Any]:
    """Return the parsed event or raise WebhookVerificationError. ``body`` must be the raw request bytes."""
    if isinstance(secrets, str):
        secrets = [secrets]
    secrets = [s for s in secrets if s]
    if not secrets:
        raise WebhookVerificationError("no webhook secret configured")
    sig, ts = _header(headers, "X-SSO-Signature"), _header(headers, "X-SSO-Timestamp")
    if not sig or not ts or not ts.strip().isdigit():
        raise WebhookVerificationError("missing signature headers")
    if abs((time.time() if now is None else now) - int(ts)) > tolerance:
        raise WebhookVerificationError("timestamp outside tolerance")
    msg = ts.strip().encode() + b"." + body
    given = [p.strip() for p in sig.split(",")]
    ok = any(hmac.compare_digest("v1=" + hmac.new(s.encode(), msg, hashlib.sha256).hexdigest(), g)
             for s in secrets for g in given)
    if not ok:
        raise WebhookVerificationError("signature mismatch")
    try:
        event = json.loads(body)
    except ValueError:
        raise WebhookVerificationError("body is not JSON") from None
    if not isinstance(event, dict) or "id" not in event or "type" not in event:
        raise WebhookVerificationError("not an SSO event")
    return event


class WebhookReceiver:
    """Verify + dedupe + dispatch. ``handle()`` returns the event, or None for a duplicate (still answer 2xx)."""

    def __init__(self, secrets: str | Iterable[str], tolerance: int = TOLERANCE, dedupe_ttl: float = 86400 * 2,
                 dedupe_size: int = 100_000):
        self.secrets = [secrets] if isinstance(secrets, str) else list(secrets)
        self.tolerance = tolerance
        self._ttl, self._size = dedupe_ttl, dedupe_size
        self._seen: OrderedDict[str, float] = OrderedDict()  # in-process only; use a shared store across replicas
        self._lock = threading.Lock()
        self._handlers: dict[str, list] = {}

    def on(self, event_type: str):
        def deco(fn):
            self._handlers.setdefault(event_type, []).append(fn)
            return fn
        return deco

    def handle(self, body: bytes, headers: Mapping[str, str]) -> dict[str, Any] | None:
        event = verify_webhook(body, headers, self.secrets, self.tolerance)
        key = str(event["id"])
        now = time.time()
        with self._lock:
            until = self._seen.get(key)
            if until is not None and until > now:
                return None
        for fn in self._handlers.get(event["type"], []) + self._handlers.get("*", []):
            fn(event)
        with self._lock:  # only after the handlers succeeded: a failure gets retried
            self._seen[key] = now + self._ttl
            self._seen.move_to_end(key)
            while len(self._seen) > self._size:
                self._seen.popitem(last=False)
        return event
