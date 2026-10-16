import hashlib
import hmac
import json
import time

import pytest

from sso_client import WebhookReceiver, WebhookVerificationError, verify_webhook


def signed(secret, event, ts=None):
    body = json.dumps(event).encode()
    ts = str(int(time.time()) if ts is None else ts)
    sig = "v1=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return body, {"x-sso-signature": sig, "X-SSO-Timestamp": ts}


EV = {"id": 7, "type": "user.suspended", "time": "2026-10-15T00:00:00Z", "sub": "42"}


def test_verify_ok_and_rotation():
    body, h = signed("new", EV)
    assert verify_webhook(body, h, ["old", "new"])["sub"] == "42"


@pytest.mark.parametrize("mut", ["secret", "body", "stale", "nohdr", "nosecret"])
def test_verify_rejects(mut):
    body, h = signed("s", EV, ts=int(time.time()) - 400 if mut == "stale" else None)
    secrets = ["s"]
    if mut == "secret":
        secrets = ["x"]
    if mut == "body":
        body = body.replace(b"42", b"43")
    if mut == "nohdr":
        h = {}
    if mut == "nosecret":
        secrets = []
    with pytest.raises(WebhookVerificationError):
        verify_webhook(body, h, secrets)


def test_receiver_dedupes_and_retries_after_handler_error():
    r = WebhookReceiver("s")
    seen, fail = [], [True]

    @r.on("user.suspended")
    def h(ev):
        if fail.pop() if fail else False:
            raise RuntimeError
        seen.append(ev["id"])

    body, hd = signed("s", EV)
    with pytest.raises(RuntimeError):
        r.handle(body, hd)
    assert r.handle(body, hd)["id"] == 7
    assert r.handle(body, hd) is None
    assert seen == [7]
