"""Container healthcheck.

Default (web, deployment plan R7): GET /healthz with the Host Django allows and X-Forwarded-Proto: https, so
neither ALLOWED_HOSTS nor SECURE_SSL_REDIRECT gets in the way.

``--worker`` (webhooks service): the worker has no HTTP port; check the heartbeat file it writes after every loop
iteration (sso/management/commands/run_webhook_worker.py). Unhealthy when the file is missing, or when the last
successful iteration is older than SSO_HEALTHCHECK_MAX_AGE seconds (default 300: one iteration may deliver up to 50
webhooks with a 5 s timeout each).

The reason is printed either way; ``docker inspect --format '{{json .State.Health}}' <container>`` shows it."""
import http.client
import json
import os
import sys
import time

# Same path as HEARTBEAT_FILE in run_webhook_worker.py.
HEARTBEAT_FILE = "/tmp/sso-webhook-worker.heartbeat"


def check_web() -> int:
    host = (os.environ.get("SSO_ALLOWED_HOSTS", "localhost").split(",")[0].strip() or "localhost").lstrip(".")
    port = int(os.environ.get("SSO_HEALTHCHECK_PORT", "8000"))
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        conn.request("GET", "/healthz", headers={"Host": host, "X-Forwarded-Proto": "https"})
        status = conn.getresponse().status
    except Exception as exc:  # noqa: BLE001
        print(f"healthcheck failed: {exc.__class__.__name__} on 127.0.0.1:{port}/healthz: {exc}", file=sys.stderr)
        return 1
    if status != 200:
        print(f"healthcheck failed: /healthz returned HTTP {status}", file=sys.stderr)
        return 1
    return 0


def check_worker(path: str = HEARTBEAT_FILE, now: float | None = None) -> int:
    max_age = float(os.environ.get("SSO_HEALTHCHECK_MAX_AGE", "300"))
    now = time.time() if now is None else now
    try:
        with open(path) as fh:
            hb = json.load(fh)
    except FileNotFoundError:
        print(f"worker healthcheck failed: no heartbeat file {path} (worker not started or still starting)",
              file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"worker healthcheck failed: unreadable heartbeat {path}: {exc}", file=sys.stderr)
        return 1
    last_ok = hb.get("last_ok")
    if last_ok is None or now - last_ok > max_age:
        since = "never" if last_ok is None else f"{now - last_ok:.0f}s ago"
        print(f"worker healthcheck failed: last successful iteration {since} (max {max_age:.0f}s), "
              f"last loop {now - hb.get('ts', 0):.0f}s ago, error: {hb.get('error') or '-'}", file=sys.stderr)
        return 1
    state = "ok" if hb.get("ok") else f"retrying after error: {hb.get('error')}"
    print(f"worker healthy: last successful iteration {now - last_ok:.0f}s ago, {state}")
    return 0


if __name__ == "__main__":
    sys.exit(check_worker() if "--worker" in sys.argv[1:] else check_web())
