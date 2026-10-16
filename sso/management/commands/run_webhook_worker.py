"""v1.3c webhook worker: ``python manage.py run_webhook_worker [--once]`` (compose service ``webhooks``).

The long-running loop writes a heartbeat file after every iteration; ``docker/healthcheck.py --worker`` reads it
(the worker has no HTTP port, so the image's default /healthz probe cannot apply)."""
import json
import logging
import os
import signal
import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections, connection

from sso.webhooks import process_once

logger = logging.getLogger("sso.webhooks")

# Same path as HEARTBEAT_FILE in docker/healthcheck.py (/tmp is the container's tmpfs).
HEARTBEAT_FILE = "/tmp/sso-webhook-worker.heartbeat"


def write_heartbeat(path: str, ok: bool, error: str = "", last_ok: float | None = None) -> None:
    """Atomically record the loop's state: ``ts`` = this iteration, ``last_ok`` = last successful one."""
    now = time.time()
    data = {"ts": now, "ok": ok, "last_ok": now if ok else last_ok, "pid": os.getpid(), "error": error}
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError:
        logger.warning("webhook worker could not write heartbeat file %s", path, exc_info=True)


class Command(BaseCommand):
    help = "Deliver signed webhooks (at-least-once, backoff, 24 h)."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="process due deliveries once and exit")

    def handle(self, once=False, **options):
        stop = {"flag": False}

        def _on_sigterm(*_args):
            logger.info("webhook worker received SIGTERM, stopping after the current iteration")
            stop.update(flag=True)

        signal.signal(signal.SIGTERM, _on_sigterm)
        if not once:
            logger.info("webhook worker started pid=%s poll=%ss heartbeat=%s",
                        os.getpid(), settings.SSO_WEBHOOK_POLL_SECONDS, HEARTBEAT_FILE)
        last_ok = None
        failing = False
        while True:
            try:
                if not connection.in_atomic_block:  # never drop a caller's transaction (tests, call_command)
                    close_old_connections()
                counts = process_once()
                if once:
                    self.stdout.write(json.dumps(counts, sort_keys=True))
                    return
                if failing:
                    logger.info("webhook worker recovered")
                    failing = False
                if counts:
                    logger.info("webhook worker processed %s", json.dumps(counts, sort_keys=True))
                last_ok = time.time()
                write_heartbeat(HEARTBEAT_FILE, ok=True)
            except Exception as exc:  # noqa: BLE001 - DB down etc.: log, keep running (outbox loses nothing)
                logger.exception("webhook worker iteration failed")
                if once:
                    raise
                failing = True
                write_heartbeat(HEARTBEAT_FILE, ok=False, error=f"{exc.__class__.__name__}: {exc}"[:300],
                                last_ok=last_ok)
            if stop["flag"]:
                logger.info("webhook worker stopped")
                return
            time.sleep(settings.SSO_WEBHOOK_POLL_SECONDS)
