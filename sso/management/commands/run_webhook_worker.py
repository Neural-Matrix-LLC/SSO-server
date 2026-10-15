"""v1.3c webhook worker: ``python manage.py run_webhook_worker [--once]`` (compose service ``webhooks``)."""
import json
import logging
import signal
import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections

from sso.webhooks import process_once

logger = logging.getLogger("sso.webhooks")


class Command(BaseCommand):
    help = "Deliver signed webhooks (at-least-once, backoff, 24 h)."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="process due deliveries once and exit")

    def handle(self, once=False, **options):
        stop = {"flag": False}
        signal.signal(signal.SIGTERM, lambda *a: stop.update(flag=True))
        while True:
            try:
                close_old_connections()
                counts = process_once()
                if once:
                    self.stdout.write(json.dumps(counts, sort_keys=True))
                    return
            except Exception:  # noqa: BLE001 - DB down etc.: log, keep running (outbox loses nothing)
                logger.exception("webhook worker iteration failed")
                if once:
                    raise
            if stop["flag"]:
                return
            time.sleep(settings.SSO_WEBHOOK_POLL_SECONDS)
