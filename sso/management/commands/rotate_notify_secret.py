"""v1.3c: ``python manage.py rotate_notify_secret <client_id>`` prints a new webhook signing secret ONCE."""
from django.core.management.base import BaseCommand, CommandError

from sso.models import ServiceClient
from sso.webhook_secrets import encrypt, generate


class Command(BaseCommand):
    help = "Generate a new notify_secret for a service client (stored encrypted; shown once)."

    def add_arguments(self, parser):
        parser.add_argument("client_id")

    def handle(self, client_id, **options):
        client = ServiceClient.objects.filter(client_id=client_id, kind="service").first()
        if client is None:
            raise CommandError(f"unknown service client {client_id!r}")
        secret = generate()
        client.notify_secret_enc = encrypt(secret)
        client.save(update_fields=["notify_secret_enc"])
        self.stdout.write(f"notify_secret for {client_id}: {secret}")
        self.stdout.write("Copy it now; it is not shown again.")
