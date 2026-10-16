"""Register (or rotate the secret of) a ServiceClient from the command line.

    python manage.py create_service_client rebalance-api --name "Rebalance API"
    python manage.py create_service_client rebalance-api --rotate-secret
    python manage.py create_service_client reporting --app app2     # link to application.app2 (must exist)

Prefer ``register_service`` for a new service (creates the permission too).

The plaintext secret is printed once to stdout; only its hash is stored.
"""
from django.core.management.base import BaseCommand, CommandError

from sso.models import ServiceClient


class Command(BaseCommand):
    help = "Create a ServiceClient (or rotate its secret) and print the client secret once."

    def add_arguments(self, parser):
        parser.add_argument("client_id")
        parser.add_argument("--name", default="")
        parser.add_argument("--rotate-secret", action="store_true")
        parser.add_argument("--origin", action="append", default=[], dest="origins")
        parser.add_argument("--app", default="", help="link to an EXISTING application.<codename> permission")

    def handle(self, client_id, name, rotate_secret, origins, app="", **options):
        app = (app or "").removeprefix("application.")
        if app:
            from application.permissions import app_permissions

            if not app_permissions().filter(codename=app).exists():
                raise CommandError(f"application.{app} does not exist; use register_service or create_app_permission.")
        client = ServiceClient.objects.filter(client_id=client_id).first()
        if client and not rotate_secret:
            raise CommandError(f"ServiceClient {client_id!r} exists; use --rotate-secret to issue a new secret.")
        if client is None:
            if rotate_secret:
                raise CommandError(f"ServiceClient {client_id!r} does not exist.")
            client = ServiceClient(client_id=client_id, name=name or client_id, allowed_origins=origins)
        if app:
            client.app_codename = app
        secret = ServiceClient.generate_secret()
        client.set_secret(secret)
        client.full_clean()
        client.save()
        self.stdout.write(f"client_id={client.client_id}\nclient_secret={secret}\n")
        self.stderr.write("Store the secret in the password manager now; it cannot be shown again.")
