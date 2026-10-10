"""Register (or rotate the secret of) a ServiceClient from the command line.

    python manage.py create_service_client rebalance-api --name "Rebalance API"
    python manage.py create_service_client rebalance-api --rotate-secret

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

    def handle(self, client_id, name, rotate_secret, origins, **options):
        client = ServiceClient.objects.filter(client_id=client_id).first()
        if client and not rotate_secret:
            raise CommandError(f"ServiceClient {client_id!r} exists; use --rotate-secret to issue a new secret.")
        if client is None:
            if rotate_secret:
                raise CommandError(f"ServiceClient {client_id!r} does not exist.")
            client = ServiceClient(client_id=client_id, name=name or client_id, allowed_origins=origins)
        secret = ServiceClient.generate_secret()
        client.set_secret(secret)
        client.full_clean()
        client.save()
        self.stdout.write(f"client_id={client.client_id}\nclient_secret={secret}\n")
        self.stderr.write("Store the secret in the password manager now; it cannot be shown again.")
