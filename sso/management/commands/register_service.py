"""Register a service in one step (design v1.2a §3.3): its app permission plus its ServiceClient.

    python manage.py register_service reporting --name "Reporting" --app app2 \
        [--app-name "Can use app2 (reporting)"] [--notify-url https://reporting.example.com/sso/events] \
        [--origin https://reporting.example.com]

* ``application.<app>`` is created if missing (``ensure_permission``, same as ``create_app_permission``) and
  linked through ``ServiceClient.app_codename``.
* The client secret is printed ONCE to stdout; only its hash is stored. An existing client_id is refused (use
  ``create_service_client <id> --rotate-secret`` to rotate, the admin to edit).
* ``--notify-url`` is stored for the v1.4 webhooks; nothing is sent yet. There is no notify secret in v1.2a.
"""
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from application.permissions import PREFIX, app_permissions, ensure_permission, validate_codename
from sso.models import ServiceClient


class Command(BaseCommand):
    help = "Create application.<app> (if missing) and a ServiceClient bound to it; print the client secret once."

    def add_arguments(self, parser):
        parser.add_argument("client_id")
        parser.add_argument("--name", default="")
        parser.add_argument("--app", required=True, help="permission codename, e.g. app2")
        parser.add_argument("--app-name", default="", help='permission description, e.g. "Can use app2 (reporting)"')
        parser.add_argument("--notify-url", default="")
        parser.add_argument("--origin", action="append", default=[], dest="origins")

    def handle(self, client_id, name, app, app_name, notify_url, origins, **options):
        app = app.removeprefix(PREFIX)
        try:
            validate_codename(app)
        except ValueError as exc:
            raise CommandError(str(exc)) from None
        if ServiceClient.objects.filter(client_id=client_id).exists():
            raise CommandError(f"ServiceClient {client_id!r} exists; rotate its secret with "
                               f"'create_service_client {client_id} --rotate-secret' or edit it in the admin.")
        name = name or client_id
        client = ServiceClient(client_id=client_id, name=name, app_codename=app, notify_url=notify_url or None,
                               allowed_origins=origins)
        secret = ServiceClient.generate_secret()
        client.set_secret(secret)
        try:
            client.full_clean()
        except ValidationError as exc:
            raise CommandError("; ".join(f"{k}: {' '.join(v)}" for k, v in exc.message_dict.items())) from None
        with transaction.atomic():
            existing = app_permissions().filter(codename=app).first()
            # an existing permission keeps its description unless --app-name is given
            description = app_name or (existing.name if existing else f"Can use {app} ({name})")
            perm, created = ensure_permission(app, description)
            client.save()
        self.stdout.write(f"client_id={client.client_id}\nclient_secret={secret}\n"
                          f"permission={PREFIX}{perm.codename}\n")
        self.stderr.write(f"{'Created' if created else 'Using existing'} permission {PREFIX}{perm.codename}. "
                          "Store the secret in the password manager now; it cannot be shown again. "
                          f"Grant {PREFIX}{perm.codename} to users or groups in the admin.")
