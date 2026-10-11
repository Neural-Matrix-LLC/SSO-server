"""python manage.py create_app_permission <codename> "<description>"  (design A1)

Creates ``application.<codename>`` without a code change. Idempotent: running it again keeps the permission
(and its grants) and only updates the description.
"""
from django.core.management.base import BaseCommand, CommandError

from application.permissions import PREFIX, ensure_permission, validate_codename


class Command(BaseCommand):
    help = "Create (idempotently) the permission application.<codename> for a new application."

    def add_arguments(self, parser):
        parser.add_argument("codename", help="e.g. app2 (^[a-z][a-z0-9_]{1,62}$)")
        parser.add_argument("description", help='e.g. "Can use app2 (reporting)"')

    def handle(self, *args, codename, description, **options):
        try:
            validate_codename(codename)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        description = description.strip()
        if not description:
            raise CommandError("description must not be empty")
        perm, created = ensure_permission(codename, description)
        verb = "created" if created else "already exists (description updated if changed)"
        self.stdout.write(f"{PREFIX}{codename} {verb}: {perm.name}")
