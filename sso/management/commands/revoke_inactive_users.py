"""Revoke the tokens of every inactive user that still has tokens that are not revoked.

    python manage.py revoke_inactive_users [--dry-run]

For suspensions that bypassed the model signal (``QuerySet.update()``, myFinance writing ``auth_user``).
Safe to run repeatedly (schedule it hourly); users whose tokens are already all revoked are skipped.
v1.2b: also prunes ``sso_revokedsession`` rows older than the refresh-token lifetime + 1 day.
"""
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from sso.revocation import prune_revoked_sessions, revoke_user_tokens


class Command(BaseCommand):
    help = "Revoke all tokens of inactive users that still hold live (unrevoked) refresh tokens."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, dry_run, **options):
        live = OutstandingToken.objects.filter(user=OuterRef("pk"), expires_at__gt=timezone.now(),
                                               blacklistedtoken__isnull=True)
        # live refresh tokens, or a login (hence possibly an access token) after the last revocation
        logged_in_since = Q(last_login__isnull=False) & (
            Q(sso_token_revocation__isnull=True) | Q(sso_token_revocation__revoked_at__lt=F("last_login")))
        users = (User.objects.filter(is_active=False).annotate(_live=Exists(live))
                 .filter(Q(_live=True) | logged_in_since))
        count = 0
        for user in users:
            count += 1
            if not dry_run:
                revoke_user_tokens(user)
        verb = "would revoke" if dry_run else "revoked"
        self.stdout.write(f"{verb} tokens of {count} inactive user(s)")
        pruned = prune_revoked_sessions(dry_run=dry_run)
        self.stdout.write(f"{'would prune' if dry_run else 'pruned'} {pruned} expired revoked-session row(s)")
        if not dry_run:  # v1.3a: expired step-up tokens
            from sso.stepup import prune_expired

            self.stdout.write(f"pruned {prune_expired()} expired admin reauth row(s)")
