"""Request/response serializers (spec §6.1, §6.5)."""
from __future__ import annotations

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import serializers

from .logs import log_stored_hash_error
from application.permissions import user_app_perms

from .tokens import user_groups


class UserSerializer(serializers.ModelSerializer):
    groups = serializers.SerializerMethodField()
    perms = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "is_staff", "groups", "perms"]
        read_only_fields = fields

    def get_groups(self, user: User) -> list[str]:
        return user_groups(user)

    def get_perms(self, user: User) -> list[str]:
        return user_app_perms(user)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=254, trim_whitespace=True)
    password = serializers.CharField(max_length=4096, trim_whitespace=False)
    client = serializers.ChoiceField(choices=["browser", "native"], default="browser", required=False)


class RefreshInputSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False, allow_blank=False, max_length=8192)


class IntrospectSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=8192)
    # v1.2b (design §4.4): client IP observed by the service; unparseable = no IP (a mismatch when bound).
    # V12B-01: a non-string or over-long (> 128 chars) value is also "no IP", never a 400.
    ip = serializers.JSONField(required=False, allow_null=True)
    # optional: "application.app2" or a list; the response adds "allowed" (all of them held)
    require = serializers.JSONField(required=False)
    # v1.3b on-behalf-of (DESIGN-v1.3b §5): the calling service's own service token
    actor_token = serializers.CharField(required=False, max_length=8192)

    def validate_ip(self, value):
        if not isinstance(value, str) or len(value) > 128:
            return None
        return value

    def validate_require(self, value):
        items = [value] if isinstance(value, str) else value
        if not isinstance(items, list) or not items or len(items) > 50 or not all(
                isinstance(i, str) and 0 < len(i) <= 255 for i in items):
            raise serializers.ValidationError("require must be a permission name or a list of them.")
        return items


def _dummy_hash(password: str) -> None:
    """Burn the same time as a real password check (Django's ModelBackend does the same)."""
    User().set_password(password)


def check_credentials(request, identifier: str, password: str) -> User | None:
    """Return the user if the password is right (active or not), else None.

    * ``identifier`` containing ``@`` is looked up by ``email__iexact``; zero or several matches,
      or an empty email, never match (addendum B.5).
    * Every failure path runs exactly one password hash, so response time does not reveal
      whether the account exists (addendum B.4).
    * ``authenticate()`` (AllowAllUsersModelBackend) also performs Django's transparent re-hash
      of legacy PBKDF2 hashes and fires ``user_login_failed``.
    """
    username = identifier
    if "@" in identifier:
        matches = list(
            User.objects.filter(email__iexact=identifier).exclude(email="").values_list("username", flat=True)[:2]
        )
        if len(matches) != 1:
            _dummy_hash(password)
            return None
        username = matches[0]
    try:
        return authenticate(request, username=username, password=password)
    except (ValueError, TypeError):
        # A malformed/truncated stored hash (e.g. "pbkdf2_sha256$notanumber$..." or a missing digest)
        # makes Django's hasher raise. Treat it as a failed login: same hash cost, same 401 answer
        # (no account-existence signal), plus an operator log line so the row can be fixed.
        _dummy_hash(password)
        log_stored_hash_error(request, username)
        return None
