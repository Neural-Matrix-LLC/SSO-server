"""New tables owned by the SSO server (spec §9.2). Nothing here alters shared Django tables."""
from __future__ import annotations

import hashlib
import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.validators import URLValidator
from django.db import models
from django.utils import timezone


class ServiceClient(models.Model):
    """A registered back-end service (introspection) or, in phase 5, an OAuth client."""

    client_id = models.SlugField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    client_secret_hash = models.CharField(max_length=256, editable=False)
    redirect_uris = models.JSONField(default=list, blank=True, help_text="Phase 5 (PKCE). JSON list of exact URIs.")
    allowed_origins = models.JSONField(default=list, blank=True, help_text="Informational in sprint 1; CORS uses SSO_CORS_ALLOWED_ORIGINS.")
    is_active = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    # v1.2a (design §3.2). Nullable on purpose: a previous image (rollback) inserts rows without these columns,
    # and Django 4.2 has no db_default, so NOT NULL columns would break its INSERTs on MySQL.
    app_codename = models.CharField(
        max_length=63, null=True, blank=True,
        help_text="The application.<codename> permission a user needs to use this service, e.g. app2.")
    notify_url = models.URLField(
        max_length=500, null=True, blank=True, validators=[URLValidator(schemes=["https"])],
        help_text="HTTPS webhook endpoint (v1.4; stored only, nothing is sent yet).")
    # v1.3a per-service credentials (design §6): the client's own application.* grants (service tokens), and
    # the time of the last secret rotation (service tokens issued before it are inactive).
    permissions = models.ManyToManyField(
        "auth.Permission", blank=True, related_name="sso_service_clients",
        db_table="sso_serviceclient_permissions",
        help_text="application.* permissions of this service client (perms of its service tokens).")
    secret_rotated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["client_id"]

    def __str__(self) -> str:
        return f"{self.client_id} ({self.name})"

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_urlsafe(32)

    def set_secret(self, raw: str) -> None:
        self.client_secret_hash = make_password(raw)

    def check_secret(self, raw: str) -> bool:
        return bool(self.client_secret_hash) and check_password(raw, self.client_secret_hash)


class UserTokenRevocation(models.Model):
    """Tokens of ``user`` issued before ``revoked_at`` are invalid (introspect + refresh)."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sso_token_revocation"
    )
    revoked_at = models.DateTimeField()

    def __str__(self) -> str:
        return f"{self.user_id} revoked at {self.revoked_at.isoformat()}"

    @classmethod
    def revoke(cls, user) -> "UserTokenRevocation":
        obj, _ = cls.objects.update_or_create(user=user, defaults={"revoked_at": timezone.now()})
        # keep the cached reverse relation in sync for the caller
        user.sso_token_revocation = obj
        return obj


class AuthorizationCode(models.Model):
    """Phase 5 (auth code + PKCE, spec §6.8). Created now so the schema is ready; unused in sprint 1."""

    code_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(ServiceClient, on_delete=models.CASCADE, related_name="authorization_codes")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sso_authorization_codes")
    redirect_uri = models.CharField(max_length=500)
    code_challenge = models.CharField(max_length=128)
    code_challenge_method = models.CharField(max_length=10, default="S256")
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def hash_code(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        return f"code for {self.client_id}/{self.user_id}"


class RevokedSession(models.Model):
    """A revoked login session (design §4.2 "Session"): every token carrying ``sid`` is dead.

    Rows exist only for revoked sessions (refresh-token reuse; v1.2b adds IP-binding mismatches). Live
    sessions need no row: their refresh tokens are found through ``OutstandingToken`` and the ``sid`` claim.
    """

    sid = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sso_revoked_sessions")
    revoked_at = models.DateTimeField(default=timezone.now)
    reason = models.CharField(max_length=32)

    def __str__(self) -> str:
        return f"session {self.sid} of {self.user_id} revoked ({self.reason})"


class AdminReauth(models.Model):
    """Step-up re-authentication (v1.3a design §3.3). Only the SHA-256 of the token is stored."""

    token_hash = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sso_admin_reauths")
    sid = models.CharField(max_length=64, blank=True, default="")
    ip = models.CharField(max_length=64, blank=True, default="")
    created = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

    @staticmethod
    def hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        return f"reauth of {self.user_id} until {self.expires_at.isoformat()}"


class AdminAuditLog(models.Model):
    """Audit trail of admin changes (v1.3a design §8). No foreign keys: rows outlive deleted users/services."""

    ts = models.DateTimeField(default=timezone.now, db_index=True)
    actor_type = models.CharField(max_length=16)  # user | service | system
    actor_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    actor_ip = models.CharField(max_length=64, blank=True, default="")
    action = models.CharField(max_length=64, db_index=True)
    target_type = models.CharField(max_length=32, blank=True, default="")
    target_id = models.CharField(max_length=191, blank=True, default="")
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    request_id = models.CharField(max_length=64, blank=True, default="")
    result = models.CharField(max_length=16, default="ok")  # ok | denied | error
    stepup = models.BooleanField(default=False)

    class Meta:
        ordering = ["-ts", "-id"]
        indexes = [models.Index(fields=["target_type", "target_id"], name="sso_audit_target_idx")]

    def __str__(self) -> str:
        return f"{self.ts.isoformat()} {self.actor_type}:{self.actor_id} {self.action} {self.target_type}:{self.target_id}"
