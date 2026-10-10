"""New tables owned by the SSO server (spec §9.2). Nothing here alters shared Django tables."""
from __future__ import annotations

import hashlib
import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
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
