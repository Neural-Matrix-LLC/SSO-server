"""v1.3c: ``notify_secret`` encrypted at rest (Fernet). Key: ``SSO_WEBHOOK_SECRET_KEY`` (urlsafe base64 of 32
bytes) or, if unset, HKDF-SHA256 of ``SSO_SECRET_KEY`` (then rotating SECRET_KEY makes stored secrets unreadable:
set the dedicated key in production)."""
from __future__ import annotations

import base64
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings


def _fernet() -> Fernet:
    key = settings.SSO_WEBHOOK_SECRET_KEY
    if not key:
        raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sso-webhook-secret-v1", info=b"notify_secret").derive(
            settings.SECRET_KEY.encode("utf-8"))
        key = base64.urlsafe_b64encode(raw).decode()
    return Fernet(key)


def encrypt(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def generate() -> str:
    return secrets.token_urlsafe(32)
