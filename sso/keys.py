"""RSA key loading, ``kid`` computation and JWKS rendering (spec §5.3, addendum B.6).

This module is imported from ``settings.py`` so it must not touch Django models or settings.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyConfigError(Exception):
    """Raised when key files are missing or unusable. Message is safe to show operators."""


@dataclass(frozen=True)
class PublicKey:
    kid: str
    pem: str
    key: rsa.RSAPublicKey = field(repr=False, compare=False)

    def to_jwk(self) -> dict:
        numbers = self.key.public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": _b64uint(numbers.n),
            "e": _b64uint(numbers.e),
        }


@dataclass(frozen=True)
class KeySet:
    """The signing key plus every public key that must be published / accepted."""

    signing_kid: str
    signing_pem: str = field(repr=False)
    public_keys: tuple[PublicKey, ...]

    @property
    def signing_public(self) -> PublicKey:
        return self.by_kid(self.signing_kid)

    def by_kid(self, kid: str) -> PublicKey | None:
        for pk in self.public_keys:
            if pk.kid == kid:
                return pk
        return None

    def jwks(self) -> dict:
        return {"keys": [pk.to_jwk() for pk in self.public_keys]}


def _b64uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compute_kid(public_key: rsa.RSAPublicKey) -> str:
    """First 16 hex chars of SHA-256 over the DER SubjectPublicKeyInfo (spec §5.3)."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:16]


def _public_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def _read(path: str, what: str) -> bytes:
    p = Path(path)
    if not path or not p.is_file():
        raise KeyConfigError(f"{what} not found: {path!r}. Generate keys with scripts/gen_keys.sh.")
    try:
        return p.read_bytes()
    except OSError as exc:  # pragma: no cover - permission problems are environment specific
        raise KeyConfigError(f"{what} is not readable: {path!r} ({exc.strerror})") from exc


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    data = _read(path, "JWT private key (SSO_JWT_PRIVATE_KEY_PATH)")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise KeyConfigError(f"JWT private key {path!r} is not an unencrypted PEM key") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyConfigError(f"JWT private key {path!r} is not an RSA key")
    if key.key_size < 2048:
        raise KeyConfigError(f"JWT private key {path!r} is {key.key_size} bits; need >= 2048")
    return key


def load_public_key(path: str) -> rsa.RSAPublicKey:
    data = _read(path, "JWT public key (SSO_JWT_PUBLIC_KEY_PATHS)")
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise KeyConfigError(f"JWT public key {path!r} is not a PEM public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyConfigError(f"JWT public key {path!r} is not an RSA key")
    return key


def _private_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def build_keyset(private_key: rsa.RSAPrivateKey, public_keys: list[rsa.RSAPublicKey]) -> KeySet:
    """Signing key's own public key is always published first; duplicates are dropped."""
    signing_pub = private_key.public_key()
    ordered: list[PublicKey] = []
    seen: set[str] = set()
    for pub in [signing_pub, *public_keys]:
        kid = compute_kid(pub)
        if kid in seen:
            continue
        seen.add(kid)
        ordered.append(PublicKey(kid=kid, pem=_public_pem(pub), key=pub))
    return KeySet(
        signing_kid=compute_kid(signing_pub),
        signing_pem=_private_pem(private_key),
        public_keys=tuple(ordered),
    )


def load_keyset(private_path: str, public_paths: list[str]) -> KeySet:
    """Load the signing key and all published public keys from disk (fail fast)."""
    private_key = load_private_key(private_path)
    publics = [load_public_key(p) for p in public_paths if p]
    return build_keyset(private_key, publics)


def generate_ephemeral_keyset() -> KeySet:
    """Throw-away key for SSO_DEBUG=True when no key files exist. Never used in production."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return build_keyset(key, [])
