"""RSA key loading, ``kid`` computation and JWKS rendering (spec §5.3, addendum B.6).

This module is imported from ``settings.py`` so it must not touch Django models or settings.
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field

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
    """Read a key file, telling "missing" apart from "there but not readable by this uid".

    ``Path.is_file()`` returns False on EACCES too, which used to report a mis-owned key (e.g. a host
    uid 1000 file in a uid 10001 container) as "not found". Messages never contain key material.
    """
    if not path:
        raise KeyConfigError(f"{what} not found: {path!r}. Generate keys with scripts/gen_keys.sh.")
    hint = "chown to SSO_UID:SSO_GID or set SSO_UID"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise KeyConfigError(f"{what} not found: {path!r}. Generate keys with scripts/gen_keys.sh.") from None
    except PermissionError:
        parent = os.path.dirname(os.path.abspath(path))
        raise KeyConfigError(
            f"{what} {path!r} cannot be reached by uid {os.geteuid()}: a parent directory (e.g. {parent!r}) "
            f"is not accessible; {hint}") from None
    except OSError as exc:
        raise KeyConfigError(f"{what} is not readable: {path!r} ({exc.strerror})") from None
    if not stat.S_ISREG(st.st_mode):
        raise KeyConfigError(f"{what} {path!r} is not a regular file")
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except PermissionError:
        raise KeyConfigError(f"{what} {path!r} exists but is not readable by uid {os.geteuid()}; {hint}") from None
    except OSError as exc:  # pragma: no cover - e.g. EIO; environment specific
        raise KeyConfigError(f"{what} is not readable: {path!r} ({exc.strerror})") from None


def load_private_key(path: str, origin: str = "SSO_JWT_PRIVATE_KEY") -> rsa.RSAPrivateKey:
    data = _read(path, f"JWT private key ({origin})")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise KeyConfigError(f"JWT private key {path!r} is not an unencrypted PEM key") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyConfigError(f"JWT private key {path!r} is not an RSA key")
    if key.key_size < 2048:
        raise KeyConfigError(f"JWT private key {path!r} is {key.key_size} bits; need >= 2048")
    return key


def load_public_key(path: str, origin: str = "SSO_JWT_PUBLIC_KEYS") -> rsa.RSAPublicKey:
    data = _read(path, f"JWT public key ({origin})")
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


def load_keyset(private_path: "str | KeyFile",
                public_paths: "list[str] | list[KeyFile] | tuple[KeyFile, ...]") -> KeySet:
    """Load the signing key and all published public keys from disk (fail fast). Accepts plain paths or the
    :class:`KeyFile` entries of :func:`resolve_key_config` (whose origin then appears in error messages)."""
    priv = private_path if isinstance(private_path, KeyFile) else KeyFile(private_path, "SSO_JWT_PRIVATE_KEY")
    private_key = load_private_key(priv.path, priv.origin)
    publics = []
    for p in public_paths:
        kf = p if isinstance(p, KeyFile) else KeyFile(p, "SSO_JWT_PUBLIC_KEYS")
        if kf.path:
            publics.append(load_public_key(kf.path, kf.origin))
    return build_keyset(private_key, publics)


# --------------------------------------------------------------------------- key file configuration
DEFAULT_KEYS_MOUNT = "/run/keys"
#: deprecated variable -> its replacement
DEPRECATED_KEY_VARS = {
    "SSO_JWT_PRIVATE_KEY_PATH": "SSO_JWT_PRIVATE_KEY",
    "SSO_JWT_PUBLIC_KEY_PATHS": "SSO_JWT_PUBLIC_KEYS",
    "SSO_JWT_PUBLIC_KEY_PATH": "SSO_JWT_PUBLIC_KEYS",
}


class KeyConfigConflict(KeyConfigError):
    """The old and the new form of the same key setting are both set. Always fatal (also with SSO_DEBUG)."""


@dataclass(frozen=True)
class KeyFile:
    path: str
    origin: str  # how the path was built, for error messages


@dataclass(frozen=True)
class KeyConfig:
    private: KeyFile
    publics: tuple[KeyFile, ...]
    mount: str
    mount_source: str  # "SSO_JWT_KEYS_MOUNT", "SSO_KEYS_DIR" or "default"
    deprecated: tuple[str, ...]  # old variables that were used


def keys_mount(env: Mapping[str, str]) -> tuple[str, str]:
    """Directory key *names* are resolved in. Precedence: SSO_JWT_KEYS_MOUNT (explicit) > SSO_KEYS_DIR >
    /run/keys. A relative directory is resolved against the working directory. docker-compose.yml sets
    SSO_JWT_KEYS_MOUNT=/run/keys for web, so the host SSO_KEYS_DIR that env_file passes in never wins there."""
    for var in ("SSO_JWT_KEYS_MOUNT", "SSO_KEYS_DIR"):
        value = (env.get(var) or "").strip()
        if value:
            return os.path.abspath(value), var
    return DEFAULT_KEYS_MOUNT, "default"


def _resolve(var: str, value: str, mount: str, mount_source: str) -> KeyFile:
    if "/" in value:  # a path, as before: absolute, or relative to the working directory
        path = os.path.abspath(value)
        how = f"{var}={value!r} is a path"
        if not os.path.isabs(value):
            how += f" relative to the working directory {os.getcwd()!r}"
        return KeyFile(path, how)
    where = f"{mount_source}={mount!r}" if mount_source != "default" else f"the default mount {mount!r}"
    return KeyFile(os.path.join(mount, value), f"{var}={value!r} in {where}")


def _names(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def resolve_key_config(env: Mapping[str, str]) -> KeyConfig:
    """Turn the key environment variables into file paths (README "Docker quick start" step 3, §3).

    New form: SSO_JWT_PRIVATE_KEY (a file name) and SSO_JWT_PUBLIC_KEYS (comma-separated file names), joined to
    :func:`keys_mount`. A value containing '/' is a path instead (absolute, or relative to the working
    directory). Old form (deprecated): SSO_JWT_PRIVATE_KEY_PATH, SSO_JWT_PUBLIC_KEY_PATHS (and the v1.0
    singular SSO_JWT_PUBLIC_KEY_PATH), used verbatim as before. Old and new form of the same setting together
    raise :class:`KeyConfigConflict`. An unset private key resolves to path "" (= "not found").
    """
    get = lambda var: (env.get(var) or "").strip()  # noqa: E731
    mount, mount_source = keys_mount(env)
    deprecated: list[str] = []

    if get("SSO_JWT_PRIVATE_KEY") and get("SSO_JWT_PRIVATE_KEY_PATH"):
        raise KeyConfigConflict("Both SSO_JWT_PRIVATE_KEY and the deprecated SSO_JWT_PRIVATE_KEY_PATH are set; "
                                "keep only SSO_JWT_PRIVATE_KEY (a file name in the keys mount).")
    old_publics = [v for v in ("SSO_JWT_PUBLIC_KEY_PATHS", "SSO_JWT_PUBLIC_KEY_PATH") if get(v)]
    if get("SSO_JWT_PUBLIC_KEYS") and old_publics:
        raise KeyConfigConflict(f"Both SSO_JWT_PUBLIC_KEYS and the deprecated {old_publics[0]} are set; "
                                "keep only SSO_JWT_PUBLIC_KEYS (comma-separated file names in the keys mount).")

    if get("SSO_JWT_PRIVATE_KEY"):
        private = _resolve("SSO_JWT_PRIVATE_KEY", get("SSO_JWT_PRIVATE_KEY"), mount, mount_source)
    elif get("SSO_JWT_PRIVATE_KEY_PATH"):
        deprecated.append("SSO_JWT_PRIVATE_KEY_PATH")
        private = KeyFile(get("SSO_JWT_PRIVATE_KEY_PATH"), "SSO_JWT_PRIVATE_KEY_PATH, deprecated")
    else:
        private = KeyFile("", "SSO_JWT_PRIVATE_KEY is not set")

    if get("SSO_JWT_PUBLIC_KEYS"):
        publics = [_resolve("SSO_JWT_PUBLIC_KEYS", n, mount, mount_source) for n in _names(get("SSO_JWT_PUBLIC_KEYS"))]
    elif old_publics:
        var = old_publics[0]  # PATHS wins over the singular, as before
        deprecated.append(var)
        publics = [KeyFile(p, f"{var}, deprecated") for p in _names(get(var))]
    else:
        publics = []
    return KeyConfig(private, tuple(publics), mount, mount_source, tuple(deprecated))


def generate_ephemeral_keyset() -> KeySet:
    """Throw-away key for SSO_DEBUG=True when no key files exist. Never used in production."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return build_keyset(key, [])
