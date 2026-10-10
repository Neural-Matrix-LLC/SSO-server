"""Shared test-data definitions.

Used both by the black-box tests and by fixtures/seed_test_data.py (which runs
inside the SSO server's Django shell to create these rows). Keep the two in sync
by importing from here only.

Every password hash is generated in *Django 4.1 format* (pbkdf2_sha256, 390000
iterations) unless the user exists to exercise another hash format. That proves
legacy myFinance hashes verify (Request R-02, addendum B14, spec section 11).
"""
from __future__ import annotations

import base64
import hashlib

DJANGO41_ITERATIONS = 390_000
DJANGO32_ITERATIONS = 260_000

DEFAULT_PASSWORD = "Qa-Passw0rd!2026"


def django_pbkdf2_sha256(password: str, salt: str, iterations: int = DJANGO41_ITERATIONS) -> str:
    """Byte-for-byte the algorithm of django.contrib.auth.hashers.PBKDF2PasswordHasher."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(dk).decode().strip()}"


def django_pbkdf2_sha1(password: str, salt: str, iterations: int = DJANGO41_ITERATIONS) -> str:
    dk = hashlib.pbkdf2_hmac("sha1", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha1${iterations}${salt}${base64.b64encode(dk).decode().strip()}"


def verify_django_pbkdf2(password: str, encoded: str) -> bool:
    """What Django 4.1 (myFinance) does to verify a pbkdf2 hash: iterations come from the hash."""
    algo, iterations, salt, digest = encoded.split("$", 3)
    hname = {"pbkdf2_sha256": "sha256", "pbkdf2_sha1": "sha1"}[algo]
    dk = hashlib.pbkdf2_hmac(hname, password.encode(), salt.encode(), int(iterations))
    return base64.b64encode(dk).decode().strip() == digest


GROUPS = ["qa_trader", "qa_beta"]

# username -> attributes. "password" is the plaintext the tests use; "hash" is what the
# seed script stores in auth_user.password (None = derive Django 4.1 hash from password).
USERS: dict[str, dict] = {
    "qa_alice": dict(email="qa_alice@example.test", first_name="Alice", last_name="Qa",
                     is_staff=False, is_active=True, groups=["qa_trader", "qa_beta"]),
    "qa_bob": dict(email="qa_bob@example.test", first_name="Bob", last_name="Qa",
                   is_staff=True, is_active=True, groups=[]),
    "qa_carol": dict(email="QA.Carol@Example.Test", first_name="Carol", last_name="Qa",
                     is_staff=False, is_active=True, groups=["qa_beta"]),
    "qa_inactive": dict(email="qa_inactive@example.test", is_active=False),
    "qa_dup1": dict(email="qa_dup@example.test"),
    "qa_dup2": dict(email="qa_dup@example.test"),
    "qa_noemail": dict(email=""),
    # dedicated users for tests that change state
    "qa_revoke": dict(email="qa_revoke@example.test"),
    "qa_disable": dict(email="qa_disable@example.test"),
    "qa_fresh": dict(email="qa_fresh@example.test", first_name="Fresh"),
    # legacy hash formats
    "qa_legacy41": dict(email="qa_legacy41@example.test", hash_kind="pbkdf2_sha256_390000"),
    "qa_rehash": dict(email="qa_rehash@example.test", hash_kind="pbkdf2_sha256_390000"),  # LEGACY-05 only
    "qa_legacy32": dict(email="qa_legacy32@example.test", hash_kind="pbkdf2_sha256_260000"),
    "qa_sha1": dict(email="qa_sha1@example.test", hash_kind="pbkdf2_sha1_390000"),
    "qa_malformed": dict(email="qa_malformed@example.test", hash_kind="malformed"),
    "qa_truncated": dict(email="qa_truncated@example.test", hash_kind="truncated"),
    "qa_unusable": dict(email="qa_unusable@example.test", hash_kind="unusable"),
    "qa_unknownalgo": dict(email="qa_unknownalgo@example.test", hash_kind="unknown_algo"),
    # throttling (each throttle test gets its own username)
    "qa_throttle1": dict(email="qa_throttle1@example.test"),
    "qa_throttle2": dict(email="qa_throttle2@example.test"),
    "qa_throttle3": dict(email="qa_throttle3@example.test"),
}
# Pool of interchangeable active users so the per-username login throttle (5/min) is
# not hit by ordinary functional tests.
POOL = [f"qa_user{n:02d}" for n in range(1, 13)]
for _u in POOL:
    USERS[_u] = dict(email=f"{_u}@example.test", groups=["qa_trader"])

for _name, _u in USERS.items():
    _u.setdefault("password", DEFAULT_PASSWORD)
    _u.setdefault("first_name", "")
    _u.setdefault("last_name", "")
    _u.setdefault("is_staff", False)
    _u.setdefault("is_active", True)
    _u.setdefault("groups", [])
    _u.setdefault("hash_kind", "pbkdf2_sha256_390000")


def password_hash_for(username: str) -> str:
    u = USERS[username]
    salt = ("qasalt" + username)[:22]
    kind = u["hash_kind"]
    if kind == "pbkdf2_sha256_390000":
        return django_pbkdf2_sha256(u["password"], salt, DJANGO41_ITERATIONS)
    if kind == "pbkdf2_sha256_260000":
        return django_pbkdf2_sha256(u["password"], salt, DJANGO32_ITERATIONS)
    if kind == "pbkdf2_sha1_390000":
        return django_pbkdf2_sha1(u["password"], salt, DJANGO41_ITERATIONS)
    if kind == "malformed":
        return "pbkdf2_sha256$notanumber$" + salt + "$AAAA"
    if kind == "truncated":
        return "pbkdf2_sha256$390000$" + salt  # missing digest
    if kind == "unusable":
        return "!qaUnusablePasswordXXXXXXXXXXXXXXXXXXXXX"  # Django UNUSABLE_PASSWORD_PREFIX
    if kind == "unknown_algo":
        return "nosuchalgo$1$" + salt + "$AAAA"
    raise ValueError(kind)


SERVICE_CLIENT_ID = "qa-service"
SERVICE_CLIENT_SECRET = "qa-service-secret-123456"
INACTIVE_SERVICE_CLIENT_ID = "qa-service-inactive"
INACTIVE_SERVICE_CLIENT_SECRET = "qa-inactive-secret-123456"
