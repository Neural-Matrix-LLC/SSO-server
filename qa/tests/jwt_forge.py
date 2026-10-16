"""Helpers to inspect real tokens and mint forged/attack JWTs for security tests."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jdump(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def header(token: str) -> dict:
    return json.loads(b64url_decode(token.split(".")[0]))


def payload(token: str) -> dict:
    return json.loads(b64url_decode(token.split(".")[1]))


def assemble(hdr: dict, pl: dict, signature: bytes = b"") -> str:
    return f"{b64url(jdump(hdr))}.{b64url(jdump(pl))}.{b64url(signature)}"


# ---- attacks ------------------------------------------------------------------------
def alg_none(pl: dict, alg: str = "none", kid: str | None = None, signature: bytes = b"") -> str:
    hdr = {"alg": alg, "typ": "JWT"}
    if kid:
        hdr["kid"] = kid
    return assemble(hdr, pl, signature)


def hs256_with_secret(pl: dict, secret: bytes, kid: str | None = None, alg: str = "HS256") -> str:
    """HMAC-sign with an arbitrary secret (PyJWT refuses PEM secrets, so do it by hand)."""
    hdr = {"alg": alg, "typ": "JWT"}
    if kid:
        hdr["kid"] = kid
    signing_input = f"{b64url(jdump(hdr))}.{b64url(jdump(pl))}".encode()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret, signing_input, digest).digest()
    return signing_input.decode() + "." + b64url(sig)


def public_key_secret_variants(pub) -> dict[str, bytes]:
    """The byte strings a vulnerable verifier might use as an HMAC secret."""
    spki_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pkcs1_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    spki_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "spki_pem": spki_pem,
        "spki_pem_nonewline": spki_pem.rstrip(b"\n"),
        "pkcs1_pem": pkcs1_pem,
        "spki_der": spki_der,
    }


def tamper_signature(token: str) -> str:
    h, p, s = token.split(".")
    sig = bytearray(b64url_decode(s))
    sig[len(sig) // 2] ^= 0x01
    return f"{h}.{p}.{b64url(bytes(sig))}"


def tamper_payload(token: str, **changes) -> str:
    h, _, s = token.split(".")
    pl = payload(token)
    pl.update(changes)
    return f"{h}.{b64url(jdump(pl))}.{s}"


def new_rsa_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def sign(pl: dict, private_key, kid: str | None, alg: str = "RS256", extra_headers: dict | None = None) -> str:
    headers = dict(extra_headers or {})
    if kid is not None:
        headers["kid"] = kid
    return jwt.encode(pl, private_key, algorithm=alg, headers=headers)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_jwk(pub, kid: str) -> dict:
    nums = pub.public_numbers()
    to_b64 = lambda i: b64url(i.to_bytes((i.bit_length() + 7) // 8, "big"))  # noqa: E731
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": to_b64(nums.n), "e": to_b64(nums.e)}


# ---- JWKS helpers -------------------------------------------------------------------
def jwk_to_public_key(jwk: dict):
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e, n).public_key()


def kid_spki(pub) -> str:
    """Spec 5.3: first 16 hex chars of SHA-256 of the public key's DER (SubjectPublicKeyInfo)."""
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def kid_pkcs1(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return hashlib.sha256(der).hexdigest()[:16]


def claims_like(real_access_token: str, **overrides) -> dict:
    """Copy of a real access token's claims with a fresh jti/iat/exp, then overrides applied
    (pass value=None to delete a claim)."""
    now = int(time.time())
    pl = payload(real_access_token)
    pl.update({"jti": uuid.uuid4().hex, "iat": now, "exp": now + 600})
    for k, v in overrides.items():
        if v is None:
            pl.pop(k, None)
        else:
            pl[k] = v
    return pl
