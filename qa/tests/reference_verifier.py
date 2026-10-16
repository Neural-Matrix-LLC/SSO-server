"""Spec section 8.2 reference verifier, copied verbatim except that the JWKS is fetched by
the test harness (so a self-signed test certificate works) instead of PyJWKClient."""
from __future__ import annotations

import jwt


def verify_access_token(token: str, jwks: dict, issuer: str, audience: str) -> dict:
    hdr = jwt.get_unverified_header(token)
    keyset = jwt.PyJWKSet.from_dict(jwks)
    matches = [k for k in keyset.keys if k.key_id == hdr.get("kid")]
    if not matches:
        raise jwt.InvalidTokenError("unknown kid")
    key = matches[0].key
    claims = jwt.decode(token, key, algorithms=["RS256"],
                        audience=audience, issuer=issuer,
                        leeway=30, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
    if claims.get("token_type") != "access":
        raise jwt.InvalidTokenError("not an access token")
    return claims
