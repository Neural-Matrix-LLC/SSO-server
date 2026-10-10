"""JWKS-xx, DISC-xx, HEALTH-xx: spec 6.7, 5.3, addendum B2/B6."""
import jwt
import pytest
import requests

import jwt_forge
from reference_verifier import verify_access_token
from sso_client import DISCOVERY, HEALTHZ, JWKS


# ---- JWKS -------------------------------------------------------------------------
def test_JWKS_01_shape(sso):
    r = sso.get(JWKS)
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    keys = r.json()["keys"]
    assert isinstance(keys, list) and keys
    for k in keys:
        assert k["kty"] == "RSA" and k["use"] == "sig" and k["alg"] == "RS256"
        assert k["e"] == "AQAB"
        assert isinstance(k["kid"], str) and len(k["kid"]) == 16
        assert jwt_forge.jwk_to_public_key(k).key_size >= 2048


def test_JWKS_02_cache_control(sso):
    cc = sso.get(JWKS).headers.get("Cache-Control", "").replace(" ", "").lower()
    assert "public" in cc.split(",") and "max-age=3600" in cc.split(","), cc


def test_JWKS_03_no_private_material(jwks):
    for k in jwks["keys"]:
        assert not ({"d", "p", "q", "dp", "dq", "qi", "k"} & set(k)), "private key parameters exposed"


def test_JWKS_04_kid_is_sha256_of_der_public_key(jwks):
    for k in jwks["keys"]:
        pub = jwt_forge.jwk_to_public_key(k)
        if k["kid"] == jwt_forge.kid_pkcs1(pub):
            pytest.fail("kid computed over PKCS#1 DER; spec 5.3 intends SubjectPublicKeyInfo DER (Q-11)")
        assert k["kid"] == jwt_forge.kid_spki(pub)


def test_JWKS_05_token_kid_matches_and_verifies(jwks, alice_session, issuer, cfg):
    kid = jwt_forge.header(alice_session["access_token"])["kid"]
    assert kid in {k["kid"] for k in jwks["keys"]}
    claims = verify_access_token(alice_session["access_token"], jwks, issuer, cfg.audience)
    assert claims["username"] == "qa_alice"


def test_JWKS_06_kids_unique(jwks):
    kids = [k["kid"] for k in jwks["keys"]]
    assert len(kids) == len(set(kids))


def test_JWKS_07_public_no_auth_and_get_only(sso):
    assert sso.get(JWKS, headers={"Authorization": "Bearer garbage"}).status_code == 200
    assert sso.post(JWKS).status_code == 405


# ---- Discovery ---------------------------------------------------------------------
def test_DISC_01_document(sso, cfg):
    r = sso.get(DISCOVERY)
    assert r.status_code == 200 and r.headers["Content-Type"].startswith("application/json")
    d = r.json()
    if cfg.issuer:
        assert d["issuer"] == cfg.issuer
    assert d["id_token_signing_alg_values_supported"] == ["RS256"]


def test_DISC_02_jwks_uri_resolves_to_same_keys(discovery, jwks, cfg):
    assert discovery["jwks_uri"].endswith("/.well-known/jwks.json")
    assert discovery["jwks_uri"].startswith(discovery["issuer"].rstrip("/"))
    if cfg.issuer:  # only fetch the advertised URL when we know it is reachable from here
        r = requests.get(discovery["jwks_uri"], verify=cfg.verify, timeout=10)
        assert r.json() == jwks


def test_DISC_03_token_endpoint_points_to_login_or_absent(discovery):
    """Addendum B2 overrides spec 6.7: no /api/v1/auth/token until phase 5."""
    if "token_endpoint" in discovery:
        assert discovery["token_endpoint"].endswith("/api/v1/auth/login"), discovery["token_endpoint"]


def test_DISC_04_no_authorization_endpoint_yet(discovery):
    assert "authorization_endpoint" not in discovery


def test_DISC_05_issuer_matches_token_iss(discovery, alice_session):
    assert jwt_forge.payload(alice_session["access_token"])["iss"] == discovery["issuer"]


def test_DISC_06_advertised_endpoints_exist(sso, discovery, issuer):
    for key in ("token_endpoint",):
        if key in discovery:
            path = discovery[key][len(discovery["issuer"].rstrip("/")):]
            assert sso.get(path).status_code == 405  # exists, POST-only


# ---- healthz ---------------------------------------------------------------------
def test_HEALTH_01_ok(sso):
    r = sso.get(HEALTHZ)
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_HEALTH_02_no_auth_needed_and_no_redirect(sso):
    r = sso.get(HEALTHZ, headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 200  # also proves no APPEND_SLASH redirect on the exact spec path
