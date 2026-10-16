"""SEC-01..SEC-19: JWT attacks against the SSO server's own token checks (/me), plus the spec 8.2
reference verifier. The examples/verifier demo gets the same attacks in test_e2e.py (E2E-04)."""
import time

import jwt
import pytest

import jwt_forge
from helpers import assert_error
from reference_verifier import verify_access_token


def rejected_by_server(sso, token):
    assert_error(sso.me(token), 401, "token_invalid")


def rejected_by_reference(token, jwks, issuer, cfg):
    with pytest.raises(jwt.PyJWTError):
        verify_access_token(token, jwks, issuer, cfg.audience)


@pytest.fixture
def base_claims(alice_session):
    return jwt_forge.claims_like(alice_session["access_token"])


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE"])
@pytest.mark.parametrize("sig", [b"", b"junk"])
def test_SEC_01_alg_none(sso, jwks, issuer, cfg, base_claims, real_kid, alg, sig):
    tok = jwt_forge.alg_none(base_claims, alg=alg, kid=real_kid, signature=sig)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_SEC_02_hmac_signed_with_public_key(sso, jwks, issuer, cfg, base_claims, real_kid, jwks_public_key, alg):
    for name, secret in jwt_forge.public_key_secret_variants(jwks_public_key).items():
        tok = jwt_forge.hs256_with_secret(base_claims, secret, kid=real_kid, alg=alg)
        rejected_by_server(sso, tok)
        rejected_by_reference(tok, jwks, issuer, cfg)


def test_SEC_03_tampered_signature(sso, jwks, issuer, cfg, alice_session):
    tok = jwt_forge.tamper_signature(alice_session["access_token"])
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.parametrize("changes", [{"is_staff": True}, {"sub": "OTHER"}, {"groups": ["admin"]},
                                     {"exp": 4102444800}, {"token_type": "access", "username": "root"}])
def test_SEC_04_tampered_payload_keeps_old_signature(sso, jwks, issuer, cfg, alice_session, changes):
    changes = dict(changes)
    if changes.get("sub") == "OTHER":  # must differ from the real sub, or the payload bytes are unchanged
        changes["sub"] = str(int(jwt_forge.payload(alice_session["access_token"])["sub"]) + 1)
    tok = jwt_forge.tamper_payload(alice_session["access_token"], **changes)
    assert tok.split(".")[1] != alice_session["access_token"].split(".")[1]
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


def test_SEC_05_unknown_kid_attacker_key(sso, jwks, issuer, cfg, base_claims):
    tok = jwt_forge.sign(base_claims, jwt_forge.new_rsa_key(), "deadbeefdeadbeef")
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


def test_SEC_06_real_kid_attacker_key(sso, jwks, issuer, cfg, base_claims, real_kid):
    tok = jwt_forge.sign(base_claims, jwt_forge.new_rsa_key(), real_kid)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


def test_SEC_07_attacker_key_header_injection(sso, base_claims, real_kid):
    """No kid / embedded jwk (CVE-2018-0114 style) / jku / x5u pointing at attacker material."""
    k = jwt_forge.new_rsa_key()
    jwk = jwt_forge.public_jwk(k.public_key(), real_kid)
    for extra, kid in [({}, None), ({"jwk": jwk}, real_kid), ({"jku": "https://evil.example/jwks.json"}, "evil1"),
                       ({"x5u": "https://evil.example/cert.pem"}, real_kid)]:
        rejected_by_server(sso, jwt_forge.sign(base_claims, k, kid, extra_headers=extra))


@pytest.mark.needs_private_key
@pytest.mark.parametrize("iss", ["https://evil.example", "WRONG", ""])
def test_SEC_08_wrong_issuer(sso, jwks, issuer, cfg, base_claims, signing_key, real_kid, iss):
    base_claims["iss"] = iss or issuer + "/"  # "" -> trailing-slash variant: exact match required
    tok = jwt_forge.sign(base_claims, signing_key, real_kid)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.needs_private_key
@pytest.mark.parametrize("aud", ["other-services", ["other-services"], None])
def test_SEC_09_wrong_or_missing_audience(sso, jwks, issuer, cfg, alice_session, signing_key, real_kid, aud):
    pl = jwt_forge.claims_like(alice_session["access_token"], aud=aud)
    if aud is None:
        pl.pop("aud", None)
    tok = jwt_forge.sign(pl, signing_key, real_kid)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.needs_private_key
def test_SEC_10_expired_beyond_leeway(sso, jwks, issuer, cfg, alice_session, signing_key, real_kid):
    now = int(time.time())
    pl = jwt_forge.claims_like(alice_session["access_token"], iat=now - 1000, exp=now - 60)
    tok = jwt_forge.sign(pl, signing_key, real_kid)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.needs_private_key
def test_SEC_11_expired_within_30s_leeway_accepted(sso, jwks, issuer, cfg, alice_session, signing_key, real_kid):
    now = int(time.time())
    pl = jwt_forge.claims_like(alice_session["access_token"], iat=now - 900, exp=now - 10)
    tok = jwt_forge.sign(pl, signing_key, real_kid)
    assert sso.me(tok).status_code == 200
    verify_access_token(tok, jwks, issuer, cfg.audience)


@pytest.mark.needs_private_key
def test_SEC_12_nbf_in_future(sso, jwks, issuer, cfg, alice_session, signing_key, real_kid):
    pl = jwt_forge.claims_like(alice_session["access_token"], nbf=int(time.time()) + 300)
    tok = jwt_forge.sign(pl, signing_key, real_kid)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.needs_private_key
def test_SEC_13_iat_in_future_beyond_skew_rejected_by_reference_verifier(
        jwks, issuer, cfg, alice_session, signing_key, real_kid):
    """Spec 8.1 #5 (service side). Server-side /me behaviour for future iat is unspecified (Q-12)."""
    now = int(time.time())
    pl = jwt_forge.claims_like(alice_session["access_token"], iat=now + 300, exp=now + 1200)
    rejected_by_reference(jwt_forge.sign(pl, signing_key, real_kid), jwks, issuer, cfg)


def test_SEC_14_refresh_token_rejected_as_access(sso, jwks, issuer, cfg, alice_session):
    rejected_by_server(sso, alice_session["refresh_token"])
    rejected_by_reference(alice_session["refresh_token"], jwks, issuer, cfg)
    assert_error(sso.logout_all(alice_session["refresh_token"]), 401, "token_invalid")


def test_SEC_15_access_token_rejected_as_refresh(sso, alice_session):
    assert_error(sso.refresh_native(alice_session["access_token"]), 401, "token_invalid")
    assert_error(sso.logout_native(alice_session["access_token"]), 401, "token_invalid")


@pytest.mark.needs_private_key
@pytest.mark.parametrize("tt", [None, "refresh", "id", "ACCESS"])
def test_SEC_16_wrong_or_missing_token_type(sso, jwks, issuer, cfg, alice_session, signing_key, real_kid, tt):
    pl = jwt_forge.claims_like(alice_session["access_token"], token_type=tt)
    if tt is None:
        pl.pop("token_type", None)
    tok = jwt_forge.sign(pl, signing_key, real_kid)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.needs_private_key
@pytest.mark.parametrize("alg", ["RS384", "RS512", "PS256"])
def test_SEC_17_only_rs256_accepted_even_with_real_key(sso, jwks, issuer, cfg, base_claims, signing_key, real_kid, alg):
    tok = jwt_forge.sign(base_claims, signing_key, real_kid, alg=alg)
    rejected_by_server(sso, tok)
    rejected_by_reference(tok, jwks, issuer, cfg)


@pytest.mark.needs_private_key
@pytest.mark.parametrize("claim", ["exp", "sub", "jti"])
def test_SEC_18_missing_required_claim(sso, alice_session, signing_key, real_kid, claim):
    pl = jwt_forge.claims_like(alice_session["access_token"])
    pl.pop(claim)
    rejected_by_server(sso, jwt_forge.sign(pl, signing_key, real_kid))


def test_SEC_19_server_issued_token_passes_reference_verifier(jwks, issuer, cfg, alice_session):
    """Positive control for the negatives above (phase 1 'done when')."""
    assert verify_access_token(alice_session["access_token"], jwks, issuer, cfg.audience)["sub"]
