"""E2E-xx: front-end and back-end example flows (spec 7, 8, 10; addendum A examples/)."""
import time

import pytest
import requests

import jwt_forge
import testdata
from helpers import assert_error
from reference_verifier import verify_access_token
from sso_client import refresh_cookie

U = testdata.USERS


def vget(cfg, verifier, path, token=None, headers=None):
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    return requests.get(verifier + path, headers=h, verify=cfg.verify, timeout=10)


def test_E2E_01_phase1_done_existing_user_token_verifies_with_8_2_code(sso, jwks, issuer, cfg):
    """Spec 10 phase 1 'done when': an existing (Django 4.1 hash) user logs in through the API and
    the token verifies with the 8.2 PyJWT code."""
    body = sso.login_ok("qa_legacy41", U["qa_legacy41"]["password"]).json()
    claims = verify_access_token(body["access_token"], jwks, issuer, cfg.audience)
    assert claims["sub"] == str(body["user"]["id"])
    assert sso.me(body["access_token"]).json()["username"] == "qa_legacy41"


@pytest.mark.needs_verifier
def test_E2E_02_native_script_flow_against_verifier(sso, cfg, verifier, pool_user):
    """Spec 7.3 'Python script / cron job' flow end to end."""
    name, pw, _ = pool_user
    t = sso.login_ok(name, pw, client="native").json()
    r = vget(cfg, verifier, cfg.verifier_path, t["access_token"])
    assert r.status_code == 200, r.text
    if isinstance(r.json(), dict) and "sub" in r.json():
        assert r.json()["sub"] == jwt_forge.payload(t["access_token"])["sub"]
    t2 = sso.refresh_native(t["refresh_token"]).json()
    assert vget(cfg, verifier, cfg.verifier_path, t2["access_token"]).status_code == 200
    assert sso.logout_native(t2["refresh_token"]).status_code == 204
    assert_error(sso.refresh_native(t2["refresh_token"]), 401, "token_invalid")


@pytest.mark.needs_verifier
def test_E2E_03_browser_flow_simulating_auth_js(sso, cfg, verifier, pool_user):
    """Spec 7.2 auth.js sequence driven over HTTP: restoreSession -> login -> apiFetch ->
    silent refresh -> logout -> restoreSession fails."""
    o = cfg.allowed_origin
    name, pw, _ = pool_user
    assert sso.refresh_cookie("", origin=o).status_code in (400, 401)          # restoreSession(): no session
    login = sso.login_ok(name, pw, client="browser", origin=o)
    cookie = refresh_cookie(login).value
    access = login.json()["access_token"]
    assert vget(cfg, verifier, cfg.verifier_path, access, {"Origin": o}).status_code == 200  # apiFetch
    r = sso.refresh_cookie(cookie, origin=o)                                    # page reload
    assert r.status_code == 200
    cookie, access = refresh_cookie(r).value, r.json()["access_token"]
    assert vget(cfg, verifier, cfg.verifier_path, access).status_code == 200
    assert sso.logout_cookie(cookie, origin=o).status_code == 204              # logout()
    assert sso.refresh_cookie(cookie, origin=o).status_code == 401             # restoreSession(): null


@pytest.mark.needs_verifier
@pytest.mark.needs_private_key
def test_E2E_04_apifetch_401_refresh_retry(sso, cfg, verifier, signing_key, real_kid, pool_user):
    """auth.js apiFetch: service returns 401 for an expired access token -> refresh -> retry ok."""
    name, pw, _ = pool_user
    login = sso.login_ok(name, pw, client="browser", origin=cfg.allowed_origin)
    now = int(time.time())
    expired = jwt_forge.sign(jwt_forge.claims_like(login.json()["access_token"], iat=now - 1000, exp=now - 60),
                             signing_key, real_kid)
    assert vget(cfg, verifier, cfg.verifier_path, expired).status_code == 401
    r = sso.refresh_cookie(refresh_cookie(login).value, origin=cfg.allowed_origin)
    assert vget(cfg, verifier, cfg.verifier_path, r.json()["access_token"]).status_code == 200


@pytest.mark.needs_verifier
def test_E2E_05_verifier_rejects_bad_tokens(sso, cfg, verifier, alice_session, jwks_public_key, real_kid):
    p = cfg.verifier_path
    r = vget(cfg, verifier, p)
    assert r.status_code == 401, f"missing token must be 401 (spec 8.1/8.6), got {r.status_code}"  # Q-13
    assert r.headers.get("WWW-Authenticate", "").startswith("Bearer")
    pl = jwt_forge.claims_like(alice_session["access_token"])
    bad = {
        "garbage": "garbage",
        "refresh_token": alice_session["refresh_token"],
        "alg_none": jwt_forge.alg_none(pl, kid=real_kid),
        "tampered": jwt_forge.tamper_payload(alice_session["access_token"], groups=["admin"]),
        "attacker_key": jwt_forge.sign(pl, jwt_forge.new_rsa_key(), real_kid),
    }
    for name, secret in jwt_forge.public_key_secret_variants(jwks_public_key).items():
        bad["hs256_" + name] = jwt_forge.hs256_with_secret(pl, secret, kid=real_kid)
    for label, tok in bad.items():
        r = vget(cfg, verifier, p, tok)
        assert r.status_code == 401, f"{label}: {r.status_code}"
        assert r.headers.get("WWW-Authenticate", "").startswith("Bearer"), label


@pytest.mark.needs_verifier
@pytest.mark.needs_private_key
def test_E2E_06_verifier_rejects_bad_claims(cfg, verifier, alice_session, signing_key, real_kid):
    now = int(time.time())
    a = alice_session["access_token"]
    cases = {
        "expired": jwt_forge.claims_like(a, iat=now - 1000, exp=now - 60),
        "wrong_iss": jwt_forge.claims_like(a, iss="https://evil.example"),
        "wrong_aud": jwt_forge.claims_like(a, aud="other-services"),
        "iat_future": jwt_forge.claims_like(a, iat=now + 300, exp=now + 1200),
        "nbf_future": jwt_forge.claims_like(a, nbf=now + 300),
        "type_refresh": jwt_forge.claims_like(a, token_type="refresh"),
    }
    for label, pl in cases.items():
        r = vget(cfg, verifier, cfg.verifier_path, jwt_forge.sign(pl, signing_key, real_kid))
        assert r.status_code == 401, f"{label}: {r.status_code}"


@pytest.mark.needs_verifier
def test_E2E_07_verifier_group_authorization(sso, cfg, verifier):
    if not cfg.verifier_group_path:
        pytest.skip("VERIFIER_GROUP_PATH not set (demo has no group-protected endpoint) - Q-13")
    member = sso.login_ok("qa_alice", U["qa_alice"]["password"]).json()["access_token"]
    outsider = sso.login_ok("qa_bob", U["qa_bob"]["password"]).json()["access_token"]
    assert cfg.verifier_group in U["qa_alice"]["groups"]
    assert vget(cfg, verifier, cfg.verifier_group_path, member).status_code == 200
    assert vget(cfg, verifier, cfg.verifier_group_path, outsider).status_code == 403


@pytest.mark.needs_verifier
def test_E2E_08_verifier_cors_allows_authorization_header(cfg, verifier):
    r = requests.options(verifier + cfg.verifier_path, verify=cfg.verify, timeout=10, headers={
        "Origin": cfg.allowed_origin, "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization"})
    assert r.headers.get("Access-Control-Allow-Origin") in (cfg.allowed_origin, "*")
    assert "authorization" in r.headers.get("Access-Control-Allow-Headers", "").lower()


@pytest.mark.needs_verifier
@pytest.mark.slow
def test_E2E_13_verifier_jwks_refetch_rate_limited(sso, cfg, verifier, alice_session):
    """Spec 8.1: an unknown kid triggers a JWKS refetch at most once per minute. Counts JWKS hits in
    the SSO server's access log (SSO_ACCESS_LOG = gunicorn --access-logfile path)."""
    import os
    log = os.environ.get("SSO_ACCESS_LOG")
    if not log or not os.path.isfile(log):
        pytest.skip("SSO_ACCESS_LOG (gunicorn access log of the SSO server) not set")

    def hits():
        time.sleep(0.3)  # let the server write the access-log line
        with open(log, errors="replace") as f:
            return sum(1 for line in f if "GET /.well-known/jwks.json" in line)

    def unknown_kid_token():
        pl = jwt_forge.claims_like(alice_session["access_token"])
        return jwt_forge.sign(pl, jwt_forge.new_rsa_key(), "qa" + uuid.uuid4().hex[:14])

    import uuid
    attackers = [unknown_kid_token() for _ in range(20)]
    assert vget(cfg, verifier, cfg.verifier_path, alice_session["access_token"]).status_code == 200  # warm cache
    c0 = hits()
    for tok in attackers:
        assert vget(cfg, verifier, cfg.verifier_path, tok).status_code == 401
    burst1 = hits() - c0
    assert burst1 <= 1, f"{burst1} JWKS fetches for 20 unknown-kid tokens within a minute (limit 1/min)"
    time.sleep(61)
    c1 = hits()
    for tok in attackers:
        assert vget(cfg, verifier, cfg.verifier_path, tok).status_code == 401
    burst2 = hits() - c1
    assert burst2 == 1, f"expected exactly 1 refetch after the 60 s interval, got {burst2}"
    assert vget(cfg, verifier, cfg.verifier_path, alice_session["access_token"]).status_code == 200
