"""examples/verifier: spec §8.2 verifier + FastAPI demo. Spec §11: refresh token rejected by the verifier."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import sso_verifier
import verifier_app
from .conftest import claims, login, sign

pytestmark = pytest.mark.django_db


@pytest.fixture
def verifier(api, monkeypatch):
    """A verifier whose JWKS is fetched from our real /.well-known/jwks.json view."""
    jwks = api.get("/.well-known/jwks.json").json()
    cache = sso_verifier.JWKSCache("https://sso.test/.well-known/jwks.json", fetch=lambda url: jwks)
    v = sso_verifier.SSOVerifier("https://sso.test/.well-known/jwks.json", "https://sso.test", jwks=cache)
    monkeypatch.setattr(sso_verifier, "_default", v)
    return v


def test_verifier_accepts_access_token(verifier, tokens, user):
    c = verifier.verify_access_token(tokens["access_token"])
    assert c["sub"] == str(user.pk) and c["groups"] == ["beta", "trader"]
    assert sso_verifier.verify_access_token(tokens["access_token"])["username"] == "thomas"


def test_verifier_rejects_refresh_token(verifier, tokens):
    with pytest.raises(sso_verifier.TokenInvalid, match="not an access token"):
        verifier.verify_access_token(tokens["refresh_token"])


@pytest.mark.parametrize("over", [{"exp": 1_000_000, "iat": 999_000}, {"aud": "other"}, {"iss": "https://evil"}])
def test_verifier_rejects_expired_wrong_aud_iss(verifier, user, over):
    with pytest.raises(sso_verifier.TokenInvalid):
        verifier.verify_access_token(sign(claims(user.pk, **over)))


def test_verifier_rejects_unpublished_key(verifier, user):
    with pytest.raises(sso_verifier.TokenInvalid):
        verifier.verify_access_token(sign(claims(user.pk), os.environ["SSO_TEST_ROGUE_PRIVATE"]))


def test_verifier_accepts_old_published_key(verifier, user):
    assert verifier.verify_access_token(sign(claims(user.pk), os.environ["SSO_TEST_OLD_PRIVATE"]))["sub"]


def test_default_verifier_from_env(monkeypatch):
    monkeypatch.setattr(sso_verifier, "_default", None)
    monkeypatch.setenv("SSO_JWKS_URL", "https://sso.test/.well-known/jwks.json")
    monkeypatch.setenv("SSO_ISSUER", "https://sso.test")
    v = sso_verifier.default_verifier()
    assert v.issuer == "https://sso.test" and v.audience == "myfin-services"


def test_fastapi_demo(verifier, api, make_user):
    make_user(username="staffer", email="s@example.org", is_staff=True, groups=("admin",))
    make_user(username="plain", email="p@example.org", groups=())
    staff = login(api, username="staffer").json()["access_token"]
    plain = login(api, username="plain").json()["access_token"]
    c = TestClient(verifier_app.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/me")
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert c.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401
    r = c.get("/me", headers={"Authorization": f"Bearer {staff}"})
    assert r.status_code == 200 and r.json()["username"] == "staffer"
    assert c.get("/group/admin", headers={"Authorization": f"Bearer {staff}"}).status_code == 200
    assert c.get("/group/admin", headers={"Authorization": f"Bearer {plain}"}).status_code == 403
    assert c.get("/staff", headers={"Authorization": f"Bearer {staff}"}).status_code == 200
    assert c.get("/staff", headers={"Authorization": f"Bearer {plain}"}).status_code == 403


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def counted_jwks(api):
    """JWKSCache over our real JWKS view, with a fake clock and a fetch counter (spec §8.1)."""
    state = {"jwks": api.get("/.well-known/jwks.json").json(), "urls": []}

    def fetch(url):
        state["urls"].append(url)
        if isinstance(state["jwks"], Exception):
            raise state["jwks"]
        return state["jwks"]

    clock = FakeClock()
    cache = sso_verifier.JWKSCache("https://sso.test/.well-known/jwks.json", fetch=fetch, clock=clock)
    v = sso_verifier.SSOVerifier("https://sso.test/.well-known/jwks.json", "https://sso.test", jwks=cache)
    return v, cache, clock, state


def _with_kid(token_claims, kid):
    return sign(token_claims, os.environ["SSO_TEST_ROGUE_PRIVATE"], kid=kid)


def test_unknown_kid_refetches_at_most_once_per_minute(counted_jwks, tokens, user):
    v, cache, clock, state = counted_jwks
    v.verify_access_token(tokens["access_token"])
    assert len(state["urls"]) == 1  # initial fetch
    with pytest.raises(sso_verifier.TokenInvalid):  # unknown kid right after a fetch: no refetch
        v.verify_access_token(_with_kid(claims(user.pk), "bogus-early"))
    assert len(state["urls"]) == 1
    clock.t += 61
    for i in range(50):  # attacker-chosen kids within the same minute
        with pytest.raises(sso_verifier.TokenInvalid, match="unknown signing key"):
            v.verify_access_token(_with_kid(claims(user.pk), f"bogus-{i}"))
        clock.t += 1  # 50 s pass in total
    assert len(state["urls"]) == 2  # exactly one refetch for all of them
    clock.t += 10  # 60 s after the refetch
    with pytest.raises(sso_verifier.TokenInvalid):
        v.verify_access_token(_with_kid(claims(user.pk), "bogus-late"))
    assert len(state["urls"]) == 3
    # known kids never trigger a fetch, however often they are used
    for _ in range(20):
        v.verify_access_token(tokens["access_token"])
    assert len(state["urls"]) == 3


def test_rotation_new_kid_picked_up_by_refetch(counted_jwks, user):
    """After a key rotation the first token with the new kid causes one refetch and then verifies."""
    import json

    import jwt as pyjwt

    from sso.keys import compute_kid, load_private_key

    v, cache, clock, state = counted_jwks
    v.verify_access_token(sign(claims(user.pk)))
    assert len(state["urls"]) == 1
    pub = load_private_key(os.environ["SSO_TEST_ROGUE_PRIVATE"]).public_key()
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(pub))
    jwk.update(kid=compute_kid(pub), use="sig", alg="RS256")
    state["jwks"] = {"keys": state["jwks"]["keys"] + [jwk]}  # the SSO now publishes the new key
    clock.t += 61
    token = sign(claims(user.pk), os.environ["SSO_TEST_ROGUE_PRIVATE"])  # kid = new key's kid
    assert v.verify_access_token(token)["sub"] == str(user.pk)
    assert len(state["urls"]) == 2


def test_jwks_lifespan_and_failed_fetch(counted_jwks, tokens):
    v, cache, clock, state = counted_jwks
    v.verify_access_token(tokens["access_token"])
    clock.t += 3600  # cache expired -> refetch on next use
    state["jwks"] = OSError("SSO down")
    v.verify_access_token(tokens["access_token"])  # old keys kept on a failed fetch
    assert len(state["urls"]) == 2
    v.verify_access_token(tokens["access_token"])  # failed attempt is rate-limited too
    assert len(state["urls"]) == 2


def test_jwks_first_fetch_failure_and_bad_headers(user):
    def boom(url):
        raise OSError("no route")

    cache = sso_verifier.JWKSCache("https://sso.test/jwks", fetch=boom)
    v = sso_verifier.SSOVerifier("https://sso.test/jwks", "https://sso.test", jwks=cache)
    with pytest.raises(sso_verifier.TokenInvalid, match="cannot fetch JWKS"):
        v.verify_access_token(sign(claims(user.pk)))
    with pytest.raises(sso_verifier.TokenInvalid, match="no kid"):
        v.verify_access_token(sign(claims(user.pk), kid=None))
    with pytest.raises(sso_verifier.TokenInvalid, match="only RS256"):
        v.verify_access_token("eyJhbGciOiJub25lIn0.e30.")


def test_http_fetch_reads_json(monkeypatch):
    import io

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"], seen["timeout"] = req.full_url, timeout
        return Resp(b'{"keys": []}')

    monkeypatch.setattr(sso_verifier.urllib.request, "urlopen", fake_urlopen)
    assert sso_verifier._http_fetch("https://sso.test/jwks") == {"keys": []}
    assert seen == {"url": "https://sso.test/jwks", "timeout": 5.0}
