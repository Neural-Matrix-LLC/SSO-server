"""LOGOUT-ALL-xx: POST /api/v1/auth/logout-all (spec 6.4, 6.6, addendum B8)."""
import time

import pytest

import jwt_forge
import testdata
from helpers import assert_error
from sso_client import LOGOUT_ALL, refresh_cookie

PW = testdata.USERS["qa_revoke"]["password"]


@pytest.fixture
def revoke_sessions(sso, cfg):
    time.sleep(1.1)  # stay clear of any earlier revocation of qa_revoke at second granularity
    n1 = sso.login_ok("qa_revoke", PW).json()
    n2 = sso.login_ok("qa_revoke", PW).json()
    b = sso.login_ok("qa_revoke", PW, client="browser", origin=cfg.allowed_origin)
    time.sleep(1.1)
    return n1, n2, refresh_cookie(b).value


def test_LOGOUT_ALL_01_revokes_every_refresh_token(sso, cfg, revoke_sessions):
    n1, n2, cookie = revoke_sessions
    r = sso.logout_all(n1["access_token"])
    assert r.status_code == 204, r.text
    assert_error(sso.refresh_native(n1["refresh_token"]), 401, "token_invalid")
    assert_error(sso.refresh_native(n2["refresh_token"]), 401, "token_invalid")
    assert_error(sso.refresh_cookie(cookie, origin=cfg.allowed_origin), 401, "token_invalid")


def test_LOGOUT_ALL_02_introspect_reports_old_access_inactive(sso, service_auth, revoke_sessions):
    n1, n2, _ = revoke_sessions
    assert sso.introspect(n2["access_token"], service_auth).json()["active"] is True
    assert sso.logout_all(n1["access_token"]).status_code == 204
    r = sso.introspect(n2["access_token"], service_auth)
    assert r.status_code == 200 and r.json() == {"active": False}


def test_LOGOUT_ALL_03_requires_bearer(sso):
    assert_error(sso.post(LOGOUT_ALL, json={}), 401, codes={"token_invalid"})  # Q-07


def test_LOGOUT_ALL_04_refresh_token_as_bearer_rejected(sso, native_session):
    assert_error(sso.logout_all(native_session["refresh_token"]), 401, "token_invalid")
    assert sso.refresh_native(native_session["refresh_token"]).status_code == 200


def test_LOGOUT_ALL_05_login_immediately_after_logout_all_works(sso, service_auth):
    """Edge: revoked_at has sub-second precision but JWT iat is whole seconds. A token issued in
    the same second as the logout-all must not be treated as revoked (Q-08)."""
    time.sleep(1.1)
    s = sso.login_ok("qa_revoke", PW).json()
    assert sso.logout_all(s["access_token"]).status_code == 204
    fresh = sso.login_ok("qa_revoke", PW).json()  # no sleep on purpose
    assert sso.introspect(fresh["access_token"], service_auth).json().get("active") is True
    assert sso.refresh_native(fresh["refresh_token"]).status_code == 200


def test_LOGOUT_ALL_06_other_users_unaffected(sso, pool_user):
    name, pw, _ = pool_user
    other = sso.login_ok(name, pw).json()
    time.sleep(1.1)
    s = sso.login_ok("qa_revoke", PW).json()
    assert sso.logout_all(s["access_token"]).status_code == 204
    assert sso.refresh_native(other["refresh_token"]).status_code == 200


@pytest.mark.skip(reason="Q-09: spec does not say whether /me (and logout-all itself) must reject "
                         "access tokens issued before revoked_at; only introspect is specified")
def test_LOGOUT_ALL_07_me_with_pre_revocation_access_token(sso, revoke_sessions):
    n1, _, _ = revoke_sessions
    sso.logout_all(n1["access_token"])
    assert sso.me(n1["access_token"]).status_code in (200, 401)


@pytest.mark.needs_manage
@pytest.mark.needs_private_key
def test_LOGOUT_ALL_08_revocation_boundary_ceil_rule(sso, service_auth, manage, signing_key, real_kid):
    """Boundary of the revocation rule (README §10: revoked iff iat < ceil(revoked_at)).
    Tokens with iat = floor(revoked_at) (same second, issued before the revocation completed) must be
    rejected; tokens with iat = ceil(revoked_at) must be accepted. Checked at introspect, /me and refresh."""
    import math
    time.sleep(1.1)
    s = sso.login_ok("qa_revoke", PW).json()
    assert sso.logout_all(s["access_token"]).status_code == 204
    ts = float(manage.shell(
        "from sso.models import UserTokenRevocation as R;"
        "print(R.objects.get(user__username='qa_revoke').revoked_at.timestamp())").splitlines()[-1])
    lo, hi = math.floor(ts), math.ceil(ts)
    if lo == hi:
        pytest.skip("revoked_at fell exactly on a whole second; rerun")
    acc = jwt_forge.payload(s["access_token"])
    ref = jwt_forge.payload(s["refresh_token"])

    def mint(base, iat):
        pl = dict(base, iat=iat, exp=iat + 900, jti=f"qa{iat}{time.time_ns()}")
        return jwt_forge.sign(pl, signing_key, real_kid)

    before_a, after_a = mint(acc, lo), mint(acc, hi)
    before_r, after_r = mint(ref, lo), mint(ref, hi)
    assert sso.introspect(before_a, service_auth).json() == {"active": False}
    assert sso.introspect(after_a, service_auth).json().get("active") is True
    assert sso.me(before_a).status_code == 401
    assert sso.me(after_a).status_code == 200
    assert sso.refresh_native(before_r).status_code == 401
    assert sso.refresh_native(after_r).status_code == 200
