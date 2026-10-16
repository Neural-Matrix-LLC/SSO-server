"""SEC-30..SEC-35 / ERR-14: throttling (spec 6.1, 9.3; addendum B3). Runs last (file name) because
it deliberately exhausts the per-IP login budget. Each test first waits for a clean window.

Requires a single gunicorn worker or a shared cache in the test env (addendum B3), otherwise
per-worker LocMem counters make these flaky (Q-03)."""
import time
import uuid

import pytest

import testdata
from helpers import assert_error

pytestmark = [pytest.mark.throttle, pytest.mark.slow]

WINDOW = 61


def _clean_window():
    time.sleep(WINDOW)


def _assert_429(r):
    b = assert_error(r, 429, "rate_limited")
    ra = r.headers.get("Retry-After")
    assert ra is not None and ra.isdigit() and 0 < int(ra) <= 60, f"Retry-After={ra!r}"
    return int(ra)


def test_SEC_30_per_username_limit(sso, cfg):
    _clean_window()
    for i in range(cfg.rate_login_user):
        r = sso.login("qa_throttle1", "wrong", retry_on_429=False)
        assert r.status_code == 401, f"attempt {i + 1}: {r.status_code}"
    _assert_429(sso.login("qa_throttle1", "wrong", retry_on_429=False))


def test_SEC_31_username_key_is_case_insensitive(sso, cfg):
    _clean_window()
    names = ["qa_throttle2", "QA_THROTTLE2", "Qa_Throttle2"]
    for i in range(cfg.rate_login_user):
        assert sso.login(names[i % 3], "wrong", retry_on_429=False).status_code == 401
    _assert_429(sso.login("qa_throttle2", "wrong", retry_on_429=False))


def test_SEC_32_throttle_blocks_correct_password_then_recovers(sso, cfg):
    _clean_window()
    pw = testdata.USERS["qa_throttle3"]["password"]
    for _ in range(cfg.rate_login_user):
        sso.login("qa_throttle3", "wrong", retry_on_429=False)
    ra = _assert_429(sso.login("qa_throttle3", pw, retry_on_429=False))
    time.sleep(ra + 1)
    assert sso.login("qa_throttle3", pw, retry_on_429=False).status_code == 200


def test_SEC_33_per_ip_limit_and_xff_spoofing(sso, cfg):
    _clean_window()
    for i in range(cfg.rate_login_ip):
        r = sso.login(f"qa_ipthrottle_{uuid.uuid4().hex[:8]}", "wrong", retry_on_429=False)
        assert r.status_code == 401, f"attempt {i + 1}: {r.status_code}"
    _assert_429(sso.login(f"qa_ipthrottle_{uuid.uuid4().hex[:8]}", "wrong", retry_on_429=False))
    # SEC-35: a client-supplied X-Forwarded-For must not reset the per-IP budget
    r = sso.post("/api/v1/auth/login", json={"username": "qa_xff", "password": "x", "client": "native"},
                 headers={"X-Forwarded-For": "203.0.113.%d" % (int(time.time()) % 250)})
    _assert_429(r)


def test_SEC_34_refresh_limit(sso, cfg):
    _clean_window()
    for i in range(cfg.rate_refresh):
        r = sso.refresh_native("garbage", retry_on_429=False)
        assert r.status_code == 401, f"attempt {i + 1}: {r.status_code}"
    _assert_429(sso.refresh_native("garbage", retry_on_429=False))
