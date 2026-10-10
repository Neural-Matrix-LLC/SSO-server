"""LEGACY-xx: existing myFinance (Django 4.1) users keep working (Request R-01/R-02, spec 4.3,
spec 11, addendum B14). All qa_* users are seeded with Django 4.1 pbkdf2_sha256$390000 hashes."""
import pytest

import testdata
from helpers import assert_error

U = testdata.USERS


def _seeded_hash_or_skip(manage, username, expected_prefix):
    h = manage.user_field(username, "password")
    if not h.startswith(expected_prefix):
        pytest.skip(f"{username} already rehashed ({h.split('$')[:2]}); re-run the seed script")
    return h


def test_LEGACY_01_django41_pbkdf2_390000_login(sso):
    assert testdata.password_hash_for("qa_legacy41").startswith("pbkdf2_sha256$390000$")
    r = sso.login_ok("qa_legacy41", U["qa_legacy41"]["password"])
    assert r.json()["user"]["username"] == "qa_legacy41"


def test_LEGACY_02_wrong_password_on_legacy_hash(sso):
    assert_error(sso.login("qa_legacy32", "wrong"), 401, "invalid_credentials")


def test_LEGACY_03_older_iteration_count_260000(sso):
    sso.login_ok("qa_legacy32", U["qa_legacy32"]["password"])


def test_LEGACY_04_pbkdf2_sha1_hash(sso):
    """PBKDF2SHA1PasswordHasher is in Django's default PASSWORD_HASHERS list (spec 4.3)."""
    sso.login_ok("qa_sha1", U["qa_sha1"]["password"])


@pytest.mark.needs_manage
def test_LEGACY_05_rehash_on_login_stays_django41_compatible(sso, manage):
    """Spec 4.3: Django 5.2/4.2 re-hashes with more iterations on login; myFinance (Django 4.1)
    must still verify the new hash -> still pbkdf2_sha256, iterations stored in the hash."""
    pw = U["qa_rehash"]["password"]
    # Dedicated user, logged in by no other test; skip if already rehashed (re-run the seed).
    before = _seeded_hash_or_skip(manage, "qa_rehash", "pbkdf2_sha256$390000$")
    sso.login_ok("qa_rehash", pw)
    after = manage.user_field("qa_rehash", "password")
    assert after != before, "expected Django to upgrade the 390000-iteration hash on login"
    algo, iters, _salt, _digest = after.split("$", 3)
    assert algo == "pbkdf2_sha256", "hasher order changed: myFinance (Django 4.1) would break"
    assert int(iters) > testdata.DJANGO41_ITERATIONS
    assert testdata.verify_django_pbkdf2(pw, after), "upgraded hash not verifiable by Django 4.1 algorithm"
    sso.login_ok("qa_rehash", pw)  # still logs in after upgrade


@pytest.mark.parametrize("username", ["qa_malformed", "qa_truncated", "qa_unusable", "qa_unknownalgo"])
def test_LEGACY_06_bad_stored_hash_is_401_not_500(sso, username):
    assert_error(sso.login(username, U[username]["password"]), 401, "invalid_credentials")


@pytest.mark.needs_manage
def test_LEGACY_07_failed_login_does_not_rewrite_hash(sso, manage):
    before = manage.user_field("qa_legacy32", "password")
    sso.login("qa_legacy32", "wrong")
    assert manage.user_field("qa_legacy32", "password") == before
