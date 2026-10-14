"""MySQL-only checks for the docker-compose.test.yml run (MySQL 8.0 and 8.4). Skipped on SQLite.

They prove what the deployment plan needs from each server version (§6.0-§6.2, R29):
the server is 8.0.x (>= 8.0.11) or 8.4.x, matches the image under test, the init-script accounts use
caching_sha2_password, the runtime client library can log in with it, and sso_app has DML only.
"""
from __future__ import annotations

import os
import re

import pytest
from django.conf import settings
from django.db import connection

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.skipif(settings.DATABASES["default"]["ENGINE"] != "django.db.backends.mysql",
                       reason="MySQL integration run only (docker-compose.test.yml)"),
]


def _query(sql, params=()):
    with connection.cursor() as c:
        c.execute(sql, params)
        return c.fetchall()


def test_server_version_supported_and_as_expected():
    version = _query("SELECT VERSION()")[0][0]
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    assert m, version
    major, minor, patch = map(int, m.groups())
    assert (major, minor) in {(8, 0), (8, 4)}, version
    if (major, minor) == (8, 0):
        assert patch >= 11, f"Django 5.2 needs MySQL >= 8.0.11, got {version}"
    expected = os.environ.get("SSO_TEST_EXPECT_MYSQL", "")
    tag = re.search(r":(\d+\.\d+)", expected)
    if tag:
        assert version.startswith(tag.group(1) + "."), f"expected {expected}, server is {version}"


@pytest.mark.parametrize("account", ["sso_app", "sso_migrator"])
def test_init_script_accounts_use_caching_sha2_password(account):
    if not os.environ.get("SSO_TEST_APP_PASSWORD"):
        pytest.skip("accounts come from docker/mysql-init (docker-compose.test.yml run only)")
    rows = _query("SELECT plugin FROM mysql.user WHERE user = %s", [account])
    assert list(rows) == [("caching_sha2_password",)]


@pytest.mark.parametrize("account,env", [("sso_app", "SSO_TEST_APP_PASSWORD"),
                                         ("sso_migrator", "SSO_TEST_MIGRATOR_PASSWORD")])
def test_client_logs_in_with_caching_sha2_password(account, env):
    import MySQLdb

    password = os.environ.get(env)
    if not password:
        pytest.skip(f"{env} not set")
    db = settings.DATABASES["default"]
    opts = {k: v for k, v in db["OPTIONS"].items() if k in {"ssl", "ssl_mode", "charset"}}
    conn = MySQLdb.connect(host=db["HOST"], port=int(db["PORT"]), user=account, password=password,
                           database="dcWebUsers", **opts)
    try:
        cur = conn.cursor()
        cur.execute("SELECT CURRENT_USER()")
        assert cur.fetchone()[0].startswith(account + "@")
        cur.execute("SHOW GRANTS")
        grants = " ".join(r[0] for r in cur.fetchall())
    finally:
        conn.close()
    if account == "sso_app":
        assert "SELECT, INSERT, UPDATE, DELETE ON `dcWebUsers`" in grants
        assert not re.search(r"\b(CREATE|ALTER|DROP|INDEX|REFERENCES)\b", grants), grants


def test_tls_required_mode_works_against_server_auto_certs():
    """SSO_DB_SSL_MODE=REQUIRED (encrypt, don't verify) against the server's auto-generated certs (8.0 and 8.4).
    VERIFY_CA needs a CA file and is a production setting (README open questions)."""
    import MySQLdb

    db = settings.DATABASES["default"]
    conn = MySQLdb.connect(host=db["HOST"], port=int(db["PORT"]), user=db["USER"], password=db["PASSWORD"],
                           ssl_mode="REQUIRED")
    try:
        cur = conn.cursor()
        cur.execute("SHOW SESSION STATUS LIKE 'Ssl_version'")
        assert cur.fetchone()[1] in {"TLSv1.2", "TLSv1.3"}
    finally:
        conn.close()
