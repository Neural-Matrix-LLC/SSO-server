"""Thomas's report (2026-10-16): code at v1.3d on a DB still at v1.3 -> "Unknown column 'channel'" deep in an
audit write. Pending SSO migrations are now logged at ERROR at start-up and (rate-limited) on /healthz."""
import logging
from unittest import mock

import pytest

import sso.dbcheck as dbcheck


def _errors(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "sso.db" and r.levelno == logging.ERROR]


@pytest.mark.django_db
def test_up_to_date_schema_logs_nothing(caplog):
    with caplog.at_level(logging.ERROR, logger="sso.db"):
        assert dbcheck.pending_migrations() == []
        assert dbcheck.check_migrations("startup") is True
    assert _errors(caplog) == []


@pytest.mark.django_db
def test_pending_migrations_log_error_with_names(caplog):
    with mock.patch.object(dbcheck, "pending_migrations", return_value=["sso.0007_v13d_audit_channel"]), \
         caplog.at_level(logging.ERROR, logger="sso.db"):
        assert dbcheck.check_migrations("startup") is False
    (msg,) = _errors(caplog)
    assert "startup: database schema at" in msg and "behind the code" in msg
    assert "sso.0007_v13d_audit_channel" in msg and "scripts/upgrade_db.sh" in msg


@pytest.mark.django_db
def test_healthz_pending_stays_200_and_rate_limits_error(client, caplog):
    dbcheck._last_pending_log = 0.0
    with mock.patch.object(dbcheck, "pending_migrations", return_value=["sso.0007_v13d_audit_channel"]), \
         caplog.at_level(logging.ERROR, logger="sso.db"):
        r1 = client.get("/healthz", HTTP_X_FORWARDED_PROTO="https")
        r2 = client.get("/healthz", HTTP_X_FORWARDED_PROTO="https")
    assert r1.status_code == 200 and r1.json()["warning"] == "database migrations pending"
    assert r2.status_code == 200
    assert len(_errors(caplog)) == 1  # second call inside the 5-minute window is not re-logged


@pytest.mark.django_db
def test_migration_check_failure_is_logged_not_raised(caplog):
    with mock.patch.object(dbcheck, "pending_migrations", side_effect=RuntimeError("boom")), \
         caplog.at_level(logging.ERROR, logger="sso.db"):
        assert dbcheck.check_migrations("startup") is False
    (msg,) = _errors(caplog)
    assert "could not check database migrations" in msg and "RuntimeError: boom" in msg


def test_only_sso_apps_are_checked():
    m_sso = mock.Mock(app_label="sso", name="x"); m_sso.name = "0099_x"
    m_other = mock.Mock(app_label="main_router"); m_other.name = "0001_initial"
    fake = mock.Mock()
    fake.return_value.migration_plan.return_value = [(m_sso, False), (m_other, False)]
    with mock.patch("django.db.migrations.executor.MigrationExecutor", fake):
        assert dbcheck.pending_migrations() == ["sso.0099_x"]
