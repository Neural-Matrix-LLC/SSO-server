"""WORKER TIMEOUT report (WSL, 2026-10-15): an unreachable MySQL hung /healthz past gunicorn's --timeout.
DB/Redis network timeouts are set, and connection failures are logged at ERROR (host, port, db, never password)."""
import logging
from unittest import mock

import pytest
from django.conf import settings
from django.db import OperationalError, connections

from sso.dbcheck import check_database


def _fail_cursor(*a, **k):
    raise OperationalError(2003, "Can't connect to MySQL server on '10.255.255.1' (110)")


@pytest.mark.django_db
def test_healthz_db_failure_is_503_and_logs_error(client, caplog):
    with mock.patch.object(connections["default"], "cursor", side_effect=_fail_cursor):
        with caplog.at_level(logging.ERROR, logger="sso.db"):
            resp = client.get("/healthz", HTTP_X_FORWARDED_PROTO="https")
    assert resp.status_code == 503
    recs = [r for r in caplog.records if r.name == "sso.db" and r.levelno == logging.ERROR]
    assert len(recs) == 1
    msg = recs[0].getMessage()
    assert "healthz: database unreachable at" in msg
    assert "OperationalError" in msg and "Can't connect" in msg
    assert f"db={settings.DATABASES['default']['NAME']}" in msg
    pwd = settings.DATABASES["default"].get("PASSWORD")
    if pwd:
        assert pwd not in msg


@pytest.mark.django_db
def test_startup_check_logs_error_with_host_port(caplog):
    db = connections.databases["default"]
    with mock.patch.dict(db, {"HOST": "10.255.255.1", "PORT": "3306", "PASSWORD": "s3cret-pw"}), \
         mock.patch.object(connections["default"], "cursor", side_effect=_fail_cursor), \
         caplog.at_level(logging.ERROR, logger="sso.db"):
        assert check_database("startup") is False
    msg = caplog.records[-1].getMessage()
    assert caplog.records[-1].levelno == logging.ERROR
    assert "startup: database unreachable at 10.255.255.1:3306" in msg
    assert "s3cret-pw" not in msg


@pytest.mark.django_db
def test_check_database_ok():
    assert check_database("startup") is True


def test_sso_db_logger_goes_to_stdout():
    import sys
    cfg = settings.LOGGING
    assert cfg["loggers"]["sso.db"]["handlers"] == ["console"]
    assert cfg["handlers"]["console"]["stream"] is sys.stdout


def test_dockerfile_runs_startup_db_check():
    from pathlib import Path
    df = (Path(settings.BASE_DIR) / "Dockerfile").read_text()
    assert "python /app/docker/dbcheck.py; exec gunicorn" in df
    assert "docker/dbcheck.py" in df


def test_mysql_and_redis_timeouts_from_env(monkeypatch):
    import importlib
    import ssoproject.settings as s
    monkeypatch.setenv("SSO_DB_ENGINE", "mysql")
    monkeypatch.setenv("SSO_CACHE_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.setenv("SSO_DB_CONNECT_TIMEOUT", "4")
    try:
        importlib.reload(s)
        opts = s.DATABASES["default"]["OPTIONS"]
        assert opts["connect_timeout"] == 4 and opts["read_timeout"] == 15 and opts["write_timeout"] == 15
        c = s.CACHES["default"]["OPTIONS"]
        assert c["socket_connect_timeout"] == 3.0 and c["socket_timeout"] == 3.0
    finally:
        monkeypatch.undo()
        importlib.reload(s)
