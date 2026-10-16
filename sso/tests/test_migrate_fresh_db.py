"""post_migrate on a database where the application tables don't exist yet (README §7 dev sequence).

Django sends post_migrate for every app after any migrate run, so ``migrate contenttypes`` on an empty database
used to crash in application.permissions.sync_after_migrate (no such table: sso_application_permission_record).
The end-to-end checks run ``manage.py`` in a subprocess against a fresh SQLite file, so the test DB is untouched.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from application import permissions

REPO = Path(__file__).resolve().parents[2]
SHARED = ["contenttypes", "auth", "admin", "sessions"]


def _manage(db: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SSO_", "DJANGO_"))}
    env.update({"SSO_ENV_FILE": "", "SSO_DEBUG": "True", "SSO_DB_ENGINE": "sqlite", "SSO_SQLITE_PATH": str(db),
                "PYTHONPATH": str(REPO), "PYTHONWARNINGS": "ignore"})
    return subprocess.run([sys.executable, "manage.py", *args], cwd=REPO, env=env, capture_output=True,
                          text=True, timeout=120)


def _ok(r: subprocess.CompletedProcess) -> None:
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Traceback" not in r.stderr and "Error" not in r.stderr, r.stderr


def _app_perms(db: Path) -> list[tuple[str, str]]:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT p.codename, r.codename FROM auth_permission p JOIN django_content_type c ON c.id = p.content_type_id "
            "LEFT JOIN sso_application_permission_record r ON r.permission_id = p.id "
            "WHERE c.app_label = 'application' ORDER BY p.codename").fetchall()
    finally:
        conn.close()


def test_single_app_migrate_on_an_empty_db_then_full_migrate(tmp_path):
    db = tmp_path / "fresh.sqlite3"
    _ok(_manage(db, "migrate", "contenttypes", "-v", "0"))
    _ok(_manage(db, "migrate", "-v", "0"))
    assert _app_perms(db) == [("app1", "app1"), ("sso_admin", "sso_admin")]


def test_readme_section_7_sequence_end_to_end(tmp_path):
    db = tmp_path / "dev.sqlite3"
    for app in SHARED:
        _ok(_manage(db, "migrate", app, "-v", "0"))
    plan = _manage(db, "migrate", "--plan")
    _ok(plan)
    planned = {line.split(".")[0] for line in plan.stdout.splitlines() if line and not line.startswith((" ", "Planned"))}
    assert planned == {"application", "sso", "token_blacklist"}
    _ok(_manage(db, "migrate", "-v", "0"))
    assert _app_perms(db) == [("app1", "app1"), ("sso_admin", "sso_admin")]
    again = _manage(db, "migrate", "--plan")
    _ok(again)
    assert "No planned migration operations" in again.stdout


@pytest.mark.django_db
def test_skip_is_logged_at_debug_only(monkeypatch, caplog):
    calls = []
    monkeypatch.setattr(permissions, "sync_permissions", lambda using="default": calls.append(using))
    monkeypatch.setattr(type(permissions.connections["default"].introspection), "table_names",
                        lambda self, cursor=None, include_views=False: ["django_content_type"])
    caplog.set_level(logging.DEBUG, logger="sso.application")
    permissions.sync_after_migrate(sender=None, using="default")
    assert calls == []
    [record] = [r for r in caplog.records if r.name == "sso.application"]
    assert record.levelno == logging.DEBUG
    assert "sso_application_permission_record" in record.getMessage()
    assert "auth_permission" in record.getMessage()


@pytest.mark.django_db
def test_sync_runs_when_all_tables_exist(monkeypatch):
    calls = []
    monkeypatch.setattr(permissions, "sync_permissions", lambda using="default": calls.append(using))
    permissions.sync_after_migrate(sender=None, using="default")
    assert calls == ["default"]
