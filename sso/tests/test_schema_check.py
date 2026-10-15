"""scripts/upgrade_db.sh post-check: manage.py sso_schema_check (docs/db/upgrade-v1.2-to-v1.3.sql)."""
import io
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.management import call_command

from sso.management.commands import sso_schema_check as cmd

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.django_db
def test_schema_check_ok_on_migrated_db():
    out = io.StringIO()
    call_command("sso_schema_check", stdout=out)
    assert "schema OK" in out.getvalue() and "MISSING" not in out.getvalue()


@pytest.mark.django_db
def test_schema_check_reports_missing(monkeypatch):
    monkeypatch.setitem(cmd.EXPECTED, "v9", {"sso_serviceclient": ["no_such_column"], "sso_nope": ["id"]})
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command("sso_schema_check", stdout=out, stderr=err)
    assert exc.value.code == 1
    assert "sso_serviceclient.no_such_column" in err.getvalue() and "table sso_nope" in err.getvalue()


@pytest.mark.django_db
def test_schema_check_counts():
    out = io.StringIO()
    call_command("sso_schema_check", "--counts", stdout=out)
    lines = out.getvalue().split("\n")
    assert any(line.startswith("COUNT auth_user ") for line in lines)
    assert any(line.startswith("COUNT sso_webhookdelivery ") for line in lines)


def test_expected_matches_models():
    """Every table/column the check expects is defined by the current models (no typos)."""
    from django.apps import apps

    defined = {}
    for m in apps.get_models(include_auto_created=True):
        defined.setdefault(m._meta.db_table, set()).update(f.column for f in m._meta.local_fields)
    for version, spec in cmd.EXPECTED.items():
        for table, cols in spec.items():
            assert table in defined, (version, table)
            assert set(cols) <= defined[table], (version, table, set(cols) - defined[table])


def test_upgrade_script_syntax_and_no_secrets():
    script = ROOT / "scripts" / "upgrade_db.sh"
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    text = script.read_text()
    assert "-p\"$SSO_DBPWD\"" not in text and "--password=" not in text  # never on a command line
    assert "--defaults-extra-file" in text and "umask 077" in text


def test_dbcheck_strict_exit_code():
    r = subprocess.run([sys.executable, str(ROOT / "docker" / "dbcheck.py"), "--strict"], capture_output=True,
                       text=True, env={"PATH": "/usr/bin:/bin", "DJANGO_SETTINGS_MODULE": "nonexistent_settings"})
    assert r.returncode == 1 and "db check failed" in r.stderr


def test_permission_sync_skipped_on_rollback(monkeypatch):
    """Rollback with the v1.3 code (migrate application 0001) must not run the sync on the older schema."""
    from application import permissions

    called = []
    monkeypatch.setattr(permissions, "sync_permissions", lambda **k: called.append(k))
    permissions.sync_after_migrate(None, plan=[(object(), True)])
    assert called == []
