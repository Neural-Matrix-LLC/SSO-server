"""Thomas (2026-10-16): scripts/upgrade_db.sh must cover ALL database upgrade steps; every new migration is
appended to its manifest. This test fails when a migration is added without updating the script, the schema check
and the DBA SQL docs."""
import re
from pathlib import Path

from sso.management.commands.sso_schema_check import EXPECTED

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "upgrade_db.sh"


def _manifest():
    out = {}
    for line in SCRIPT.read_text().splitlines():
        m = re.match(r"^# MANIFEST (v\S+)\s+(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).split()
    return out


def _migration_files():
    names = []
    for app in ("sso", "application"):
        for f in sorted((ROOT / app / "migrations").glob("[0-9][0-9][0-9][0-9]_*.py")):
            names.append(f"{app}.{f.stem}")
    return names


def test_every_migration_is_in_upgrade_db_manifest():
    listed = [m for ms in _manifest().values() for m in ms]
    missing = [m for m in _migration_files() if m not in listed]
    assert not missing, f"append these to the MANIFEST in scripts/upgrade_db.sh: {missing}"
    stale = [m for m in listed if m not in _migration_files()]
    assert not stale, f"manifest lists migrations that do not exist: {stale}"


def test_every_manifest_version_has_schema_check_entries():
    versions = [v for v in _manifest() if v != "v1.1"]
    missing = [v for v in versions if v not in EXPECTED]
    assert not missing, f"add tables/columns for {missing} to sso_schema_check.EXPECTED"


def test_latest_version_has_dba_sql():
    latest = list(_manifest())[-1]
    sql = list((ROOT / "docs" / "db").glob(f"upgrade-*-to-{latest}.sql"))
    assert sql, f"add docs/db/upgrade-<prev>-to-{latest}.sql for DBAs"
