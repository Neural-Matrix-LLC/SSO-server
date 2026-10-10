"""Seed QA users/groups/service clients into the SSO server's database.

Run from the sso-server repo root, inside the server's Django environment, e.g.:

    SSO_ALLOW_SYNTHETIC_SEED=1 python manage.py shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())"
    # or with docker:
    docker compose exec -T -e SSO_ALLOW_SYNTHETIC_SEED=1 web python manage.py shell < qa/tests/fixtures/seed_test_data.py

Idempotent: re-running resets every qa_* user (password hash, flags, groups) so state-
changing tests (rehash, deactivate, logout-all) start clean. Touches only rows whose
username starts with "qa_" and service clients whose client_id starts with "qa-".
NEVER run against production dcWebUsers.

Set QA_TESTS_DIR if qa/tests is not at ./qa/tests relative to the current directory.

SAFETY GUARD (deployment plan R27). The script refuses to run (exit code 2) unless BOTH are true:
  1. SSO_ALLOW_SYNTHETIC_SEED=1 is set in the environment of the Django process
     (QA_ALLOW_SEED=1 is accepted as an alias), and
  2. the configured database is a local/throw-away one:
     - SQLite: ":memory:", or a file under the system temp dir, under a "qa" directory,
       or whose file name contains "test" or "qa";
     - MySQL/other: HOST is a local or container host (localhost, 127.0.0.1, ::1, a unix socket,
       "db", "mysql", or a name listed in SSO_SEED_LOCAL_HOSTS, comma-separated).
"""
import os
import sys
import tempfile
from pathlib import Path

from django.conf import settings as _settings


def _seed_guard() -> None:
    def refuse(msg: str) -> None:
        sys.stderr.write(f"REFUSING TO SEED: {msg}\n"
                         "The QA seed creates/reset qa_* users and must only run on a throw-away test DB "
                         "(deployment plan R27). See the header of qa/tests/fixtures/seed_test_data.py.\n")
        raise SystemExit(2)

    flag = os.environ.get("SSO_ALLOW_SYNTHETIC_SEED") or os.environ.get("QA_ALLOW_SEED")
    if flag != "1":
        refuse("SSO_ALLOW_SYNTHETIC_SEED=1 is not set.")
    db = _settings.DATABASES["default"]
    engine, name = db.get("ENGINE", ""), str(db.get("NAME", ""))
    if engine.endswith("sqlite3"):
        if name == ":memory:" or name.startswith("file::memory:"):
            return
        path = Path(name).resolve()
        tmp = Path(tempfile.gettempdir()).resolve()
        lowered = path.name.lower()
        if tmp in path.parents or "qa" in [p.lower() for p in path.parts[:-1]] or "test" in lowered or "qa" in lowered:
            return
        refuse(f"SQLite DB {path} is not under {tmp}, not under a 'qa' directory, and its name has no 'test'/'qa'.")
    host = str(db.get("HOST", "") or "")
    extra = {h.strip().lower() for h in os.environ.get("SSO_SEED_LOCAL_HOSTS", "").split(",") if h.strip()}
    local = {"", "localhost", "127.0.0.1", "::1", "db", "mysql"} | extra
    if host.lower() in local or host.startswith("/"):
        return
    refuse(f"database host {host!r} (engine {engine}, name {name!r}) is not a local/container host.")


_seed_guard()

sys.path.insert(0, os.environ.get("QA_TESTS_DIR", "qa/tests"))

from django.contrib.auth.hashers import make_password  # noqa: E402
from django.contrib.auth.models import Group, User  # noqa: E402

import testdata  # noqa: E402

for g in testdata.GROUPS:
    Group.objects.get_or_create(name=g)

for username, u in testdata.USERS.items():
    assert username.startswith("qa_")
    user, _ = User.objects.update_or_create(
        username=username,
        defaults=dict(email=u["email"], first_name=u["first_name"], last_name=u["last_name"],
                      is_staff=u["is_staff"], is_active=u["is_active"], is_superuser=False,
                      password=testdata.password_hash_for(username)),
    )
    user.groups.set(Group.objects.filter(name__in=u["groups"]))

# Clear revocation markers / outstanding tokens for qa users so runs are repeatable.
try:
    from sso.models import UserTokenRevocation
    UserTokenRevocation.objects.filter(user__username__startswith="qa_").delete()
except Exception as e:  # model name may differ while the server is being built
    print("WARN: could not reset UserTokenRevocation:", e)

try:
    from sso.models import ServiceClient
    for cid, secret, active in [
        (testdata.SERVICE_CLIENT_ID, testdata.SERVICE_CLIENT_SECRET, True),
        (testdata.INACTIVE_SERVICE_CLIENT_ID, testdata.INACTIVE_SERVICE_CLIENT_SECRET, False),
    ]:
        ServiceClient.objects.update_or_create(
            client_id=cid,
            defaults=dict(name=cid, client_secret_hash=make_password(secret), is_active=active),
        )
except Exception as e:
    print("WARN: could not seed ServiceClient:", e)

print("QA seed done:", len(testdata.USERS), "users")
