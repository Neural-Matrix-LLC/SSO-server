"""Container start-up DB check: logs one clear ERROR line if MySQL is unreachable, then lets gunicorn
start anyway (the DB may come up later; /healthz reports 503 until then). Never blocks longer than
SSO_DB_CONNECT_TIMEOUT.

``python docker/dbcheck.py --strict`` (scripts/upgrade_db.sh pre-check): exit 1 when the DB is unreachable or the
settings fail, 0 when reachable."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # /app

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ssoproject.settings")  # the image sets it; a host venv may not

import django  # noqa: E402

STRICT = "--strict" in sys.argv[1:]
ok = False
try:
    django.setup()
    from sso.dbcheck import check_database, db_target, logger

    ok = check_database("upgrade" if STRICT else "startup")
    if ok:
        logger.info("%s: database reachable at %s", "upgrade" if STRICT else "startup", db_target())
        if STRICT:
            print(f"db ok: {db_target()}")
except Exception as exc:  # noqa: BLE001 - settings errors surface again in gunicorn with a traceback
    print(f"{'db check failed' if STRICT else 'startup db check skipped'}: {exc.__class__.__name__}: {exc}",
          file=sys.stderr)
if STRICT:
    sys.exit(0 if ok else 1)
