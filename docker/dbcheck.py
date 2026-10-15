"""Container start-up DB check: logs one clear ERROR line if MySQL is unreachable, then lets gunicorn
start anyway (the DB may come up later; /healthz reports 503 until then). Never blocks longer than
SSO_DB_CONNECT_TIMEOUT."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # /app

import django  # noqa: E402

try:
    django.setup()
    from sso.dbcheck import check_database, db_target, logger

    if check_database("startup"):
        logger.info("startup: database reachable at %s", db_target())
except Exception as exc:  # noqa: BLE001 - settings errors surface again in gunicorn with a traceback
    print(f"startup db check skipped: {exc.__class__.__name__}: {exc}", file=sys.stderr)
