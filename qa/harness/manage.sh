#!/usr/bin/env bash
# manage.sh ARGS... -- manage.py against the QA SQLite DB with the QA key config (harness/sso.env).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sso.env"
export SSO_ISSUER="${SSO_ISSUER:-http://127.0.0.1:8050}"
cd "$HERE/../.."
case "$SSO_SQLITE_PATH" in */qa/run/*) ;; *) echo "refusing non-QA DB $SSO_SQLITE_PATH" >&2; exit 2;; esac
exec "${SSO_VENV:-.venv}/bin/python" manage.py "$@"
