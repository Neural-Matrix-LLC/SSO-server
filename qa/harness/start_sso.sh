#!/usr/bin/env bash
# start_sso.sh PORT LOGFILE [VAR=value ...] -- gunicorn on a DEDICATED port (never 8000) against the QA SQLite DB.
# Records the PID in qa/run/sso-PORT.pid; stop with harness/stop_sso.sh PORT (by PID only).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$1"; LOG="$2"; shift 2
[[ "$PORT" != 8000 ]] || { echo "refusing port 8000" >&2; exit 2; }
. "$HERE/sso.env"
for kv in "$@"; do export "$kv"; done
export SSO_ISSUER="${SSO_ISSUER:-http://127.0.0.1:$PORT}"
cd "$HERE/../.."
VENV="${SSO_VENV:-.venv}"
echo "QA start_sso: $($VENV/bin/python -c 'import sys,platform; print("Python", platform.python_version(), sys.executable)')" >"$LOG"
echo "QA keys: mount=$SSO_JWT_KEYS_MOUNT private=$SSO_JWT_PRIVATE_KEY publics=$SSO_JWT_PUBLIC_KEYS" >>"$LOG"
setsid "$VENV/bin/gunicorn" ssoproject.wsgi:application -b "127.0.0.1:$PORT" --workers "${GUNICORN_WORKERS:-1}" \
  --access-logfile - --error-logfile - >>"$LOG" 2>&1 &
echo $! >"$QA_RUN/sso-$PORT.pid"
echo "started pid $! on $PORT"
