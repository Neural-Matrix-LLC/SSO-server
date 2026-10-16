#!/usr/bin/env bash
# run_v12b_e2e.sh SERVER_VENV LIB_VENV TAG [extra SSO VAR=value ...] -- sso-client E2E (qa/e2e/drive_e2e.py), fresh DB.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; QA="$(cd "$HERE/.." && pwd)"
VENV="$1"; LIBV="$2"; TAG="$3"; shift 3
RUN="$QA/run"; OUT="$RUN/v12b-e2e-$TAG"; mkdir -p "$OUT"
export SSO_VENV="$VENV" SSO_ISSUER="http://127.0.0.1:8062" SSO_IP_BINDING_MODE=NOIP SSO_CACHE_URL="${SSO_CACHE_URL:-filecache:///tmp/qa-cache-v12b-e2e-$TAG}"
export SSO_SQLITE_PATH="$RUN/sso-v12b-e2e-$TAG.sqlite3"; rm -f "$SSO_SQLITE_PATH"
"$HERE/manage.sh" migrate --noinput >"$OUT/migrate.log" 2>&1 || { echo migrate failed; exit 1; }
SSO_ALLOW_SYNTHETIC_SEED=1 "$HERE/manage.sh" shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())" >"$OUT/seed.log" 2>&1 || { echo seed failed; exit 1; }
PYTHONDONTWRITEBYTECODE=1 "$LIBV/bin/python" "$QA/e2e/drive_e2e.py" "$OUT" "$@" 2>&1 | tee "$OUT/drive.log"
