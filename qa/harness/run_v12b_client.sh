#!/usr/bin/env bash
# run_v12b_client.sh SERVER_VENV LIB_VENV TAG [pytest args] -- qa/tests_client against live SSOs (8065/8066) on a fresh DB.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; QA="$(cd "$HERE/.." && pwd)"; REPO="$(cd "$QA/.." && pwd)"
VENV="$1"; LIBV="$2"; TAG="$3"; shift 3
RUN="$QA/run"; OUT="$RUN/v12b-client-$TAG"; mkdir -p "$OUT"
export SSO_VENV="$VENV" SSO_ISSUER="http://127.0.0.1:8065" SSO_IP_BINDING_MODE=NOIP
export SSO_SQLITE_PATH="$RUN/sso-v12b-client-$TAG.sqlite3"; rm -f "$SSO_SQLITE_PATH"
"$HERE/manage.sh" migrate --noinput >"$OUT/migrate.log" 2>&1 || { echo migrate failed; exit 1; }
SSO_ALLOW_SYNTHETIC_SEED=1 "$HERE/manage.sh" shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())" >"$OUT/seed.log" 2>&1 || { echo seed failed; exit 1; }
cd "$QA/tests_client"
PYTHONDONTWRITEBYTECODE=1 "$LIBV/bin/python" -m pytest -p no:cacheprovider -q -rfEsx . --junitxml="$OUT/junit.xml" "$@" 2>&1 | tee "$OUT/pytest.log" | tail -30
