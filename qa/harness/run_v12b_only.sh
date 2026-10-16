#!/usr/bin/env bash
# run_v12b_only.sh VENV TAG [pytest args]  -- only qa/tests/test_v12b.py on a fresh throw-away DB (servers self-started).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; QA="$(cd "$HERE/.." && pwd)"; REPO="$(cd "$QA/.." && pwd)"
VENV="$1"; TAG="$2"; shift 2
VENV_ABS="$(cd "$REPO" && cd "$VENV" && pwd)"; RUN="$QA/run"; OUT="$RUN/v12b-only-$TAG"; mkdir -p "$OUT"
export SSO_VENV="$VENV" SSO_ISSUER="http://127.0.0.1:8060" QA_V12B_TAG="only-$TAG" SSO_IP_BINDING_MODE=NOIP
export SSO_SQLITE_PATH="$RUN/sso-v12b-only-$TAG.sqlite3"; rm -f "$SSO_SQLITE_PATH"
"$HERE/manage.sh" migrate --noinput >"$OUT/migrate.log" 2>&1 || { echo migrate failed; exit 1; }
SSO_ALLOW_SYNTHETIC_SEED=1 "$HERE/manage.sh" shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())" >"$OUT/seed.log" 2>&1 || { echo seed failed; exit 1; }
export SSO_MANAGE_CMD="$HERE/manage.sh" SSO_REPO_DIR="$REPO" SSO_BASE_URL="http://127.0.0.1:8060" PYTHONDONTWRITEBYTECODE=1
cd "$QA/tests"
"$VENV_ABS/bin/python" -m pytest -p no:cacheprovider -q -rfEsx test_v12b.py --junitxml="$OUT/junit.xml" "$@" 2>&1 | tee "$OUT/pytest.log" | tail -40
