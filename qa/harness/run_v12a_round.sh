#!/usr/bin/env bash
# run_v12a_round.sh VENV TAG [PORT_BASE]  -- v1.2a QA round on throw-away SQLite DBs, dedicated ports, PID stop.
#   PORT_BASE (default 8054): +0 main, +1 grace-0 instance, +2 admin instance (SSO_SECURE_COOKIES=False),
#   +3 throttle-phase server (spec rates, fresh DB), +4 examples/verifier.  KEYROT uses QA_KEYS_PORT (8050/8051).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; QA="$(cd "$HERE/.." && pwd)"; REPO="$(cd "$QA/.." && pwd)"
VENV="$1"; TAG="$2"; B="${3:-8054}"; KPORT="${QA_KEYS_PORT:-8050}"
VENV_ABS="$(cd "$REPO" && cd "$VENV" && pwd)"
RUN="$QA/run"; OUT="$RUN/v12a-$TAG"; mkdir -p "$OUT"; rm -f "$OUT"/*
P_MAIN=$B; P_G0=$((B+1)); P_ADM=$((B+2)); P_THR=$((B+3)); P_VER=$((B+4))
for p in $P_MAIN $P_G0 $P_ADM $P_THR $P_VER $KPORT; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && { echo "port $p busy"; exit 2; }; done
[[ -s "$RUN/secret_key" ]] || { "$VENV_ABS/bin/python" -c 'import secrets;print(secrets.token_urlsafe(48))' >"$RUN/secret_key"; chmod 600 "$RUN/secret_key"; }
export SSO_VENV="$VENV" SSO_ISSUER="http://127.0.0.1:$P_MAIN"
FAST="SSO_THROTTLE_LOGIN=10000/min SSO_THROTTLE_LOGIN_USER=10000/min SSO_THROTTLE_REFRESH=10000/min"
VPID=""
cleanup() { for p in $P_MAIN $P_G0 $P_ADM $P_THR; do "$HERE/stop_sso.sh" $p >/dev/null 2>&1; done
            [[ -n "$VPID" ]] && kill -0 "$VPID" 2>/dev/null && grep -q uvicorn /proc/$VPID/cmdline && kill "$VPID"; }
trap cleanup EXIT
setup_db() {  # $1 db path
  export SSO_SQLITE_PATH="$1"; rm -f "$1"
  "$HERE/manage.sh" migrate --noinput >"$OUT/migrate-$(basename "$1").log" 2>&1 || { echo "migrate failed"; exit 1; }
  SSO_ALLOW_SYNTHETIC_SEED=1 "$HERE/manage.sh" shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())" \
     >"$OUT/seed-$(basename "$1").log" 2>&1 || { echo "seed failed"; exit 1; }
}
wait_up() { for _ in $(seq 80); do curl -fsS "http://127.0.0.1:$1/healthz" >/dev/null 2>&1 && return 0; sleep 0.5; done; echo "port $1 not up"; return 1; }
common_env() {
  export SSO_BASE_URL="http://127.0.0.1:$1" SSO_AUDIENCE=myfin-services SSO_TEST_ALLOWED_ORIGIN=https://example.com \
         SSO_COOKIE_DOMAIN= SSO_TEST_PRIVATE_KEY_PATH="$RUN/keys/qa-test.private.pem" SSO_MANAGE_CMD="$HERE/manage.sh" \
         SSO_REPO_DIR="$REPO" QA_SSO_PYTHON="$VENV_ABS/bin/python" QA_KEYS_PORT="$KPORT" PYTHONDONTWRITEBYTECODE=1
}
# ---------------- phase 1: functional + static + keys + v12a (high rates)
setup_db "$RUN/sso-v12a-$TAG.sqlite3"
export SSO_CACHE_URL="filecache:///tmp/qa-cache-v12a-$TAG-main"
"$HERE/start_sso.sh" $P_MAIN "$OUT/sso-main.log" $FAST
SSO_CACHE_URL="filecache:///tmp/qa-cache-v12a-$TAG-g0" "$HERE/start_sso.sh" $P_G0 "$OUT/sso-grace0.log" $FAST SSO_REFRESH_REUSE_GRACE_SECONDS=0
SSO_CACHE_URL="filecache:///tmp/qa-cache-v12a-$TAG-adm" "$HERE/start_sso.sh" $P_ADM "$OUT/sso-admin.log" $FAST SSO_SECURE_COOKIES=False
wait_up $P_MAIN && wait_up $P_G0 && wait_up $P_ADM || exit 1
( cd "$REPO/examples/verifier" && VERIFIER_CORS_ORIGINS=https://example.com SSO_JWKS_URL="http://127.0.0.1:$P_MAIN/.well-known/jwks.json" SSO_ISSUER="$SSO_ISSUER" \
  exec "$VENV_ABS/bin/python" -m uvicorn verifier_app:app --host 127.0.0.1 --port $P_VER >"$OUT/verifier.log" 2>&1 ) & echo $! >"$RUN/verifier-$P_VER.pid"
VPID="$(cat "$RUN/verifier-$P_VER.pid")"
for p in $P_MAIN $P_G0 $P_ADM; do echo "$p: $(tr '\0' ' ' </proc/$(cat "$RUN/sso-$p.pid")/cmdline)"; done >"$OUT/server-cmdline.txt"
echo "verifier: $(tr '\0' ' ' </proc/$VPID/cmdline)" >>"$OUT/server-cmdline.txt"
common_env $P_MAIN
export SSO_GRACE0_URL="http://127.0.0.1:$P_G0" SSO_ADMIN_URL="http://127.0.0.1:$P_ADM" \
       SSO_SERVER_LOG="$OUT/sso-main.log" SSO_GRACE0_LOG="$OUT/sso-grace0.log" SSO_ADMIN_LOG="$OUT/sso-admin.log" \
       SSO_ACCESS_LOG="$OUT/sso-main.log" VERIFIER_BASE_URL="http://127.0.0.1:$P_VER" VERIFIER_PROTECTED_PATH=/me \
       VERIFIER_GROUP_PATH=/group/qa_trader VERIFIER_GROUP_NAME=qa_trader \
       SSO_TEST_RATE_LOGIN_IP=10000 SSO_TEST_RATE_LOGIN_USER=10000 SSO_TEST_RATE_REFRESH=10000
cd "$QA/tests"
"$VENV_ABS/bin/python" -m pytest -p no:cacheprovider -q -rfEsx -m "not throttle" . \
   --junitxml="$OUT/junit-functional.xml" >"$OUT/pytest-functional.log" 2>&1; RC1=$?
tail -2 "$OUT/pytest-functional.log"
cleanup; VPID=""
# ---------------- phase 2: throttle suite at spec rates, fresh DB
cd "$REPO"; setup_db "$RUN/sso-v12a-$TAG-thr.sqlite3"
export SSO_CACHE_URL="filecache:///tmp/qa-cache-v12a-$TAG-thr-$$"; export SSO_ISSUER="http://127.0.0.1:$P_THR"
"$HERE/start_sso.sh" $P_THR "$OUT/sso-throttle.log"; wait_up $P_THR || exit 1
common_env $P_THR; unset SSO_TEST_RATE_LOGIN_IP SSO_TEST_RATE_LOGIN_USER SSO_TEST_RATE_REFRESH
cd "$QA/tests"
"$VENV_ABS/bin/python" -m pytest -p no:cacheprovider -q -rfEsx -m throttle . \
   --junitxml="$OUT/junit-throttle.xml" >"$OUT/pytest-throttle.log" 2>&1; RC2=$?
tail -2 "$OUT/pytest-throttle.log"
echo "rc functional=$RC1 throttle=$RC2"
