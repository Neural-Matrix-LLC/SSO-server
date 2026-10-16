#!/usr/bin/env bash
# run_keys_round.sh PYVENV TAG PORT -- static deploy tests + key tests (KEYCFG/KEYROT) + JWKS/discovery/health and JWT
# security tests against a server started with the NEW key variables. Throw-away DB, dedicated port, PID stop.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; QA="$(cd "$HERE/.." && pwd)"; REPO="$(cd "$QA/.." && pwd)"
VENV="$1"; TAG="$2"; PORT="$3"; KPORT="${4:-8050}"
VENV_ABS="$(cd "$REPO" && cd "$VENV" && pwd)"
RUN="$QA/run"; OUT="$RUN/keys-$TAG"; mkdir -p "$OUT"; rm -f "$OUT"/*
[[ -s "$RUN/secret_key" ]] || { "$VENV_ABS/bin/python" -c 'import secrets;print(secrets.token_urlsafe(48))' >"$RUN/secret_key"; chmod 600 "$RUN/secret_key"; }
export SSO_VENV="$VENV" SSO_SQLITE_PATH="$RUN/sso-keys-$TAG.sqlite3" SSO_CACHE_URL="filecache:///tmp/qa-cache-keys-$TAG"
export SSO_ISSUER="http://127.0.0.1:$PORT"
rm -f "$SSO_SQLITE_PATH"; rm -rf "/tmp/qa-cache-keys-$TAG"
"$HERE/manage.sh" migrate --noinput >"$OUT/migrate.log" 2>&1 || { echo migrate failed; exit 1; }
SSO_ALLOW_SYNTHETIC_SEED=1 "$HERE/manage.sh" shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())" >"$OUT/seed.log" 2>&1 || { echo seed failed; tail "$OUT/seed.log"; exit 1; }
"$HERE/manage.sh" check >"$OUT/check.log" 2>&1; echo "manage.py check exit $?" >>"$OUT/check.log"
"$HERE/start_sso.sh" "$PORT" "$OUT/sso-server.log" SSO_THROTTLE_LOGIN=1000/min SSO_THROTTLE_LOGIN_USER=1000/min SSO_THROTTLE_REFRESH=1000/min
for _ in $(seq 60); do curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
cat /proc/"$(cat "$RUN/sso-$PORT.pid")"/cmdline | tr '\0' ' ' >"$OUT/server-cmdline.txt"; echo >>"$OUT/server-cmdline.txt"
cd "$QA/tests"
export SSO_BASE_URL="http://127.0.0.1:$PORT" SSO_AUDIENCE=myfin-services SSO_TEST_ALLOWED_ORIGIN=https://example.com \
       SSO_COOKIE_DOMAIN= SSO_TEST_PRIVATE_KEY_PATH="$RUN/keys/qa-test.private.pem" SSO_MANAGE_CMD="$HERE/manage.sh" \
       SSO_REPO_DIR="$REPO" QA_SSO_PYTHON="$VENV_ABS/bin/python" QA_KEYS_PORT="$KPORT" PYTHONDONTWRITEBYTECODE=1
cd "$QA/tests" && "$VENV_ABS/bin/python" -m pytest -p no:cacheprovider -q -rfEsx \
  test_deploy_files.py test_keys_config.py test_jwks_discovery_health.py test_security_jwt.py \
  --junitxml="$OUT/junit.xml" >"$OUT/pytest.log" 2>&1; RC=$?
"$HERE/stop_sso.sh" "$PORT" >>"$OUT/pytest.log"
tail -3 "$OUT/pytest.log"; echo "rc=$RC"
