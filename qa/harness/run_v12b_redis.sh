#!/usr/bin/env bash
# run_v12b_redis.sh VENV TAG -- REDIS-01: real Redis 7 (docker, host network, 127.0.0.1:8069) as SSO_CACHE_URL.
#  (a) test_v12b.py cache/throttle/binding cases with every server on 3 gunicorn workers sharing Redis;
#  (b) the login/refresh throttle suite (spec rates) against ONE gunicorn with 3 workers on 8057 + Redis.
# Starts/stops only its own container (sso-qa-v12b-redis) and gunicorn (PID file).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; QA="$(cd "$HERE/.." && pwd)"; REPO="$(cd "$QA/.." && pwd)"
VENV="$1"; TAG="$2"; VENV_ABS="$(cd "$REPO" && cd "$VENV" && pwd)"; RUN="$QA/run"; OUT="$RUN/v12b-redis-$TAG"; mkdir -p "$OUT"
REDIS_URL="redis://127.0.0.1:8069/0"
sudo docker run -d --rm --name sso-qa-v12b-redis --network host redis:7 redis-server --port 8069 --bind 127.0.0.1 --save "" --appendonly no >"$OUT/redis-id.txt" || exit 1
cleanup() { "$HERE/stop_sso.sh" 8057 >/dev/null 2>&1; sudo docker stop sso-qa-v12b-redis >/dev/null 2>&1; }
trap cleanup EXIT
for _ in $(seq 40); do sudo docker exec sso-qa-v12b-redis redis-cli -p 8069 ping 2>/dev/null | grep -q PONG && break; sleep 0.5; done
sudo docker exec sso-qa-v12b-redis redis-server --version >"$OUT/redis-version.txt"
# (a)
QA_V12B_CACHE_URL="$REDIS_URL" QA_V12B_WORKERS=3 "$HERE/run_v12b_only.sh" "$VENV" "redis-$TAG" \
   -k "CACHE or INTRO_04 or BIND_03 or BIND_06 or BIND_07" >"$OUT/a-summary.txt" 2>&1
tail -3 "$OUT/a-summary.txt"
sudo docker exec sso-qa-v12b-redis redis-cli -p 8069 --scan --pattern '*revoked_sid*' | wc -l >"$OUT/a-revoked-keys.txt"
# (b)
export SSO_VENV="$VENV" SSO_ISSUER="http://127.0.0.1:8057" SSO_SQLITE_PATH="$RUN/sso-v12b-redis-thr-$TAG.sqlite3" SSO_CACHE_URL="$REDIS_URL"
rm -f "$SSO_SQLITE_PATH"; sudo docker exec sso-qa-v12b-redis redis-cli -p 8069 flushall >/dev/null
"$HERE/manage.sh" migrate --noinput >"$OUT/migrate.log" 2>&1 && SSO_ALLOW_SYNTHETIC_SEED=1 "$HERE/manage.sh" shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())" >"$OUT/seed.log" 2>&1 || { echo seed failed; exit 1; }
GUNICORN_WORKERS=3 "$HERE/start_sso.sh" 8057 "$OUT/sso-throttle.log"
for _ in $(seq 80); do curl -fsS http://127.0.0.1:8057/healthz >/dev/null 2>&1 && break; sleep 0.5; done
pgrep -P "$(cat "$RUN/sso-8057.pid")" | wc -l >"$OUT/b-worker-count.txt"
export SSO_BASE_URL=http://127.0.0.1:8057 SSO_AUDIENCE=myfin-services SSO_TEST_ALLOWED_ORIGIN=https://example.com SSO_COOKIE_DOMAIN= \
       SSO_TEST_PRIVATE_KEY_PATH="$RUN/keys/qa-test.private.pem" SSO_MANAGE_CMD="$HERE/manage.sh" SSO_REPO_DIR="$REPO" PYTHONDONTWRITEBYTECODE=1
cd "$QA/tests" && "$VENV_ABS/bin/python" -m pytest -p no:cacheprovider -q -rfEsx -m throttle . --junitxml="$OUT/junit-throttle.xml" >"$OUT/pytest-throttle.log" 2>&1
tail -2 "$OUT/pytest-throttle.log"; echo "workers: $(cat "$OUT/b-worker-count.txt")"
