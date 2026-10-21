#!/usr/bin/env bash
# One-command (re)deploy of the SSO stack, then the post-start check.
#
#   scripts/deploy.sh [--pull | --no-pull] [--build | --no-build] [--wait-timeout SECONDS] [--skip-schema-gate]
#
#   1. .env present and "docker compose config --quiet" valid
#   2. pull the images (default when there is no Dockerfile, i.e. an image-only VPS from the deploy kit)
#   3. schema gate: a one-off "web" container (the "init" service runs first and creates missing keys / bootstrap
#      certificate, scripts/init_secrets.sh) checks as the runtime account that the database is reachable and the
#      SSO schema is at the new image's level (manage.py sso_schema_check). If not, STOP before anything is
#      (re)started: the running release stays as it is. The schema is migrated beforehand, from the migration
#      server, with scripts/upgrade_db.sh (docs/SSO-Setup.md §12.6 / §11).
#   4. docker compose up -d --wait: web, webhooks, redis and nginx must become healthy
#   5. scripts/deploy_check.sh (also when step 4 failed, to say why)
#
# Never migrates and needs no DDL account. --skip-schema-gate: start anyway (the check then reports H01).
# In a repo checkout (Dockerfile present) the images are built (--build) unless --no-build.
# Extra compose files via COMPOSE_FILE, e.g. COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml.
# DOCKER overrides the docker command (e.g. DOCKER="sudo docker").
set -uo pipefail
cd "$(dirname "$0")/.."
DOCKER="${DOCKER:-docker}"

if [[ -f Dockerfile ]]; then PULL=0 BUILD=1; else PULL=1 BUILD=0; fi
WAIT_TIMEOUT=180 GATE=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pull) PULL=1 ;;
    --no-pull) PULL=0 ;;
    --build) BUILD=1 ;;
    --no-build) BUILD=0 ;;
    --wait-timeout) WAIT_TIMEOUT="$2"; shift ;;
    --skip-schema-gate) GATE=0 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

step() { echo; echo "==> $*"; }
[[ -f .env ]] || { echo "error: no .env in $(pwd) (SSO-Setup §2 / §12.3)" >&2; exit 1; }

step "validate compose configuration"
$DOCKER compose config --quiet || exit 1
$DOCKER compose config --images

if (( PULL )); then
  step "pull images"
  $DOCKER compose pull || exit 1
fi

if (( BUILD )); then
  step "build images"
  $DOCKER compose build || exit 1
fi

T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"   # init output of this run only (the init container is reused across runs)
init_logs() { $DOCKER compose logs --no-color --no-log-prefix --since "$T0" init 2>/dev/null | sed 's/^/    /'; }
if (( GATE )); then
  step "schema gate (init: keys + certificate, then database reachable and SSO schema migrated)"
  if ! $DOCKER compose run --rm -T --pull never web \
       sh -c 'python docker/dbcheck.py --strict && python manage.py sso_schema_check'; then
    init_logs
    cat >&2 <<'MSG'

STOP: schema gate failed, nothing was (re)started; a running release keeps running.
  - init failed (keys / certificate): see its output above (SSO-Setup Troubleshooting: "init didn't complete").
  - database unreachable: SSO-Setup Troubleshooting rows 110 / 111 / 1045 / 1130.
  - "unapplied SSO migrations" / MISSING tables: the database is not migrated to this release yet. The DB team
    runs scripts/upgrade_db.sh on the migration server first (SSO-Setup §12.6 / §11), then run deploy.sh again.
MSG
    exit 3
  fi
fi

step "start (wait for healthy services, timeout ${WAIT_TIMEOUT}s)"
$DOCKER compose up -d --no-build --wait --wait-timeout "$WAIT_TIMEOUT"
up_rc=$?
init_logs
(( up_rc == 0 )) || echo "warning: 'docker compose up --wait' exited $up_rc; running the check to find out why" >&2

step "post-start check"
scripts/deploy_check.sh
check_rc=$?
(( up_rc == 0 && check_rc == 0 ))
