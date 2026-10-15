#!/usr/bin/env bash
# Upgrade the SSO-owned schema in the shared dcWebUsers database to the code's level (v1.3: sso 0003-0006,
# application 0002; from v1.1 also sso 0002). Safe to re-run: with nothing to apply it only checks.
#
#   scripts/upgrade_db.sh [options]
#
# Steps: 1 pre-check (DB reachable, docker/dbcheck.py --strict)  2 current state (showmigrations + migrate --plan;
# STOP if the plan touches any app other than sso / application / token_blacklist)  3 backup of the SSO-owned
# tables (mysqldump, default on)  4 migrate  5 post-check (manage.py sso_schema_check: all SSO migrations applied,
# every v1.1-v1.3c table/column present; row counts unchanged)  6 summary. Exit code != 0 on any failure.
#
# Runner (default: compose when docker-compose.yml + docker compose are available, else venv):
#   --compose            docker compose run --rm web python manage.py ... (builds the image first, see --no-build)
#   --venv [DIR]         DIR/bin/python manage.py ... on this host (default DIR: .venv; needs mysqlclient)
# Options:
#   --plan               dry run: steps 1, 2 and the schema report only; no backup, no migrate
#   --no-backup          skip step 3 (not recommended)
#   --backup-dir DIR     where the dump goes (default ./backups, created 700)
#   --dump-with WHAT     auto | host | docker   (auto: host mysqldump if it is MySQL's, else the mysql image)
#   --mysql-image IMG    client image for --dump-with docker (default mysql:8.4; dumps 8.0 and 8.4)
#   --db-host H --db-port P   address mysqldump uses (default: SSO_DBHOST/SSO_DBPORT; in compose mode the dump
#                        container runs on the compose edge network, so host.docker.internal works as in .env)
#   --no-build           compose: do not rebuild the web image first
#   --allow-shared-apps  allow a plan that also creates Django's shared apps (auth, admin, ...): ONLY for an empty
#                        local/test database, never for the shared production dcWebUsers
#   -y, --yes            do not ask before migrating
#
# Credentials: the DDL account. SSO_DBUSER (default sso_migrator) and SSO_DBPWD from the environment; if
# SSO_DBPWD is unset the script asks (hidden input). The password is never written to the command line or to a
# file in the repo: containers get it with "-e SSO_DBPWD" (name only), mysqldump reads a temporary 600
# --defaults-extra-file that is deleted on exit. Other settings come from .env as for the server.
# DOCKER overrides the docker command (e.g. DOCKER="sudo docker").
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."

RUNNER="" VENV=".venv" PLAN=0 BACKUP=1 BACKUP_DIR="./backups" DUMP_WITH="auto" MYSQL_IMAGE="mysql:8.4"
DB_HOST_OVR="" DB_PORT_OVR="" BUILD=1 YES=0 ALLOW_SHARED=0
DOCKER="${DOCKER:-docker}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --compose) RUNNER=compose ;;
    --venv) RUNNER=venv; if [[ $# -gt 1 && "$2" != -* ]]; then VENV="$2"; shift; fi ;;
    --plan) PLAN=1 ;;
    --no-backup) BACKUP=0 ;;
    --backup-dir) BACKUP_DIR="$2"; shift ;;
    --dump-with) DUMP_WITH="$2"; shift ;;
    --mysql-image) MYSQL_IMAGE="$2"; shift ;;
    --db-host) DB_HOST_OVR="$2"; shift ;;
    --db-port) DB_PORT_OVR="$2"; shift ;;
    --no-build) BUILD=0 ;;
    --allow-shared-apps) ALLOW_SHARED=1 ;;
    -y|--yes) YES=1 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

STEP="start"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'echo "FAILED in step: $STEP (exit $?)" >&2' ERR
say() { printf '\n== %s\n' "$*"; }

# value from the environment, else from .env (first "KEY=value", inline " # comment" and quotes stripped)
envval() {
  local k="$1" v=""
  if [[ -n "${!k:-}" ]]; then printf '%s' "${!k}"; return; fi
  [[ -f .env ]] || return 0
  v="$(sed -n "s/^${k}=//p" .env | tail -n 1)"
  v="${v%%[[:space:]]#*}"; v="${v%"${v##*[![:space:]]}"}"
  v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
  printf '%s' "$v"
}

if [[ -z "$RUNNER" ]]; then
  if [[ -f docker-compose.yml ]] && $DOCKER compose version >/dev/null 2>&1; then RUNNER=compose; else RUNNER=venv; fi
fi
export SSO_DBUSER="${SSO_DBUSER:-sso_migrator}"
if [[ -z "${SSO_DBPWD:-}" ]]; then
  [[ -t 0 ]] || { echo "SSO_DBPWD is not set and stdin is not a terminal" >&2; exit 2; }
  read -rs -p "password for ${SSO_DBUSER}: " SSO_DBPWD; echo
fi
export SSO_DBPWD
DBNAME="$(envval SSO_DBNAME)"; DBNAME="${DBNAME:-dcWebUsers}"
DBHOST="${DB_HOST_OVR:-$(envval SSO_DBHOST)}"; DBHOST="${DBHOST:-127.0.0.1}"
DBPORT="${DB_PORT_OVR:-$(envval SSO_DBPORT)}"; DBPORT="${DBPORT:-3306}"
if [[ "$RUNNER" == venv && "$DBHOST" == host.docker.internal && -z "$DB_HOST_OVR" ]]; then
  DBHOST=127.0.0.1   # .env written for the container; on the host the same MySQL is local
  export SSO_DBHOST=127.0.0.1
fi

manage() {
  if [[ "$RUNNER" == compose ]]; then
    $DOCKER compose run --rm -T -e SSO_DBUSER -e SSO_DBPWD web python manage.py "$@"
  else
    "$VENV/bin/python" manage.py "$@"
  fi
}
pyrun() {  # python file inside the runner (path relative to the repo / /app)
  if [[ "$RUNNER" == compose ]]; then
    $DOCKER compose run --rm -T -e SSO_DBUSER -e SSO_DBPWD web python "$@"
  else
    "$VENV/bin/python" "$@"
  fi
}

echo "SSO database upgrade: runner=$RUNNER db=$DBNAME user=$SSO_DBUSER mode=$([[ $PLAN == 1 ]] && echo plan || echo apply)"
if [[ "$RUNNER" == compose && "$BUILD" == 1 ]]; then
  STEP="build"; say "0. docker compose build web (the image must contain the new migrations)"
  $DOCKER compose build -q web
fi
if [[ "$RUNNER" == venv ]]; then
  [[ -x "$VENV/bin/python" ]] || { echo "no venv at $VENV (use --venv DIR)" >&2; exit 2; }
  "$VENV/bin/python" -c 'import MySQLdb' 2>/dev/null || { echo "$VENV lacks mysqlclient (pip install -r requirements.txt)" >&2; exit 2; }
fi

STEP="1 pre-check"; say "1. pre-check: database reachable"
pyrun docker/dbcheck.py --strict

STEP="2 state"; say "2. current state"
manage showmigrations sso application token_blacklist
manage migrate --plan | tee "$TMP/plan.txt"
foreign="$(grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*\.[0-9]{4}_' "$TMP/plan.txt" | sed 's/^[[:space:]]*//' | cut -d. -f1 \
           | grep -vxE 'sso|application|token_blacklist' | sort -u || true)"
if [[ -n "$foreign" && "$ALLOW_SHARED" == 1 ]]; then
  echo "WARNING: --allow-shared-apps: the plan also creates $(echo $foreign) (empty local/test database only)"
elif [[ -n "$foreign" ]]; then
  echo "STOP: the plan also migrates shared apps ($(echo $foreign)). dcWebUsers is shared with myFinance; nothing done." >&2
  exit 3
fi
PENDING="$(grep -cE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*\.[0-9]{4}_' "$TMP/plan.txt" || true)"
echo "pending SSO migrations: $PENDING"
manage sso_schema_check --counts > "$TMP/before.txt"

if [[ "$PLAN" == 1 ]]; then
  STEP="plan report"; say "schema report (plan mode, nothing changed)"
  manage sso_schema_check || true
  echo; echo "PLAN ONLY: $PENDING migration(s) would be applied. Re-run without --plan to apply."
  exit 0
fi

BACKUP_FILE=""
if [[ "$PENDING" -eq 0 ]]; then
  say "3./4. nothing to apply: no backup, no migrate"
else
  if [[ "$BACKUP" == 1 ]]; then
    STEP="3 backup"; say "3. backup of the SSO-owned tables"
    mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    TS="$(date +%Y%m%dT%H%M%S)"
    BACKUP_FILE="$BACKUP_DIR/sso-tables-$DBNAME-$TS.sql.gz"
    CNF="$TMP/my.cnf"
    printf '[client]\nuser=%s\npassword="%s"\nhost=%s\nport=%s\n' "$SSO_DBUSER" "${SSO_DBPWD//\"/\\\"}" "$DBHOST" "$DBPORT" > "$CNF"
    chmod 600 "$CNF"
    if [[ "$DUMP_WITH" == auto ]]; then
      if command -v mysqldump >/dev/null && ! mysqldump --version 2>/dev/null | grep -qi mariadb; then DUMP_WITH=host
      elif $DOCKER version >/dev/null 2>&1; then DUMP_WITH=docker
      elif command -v mysqldump >/dev/null; then DUMP_WITH=host
      else echo "no mysqldump and no docker: install mysql-client or use --no-backup" >&2; exit 4; fi
    fi
    client() {  # client <mysql|mysqldump> args...   (credentials from the options file only)
      local bin="$1"; shift
      if [[ "$DUMP_WITH" == host ]]; then
        "$bin" --defaults-extra-file="$CNF" "$@"
      else
        local net=(--network host)
        if [[ "$RUNNER" == compose ]]; then
          local n; n="$($DOCKER network ls -q --filter label=com.docker.compose.network=edge \
                        --filter "label=com.docker.compose.project=$($DOCKER compose config 2>/dev/null | sed -n 's/^name: //p' | head -1)" | head -1)"
          [[ -n "$n" ]] && net=(--network "$n" --add-host host.docker.internal:host-gateway)
        fi
        $DOCKER run --rm -i "${net[@]}" --user "$(id -u):$(id -g)" -v "$CNF:/tmp/my.cnf:ro" "$MYSQL_IMAGE" \
          "$bin" --defaults-extra-file=/tmp/my.cnf "$@"
      fi
    }
    MARIA=0; [[ "$DUMP_WITH" == host ]] && mysqldump --version 2>/dev/null | grep -qi mariadb && MARIA=1
    TABLES="$(client mysql -N -B -e "SELECT table_name FROM information_schema.tables WHERE table_schema='$DBNAME' \
      AND table_type='BASE TABLE' AND (table_name LIKE 'sso\\_%' OR table_name LIKE 'token\\_blacklist\\_%') ORDER BY 1")"
    if [[ -z "$TABLES" ]]; then
      echo "no SSO tables in $DBNAME yet (first installation): nothing to back up. Back up the whole database"
      echo "yourself before a first installation on the shared dcWebUsers (README §5 step 1)."
    else
    echo "tables: $(echo $TABLES)"
    OPTS=(--single-transaction --quick --hex-blob --no-tablespaces --default-character-set=utf8mb4 --skip-triggers)
    [[ "$MARIA" == 1 ]] || OPTS+=(--set-gtid-purged=OFF --column-statistics=0)
    {
      echo "-- SSO-owned tables of $DBNAME before the v1.3 upgrade, $TS. Restore: docs/db/upgrade-v1.2-to-v1.3.sql (rollback)."
      client mysqldump "${OPTS[@]}" "$DBNAME" $TABLES
      echo "-- django_migrations rows of sso / application / token_blacklist (data only)"
      client mysqldump "${OPTS[@]}" --no-create-info --skip-add-locks \
        --where="app IN ('sso','application','token_blacklist')" "$DBNAME" django_migrations
    } | gzip -9 > "$BACKUP_FILE"
    gzip -t "$BACKUP_FILE"
    [[ "$(zcat "$BACKUP_FILE" | grep -c '^-- Dump completed')" -ge 2 ]] || { echo "backup incomplete: $BACKUP_FILE" >&2; exit 4; }
    echo "backup: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1)); it holds service secret hashes: keep it private"
    fi
  else
    say "3. backup skipped (--no-backup)"
  fi
  if [[ "$YES" == 0 && -t 0 ]]; then
    read -r -p "apply $PENDING migration(s) to $DBNAME now? [y/N] " a
    [[ "$a" == y || "$a" == Y ]] || { echo "aborted, nothing changed"; exit 1; }
  fi
  STEP="4 migrate"; say "4. migrate"
  manage migrate --noinput
fi

STEP="5 post-check"; say "5. post-check"
manage sso_schema_check
manage sso_schema_check --counts > "$TMP/after.txt"
changed="$(join <(sort "$TMP/before.txt" | awk '{print $2, $3}') <(sort "$TMP/after.txt" | awk '{print $2, $3}') \
           | awk '($3 < $2) || ($2 != $3 && $1 != "auth_permission" && $1 != "sso_application_permission_record") \
                  {print $1": "$2" -> "$3}')"
if [[ -n "$changed" ]]; then
  echo "ERROR row counts changed during the upgrade:" >&2; echo "$changed" >&2; exit 5
fi
echo "row counts unchanged ($(wc -l < "$TMP/before.txt") tables compared; auth_permission and
  sso_application_permission_record may only grow: post-migrate adds the new model and code-defined permissions, e.g.
  application.sso_admin)"

STEP="summary"; say "6. summary"
echo "database:        $DBNAME as $SSO_DBUSER via $RUNNER"
echo "applied:         $PENDING migration(s)"
echo "backup:          ${BACKUP_FILE:-none}"
echo "schema:          OK (sso_schema_check)"
manage showmigrations sso application token_blacklist | sed 's/^/  /'
echo "done. Next: restart the stack (docker compose up -d) and start the webhooks worker (v1.3c)."
