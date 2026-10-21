#!/usr/bin/env bash
# Post-start deployment check: detects the known failures from docs/SSO-Setup.md "Troubleshooting" and
# "Production deployment watch-outs" and prints the documented fix for each. Read-only (never restarts anything).
#
#   scripts/deploy_check.sh            (run by scripts/deploy.sh after "up --wait"; also safe to run any time)
#
# Host part (docker CLI only): D01-D02 container state (init exited 0, services running + healthy, no restart loop),
# D03-D06 nginx networking / Docker DNS, D07-D08 log scan, D09 image consistency, D10 admin UI allow-list, D11 the
# published HTTPS port (needs curl; skipped without). In-container part (web: docker/deploy_check.py,
# sso/deploycheck.py): C01-C07 .env consistency, T01-T04 TLS / certificate, H01 /healthz (DB, migrations), J01 JWKS.
# Exit code 1 if any check FAILs, 0 otherwise (WARNs included).
#
# Runs in the compose project directory (repo root, or $SSO_DIR on an image-only VPS). Extra compose files via
# COMPOSE_FILE (e.g. COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml). DOCKER overrides the docker command.
set -uo pipefail
cd "$(dirname "$0")/.."
DOCKER="${DOCKER:-docker}"
dc() { $DOCKER compose "$@"; }

if [[ -t 1 ]]; then C_P=$'\e[32m' C_W=$'\e[33m' C_F=$'\e[31m' C_0=$'\e[0m'; else C_P="" C_W="" C_F="" C_0=""; fi
NPASS=0 NWARN=0 NFAIL=0 NSKIP=0
report() {  # STATUS ID TITLE [DETAIL] [FIX]
  local st="$1" id="$2" title="$3" detail="${4:-}" fix="${5:-}" col=""
  case "$st" in
    PASS) NPASS=$((NPASS + 1)); col="$C_P" ;;
    WARN) NWARN=$((NWARN + 1)); col="$C_W" ;;
    FAIL) NFAIL=$((NFAIL + 1)); col="$C_F" ;;
    *)    NSKIP=$((NSKIP + 1)) ;;
  esac
  printf '%s[%s]%s %-4s %s%s\n' "$col" "$st" "$C_0" "$id" "$title" "${detail:+  ($detail)}"
  if [[ -n "$fix" && "$st" != PASS ]]; then printf '              fix: %s\n' "$fix"; fi
}

# .env values (an exported shell variable wins, as in compose interpolation)
envval() {
  local name="$1" def="${2:-}" v=""
  if [[ -n "${!name+x}" ]]; then printf '%s' "${!name}"; return; fi
  [[ -f .env ]] && v="$(grep -E "^[[:space:]]*$name[[:space:]]*=" .env | tail -n1 | cut -d= -f2- \
                        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^[\"']//" -e "s/[\"']$//")"
  printf '%s' "${v:-$def}"
}
HOST="$(envval SSO_HOSTNAME)"
HTTPS_PORT="$(envval SSO_HTTPS_PORT 443)"
ADMIN_UI_ALLOW_DIR="$(envval SSO_ADMIN_UI_ALLOW_DIR ./docker/nginx-admin-ui.d)"

echo "SSO deployment check: $(pwd), SSO_HOSTNAME=${HOST:-<unset>}, HTTPS port $HTTPS_PORT"
echo

# ---------------------------------------------------------------- D01-D02 container state
cid() { dc ps -a -q "$1" 2>/dev/null | head -n1; }
INIT_ID="$(cid init)"
if [[ -z "$INIT_ID" ]]; then
  report WARN D01 "init service ran" "no init container" \
    "The compose file predates auto-init: extract the deploy kit of the current image (SSO-Setup §12.2)"
else
  rc="$($DOCKER inspect -f '{{.State.ExitCode}}' "$INIT_ID")"
  if [[ "$rc" == 0 ]]; then report PASS D01 "init service (keys + certificate)" "exit 0"
  else
    report FAIL D01 "init service (keys + certificate)" "exit $rc: $(dc logs --no-color --no-log-prefix init 2>/dev/null \
      | grep -E 'ERROR' | tail -n1)" "docker compose logs init; fix .env / the key or cert folder, then up again"
  fi
fi

for svc in web webhooks redis nginx; do
  id="$(cid "$svc")"
  if [[ -z "$id" ]]; then
    report FAIL D02 "$svc running" "no container" "docker compose up -d --no-build (SSO-Setup §12.7)"; continue
  fi
  read -r state health restarts < <($DOCKER inspect -f \
    '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.RestartCount}}' "$id")
  if [[ "$state" == running && ( "$health" == healthy || "$health" == none ) ]]; then
    report PASS D02 "$svc running" "$state/$health${restarts:+, restarts $restarts}"
    continue
  fi
  case "$svc" in
    nginx) fix="docker compose logs nginx: 'cannot load certificate' = SSO_TLS_CERT_FILE / SSO_TLS_KEY_FILE / SSO_CERTS_DIR (step 3)" ;;
    web)   fix="docker compose logs web: key errors = SSO_UID/SSO_GID vs key owner (step 4); 'database unreachable' = see D08" ;;
    webhooks) fix="no SSO tables yet? see H01 (upgrade_db.sh on the migration server); else docker compose logs webhooks" ;;
    *)     fix="docker compose logs $svc" ;;
  esac
  report FAIL D02 "$svc running" "$state/$health, restarts $restarts" "$fix"
done

# ---------------------------------------------------------------- D03-D06 nginx networking / Docker DNS
NGINX_ID="$(cid nginx)"
if [[ -n "$NGINX_ID" ]]; then
  mode="$($DOCKER inspect -f '{{.HostConfig.NetworkMode}}' "$NGINX_ID")"
  nets="$($DOCKER inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$NGINX_ID")"
  if [[ "$mode" == host ]]; then
    report FAIL D03 "nginx network mode" "host" \
      "Remove network_mode from the nginx service, keep networks: [edge] (watch-outs: 'while resolving')"
  else report PASS D03 "nginx network mode" "$mode"; fi
  if [[ " $nets" == *"_edge "* ]]; then report PASS D04 "nginx on the edge network" "$nets"
  else
    report FAIL D04 "nginx on the edge network" "networks: ${nets:-none}" \
      "The compose file is old or hand-edited: replace it with the deploy kit's docker-compose.yml (§12.2)"
  fi
  if [[ "$($DOCKER inspect -f '{{.State.Running}}' "$NGINX_ID")" == true ]]; then
    if dc exec -T nginx cat /etc/resolv.conf 2>/dev/null | grep -q '^nameserver 127\.0\.0\.11'; then
      report PASS D05 "nginx uses Docker's DNS" "127.0.0.11"
    else
      report FAIL D05 "nginx uses Docker's DNS" "no 'nameserver 127.0.0.11' in /etc/resolv.conf" \
        "Unusual daemon DNS setup (daemon.json, rootless): see watch-outs table, last row"
    fi
    if dc exec -T nginx nslookup web 127.0.0.11 >/dev/null 2>&1; then
      report PASS D06 "nginx resolves 'web'"
    else
      report FAIL D06 "nginx resolves 'web'" "nslookup web 127.0.0.11 failed" \
        "docker compose down && docker compose up -d --no-build (recreates the network); else systemctl restart docker"
    fi
  else
    report SKIP D05 "nginx uses Docker's DNS" "nginx not running"
    report SKIP D06 "nginx resolves 'web'" "nginx not running"
  fi
fi

# ---------------------------------------------------------------- D07-D08 log scan
if [[ -n "$NGINX_ID" ]]; then
  ngx_recent="$(dc logs --no-color --since 2m nginx 2>&1)"
  ngx_all="$(dc logs --no-color --tail 300 nginx 2>&1)"
  if grep -q 'while resolving' <<<"$ngx_recent"; then
    report FAIL D07 "nginx log" "'while resolving' errors in the last 2 minutes: every proxied request gets 502" \
      "SSO-Setup 'Production deployment watch-outs' (network mode / DNS, D03-D06)"
  elif grep -q 'cannot load certificate' <<<"$ngx_all"; then
    report FAIL D07 "nginx log" "cannot load certificate" \
      "Step 3: fix SSO_CERTS_DIR / SSO_TLS_CERT_FILE / SSO_TLS_KEY_FILE, docker compose up -d --force-recreate nginx"
  else report PASS D07 "nginx log" "no resolver / certificate errors"; fi
fi
db_err="$(dc logs --no-color --tail 300 web 2>/dev/null | grep 'database unreachable' | tail -n1)"
if [[ -z "$db_err" ]]; then report PASS D08 "web log: database" "no 'database unreachable'"
else
  case "$db_err" in
    *"(110"*)  fix="errno 110 = timeout, packets dropped (ufw DEFAULT_INPUT_POLICY=DROP): step 6 firewall rule" ;;
    *"(111"*)  fix="errno 111 = refused: MySQL not running or bound to 127.0.0.1 only: step 5.1 bind-address" ;;
    *"(1045"*|*"(1130"*) fix="access denied / host not allowed: account, password or host part (172.31.250.%): step 5.2" ;;
    *)         fix="docker compose logs web | grep sso.db" ;;
  esac
  # transient at start-up is normal (MySQL later than web); H01 below says whether it is still down
  report WARN D08 "web log: database" "$(cut -c1-160 <<<"$db_err")" "$fix (if H01 passes, it has recovered)"
fi

# ---------------------------------------------------------------- D09 images
WEB_ID="$(cid web)"
if [[ -n "$WEB_ID" && -n "$NGINX_ID" ]]; then
  wimg="$($DOCKER inspect -f '{{.Config.Image}}' "$WEB_ID")"; nimg="$($DOCKER inspect -f '{{.Config.Image}}' "$NGINX_ID")"
  stale=""
  for c in "$WEB_ID" "$NGINX_ID"; do
    ref="$($DOCKER inspect -f '{{.Config.Image}}' "$c")"
    [[ "$($DOCKER inspect -f '{{.Image}}' "$c")" == "$($DOCKER image inspect -f '{{.Id}}' "$ref" 2>/dev/null)" ]] \
      || stale+="$ref "
  done
  if [[ "${wimg##*:}" != "${nimg##*:}" ]]; then
    report FAIL D09 "images" "web $wimg vs nginx $nimg" "Use one IMAGE_TAG for sso-server and sso-nginx (§12.1)"
  elif [[ -n "$stale" ]]; then
    report WARN D09 "images" "container runs an older image than the local $stale" \
      "docker compose up -d --no-build (recreates with the pulled image); never re-push an existing tag"
  else report PASS D09 "images" "tag ${wimg##*:}"; fi
fi

# ---------------------------------------------------------------- D10 admin UI allow-list
local_host=0
[[ "$HOST" == localhost || "$HOST" =~ ^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]] && local_host=1
shopt -s nullglob; allow=("$ADMIN_UI_ALLOW_DIR"/*.conf); shopt -u nullglob
if (( ${#allow[@]} > 0 )); then report PASS D10 "admin UI IP allow-list" "${allow[*]}"
elif (( local_host )); then report PASS D10 "admin UI IP allow-list" "none (local address)"
else
  report WARN D10 "admin UI IP allow-list" "admin UI open to the internet" \
    "printf 'allow <your IP>;\\ndeny all;\\n' > $ADMIN_UI_ALLOW_DIR/allow.conf; up -d --force-recreate nginx (§12.9)"
fi

# ---------------------------------------------------------------- D11 published port
if ! command -v curl >/dev/null; then report SKIP D11 "published HTTPS port" "curl not installed"
elif [[ -z "$HOST" ]]; then report SKIP D11 "published HTTPS port" "SSO_HOSTNAME unset"
else
  if [[ "$HOST" =~ ^[0-9.]+$ ]]; then url="https://$HOST:$HTTPS_PORT/healthz"; res=()
  else url="https://$HOST:$HTTPS_PORT/healthz"; res=(--resolve "$HOST:$HTTPS_PORT:127.0.0.1"); fi
  code="$(curl -sS -k -m 10 "${res[@]}" -o /dev/null -w '%{http_code}' "$url" 2>&1)"; rc=$?
  if [[ $rc == 0 && "$code" == 200 ]]; then report PASS D11 "published HTTPS port" "$url via 127.0.0.1: 200"
  else
    report FAIL D11 "published HTTPS port" "$url: curl exit $rc, $code" \
      "7 = nothing listens (nginx Restarting? SSO_HTTPS_PORT), 35 = SNI (C03), 52 = Host header (H01)"
  fi
fi

# ---------------------------------------------------------------- in-container checks (web)
echo
if [[ -n "$WEB_ID" && "$($DOCKER inspect -f '{{.State.Running}}' "$WEB_ID")" == true ]]; then
  out="$(dc exec -T web sh -c 'if [ -f /app/docker/deploy_check.py ]; then python /app/docker/deploy_check.py; else echo MISSING; fi' 2>&1)"
  if [[ "$out" == *MISSING* ]]; then
    report SKIP C00 "in-container checks" "the web image predates docker/deploy_check.py" "pull a newer IMAGE_TAG"
  else
    while IFS=$'\t' read -r st id title detail fix; do
      case "$st" in PASS|WARN|FAIL|SKIP) report "$st" "$id" "$title" "$detail" "$fix" ;; *) [[ -n "$st" ]] && echo "  $st" ;; esac
    done <<<"$out"
  fi
else
  report FAIL C00 "in-container checks" "web is not running" "See D02"
fi

echo
echo "Not checked automatically: Let's Encrypt reachability from the internet (DNS A record, port 80 open; §12.8),"
echo "per-user admin access (scripts/sso_login_check.py, §9/§10)."
echo "Result: $NPASS passed, $NWARN warnings, $NFAIL failed, $NSKIP skipped."
(( NFAIL == 0 ))
