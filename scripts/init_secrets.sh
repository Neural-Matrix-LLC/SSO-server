#!/usr/bin/env bash
# One-shot "init" service of docker-compose.yml: makes sure the JWT signing keys and nginx's TLS certificate exist
# before web / webhooks / nginx start (they depend on it with condition: service_completed_successfully).
#
#   Keys  (SSO_KEYS_DIR mounted rw at /init/keys):
#     - folder without any *.pem  -> generate SSO_JWT_PRIVATE_KEY / its .public.pem with gen_keys.sh
#                                    (only when SSO_JWT_PUBLIC_KEYS is exactly that one public key: a rotation list
#                                    with an empty folder means keys were LOST, so it stops instead)
#     - otherwise                 -> every configured file must exist; never generates into a non-empty folder
#     - always                    -> owner SSO_UID:SSO_GID, dir 0700, private keys 0600, public keys 0644
#   Cert  (SSO_CERTS_DIR mounted rw at /init/certs):
#     - cert + key present        -> kept (WARN if a self-signed one does not cover SSO_HOSTNAME)
#     - both missing, plain names -> self-signed bootstrap for SSO_HOSTNAME (gen_selfsigned_cert.sh)
#     - both missing, names with '/' (Let's Encrypt live/<host>/...) or only one present -> stop
#
# SSO_AUTO_INIT=false: check only, never generate. Idempotent: a no-op once the files exist.
# Runs as root with CHOWN/DAC_OVERRIDE/FOWNER only and no network (compose); it never reads .env secrets.
# INIT_KEYS_DIR / INIT_CERTS_DIR / INIT_SCRIPTS_DIR override the paths (tests).
set -euo pipefail
umask 077

KEYS_DIR="${INIT_KEYS_DIR:-/init/keys}"
CERTS_DIR="${INIT_CERTS_DIR:-/init/certs}"
SCRIPTS_DIR="${INIT_SCRIPTS_DIR:-$(cd "$(dirname "$0")" && pwd)}"
SSO_UID="${SSO_UID:-10001}"
SSO_GID="${SSO_GID:-10001}"
HOSTNAME_="${SSO_HOSTNAME:-}"
PRIV_NAME="${SSO_JWT_PRIVATE_KEY:-}"
PUB_NAMES="${SSO_JWT_PUBLIC_KEYS:-}"
CERT_FILE="${SSO_TLS_CERT_FILE:-fullchain.pem}"
KEY_FILE="${SSO_TLS_KEY_FILE:-privkey.pem}"
SNI="$(echo "${SSO_TLS_REJECT_UNKNOWN_SNI:-on}" | tr '[:upper:]' '[:lower:]')"
AUTO="$(echo "${SSO_AUTO_INIT:-true}" | tr '[:upper:]' '[:lower:]')"

log()  { echo "init: $*"; }
warn() { echo "init: WARNING: $*" >&2; }
die()  { echo "init: ERROR: $*" >&2; exit 1; }
auto() { [[ "$AUTO" == "true" || "$AUTO" == "1" || "$AUTO" == "yes" ]]; }
is_ip() { [[ "$1" =~ ^[0-9.]+$ || "$1" == *:* ]]; }

# ---------------------------------------------------------------- keys
init_keys() {
  [[ -n "$PRIV_NAME" ]] || die "SSO_JWT_PRIVATE_KEY is empty in .env (a file name such as sso-$(date +%Y-%m).private.pem)"
  [[ -n "$PUB_NAMES" ]] || die "SSO_JWT_PUBLIC_KEYS is empty in .env"
  [[ -d "$KEYS_DIR" ]] || mkdir -p "$KEYS_DIR"

  shopt -s nullglob
  local pems=("$KEYS_DIR"/*.pem)
  shopt -u nullglob
  if (( ${#pems[@]} == 0 )); then
    auto || die "$KEYS_DIR is empty and SSO_AUTO_INIT=false: create the keys (scripts/gen_keys.sh, SSO-Setup §12.4)"
    [[ "$PRIV_NAME" =~ ^[A-Za-z0-9._-]+\.private\.pem$ ]] \
      || die "SSO_JWT_PRIVATE_KEY='$PRIV_NAME': auto-init needs a plain file name ending in .private.pem"
    local name="${PRIV_NAME%.private.pem}"
    local pubs
    pubs="$(echo "$PUB_NAMES" | tr -d ' ')"
    [[ "$pubs" == "$name.public.pem" ]] \
      || die "the key folder is empty, but SSO_JWT_PUBLIC_KEYS='$PUB_NAMES' expects other keys too. Were the keys" \
             "lost? Restore them from backup; for a NEW install set SSO_JWT_PUBLIC_KEYS=$name.public.pem"
    warn "no signing key in the key folder: generating a NEW key pair '$name'. If this server has issued tokens" \
         "before, all of them are now invalid and clients must refresh their JWKS."
    "$SCRIPTS_DIR/gen_keys.sh" "$KEYS_DIR" "$name" 2>/dev/null | sed 's/^/init: /'
  fi

  local missing=() f
  IFS=',' read -r -a want <<< "$PRIV_NAME,$PUB_NAMES"
  for f in "${want[@]}"; do
    f="$(echo "$f" | tr -d ' ')"
    [[ -z "$f" ]] && continue
    [[ "$f" == */* ]] && die "'$f' is a path; in Docker SSO_JWT_PRIVATE_KEY / SSO_JWT_PUBLIC_KEYS are file names in SSO_KEYS_DIR"
    [[ -f "$KEYS_DIR/$f" ]] || missing+=("$f")
  done
  (( ${#missing[@]} == 0 )) \
    || die "key folder is not empty but is missing: ${missing[*]} (check the names in .env; nothing generated)"

  # ownership / modes the web container (uid SSO_UID) needs: fixes "web keeps restarting, keys unreadable"
  if [[ "$(id -u)" == 0 ]]; then
    chown "$SSO_UID:$SSO_GID" "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"
    for f in "$KEYS_DIR"/*.pem; do
      chown "$SSO_UID:$SSO_GID" "$f"
      if [[ "$f" == *.private.pem ]] || grep -q "PRIVATE KEY" "$f"; then chmod 600 "$f"; else chmod 644 "$f"; fi
    done
  fi
  log "keys ok: $PRIV_NAME (+ $(echo "$PUB_NAMES" | tr -d ' ')) owned by $SSO_UID:$SSO_GID"
}

# ---------------------------------------------------------------- TLS certificate
init_cert() {
  local crt="$CERTS_DIR/$CERT_FILE" key="$CERTS_DIR/$KEY_FILE"
  [[ -d "$CERTS_DIR" ]] || mkdir -p "$CERTS_DIR"
  if [[ -f "$crt" && -f "$key" ]]; then
    if [[ -n "$HOSTNAME_" ]] \
       && [[ "$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')" \
             == "$(openssl x509 -in "$crt" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')" ]]; then
      local opt="-checkhost"; is_ip "$HOSTNAME_" && opt="-checkip"
      if ! openssl x509 -in "$crt" -noout "$opt" "$HOSTNAME_" | grep -q "does match"; then
        warn "the self-signed $CERT_FILE does not cover SSO_HOSTNAME=$HOSTNAME_ (clients get 'hostname mismatch')." \
             "Move $CERT_FILE / $KEY_FILE out of SSO_CERTS_DIR and run 'docker compose up' again to regenerate."
      fi
    fi
    log "certificate ok: $CERT_FILE"
    return
  fi
  [[ -f "$crt" || -f "$key" ]] && die "only one of $CERT_FILE / $KEY_FILE exists in SSO_CERTS_DIR; restore the pair or remove both"
  if [[ "$CERT_FILE" == */* || "$KEY_FILE" == */* ]]; then
    die "$CERT_FILE not found in SSO_CERTS_DIR. Let's Encrypt paths are not auto-generated: bootstrap with" \
        "SSO_CERTS_DIR=./docker/certs SSO_TLS_CERT_FILE=selfsigned.crt SSO_TLS_KEY_FILE=selfsigned.key, then SSO-Setup §12.8"
  fi
  auto || die "$CERT_FILE missing and SSO_AUTO_INIT=false: create it (scripts/gen_selfsigned_cert.sh, SSO-Setup §12.5)"
  [[ -n "$HOSTNAME_" ]] || die "SSO_HOSTNAME is empty: needed for the certificate"
  log "no TLS certificate: generating a self-signed bootstrap certificate for $HOSTNAME_"
  "$SCRIPTS_DIR/gen_selfsigned_cert.sh" "$HOSTNAME_" "$CERTS_DIR" "$CERT_FILE" "$KEY_FILE" | sed 's/^/init: /'
}

if [[ -n "$HOSTNAME_" ]] && is_ip "$HOSTNAME_" && [[ "$SNI" != "off" ]]; then
  warn "SSO_HOSTNAME=$HOSTNAME_ is an IP address but SSO_TLS_REJECT_UNKNOWN_SNI is not off: clients connecting by IP" \
       "send no SNI and every TLS handshake fails (SSO-Setup step 1, option B)"
fi
init_keys
init_cert
log "done"
