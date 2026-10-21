#!/usr/bin/env bash
# Self-signed TLS cert for nginx (addendum C): local/QA, a server reached by IP whose clients pin this cert, and
# the bootstrap cert nginx needs before the first Let's Encrypt run.
#   Usage: scripts/gen_selfsigned_cert.sh [CN] [OUT_DIR] [CERT_NAME] [KEY_NAME]
#   (defaults: localhost, ./docker/certs, selfsigned.crt, selfsigned.key)
# The compose "init" service runs it automatically when SSO_CERTS_DIR has no certificate (scripts/init_secrets.sh).
# Also in the sso-server image (no repo checkout needed; OUT_DIR writable by uid 10001):
#   docker run --rm -v /opt/sso/docker/certs:/out <image> /app/scripts/gen_selfsigned_cert.sh <CN> /out
set -euo pipefail
umask 077
CN="${1:-localhost}"
OUT="${2:-./docker/certs}"
CRT="${3:-selfsigned.crt}"
KEY="${4:-selfsigned.key}"
mkdir -p "$OUT"
if [[ -e "$OUT/$CRT" ]]; then echo "$OUT/$CRT exists; leaving it" >&2; exit 0; fi
# an IP address needs an IP SAN (clients do not match IPs against DNS: entries)
if [[ "$CN" =~ ^[0-9.]+$ || "$CN" == *:* ]]; then SAN="IP:$CN"; else SAN="DNS:$CN"; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$CN" \
  -addext "subjectAltName=$SAN,DNS:localhost,IP:127.0.0.1" \
  -keyout "$OUT/$KEY" -out "$OUT/$CRT" 2>/dev/null
chmod 644 "$OUT/$CRT"   # nginx reads it as root; key stays 600
echo "wrote $OUT/$CRT and $OUT/$KEY"
