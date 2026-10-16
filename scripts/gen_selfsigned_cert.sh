#!/usr/bin/env bash
# DEV ONLY: self-signed TLS cert for nginx (addendum C). Usage: scripts/gen_selfsigned_cert.sh [CN] [OUT_DIR]
set -euo pipefail
umask 077
CN="${1:-localhost}"
OUT="${2:-./docker/certs}"
mkdir -p "$OUT"
if [[ -e "$OUT/selfsigned.crt" ]]; then echo "$OUT/selfsigned.crt exists; leaving it" >&2; exit 0; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$CN" \
  -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1" \
  -keyout "$OUT/selfsigned.key" -out "$OUT/selfsigned.crt" 2>/dev/null
chmod 644 "$OUT/selfsigned.crt"   # nginx reads it as root; key stays 600
echo "wrote $OUT/selfsigned.crt and $OUT/selfsigned.key"
