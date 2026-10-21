#!/usr/bin/env bash
# Generate an RSA key pair for signing SSO JWTs (spec §5.3, deployment plan §4.2 / R26).
#
#   scripts/gen_keys.sh [OUT_DIR] [NAME] [BITS]
#     OUT_DIR  default ./keys
#     NAME     default sso-YYYY-MM   (files: NAME.private.pem, NAME.public.pem)
#     BITS     default 3072          (2048 minimum)
#
# Prints the kid = first 16 hex chars of SHA-256 over the DER SubjectPublicKeyInfo,
# exactly as the server computes it (sso/keys.py:compute_kid). Refuses to overwrite.
# Also in the sso-server image (no repo checkout needed; the files come out owned by the image user 10001):
#   sudo install -d -m 700 -o 10001 -g 10001 /opt/sso/keys
#   docker run --rm -v /opt/sso/keys:/out -e HOST_KEYS_DIR=/opt/sso/keys <image> /app/scripts/gen_keys.sh /out [NAME]
# (HOST_KEYS_DIR only changes the SSO_KEYS_DIR line printed for .env; default OUT_DIR.)
set -euo pipefail
umask 077

OUT_DIR="${1:-./keys}"
NAME="${2:-sso-$(date +%Y-%m)}"
BITS="${3:-3072}"

if ! [[ "$BITS" =~ ^[0-9]+$ ]] || (( BITS < 2048 )); then
  echo "error: BITS must be an integer >= 2048 (got '$BITS')" >&2; exit 2
fi
if ! [[ "$NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "error: NAME may only contain letters, digits, '.', '_' and '-'" >&2; exit 2
fi

PRIV="$OUT_DIR/$NAME.private.pem"
PUB="$OUT_DIR/$NAME.public.pem"
mkdir -p "$OUT_DIR"
for f in "$PRIV" "$PUB"; do
  if [[ -e "$f" ]]; then echo "error: $f already exists; refusing to overwrite" >&2; exit 1; fi
done
if [[ ! -w "$OUT_DIR" ]]; then
  echo "error: $OUT_DIR is not writable by uid $(id -u) (gid $(id -g))." >&2
  echo "  In Docker: is the host dir in -v correct (empty variable?) and owned by that uid, e.g." >&2
  echo "  install -d -m 700 -o $(id -u) -g $(id -g) <host-keys-dir>" >&2
  exit 1
fi

openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$BITS" -out "$PRIV" 2>/dev/null \
  || { echo "error: openssl genpkey failed writing $PRIV" >&2; exit 1; }
openssl pkey -in "$PRIV" -pubout -out "$PUB"
chmod 600 "$PRIV"
chmod 644 "$PUB"

KID="$(openssl pkey -pubin -in "$PUB" -outform DER | sha256sum | cut -c1-16)"
echo "private=$PRIV"
echo "public=$PUB"
echo "kid=$KID"
SHOWN_DIR="${HOST_KEYS_DIR:-$OUT_DIR}"
cat >&2 <<EOF
.env lines (file names; resolved in /run/keys in the container, SSO_KEYS_DIR=$SHOWN_DIR on the host):
SSO_KEYS_DIR=$SHOWN_DIR
SSO_JWT_PRIVATE_KEY=$NAME.private.pem
SSO_JWT_PUBLIC_KEYS=$NAME.public.pem
Rotation: APPEND the new public key and keep the old one, e.g. SSO_JWT_PUBLIC_KEYS=<old>.public.pem,$NAME.public.pem
(switch SSO_JWT_PRIVATE_KEY to $NAME.private.pem only after >= 24 h; README §4).
EOF
echo "On the server: chown them to the container user (SSO_UID:SSO_GID, default 10001:10001). Never commit them." >&2
