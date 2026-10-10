#!/usr/bin/env bash
# One-time local setup for docker-compose.dev.yml: dev signing keys, self-signed cert, .env.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -e keys/dev.private.pem ]] || scripts/gen_keys.sh keys dev 2048
# the container runs as uid 10001 and must read the private key (deployment plan §4.2)
if [[ "$(id -u)" == "0" ]]; then chown 10001:10001 keys/dev.*.pem; else
  echo "NOTE: run 'sudo chown 10001:10001 keys/dev.*.pem' so the web container (uid 10001) can read the key" >&2; fi
scripts/gen_selfsigned_cert.sh localhost docker/certs
if [[ ! -e .env ]]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
  sed "s|__generated_by_dev_setup__|$secret|" .env.dev.example > .env
  chmod 600 .env
  echo "wrote .env from .env.dev.example"
else
  echo ".env exists; not touched"
fi
