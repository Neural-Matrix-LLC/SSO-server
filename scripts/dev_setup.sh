#!/usr/bin/env bash
# One-time local setup for docker-compose.dev.yml: dev signing keys, self-signed cert, .env.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -e keys/dev.private.pem ]] || scripts/gen_keys.sh keys dev 2048
# the container runs as uid 10001 and must read the private key (deployment plan §4.2)
if [[ "$(id -u)" == "0" ]]; then chown 10001:10001 keys/dev.*.pem; else
  echo "NOTE: run 'sudo chown 10001:10001 keys/dev.*.pem' so the web container (uid 10001) can read the key" >&2; fi
scripts/gen_selfsigned_cert.sh localhost docker/certs
if [[ ! -e .env.test ]]; then
  pw() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }
  { echo "SSO_TEST_MYSQL_ROOT_PASSWORD=$(pw)"; echo "SSO_TEST_APP_PASSWORD=$(pw)"; echo "SSO_TEST_MIGRATOR_PASSWORD=$(pw)"; } > .env.test
  chmod 600 .env.test
  echo "wrote .env.test (random local MySQL passwords)"
fi
if [[ ! -e .env ]]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
  { sed "s|__generated_by_dev_setup__|$secret|" .env.dev.example; cat .env.test; } > .env
  chmod 600 .env
  echo "wrote .env from .env.dev.example"
else
  echo ".env exists; not touched"
fi
