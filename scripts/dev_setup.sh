#!/usr/bin/env bash
# One-time local setup for docker-compose.dev.yml: dev signing keys, self-signed cert, .env.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -e keys/dev.private.pem ]] || scripts/gen_keys.sh keys dev 2048
# The web container runs as SSO_UID:SSO_GID (non-root) and must read the private key (deployment plan §4.2).
# As a normal user, the container user becomes your own uid/gid (written to .env below), so no chown is needed.
# As root, the default 10001 is kept and the keys are chowned to it.
if [[ "$(id -u)" == "0" ]]; then
  KEY_UID=10001; KEY_GID=10001; chown "$KEY_UID:$KEY_GID" keys/dev.*.pem
else
  KEY_UID="$(id -u)"; KEY_GID="$(id -g)"
fi
scripts/gen_selfsigned_cert.sh localhost docker/certs
if [[ ! -e .env.test ]]; then
  pw() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }
  { echo "SSO_TEST_MYSQL_ROOT_PASSWORD=$(pw)"; echo "SSO_TEST_APP_PASSWORD=$(pw)"; echo "SSO_TEST_MIGRATOR_PASSWORD=$(pw)"; } > .env.test
  chmod 600 .env.test
  echo "wrote .env.test (random local MySQL passwords)"
fi
if [[ ! -e .env ]]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
  { sed "s|__generated_by_dev_setup__|$secret|" .env.dev.example; echo "SSO_UID=$KEY_UID"; echo "SSO_GID=$KEY_GID"; cat .env.test; } > .env
  chmod 600 .env
  echo "wrote .env from .env.dev.example"
else
  echo ".env exists; not touched"
fi
