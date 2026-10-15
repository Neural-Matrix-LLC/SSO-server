# SSO server setup on WSL2 (Docker Engine + MySQL in WSL)

A step-by-step setup for running the SSO server with the production compose file (`docker-compose.yml`:
`web` + `redis` + `nginx`) on a WSL2 machine where **Docker Engine and MySQL both run inside WSL** and
the server answers on `https://localhost` (port 443) with a self-signed certificate.

This guide follows the [README Docker quick start](../README.md#docker-quick-start-local--wsl) and adds
the WSL-specific steps (ufw, MySQL account host, `SSO_HOSTNAME`) that cause the most common start-up
failures. The README remains the reference for every variable; see its §3 table.

## 0. Prerequisites

- WSL2 (Ubuntu 22.04) with Docker Engine and the compose plugin (`docker compose version`).
- MySQL 8.0/8.4 running in WSL with the existing `dcWebUsers` database (`systemctl is-active mysql`).
- `sudo` rights, which steps 4 and 5 need for the MySQL accounts and the firewall.

## 1. Create `.env`

```bash
cp .env.example .env && chmod 600 .env
python3 -c 'import secrets; print(secrets.token_urlsafe(50))'   # paste as SSO_SECRET_KEY=
```

Set these values for a local run on port 443. Every host name must be `localhost`. Leftover
`example.com` placeholders break the TLS handshake, the refresh cookie or CORS (see
[Troubleshooting](#troubleshooting)).

```ini
SSO_ALLOWED_HOSTS=localhost,127.0.0.1
SSO_ISSUER=https://localhost
SSO_CSRF_TRUSTED_ORIGINS=https://localhost
SSO_CORS_ALLOWED_ORIGINS=https://localhost
SSO_COOKIE_DOMAIN=
SSO_HSTS_SECONDS=0
SSO_DOMAIN=localhost
SSO_HOSTNAME=localhost
SSO_HTTP_PORT=80
SSO_HTTPS_PORT=443
SSO_CERTS_DIR=./docker/certs
SSO_TLS_CERT_FILE=selfsigned.crt
SSO_TLS_KEY_FILE=selfsigned.key
SSO_DB_ENGINE=mysql
SSO_DBHOST=host.docker.internal
SSO_DBPORT=3306
SSO_DBNAME=dcWebUsers
SSO_DBUSER=sso_app
SSO_DBPWD=<sso_app password>
```

- `SSO_HOSTNAME` must match the name you put in the URL. nginx's default server
  (`ssl_reject_handshake on`) refuses every other name during the TLS handshake.
- `SSO_DBHOST=host.docker.internal` is resolved inside the container. `docker-compose.yml` maps it to the
  Docker host (`extra_hosts: host-gateway`). `localhost` would mean the container itself.
- If you use other ports (for example 8443), the port goes into `SSO_ISSUER`, every origin and the URLs
  below: `https://localhost:8443`.

## 2. TLS certificate for nginx

nginx exits at start-up if the files named by `SSO_TLS_CERT_FILE` / `SSO_TLS_KEY_FILE` are missing from
`SSO_CERTS_DIR`. Create a self-signed pair (dev only; it never overwrites an existing one):

```bash
scripts/gen_selfsigned_cert.sh localhost docker/certs
ls docker/certs          # selfsigned.crt  selfsigned.key
```

For a real certificate, put `fullchain.pem` / `privkey.pem` in `docker/certs/` instead, or point
`SSO_CERTS_DIR` at their folder (e.g. `/etc/letsencrypt/live/<host>`), and set the two file names in `.env`
accordingly.

## 3. JWT signing keys

```bash
scripts/gen_keys.sh ./keys sso-2026-10        # note the printed kid=
```

```ini
SSO_KEYS_DIR=./keys
SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem
SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem
SSO_UID=1000          # output of: id -u   (container runs as you, so it can read keys/)
SSO_GID=1000          # output of: id -g
```

Changing `SSO_UID`/`SSO_GID` needs an image rebuild (`--build` in step 7). The alternative is
`sudo chown -R 10001:10001 keys` with the default container user. See README quick start steps 2 to 4.

## 4. MySQL: listen address and accounts

The `web` container reaches MySQL from the compose `edge` network, `SSO_EDGE_SUBNET` (default
`172.31.250.0/24`). MySQL sees the container's own address (`172.31.250.x`) as the client host.

1. **Listen on more than loopback.** `ss -ltn | grep 3306` must show `*:3306` or `0.0.0.0:3306`, not
   only `127.0.0.1:3306`. Otherwise set `bind-address = 0.0.0.0` in
   `/etc/mysql/mysql.conf.d/mysqld.cnf` and run `sudo systemctl restart mysql`.

2. **Create the two accounts, limited to the edge subnet.** The grants are the ones from
   `docker/mysql-init/01-sso-accounts.sh`, with the host part narrowed from `%`:

   ```sql
   -- sudo mysql
   CREATE USER IF NOT EXISTS 'sso_app'@'172.31.250.%'
     IDENTIFIED WITH caching_sha2_password BY '<sso_app password>';
   GRANT SELECT, INSERT, UPDATE, DELETE ON `dcWebUsers`.* TO 'sso_app'@'172.31.250.%';

   CREATE USER IF NOT EXISTS 'sso_migrator'@'172.31.250.%'
     IDENTIFIED WITH caching_sha2_password BY '<sso_migrator password>';
   GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
     ON `dcWebUsers`.* TO 'sso_migrator'@'172.31.250.%';
   FLUSH PRIVILEGES;
   ```

   Check: `SELECT user, host FROM mysql.user WHERE user LIKE 'sso_%';`

## 5. Firewall: let the containers reach MySQL

When ufw is enabled with `DEFAULT_INPUT_POLICY="DROP"` (check with `grep -E '^ENABLED|^DEFAULT_INPUT'
/etc/ufw/ufw.conf /etc/default/ufw`), packets from the Docker bridges to the host's port 3306 are
silently dropped. Allow exactly the edge subnet:

```bash
sudo ufw allow from 172.31.250.0/24 to any port 3306 proto tcp comment 'SSO web -> MySQL'
sudo ufw status numbered
```

Use the subnet, not the bridge interface: the `br-<id>` name changes whenever compose recreates the
network, but `SSO_EDGE_SUBNET` is fixed. If you change `SSO_EDGE_SUBNET`, change this rule and the MySQL
account host parts too.

## 6. Back up, then migrate once as `sso_migrator`

`dcWebUsers` is shared with myFinance. Take the `mysqldump` backup from
[README §5](../README.md#5-database-first-deployment-and-migrate-procedure) step 1 first, then:

```bash
read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
docker compose build web
docker compose run --rm -e SSO_DBUSER=sso_migrator -e SSO_DBPWD web python manage.py migrate --plan
```

**Stop** unless the plan lists only `application.*`, `sso.*` and `token_blacklist.*`. Then:

```bash
docker compose run --rm -e SSO_DBUSER=sso_migrator -e SSO_DBPWD web python manage.py migrate
unset SSO_DBPWD
```

## 7. Start and verify

```bash
docker compose up -d --build
docker compose ps                                   # web, redis, nginx: Up (healthy), none "Restarting"
docker compose exec web python -c \
  "import socket; socket.create_connection(('host.docker.internal', 3306), 3); print('db ok')"
curl -sk https://localhost/healthz                  # {"status":"ok"}
curl -sk https://localhost/.well-known/jwks.json \
  | python3 -c 'import json,sys; print([k["kid"] for k in json.load(sys.stdin)["keys"]])'
```

The kid must equal the one `gen_keys.sh` printed in step 3.

## 8. Admin user and app access

```bash
docker compose run --rm web python manage.py createsuperuser
```

The admin is at `https://localhost/sso-admin/` (`SSO_ADMIN_PATH`). Superusers get **no** app access
automatically: grant `application.app1` explicitly (README quick start step 8).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `web` log: `ERROR sso.db startup: database unreachable at host.docker.internal:3306 ... (2002, "Can't connect ... (110)")`, `/healthz` 503 | Error 110 = timeout: the packets are dropped, usually by ufw (`DEFAULT_INPUT_POLICY="DROP"`) | Step 5 (ufw rule). `/healthz` recovers on the next probe; no restart needed |
| Same, but error **111** (connection refused) | MySQL not running or bound to `127.0.0.1` only | Step 4.1 (`bind-address`) |
| Error **1045** / **1130** (access denied / host not allowed) | Account missing, wrong password, or host part does not match `172.31.250.%` | Step 4.2 |
| `curl: (7) Failed to connect to localhost port 443 ... Connection refused`; `docker compose ps` shows nginx `Restarting` | nginx cannot start; `docker compose logs nginx` shows `cannot load certificate "/etc/nginx/certs/..."` | Step 2: create the certificate or fix `SSO_TLS_CERT_FILE` / `SSO_TLS_KEY_FILE` / `SSO_CERTS_DIR`, then `docker compose up -d --force-recreate nginx` |
| `curl: (35) ... tlsv1 unrecognized name` | The URL's host name is not `SSO_HOSTNAME` (e.g. still `sso.example.com`); nginx rejects unknown SNI | Set `SSO_HOSTNAME=localhost`, then `docker compose up -d --force-recreate nginx` |
| HTTP 400 Bad Request from Django | Host header not in `SSO_ALLOWED_HOSTS` | Add the host name to `SSO_ALLOWED_HOSTS`, restart `web` |
| Browser login works but refresh fails / no cookie stored | `SSO_COOKIE_DOMAIN` set to another domain (e.g. `.example.com`) | Leave `SSO_COOKIE_DOMAIN=` empty for localhost |
| Browser-mode login/refresh rejected on `Origin` | Page origin not in `SSO_CORS_ALLOWED_ORIGINS` | Add the exact origin (scheme, host, port) |
| `web` keeps restarting, log mentions keys | Container user cannot read `keys/` | Step 3 (`SSO_UID`/`SSO_GID` + rebuild, or chown to 10001) |

After any `.env` change, recreate the affected service (`docker compose up -d --force-recreate <service>`);
a plain `restart` does not re-read `.env`.
