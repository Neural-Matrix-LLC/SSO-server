# SSO server setup (Docker Engine + MySQL on the same Linux / WSL2 host)

A step-by-step setup for running the SSO server with the production compose file (`docker-compose.yml`:
`web` + `webhooks` + `redis` + `nginx`) on a machine where **Docker Engine and MySQL both run on the same host**
(native Linux or inside WSL2), with a self-signed certificate on port 443.

This is the full setup manual behind the [README quick start](../README.md#docker-quick-start-local--wsl),
including the host-specific steps (address choice, MySQL account host, ufw) that cause the most common start-up
failures. Every variable is annotated in `.env.example` and listed in
[ARCHITECTURE.md §10](ARCHITECTURE.md#10-configuration-reference).

For a **production VPS that runs only the published images** (no repo checkout; keys and certificate generated on
the VPS from the image, Let's Encrypt via a certbot container), follow
[§12](#12-deploy-to-a-vps-from-the-docker-images-only) instead.

## 0. Prerequisites

- Ubuntu 22.04+ (native or WSL2) with Docker Engine and the compose plugin (`docker compose version`).
- MySQL 8.0/8.4 on the same host with the existing `dcWebUsers` database (`systemctl is-active mysql`).
- `sudo` rights, which steps 5 and 6 need for the MySQL accounts and the firewall.

### 0.1 Network ports

| Port | Direction | Who | Required | Notes |
|---|---|---|---|---|
| `SSO_HTTPS_PORT` (default 443) | inbound, published on the host | every client → `nginx` | **yes** | The only port clients use. If it is not 443, it is part of `SSO_ISSUER`, every origin and every URL (`https://<host>:<port>`) |
| `SSO_HTTP_PORT` (default 80) | inbound, published on the host | browsers, Let's Encrypt → `nginx` | yes (compose always publishes it) | Redirects to HTTPS and serves the ACME challenge. Must be **80 as seen from the internet** for Let's Encrypt HTTP-01 (§12.8); with a self-signed or IP-only setup any free port works |
| 22 | inbound | admins | yes | SSH; ufw only needs this (Docker-published ports bypass ufw, step 6) |
| 8000 | internal only (`edge` network) | `nginx` → `web` (gunicorn) | – | Never published. Shared-nginx variant only: `127.0.0.1:${SSO_WEB_LOCAL_PORT:-8001}` |
| 6379 | internal only (`backend`, no external route) | `web`, `webhooks` → `redis` | – | Never published |
| `SSO_DBPORT` (3306; DigitalOcean 25060) | outbound | `web`, `webhooks`; the migration server (`upgrade_db.sh`) | **yes** | To MySQL `dcWebUsers`; the DB firewall / trusted sources must allow these hosts |
| 443 | outbound | Docker (image pulls from `ghcr.io` / Docker Hub), `certbot` (Let's Encrypt), `webhooks` (services' `notify_url`) | yes | Webhook targets may use other ports if their `notify_url` says so |
| 53 | outbound | all containers (via Docker's DNS) | yes | Name resolution of the DB host, registries, webhook targets |

Both published ports must be **free on the host**: `sudo ss -ltnp '( sport = :80 or sport = :443 )'` must show
nothing. If another proxy already holds them (e.g. a hosting panel's Traefik), `docker compose up` fails with
`failed to bind host port 0.0.0.0:80/tcp: address already in use`; pick other ports
(Troubleshooting). Open both published ports in the cloud provider's firewall.

**Remote or managed MySQL** (e.g. DigitalOcean managed database): set `SSO_DBHOST` / `SSO_DBPORT` to the
provider's host and port (DigitalOcean: `25060`) and skip step 5.1, the `host.docker.internal` notes and step 6.
Create the accounts in step 5.2 with the provider's tools or with host part `'%'`, and allow this machine's public
IP in the provider's trusted sources. Set `SSO_DB_SSL_CA` / `SSO_DB_SSL_MODE=VERIFY_CA` to the provider's CA
certificate (mounted from `SSO_MYSQL_CA_DIR` at `/run/mysql-ca`) so the database certificate is verified.

## 1. Choose the address clients use

Every client (browser, app, `curl`) must call the server by exactly one address, and that address ends up in the
tokens (`iss`). Pick one before you write `.env` or the certificate:

| | A: this machine only | B: other machines on the LAN, by IP |
|---|---|---|
| URL | `https://localhost` | `https://192.168.0.212` (your host's LAN IP) |
| `SSO_HOSTNAME` | `localhost` | `192.168.0.212` |
| `SSO_TLS_REJECT_UNKNOWN_SNI` | `on` (default, leave unset) | **`off`** |
| Certificate (step 3) | `gen_selfsigned_cert.sh localhost` | `gen_selfsigned_cert.sh 192.168.0.212` |

- Option B: clients send no SNI (the TLS server name) when they connect to an IP, so with the default `on`
  nginx's catch-all `:443` server rejects every handshake (`TLSV1_UNRECOGNIZED_NAME`). With `off` the handshake
  completes and nginx still routes by `Host`: the SSO host goes to the SSO, any other host gets no answer (444).
- The issuer is part of every token and every client's configuration. If the IP changes later, all issued tokens
  fail the `iss` check and every client must be reconfigured. Use a fixed (reserved) IP, or a DNS name for anything
  beyond a LAN or test setup (then follow option A with that name, and a real certificate).
- WSL2 with the default NAT networking is not reachable from the LAN by the Windows host's IP; option B on WSL2
  needs mirrored networking (`networkingMode=mirrored` in `.wslconfig`) or a Windows port proxy.

The examples below use option A (`localhost`). For option B replace `localhost` with your IP everywhere (URLs,
`SSO_ISSUER`, origins, `SSO_ALLOWED_HOSTS`, `SSO_HOSTNAME`). If you use another HTTPS port (for example 8443),
the port goes into `SSO_ISSUER`, every origin and every URL: `https://localhost:8443`.

## 2. Create `.env`

```bash
cp .env.example .env && chmod 600 .env
python3 -c 'import secrets; print(secrets.token_urlsafe(50))'   # paste as SSO_SECRET_KEY=
python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'   # paste as SSO_WEBHOOK_SECRET_KEY=
```

Set these values. Leftover `sso.dev.com` / `example.com` placeholders break the TLS handshake, the refresh cookie
or CORS (see [Troubleshooting](#troubleshooting)).

```ini
SSO_ALLOWED_HOSTS=localhost,127.0.0.1
SSO_ISSUER=https://localhost
SSO_CSRF_TRUSTED_ORIGINS=https://localhost
SSO_CORS_ALLOWED_ORIGINS=https://localhost
SSO_COOKIE_DOMAIN=
SSO_HSTS_SECONDS=0
SSO_HOSTNAME=localhost
# SSO_TLS_REJECT_UNKNOWN_SNI=off     # option B (IP address) only
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

- `SSO_COOKIE_DOMAIN` stays **empty** (host-only cookie) for both options; a domain cookie cannot be set for
  `localhost` or an IP.
- `SSO_DBHOST=host.docker.internal` is resolved inside the container. `docker-compose.yml` maps it to the Docker
  host (`extra_hosts: host-gateway`). `localhost` would mean the container itself.
- `SSO_WEBHOOK_SECRET_KEY` encrypts webhook secrets at rest. Left empty it is derived from `SSO_SECRET_KEY`, and
  rotating `SSO_SECRET_KEY` then makes stored webhook secrets unreadable.
- Browsers ignore HSTS for `localhost` and IP addresses; `SSO_HSTS_SECONDS=0` keeps a dev certificate from being
  pinned by a browser on a real name later.

## 3. TLS certificate for nginx

nginx exits at start-up if the files named by `SSO_TLS_CERT_FILE` / `SSO_TLS_KEY_FILE` are missing from
`SSO_CERTS_DIR`. **Automatic:** when both files are missing, the compose `init` service creates a self-signed pair
for `SSO_HOSTNAME` under those names on the next `docker compose up` (`scripts/init_secrets.sh`; not for Let's
Encrypt `live/...` names). To create it by hand instead, for the address from step 1 (dev only):

```bash
scripts/gen_selfsigned_cert.sh localhost docker/certs        # option B: scripts/gen_selfsigned_cert.sh 192.168.0.212 docker/certs
openssl x509 -in docker/certs/selfsigned.crt -noout -ext subjectAltName
```

The certificate lists the address as `DNS:localhost` or, for an IP, `IP Address:192.168.0.212`; clients check an
IP only against IP entries. The script never overwrites an existing pair: to change the address, move
`selfsigned.crt` / `selfsigned.key` away first, then `docker compose up -d --force-recreate init nginx` (init
regenerates it for the current `SSO_HOSTNAME`).

Every client must trust this certificate (import `docker/certs/selfsigned.crt`, or pass it as the CA file,
e.g. `curl --cacert docker/certs/selfsigned.crt`). For a real certificate on a DNS name, put `fullchain.pem` /
`privkey.pem` in `docker/certs/` instead, or point `SSO_CERTS_DIR` at their folder (e.g.
`/etc/letsencrypt/live/<host>`), and set the two file names in `.env`.

## 4. JWT signing keys

**Automatic:** when `SSO_KEYS_DIR` contains no `*.pem`, the compose `init` service generates the pair named by
`SSO_JWT_PRIVATE_KEY` / `SSO_JWT_PUBLIC_KEYS` on the next `docker compose up` and gives it to `SSO_UID:SSO_GID`
(private `0600`). It refuses when `SSO_JWT_PUBLIC_KEYS` lists more than that one key (a rotation list with an empty
folder means lost keys), and never writes into a folder that already has keys. `SSO_AUTO_INIT=false` turns
generation off. By hand:

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

`SSO_KEYS_DIR` is mounted read-only at `/run/keys` in `web`; the two key variables are **file names** in it
(a value containing `/` is a path). `SSO_JWT_PUBLIC_KEYS` is a comma list: for a rotation append the new public key
([README §4](../README.md#4-key-generation-and-rotation)). The old `SSO_JWT_PRIVATE_KEY_PATH` /
`SSO_JWT_PUBLIC_KEY_PATHS` full-path forms still work with warning `sso.W001`; setting an old and a new form
together stops the server.

`SSO_UID`/`SSO_GID` are build arguments: the image is (re)built in step 7 and with `--build` in step 8. The
alternative is `sudo chown -R 10001:10001 keys` with the default container user (the only option with a pre-built
image). The private key stays `0600` (or `0640` with the `SSO_GID` group), never world-readable; public keys may be
`0644`. Check with `ls -n keys/` and `ls -nd keys/` (numeric owner = `SSO_UID`, directory enterable). A wrong owner
stops `web` with `JWT private key (...) exists but is not readable by uid 10001; chown to SSO_UID:SSO_GID or set
SSO_UID` (or `cannot be reached by uid 10001` for the directory).

## 5. MySQL: listen address and accounts

The `web` and `webhooks` containers reach MySQL from the compose `edge` network, `SSO_EDGE_SUBNET` (default
`172.31.250.0/24`). MySQL sees the container's own address (`172.31.250.x`) as the client host.

1. **Listen on more than loopback.** `ss -ltn | grep 3306` must show `*:3306` or `0.0.0.0:3306`, not only
   `127.0.0.1:3306`. Otherwise set `bind-address = 0.0.0.0` in `/etc/mysql/mysql.conf.d/mysqld.cnf` and run
   `sudo systemctl restart mysql`. (Step 6 keeps port 3306 closed to everything but the edge subnet.)

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

## 6. Firewall: let the containers reach MySQL

When ufw is enabled with `DEFAULT_INPUT_POLICY="DROP"` (check with `grep -E '^ENABLED|^DEFAULT_INPUT'
/etc/ufw/ufw.conf /etc/default/ufw`), packets from the Docker bridges to the host's port 3306 are silently
dropped. Allow exactly the edge subnet:

```bash
sudo ufw allow from 172.31.250.0/24 to any port 3306 proto tcp comment 'SSO web -> MySQL'
sudo ufw status numbered
```

Use the subnet, not the bridge interface: the `br-<id>` name changes whenever compose recreates the network, but
`SSO_EDGE_SUBNET` is fixed. If you change `SSO_EDGE_SUBNET`, change this rule and the MySQL account host parts
too.

Ports 80/443 need no ufw rule: Docker publishes them through its own iptables chains, which bypass ufw. With
option B the server is therefore reachable from the whole LAN; limit the admin paths with the nginx allow-lists
(step 10).

## 7. Back up, then create the SSO schema as `sso_migrator`

`dcWebUsers` is shared with myFinance. **Back up the whole database first** (spec §4.6), with the credentials in
an options file so they stay out of `ps`:

```bash
TS=$(date +%Y%m%dT%H%M%S)
mysqldump --defaults-extra-file=~/.my-dcweb.cnf --single-transaction --quick --routines --triggers \
  --events --hex-blob --no-tablespaces --set-gtid-purged=OFF --default-character-set=utf8mb4 \
  dcWebUsers | gzip -9 > dcWebUsers-pre-sso-$TS.sql.gz
gzip -t dcWebUsers-pre-sso-$TS.sql.gz && zcat dcWebUsers-pre-sso-$TS.sql.gz | tail -n 1   # "-- Dump completed"
mysql --defaults-extra-file=~/.my-dcweb.cnf -e 'SELECT COUNT(*) FROM dcWebUsers.auth_user'  # baseline
```

Store the dump encrypted and off the host: it contains every password hash. Then use
`scripts/upgrade_db.sh`, the single path for every SSO database change; on a first install it creates the SSO
tables (`sso.0001` onwards, `application.*`, `token_blacklist.*`):

```bash
read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
scripts/upgrade_db.sh --plan       # builds the web image, checks the DB path (steps 5 and 6), shows the plan
scripts/upgrade_db.sh              # backup of the SSO tables, migrate (asks first), schema check
unset SSO_DBPWD
```

The script **stops** if the plan touches any app other than `sso`, `application` and `token_blacklist`; never
work around that on the shared database (an existing `dcWebUsers` already has `contenttypes`, `auth`, `admin` and
`sessions`). The post-migrate step only adds rows to `django_content_type` / `auth_permission` (including
`application.app1` and `application.sso_admin`). Afterwards `SELECT COUNT(*) FROM auth_user` must be unchanged; log
in with an existing account through the API **and** through myFinance. Details in
[§11](#11-upgrading-the-database-later).

## 8. Start and verify

```bash
scripts/deploy.sh                                   # up --build --wait, then scripts/deploy_check.sh
```

`deploy.sh` starts the stack (the `init` service first: keys and certificate from steps 3 and 4 if missing), stops
before starting anything if the schema from step 7 is missing (schema gate, exit code 3), waits until every
service is healthy, then runs `scripts/deploy_check.sh`. The check tests the rows of
[Troubleshooting](#troubleshooting) and the [watch-outs](#production-deployment-watch-outs) it can detect
(container state, nginx DNS, `.env` consistency, TLS/SNI and certificate name, Host header, database, pending
migrations, JWKS kid) and prints the fix for each failure. Exit code 1 on any FAIL. It is read-only, so run
`scripts/deploy_check.sh` again at any time. The manual equivalent:

```bash
docker compose up -d --build
docker compose ps                                   # web, webhooks, redis, nginx: Up (healthy), none "Restarting"
docker compose exec web python -c "import os,socket; \
  socket.create_connection((os.environ['SSO_DBHOST'], int(os.environ['SSO_DBPORT'])), 3); print('db ok')"
curl -s --cacert docker/certs/selfsigned.crt https://localhost/healthz          # {"status":"ok"}
curl -s --cacert docker/certs/selfsigned.crt https://localhost/.well-known/jwks.json \
  | python3 -c 'import json,sys; print([k["kid"] for k in json.load(sys.stdin)["keys"]])'
```

- The kid must equal the one `gen_keys.sh` printed in step 4.
- `{"status": "ok", "warning": "database migrations pending"}` means step 7 was skipped or failed.
- `--cacert` also checks that the certificate matches the address; if it fails while `-k` works, the certificate
  is for another name or IP (step 3).

## 9. Admin user, app access and a login check

```bash
docker compose run --rm web python manage.py createsuperuser
```

Django admin is at `https://localhost/sso-admin/` (`SSO_ADMIN_PATH`). Superusers get **no** app access
automatically (`SSO_SUPERUSER_ALL_APPS=false`): grant `application.app1` explicitly (*Users* → the user → *User
permissions* (or a group → *Permissions*) → "Applications | application access | Can use app1 (llm-wiki-svc)" →
Save). `perms` in the next token (or after a refresh) then contains it. An existing `dcWebUsers` user can be made
staff/superuser there instead of creating a new one. More applications:
`docker compose run --rm web python manage.py create_app_permission app2 "Can use app2 (reporting)"`.

Then check a real login end to end (logs in, prints groups and `perms`, logs out; tokens are never printed):

```bash
scripts/sso_login_check.py <username>       # URL from SSO_ISSUER in .env; pins docker/certs/<SSO_TLS_CERT_FILE>
```

`perms` must contain `application.app1` after the grant. Exit code 1 means the login was refused (wrong password,
inactive account, throttled); see `--help` for `--url` / `--cacert`.

### 9.1 Manual check with curl (from another machine)

The same checks by hand, e.g. from a laptop against a test server reached by IP address (here
`SSO_HOSTNAME=192.168.0.213`, `SSO_TLS_REJECT_UNKNOWN_SNI=off`, step 1). `-k` skips certificate verification for the
self-signed bootstrap certificate; use `--cacert docker/certs/selfsigned.crt` instead to also check the name (step 3).
Always `https://`: plain `http://` only redirects.

```bash
SSO=https://192.168.0.213

# health
curl -sk $SSO/healthz                               # {"status":"ok"}

# login (native client: refresh token in the body)
curl -sk $SSO/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"YOUR_USER","password":"YOUR_PASSWORD","client":"native"}'

# login, keep the access token, then ask who it belongs to (needs jq)
TOKEN=$(curl -sk $SSO/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"YOUR_USER","password":"YOUR_PASSWORD","client":"native"}' | jq -r .access_token)
curl -sk $SSO/api/v1/auth/me -H "Authorization: Bearer $TOKEN"

# published keys and discovery
curl -sk $SSO/.well-known/jwks.json
curl -sk $SSO/.well-known/openid-configuration
```

- Login 200 returns `access_token`, `refresh_token`, `expires_in` (900) and `user` (with `groups` and `perms`).
- 401 = wrong user or password; 403 `account_inactive` = correct password, inactive account; 429 = throttled
  (`SSO_THROTTLE_LOGIN` 10/min per IP, `SSO_THROTTLE_LOGIN_USER` 5/min per user, see `Retry-After`).
- TLS handshake error by IP = `SSO_TLS_REJECT_UNKNOWN_SNI` still `on`; Django 400 "Bad Request" = the address is
  not in `SSO_ALLOWED_HOSTS`. See [Troubleshooting](#troubleshooting).
- Commands typed into a shell end up in its history; prefer `scripts/sso_login_check.py` (prompts for the
  password) for real accounts.

## 10. Admin web UI

The admin UI (v1.3d, [DESIGN-v1.3d-admin-ui.md](DESIGN-v1.3d-admin-ui.md)) is enabled by default at
`https://localhost/admin/` (`SSO_ADMIN_UI_PATH`). Its schema change (`sso.0007`) is already applied by step 7.
Django admin (step 9) stays available as break-glass.

1. Your admin account must be **active**, have **staff status** and hold `application.sso_admin` (directly or via a
   group). A staff superuser also works.
2. Optional, recommended for option B: limit who can reach it.
   ```bash
   mkdir -p docker/nginx-admin-ui.d
   printf 'allow 127.0.0.1;\nallow 192.168.0.0/24;\ndeny all;\n' > docker/nginx-admin-ui.d/allow.conf
   docker compose up -d --force-recreate nginx
   ```
   (`SSO_ADMIN_UI_ALLOW_DIR` points elsewhere if you keep it outside the repo; `docker/nginx-admin.d` /
   `SSO_ADMIN_ALLOW_DIR` does the same for Django admin.)
3. `SSO_CSRF_TRUSTED_ORIGINS` must contain the exact origin you open it with (`https://localhost`, or
   `https://192.168.0.212` for option B).
4. Open `https://localhost/admin/` and sign in. Suspend, delete, set password, rotate secrets and granting
   `sso_admin` ask for your password again (valid 5 min, `SSO_ADMIN_REAUTH_SECONDS`). Sessions end after 30 min
   idle or 8 h (`SSO_ADMIN_UI_IDLE_SECONDS`, `SSO_ADMIN_UI_MAX_AGE_SECONDS`) and are bound to your IP.

How to use the UI (and the same tasks from the command line): [SSO-Admin-User-Manual.md](SSO-Admin-User-Manual.md).

MFA for admins is not implemented.

## 11. Upgrading the database later

Use this when the database is already in use by an older SSO version (for example v1.2b or v1.3c) and you deploy
a newer one. It is the same `scripts/upgrade_db.sh` as step 7 and safe to re-run: when nothing is pending it only
checks.

```bash
git pull                                            # the new code; .env stays as it is
read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
scripts/upgrade_db.sh --plan                        # dry run: DB reachable? what would be applied?
scripts/upgrade_db.sh                               # build image, backup, migrate, verify (asks before migrating)
unset SSO_DBPWD
docker compose up -d --build                        # recreate web and webhooks on the new image
```

What it does, in order (exit code is non-zero and nothing more happens if a step fails):

1. **Pre-check**: `docker compose build web`, then `docker/dbcheck.py --strict` in a `web` container (same path
   to MySQL as the server: step 5 and 6 problems show up here, with the same error numbers as in Troubleshooting).
2. **State**: `showmigrations` for `sso`, `application`, `token_blacklist` and `migrate --plan`. It **stops** if
   the plan contains any other app (dcWebUsers is shared with myFinance).
3. **Backup** (default on, `--no-backup` to skip): `mysqldump` of all `sso_*` and `token_blacklist_*` tables and the
   SSO rows of `django_migrations`, to `backups/sso-tables-dcWebUsers-<timestamp>.sql.gz` (folder mode 700). The dump
   runs in a `mysql:8.4` client container on the compose `edge` network, so the `sso_migrator@'172.31.250.%'`
   account from step 5 works. The password goes into a temporary mode-600 options file that is deleted on exit;
   it is never on a command line. The dump contains service secret hashes: keep it private. This is **not** a
   backup of myFinance's tables; take the full dump from [step 7](#7-back-up-then-create-the-sso-schema-as-sso_migrator) too if you want one.
4. **Migrate** as `sso_migrator` (`migrate --noinput`).
5. **Post-check**: `manage.py sso_schema_check` (every SSO migration applied, every v1.1 to v1.3d table and
   column present) and row counts of `auth_user`, groups and the SSO tables unchanged.
6. **Summary**.

Options: `--plan`, `--no-backup`, `--backup-dir DIR`, `--no-build`, `-y` (no question), `--venv [DIR]` (bare venv
on the host instead of compose; then `SSO_DBHOST=host.docker.internal` is read as `127.0.0.1` and the MySQL account
must allow `localhost`), `--dump-with auto|host|docker`, `--mysql-image`. `scripts/upgrade_db.sh --help` lists them.

New tables and columns per version (raw SQL for a DBA, with rollback notes:
[db/upgrade-v1.2-to-v1.3.sql](db/upgrade-v1.2-to-v1.3.sql), [db/upgrade-v1.3-to-v1.3d.sql](db/upgrade-v1.3-to-v1.3d.sql)):

| Version | Migration | New in the database |
|---|---|---|
| v1.2a | `sso.0002_v12a_service_registry_sessions` | `sso_serviceclient.app_codename`, `.notify_url`; table `sso_revokedsession` |
| v1.3a | `sso.0003_v13a` | `sso_serviceclient.secret_rotated_at`; tables `sso_serviceclient_permissions`, `sso_adminauditlog`, `sso_adminreauth` |
| v1.3a | `application.0002_v13a` | table `sso_application`; `sso_application_permission_record.app_codename`, `.deprecated_at`, `.description` |
| v1.3a | `sso.0004_v13a_tombstone` | table `sso_usertombstone` |
| v1.3b | `sso.0005_v13b` | `sso_serviceclient.kind`, `.owner_id`, `.device_name`, `.public_key`, `.public_key_fingerprint`, `.last_used`, `.can_delegate`, `.can_register_devices` |
| v1.3c | `sso.0006_v13c` | `sso_serviceclient.notify_events`, `.notify_secret_enc`; tables `sso_webhookevent`, `sso_webhookdelivery` |
| v1.3d | `sso.0007_v13d_audit_channel` | `sso_adminauditlog.channel` (+ index) |

All changes only add tables, columns and indexes; no existing row is changed. The post-migrate step adds rows to
`auth_permission` / `django_content_type` and the code-defined permission `application.sso_admin`. After an
upgrade from before v1.3:

- Grant `application.sso_admin` (and Django **staff status**) to the people who use the admin API or admin UI.
- Set `SSO_WEBHOOK_SECRET_KEY` in `.env` (step 2) before you set any webhook secret.

## 12. Deploy to a VPS from the Docker images only

Steps 0 to 11 run the stack from a repo checkout. On a production VPS you only **pull images**. Everything the
host needs ships inside the images:

- `sso-server` has the key and certificate generators in `/app/scripts/` and a deploy kit in `/app/deploy/`
  (`docker-compose.yml`, `env.example`, `scripts/upgrade_db.sh`, `scripts/deploy.sh`, `scripts/deploy_check.sh`).
- `sso-nginx` has `nginx.conf` built in.

The keys and the bootstrap certificate are generated **on the VPS** by the compose `init` service on the first
`up`, into the host folders `SSO_KEYS_DIR` / `SSO_CERTS_DIR`. They never enter an image and are never copied from
a workstation.

Two hosts, two roles, always in this order:

1. **Migration server** (DB team, 12.6): brings the SSO schema in `dcWebUsers` to the release's level with
   `scripts/upgrade_db.sh` as `sso_migrator`. Only this host has the `sso_migrator` password and grant.
2. **VPS** (Ops, 12.7): `scripts/deploy.sh` creates keys and certificate (`init`), checks that the schema is
   already migrated (schema gate, runtime account `sso_app`), and only then starts the containers. The VPS
   never migrates and never holds DDL credentials.

Example values below: release tag `0.1.2` (use your own), image `ghcr.io/thomas-choi/sso-server:0.1.2`, host name `sso.example.com`, a remote/managed
MySQL. Run everything as root (`sudo -i`) in the install directory `$SSO_DIR` (here `/opt/sso`; any path works, but
set the variable in every new shell): `.env` is `root:root 0600` and compose reads it as root.

### 12.1 Prerequisites

- Ubuntu VPS with Docker Engine and the compose plugin (`docker compose version`).
- Inbound TCP **80 and 443** (`SSO_HTTP_PORT` / `SSO_HTTPS_PORT`) open in the provider's firewall and **free on the
  host** (§0.1; hosting panels often run Traefik on them). Docker-published ports bypass ufw (step 6), so ufw only
  needs SSH (`ufw allow OpenSSH`).
- A **DNS A record** `sso.example.com` → the VPS IP, needed for Let's Encrypt (12.8). Serving by IP only works too:
  see the note in 12.8.
- An image tag built **from a commit that has the deploy kit**, with `sso-server` and `sso-nginx` both pushed under
  that tag. Older tags (e.g. `0.1.1`) don't have `/app/deploy`. Until CI publishes them, build and push both
  from your workstation's checkout, after committing:
  ```bash
  TAG=0.1.2                                        # new release tag; never reuse a pushed one
  docker build -t ghcr.io/thomas-choi/sso-server:$TAG .
  docker build -f docker/Dockerfile.nginx -t ghcr.io/thomas-choi/sso-nginx:$TAG .
  docker login ghcr.io -u thomas-choi              # token with write:packages
  docker push ghcr.io/thomas-choi/sso-server:$TAG && docker push ghcr.io/thomas-choi/sso-nginx:$TAG
  ```
- GHCR packages are private by default. Log in once with a personal access token that has only `read:packages`:
  `docker login ghcr.io -u thomas-choi`.
- The database accounts `sso_app` (DML) and `sso_migrator` (DDL) exist, with the grants from step 5.2. Host
  parts instead of `172.31.250.%`: `sso_app` from the **VPS public IP**, `sso_migrator` from the **migration
  server's IP** only (for a managed database: add both IPs to the trusted sources). Containers reach the database
  through their host's own address.
- A **migration server** for 12.6 (DB team): any Linux host with Docker that can reach the database and pull the
  images. It may be the DB host itself, but not the VPS.

### 12.2 Get the deploy kit

```bash
export TAG=0.1.2                                   # the tag you pushed (12.1)
export IMG=ghcr.io/thomas-choi/sso-server:$TAG
export SSO_HOSTNAME=sso.example.com
export SSO_DIR=/opt/sso                            # install directory; used by every step below
install -d -m 755 "$SSO_DIR" && cd "$SSO_DIR"
docker pull "$IMG"                                 # always: docker run reuses a cached image of the same tag
docker run --rm "$IMG" ls /app/scripts /app/deploy # gen_keys.sh ... / docker-compose.yml env.example scripts
docker run --rm "$IMG" tar -C /app/deploy -cf - . | tar -xf - --no-same-owner -C "$SSO_DIR"
```

Don't edit `docker-compose.yml`: the next upgrade overwrites it. Put local changes in `.env`, or in a
`docker-compose.override.yml` next to it (compose loads that file automatically).

### 12.3 Create `.env`

```bash
install -m 600 env.example .env
docker run --rm "$IMG" python -c 'import secrets; print(secrets.token_urlsafe(50))'    # SSO_SECRET_KEY=
docker run --rm "$IMG" python -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'  # SSO_WEBHOOK_SECRET_KEY=
```

Edit these keys in `.env`. Each one already exists in the template, so change it in place rather than appending
a second copy (the last copy wins). Keep comments on their own lines: in `KEY=   # note`, compose reads the
value as `# note`.

```ini
# images = ${DOCKER_USER}/sso-server and /sso-nginx
DOCKER_USER=ghcr.io/thomas-choi
IMAGE_TAG=0.1.2
SSO_SECRET_KEY=<generated>
SSO_WEBHOOK_SECRET_KEY=<generated>
SSO_HOSTNAME=sso.example.com
SSO_ISSUER=https://sso.example.com
SSO_ALLOWED_HOSTS=sso.example.com
SSO_CSRF_TRUSTED_ORIGINS=https://sso.example.com
# the front-end origins that use the SSO
SSO_CORS_ALLOWED_ORIGINS=https://fin.example.com
# or .example.com to share the cookie with sibling hosts
SSO_COOKIE_DOMAIN=
# raise to 31536000 once TLS is final (12.8)
SSO_HSTS_SECONDS=300
SSO_DBHOST=<db host>
# DigitalOcean managed MySQL; 3306 for a plain MySQL
SSO_DBPORT=25060
SSO_DBNAME=dcWebUsers
SSO_DBUSER=sso_app
SSO_DBPWD=<sso_app password>
# your real install path (= $SSO_DIR/mysql-ca), written out
SSO_MYSQL_CA_DIR=/opt/sso/mysql-ca
SSO_DB_SSL_CA=/run/mysql-ca/ca.pem
SSO_DB_SSL_MODE=VERIFY_CA
# bootstrap cert (12.5); 12.8 switches to Let's Encrypt
SSO_CERTS_DIR=./docker/certs
SSO_TLS_CERT_FILE=selfsigned.crt
SSO_TLS_KEY_FILE=selfsigned.key
# keys: generated on the first "up" (12.4) under these names; keep them stable
SSO_KEYS_DIR=./keys
SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem
SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem
```

`SSO_ISSUER` goes into every token. Choose the final name now: changing it later invalidates every issued token,
and every client has to be reconfigured.

Database CA certificate: download it from the provider (DigitalOcean: the database's *Connection details* →
*Download CA certificate*). It is public, not a secret:

```bash
install -d -m 755 mysql-ca && install -m 644 /path/to/ca-certificate.crt mysql-ca/ca.pem
```

### 12.4 JWT signing keys (automatic)

Nothing to do: the first `scripts/deploy.sh` / `docker compose up` (12.7) runs the `init` service, which creates
`$SSO_DIR/keys`, generates the pair named in `.env` (owner `SSO_UID:SSO_GID`, private `0600`) and prints its
`kid=` (`docker compose logs init`). If `keys/` is later lost, init generates a new pair (everyone logs in
again, deployment plan §4.2 rule 5) unless `SSO_JWT_PUBLIC_KEYS` lists more than one key, then it stops.

By hand (fallback, or with `SSO_AUTO_INIT=false`):

```bash
: "${SSO_DIR:?set SSO_DIR first (e.g. export SSO_DIR=\$PWD)}"   # empty -> Docker mounts /keys (root-owned) instead
install -d -m 700 -o 10001 -g 10001 "$SSO_DIR/keys"
docker run --rm -v "$SSO_DIR/keys:/out" -e HOST_KEYS_DIR="$SSO_DIR/keys" "$IMG" \
  /app/scripts/gen_keys.sh /out sso-$(date +%Y-%m)
```

Copy the printed `SSO_KEYS_DIR=` / `SSO_JWT_PRIVATE_KEY=` / `SSO_JWT_PUBLIC_KEYS=` lines into `.env` and note
the `kid=`. The container runs as uid 10001, the user `web` runs as. The files therefore already have the right
owner: private key `0600`, public key `0644`. If you build with a different `SSO_UID`/`SSO_GID`, add
`--user <uid>:<gid>` and use that owner for `keys/`. Rotation: [README §4](../README.md#4-key-generation-and-rotation).

### 12.5 Bootstrap TLS certificate (automatic)

nginx needs a certificate to start, and Let's Encrypt (12.8) needs nginx running. So it starts with a self-signed
one: with `SSO_CERTS_DIR=./docker/certs` and the `selfsigned.crt` / `selfsigned.key` names from 12.3, the `init`
service generates it for `SSO_HOSTNAME` on the first `up`. By hand (fallback):

```bash
install -d -m 700 -o 10001 -g 10001 docker/certs
docker run --rm -v "$SSO_DIR/docker/certs:/out" "$IMG" /app/scripts/gen_selfsigned_cert.sh "$SSO_HOSTNAME" /out
```

### 12.6 Create the schema (DB team, on the migration server)

This runs **before** Ops starts the VPS (12.7), on the migration server, never on the VPS. Prepare that host like
the VPS: the deploy kit of the same tag (12.2), a `.env` (copy of the VPS one from 12.3, `chmod 600`; `SSO_DBHOST`
/ `SSO_DBPORT` as reachable from this host) and the database CA in `mysql-ca/`. The `web` container needs
signing keys to load its settings, so `init` creates a throw-away key pair and certificate in this host's `keys/`
and `docker/certs/`. They sign nothing anyone trusts (their kid is not in the VPS's JWKS); never copy them to or
from the VPS.

Take the full `mysqldump` backup from [step 7](#7-back-up-then-create-the-sso-schema-as-sso_migrator) first (`dcWebUsers` is shared with myFinance). Then:

```bash
docker compose config --images                     # ghcr.io/thomas-choi/sso-server:0.1.2, .../sso-nginx:0.1.2, redis
docker compose pull web
read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
scripts/upgrade_db.sh --plan                       # DB reachable (TLS + CA)? what would be applied?
scripts/upgrade_db.sh                              # backup of the SSO tables, migrate (asks first), schema check
unset SSO_DBPWD
docker compose down                                # removes the one-off redis/init containers; nothing else runs here
```

There is no `Dockerfile` here, so `upgrade_db.sh` uses the pulled `IMAGE_TAG` and doesn't build. Everything else
works as in [§11](#11-upgrading-the-database-later), including the stop when the plan touches any app other than
`sso`, `application` and `token_blacklist`. When the summary says `schema: OK`, tell Ops the tag: 12.7 can start.

### 12.7 Start and verify (Ops, on the VPS)

Only after the DB team finished 12.6 for this tag:

```bash
scripts/deploy.sh                                  # pull, init (keys + cert), schema gate, up --wait, deploy_check.sh
```

Without a `Dockerfile` (image-only install), `deploy.sh` pulls and starts with `--no-build`. Before starting
anything it runs the **schema gate**: a one-off `web` container (after `init` has created the keys and the
certificate) checks as `sso_app` that the database is reachable and `manage.py sso_schema_check` passes. If the
schema is not migrated yet it stops with exit code 3 and changes nothing; on an upgrade the old release keeps
running. Ask the DB team for 12.6, then run `deploy.sh` again. It ends with
`scripts/deploy_check.sh`, which prints `[PASS]` / `[WARN]` / `[FAIL]` per check plus the fix from
[Troubleshooting](#troubleshooting). Expect two WARNs on a fresh VPS: T04 (self-signed certificate until 12.8) and,
until 12.9, D10 (admin UI not IP-restricted). Manual equivalent:

```bash
docker compose up -d --no-build
docker compose ps                                  # web, webhooks, redis, nginx: Up (healthy)
R="--resolve $SSO_HOSTNAME:443:127.0.0.1 --cacert docker/certs/selfsigned.crt"
curl -s $R https://$SSO_HOSTNAME/healthz           # {"status":"ok"}
curl -s $R https://$SSO_HOSTNAME/.well-known/jwks.json \
  | python3 -c 'import json,sys; print([k["kid"] for k in json.load(sys.stdin)["keys"]])'   # = kid from 12.4
```

`--resolve` tests the local nginx even before DNS has propagated. Always pass `--no-build`: the compose file has
`build:` sections, and there is no source code on the VPS.

### 12.8 Let's Encrypt certificate

This needs the DNS record from 12.1 and port 80 reachable from the internet. certbot runs as an on-demand
container (`certbot` service, compose profile). It writes into `./letsencrypt` (`SSO_LETSENCRYPT_DIR`), which
holds private keys, so it is secret like `keys/`:

```bash
docker compose run --rm certbot certonly --webroot -w /var/www/acme \
  -d "$SSO_HOSTNAME" -m you@example.com --agree-tos --no-eff-email
```

Point nginx at the new certificate in `.env`:

```ini
SSO_CERTS_DIR=./letsencrypt
SSO_TLS_CERT_FILE=live/sso.example.com/fullchain.pem
SSO_TLS_KEY_FILE=live/sso.example.com/privkey.pem
SSO_HSTS_SECONDS=31536000
```

```bash
docker compose up -d --no-build --force-recreate nginx web
curl -s https://$SSO_HOSTNAME/healthz              # now from anywhere, without --cacert
```

Renewal and the token clean-up, in `/etc/cron.d/sso`:

Write the real `$SSO_DIR` path, because cron does not know the variable:

```cron
17 4 * * * root cd /opt/sso && docker compose run --rm certbot renew -q && docker compose exec -T nginx nginx -s reload
30 3 * * * root cd /opt/sso && docker compose exec -T web python manage.py flushexpiredtokens
```

Test renewal once with `docker compose run --rm certbot renew --dry-run`.

**Serving by IP only (no DNS name):** skip 12.8 and keep the self-signed certificate. Generate it for the IP
(`gen_selfsigned_cert.sh <public IP> /out` in 12.5), set `SSO_HOSTNAME` / `SSO_ISSUER` to that IP and
`SSO_TLS_REJECT_UNKNOWN_SNI=off` (step 1, option B). Every client must trust or pin `docker/certs/selfsigned.crt`.

### 12.9 Admin user, admin UI and a login check

```bash
docker compose run --rm web python manage.py createsuperuser        # or promote an existing dcWebUsers user
```

Grant app access as in [§9](#9-admin-user-app-access-and-a-login-check) and the admin UI permission as in
[§10](#10-admin-web-ui). On a public VPS, restrict the admin UI to your own addresses:

```bash
install -d -m 755 docker/nginx-admin-ui.d
printf 'allow 203.0.113.10;\ndeny all;\n' > docker/nginx-admin-ui.d/allow.conf     # your office / VPN IP
docker compose up -d --no-build --force-recreate nginx
```

For Django admin, the same file goes in `docker/nginx-admin.d/`. Check a real login from your workstation's
checkout:

```bash
scripts/sso_login_check.py --url https://sso.example.com --cacert /etc/ssl/certs/ca-certificates.crt <username>
```

### 12.10 Upgrading to a new release

```bash
export SSO_DIR=/opt/sso && cd "$SSO_DIR"
export TAG=0.1.3                                   # the new tag, pushed as in 12.1
export IMG=ghcr.io/thomas-choi/sso-server:$TAG
docker pull "$IMG"
cp env.example env.example.prev
docker run --rm "$IMG" tar -C /app/deploy -cf - . | tar -xf - --no-same-owner -C "$SSO_DIR"
diff env.example.prev env.example                  # new variables to copy into .env?
sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=$TAG/" .env
```

Run this block on **both** hosts. Then, in order:

```bash
# 1. migration server (DB team)
docker compose pull web
read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
scripts/upgrade_db.sh --plan && scripts/upgrade_db.sh
unset SSO_DBPWD; docker compose down
# 2. VPS (Ops), after 1 reported "schema: OK"
scripts/deploy.sh                                  # init, schema gate, up --no-build --wait + deploy_check.sh
```

Migrations are additive (deployment plan §6), so the old release keeps working between step 1 and step 2.

The kit never contains `.env`, `keys/`, `docker/certs/`, `letsencrypt/` or the allow-lists, so extracting it
over `$SSO_DIR` is safe. To roll back a release that had no migrations, set `IMAGE_TAG` back and run
`docker compose up -d --no-build`. With migrations, follow deployment plan §13.

## Troubleshooting

`scripts/deploy_check.sh` detects most of these automatically and prints the matching fix: container state and
restart loops (D01, D02), nginx DNS (D03 to D07), database errors in the log (D08), image tags (D09), the admin
allow-list (D10), the published port (D11), `.env` consistency for issuer, Host, SNI, cookie domain, origins and
CSRF (C01 to C07), TLS handshake and certificate name or expiry (T01 to T04), `/healthz` with database and
migrations (H01), and the JWKS kid (J01). It cannot see certbot reachability from the internet or per-user admin
permissions.

| Symptom | Cause | Fix |
|---|---|---|
| `web` log: `ERROR sso.db startup: database unreachable at host.docker.internal:3306 ... (2002, "Can't connect ... (110)")`, `/healthz` 503 | Error 110 = timeout: the packets are dropped, usually by ufw (`DEFAULT_INPUT_POLICY="DROP"`) | Step 6 (ufw rule). `/healthz` recovers on the next probe; no restart needed |
| `web` log: `WORKER TIMEOUT` / `Worker was sent SIGKILL! Perhaps out of memory?` | Almost never memory: a request (usually the healthcheck's `/healthz`) waited on MySQL past gunicorn's 30 s timeout. Since v1.2b the DB connect timeout is 3 s (`SSO_DB_CONNECT_TIMEOUT`), so you should see the `sso.db` line above instead | Treat as the database-unreachable rows; test with `docker compose run --rm --no-deps web python /app/docker/dbcheck.py` |
| Same, but error **111** (connection refused) | MySQL not running or bound to `127.0.0.1` only | Step 5.1 (`bind-address`) |
| Error **1045** / **1130** (access denied / host not allowed) | Account missing, wrong password, or host part does not match `172.31.250.%` | Step 5.2 |
| `deploy.sh` stops at the schema gate (exit 3: `unapplied SSO migrations` / `MISSING`), or `/healthz` answers `"warning": "database migrations pending"` | SSO schema older than the code: the migration was not run for this release | Step 7 / §11; on a VPS the DB team runs 12.6 on the migration server, then `scripts/deploy.sh` again |
| `failed to bind host port 0.0.0.0:80/tcp: address already in use` (or `:443`); nginx stays `Created` | Another process owns the port: `sudo ss -ltnp '( sport = :80 or sport = :443 )'` names it (often a hosting panel's Traefik, or a host nginx/Apache) | Stop it if nothing needs it; otherwise set free ports, e.g. `SSO_HTTPS_PORT=8443` / `SSO_HTTP_PORT=8080`, and put the port into `SSO_ISSUER`, `SSO_CSRF_TRUSTED_ORIGINS` and the clients' URLs (§0.1); open them in the provider's firewall. Don't proxy through the other proxy: `nginx.conf` sets `X-Forwarded-For` to its peer, so every client would share the proxy's IP in the per-IP throttle |
| `curl: (7) Failed to connect ... port 443 ... Connection refused`; `docker compose ps` shows nginx `Restarting` | nginx cannot start; `docker compose logs nginx` shows `cannot load certificate "/etc/nginx/certs/..."` | Step 3: create the certificate or fix `SSO_TLS_CERT_FILE` / `SSO_TLS_KEY_FILE` / `SSO_CERTS_DIR`, then `docker compose up -d --force-recreate nginx` |
| `curl: (35) ... tlsv1 unrecognized name` / Python `TLSV1_UNRECOGNIZED_NAME` | The URL's host is not `SSO_HOSTNAME` (e.g. still `sso.dev.com`), or you connect **by IP** with `SSO_TLS_REJECT_UNKNOWN_SNI` still `on` | Set `SSO_HOSTNAME` to the address you use; for an IP also `SSO_TLS_REJECT_UNKNOWN_SNI=off` (step 1). Then `docker compose up -d --force-recreate nginx` |
| `curl: (60)` / `CERTIFICATE_VERIFY_FAILED ... IP address mismatch` or `hostname mismatch` (but `-k` works) | Certificate issued for another name or IP | Step 3: regenerate for the address from step 1 |
| `curl: (52) Empty reply from server` | Host header is not `SSO_HOSTNAME`; nginx closes the connection (444) | Call it by exactly `SSO_HOSTNAME` |
| HTTP 400 Bad Request from Django | Host header not in `SSO_ALLOWED_HOSTS` | Add the address to `SSO_ALLOWED_HOSTS`, recreate `web` |
| Tokens rejected by apps with an issuer error | App configured with another issuer, or `SSO_ISSUER` changed (new IP / name) | Use the same `SSO_ISSUER` everywhere; users log in again |
| Browser login works but refresh fails / no cookie stored | `SSO_COOKIE_DOMAIN` set to another domain (e.g. `.example.com`) | Leave `SSO_COOKIE_DOMAIN=` empty |
| Browser-mode login/refresh rejected on `Origin` | Page origin not in `SSO_CORS_ALLOWED_ORIGINS` | Add the exact origin (scheme, host, port) |
| `web` keeps restarting, log mentions keys | Container user cannot read `keys/` | The `init` service fixes the owner to `SSO_UID:SSO_GID` on every `up`; otherwise step 4 (`SSO_UID`/`SSO_GID` + rebuild, or chown to 10001) |
| `docker compose up`: `service "init" didn't complete successfully: exit 1`; web/nginx not started | `init` found a configured key or certificate missing in a non-empty folder, a Let's Encrypt path without files, or a rotation list with an empty key folder | `docker compose logs init` names the file; fix the names in `.env` or restore the files (§4 / §3) |
| `webhooks` container `unhealthy` | The worker's last successful loop is older than `SSO_HEALTHCHECK_MAX_AGE` (300 s): database or Redis unreachable, or the worker is stuck | `docker inspect --format '{{json .State.Health}}' sso-webhooks-1` shows the reason; `docker compose logs webhooks` |
| `403 Forbidden` from nginx on `/admin/` | Your IP is not in `docker/nginx-admin-ui.d/*.conf` | Add an `allow` line, `docker compose up -d --force-recreate nginx` |
| An edit to `docker/nginx.conf` has no effect | The template is baked into the `sso-nginx` image (`docker/Dockerfile.nginx`), not mounted | `docker compose up -d --build nginx` |
| VPS: `docker run ... ls /app/deploy` fails, or `stat /app/scripts/gen_keys.sh: no such file or directory` | The VPS runs a **cached older image** of that tag (`docker run` doesn't re-pull; typical after re-pushing an existing tag), or the tag was built before the deploy kit existed | `docker pull "$IMG"` and check again; otherwise push a new tag of both `sso-server` and `sso-nginx` (§12.1). Don't reuse tags |
| VPS: `docker compose pull`: `denied` / `unauthorized` from `ghcr.io` | GHCR packages are private by default | `docker login ghcr.io` with a `read:packages` token, or make the packages public (§12.1) |
| VPS: `docker compose up` tries to build (`unable to prepare context` / `Dockerfile: no such file`) | `--no-build` missing and an image is not pulled | `docker compose pull`, then `docker compose up -d --no-build` (§12.7) |
| VPS: certbot `Timeout during connect` / `unauthorized` for the challenge | Port 80 is blocked by the provider's firewall, or DNS does not point at the VPS yet | Open 80 in the provider's firewall; check `dig +short $SSO_HOSTNAME` (§12.8) |
| Admin UI: "Invalid username or password, or no admin access" with the right password | Account not staff, not active, or missing `application.sso_admin` | Fix in Django admin (`/sso-admin/`) |
| Admin UI: `403 CSRF verification failed` | Admin origin not in `SSO_CSRF_TRUSTED_ORIGINS` | Add the exact origin (scheme, host, port), recreate `web` |
| Admin UI: sent back to the login page after a while or after a network change | Idle timeout (30 min), max age (8 h) or IP binding | Sign in again |

After any `.env` change, recreate the affected service (`docker compose up -d --force-recreate <service>`); a plain
`restart` does not re-read `.env`.

## Production deployment watch-outs

### nginx: `recv() failed (111: Connection refused) while resolving, resolver: 127.0.0.11:53`

Seen on a VPS right after `docker compose up`: the nginx log repeats this every 5 s, then
`web could not be resolved (110: Operation timed out)`, while `web` stays healthy. nginx re-resolves `web` through
Docker's embedded DNS (`resolver 127.0.0.11` in `docker/nginx.conf`), so until this is fixed **every proxied
request gets a 502**.

"Connection refused" means nothing answers DNS on `127.0.0.11` inside the nginx container. A failed lookup would
look different (Docker's DNS answers NXDOMAIN). The compose file in this repo puts nginx on the user-defined `edge`
network, where Docker always provides `127.0.0.11`, so look at how the container really runs on the VPS. If
`docker compose up` lists only web, webhooks and redis and creates nginx on its own, suspect a different or
edited compose file for nginx.

Diagnose (in `$SSO_DIR`):

```bash
# 1. network mode and networks of nginx: expect "sso_edge" (not "host" or "default")
docker inspect sso-nginx-1 --format '{{.HostConfig.NetworkMode}} {{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'

# 2. DNS server seen by the container: expect "nameserver 127.0.0.11"
docker compose exec nginx cat /etc/resolv.conf

# 3. lookup from nginx vs from web
docker compose exec nginx nslookup web 127.0.0.11
docker compose exec web python -c "import socket; print(socket.gethostbyname('nginx'))"

# 4. the nginx service in the compose file actually used, and the daemon config
docker compose config | sed -n '/^  nginx:/,/^  [a-z]/p' | grep -A3 -E 'network'
cat /etc/docker/daemon.json 2>/dev/null; docker version --format '{{.Server.Version}}'
```

| Result | Cause | Fix |
|---|---|---|
| Step 1 shows `host` | `network_mode: host` set on the VPS (some hosting panels add it). `127.0.0.11` is then the VPS's own loopback, where nothing listens, and `web` can never be resolved | Remove `network_mode`, keep `networks: [edge]`, `docker compose up -d --force-recreate nginx` |
| Step 1 shows `bridge` / `default`, or step 4 shows no `edge` | The VPS compose file is older or hand-edited | Replace it with the current `docker-compose.yml` from the deploy kit in the image (`/app/deploy`, §12.2) |
| Step 1 shows `sso_edge`, step 3 fails in nginx but works in web | The Docker daemon failed to set up DNS for this container (seen after a Docker upgrade or restart) | `docker compose down && docker compose up -d --no-build` (recreates the network); if that does not help, `systemctl restart docker`, then bring the stack up again |
| Step 2 shows something other than `127.0.0.11` | Unusual daemon DNS setup (`daemon.json`, rootless Docker) | The nginx template needs to take its resolver from the container's `/etc/resolv.conf` instead of the hard-coded `127.0.0.11` (code change in `docker/nginx.conf` + `docker/Dockerfile.nginx`, then a new `sso-nginx` tag) |

Check afterwards: the nginx log has no more `while resolving` errors, and
`curl -sS --resolve "$SSO_HOSTNAME:443:127.0.0.1" "https://$SSO_HOSTNAME/healthz"` returns 200 (add `-k` with the
bootstrap certificate).
