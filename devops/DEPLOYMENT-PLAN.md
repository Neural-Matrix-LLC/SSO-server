# SSO server: deployment plan (DevOps)

> **Status: PLAN ONLY, not executed.** Nothing has been deployed, provisioned, connected to or bought.
> Every command below is something to run **later**, after Thomas approves, on the real VPS or database.
> **Sources:** `docs/Request.txt`, `docs/SSO-server.md` ("spec §x"), `docs/DESIGN-ADDENDUM-v1.1.md` ("addendum B.x";
> it wins over the spec), and Thomas's answers relayed by Philip on 2026-10-10 ("Thomas 2026-10-10"), which win over
> both. **[ASSUMPTION]** marks anything not in those sources; each one is also listed in §16.
> **Ownership:** the Developer writes `Dockerfile`, `docker-compose.yml`, `docker-compose.test.yml`,
> `docker/nginx.conf`, `scripts/gen_keys.sh`, `.env.example` and the README (addendum A). §15 lists what those files
> must satisfy. DevOps owns only this plan and the **draft** pipeline `devops/ci/pipeline.yml`.

## Changelog
| Version | Date | Change |
|---|---|---|
| v1.1 | 2026-10-10 | Thomas's answers applied. **MySQL 8.4 + Django 5.2 only**: the 4.2 fallback and CI matrix are dropped (supersedes addendum B.1). 8.4 notes added: auth plugin, TLS, client library, `mysqldump` client. **Ubuntu VPS** host section made concrete (Docker Engine + compose plugin, ufw, cron, unattended-upgrades). **Hostname, domain and ports parameterized** (`SSO_HOSTNAME`, `SSO_DOMAIN`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`); the decision is still pending (§0). **Local/QA environment** added: `mysql:8.4` container + synthetic users. The staging copy of `dcWebUsers` moved to the pre-go-live checklist. Open questions Q1, Q2 (host type), Q3 and Q7 resolved. Names aligned with the Developer's code as it now exists (`SSO_ADMIN_PATH`, `SSO_NUM_PROXIES`, `SSO_DBNAME`, kid-based multi-key verification in `sso/tokens.py`). CI: `mysql:8.4` service, plus a DB login check from inside the built image. |
| v1.0 | 2026-10-10 | First plan. |

---

## 0. Parameters to decide (Thomas 2026-10-10: "port, hostname and domain undecided")

Every hostname, URL and port in this plan uses the parameters below. **Nothing is hard-coded.** Where the spec says
`sso.thomas-choi.com`, read it as `${SSO_HOSTNAME}`.

| Parameter | Meaning | Example only | Decided? |
|---|---|---|---|
| `SSO_DOMAIN` | Parent (registrable) domain shared by SSO and the front-ends. Drives the cookie domain (spec §7.1: apps and SSO must be same-site). | `example.com` | **pending** |
| `SSO_HOSTNAME` | Public FQDN of the SSO server | `sso.${SSO_DOMAIN}` | **pending** |
| `SSO_HTTPS_PORT` | Public HTTPS port on the VPS (mapped to nginx :443) | `443` | **pending** |
| `SSO_HTTP_PORT` | Public HTTP port (ACME + redirect, mapped to nginx :80). Empty means none. | `80` | **pending** |
| `SSO_STAGING_HOSTNAME` | Staging FQDN (pre-go-live rehearsal) | `sso-staging.${SSO_DOMAIN}` | **pending** |

Derived app settings, written out explicitly in `/opt/sso/.env`. The app does not compute them.

| App env var (existing in `ssoproject/settings.py`) | Value |
|---|---|
| `SSO_ISSUER` | `https://${SSO_HOSTNAME}` if `SSO_HTTPS_PORT=443`, else `https://${SSO_HOSTNAME}:${SSO_HTTPS_PORT}`. **Exact string** that services compare against `iss` (spec §8.1). |
| `SSO_ALLOWED_HOSTS` | `${SSO_HOSTNAME}` (Django ignores the port when matching) |
| `SSO_CSRF_TRUSTED_ORIGINS` | the `SSO_ISSUER` value (for `/admin` forms behind the proxy) |
| `SSO_COOKIE_DOMAIN` | `.${SSO_DOMAIN}` |
| `SSO_CORS_ALLOWED_ORIGINS` | the front-end origins, e.g. `https://fin.${SSO_DOMAIN}` |
| Service side (spec §8.1) | `SSO_ISSUER` as above, `SSO_JWKS_URL=${SSO_ISSUER}/.well-known/jwks.json` |

Consequences of the choices:
- If `SSO_HTTPS_PORT` is not 443, the issuer carries the port, and every consumer must use exactly that string.
  Some corporate networks block non-standard ports.
- If `SSO_HTTP_PORT` is not 80 or is empty, Let's Encrypt **HTTP-01 cannot be used** (it always connects to
  port 80). Use DNS-01 or another cert source (§3.2).
- **Changing `SSO_HOSTNAME`/issuer after go-live invalidates every issued token and requires every service to
  reconfigure.** Decide before go-live (pre-go-live gate G1, §12).
- Plan-wide placeholders used below: `<db_host>`, `<sso_vps_ip>` (egress IP of the VPS), `<app_origin>`.

## 1. Architecture summary

```
Internet ──${SSO_HTTPS_PORT}──▶ nginx :443 (TLS) ──http:8000──▶ web (gunicorn, 3 workers, Django 5.2, app "sso")
         ──${SSO_HTTP_PORT}───▶ nginx :80 (ACME + 301)                  │            │
                                                                         │            └─▶ redis (throttle cache)
            Ubuntu VPS, Docker Engine + compose plugin, ufw              ▼                internal network only
                                                       remote MySQL 8.4  `dcWebUsers` (shared with myFinance), TLS
Host files: /opt/sso/.env (0600)  /opt/sso/keys/*.pem → /run/keys:ro  /opt/sso/certs  /etc/cron.d/sso-*
```

- No DB container in staging or prod. MySQL is remote (spec §9.5). The `mysql:8.4` container exists **only** in
  local/QA and CI (§2).
- Only nginx publishes ports. `web` and `redis` stay on the internal compose network.
- No migrations run automatically. `migrate` is a backed-up, operator-run step (§6, §12).

## 2. Environments

| | dev (Developer) | **local / QA (sprint 1)** | staging (**pre-go-live**) | prod |
|---|---|---|---|---|
| Purpose | Unit tests, coding | QA black-box suite (`qa/tests`) and `examples/` end to end, on MySQL 8.4 | Rehearse the prod rollout on a **copy of real `dcWebUsers`** | Live |
| Where | Developer box | Shared box / any Docker host, `docker compose -f docker-compose.test.yml` (+ the app stack) | Ubuntu VPS (same as prod, or a second VPS: Q20) | Ubuntu VPS |
| Hostname | `localhost` | `localhost` (self-signed) | `${SSO_STAGING_HOSTNAME}` | `${SSO_HOSTNAME}` |
| DB | SQLite (`SSO_DB_ENGINE=sqlite`; `settings_test.py` uses `:memory:`) | **`mysql:8.4` container**, schema `dcWebUsers`, **synthetic users only** (§2.1) | Separate MySQL 8.4 schema restored from a fresh `dcWebUsers` dump (§6.3) | Remote MySQL 8.4 `dcWebUsers` |
| TLS | none / self-signed | self-signed (addendum C) | same source as prod | §3.2 |
| Cache | LocMem | Redis (proves shared-cache throttling) | Redis | Redis |
| Keys | ephemeral (`SSO_DEBUG=True` generates one) / `settings_test.py` | throw-away pair (`scripts/gen_keys.sh`) | own pair | own pair. **Never shared across envs** |
| `SSO_DEBUG` | `True` allowed | `False` (prod-like) | `False` | `False` |

Rules: each environment has its own issuer and keys. The same image tag moves local/QA → staging → prod. Staging
holds real password hashes and emails (Thomas accepted a copy for pre-go-live), so it is protected **exactly like
prod**: same host hardening, encrypted dump, and the schema is dropped after go-live unless kept on purpose (Q6).

### 2.1 Local/QA: `mysql:8.4` container with synthetic users
Thomas 2026-10-10: sprint-1 QA tests against a local `mysql:8.4` container with synthetic users.

Container (in the Developer's `docker-compose.test.yml`, addendum B.14). Requirements:
- `image: mysql:8.4` (pin to a patch version once chosen). `MYSQL_DATABASE=dcWebUsers`. Root password and app
  passwords come from a git-ignored `.env.test`. Data in a named volume that can be thrown away. Port bound to
  `127.0.0.1:3307:3306` at most, or not published at all. No authentication overrides: keep 8.4 defaults
  (`caching_sha2_password`, `mysql_native_password` disabled), so QA sees exactly prod's auth behaviour.
- An init script in `/docker-entrypoint-initdb.d/` (runs only on first start of an empty volume) creates the same two
  accounts as prod (§6.2): `sso_app` (DML only) and `sso_migrator` (DDL). QA then also proves the app runs with
  DML-only grants. `'%'` as the host part is acceptable **here only**.

Bringing the schema to a "looks like myFinance's `dcWebUsers`" state:
1. `migrate` **only Django's built-in apps** first, as `sso_migrator`:
   `python manage.py migrate auth`, `migrate contenttypes`, `migrate admin`, `migrate sessions`. This reproduces
   the tables and `django_migrations` rows that myFinance already created in prod (spec §4).
2. Seed synthetic users: run the QA seed **before** step 3. Then step 3 behaves like prod, where users already
   exist. Use the existing QA fixture `qa/tests/fixtures/seed_test_data.py` (definitions in `qa/tests/testdata.py`):
   `qa_*` users with **Django 4.1-format PBKDF2 hashes** (`pbkdf2_sha256$390000$…`) plus other legacy formats,
   inactive users, duplicate emails, empty emails, staff, and groups. It is idempotent and touches only `qa_*` /
   `qa-*` rows.
   `docker compose exec -T web python manage.py shell < qa/tests/fixtures/seed_test_data.py`
3. `python manage.py migrate --plan`. It must list only `sso` and `token_blacklist`. Then `migrate`, as in prod
   (§12 P6).
4. Run `qa/tests` against `https://localhost:${SSO_HTTPS_PORT}` (QA env vars `SSO_BASE_URL`, `SSO_VERIFY_TLS=0`, …).
- **Requirement (QA/Developer, R27):** the seed script needs a hard guard. It must refuse to run unless an explicit
  `SSO_ALLOW_SYNTHETIC_SEED=1` is set **and** `SSO_DBHOST` is a local/container host. Today it only says "NEVER run
  against production" in a comment.
- Limitation: the container's charset/collation is the 8.4 default (`utf8mb4` / `utf8mb4_0900_ai_ci`). Prod
  `dcWebUsers` may have older table collations from earlier MySQL versions. Staging (real dump) is where that gets
  verified.

## 3. Ubuntu VPS host, Docker Compose, nginx and TLS

### 3.0 Host baseline (Ubuntu VPS; Thomas 2026-10-10). Planned commands, **not run**
**[ASSUMPTION]** Ubuntu **24.04 LTS** (Q20). Run as a sudo-capable admin user over SSH.

1. **Base hardening**
   - SSH key-only login: in `/etc/ssh/sshd_config.d/10-hardening.conf` set `PasswordAuthentication no`,
     `PermitRootLogin no`, then `sudo systemctl reload ssh`.
   - Time sync (JWT `iat`/`exp` rely on it): `timedatectl status` must show `System clock synchronized: yes`
     (systemd-timesyncd is on by default).
   - Optional: `fail2ban` for sshd.
2. **Docker Engine + compose plugin** from Docker's official apt repository. Ubuntu's `docker.io` package works,
   but the compose v2 plugin comes from Docker's repo:
   ```bash
   sudo apt-get update && sudo apt-get install -y ca-certificates curl
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
     | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
   sudo apt-get update
   sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   docker --version && docker compose version
   ```
   `/etc/docker/daemon.json`:
   `{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"5"},"live-restore":true}`.
   `live-restore` keeps containers running across daemon restarts and upgrades. Membership of the `docker` group is
   root-equivalent, so give it only to the admin user.
3. **ufw firewall**
   ```bash
   sudo ufw default deny incoming && sudo ufw default allow outgoing
   sudo ufw limit OpenSSH
   sudo ufw allow ${SSO_HTTPS_PORT}/tcp
   sudo ufw allow ${SSO_HTTP_PORT}/tcp        # only if SSO_HTTP_PORT is set (ACME HTTP-01 / redirect)
   sudo ufw enable && sudo ufw status verbose
   ```
   **Docker caveat (important):** ports that Docker publishes are opened by Docker's own iptables rules, which
   **bypass ufw's INPUT rules**. So `ports: "6379:6379"` would be reachable from the internet even with ufw set to
   deny. The mitigation is §15 R21: only nginx publishes ports, and anything else is bound to `127.0.0.1`. Optional
   extra filtering goes in the `DOCKER-USER` iptables chain. After go-live, verify from **outside** with
   `nmap -Pn -p 1-65535 <vps_ip>`.
   Outbound: the VPS must reach `<db_host>:3306` (and the DB firewall must allow `<sso_vps_ip>` only: Q5).
4. **Unattended upgrades**
   ```bash
   sudo apt-get install -y unattended-upgrades apt-listchanges
   sudo dpkg-reconfigure -plow unattended-upgrades      # enables /etc/apt/apt.conf.d/20auto-upgrades
   ```
   In `/etc/apt/apt.conf.d/50unattended-upgrades`: keep the default `${distro_id}:${distro_codename}-security`
   origin. Add `Unattended-Upgrade::Package-Blacklist { "docker-ce"; "docker-ce-cli"; "containerd.io"; };`
   so Docker is upgraded by hand in a maintenance window. Docker's repo isn't an allowed origin by default anyway;
   the blacklist makes that explicit. Set `Unattended-Upgrade::Automatic-Reboot "false";` and watch
   `/var/run/reboot-required` (alert in §9), **or** set `"true"` with
   `Automatic-Reboot-Time "04:30"` if a short nightly blip is acceptable (Q13). Check with
   `sudo unattended-upgrade --dry-run --debug`.
5. **cron**: Ubuntu ships `cron` enabled (`systemctl status cron`). SSO jobs go in `/etc/cron.d/` files (§10), which
   take a user field. Not in a personal crontab.
6. **Layout**: `/opt/sso/` (compose file, `.env`, `keys/`, `certs/`, `DEPLOYED`), owned by root, mode 0750.
   `/var/log/sso-cron.log` with a logrotate entry.
7. **Optional**: `unattended-upgrades` covers the OS. Images are patched by rebuilding/pulling pinned tags and
   redeploying (§7), at least monthly and on critical CVEs (Trivy, §8).

### 3.1 Compose topology (Developer implements; §15)
Services: `web`, `nginx`, `redis` (redis satisfies addendum B.3, §5). One-offs (`migrate`, `createsuperuser`,
`create_service_client`) and cron reuse `web` via `docker compose run --rm` / `exec -T`.
nginx publishes `"${SSO_HTTPS_PORT:-443}:443"` and `"${SSO_HTTP_PORT:-80}:80"`. The container ports stay fixed.
**[ASSUMPTION]** The VPS has no other web server on these ports. If myFinance's nginx is on the same VPS (Q2),
SSO becomes a `server` block in that nginx instead, proxying to `127.0.0.1:8001`. §3.3 still applies.

### 3.2 TLS certificate source (pick one; Q4)
| Option | Works when | Notes |
|---|---|---|
| **A. Let's Encrypt HTTP-01 (certbot webroot)**, default | `SSO_HTTP_PORT=80` and port 80 reachable from the internet | Free. Shared webroot volume for `/.well-known/acme-challenge/`. Renewal via certbot's systemd timer (Ubuntu package `certbot`) with deploy hook `docker compose -f /opt/sso/docker-compose.yml exec -T nginx nginx -s reload`. |
| B. Let's Encrypt DNS-01 | Any port; needed if `SSO_HTTP_PORT` ≠ 80. Also wildcards. | Needs a DNS-provider API token, stored like §4. |
| C. Existing cert covering `${SSO_HOSTNAME}` (e.g. a wildcard for `${SSO_DOMAIN}`) | One already exists | Renewal tied to its owner's process. |
| D. CDN (e.g. Cloudflare) origin cert + proxy | Domain is behind a CDN | No caching of `/api/*`. The real client IP header changes, so `SSO_NUM_PROXIES` changes (§5). |
| Self-signed | local/QA only | addendum C |

Certs are mounted read-only into nginx, never baked into an image.

### 3.3 nginx behaviour (required)
- Use nginx's official image templating (`/etc/nginx/templates/*.template`, rendered with envsubst at container
  start) so `SSO_HOSTNAME` / `SSO_HTTPS_PORT` come from env and aren't hard-coded.
- `:80`: serves the ACME challenge, everything else gets
  `301 https://${SSO_HOSTNAME}[:${SSO_HTTPS_PORT}]$request_uri`. Include the port when it isn't 443.
- `:443 ssl`: TLS 1.2 + 1.3 only, `server_name ${SSO_HOSTNAME}`, default server returns 444 for unknown Host,
  `server_tokens off`. HSTS is sent by Django (`SSO_HSTS_SECONDS`, default 1 year with includeSubDomains). Don't
  duplicate it in nginx. Use a short value on staging, and note that `includeSubDomains` affects all of
  `${SSO_HOSTNAME}`'s subdomains.
- Headers: `proxy_set_header Host $http_host; X-Forwarded-Proto $scheme;` and
  `X-Forwarded-For $remote_addr;`. The latter **overwrites** the header so clients can't spoof the throttle IP.
  This matches `SSO_NUM_PROXIES=1` (§5).
- `client_max_body_size 64k`, `proxy_read_timeout 30s`.
- Logs: default `combined` format. Never log `$http_authorization`, `$http_cookie` or `$request_body` (spec §9.6).
- Admin lives at `/${SSO_ADMIN_PATH}` (code default `sso-admin/`). Optional IP allowlist for that location (Q12).
- Optional `limit_req` on `/api/v1/auth/login` as defence in depth. The authoritative limits stay in DRF.
- Don't override Django's `Cache-Control` on `/.well-known/jwks.json` (`public, max-age=3600`, spec §6.7).

## 4. Secrets and signing private-key handling

### 4.1 Inventory
| Secret | Location on the VPS | Consumed as |
|---|---|---|
| `SSO_SECRET_KEY` (50+ random chars, unique per env, not myFinance's: spec §4.8) | `/opt/sso/.env` | env |
| `SSO_DBUSER`/`SSO_DBPWD` (`sso_app`) | `/opt/sso/.env` | env |
| `sso_migrator` password | `/opt/sso/migrate.env`, present **only during a migration window** | env for one-off `run` |
| MySQL server CA cert (if verifying DB TLS, §6.0) | `/opt/sso/mysql-ca/ca.pem` (not secret, but integrity matters) | file mount |
| JWT private key(s) | `/opt/sso/keys/*.private.pem` | `/run/keys:ro` |
| JWT public key(s) | `/opt/sso/keys/*.public.pem` | `/run/keys:ro` |
| TLS key | `/etc/letsencrypt/` or `/opt/sso/certs/` | nginx mount `:ro` |
| Redis password (optional) | `/opt/sso/.env` | in `SSO_CACHE_URL` |
| `ServiceClient` secrets | Created via admin or `manage.py create_service_client`. The DB stores only the hash. Plaintext goes once to the owner via the password manager. | n/a |
| `EMAIL_*` (phase 5) | `/opt/sso/.env` | env |

The master copy of secrets lives in Thomas's password manager **[ASSUMPTION; Q10]**. CI holds no runtime secrets.

### 4.2 Rules
1. **Never in git, never in the image.** `.gitignore` / `.dockerignore` exclude `keys/`, `*.pem`, `.env*` (except
   `.env.example`), `*.sql`, `*.sql.gz`. CI enforces this (§8).
2. Permissions on the VPS:
   ```bash
   sudo install -d -m 0700 -o 10001 -g 10001 /opt/sso/keys        # 10001 = container uid (§15 R2)
   sudo chmod 0600 /opt/sso/keys/*.private.pem && sudo chmod 0644 /opt/sso/keys/*.public.pem
   sudo chown 10001:10001 /opt/sso/keys/*.pem
   sudo chown root:root /opt/sso/.env && sudo chmod 0600 /opt/sso/.env
   ```
   `.env` is read by compose as root. The keys are opened by the app (uid 10001) at start-up.
3. Keys are mounted **read-only** at `/run/keys` (spec §9.5).
4. Generate keys **on the VPS**, never in CI. RSA 3072 recommended (spec allows 2048/3072; Q10). Name them by month:
   ```bash
   umask 077
   openssl genrsa -out /opt/sso/keys/sso-2026-10.private.pem 3072
   openssl rsa -in /opt/sso/keys/sso-2026-10.private.pem -pubout -out /opt/sso/keys/sso-2026-10.public.pem
   ```
5. Private-key backup: recommend **none**. Losing the key means everyone logs in again (§11.3). If Thomas wants a
   backup, keep only an encrypted copy in the password manager (Q10).
6. The app refuses to start in non-debug mode when `SSO_SECRET_KEY`, `SSO_ISSUER` or the key files are missing
   (implemented in `ssoproject/settings.py`, addendum B.12).
7. Don't print secrets: use `docker compose config --quiet` to validate, not plain `config`.

## 5. Shared cache for throttling
- **Why:** DRF throttle counters live in Django's cache. LocMem is per gunicorn worker, so with 3 workers the
  `login 10/min` limit becomes about 30/min (addendum B.3).
- **Decision:** a Redis (or Valkey: Q14) compose service. `SSO_CACHE_URL=redis://redis:6379/0` (or
  `redis://:${SSO_REDIS_PASSWORD}@redis:6379/0`). The code already reads it via `env.cache_url` with
  `KEY_PREFIX="sso"`, and `redis` is in `requirements.txt`.
- Redis config: pinned image, no published port, internal network,
  `--save "" --appendonly no --maxmemory 64mb --maxmemory-policy allkeys-lru`. Licence note: Redis ≥ 7.4 is
  RSAL/SSPL (8.x adds AGPL). Valkey 8 is a BSD drop-in.
- If Redis is down, login fails with 500 (fail closed). That's the recommended behaviour, plus an alert and a
  compose healthcheck (Q16).
- The DB cache was rejected: it would add an unmanaged table and write load to the shared `dcWebUsers`.
- **Client IP:** `SSO_NUM_PROXIES=1` (code default) together with nginx overwriting `X-Forwarded-For` (§3.3). If a
  CDN is added, increase it.

## 6. Remote MySQL 8.4 `dcWebUsers` prerequisites
Thomas 2026-10-10: production MySQL is moving to **8.4**, and the target is **Django 5.2 only**. Django 5.2
supports MySQL ≥ 8.0.11, so 8.4 is within range. All SQL here is run **by Thomas or the DBA with the MySQL admin
account**. DevOps has not connected.

### 6.0 MySQL 8.4 considerations (factual; verify on the real server)
- **Authentication plugins.** `caching_sha2_password` is the default (since 8.0). In 8.4,
  **`mysql_native_password` is deprecated and disabled by default**. Accounts that use it can't log in unless the
  server is started with `--mysql-native-password=ON`, and it is removed entirely in 9.0. The
  `default_authentication_plugin` variable is **removed** in 8.4; `authentication_policy` replaces it.
  → Create the SSO accounts with `caching_sha2_password` (§6.2). Don't ask for native-password to be re-enabled.
- **Client library.** `mysqlclient` links against the C client library in the image. On Debian-based
  `python:3.12-slim`, `default-libmysqlclient-dev` resolves to **MariaDB Connector/C** (on Ubuntu it is Oracle's
  libmysqlclient). Both ship a `caching_sha2_password` client plugin in current versions, but this is **verified, not
  assumed**: CI logs in **from inside the built image** to a `mysql:8.4` service with a `caching_sha2_password` user
  (§8, image job), and local/QA does the same (§2.1). If the plugin is missing in the runtime stage, the Dockerfile
  must install the package that provides it (§15 R1).
- **caching_sha2_password and TLS.** For an account that is not yet in the server's auth cache (for example after a
  server restart), the full authentication over TCP needs either a **TLS connection** or RSA key exchange.
  Connecting over TLS (below) avoids the RSA path entirely. That's another reason to use TLS.
- **Server TLS.** MySQL 8.x supports TLSv1.2 and TLSv1.3 only. If the DBA configures no certificates, the server
  auto-generates **self-signed** ones at data-directory initialization. Clients connect with "preferred" TLS by default:
  encrypted, but **the server certificate is not verified**. For verification (VERIFY_CA / VERIFY_IDENTITY), the
  DBA must provide the CA certificate, and the SSO DB connection must pass it. That needs a small settings addition,
  for example `SSO_DB_SSL_CA` → `DATABASES.OPTIONS["ssl"] = {"ca": …}` (proposed; not in code yet, §15 R28). The SSO
  accounts also get `REQUIRE SSL` (§6.2), so an unencrypted connection is refused server-side.
  `require_secure_transport=ON` on the server is a DBA choice, and it would also affect myFinance (Q5).
- **Foreign keys.** 8.4 adds `restrict_fk_on_non_standard_key=ON` by default, which forbids FKs referencing
  non-unique keys. Django FKs (`token_blacklist_*` → `auth_user.id`, `sso_*` → `auth_user.id`) reference primary
  keys, so this is not a problem.
- **Defaults.** Charset `utf8mb4`, collation `utf8mb4_0900_ai_ci`. New SSO tables take the schema's default
  charset. The connection uses `charset=utf8mb4` (code).
- **Client tools.** Ubuntu 24.04's `mysql-client` package is 8.0.x. Prefer the 8.4 client from the official image for
  dump/restore: `docker run --rm … mysql:8.4 mysqldump …` (§6.3).
- **myFinance impact (not SSO's change, but the same DB):** if myFinance's DB account still uses
  `mysql_native_password`, it **stops authenticating** after the move to 8.4. Its client library must also support
  `caching_sha2_password`. Check this with the query in §6.1 before the upgrade (Q21).

### 6.1 Version and compatibility check (expect 8.4.x)
```sql
SELECT VERSION();                         -- expect 8.4.x (8.4 LTS). Anything else: stop and re-check this plan.
SELECT @@version_comment;                 -- expect "MySQL Community Server - GPL" (or Enterprise)
SELECT @@authentication_policy;           -- 8.4 default '*,,' => caching_sha2_password for new accounts
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS
 WHERE PLUGIN_NAME IN ('caching_sha2_password','mysql_native_password');   -- native: absent/disabled on default 8.4
SELECT user, host, plugin FROM mysql.user WHERE user NOT LIKE 'mysql.%';    -- myFinance account must NOT be mysql_native_password
SELECT @@require_secure_transport, @@tls_version, @@ssl_ca, @@ssl_cert;     -- TLS posture
SHOW SESSION STATUS LIKE 'Ssl_version';                                      -- run from a TLS session: non-empty
SELECT @@character_set_server, @@collation_server, @@default_storage_engine, @@sql_mode, @@time_zone;
SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA
 WHERE SCHEMA_NAME = 'dcWebUsers';
SELECT TABLE_NAME, ENGINE, TABLE_COLLATION FROM information_schema.TABLES
 WHERE TABLE_SCHEMA = 'dcWebUsers' ORDER BY TABLE_NAME;                   -- all InnoDB
SELECT app, name FROM dcWebUsers.django_migrations
 WHERE app IN ('auth','contenttypes','admin','sessions') ORDER BY app, id; -- auth up to 0012 (spec §4.4)
SELECT app, COUNT(*) FROM dcWebUsers.django_migrations
 WHERE app IN ('sso','token_blacklist') GROUP BY app;                     -- expect no rows
SELECT COUNT(*) AS users, SUM(is_active) AS active FROM dcWebUsers.auth_user;  -- baseline (Request #2)
```
Go/no-go: the version is 8.4.x, every table is InnoDB, the SSO apps aren't present yet, and the myFinance account
isn't on `mysql_native_password`. If MySQL is still mid-upgrade, the SSO go-live waits for 8.4 to be in place
(gate G2, §12).

### 6.2 Dedicated DB accounts (least privilege; spec §4.9)
Two accounts, so runtime credentials never hold DDL. Both use `caching_sha2_password` with TLS required.
```sql
-- Runtime account (in /opt/sso/.env)
CREATE USER 'sso_app'@'<sso_vps_ip>'
  IDENTIFIED WITH caching_sha2_password BY '<generated-32+char-password>'
  REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON dcWebUsers.* TO 'sso_app'@'<sso_vps_ip>';

-- Migration account (one-off migrate runs only; locked otherwise)
CREATE USER 'sso_migrator'@'<sso_vps_ip>'
  IDENTIFIED WITH caching_sha2_password BY '<generated-32+char-password>'
  REQUIRE SSL ACCOUNT LOCK;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
  ON dcWebUsers.* TO 'sso_migrator'@'<sso_vps_ip>';
-- DROP only temporarily, for a migration rollback (§13.3):
--   GRANT DROP ON dcWebUsers.* TO 'sso_migrator'@'<sso_vps_ip>'; … REVOKE DROP ON dcWebUsers.* FROM 'sso_migrator'@'<sso_vps_ip>';

-- Migration window
ALTER USER 'sso_migrator'@'<sso_vps_ip>' ACCOUNT UNLOCK;
--   … §12 P6 …
ALTER USER 'sso_migrator'@'<sso_vps_ip>' ACCOUNT LOCK;

SHOW GRANTS FOR 'sso_app'@'<sso_vps_ip>';
SHOW GRANTS FOR 'sso_migrator'@'<sso_vps_ip>';
SELECT user, host, plugin, ssl_type, account_locked FROM mysql.user WHERE user LIKE 'sso\_%';
```
- Never use `'%'` in prod. `<sso_vps_ip>` is the VPS egress IP (Q5).
- Runtime needs `UPDATE auth_user` (for `last_login` and the PBKDF2 re-hash, spec §4.3), DML on `token_blacklist_*` /
  `sso_*`, and `INSERT` on `django_admin_log` / `django_session`. The spec prescribes DB-wide DML; table-level grants
  are optional hardening (Q15).
- `migrate`'s post-migrate step inserts `django_content_type` / `auth_permission` rows for `sso` and
  `token_blacklist` into the shared tables. That's expected.
- Staging gets its own accounts (`sso_app_stg`, `sso_migrator_stg`) on its own schema.

### 6.3 Backup before the first migrate (spec §4.6, §9.5)
Use the **8.4 client** (via the official image) and a client options file, so the password never appears on the
command line:
```bash
# ~/.my-dcweb.cnf (chmod 600)
# [client]
# host=<db_host>
# port=3306
# user=<admin_or_backup_user>
# password=<…>
# ssl-mode=VERIFY_IDENTITY        # or REQUIRED if no CA is available (Q5)
# ssl-ca=/cfg/ca.pem              # path inside the container below

TS=$(date +%Y%m%dT%H%M%S)
docker run --rm -i --network host \
  -v ~/.my-dcweb.cnf:/cfg/my.cnf:ro -v ~/mysql-ca/ca.pem:/cfg/ca.pem:ro \
  mysql:8.4 mysqldump --defaults-extra-file=/cfg/my.cnf \
    --single-transaction --quick --routines --triggers --events --hex-blob \
    --no-tablespaces --set-gtid-purged=OFF --default-character-set=utf8mb4 \
    dcWebUsers | gzip -9 > dcWebUsers-pre-sso-$TS.sql.gz
# (If the native 8.4 client is installed: the same mysqldump flags with --defaults-extra-file=~/.my-dcweb.cnf.)

gzip -t dcWebUsers-pre-sso-$TS.sql.gz
zcat dcWebUsers-pre-sso-$TS.sql.gz | tail -n 1                          # "-- Dump completed on …"
zcat dcWebUsers-pre-sso-$TS.sql.gz | grep -c 'INSERT INTO `auth_user`'  # > 0
sha256sum dcWebUsers-pre-sso-$TS.sql.gz > dcWebUsers-pre-sso-$TS.sql.gz.sha256
chmod 600 dcWebUsers-pre-sso-$TS.sql.gz*
```
- The dump holds every password hash and email. Encrypt it (`gpg --symmetric` / `age`), store it off-host, and keep
  it at least 30 days after go-live (Q6).
- A backup user, if not the admin: `SELECT, LOCK TABLES, SHOW VIEW, TRIGGER, EVENT` (`--no-tablespaces` avoids
  `PROCESS`).
- **The same command produces the staging copy** (pre-go-live, §12 G4). Restore it into the staging schema. That
  restore doubles as the restore test.

## 7. Release artefact and tagging
- Image `sso-server`: `sha-<12 hex>` per main build, `vMAJOR.MINOR.PATCH` per git tag. Deploys use the immutable
  `SSO_IMAGE_TAG` and **never `latest`**. Record tag + digest in `/opt/sso/DEPLOYED`.
- Registry TBD (Q8). There's no push until Thomas approves and a GitHub login exists (addendum D). Interim: build on
  the VPS from a tagged checkout.
- Django 5.2 only: `requirements-django42.txt` is no longer needed (Developer may delete it, §15 R9).

## 8. CI pipeline (draft: `devops/ci/pipeline.yml`)
**[ASSUMPTION]** GitHub Actions. The file is stored under `devops/ci/` and **inactive** until it's moved to
`.github/workflows/` after approval.
1. **lint**: ruff check + format, gitleaks, "no key/env/dump files tracked".
2. **unit** (SQLite, Django 5.2 only): `makemigrations --check --dry-run` (addendum B.11), `pytest` with
   `--cov-fail-under=90` (addendum C). `settings_test.py` generates its own throw-away keys.
3. **integration-mysql**: `mysql:8.4` service with default auth (`caching_sha2_password`). Asserts the plugin, then
   migrates the Django built-ins and checks `migrate --plan` lists only `sso`/`token_blacklist`. Then `migrate` and
   pytest with `SSO_DB_ENGINE=mysql`.
4. **deploy-check**: `manage.py check --deploy --fail-level WARNING` with prod-like env, `pip-audit`.
5. **image**: build; non-root uid 10001; no secrets in the image. Then **DB login from inside the image** to a
   `mysql:8.4` service as a `caching_sha2_password` user (proves the runtime client library, §6.0), `migrate`,
   `/healthz` = 200 with a `Host` header, and a Trivy scan.
6. **publish**: commented out until a registry is approved. No CD: deploys are manual (§12).

## 9. Monitoring, `/healthz` and alerting
### 9.1 `/healthz`
Implemented in `sso/views.py`: a DB round-trip returns `200 {"status":"ok"}` (`Cache-Control: no-store`). A DB
failure returns `503 {"error":"unhealthy","detail":"database"}` and logs the error without details. It's exempt
from the SSL redirect (`SECURE_REDIRECT_EXEMPT`), but it still needs a `Host` that's in `SSO_ALLOWED_HOSTS`.
Not yet decided: also checking Redis and keys (Q16).

### 9.2 What to watch
| Check | How | Alert when |
|---|---|---|
| Uptime | External check of `${SSO_ISSUER}/healthz` every 1 min (tool TBD, Q9; free/self-hosted, no spend without approval) | 2 consecutive failures |
| JWKS | `${SSO_ISSUER}/.well-known/jwks.json` has ≥ 1 key incl. the current signing `kid` | missing |
| TLS expiry | cert check on `${SSO_HOSTNAME}:${SSO_HTTPS_PORT}` | < 21 days |
| Containers | docker health status | `unhealthy` > 5 min |
| 5xx rate | nginx access log | > 1 % / 5 min |
| Login abuse | `sso.auth` structured log: failures, 429s per IP/user | spike (e.g. > 50 failures / 5 min) |
| Redis | compose healthcheck | unhealthy |
| Cron | `flushexpiredtokens` heartbeat | missed run (26 h) |
| DB growth | weekly `SELECT COUNT(*) FROM token_blacklist_outstandingtoken` | unexpected growth |
| VPS | disk, memory, `/var/run/reboot-required` present > 7 days, unattended-upgrades failures (`/var/log/unattended-upgrades/`) | disk > 80 % / pending reboot |
| DB TLS cert | expiry of the MySQL server cert (if a CA-issued one is used) | < 21 days |

Logs: stdout → docker json-file with rotation (daemon.json, §3.0). Never tokens or passwords. Shipping destination
TBD (Q19). Alert channel TBD (Q9).

## 10. `flushexpiredtokens` cron (spec §9.6)
- Deletes expired `OutstandingToken` rows (and their `BlacklistedToken` rows by cascade). It works with `sso_app`
  (DML) credentials.
- Daily at 03:30 VPS-local time (Q18). Ubuntu cron file:
  ```cron
  # /etc/cron.d/sso-flushexpiredtokens   (cron does not read /opt/sso/.env)
  SHELL=/bin/bash
  SSO_CRON_HEARTBEAT_URL=
  30 3 * * * root cd /opt/sso && docker compose exec -T web python manage.py flushexpiredtokens >> /var/log/sso-cron.log 2>&1 && { [ -z "$SSO_CRON_HEARTBEAT_URL" ] || curl -fsS -m 10 "$SSO_CRON_HEARTBEAT_URL" >/dev/null; }
  ```
  `-T` is needed without a TTY. Add a logrotate entry for `/var/log/sso-cron.log`.
- Alternative: a `supercronic` sidecar container, if host cron is off-limits.
- **Never** schedule `clearsessions` or `remove_stale_contenttypes` from SSO. Those tables are shared with
  myFinance (addendum B.11).

## 11. Signing-key rotation runbook (spec §5.3, addendum B.6)
`SSO_JWT_PRIVATE_KEY_PATH` is the signing key. `SSO_JWT_PUBLIC_KEY_PATHS` is a comma-separated list of every
published key; JWKS lists them all. `kid` = first 16 hex chars of SHA-256 over the DER SubjectPublicKeyInfo
(`sso/keys.py::compute_kid`).
**Prerequisite met in code:** `sso/tokens.py` picks the verifying key by `kid` across all published keys. That means
refresh tokens signed with the old key still work after the switch. Rehearse once on staging before the first prod
rotation (gate G6). Cadence: yearly, and on compromise **[ASSUMPTION; Q10]**.

### 11.1 Timeline
| T | Step | JWKS | Signs with |
|---|---|---|---|
| T0 | publish new public key | old + new | old |
| T0 + ≥ 24 h | switch signing | old + new | new |
| switch + 8 days (15 min + 7 d refresh + margin) | remove old public key | new | new |

The 24 h exceeds the JWKS `max-age=3600` and the services' 1 h cache (spec §6.7/§8.1). Recompute the 8 days if the TTLs
change.

### 11.2 Steps (example: old `sso-2026-10`, new `sso-2027-10`)
1. Pre-check: `curl -s ${SSO_ISSUER}/.well-known/jwks.json | jq '.keys[].kid'` shows one kid (OLD_KID). Record
   `SSO_IMAGE_TAG`. Monitoring is green.
2. Generate the pair on the VPS (§4.2), fix ownership/permissions, compute NEW_KID:
   `openssl pkey -pubin -in /opt/sso/keys/sso-2027-10.public.pem -outform DER | sha256sum | cut -c1-16`.
3. T0: set `SSO_JWT_PUBLIC_KEY_PATHS=/run/keys/sso-2026-10.public.pem,/run/keys/sso-2027-10.public.pem` (signing
   unchanged), then `docker compose up -d --force-recreate web`.
4. Verify: JWKS lists OLD_KID + NEW_KID, a new login token still has `kid=OLD_KID`, and `/healthz` returns 200.
   Notify service owners.
5. Wait ≥ 24 h.
6. Switch: set `SSO_JWT_PRIVATE_KEY_PATH=/run/keys/sso-2027-10.private.pem`, then recreate `web`.
7. Verify: a new token has `kid=NEW_KID` and verifies with `examples/verifier`. A refresh token from before step 6
   still refreshes. Watch service 401s for 1 h.
8. Wait 8 days.
9. Retire: set `SSO_JWT_PUBLIC_KEY_PATHS=/run/keys/sso-2027-10.public.pem`, recreate `web`, and confirm JWKS shows
   NEW_KID only.
10. `shred -u /opt/sso/keys/sso-2026-10.private.pem`. Log the date, kids and operator.
Rollback before step 9: revert the `.env` line(s) and recreate. Both keys are still published, so nothing breaks.

### 11.3 Emergency rotation (compromise)
1. Generate a new key. Set **only** the new key in both env vars and recreate `web`. Every user has to log in again.
2. Services may keep the old key cached for up to 1 h. Tell their owners to restart them or flush the JWKS cache.
3. Optionally blacklist all outstanding refresh tokens and set `UserTokenRevocation` (introspect then reports old
   tokens inactive).
4. Investigate. If the VPS was compromised, also rotate `SSO_SECRET_KEY` and the DB passwords.

## 12. Rollout steps

### 12.1 Pre-go-live checklist (gates)
- [ ] **G1 Parameters decided** (§0): `SSO_DOMAIN`, `SSO_HOSTNAME`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`, staging
      hostname. That fixes the cert option (§3.2) and the issuer.
- [ ] **G2 MySQL 8.4 live** for `dcWebUsers`, with §6.1 output saved (8.4.x, InnoDB, myFinance account not on native
      password).
- [ ] **G3 Sprint-1 DoD met** (addendum C), including the QA suite green against **local `mysql:8.4` + synthetic users**
      (§2.1). The image is built by CI or on the VPS at a tag.
- [ ] **G4 Staging copy of `dcWebUsers`**: fresh dump (§6.3) restored into a separate staging schema on 8.4, using
      staging accounts. This is the pre-go-live step Thomas asked for.
- [ ] **G5 Full rehearsal of P1–P10 on staging** against that copy. It must show that only `sso`/`token_blacklist`
      migrations apply and that real legacy hashes log in. Also test myFinance-style login against the staging copy
      if feasible.
- [ ] **G6 Rotation rehearsal** (§11) on staging with shortened TTLs.
- [ ] **G7 Decisions**: cert source, monitoring tool and alert channel, DB TLS/CA (Q4, Q5, Q9).

### 12.2 Production
- **P1 VPS baseline** per §3.0 (Docker, ufw, unattended-upgrades, cron, time sync). Create `/opt/sso` and fill `.env`
  from `.env.example` with the §0 derived values.
- **P2 DNS + TLS**: A/AAAA record for `${SSO_HOSTNAME}` → VPS. Obtain the cert (§3.2). Check with
  `openssl s_client -connect ${SSO_HOSTNAME}:${SSO_HTTPS_PORT} -servername ${SSO_HOSTNAME}`.
- **P3 Keys** (§4.2).
- **P4 DB accounts**: run §6.1 and save the output, create the accounts (§6.2), then check connectivity from the VPS:
  `docker compose run --rm web python manage.py check --database default`.
  This also proves `caching_sha2_password` + TLS from the image.
- **P5 Backup** (§6.3), verify and encrypt it. Record the `auth_user` count baseline.
- **P6 Migrate** (operator-run):
  ```bash
  cd /opt/sso
  # DBA: ALTER USER 'sso_migrator'@'<sso_vps_ip>' ACCOUNT UNLOCK;
  set -a; . ./migrate.env; set +a                 # SSO_DBUSER=sso_migrator SSO_DBPWD=…
  docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python manage.py showmigrations
  docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python manage.py migrate --plan
  #   STOP unless the plan lists ONLY `sso` and `token_blacklist`
  docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python manage.py migrate
  unset SSO_DBUSER SSO_DBPWD; shred -u migrate.env
  # DBA: ALTER USER 'sso_migrator'@'<sso_vps_ip>' ACCOUNT LOCK;
  ```
- **P7 Start**: `docker compose up -d`. All services healthy.
- **P8 Smoke tests** (spec §11), all against `${SSO_ISSUER}`:
  - `/healthz` returns 200. JWKS has one key with the expected kid.
  - Discovery: `token_endpoint` = `/api/v1/auth/login`, with no `authorization_endpoint` (addendum B.2).
  - Native login → `/me` → `/refresh` (reusing the old refresh token is rejected) → `/logout`.
  - A wrong password returns `401 invalid_credentials`. The 11th rapid login per IP returns `429` + `Retry-After`.
  - `examples/verifier` accepts the access token.
  - **Log in to myFinance with the same account.** The `auth_user` count still equals the baseline.
- **P9 Configure**: `createsuperuser` only if needed. Register `ServiceClient`s (admin at `/${SSO_ADMIN_PATH}` or
  `manage.py create_service_client`). Set the real `SSO_CORS_ALLOWED_ORIGINS` and recreate `web`.
- **P10 Operate**: install the cron (§10), enable monitors (§9), write `DEPLOYED`, publish
  `SSO_ISSUER`/`SSO_JWKS_URL` to service developers. Drop or retain the staging copy as decided (Q6).

Later releases: tag → local/QA → staging → backup if there are migrations → `migrate --plan` review → migrate →
`SSO_IMAGE_TAG=<new>` + `docker compose up -d` → P8 subset. Migrations must be backward-compatible with the previous
image (expand-only). With a single `web` container, `up -d` causes a few seconds of 502s (Q13).

## 13. Rollback steps (use the lowest level that works)
### 13.1 Level 1: previous image (no DB change)
```bash
cd /opt/sso && sed -i 's/^SSO_IMAGE_TAG=.*/SSO_IMAGE_TAG=<previous tag from DEPLOYED>/' .env && docker compose up -d
```
Then run the P8 smoke tests. This is safe because migrations are backward-compatible. Keys and tokens are unchanged.

### 13.2 Level 2: SSO offline, DB untouched
`docker compose down` (or an nginx maintenance page). The `sso_*` / `token_blacklist_*` tables are additive and
ignored by myFinance. Passwords re-hashed by Django 5.2 (more PBKDF2 iterations) still verify in Django 4.1
(spec §4.3).

### 13.3 Level 3: remove SSO's schema changes surgically (preferred over a restore)
Take a fresh dump first (§6.3, new name). Then either:
- temporarily `GRANT DROP` to `sso_migrator`, run `docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python
  manage.py migrate sso zero` and `… migrate token_blacklist zero`, then revoke DROP and lock the account; or
- use the DBA SQL fallback below. Verify the names with `SHOW TABLES LIKE 'sso\_%'` / `'token\_blacklist\_%'` first:
  ```sql
  DROP TABLE IF EXISTS token_blacklist_blacklistedtoken;      -- FK to outstandingtoken: first
  DROP TABLE IF EXISTS token_blacklist_outstandingtoken;
  DROP TABLE IF EXISTS sso_authorizationcode, sso_usertokenrevocation, sso_serviceclient;
  DELETE FROM django_migrations WHERE app IN ('sso','token_blacklist');
  -- optional clean-up of post_migrate rows in shared tables (FK order):
  DELETE FROM auth_user_user_permissions WHERE permission_id IN (SELECT id FROM auth_permission WHERE content_type_id IN (SELECT id FROM django_content_type WHERE app_label IN ('sso','token_blacklist')));
  DELETE FROM auth_group_permissions     WHERE permission_id IN (SELECT id FROM auth_permission WHERE content_type_id IN (SELECT id FROM django_content_type WHERE app_label IN ('sso','token_blacklist')));
  DELETE FROM auth_permission  WHERE content_type_id IN (SELECT id FROM django_content_type WHERE app_label IN ('sso','token_blacklist'));
  DELETE FROM django_admin_log WHERE content_type_id IN (SELECT id FROM django_content_type WHERE app_label IN ('sso','token_blacklist'));
  DELETE FROM django_content_type WHERE app_label IN ('sso','token_blacklist');
  ```
  (Check the real table list against `sso/migrations/0001_initial.py`. A migration that the DB doesn't know about
  needs no SQL.)

### 13.4 Level 4: full restore from the pre-SSO dump (disaster only)
This **discards every myFinance change since the dump**. It needs Thomas's explicit approval, with myFinance
stopped.
```bash
# 1. stop SSO + myFinance   2. dump the current state for forensics (§6.3, new name)
sha256sum -c dcWebUsers-pre-sso-<TS>.sql.gz.sha256
zcat dcWebUsers-pre-sso-<TS>.sql.gz | docker run --rm -i --network host \
  -v ~/.my-dcweb.cnf:/cfg/my.cnf:ro -v ~/mysql-ca/ca.pem:/cfg/ca.pem:ro \
  mysql:8.4 mysql --defaults-extra-file=/cfg/my.cnf dcWebUsers
# 3. SELECT COUNT(*) FROM auth_user == P5 baseline; log in to myFinance
```
The dump has no `CREATE DATABASE`, so tables created after the dump (SSO's) remain. Drop them as in §13.3.

### 13.5 Keys on rollback
An image rollback doesn't touch keys. The code reads `SSO_JWT_PUBLIC_KEY_PATHS` and falls back to the singular
`SSO_JWT_PUBLIC_KEY_PATH`, so images from this sprint onward are interchangeable.

## 14. Security checklist mapping (spec §9.6)
| Spec item | Where handled |
|---|---|
| HTTPS everywhere | §3.3, Django `SECURE_SSL_REDIRECT`/HSTS, secure cookies; DB over TLS (§6.0) |
| RS256 only / short TTL / rotation + blacklist | code + CI tests; P8 |
| Login throttling | §5 (Redis, `SSO_NUM_PROXIES`); P8 429 test |
| Never log tokens/passwords | §3.3, §9.2 |
| Private key 600, outside git | §4.2 |
| Admin at non-default path | `SSO_ADMIN_PATH` (code default `sso-admin/`) |
| `flushexpiredtokens` daily | §10 |
| Host | §3.0 (ufw + Docker caveat, SSH keys only, unattended security upgrades) |

## 15. Requirements for the Developer's Dockerfile / compose / nginx files
"Must" items block deployment. "Done in code" marks what's already met in the repo as of 2026-10-10.

**Dockerfile**
- R1. **Must**: `python:3.12-slim` (pinned), multi-stage. The builder has `build-essential pkg-config
  default-libmysqlclient-dev`. The runtime stage has only the runtime client library, **including its
  `caching_sha2_password` client plugin** (§6.0; the CI image job proves it), and no compilers.
- R2. **Must**: run as a non-root user with **fixed uid/gid 10001**.
- R3. **Must not** contain keys, `.env`, certs or dumps. `.dockerignore` excludes `keys/ *.pem .env* *.sql* .git
  .venv qa/ examples/`.
- R4. **Must**: `collectstatic` at build. WhiteNoise is already in the middleware (done in code).
- R5. **Must**: gunicorn `0.0.0.0:8000`, `--workers ${GUNICORN_WORKERS:-3}`, `--timeout 30`,
  `--worker-tmp-dir /dev/shm`, `--access-logfile -`, `--forwarded-allow-ips '*'` (safe only because `web` isn't
  published).
- R6. **Must not** run `migrate`, `createsuperuser`, `clearsessions`, `remove_stale_contenttypes` or
  `flushexpiredtokens` in the entrypoint.
- R7. **Must**: a healthcheck on `http://127.0.0.1:8000/healthz` with `Host: <first SSO_ALLOWED_HOSTS entry>`
  (`/healthz` is already exempt from the SSL redirect). Python one-liner. Interval 30 s, timeout 5 s, retries 3,
  start_period 20 s.
- R8. Should run with a `read_only: true` root filesystem plus `tmpfs: /tmp`.
- R9. Should pin requirements exactly or by hash. **Django 5.2 only**: drop `requirements-django42.txt` and the
  "fallback" comment in `requirements.txt` (Thomas 2026-10-10).

**Settings / app behaviour**
- R10. Env vars documented in `.env.example`, using the §0 parameters as placeholders (no `thomas-choi.com` literal):
  `SSO_SECRET_KEY, SSO_DEBUG, SSO_ALLOWED_HOSTS, SSO_CSRF_TRUSTED_ORIGINS, SSO_DB_ENGINE, SSO_DBNAME, SSO_DBHOST,
  SSO_DBPORT, SSO_DBUSER, SSO_DBPWD, SSO_ISSUER, SSO_AUDIENCE, SSO_JWT_PRIVATE_KEY_PATH, SSO_JWT_PUBLIC_KEY_PATHS,
  SSO_ACCESS_TTL_MIN, SSO_REFRESH_TTL_DAYS, SSO_CORS_ALLOWED_ORIGINS, SSO_COOKIE_DOMAIN, SSO_CACHE_URL, SSO_NUM_PROXIES,
  SSO_ADMIN_PATH`, plus compose-only `SSO_HOSTNAME, SSO_DOMAIN, SSO_HTTPS_PORT, SSO_HTTP_PORT, SSO_IMAGE_TAG,
  GUNICORN_WORKERS`. (QA's `qa/tests/conftest.py` still defaults `SSO_ALLOWED_ORIGIN` to a `thomas-choi.com`
  origin; QA should parameterize it too.)
- R11. `SSO_NUM_PROXIES=1`: done in code.
- R12. Cache from `SSO_CACHE_URL` with `KEY_PREFIX` `sso`: done in code.
- R13. Fail-fast on a missing secret, issuer or keys: done in code. `check --deploy` must pass (CI).
- R14. Kid-based multi-key verification: done in code (`sso/tokens.py`). Keep the rotation test.
- R15. `/healthz` per §9.1: done in code.
- R16. Structured login log, no tokens/passwords: present in code (`sso/logs.py`). QA verifies.
- R17. `flushexpiredtokens` works with DML-only credentials (QA verifies with the `sso_app` account in §2.1).
- R28. **New (proposed):** optional DB TLS verification settings, e.g. `SSO_DB_SSL_CA` (and possibly
  `SSO_DB_SSL_MODE`) mapped into `DATABASES["default"]["OPTIONS"]["ssl"]`. Whether `ssl_mode` is honoured depends on
  the client library (§6.0), so the Developer should confirm with the runtime image. The key file goes in a read-only
  mount.

**docker-compose.yml (staging/prod)**
- R18. `web`, `nginx`, `redis`. **No DB service.** The `mysql:8.4` container lives only in `docker-compose.test.yml`.
- R19. `image: sso-server:${SSO_IMAGE_TAG:?set SSO_IMAGE_TAG}`, `env_file: .env`.
- R20. Volumes: `./keys:/run/keys:ro` (web), certs `:ro` + ACME webroot (nginx), optional `./mysql-ca:/run/mysql-ca:ro`
  (web).
- R21. **Only nginx publishes ports:** `"${SSO_HTTPS_PORT:-443}:443"` and `"${SSO_HTTP_PORT:-80}:80"`. No `ports:` on
  web or redis, because Docker-published ports bypass ufw (§3.0). For the shared-nginx variant, bind to
  `127.0.0.1` only.
- R22. `restart: unless-stopped`, `depends_on: condition: service_healthy`, healthchecks on all three services,
  json-file log rotation.
- R23. Redis per §5.
- R24. Dev/self-signed overrides go in an override file or profile, never in the prod file.

**docker-compose.test.yml (local/QA)**
- R29. `mysql:8.4` with default auth settings. `MYSQL_DATABASE=dcWebUsers`. An init script creates
  `sso_app`/`sso_migrator` with prod-equivalent grants. Passwords come from a git-ignored `.env.test`. No published
  port, or `127.0.0.1` only. Healthcheck with `mysqladmin ping`. Throw-away volume.
- R27. The synthetic seed (`qa/tests/fixtures/seed_test_data.py`) gets a hard guard (`SSO_ALLOW_SYNTHETIC_SEED=1` + local
  DB host). The documented order is: built-in migrations → seed → `migrate --plan` → `migrate` (§2.1).

**docker/nginx.conf (as a template)**
- R25. Everything in §3.3: env-templated `SSO_HOSTNAME`/port, 80 → https with the port, ACME location,
  TLS 1.2/1.3, `Host $http_host`, `X-Forwarded-Proto $scheme`, `X-Forwarded-For $remote_addr` (overwrite),
  `client_max_body_size`, no sensitive log fields, default server returns 444.

**scripts/gen_keys.sh**
- R26. `umask 077`, RSA 3072 (or a parameter), writes `<name>.private.pem`/`<name>.public.pem`, prints the kid using the
  same DER-SPKI method as `sso/keys.py`, and refuses to overwrite existing files.

## 16. Open questions
IDs are kept stable from v1.0. Resolved items are listed separately.

### 16.1 Open
2. **Same VPS as myFinance?** (Host *type* resolved, see below.) Is there an existing nginx on 80/443 on that VPS
   (§3.1)?
4. **TLS source:** LE HTTP-01 (needs `SSO_HTTP_PORT=80`), DNS-01, an existing cert, or a CDN? Depends on the §0
   parameters.
5. **DB network and TLS:** does the VPS reach MySQL over the public internet or a private network? `<sso_vps_ip>` for
   the grants? Will the DBA supply a CA-signed server cert, so connections can use VERIFY_IDENTITY rather than
   only-encrypted (§6.0)? Is `require_secure_transport` planned (it affects myFinance too)?
6. **DB admin and backups:** who runs the §6 SQL and the dumps? Where are dumps stored and for how long? Is there an
   ongoing `dcWebUsers` backup? Is the staging copy dropped after go-live?
8. **CI/registry:** GitHub Actions + GHCR assumed. When will the repo exist? Until then, build on the VPS?
9. **Monitoring tool and alert channel** (free/self-hosted; email to Thomas?).
10. **Keys:** RSA 3072 OK? Yearly rotation? No private-key backup? Password manager as master store?
12. **Admin path value** (code default `sso-admin/`). Should it be IP-allowlisted at nginx?
13. **Downtime tolerance:** are short 502s acceptable on deploys, rotations and (if enabled) unattended reboots?
    Otherwise use 2 web replicas.
14. **Redis vs Valkey**, and should it have a password?
15. **Two-account DB model** OK vs spec §4.9's single account? Table-level grants?
16. **`/healthz` depth** (Redis/keys)? Fail closed when Redis is down (plan) or fail open?
17. **myFinance side effects:** does it run `clearsessions` / `remove_stale_contenttypes` crons? Is the CPU cost of the
    PBKDF2 re-hash OK?
18. **Cron timing:** VPS timezone and quiet hour (plan: 03:30 local).
19. **Logs:** retention and destination?
20. **New: Ubuntu release** on the VPS (24.04 LTS assumed)? VPS provider and size? A separate VPS for staging, or
    staging on the prod VPS?
21. **New: MySQL 8.4 migration timing and myFinance compatibility.** When does `dcWebUsers` move to 8.4? Does
    myFinance's DB account use `mysql_native_password` (it would stop working on 8.4 by default)? Does its client
    library support `caching_sha2_password`? myFinance runs Django 4.1, whose official MySQL support predates 8.4.
    Has myFinance been tested on 8.4?
22. **New: parameters in §0** (`SSO_DOMAIN`, `SSO_HOSTNAME`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`, staging hostname).
    The decision is pending (see Q3 below). It's needed before gate G1.

### 16.2 Resolved
1. ~~MySQL version~~. **MySQL 8.4; Django 5.2 only.** The 4.2 fallback and CI matrix are dropped (Thomas 2026-10-10).
   The check SQL is in §6.1. 8.4 considerations are in §6.0.
2. (part) ~~Host type~~. **Docker on an Ubuntu VPS** (Thomas 2026-10-10). The concrete baseline is in §3.0. Still open:
   same VPS as myFinance (Q2 above) and Ubuntu release (Q20).
3. ~~Real hostname / DNS~~. **Parameterized, decision pending** (Thomas 2026-10-10). See §0 and Q22. Who manages DNS
   is still to be answered with that decision.
7. ~~Real data in staging~~. **Sprint-1 QA uses a local `mysql:8.4` container with synthetic users (§2.1). A staging
   copy of `dcWebUsers` is a pre-go-live step** (gate G4), protected like prod (Thomas 2026-10-10).
11. ~~Multi-key verification~~. **Implemented in `sso/tokens.py`**, with the singular-env fallback in settings. Only a
    staging rehearsal remains (G6).
