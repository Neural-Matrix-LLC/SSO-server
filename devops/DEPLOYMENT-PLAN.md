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
| v1.5 | 2026-10-11 | Key env vars updated to match branch `feat/app-permissions` (verified in `sso/keys.py`, `sso/checks.py`, `docker-compose.yml`). `SSO_KEYS_DIR` = host folder, mounted read-only at `/run/keys`. `SSO_JWT_PRIVATE_KEY` = signing-key **file name**. `SSO_JWT_PUBLIC_KEYS` = **comma-separated file names**. Names resolve in `SSO_JWT_KEYS_MOUNT` > `SSO_KEYS_DIR` > `/run/keys`, and compose pins `SSO_JWT_KEYS_MOUNT=/run/keys` for `web`. `SSO_JWT_PRIVATE_KEY_PATH` / `SSO_JWT_PUBLIC_KEY_PATHS` / `SSO_JWT_PUBLIC_KEY_PATH` are deprecated (still read, warning `sso.W001`; setting old + new together is fatal). Updated §1, §4, §11 rotation runbook (edit the file list / file name), §12 P3, §13.5 (rollback across the rename), R10, R20, R26 and the CI env. New §4.3 on the deprecated vars. |
| v1.4 | 2026-10-10 | Local/QA/CI MySQL default aligned to **`mysql:8.0`** (prod runs 8.0 today; 8.4 supported) through the Developer's `MYSQL_IMAGE` variable (falls back to `QA_MYSQL_TAG`), in §2, §2.1, §6.4 and R29. New §15.1 **Accepted deviations (Developer)**: R19 (`IMAGE_TAG=latest` default + `build:` in compose, dev/local only; prod pins `sha-*`/`vX.Y.Z` and verifies the digest; CI never pushes `latest`), R2 (configurable `SSO_UID`/`SSO_GID`, default 10001; host key ownership must match), R29 (`MYSQL_IMAGE` default `mysql:8.0`). R2/R19/R29 and §4.2 point to them. |
| v1.3 | 2026-10-10 | Q23 closed: Docker Hub repo `thomaschoi/sso-server` is **PUBLIC** (Thomas). The private-repo pull-token path is removed. The VPS pulls anonymously (rate-limited; an optional read-only token raises the limit), and the image is world-readable. New **hard CI secret gate** `image-secret-scan` (§7.1): trufflehog + Trivy secret scanner over the saved image, a per-layer file-name check (catches files deleted in later layers), and checks on `docker history` / config Env / Labels. Publish now depends on it. New pre-publish manual checklist (§7.2) and leaked-secret response (§7.3). Developer requirements R3 tightened; R30–R32 added (no build-time secrets via ARG/ENV, multi-stage with explicit final-stage COPY). |
| v1.2 | 2026-10-10 | Thomas's update applied. **Prod MySQL stays on 8.0 for now, 8.4 later**: the prerequisites cover both (version check accepts 8.0.x ≥ 8.0.11 or 8.4.x; auth-plugin guidance per version; SSO accounts use `caching_sha2_password` on 8.0 too). A new §6.4 covers the 8.0 → 8.4 upgrade and the `mysql_native_password` risk. CI tests against `mysql:8.0` **and** `mysql:8.4` (matrix). G2 and Q21 reworded: go-live no longer waits for 8.4. 8.0's April 2026 EOL noted. **Python 3.13**: runtime `python:3.13-slim` (= Debian **trixie**, confirmed by digest on Docker Hub, 2026-10-10), CI `setup-python 3.13`, and a dependency checklist (unverified items marked). **Docker Hub**: image `${DOCKER_USER}/sso-server:${IMAGE_TAG}` with `DOCKER_USER=thomaschoi` (replaces GHCR and `SSO_IMAGE_TAG`). The publish step (commented out) uses `docker/login-action` with `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` (access token). Rollout, rollback, compose refs and R1/R19 updated. New Q23: public vs private repo. |
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
Internet ──${SSO_HTTPS_PORT}──▶ nginx :443 (TLS) ──http:8000──▶ web (gunicorn, 3 workers, Py 3.13, Django 5.2)
         ──${SSO_HTTP_PORT}───▶ nginx :80 (ACME + 301)                  │            │
                                                                         │            └─▶ redis (throttle cache)
            Ubuntu VPS, Docker Engine + compose plugin, ufw              ▼                internal network only
                                                       remote MySQL 8.0→8.4 `dcWebUsers` (shared with myFinance), TLS
Host files: /opt/sso/.env (0600)  SSO_KEYS_DIR=/opt/sso/keys/*.pem → /run/keys:ro  /opt/sso/certs  /etc/cron.d/sso-*
```

- No DB container in staging or prod. MySQL is remote (spec §9.5). The `mysql:8.0` / `mysql:8.4` containers exist
  **only** in local/QA and CI (§2).
- Only nginx publishes ports. `web` and `redis` stay on the internal compose network.
- No migrations run automatically. `migrate` is a backed-up, operator-run step (§6, §12).

## 2. Environments

| | dev (Developer) | **local / QA (sprint 1)** | staging (**pre-go-live**) | prod |
|---|---|---|---|---|
| Purpose | Unit tests, coding | QA black-box suite (`qa/tests`) and `examples/` end to end, on MySQL 8.0 **and** 8.4 | Rehearse the prod rollout on a **copy of real `dcWebUsers`** | Live |
| Where | Developer box | Shared box / any Docker host, `docker compose -f docker-compose.test.yml` (+ the app stack) | Ubuntu VPS (same as prod, or a second VPS: Q20) | Ubuntu VPS |
| Hostname | `localhost` | `localhost` (self-signed) | `${SSO_STAGING_HOSTNAME}` | `${SSO_HOSTNAME}` |
| DB | SQLite (`SSO_DB_ENGINE=sqlite`; `settings_test.py` uses `:memory:`) | **`${MYSQL_IMAGE}` container** (default `mysql:8.0`; 8.4 supported), schema `dcWebUsers`, **synthetic users only** (§2.1) | Separate schema on the **same MySQL version as prod at that time**, restored from a fresh `dcWebUsers` dump (§6.3) | Remote MySQL `dcWebUsers`: 8.0 now, 8.4 after §6.4 |
| TLS | none / self-signed | self-signed (addendum C) | same source as prod | §3.2 |
| Cache | LocMem | Redis (proves shared-cache throttling) | Redis | Redis |
| Keys | ephemeral (`SSO_DEBUG=True` generates one) / `settings_test.py` | throw-away pair (`scripts/gen_keys.sh`) | own pair | own pair. **Never shared across envs** |
| `SSO_DEBUG` | `True` allowed | `False` (prod-like) | `False` | `False` |

Rules: each environment has its own issuer and keys. The same image tag moves local/QA → staging → prod. Staging
holds real password hashes and emails (Thomas accepted a copy for pre-go-live), so it is protected **exactly like
prod**: same host hardening, encrypted dump, and the schema is dropped after go-live unless kept on purpose (Q6).

### 2.1 Local/QA: MySQL container (8.0 and 8.4) with synthetic users
Thomas 2026-10-10: sprint-1 QA tests against a local `mysql:8.4` container with synthetic users. v1.2 update: prod
stays on 8.0 for now, so QA runs the suite on **both** `mysql:8.0` (today's prod) and `mysql:8.4` (the upgrade target).
It's selected with the Developer's `MYSQL_IMAGE` variable. The **default is `mysql:8.0`**, matching prod today (v1.4).
`MYSQL_IMAGE=mysql:8.4` selects the upgrade target, and `QA_MYSQL_TAG=8.0|8.4` also works when `MYSQL_IMAGE` is
unset. Each version gets its own throw-away volume (`SSO_TEST_MYSQL_VOLUME`).

Container (in the Developer's `docker-compose.test.yml`, addendum B.14). Requirements:
- `image: ${MYSQL_IMAGE:-mysql:${QA_MYSQL_TAG:-8.0}}` (default `mysql:8.0`; pin patch versions once chosen, with 8.0
  matching prod's patch level; see §15.1). `MYSQL_DATABASE=dcWebUsers`. Root password and app
  passwords come from a git-ignored `.env.test`. Data in a named volume that can be thrown away. Port bound to
  `127.0.0.1:3307:3306` at most, or not published at all. No authentication overrides: keep each version's defaults
  (`caching_sha2_password` default on both; native password enabled on 8.0 and disabled on 8.4), so QA sees the
  real auth behaviour of each.
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
- Limitation: the container's charset/collation is the MySQL 8 default (`utf8mb4` / `utf8mb4_0900_ai_ci`). Prod
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
| JWT private key(s) | `SSO_KEYS_DIR` = `/opt/sso/keys/`, e.g. `sso-2026-10.private.pem` | mounted at `/run/keys:ro`; `SSO_JWT_PRIVATE_KEY=<file name>` |
| JWT public key(s) | `SSO_KEYS_DIR` = `/opt/sso/keys/` | mounted at `/run/keys:ro`; `SSO_JWT_PUBLIC_KEYS=<name>[,<name>…]` |
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
   # 10001 = default container uid/gid. If SSO_UID/SSO_GID are set in .env, use those values instead (§15.1 R2).
   sudo install -d -m 0700 -o 10001 -g 10001 /opt/sso/keys
   sudo chmod 0600 /opt/sso/keys/*.private.pem && sudo chmod 0644 /opt/sso/keys/*.public.pem
   sudo chown 10001:10001 /opt/sso/keys/*.pem
   sudo chown root:root /opt/sso/.env && sudo chmod 0600 /opt/sso/.env
   ```
   `.env` is read by compose as root. The keys are opened by the app (uid `SSO_UID`,
   default 10001) at start-up, so the key directory's and files' owner **must equal the configured `SSO_UID:SSO_GID`**.
3. Keys live in **one host folder**, `SSO_KEYS_DIR=/opt/sso/keys` (in `/opt/sso/.env`), which compose mounts
   **read-only** at the fixed `/run/keys` (spec §9.5). The `.env` names the files only, not paths:
   ```dotenv
   SSO_KEYS_DIR=/opt/sso/keys
   SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem
   SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem
   ```
   The app resolves names in `SSO_JWT_KEYS_MOUNT` > `SSO_KEYS_DIR` > `/run/keys`. Compose **pins
   `SSO_JWT_KEYS_MOUNT=/run/keys`** for `web`, because `env_file` also passes the *host* path `SSO_KEYS_DIR` into the
   container. **Don't override `SSO_JWT_KEYS_MOUNT` in `.env`.** A value containing `/` is treated as a path, not a
   name, so use bare file names in prod. The signing key's own public key is always published, even if it isn't
   listed in `SSO_JWT_PUBLIC_KEYS`.
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

### 4.3 Deprecated key variables (code on `feat/app-permissions`)
- `SSO_JWT_PRIVATE_KEY_PATH`, `SSO_JWT_PUBLIC_KEY_PATHS` and the v1.0 singular `SSO_JWT_PUBLIC_KEY_PATH` (full paths)
  are **deprecated**. They are still read verbatim, but they log `sso.W001` ("… is deprecated; use …", once per
  process; also shown by `manage.py check`).
- Setting the old and new form of the **same** setting together (e.g. `SSO_JWT_PRIVATE_KEY` + `SSO_JWT_PRIVATE_KEY_PATH`)
  is **always fatal** (`ImproperlyConfigured`, even with `SSO_DEBUG=True`). Empty values count as unset (the
  Developer's `.env.example` keeps `SSO_JWT_PRIVATE_KEY_PATH=` / `SSO_JWT_PUBLIC_KEY_PATHS=` empty). When migrating
  an existing `.env`, delete or empty the old lines in the same edit as adding the new ones.
- New deployments use only `SSO_KEYS_DIR`, `SSO_JWT_PRIVATE_KEY` and `SSO_JWT_PUBLIC_KEYS`. CI treats `sso.W001` as a
  failure in `check --deploy --fail-level WARNING`, so a deprecated var in CI's env would fail the build.

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

## 6. Remote MySQL `dcWebUsers` prerequisites (8.0 now, 8.4 later)
Thomas 2026-10-10 (update): **production stays on MySQL 8.0 for now and moves to 8.4 later.** The SSO server must work
on both, and CI tests both (§8). Django 5.2's documented minimum is **MySQL 8.0.11** ("Django supports MySQL 8.0.11
and higher", Django 5.2 database docs, checked 2026-10-10). DevOps recommends the **latest 8.0 patch release**
regardless, for security fixes. **MySQL 8.0 reached end of life in April 2026** (Oracle's announced EOL), so 8.0
gets no further security fixes from Oracle. That's a reason not to postpone the 8.4 upgrade for long (Q21).
All SQL here is run **by Thomas or the DBA with the MySQL admin account**. DevOps has not connected.

### 6.0 Version-specific notes (factual; verify on the real server)
| Topic | MySQL 8.0.x (now) | MySQL 8.4.x (later) |
|---|---|---|
| Default auth plugin for new accounts | `caching_sha2_password` (default since 8.0.4) | `caching_sha2_password` |
| `mysql_native_password` | **Enabled**, deprecated (since 8.0.34). Existing accounts using it keep working. | **Disabled by default**. Accounts using it **cannot log in** unless the server runs with `--mysql-native-password=ON`. Removed in 9.0. |
| Config variable | `default_authentication_plugin` (deprecated since 8.0.27) and `authentication_policy` | `default_authentication_plugin` **removed**. Only `authentication_policy`. |
| TLS | TLSv1.2/1.3 only (≥ 8.0.28). Auto-generated self-signed certs if none are configured. Client default "preferred" = encrypted, not verified. | same |
| FK rule | n/a | `restrict_fk_on_non_standard_key=ON` (FKs must reference unique/PK keys). Django FKs reference PKs, so no impact. |
| Default collation | `utf8mb4_0900_ai_ci` | same |
| Client tools for dump/restore | `mysql:8.0` image (or a native 8.0 client) | `mysql:8.4` image. Ubuntu 24.04's `mysql-client` package is 8.0.x. |

Auth-plugin guidance:
- **On 8.0 and 8.4: create SSO's own accounts with `caching_sha2_password`** (§6.2). The SSO account then doesn't
  need to change at the 8.4 upgrade.
- On 8.0, don't use `mysql_native_password` for anything new, even though it still works. Existing myFinance
  accounts on it are handled in §6.4 **before** the upgrade.
- `caching_sha2_password` first-time (non-cached) authentication over TCP needs **TLS** or RSA key exchange. Using
  TLS (`REQUIRE SSL` on the account) covers that on both versions.
- **Client library:** on the Debian **trixie** base image (`python:3.13-slim`, §15 R1), `default-libmysqlclient-dev` is
  provided by **MariaDB Connector/C**. Debian's file list for trixie's `libmariadb3` (11.8.x) includes
  `plugin/caching_sha2_password.so` (packages.debian.org, checked 2026-10-10). That's packaging evidence only. CI
  proves an actual login from inside the built image against **both** `mysql:8.0` and `mysql:8.4` (§8 image job),
  and the runtime stage must keep `libmariadb3` with its plugin directory (R1).
- **Verified DB TLS** (VERIFY_CA / VERIFY_IDENTITY) needs the DBA's CA cert and a settings hook (proposed R28,
  `SSO_DB_SSL_CA`). Without it, the connection is encrypted but the server isn't authenticated.

### 6.1 Version and compatibility check (accept 8.0.x ≥ 8.0.11 or 8.4.x)
```sql
SELECT VERSION();                 -- accept 8.0.x with x >= 11 (recommend latest 8.0 patch) OR 8.4.x; anything else: stop
SELECT @@version_comment;         -- "MySQL Community Server - GPL" (or Enterprise)
SELECT @@authentication_policy;   -- both versions
-- 8.0 only (the variable no longer exists on 8.4 and errors there):
--   SELECT @@default_authentication_plugin;      -- expect caching_sha2_password
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS
 WHERE PLUGIN_NAME IN ('caching_sha2_password','mysql_native_password');
   -- 8.0: both ACTIVE. 8.4 default: native absent/DISABLED.
SELECT user, host, plugin FROM mysql.user WHERE user NOT LIKE 'mysql.%' ORDER BY plugin, user;
   -- inventory for §6.4; on 8.4 any mysql_native_password row is an account that cannot log in
SELECT @@require_secure_transport, @@tls_version, @@ssl_ca, @@ssl_cert;
SHOW SESSION STATUS LIKE 'Ssl_version';            -- non-empty when this session uses TLS
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
Go/no-go for the SSO first migrate:
- the version is 8.0.x (≥ 8.0.11) or 8.4.x;
- every table is InnoDB;
- the SSO apps aren't present yet;
- the SSO accounts (§6.2) are on `caching_sha2_password`.

The myFinance accounts' plugin is **not** an SSO go-live condition on 8.0. It's a gate for the **8.4 upgrade** (§6.4).

### 6.2 Dedicated DB accounts (least privilege; spec §4.9). Same SQL on 8.0 and 8.4
Two accounts, so runtime credentials never hold DDL. Both use `caching_sha2_password` **explicitly**, with TLS
required, even on 8.0.
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
                               -- plugin must read caching_sha2_password for both
```
- Never use `'%'` in prod. `<sso_vps_ip>` is the VPS egress IP (Q5).
- Runtime needs `UPDATE auth_user` (for `last_login` and the PBKDF2 re-hash, spec §4.3), DML on `token_blacklist_*` /
  `sso_*`, and `INSERT` on `django_admin_log` / `django_session`. The spec prescribes DB-wide DML; table-level grants
  are optional (Q15).
- `migrate`'s post-migrate step inserts `django_content_type` / `auth_permission` rows for `sso` and
  `token_blacklist`. That's expected.
- Staging gets its own accounts (`sso_app_stg`, `sso_migrator_stg`) on its own schema.

### 6.3 Backup before the first migrate (spec §4.6, §9.5)
Use a client of the **same major.minor as the server**, via the official image: `MYSQL_CLIENT_TAG=8.0` today, `8.4`
after the upgrade. Pass credentials in a client options file so the password never appears on the command line:
```bash
# ~/.my-dcweb.cnf (chmod 600)
# [client]
# host=<db_host>
# port=3306
# user=<admin_or_backup_user>
# password=<…>
# ssl-mode=VERIFY_IDENTITY        # or REQUIRED if no CA is available (Q5)
# ssl-ca=/cfg/ca.pem              # path inside the container below

MYSQL_CLIENT_TAG=8.0              # = server major.minor (8.0 now, 8.4 after §6.4)
TS=$(date +%Y%m%dT%H%M%S)
docker run --rm -i --network host \
  -v ~/.my-dcweb.cnf:/cfg/my.cnf:ro -v ~/mysql-ca/ca.pem:/cfg/ca.pem:ro \
  mysql:${MYSQL_CLIENT_TAG} mysqldump --defaults-extra-file=/cfg/my.cnf \
    --single-transaction --quick --routines --triggers --events --hex-blob \
    --no-tablespaces --set-gtid-purged=OFF --default-character-set=utf8mb4 \
    dcWebUsers | gzip -9 > dcWebUsers-pre-sso-$TS.sql.gz

gzip -t dcWebUsers-pre-sso-$TS.sql.gz
zcat dcWebUsers-pre-sso-$TS.sql.gz | tail -n 1                          # "-- Dump completed on …"
zcat dcWebUsers-pre-sso-$TS.sql.gz | grep -c 'INSERT INTO `auth_user`'  # > 0
sha256sum dcWebUsers-pre-sso-$TS.sql.gz > dcWebUsers-pre-sso-$TS.sql.gz.sha256
chmod 600 dcWebUsers-pre-sso-$TS.sql.gz*
```
- The dump holds every password hash and email. Encrypt it (`gpg --symmetric` / `age`), store it off-host, and keep
  it ≥ 30 days after go-live (Q6).
- A backup user, if not the admin: `SELECT, LOCK TABLES, SHOW VIEW, TRIGGER, EVENT` (`--no-tablespaces` avoids
  `PROCESS`).
- **The same command produces the staging copy** (pre-go-live, §12 G4). Restoring it is the restore test.

### 6.4 Upgrading `dcWebUsers` from MySQL 8.0 to 8.4 (later; DBA-run, separate change)
The main risk: **any account still on `mysql_native_password` stops authenticating on 8.4** (default-disabled
plugin). That includes myFinance's DB account, cron/backup users and admin tools. SSO's own accounts are already on
`caching_sha2_password` (§6.2), so SSO needs no account change, only a re-test.

1. **Inventory (on 8.0, weeks before):**
   ```sql
   SELECT user, host, plugin, ssl_type, account_locked FROM mysql.user
    WHERE user NOT LIKE 'mysql.%' ORDER BY plugin, user;
   ```
   Every row with `plugin = 'mysql_native_password'` needs an owner and a migration slot. (`mysql.*` system accounts
   are managed by the server.)
2. **Verify each client before changing anything.** On staging, or with a temporary test account on the real server,
   created `IDENTIFIED WITH caching_sha2_password … REQUIRE SSL`, check that:
   - **myFinance** (Django 4.1 + its `mysqlclient` / C client library) connects, logs a user in, and runs its
     cron/management commands;
   - **SSO** connects from the deployed image (already proven in CI against 8.0 and 8.4, §8);
   - backup tooling, admin GUIs and any other script that touches `dcWebUsers` connect.
   A client that fails needs a newer client library first (for example a rebuilt myFinance image). Don't re-enable
   native passwords.
3. **Migrate accounts to `caching_sha2_password` on 8.0** (still the old server, so it can be rolled back). The
   existing native hash can't be converted, so **a password must be supplied**: either the current one (if known) or
   a new one, with the client config updated at the same time:
   ```sql
   ALTER USER '<user>'@'<host>' IDENTIFIED WITH caching_sha2_password BY '<password>';
   -- optional, recommended for remote clients:
   ALTER USER '<user>'@'<host>' REQUIRE SSL;
   SELECT user, host, plugin FROM mysql.user WHERE user = '<user>';   -- now caching_sha2_password
   ```
   After each change, restart or reconnect that client and confirm it works. Rollback on 8.0:
   `ALTER USER … IDENTIFIED WITH mysql_native_password BY '<password>'` (still possible on 8.0, not after the
   upgrade).
4. **Gate:** the inventory query returns **no** `mysql_native_password` rows except ones knowingly left behind
   (documented, with the owner aware they'll break).
5. **Upgrade** (the DBA's procedure; outside SSO's scope). Take a full backup first (same as §6.3, plus whatever the
   DBA's server-level backup is), and follow Oracle's 8.0 → 8.4 upgrade checks (for example MySQL Shell's upgrade
   checker utility). Plan a maintenance window for myFinance **and** SSO.
6. **After the upgrade:** re-run §6.1 (expect 8.4.x, native plugin disabled). Run the P8 SSO smoke tests and a
   myFinance login. Switch the dump client to `MYSQL_CLIENT_TAG=8.4`, and change the `MYSQL_IMAGE` default (QA/dev compose) to
   `mysql:8.4`. Keep 8.0 in the CI matrix until no environment runs it.
7. **Escape hatch, temporary only:** starting 8.4 with `--mysql-native-password=ON` lets lagging native accounts log
   in again. It's a DBA decision, it should be time-boxed, and it is no option on 9.x.

## 7. Release artefact, image naming and tagging (Docker Hub)
Thomas 2026-10-10: images are published to **Docker Hub** as **`${DOCKER_USER}/sso-server:${IMAGE_TAG}`** with
`DOCKER_USER=thomaschoi`. GHCR is no longer the plan.
- Tags: `sha-<12 hex>` for every main-branch build, `vMAJOR.MINOR.PATCH` for every git tag. Deploys pin an immutable
  `IMAGE_TAG` and **never use `latest`**. Optional: pin by digest (`thomaschoi/sso-server@sha256:…`). After a deploy,
  record tag + digest in `/opt/sso/DEPLOYED` (`docker image inspect --format '{{index .RepoDigests 0}}' …`).
- In `/opt/sso/.env` on the VPS: `DOCKER_USER=thomaschoi` and `IMAGE_TAG=<tag>`. Compose interpolates them (R19).
- CI pushes with the GitHub Actions secrets `DOCKERHUB_USERNAME` (= `thomaschoi`) and `DOCKERHUB_TOKEN`. The latter
  is a **Docker Hub personal access token**, not the account password, with the minimum scope (Read & Write; no
  Delete). The publish step stays **commented out** in the draft (§8).
- **The repository is PUBLIC** (Thomas 2026-10-10, Q23 closed). Consequences:
  - **Anyone can pull and read the image**, including every layer, the build history and the config. So the image
    must never contain anything confidential. Even a file deleted in a later layer still ships in the earlier one.
    This is enforced by the hard CI gate in §7.1, the manual check in §7.2 and Developer requirements R3/R30–R32.
  - **VPS pulls need no credentials.** `docker compose pull` works anonymously, but it is subject to Docker Hub's
    **anonymous pull rate limits** (counted per source IP; check Docker's current published limits, which have
    changed over time). Deploys pull rarely, so this is normally fine. Optionally, log in on the VPS with a
    **read-only** Docker Hub access token (`docker login -u thomaschoi`, token pasted at the prompt). That raises the
    limit to the authenticated tier. The credential then lives in root's `~/.docker/config.json` (0600; a credential
    helper is better). It must be **separate from CI's Read & Write `DOCKERHUB_TOKEN`**.
  - Recommended: set the Docker Hub repo description/README to say the image needs runtime config and keys and has
    no defaults that work for anyone else.
- Until a GitHub repo and the CI Docker Hub token exist (addendum D), the interim option is to build on the VPS from a tagged
  checkout with the same name: `docker build -t thomaschoi/sso-server:<tag> .`
- Django 5.2 only: `requirements-django42.txt` is no longer needed (Developer may delete it, §15 R9).

### 7.1 Hard secret gate before publishing (CI job `image-secret-scan`)
Publish **depends on** this job. Any finding fails the build. Allowlist entries are reviewed in PRs and live in the
pipeline file.
1. **Secret scanners over the saved image** (`docker save` tarball, so every layer is covered, not just the final
   filesystem):
   - `trufflehog docker --image file://image.tar --fail` (exits non-zero on findings);
   - Trivy with `scanners: secret` against the same tarball (`input: image.tar`), `exit-code: 1`.
2. **Per-layer forbidden-file check.** Iterate over **every layer tarball** listed in the saved image's `manifest.json`
   and fail if any entry matches `*.pem`, `*.key`, `id_rsa*` / `id_ed25519*` / `id_ecdsa*`, `.env` / `.env.*`,
   `*.sqlite3`, `*.sql`, `*.sql.gz`, `*.dump`, `*.bak` or `dcWebUsers*`. The only exceptions are an explicit allowlist
   of public CA bundles (`etc/ssl/certs/`, `usr/share/ca-certificates/`, `…/certifi/cacert.pem`). The layers are also
   grepped for `-----BEGIN … PRIVATE KEY-----`, **including inside allowlisted paths**. Whiteout entries (`.wh.*`)
   are reported too: they mean something was deleted in a later layer, which the earlier layer still carries.
3. **History and config check.** `docker history --no-trunc` (every `CreatedBy`, including the `|N KEY=value` build-arg
   prefix BuildKit records for RUN steps) plus the image config `Env` and `Labels` must contain no secret-looking
   assignments (`*SECRET*=`, `*PASSWORD*=`, `*PASSWD*=`, `*TOKEN*=`, `*API_KEY*=`, `*PRIVATE*=`, `*CREDENTIAL*=`,
   `SSO_DBPWD=`, `EMAIL_PWD=`). They must also contain no `ARG` with such a name. The allowlist covers known-public
   base-image values (e.g. the Python image's `GPG_KEY`, a public signing-key fingerprint, and `PYTHON_SHA256`).
4. The vulnerability scan (Trivy `vuln`) stays in `image-build`. The secret gate is a separate, required job.

### 7.2 Pre-publish manual checklist (before the first push, and on every `v*` release)
The commented `publish` job is bound to a GitHub **environment** `dockerhub-publish` with a required reviewer
(Thomas), so a human ticks this before the push runs:
- [ ] `image-secret-scan` is green for **this exact** `sha-…` tag (not a rebuild).
- [ ] `docker history --no-trunc thomaschoi/sso-server:<tag>` and `docker image inspect` (Env, Labels) reviewed by
      eye: no secrets, no internal hostnames or IPs worth hiding, no build args with values.
- [ ] The Dockerfile diff since the last release was reviewed for new `ARG`/`ENV`/`COPY`/`ADD` lines, and
      `.dockerignore` is unchanged or still excludes everything in R3.
- [ ] The tag is `sha-…` / `vX.Y.Z`, never `latest`. The repo is `docker.io/thomaschoi/sso-server`.
- [ ] Thomas has confirmed once that publishing the application code inside a public image is OK (Q25; first push only).

### 7.3 Response if a secret is ever pushed
A public image may already have been pulled (or mirrored or cached), so **treat the secret as compromised. Deleting
the tag is not enough.**
1. **Stop the spread:** disable the `publish` job / environment, then **delete the affected tag(s)** on Docker Hub,
   plus any other tag pointing at the same digest (UI: repo → Tags → delete; requires an owner login or a token
   with Delete scope, which CI's token deliberately lacks).
2. **Rotate every exposed secret**, whatever leaked:
   - **JWT signing key**: run the **emergency rotation, §11.3** (new key only; every user logs in again).
   - `SSO_SECRET_KEY`: replace it and recreate `web`. This invalidates admin sessions and CSRF tokens.
   - DB passwords: `ALTER USER 'sso_app'@'<sso_vps_ip>' IDENTIFIED WITH caching_sha2_password BY '<new>'` (the same
     for `sso_migrator`), then update `.env` and recreate.
   - `ServiceClient` secrets (rotate via admin; tell their owners), Docker Hub tokens, `EMAIL_*`, DNS/ACME tokens, TLS
     private key (reissue the cert).
3. **Rebuild clean**: fix the Dockerfile/`.dockerignore`, build a new tag, pass §7.1 and §7.2, publish, and redeploy
   with `IMAGE_TAG=<new>`. If the secret also entered **git history**, purge it there too, and treat it as leaked
   anyway.
4. **Review** DB, admin and auth logs for use of the leaked secret since the push time. Record the incident (what, when
   pushed, when deleted, what rotated).

## 8. CI pipeline (draft: `devops/ci/pipeline.yml`)
**[ASSUMPTION]** GitHub Actions. The file is stored under `devops/ci/` and **inactive** until it's moved to
`.github/workflows/` after approval. It uses Python **3.13** (`actions/setup-python`), matching the runtime image.
1. **lint**: ruff check + format, gitleaks, "no key/env/dump files tracked".
2. **unit** (SQLite, Django 5.2, Python 3.13): `makemigrations --check --dry-run` (addendum B.11) and `pytest` with
   `--cov-fail-under=90` (addendum C).
3. **integration-mysql**: a **matrix over `mysql:8.0` and `mysql:8.4`**. Each run asserts the server version and that
   the default auth plugin is `caching_sha2_password`. It then migrates the Django built-ins, checks
   `migrate --plan` lists only `sso`/`token_blacklist`, runs `migrate`, and runs pytest with `SSO_DB_ENGINE=mysql`.
4. **deploy-check**: `manage.py check --deploy --fail-level WARNING` with prod-like env, and `pip-audit`.
5. **image-build**: builds `thomaschoi/sso-server:sha-<12hex>` once. Checks Python 3.13/trixie, non-root uid 10001 (the default build;
   §15.1 R2),
   and no secret files in the final filesystem. Runs a Trivy vulnerability scan, then saves the image as an artifact.
6. **image-db-smoke** (matrix 8.0, 8.4): logs in **from inside the image** as a `caching_sha2_password` user (§6.0),
   runs `migrate`, and checks `/healthz` with a `Host` header.
7. **image-secret-scan** (**hard gate**, §7.1): trufflehog + Trivy secret scanning over the saved image, the per-layer
   forbidden-file check, and the history/config/Env/Labels check.
8. **publish**: commented out. It `needs: [image-build, image-db-smoke, image-secret-scan]` and runs in the
   `dockerhub-publish` environment with a required reviewer (§7.2). It uses `docker/login-action` with the
   `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets, then pushes `sha-…` (main) and `v…` (tags) to
   `docker.io/thomaschoi/sso-server` (**public**). Enable only after Thomas approves. **No CD.** Deploys are manual
   (§12).

Python 3.13 dependency checks (**not yet verified by running anything**; this is what CI/QA must prove):
- `mysqlclient` builds from source on Linux against MariaDB Connector/C. Its PyPI metadata (2.3.0) lists Python 3.13.
  The CI build plus the in-image DB login are the real test.
- `gunicorn`, `cryptography`, `Django 5.2`, `djangorestframework`, `djangorestframework-simplejwt`, `PyJWT`,
  `django-cors-headers`, `django-environ`, `whitenoise`, `redis`: make sure the **resolved** versions in a 3.13
  environment install and pass the full suite. PyPI classifiers (seen for gunicorn 26.2.0 and cryptography
  50.0.2) are a hint, not proof. `pip-audit` runs on the same environment.
- Python 3.13 removed some long-deprecated stdlib modules (PEP 594, e.g. `cgi`, `crypt`, `telnetlib`). The unit +
  integration suites under 3.13 will surface any transitive use.
- Pin the resolved set (lock file or `pip-compile` with hashes, R9) once it's green, so the image and CI use the same
  versions.

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
Keys are files in `SSO_KEYS_DIR` (`/opt/sso/keys`, mounted at `/run/keys`). **Rotation means editing two `.env`
values:** `SSO_JWT_PRIVATE_KEY` (the signing-key **file name**) and `SSO_JWT_PUBLIC_KEYS` (the **comma-separated list
of public-key file names**; JWKS lists all of them, plus the signing key's own public key, which is always published).
No paths and no compose changes are needed. Put new key files in `SSO_KEYS_DIR`, edit the names, recreate `web`. `kid` = first 16 hex chars of SHA-256 over the DER SubjectPublicKeyInfo
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
   `IMAGE_TAG`. Monitoring is green.
2. Generate the pair on the VPS (§4.2), fix ownership/permissions, compute NEW_KID:
   `openssl pkey -pubin -in /opt/sso/keys/sso-2027-10.public.pem -outform DER | sha256sum | cut -c1-16`.
3. T0: in `/opt/sso/.env`, **append** the new public key to the list:
   `SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem,sso-2027-10.public.pem`. `SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem`
   stays unchanged. Then `docker compose up -d --force-recreate web`.
4. Verify: JWKS lists OLD_KID + NEW_KID, a new login token still has `kid=OLD_KID`, and `/healthz` returns 200.
   Notify service owners.
5. Wait ≥ 24 h.
6. Switch: change the file name to `SSO_JWT_PRIVATE_KEY=sso-2027-10.private.pem`. **Keep both names** in
   `SSO_JWT_PUBLIC_KEYS`. Then recreate `web`.
7. Verify: a new token has `kid=NEW_KID` and verifies with `examples/verifier`. A refresh token from before step 6
   still refreshes. Watch service 401s for 1 h.
8. Wait 8 days.
9. Retire: remove the old name from the list, so `SSO_JWT_PUBLIC_KEYS=sso-2027-10.public.pem`. Recreate `web`, and
   confirm JWKS shows NEW_KID only.
10. `shred -u /opt/sso/keys/sso-2026-10.private.pem`. Log the date, kids and operator.
Rollback before step 9: revert the `.env` line(s) and recreate. Both keys are still published, so nothing breaks.

### 11.3 Emergency rotation (compromise)
1. Generate a new key into `SSO_KEYS_DIR`. Set `SSO_JWT_PRIVATE_KEY=<new>.private.pem` and
   `SSO_JWT_PUBLIC_KEYS=<new>.public.pem` (the **new name only**), then recreate `web`. Every user has to log in again.
   Then `shred -u` the compromised private key file.
2. Services may keep the old key cached for up to 1 h. Tell their owners to restart them or flush the JWKS cache.
3. Optionally blacklist all outstanding refresh tokens and set `UserTokenRevocation` (introspect then reports old
   tokens inactive).
4. Investigate. If the VPS was compromised, also rotate `SSO_SECRET_KEY` and the DB passwords.
5. If the key leaked through a **published image**, also follow §7.3 (delete the tag, rotate everything that was in
   it, treat it as compromised).

## 12. Rollout steps

### 12.1 Pre-go-live checklist (gates)
- [ ] **G1 Parameters decided** (§0): `SSO_DOMAIN`, `SSO_HOSTNAME`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`, staging
      hostname. That fixes the cert option (§3.2) and the issuer.
- [ ] **G2 Prod MySQL passes §6.1** with output saved: **8.0.x (≥ 8.0.11) or 8.4.x**, all InnoDB, no `sso`/
      `token_blacklist` migrations yet, and SSO accounts created with `caching_sha2_password` + TLS. Go-live does
      **not** wait for the 8.4 upgrade. That's a separate change with its own gate (§6.4 step 4).
- [ ] **G3 Sprint-1 DoD met** (addendum C), including the QA suite green against **local `mysql:8.0` and `mysql:8.4` +
      synthetic users** (§2.1), and the CI matrix green on both. The image is built by CI or on the VPS at a tag.
- [ ] **G4 Staging copy of `dcWebUsers`**: fresh dump (§6.3) restored into a separate staging schema on prod's MySQL
      version, using
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
- **P3 Keys** (§4.2): generate into `/opt/sso/keys`. In `.env`, set `SSO_KEYS_DIR=/opt/sso/keys`,
  `SSO_JWT_PRIVATE_KEY=<name>.private.pem` and `SSO_JWT_PUBLIC_KEYS=<name>.public.pem`. No deprecated `*_PATH(S)` vars.
- **P3b Image**: `docker compose pull web` for `${DOCKER_USER}/sso-server:${IMAGE_TAG}`. The public repo pulls
  anonymously, subject to anonymous rate limits; an optional read-only token login is described in §7. Or build
  locally under the same name (§7). Check that the pulled digest matches the one that passed §7.1.
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
set `IMAGE_TAG=<new>` (`sha-*`/`vX.Y.Z`) in `.env` → `docker compose pull web` → verify the digest equals the one that
passed §7.1 → `docker compose up -d` → P8 subset. Migrations must be backward-compatible with the previous
image (expand-only). With a single `web` container, `up -d` causes a few seconds of 502s (Q13).

## 13. Rollback steps (use the lowest level that works)
### 13.1 Level 1: previous image (no DB change)
```bash
cd /opt/sso
sed -i 's/^IMAGE_TAG=.*/IMAGE_TAG=<previous tag from DEPLOYED>/' .env
docker compose pull web       # thomaschoi/sso-server:<previous tag>; usually still cached locally
docker compose up -d
docker compose images web     # confirm the tag/digest matches DEPLOYED's previous entry
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
  mysql:${MYSQL_CLIENT_TAG} mysql --defaults-extra-file=/cfg/my.cnf dcWebUsers   # client = server major.minor
# 3. SELECT COUNT(*) FROM auth_user == P5 baseline; log in to myFinance
```
The dump has no `CREATE DATABASE`, so tables created after the dump (SSO's) remain. Drop them as in §13.3.

### 13.5 Keys on rollback
An image rollback doesn't touch the key files, but **the env var form must match the image**:
- Images built from `feat/app-permissions` onward read `SSO_KEYS_DIR` / `SSO_JWT_PRIVATE_KEY` / `SSO_JWT_PUBLIC_KEYS`
  and still accept the deprecated `*_PATH(S)` vars (with `sso.W001`).
- **Older images only read `SSO_JWT_PRIVATE_KEY_PATH` / `SSO_JWT_PUBLIC_KEY_PATHS`.** Rolling back to such an image
  means switching `.env` to the old form, with full container paths: `SSO_JWT_PRIVATE_KEY_PATH=/run/keys/<name>`,
  `SSO_JWT_PUBLIC_KEY_PATHS=/run/keys/<a>,/run/keys/<b>`. **Remove** the new `SSO_JWT_PRIVATE_KEY` /
  `SSO_JWT_PUBLIC_KEYS` lines at the same time; the new code rejects both forms together, but the old code just
  ignores the new names. Also check that the older compose file still mounts the same host folder at `/run/keys`.
  Otherwise the old image fails fast at start-up (missing key).
- Keep both `.env` variants next to `DEPLOYED` during the first releases after the rename.

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
- R1. **Must**: `python:3.13-slim-trixie`, multi-stage. As of 2026-10-10, `python:3.13-slim` equals the trixie image by
  digest. Name the codename explicitly and pin a patch version (e.g. `3.13.13-slim-trixie`) or a digest. The builder
  has `build-essential pkg-config default-libmysqlclient-dev`. The runtime stage has only the runtime client library
  (`libmariadb3`, **including its `caching_sha2_password` plugin** under `/usr/lib/<arch>/libmariadb3/plugin/`; §6.0;
  the CI image job proves it on MySQL 8.0 and 8.4), and no compilers.
- R2. **Must**: run as a non-root user, uid/gid **10001 by default**. Configurable via `SSO_UID`/`SSO_GID`: accepted
  deviation, see §15.1. Never 0.
- R3. **Must not** contain keys, `.env`, certs, dumps or databases. **The image is public** (§7). `.dockerignore`
  **must** exclude at least: `.env` and `.env.*` (allow `.env.example` only if the image needs it, which it shouldn't),
  `keys/`, `*.pem`, `*.key`, `id_rsa*`, `.git/`, `.github/`, `.venv/`, `*.sql`, `*.sql.gz`, `*.dump`, `*.bak`,
  `*.sqlite3`, `db.sqlite3`, `staticfiles/`, `docker/certs/`, `qa/` (including any fixtures or dumps with real data),
  `examples/`, `devops/`, `.pytest_cache/`, `.coverage`, `__pycache__/`. CI's §7.1 gate enforces the result.
- R30. **No secrets at build time via `ARG` or `ENV`.** They persist in the image history or config and are public.
  The Dockerfile has no `ARG`/`ENV` holding passwords, tokens or keys. If a build step ever genuinely needs a secret
  (e.g. a private package index), use **BuildKit `RUN --mount=type=secret,id=…`**, which doesn't persist in layers or
  history. Runtime secrets come only from `env_file` and the `/run/keys` mount (§4).
- R31. **Multi-stage build** (builder with compilers and `-dev` packages → slim runtime). Nothing from the builder
  reaches the runtime except explicitly copied artefacts (e.g. the installed virtualenv / wheels).
- R32. **The final stage copies only explicit paths.** For example `COPY --chown=10001:10001 manage.py ./`,
  `COPY ssoproject/ ssoproject/`, `COPY sso/ sso/`, and the venv from the builder. **No `COPY . .`** in the final stage
  (it defeats a mistaken `.dockerignore`), and no `ADD` of remote URLs. Don't create-then-delete secret files in a
  `RUN` step, because deleted files still ship in earlier layers.
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
- R9. Should pin requirements exactly or by hash, **resolved under Python 3.13** (§8 checklist). **Django 5.2 only**: drop `requirements-django42.txt` and the
  "fallback" comment in `requirements.txt` (Thomas 2026-10-10).

**Settings / app behaviour**
- R10. Env vars documented in `.env.example`, using the §0 parameters as placeholders (no `thomas-choi.com` literal):
  `SSO_SECRET_KEY, SSO_DEBUG, SSO_ALLOWED_HOSTS, SSO_CSRF_TRUSTED_ORIGINS, SSO_DB_ENGINE, SSO_DBNAME, SSO_DBHOST,
  SSO_DBPORT, SSO_DBUSER, SSO_DBPWD, SSO_ISSUER, SSO_AUDIENCE, SSO_KEYS_DIR, SSO_JWT_PRIVATE_KEY, SSO_JWT_PUBLIC_KEYS
  (file names; the deprecated `*_PATH(S)` forms only as commented notes, §4.3), SSO_ACCESS_TTL_MIN, SSO_REFRESH_TTL_DAYS, SSO_CORS_ALLOWED_ORIGINS, SSO_COOKIE_DOMAIN, SSO_CACHE_URL, SSO_NUM_PROXIES,
  SSO_ADMIN_PATH`, plus compose-only `SSO_HOSTNAME, SSO_DOMAIN, SSO_HTTPS_PORT, SSO_HTTP_PORT, DOCKER_USER,
  IMAGE_TAG, GUNICORN_WORKERS`. (QA's `qa/tests/conftest.py` still defaults `SSO_ALLOWED_ORIGIN` to a `thomas-choi.com`
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
- R18. `web`, `nginx`, `redis`. **No DB service.** MySQL containers live only in `docker-compose.test.yml`.
- R19. `image: ${DOCKER_USER:?set DOCKER_USER}/sso-server:${IMAGE_TAG:?set IMAGE_TAG}` (Docker Hub;
  `DOCKER_USER=thomaschoi`), `env_file: .env`. Production never runs `latest`. The Developer's compose defaults to
  `IMAGE_TAG=latest` and keeps `build:`: accepted deviation for local/dev use, see §15.1. Prod `.env` pins the tag.
- R20. Volumes: `${SSO_KEYS_DIR:-./keys}:/run/keys:ro` (web), with `SSO_JWT_KEYS_MOUNT: /run/keys` pinned in the web
  service's `environment` (done on `feat/app-permissions`), certs `:ro` + ACME webroot (nginx), optional `./mysql-ca:/run/mysql-ca:ro`
  (web).
- R21. **Only nginx publishes ports:** `"${SSO_HTTPS_PORT:-443}:443"` and `"${SSO_HTTP_PORT:-80}:80"`. No `ports:` on
  web or redis, because Docker-published ports bypass ufw (§3.0). For the shared-nginx variant, bind to
  `127.0.0.1` only.
- R22. `restart: unless-stopped`, `depends_on: condition: service_healthy`, healthchecks on all three services,
  json-file log rotation.
- R23. Redis per §5.
- R24. Dev/self-signed overrides go in an override file or profile, never in the prod file.

**docker-compose.test.yml (local/QA)**
- R29. `${MYSQL_IMAGE:-mysql:${QA_MYSQL_TAG:-8.0}}`. **Default `mysql:8.0`** (prod today); 8.4 supported (accepted
  deviation from the earlier `8.4` default, see §15.1). Default auth settings. `MYSQL_DATABASE=dcWebUsers`. An init script creates
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
  same DER-SPKI method as `sso/keys.py`, and refuses to overwrite existing files. It prints the matching `.env` lines
  (`SSO_KEYS_DIR=…`, `SSO_JWT_PRIVATE_KEY=<name>.private.pem`, `SSO_JWT_PUBLIC_KEYS=<name>.public.pem`) and the rotation
  hint (append the public key). Done on `feat/app-permissions`.

### 15.1 Accepted deviations (Developer)
Agreed on 2026-10-10. The Developer's files differ from the original requirement text, and these differences are
accepted with the conditions below.

| Req. | Developer's implementation | Accepted for | Conditions |
|---|---|---|---|
| R19 | `docker-compose.yml`: `image: ${DOCKER_USER:-thomaschoi}/sso-server:${IMAGE_TAG:-latest}`, and `build:` kept in the main compose file | Local and dev use | **Production `/opt/sso/.env` must pin `IMAGE_TAG` to `sha-<12hex>` or `vX.Y.Z`.** An exported shell variable overrides `.env`, so check there's no stray `export IMAGE_TAG`. Rollout (§12 P3b / later releases) **verifies the pulled digest** against the one that passed §7.1 and records it in `DEPLOYED`. On the VPS, use `docker compose pull`/`up -d`, never `up --build`. **CI never pushes `latest`** (publish job pushes only `sha-*` and `v*`). |
| R2 | uid/gid configurable via build args and compose `SSO_UID`/`SSO_GID` (default **10001**; the Dockerfile rejects 0 and non-numeric values) | All environments | The **host key directory and key files must be owned by the configured `SSO_UID:SSO_GID`** (§4.2). Published images are built with the default 10001 (the CI check asserts it). A non-default uid means a local build on that host. |
| R29 | `MYSQL_IMAGE` defaults to **`mysql:8.0`** (`QA_MYSQL_TAG` as fallback) in test/dev compose | Local/QA/dev | 8.4 stays supported and tested (`MYSQL_IMAGE=mysql:8.4`, CI matrix). Change the default to 8.4 after the prod upgrade (§6.4 step 6). |

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
8. **CI:** GitHub Actions assumed. When will the GitHub repo exist, and when will the `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`
   secrets be created? Until then, build on the VPS? (The registry itself is resolved: Docker Hub, see below.)
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
21. **MySQL 8.0 → 8.4 upgrade (separate from SSO go-live).** When is the upgrade planned? 8.0 has been past EOL since April
    2026. Which accounts in `SELECT user, host, plugin FROM mysql.user` still use `mysql_native_password`
    (myFinance's especially)? Who owns migrating them with `ALTER USER … IDENTIFIED WITH caching_sha2_password`, and
    their clients' config? Has myFinance (Django 4.1, whose official MySQL support predates 8.4) been verified against
    8.4 with a `caching_sha2_password` account (§6.4 step 2)?
22. **Parameters in §0** (`SSO_DOMAIN`, `SSO_HOSTNAME`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`, staging hostname).
    The decision is pending (see Q3 below). It's needed before gate G1.
25. **New: OK to publish the source as part of a public image?** The image contains the `sso` application code
    (no secrets). Confirm once with Thomas before the first push (§7.2 checklist).

### 16.2 Resolved
1. ~~MySQL version~~. **Django 5.2 only (4.2 fallback dropped). Prod MySQL is 8.0 now, 8.4 later** (Thomas
   2026-10-10, v1.2 update). Both versions are supported and tested (§6, §8). Upgrade timing is tracked in Q21.
8b. ~~Registry~~. **Docker Hub, `thomaschoi/sso-server`** (Thomas 2026-10-10).
23. ~~Docker Hub repo visibility~~. **PUBLIC** (Thomas 2026-10-10). VPS pulls are anonymous (rate-limited); an
    optional read-only token raises the limit. The image is world-readable, so the hard secret gate (§7.1),
    checklist (§7.2) and leak response (§7.3) apply.
24. ~~Python version~~. **Python 3.13**, `python:3.13-slim` (Debian trixie) (Thomas 2026-10-10).
2. (part) ~~Host type~~. **Docker on an Ubuntu VPS** (Thomas 2026-10-10). The concrete baseline is in §3.0. Still open:
   same VPS as myFinance (Q2 above) and Ubuntu release (Q20).
3. ~~Real hostname / DNS~~. **Parameterized, decision pending** (Thomas 2026-10-10). See §0 and Q22. Who manages DNS
   is still to be answered with that decision.
7. ~~Real data in staging~~. **Sprint-1 QA uses a local MySQL container (`MYSQL_IMAGE`, default `mysql:8.0`; 8.4 supported) with synthetic users (§2.1). A staging
   copy of `dcWebUsers` is a pre-go-live step** (gate G4), protected like prod (Thomas 2026-10-10).
11. ~~Multi-key verification~~. **Implemented in `sso/tokens.py`**, with the singular-env fallback in settings. Only a
    staging rehearsal remains (G6).
