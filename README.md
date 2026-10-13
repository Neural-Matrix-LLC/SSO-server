# sso-server

> **See also:** [v1.2 requirements design](docs/DESIGN-v1.2-requirements.md) and the [API Reference Manual for client and service developers](docs/API-REFERENCE-MANUAL.md). Future items: [TODOS.md](TODOS.md).

Single sign-on server for myFinance and related apps. It implements `docs/SSO-server.md` (v1.0 spec)
as amended by `docs/DESIGN-ADDENDUM-v1.1.md`, and it follows the container requirements in
`devops/DEPLOYMENT-PLAN.md` §15.

* REST login with **Django's own user management**, run against the existing **`dcWebUsers`** MySQL
  database. It uses the stock `auth_user` table, so every existing user keeps their password.
* RS256 JWTs: a 15-min access token and a 7-day refresh token. The refresh token rotates on every use,
  and the old one goes on the blacklist. Each token header carries a `kid`. JWKS publishes every public key.
* Browser mode keeps the refresh token in an HttpOnly cookie and checks `Origin`. Native mode returns
  the refresh token in the response body.
* Back-end services verify tokens locally with the published JWKS (`examples/verifier`). Introspection
  is available for revocation-aware checks.

Sprint 1 scope covers spec phases 1–2 plus the phase-3 deployment files. Phase 4 (first consumer) and
phase 5 (PKCE / hosted login / account endpoints) are not built yet. The `AuthorizationCode` model exists
but nothing uses it.

## Docker quick start (local / WSL)

From a fresh checkout to a running server against an existing `dcWebUsers` MySQL, with the production
compose file (`docker-compose.yml`: `web` + `redis` + `nginx`, no DB container). Values below are for a local
machine (`https://localhost:8443`, self-signed TLS); a server uses its real host name, port 443 and a real
certificate. For a throw-away local MySQL instead, see "Local dev with self-signed TLS" in [§7](#7-docker).

1. **Create `.env`** (never commit it):
   ```bash
   cp .env.example .env && chmod 600 .env
   python3 -c 'import secrets; print(secrets.token_urlsafe(50))'   # paste as SSO_SECRET_KEY=
   ```
   For a local run, change these lines in `.env`:
   ```ini
   SSO_ALLOWED_HOSTS=localhost
   SSO_ISSUER=https://localhost:8443
   SSO_CSRF_TRUSTED_ORIGINS=https://localhost:8443
   SSO_CORS_ALLOWED_ORIGINS=https://localhost:8443
   SSO_COOKIE_DOMAIN=
   SSO_HSTS_SECONDS=0
   SSO_DOMAIN=localhost
   SSO_HOSTNAME=localhost
   SSO_HTTP_PORT=8080
   SSO_HTTPS_PORT=8443
   SSO_TLS_CERT_FILE=selfsigned.crt
   SSO_TLS_KEY_FILE=selfsigned.key
   IMAGE_TAG=dev
   ```
   and create the self-signed certificate nginx expects in `SSO_CERTS_DIR` (default `./docker/certs`):
   `scripts/gen_selfsigned_cert.sh localhost docker/certs` (writes `selfsigned.crt` / `selfsigned.key`).

2. **Generate the JWT signing keys.** `scripts/gen_keys.sh [OUT_DIR] [NAME] [BITS]` (defaults `./keys`,
   `sso-YYYY-MM`, 3072 bits; it never overwrites):
   ```bash
   scripts/gen_keys.sh ./keys sso-2026-10
   # private=./keys/sso-2026-10.private.pem      (mode 0600)
   # public=./keys/sso-2026-10.public.pem        (mode 0644)
   # kid=<16 hex>                                 note it: JWKS must show the same kid (step 7)
   ```

3. **Name the keys in `.env`.** `SSO_KEYS_DIR` (default `./keys`) is the one host folder with the keys;
   compose mounts it **read-only at `/run/keys`** inside `web`. Give the key **file names** only, exactly as
   `gen_keys.sh` prints them:
   ```ini
   SSO_KEYS_DIR=./keys
   SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem
   SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem
   ```
   The names are resolved in a directory chosen by this precedence: **`SSO_JWT_KEYS_MOUNT` (explicit) >
   `SSO_KEYS_DIR` > `/run/keys`**. `docker-compose.yml` pins `SSO_JWT_KEYS_MOUNT=/run/keys` for `web`, because
   `env_file: .env` also hands the *host* path `SSO_KEYS_DIR` to the container; so in Docker the keys are
   always `/run/keys/<name>`, and without Docker (`manage.py`, tests) they resolve in `SSO_KEYS_DIR`. A
   relative directory is taken relative to the working directory. A value containing `/` is a path, not a
   name (absolute, or relative to the working directory). `SSO_JWT_PUBLIC_KEYS` is comma-separated: for a
   rotation **append** the new public key (`old.public.pem,new.public.pem`, see §4). The old
   `SSO_JWT_PRIVATE_KEY_PATH` / `SSO_JWT_PUBLIC_KEY_PATHS` (full paths) still work but log a deprecation
   warning (`sso.W001`); setting an old and a new form of the same key together stops the server.

4. **Let the container user read them.** `web` runs as `SSO_UID:SSO_GID` (default `10001:10001`), not as you,
   and `gen_keys.sh` creates `keys/` as `0700` owned by you. Either
   ```bash
   sudo chown -R 10001:10001 keys && chmod 0600 keys/*.private.pem        # a)
   ```
   or b) run the container as yourself: add `SSO_UID=$(id -u)` / `SSO_GID=$(id -g)` (the numbers, e.g.
   `1000`) to `.env` and **rebuild** the image (step 7 uses `--build`). The private key stays `0600` (or
   `0640` with the `SSO_GID` group). Symptoms and checks (`ls -n keys/`): see
   [Troubleshooting: key ownership](#troubleshooting-key-ownership) in §7.

5. **Database.** The settings read `SSO_DB_ENGINE=mysql`, `SSO_DBHOST`, `SSO_DBPORT` (3306), `SSO_DBNAME`
   (`dcWebUsers`), `SSO_DBUSER`, `SSO_DBPWD` (optional TLS: `SSO_DB_SSL_CA` / `SSO_DB_SSL_MODE`). `.env` holds the
   **runtime** account `sso_app` (`SELECT, INSERT, UPDATE, DELETE` only); migrations use a separate
   **`sso_migrator`** account that additionally has `CREATE, ALTER, INDEX, REFERENCES`. The exact grants are in
   `docker/mysql-init/01-sso-accounts.sh` (it creates both accounts for the local/QA MySQL; on a real server
   a DBA creates them the same way, restricted to the SSO host). `SSO_DBHOST` is resolved inside the container:
   `localhost` is the container itself. For MySQL on the Docker host (Windows/WSL or Linux) use
   `SSO_DBHOST=host.docker.internal`: `docker-compose.yml` maps that name to the host (`extra_hosts:
   host-gateway`), so it works with Docker Desktop and with Docker Engine in WSL/Linux alike. MySQL must then
   listen on an address the containers can reach (not only `127.0.0.1`) and allow the account from that host. **Before migrating a real `dcWebUsers`, take the `mysqldump` backup in
   [§5](#5-database-first-deployment-and-migrate-procedure) step 1.**

6. **Migrate once, as `sso_migrator`** (the container never migrates on its own). The password is read into the
   shell so it stays out of `.env` and the command line; `-e SSO_DBPWD` passes it through:
   ```bash
   read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
   docker compose build web
   docker compose run --rm -e SSO_DBUSER=sso_migrator -e SSO_DBPWD web python manage.py migrate --plan
   ```
   **Stop** unless the plan lists only `application.*`, `sso.*` and `token_blacklist.*` (an existing `dcWebUsers`
   already has `contenttypes`, `auth`, `admin` and `sessions`; see §5). Then apply it:
   ```bash
   docker compose run --rm -e SSO_DBUSER=sso_migrator -e SSO_DBPWD web python manage.py migrate
   unset SSO_DBPWD
   ```
   This also creates the permission `application.app1` (llm-wiki-svc).

7. **Start and check.** nginx answers only for `SSO_HOSTNAME` (any other `Host` is dropped), so call it by that
   name; `-k` accepts the self-signed certificate:
   ```bash
   docker compose up -d --build
   docker compose ps                                   # web and nginx "healthy"
   curl -sk https://localhost:8443/healthz             # {"status":"ok"}
   curl -sk https://localhost:8443/.well-known/jwks.json \
     | python3 -c 'import json,sys; print([k["kid"] for k in json.load(sys.stdin)["keys"]])'
   ```
   The kid must equal the `kid=` that `gen_keys.sh` printed. With a real host name that does not resolve yet,
   add `--resolve "$SSO_HOSTNAME:$SSO_HTTPS_PORT:127.0.0.1"` and use `https://$SSO_HOSTNAME:$SSO_HTTPS_PORT/...`.
   If `web` keeps restarting, `docker compose logs web` names the problem (missing or unreadable key, DB, cache).

8. **Admin user and app access.**
   ```bash
   docker compose run --rm web python manage.py createsuperuser
   # other applications later:  docker compose run --rm web python manage.py create_app_permission app2 "Can use app2 (reporting)"
   ```
   The admin is at `https://localhost:8443/<SSO_ADMIN_PATH>` (default `sso-admin/`). **Superusers do not get
   app access automatically** (`SSO_SUPERUSER_ALL_APPS=false`, §6a): to use llm-wiki-svc, grant
   `application.app1` explicitly. In the admin open *Users* → the user → *User permissions* (or a group the
   user is in → *Permissions*) → "Applications | application access | Can use app1 (llm-wiki-svc)" → Save. `perms` in the
   next token (or after a refresh) then contains `application.app1`. An existing `dcWebUsers` user can be made
   staff/superuser the same way instead of creating a new one.

---

## 1. Layout

| Path | Purpose |
|---|---|
| `manage.py` | Django entry point |
| `ssoproject/settings.py` | All configuration from env (django-environ). Fail-fast checks. MySQL/SQLite switch |
| `ssoproject/settings_test.py` | pytest settings: SQLite in memory, throw-away RSA keys (current + old + rogue) |
| `ssoproject/urls.py` | URL map (API, `.well-known`, `healthz`, admin at `SSO_ADMIN_PATH`). JSON 404/500 handlers |
| `sso/keys.py` | RSA key loading, `kid` = sha256(DER SPKI)[:16], JWKS rendering, key-error messages |
| `sso/tokens.py` | `KidTokenBackend` (signs with a `kid` header, verifies by `kid` across all published keys, RS256 only, iss/aud). Access/refresh token classes. Token-pair issuing. Revocation helpers |
| `sso/views.py` | login, refresh, logout, logout-all, me, introspect, JWKS, discovery, healthz |
| `sso/serializers.py` | Login/refresh/introspect input. `UserSerializer`. Username-or-email credential check with a timing-safe dummy hash |
| `sso/authentication.py` | Bearer access-token auth (honours revocation). HTTP Basic auth for `ServiceClient` |
| `sso/throttles.py` | `LoginIPThrottle` (10/min), `LoginUserThrottle` (5/min per lowercased username/email), `RefreshThrottle` (60/min) |
| `sso/errors.py` | Uniform `{"error","detail"}` handler for DRF and Django-level errors |
| `sso/logs.py` | One structured JSON log line per login attempt (username, IP, result). Never tokens or passwords |
| `sso/models.py` | `ServiceClient`, `UserTokenRevocation`, `AuthorizationCode` (phase 5, unused) |
| `sso/signals.py` | A password change made through this project revokes the user's tokens. A login rehash does not |
| `sso/admin.py` | ServiceClient admin. The secret is generated and shown once; only its hash is stored |
| `sso/management/commands/create_service_client.py` | CLI registration and secret rotation |
| `sso/checks.py`, `sso/runtime.py` | System checks (Errors) with `SSO_DEBUG=False`: `sso.E001` per-process/no-op cache, `sso.E002` running as root |
| `sso/migrations/0001_initial.py` | SSO's own tables (`sso_*`) |
| `application/` | Central application permissions (`application.<codename>`, §6a): `ApplicationAccess` anchor model, SSO-side permission registry, `create_app_permission` command, read-only admin, post-migrate re-sync. Its migration only creates `sso_application_*` tables |
| `sso/tests/` | pytest suite (see §9 for the spec §11 mapping) |
| `examples/verifier/` | Spec §8.2 PyJWT verifier (`sso_verifier.py`, with `JWKSCache`: keys cached 1 h, an unknown `kid` refetches the JWKS at most once per 60 s, spec §8.1) plus a FastAPI demo (`verifier_app.py`) and its Dockerfile |
| `examples/frontend/` | `index.html` test page plus the spec §7.2 `auth.js` (SSO base URL configurable) |
| `scripts/gen_keys.sh` | RSA key pair (default 3072-bit). Prints the `kid`. Refuses to overwrite |
| `scripts/gen_selfsigned_cert.sh`, `scripts/dev_setup.sh` | Local dev TLS cert, keys and `.env` |
| `scripts/test_both_django.sh` | Runs the suite on Django 5.2 (shipped) and Django 4.2 (portability check only); `PYTHON=` picks the interpreter |
| `Dockerfile`, `.dockerignore`, `docker/healthcheck.py` | Production image (Python 3.13 / Debian trixie, multi-stage, non-root `SSO_UID:SSO_GID` default 10001, no keys inside) |
| `docker-compose.yml` | Production/staging: `web` + `redis` + `nginx`. No DB container |
| `docker-compose.dev.yml`, `docker/nginx-dev.d/` | Local overlay: self-signed TLS, MySQL `MYSQL_IMAGE` (default 8.0, 8.4 supported; sso_app/sso_migrator), demo page, verifier |
| `docker-compose.test.yml`, `docker/Dockerfile.test` | Local/QA MySQL (`MYSQL_IMAGE`, default `mysql:8.0`, also meant for `mysql:8.4`) and a pytest run against it, incl. `sso/tests/test_mysql_integration.py` |
| `docker/mysql-init/01-sso-accounts.sh` | Local MySQL init: creates `sso_app` (DML only) and `sso_migrator` (DDL) like prod |
| `docker/nginx.conf` | nginx template: TLS 1.2/1.3, port-aware redirect, 444 default server, proxy headers, ACME, admin allow-list hook, login rate limit |
| `docker/nginx-admin.d/`, `mysql-ca/` | Mount points for the optional admin allow-list and the DB CA certificate |
| `requirements.txt` / `requirements.lock` / `requirements-dev.txt` | Ranges, exact image pins (Django 5.2 only), test deps |
| `.env.example`, `.env.dev.example`, `.env.test.example` | Every environment variable, documented (placeholders only) |

## 2. Local setup and tests

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt     # Python 3.13 (= the image)
.venv/bin/pytest                      # SQLite, prints the coverage report for sso/
scripts/test_both_django.sh           # Django 5.2 (.venv) and Django 4.2 (.venv-dj42), both with --cov-fail-under=90
PYTHON=python3.13 scripts/test_both_django.sh   # explicit interpreter -> .venv-py<version>-dj52 / -dj42
```
Without a system 3.13, `uv python install 3.13` gives one (no sudo); pass its path as `PYTHON=`. A venv built
with another Python version is never reused; the script stops and says so.
The tests need no database server and no key files. `ssoproject/settings_test.py` generates throw-away keys.
`mysqlclient` is needed only for MySQL (`requirements.txt`, the Docker image, `docker-compose.test.yml`).

MySQL integration run (needs Docker; passwords come from the git-ignored `.env.test`). Production is on
MySQL **8.0** today and moves to **8.4** later, so run it on both. `MYSQL_IMAGE` picks the server
(default `mysql:8.0`; `QA_MYSQL_TAG=8.0|8.4` from the deployment plan also works). Each version needs its own
data volume (`SSO_TEST_MYSQL_VOLUME`): 8.0 cannot open an 8.4 data directory, and 8.4 upgrades an 8.0 one in place.
```bash
scripts/dev_setup.sh          # creates .env.test once (random passwords)
T='docker compose --env-file .env.test -f docker-compose.test.yml'
$T run --rm --build tests                                                          # MySQL 8.0
MYSQL_IMAGE=mysql:8.4 SSO_TEST_MYSQL_VOLUME=sso-test-mysql-8.4 $T run --rm --build tests   # MySQL 8.4
$T down -v                    # throw the 8.0 data away (repeat with the 8.4 variables for 8.4)
```
`sso/tests/test_mysql_integration.py` (skipped on SQLite) then checks the server version (8.0.x ≥ 8.0.11 or
8.4.x, and that it matches `MYSQL_IMAGE`), that the init-script accounts use `caching_sha2_password`, that
the client library logs in with them, that `sso_app` has DML grants only, and that `SSO_DB_SSL_MODE=REQUIRED`
works against the server's auto-generated certificates. The init script's SQL is valid on 8.0.4+ and 8.4.

Run the server locally without Docker (SQLite, plain HTTP):
```bash
scripts/gen_keys.sh /tmp/ssokeys dev 2048
cat > .env <<'X'
SSO_SECRET_KEY=change-me-to-a-long-random-string-of-50-plus-characters-xxxxxxxx
SSO_DEBUG=False
SSO_ALLOWED_HOSTS=localhost,127.0.0.1
SSO_ISSUER=http://127.0.0.1:8000
SSO_DB_ENGINE=sqlite
SSO_KEYS_DIR=/tmp/ssokeys
SSO_JWT_PRIVATE_KEY=dev.private.pem
SSO_JWT_PUBLIC_KEYS=dev.public.pem
SSO_CORS_ALLOWED_ORIGINS=http://127.0.0.1:5500
SSO_SSL_REDIRECT=False
SSO_COOKIE_SECURE=False
# SSO_DEBUG=False needs a shared cache; without Redis a file cache works for one host
SSO_CACHE_URL=filecache:///tmp/sso-cache
X
.venv/bin/python manage.py migrate && .venv/bin/python manage.py createsuperuser
.venv/bin/gunicorn ssoproject.wsgi:application -b 127.0.0.1:8000     # gunicorn comes with requirements-dev.txt
curl -s http://127.0.0.1:8000/healthz                                 # {"status":"ok"}
```
Run it as a normal user: with `SSO_DEBUG=False` the server and `manage.py` refuse to start as root (uid 0).
With `SSO_DEBUG=True` the server also starts without key files. It then uses an **ephemeral** in-memory
key and logs a warning, and tokens become invalid on every restart.

## 3. Environment variables

The complete annotated list is in `.env.example`. The most important ones:

| Variable | Default | Notes |
|---|---|---|
| `SSO_SECRET_KEY` | — | **Required** unless `SSO_DEBUG=True`. Does not need to match myFinance (spec §4.8) |
| `SSO_DEBUG` | `False` | |
| `SSO_ALLOWED_HOSTS` | — | Comma list. The first entry is also the Host header the container healthcheck sends |
| `SSO_ISSUER` | — | **Required.** The public base URL, which becomes the JWT `iss` and the root of the discovery URLs. No domain is built into the code |
| `SSO_AUDIENCE` | `myfin-services` | JWT `aud` (access and refresh tokens) |
| `SSO_SUPERUSER_ALL_APPS` | `false` | Superusers administer users; like everybody else they get only their explicit `application.*` grants (user or group) in `perms` (§6a). `true` (opt-in): every active superuser gets all `application.*` permissions |
| `SSO_DB_ENGINE` | `mysql` | `mysql` or `sqlite` |
| `SSO_DBHOST` / `SSO_DBPORT` / `SSO_DBNAME` / `SSO_DBUSER` / `SSO_DBPWD` | `127.0.0.1` / `3306` / `dcWebUsers` / — / — | MySQL connection (runtime account `sso_app`, DML only) |
| `SSO_DB_SSL_CA` / `SSO_DB_SSL_MODE` | — / — | Optional DB TLS. With a CA, the mode defaults to `VERIFY_CA`. Modes: `DISABLED`, `PREFERRED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`. A missing CA file stops start-up |
| `SSO_KEYS_DIR` | `./keys` (compose) | The host folder with the key files; compose mounts it read-only at `/run/keys`. Without Docker it is where key names resolve (unless `SSO_JWT_KEYS_MOUNT` is set) |
| `SSO_JWT_KEYS_MOUNT` | `SSO_KEYS_DIR`, else `/run/keys` | Directory key names resolve in. Precedence: `SSO_JWT_KEYS_MOUNT` > `SSO_KEYS_DIR` > `/run/keys`; relative = relative to the working directory. Compose pins it to `/run/keys` for `web` |
| `SSO_JWT_PRIVATE_KEY` | — | **Required.** Signing key file name, e.g. `sso-2026-10.private.pem`. A value with `/` is a path (absolute, or relative to the working directory) |
| `SSO_JWT_PUBLIC_KEYS` | — | Comma list of file names of **all** published or accepted public keys (rotation: append). The signing key's own public key is always published even if not listed |
| `SSO_JWT_PRIVATE_KEY_PATH` / `SSO_JWT_PUBLIC_KEY_PATHS` | — | **Deprecated** full-path forms (and the v1.0 singular `SSO_JWT_PUBLIC_KEY_PATH`). Still read, with warning `sso.W001` (logged once per process). Setting one together with its new form is an `ImproperlyConfigured` error |
| `SSO_ACCESS_TTL_MIN` / `SSO_REFRESH_TTL_DAYS` | `15` / `7` | |
| `SSO_CORS_ALLOWED_ORIGINS` | — | Front-end origins. Also the allow-list for the cookie-mode `Origin` check |
| `SSO_COOKIE_DOMAIN` | host-only | e.g. `.example.com` so sibling sub-domains share the cookie |
| `SSO_CACHE_URL` | none (`locmemcache://` only when `SSO_DEBUG=True`) | Throttle counters, shared by all gunicorn workers. **Required when `SSO_DEBUG=False`**: empty, `locmemcache://` or `dummycache://` stop the server at startup (`ImproperlyConfigured`), and `manage.py check` reports `sso.E001` if `CACHES` is overridden to one of them. `docker-compose.yml` defaults it to `redis://redis:6379/0`; on a single host without Redis use `filecache:///path`. Keys are prefixed with `sso` |
| `SSO_NUM_PROXIES` | `0` | DRF `NUM_PROXIES`. `0` ignores `X-Forwarded-For` (safe when gunicorn is reached directly). `docker-compose.yml` defaults it to `1` (overridable from `.env`): nginx **overwrites** `X-Forwarded-For` and `web` is not published, so the right-most entry is the real client IP. Never set `1` when clients can reach gunicorn directly or the proxy appends to a client-supplied header: they could then pick their own IP and bypass the per-IP throttle |
| `SSO_FORWARDED_ALLOW_IPS` | `127.0.0.1` (image) | gunicorn `--forwarded-allow-ips`: comma list of IPs/CIDRs whose `X-Forwarded-Proto` is trusted. Compose sets it to the `edge` network (`SSO_EDGE_SUBNET`, default `172.31.250.0/24`), where nginx is the only other container. Never `*` |
| `SSO_ADMIN_PATH` | `sso-admin/` | Admin is not served at `/admin/` |
| `SSO_SSL_REDIRECT`, `SSO_HSTS_SECONDS`, `SSO_COOKIE_SECURE`, `SSO_THROTTLE_*`, `SSO_LOG_LEVEL` | secure defaults | Overrides for dev and tuning |
| Deployment parameters / compose only: `SSO_DOMAIN`, `SSO_HOSTNAME`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`, `DOCKER_USER` (default `thomaschoi`), `IMAGE_TAG` (default `latest`; pin e.g. `0.1.0` on servers), `SSO_UID`/`SSO_GID` (container user, default `10001`, never 0), `MYSQL_IMAGE` / `SSO_TEST_MYSQL_VOLUME` / `SSO_DEV_MYSQL_VOLUME` (test/dev MySQL), `GUNICORN_WORKERS`, `SSO_KEYS_DIR`, `SSO_CERTS_DIR`, `SSO_TLS_CERT_FILE`, `SSO_TLS_KEY_FILE`, `SSO_ACME_WEBROOT`, `SSO_MYSQL_CA_DIR`, `SSO_ADMIN_ALLOW_DIR`, `SSO_EDGE_SUBNET` (fixed subnet of the nginx↔web network; change it if it collides with a host network) | | Deployment plan §0. Nothing host-specific is built into code, compose or nginx. The derived app values (`SSO_ISSUER`, origins, cookie domain) are written out in `.env` |

With `SSO_DEBUG=False`, the process **refuses to start** (`ImproperlyConfigured` with a clear message) if any
of these is true: `SSO_SECRET_KEY` or `SSO_ISSUER` is empty, a key file is missing or unreadable, or a key
is not RSA or is under 2048 bits.

## 4. Key generation and rotation

```bash
scripts/gen_keys.sh /opt/sso/keys sso-2026-10          # 3072-bit default. Prints kid=<16 hex>
sudo chown 10001:10001 /opt/sso/keys/sso-2026-10.*.pem  # = SSO_UID:SSO_GID; the container user must read the key
```
The script uses `umask 077`, writes `<name>.private.pem` (0600) and `<name>.public.pem`, and never
overwrites existing files. Its `kid` (`openssl pkey -pubin -outform DER | sha256sum | cut -c1-16`) is
tested to equal the server's `kid`.

Rotation follows deployment plan §11 and spec §5.3:
1. Generate the new pair into `SSO_KEYS_DIR`. Append the new public key to `SSO_JWT_PUBLIC_KEYS`
   (`sso-2026-10.public.pem,sso-2027-10.public.pem`; the old key keeps signing). Recreate `web`. JWKS now lists both kids.
2. After ≥ 24 h, set `SSO_JWT_PRIVATE_KEY` to the new private key's name and recreate `web`. Refresh and
   access tokens signed with the old key **stay valid** because verification picks the key by `kid`. A
   test covers this (`test_rotation_refresh_token_signed_with_old_key_still_refreshes`).
3. After ≥ 8 days (15 min + refresh TTL + margin), remove the old public key and recreate. Shred the old private key.

## 5. Database: first deployment and migrate procedure

`dcWebUsers` is shared with myFinance. This project uses the stock `auth.User` and adds only the
`sso_*` and `token_blacklist_*` tables. A test asserts that `makemigrations --check` is clean, that the
only migrations this project owns are `sso`, `application` and `token_blacklist`, and that the shared apps sit at the
same leaf migrations as Django 4.1 (so `migrate` does nothing to them).

**Never** run `clearsessions` or `remove_stale_contenttypes` from this project. `django_session` and
`django_content_type` are shared with myFinance. **And never run `remove_stale_contenttypes` in myFinance
either** once SSO is migrated: see the warning in §6a.

1. **Back up first** (spec §4.6). Keep credentials in an options file so they stay out of `ps`:
   ```bash
   TS=$(date +%Y%m%dT%H%M%S)
   mysqldump --defaults-extra-file=~/.my-dcweb.cnf --single-transaction --quick --routines --triggers \
     --events --hex-blob --no-tablespaces --set-gtid-purged=OFF --default-character-set=utf8mb4 \
     dcWebUsers | gzip -9 > dcWebUsers-pre-sso-$TS.sql.gz
   gzip -t dcWebUsers-pre-sso-$TS.sql.gz && zcat dcWebUsers-pre-sso-$TS.sql.gz | tail -n 1   # "-- Dump completed"
   mysql --defaults-extra-file=~/.my-dcweb.cnf -e 'SELECT COUNT(*) FROM dcWebUsers.auth_user'  # baseline
   ```
   Store the dump encrypted and off the host. It contains every password hash.
2. **Review the plan** using the migration account (DDL rights only during this window):
   ```bash
   docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python manage.py migrate --plan
   ```
   **Stop** unless the plan lists only `sso.*`, `application.*` and `token_blacklist.*`.
3. **Migrate**: `docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python manage.py migrate`.
   The post-migrate step also inserts rows into `django_content_type` and `auth_permission` for the new
   apps (including `application.app1`). That only adds rows and does not affect myFinance.
4. Verify: `SELECT COUNT(*) FROM auth_user` is unchanged. Log in with an existing account through the
   API **and** through myFinance.

The container **never** runs migrations on its own. The runtime DB account needs only `SELECT, INSERT,
UPDATE, DELETE`. That covers `flushexpiredtokens`, `last_login`, and the PBKDF2 rehash on login.

## 6. Registering a ServiceClient (for `/api/v1/auth/introspect`)

* Admin: `https://<host>/<SSO_ADMIN_PATH>sso/serviceclient/add/`. Enter `client_id` (a slug) and a name,
  then save. The generated secret appears **once** in the confirmation message. Tick
  "regenerate secret" to rotate it.
* CLI: `docker compose exec web python manage.py create_service_client rebalance-api --name "Rebalance API"`
  prints `client_id=…` and `client_secret=…` once. Add `--rotate-secret` to issue a new one.

Hand the secret to the service owner through the password manager. The service calls
`POST /api/v1/auth/introspect` with HTTP Basic `client_id:client_secret` and the body `{"token": "<access token>"}`.

## 7. Docker

**Production/staging** (`docker-compose.yml`): `web` (gunicorn, non-root `SSO_UID:SSO_GID`, read-only root fs, keys mounted
read-only at `/run/keys`), `redis` (internal network, no persistence), and `nginx` (the only published
service, with ports from `SSO_HTTP_PORT` / `SSO_HTTPS_PORT`). MySQL is remote (8.0 now, 8.4 later). The
image is `python:3.13.16-slim-trixie` (Debian 13) because its `libmariadb3` ships the `caching_sha2_password`
client plugin, the default auth plugin for new accounts on both MySQL 8.0 and 8.4. The Dockerfile fails the
build if the plugin is missing.
```bash
cp .env.example .env && chmod 600 .env     # fill in. SSO_HOSTNAME is required; set IMAGE_TAG (e.g. 0.1.0)
docker compose config --images             # -> thomaschoi/sso-server:<IMAGE_TAG>; check before up
docker compose build && docker compose up -d && docker compose ps
```
**Image name.** `image: ${DOCKER_USER:-thomaschoi}/sso-server:${IMAGE_TAG:-latest}`. Compose takes these (and every
other `${...}` in the file) from `.env`, but an **exported shell variable of the same name wins** over `.env`;
`docker compose config --images` shows the result. Pin `IMAGE_TAG` on servers rather than relying on `latest`.

**Container user.** `web` runs as `SSO_UID:SSO_GID` (default `10001:10001`): the same values are the image build
args (the user is created at build time) and compose's `user:`. Set them to the owner of the host key files so the
private key can stay `0600`; the build refuses 0 (root) and a uid that already exists in the base image. If you
change them, rebuild (`docker compose build`) so the image's user matches `user:`. (The app files are root-owned
and read-only, so a mismatch would still run; it just leaves the uid without a passwd entry.) A pre-built image
pulled from Docker Hub has the default 10001: keep `SSO_UID`/`SSO_GID` unset and chown the keys to 10001. With `SSO_DEBUG=False` the
process also refuses to start as uid 0 (`ImproperlyConfigured` at settings load, plus system check `sso.E002`), so a
`docker run --user 0` or a host-side `sudo manage.py …` fails loudly; run commands via `docker compose exec/run web …`,
which use `user:`. The build's `collectstatic` runs as root but with a throw-away `SSO_DEBUG=True` config, so the
guard does not affect it; the test image (`docker/Dockerfile.test`) runs pytest as uid 10001. There is no root
entrypoint that drops privileges: the
container starts as the unprivileged user and never needs root (keys are read-only mounts, the root fs is read-only).
**Proxy trust and the shared-host-nginx variant.** `SSO_NUM_PROXIES` defaults to `1` in compose and can be
set in `.env`. If a host-level nginx sits in front of the compose nginx, that host nginx **must overwrite**
`X-Forwarded-For` (`proxy_set_header X-Forwarded-For $remote_addr;`), not append to it with
`$proxy_add_x_forwarded_for`. Otherwise a client can put any IP in the header and get around the per-IP
throttle. Set `SSO_NUM_PROXIES` to match the number of trusted hops, and add the host nginx's address to
`SSO_FORWARDED_ALLOW_IPS` if it talks to gunicorn directly.

**Throttle counters aren't atomic.** DRF's throttles read and then write the cache entry, so a parallel burst
across gunicorn workers can let one extra request (roughly one per worker) through before the limit
applies. In compose, nginx `limit_req` on the login location (`docker/nginx.conf`: 30 r/min per IP,
burst 10, 429) puts a hard per-IP bound in front of it. Deployments without that nginx should add an
equivalent limit at their proxy.

Daily cron on the host (deployment plan §10):
`30 3 * * * cd /opt/sso && docker compose exec -T web python manage.py flushexpiredtokens`

**Local dev with self-signed TLS** (`docker-compose.dev.yml`). The order follows deployment plan §2.1:
```bash
scripts/dev_setup.sh                                  # keys, cert, .env, .env.test
set -a; . ./.env.test; set +a
alias dc='docker compose -f docker-compose.yml -f docker-compose.dev.yml'
dc up -d --build db redis
M="-e SSO_DBUSER=sso_migrator -e SSO_DBPWD=$SSO_TEST_MIGRATOR_PASSWORD"
for app in contenttypes auth admin sessions; do dc run --rm $M web python manage.py migrate $app; done  # = myFinance's tables
# optional: QA seed (qa/tests/fixtures/seed_test_data.py), as in §2.1 step 2
dc run --rm $M web python manage.py migrate --plan     # must list only sso + token_blacklist
dc run --rm $M web python manage.py migrate
dc run --rm $M web python manage.py createsuperuser
dc up -d --build
# test page: https://localhost:8443/demo/   demo API: https://localhost:8443/verifier/me
```
The web container itself runs as `sso_app` (DML only).
`cp docker-compose.dev.yml docker-compose.override.yml` makes a plain `docker compose up` use the overlay.
The override file is gitignored, so it can never reach a server checkout.

<a id="troubleshooting-key-ownership"></a>
**Troubleshooting: key ownership (e.g. WSL, where your user is uid 1000).** The container reads the keys
as `SSO_UID:SSO_GID` (default `10001:10001`), not as you. If the key files or the keys directory belong to
your host user (`id -u` is usually `1000` in WSL) with mode 0600/0700, `web` stops at startup with
`JWT private key (SSO_JWT_PRIVATE_KEY='sso-2026-10.private.pem' in SSO_JWT_KEYS_MOUNT='/run/keys')
'/run/keys/sso-2026-10.private.pem' exists but is not readable by uid 10001; chown to SSO_UID:SSO_GID or set SSO_UID` (or `cannot be reached by uid 10001` when the directory is the
problem). Check numeric owners and modes:
```bash
ls -n keys/          # columns 3/4 = uid/gid; compare with SSO_UID/SSO_GID (default 10001)
ls -nd keys/         # the directory must be enterable (x) by that uid too
```
Fix it one of two ways:
1. Give the keys to the container user (works with the pre-built Docker Hub image):
   `sudo chown 10001:10001 keys/ keys/*.pem && chmod 0700 keys/ && chmod 0600 keys/*.private.pem`.
2. Or run the container as yourself: put `SSO_UID=$(id -u)` and `SSO_GID=$(id -g)` (e.g. `1000`) in `.env`, then
   **rebuild** (`docker compose build web && docker compose up -d`), since the image's user is created at build time.
The private key should be `0600` (owner only) or `0640` (owner + the `SSO_GID` group); never world-readable.
The public keys may be `0644`.

## 6a. Application permissions (`application.<codename>`)

One permission per application, checked by that application in the access token's `perms` claim
(docs/sso-integration-design.md). `application.app1` = llm-wiki-svc, created by `migrate`.

* **Grant:** admin → Users (or Groups) → "user permissions" / "group permissions" → pick
  `application | application access | Can use app1 (llm-wiki-svc)`. Direct and group grants both count;
  by default superusers get only explicit grants (see below); inactive users have none.
  Shell alternative: `u.user_permissions.add(Permission.objects.get(content_type__app_label="application", codename="app1"))`.
* **Takes effect** at the user's next token refresh (access tokens live ≤ 15 min); `/me` and `/introspect` show it at once.
* **Add an application (no code change):**
  `docker compose exec web python manage.py create_app_permission app2 "Can use app2 (reports)"`.
  Idempotent (re-running only updates the description, grants are kept). Codename `^[a-z][a-z0-9_]{1,62}$`.
* **See them:** admin → Applications → "Application permissions" (read-only list with grant counts) and
  "Application permission records" (the SSO-side registry).
* Tokens export only `application.*` permissions, never the full Django permission list. `perms` is always
  present (`[]` when the user has none).
* Superusers administer `dcWebUsers`; they get **no automatic app access**. `perms` is computed from real
  permission rows (the user's own grants plus their groups', filtered to `application.*`), never from
  Django's `get_all_permissions()` / `has_perm()`, which return everything for a superuser. Grant a
  superuser an app like any other user. `SSO_SUPERUSER_ALL_APPS=true` restores the old all-apps rule.
* Grant revocation takes effect at the next refresh, i.e. up to the access-token lifetime (15 min); accepted.

**Server-side logins (apps like llm-wiki-svc).** An app that calls `/api/v1/auth/login` and `/refresh` from
its server would make every one of its users share the app's per-IP throttle. Register it as a ServiceClient
(§6) and have it send HTTP Basic `client_id:client_secret` plus `"client_ip": "<end user's IP>"` in the JSON
body: then the per-IP throttle and the login log use `client_ip`. Without an `Authorization: Basic` header
`client_ip` is ignored and the request is handled as before, from the caller's address. Design v1.2: a Basic
header that does not authenticate an active ServiceClient (wrong secret, unknown or inactive client) is refused
with 401 `invalid_client` (no silent fallback); valid credentials with a `client_ip` that is not an IP address
get 400 `invalid_request`; valid credentials without `client_ip` use the caller's address. The per-username
throttle is unchanged. A leaked client secret lets its holder choose the IP that is throttled; accepted (the
per-username throttle still applies) - rotate it with `create_service_client <id> --rotate-secret`.

> **WARNING: shared `django_content_type` / `auth_permission`.** These tables belong to myFinance as much as
> to SSO. Running **`manage.py remove_stale_contenttypes` in myFinance** (which does not know the
> `application` app) deletes the `application.applicationaccess` content type, and the database
> CASCADE-deletes every `application.*` permission **and every user/group grant of them**: everybody loses access
> to every app at once. On the next `manage.py migrate`, SSO's post-migrate step recreates the **code-defined**
> permissions (`application.app1`) and logs an ERROR "ALL GRANTS ... WERE LOST" on logger `sso.application`,
> listing every lost permission. **Command-created permissions (`create_app_permission`, e.g. app2) are not
> recreated** (design v1.1, Q-13): they are named in that ERROR once (SSO's registry,
> `sso_application_permission_record`, remembers them) and you re-run `create_app_permission` for those still
> wanted. **Grants cannot be recovered** either way: re-assign them (or restore `auth_user_user_permissions` /
> `auth_group_permissions` from the backup). Tell the myFinance maintainers never to run
> `remove_stale_contenttypes` (or to answer "no" for `application`).

## 8. API summary

| Method and path | Auth | Notes |
|---|---|---|
| `POST /api/v1/auth/login` | — | `{username\|email, password, client: browser\|native}`. Throttled 10/min/IP and 5/min/username |
| `POST /api/v1/auth/refresh` | refresh token (body or cookie plus allowed `Origin`) | Rotates. Rejects tokens that are blacklisted, revoked, or belong to inactive users |
| `POST /api/v1/auth/logout` | same | 204. Blacklists the token and clears the cookie |
| `POST /api/v1/auth/logout-all` | Bearer access | 204. Blacklists all refresh tokens and sets `UserTokenRevocation` |
| `GET /api/v1/auth/me` | Bearer access | Fresh from the DB |
| `POST /api/v1/auth/introspect` | Basic (ServiceClient) | `{"active": true, sub, username, email, is_staff, groups, perms, iat, exp, …}` or `{"active": false}` |
| `GET /.well-known/jwks.json` | — | All public keys. `Cache-Control: public, max-age=3600` |
| `GET /.well-known/openid-configuration` | — | `token_endpoint` = `/api/v1/auth/login`. No `authorization_endpoint` until phase 5 |
| `GET /healthz` | — | `200 {"status":"ok"}`, or `503 {"error":"unhealthy","detail":"database"}` |

Error codes: `invalid_request` 400, `invalid_credentials` 401, `token_invalid` 401, `invalid_client` 401,
`account_inactive` 403, `origin_not_allowed` 403, `forbidden` 403, `not_found` 404, `method_not_allowed` 405,
`unsupported_media_type` 415, `rate_limited` 429 (with `Retry-After`), `server_error` 500.

## 9. Spec §11 test mapping

| Spec §11 item | Test(s) |
|---|---|
| Legacy Django 4.1 PBKDF2 hash | `test_login.py::test_login_ok_native_with_legacy_django41_hash` (fixture `pbkdf2_sha256$390000$…`); corrupt hashes (QA LEGACY-06): `test_login_corrupt_stored_hash_is_401_not_500` |
| login ok / wrong password / unknown user / inactive user | `test_login.py::test_login_ok_*`, `test_login_wrong_password`, `test_login_unknown_user_same_error_and_runs_dummy_hash`, `test_login_inactive_user*` |
| email login | `test_login_by_email_case_insensitive`, `test_login_by_email_duplicate_rejected`, `test_empty_email_never_matches`, `test_login_unknown_email_runs_dummy_hash` |
| throttling | `test_throttle_per_ip`, `test_throttle_per_username_across_ips`, `test_throttle_uses_x_forwarded_for_with_one_proxy`, `test_x_forwarded_for_ignored_with_zero_proxies`; fail-fast cache: `test_keys_settings.py::test_settings_fail_fast_without_shared_cache` |
| refresh rotation (old token rejected on reuse) | `test_token_flow.py::test_refresh_rotation_old_token_rejected_on_reuse`, `test_cookie_mode.py::test_cookie_refresh_with_allowed_origin_rotates_cookie` |
| logout blacklists | `test_logout_blacklists_refresh_token`, `test_cookie_logout_checks_origin_then_clears_cookie` |
| logout-all and introspect after revocation | `test_logout_all_blacklists_everything_and_revokes`, `test_introspect.py::test_introspect_inactive_after_logout_all` |
| access token rejected at /refresh | `test_access_token_rejected_at_refresh` |
| refresh token rejected by the §8.2 verifier | `test_verifier.py::test_verifier_rejects_refresh_token` |
| verifier JWKS refetch ≤ 1/min on unknown kid (§8.1) | `test_verifier.py::test_unknown_kid_refetches_at_most_once_per_minute`, `test_rotation_new_kid_picked_up_by_refetch` |
| JWKS `kid` matches the token header | `test_discovery_errors.py::test_jwks_lists_all_public_keys_and_kid_matches_token_header` |
| expired and wrong aud/iss rejected | `test_refresh_rejects_bad_claims`, `test_me_rejects_expired_wrong_aud_iss`, `test_verifier_rejects_expired_wrong_aud_iss`, `test_introspect_inactive_cases` |
| cookie mode HttpOnly/Secure + Origin | `test_cookie_mode.py::test_browser_login_sets_hardened_cookie_and_omits_body_token`, `test_cookie_refresh_requires_allowed_origin` |
| Addendum B.11 migrations | `test_migrations.py` (all) |
| Deployment plan R14 rotation | `test_rotation_refresh_token_signed_with_old_key_still_refreshes` |
| Addendum B.12 fail-fast / R13 `check --deploy` | `test_keys_settings.py::test_settings_fail_fast_in_non_debug`, `test_deploy_check_passes_with_prod_like_env` |

## 10. Design decisions and deviations (summary)

* **Inactive users** are authenticated with `AllowAllUsersModelBackend`. Exactly one hash runs in every
  case. The 403 `account_inactive` answer is given **only when the password is correct**; a wrong password
  gives 401.
* **Revocation granularity**: `iat` is in whole seconds. A token counts as revoked if `iat < ceil(revoked_at)`.
  A login in the same second as a revocation waits under 1 s, so its new tokens are valid.
* **Revocation at the SSO server itself**: `/me` and `/logout-all` reject access tokens issued before a
  revocation. Other services still see such tokens as valid until they expire (≤ 15 min) unless they introspect.
* **Refresh issues a fresh pair from the DB**, so group changes take effect at the next refresh. The
  blacklist write is the race guard: if two refreshes use the same token at once, only one succeeds.
* **Introspect** returns current DB values for username, email, groups and is_staff, plus `iat`, `exp`,
  `iss`, `aud` and `client_id`.
* **Corrupt stored hashes** (e.g. `pbkdf2_sha256$notanumber$…`, or a missing digest) make Django's hasher
  raise. Login treats that as a wrong password: one dummy hash, 401 `invalid_credentials`, an extra
  `sso.auth` log line `result=stored_hash_invalid` (no hash, no password), and the row is left unchanged.
* **Logout** in cookie mode with no cookie returns 204. With an invalid token it returns 401
  `token_invalid` and still clears the cookie.
* **JSON-only parser** (no form or multipart), so a cross-site form POST cannot reach the API. Form posts get 415.
* **`/admin/` is moved** to `SSO_ADMIN_PATH` (default `sso-admin/`).
* **HSTS preload** deploy-check warning (`security.W021`) is silenced. Preloading binds the whole domain,
  so the domain owner should decide it.
* **WhiteNoise** serves the admin static files (collected at image build).
* **Extra error codes** beyond spec §6.0: `invalid_client`, `origin_not_allowed`, `forbidden`, `not_found`,
  `method_not_allowed`, `unsupported_media_type`, `server_error`, and `unhealthy` (healthz).
* **The dev stack is an overlay file** (`docker-compose.dev.yml`), not an auto-loaded override, so a
  server checkout can never pick up dev settings (deployment plan R24).

## 11. Open questions

1. ~~MySQL version of production `dcWebUsers`~~ **Answered (updated): MySQL 8.0 now, 8.4 later** (team lead,
   2026-10-10). The code, init script and settings are written for both; the test compose defaults to `mysql:8.0`.
   MySQL 8.0 reached end of life in April 2026 (the `mysql:8.0` image was last updated 2026-05), so the 8.4
   upgrade should not wait long. Django 5.2 only is shipped (`requirements.lock`); the suite still passes on 4.2
   as a portability check. Still to confirm: prod's exact 8.0 patch level (≥ 8.0.11) and that `auth_user` is InnoDB.
2. Public host name, domain, ports and DB host/port are **undecided** (deployment plan §0). Everything is
   set through env (`SSO_HOSTNAME`, `SSO_DOMAIN`, `SSO_HTTP(S)_PORT`, `SSO_ISSUER`, `SSO_ALLOWED_HOSTS`,
   `SSO_DBHOST`, `SSO_DBPORT`). `.env.example` uses `example.com` placeholders. Changing the issuer after
   go-live invalidates every token.
3. DB TLS: the runtime image's Connector/C 3.4 would verify server certificates by default; mysqlclient
   2.3 maps `ssl_mode` onto that. `SSO_DB_SSL_MODE`/`SSO_DB_SSL_CA` exist (R28), but nothing has been tested
   against a real MySQL yet. The local MySQL accounts do **not** use `REQUIRE SSL`, because the container's
   auto-generated certificates are self-signed. Prod accounts should (plan §6.2), so the CA must be provided.
4. Password changes made **in myFinance** do not set `UserTokenRevocation` (it is a different process).
   Options: myFinance writes the revocation row, or introspect compares a password-hash fingerprint.
   That fingerprint would need care, because the login rehash changes the hash.
5. Should `/healthz` also check Redis and the keys (deployment plan Q16)? Should throttling fail open
   when Redis is down? Currently it fails closed (500).
6. Is HSTS preload wanted for the domain?
7. Should `ServiceClient.allowed_origins` feed CORS dynamically, or stay env-only (`SSO_CORS_ALLOWED_ORIGINS`)?
8. Redis 7.2 (BSD) vs Valkey 8 for the cache (deployment plan Q14).
9. Should the cookie-mode `Origin` check also cover `/login` (login-CSRF hardening)? It is not required by
   the addendum and is not implemented.
10. ~~QA seed R27 guard / real-domain origin in `qa/tests/conftest.py`~~ **Done by QA** (QA results §8).
