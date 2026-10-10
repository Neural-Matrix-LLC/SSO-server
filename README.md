# sso-server

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
| `sso/checks.py` | Deploy check `sso.W001`: LocMem cache used in production |
| `sso/migrations/0001_initial.py` | The only migration this project owns (new `sso_*` tables) |
| `sso/tests/` | pytest suite (see §9 for the spec §11 mapping) |
| `examples/verifier/` | Spec §8.2 PyJWT verifier (`sso_verifier.py`) plus a FastAPI demo (`verifier_app.py`) and its Dockerfile |
| `examples/frontend/` | `index.html` test page plus the spec §7.2 `auth.js` (SSO base URL configurable) |
| `scripts/gen_keys.sh` | RSA key pair (default 3072-bit). Prints the `kid`. Refuses to overwrite |
| `scripts/gen_selfsigned_cert.sh`, `scripts/dev_setup.sh` | Local dev TLS cert, keys and `.env` |
| `scripts/test_both_django.sh` | Runs the suite on Django 5.2 (shipped) and Django 4.2 (portability check only) |
| `Dockerfile`, `.dockerignore`, `docker/healthcheck.py` | Production image (multi-stage, uid 10001, no keys inside) |
| `docker-compose.yml` | Production/staging: `web` + `redis` + `nginx`. No DB container |
| `docker-compose.dev.yml`, `docker/nginx-dev.d/` | Local overlay: self-signed TLS, MySQL 8.4 (sso_app/sso_migrator), demo page, verifier |
| `docker-compose.test.yml`, `docker/Dockerfile.test` | Local/QA MySQL 8.4 and a pytest run against it |
| `docker/mysql-init/01-sso-accounts.sh` | Local MySQL init: creates `sso_app` (DML only) and `sso_migrator` (DDL) like prod |
| `docker/nginx.conf` | nginx template: TLS 1.2/1.3, port-aware redirect, 444 default server, proxy headers, ACME, admin allow-list hook, login rate limit |
| `docker/nginx-admin.d/`, `mysql-ca/` | Mount points for the optional admin allow-list and the DB CA certificate |
| `requirements.txt` / `requirements.lock` / `requirements-dev.txt` | Ranges, exact image pins (Django 5.2 only), test deps |
| `.env.example`, `.env.dev.example`, `.env.test.example` | Every environment variable, documented (placeholders only) |

## 2. Local setup and tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest                      # SQLite, prints the coverage report for sso/
scripts/test_both_django.sh           # Django 5.2 (.venv) and Django 4.2 (.venv-dj42), both with --cov-fail-under=90
```
The tests need no database server and no key files. `ssoproject/settings_test.py` generates throw-away keys.
`mysqlclient` is needed only for MySQL (`requirements.txt`, the Docker image, `docker-compose.test.yml`).

MySQL 8.4 integration run (needs Docker; passwords come from the git-ignored `.env.test`):
```bash
scripts/dev_setup.sh          # creates .env.test once (random passwords)
docker compose --env-file .env.test -f docker-compose.test.yml run --rm --build tests
docker compose --env-file .env.test -f docker-compose.test.yml down -v
```

Run the server locally without Docker (SQLite, plain HTTP):
```bash
scripts/gen_keys.sh /tmp/ssokeys dev 2048
cat > .env <<'X'
SSO_SECRET_KEY=change-me-to-a-long-random-string-of-50-plus-characters-xxxxxxxx
SSO_DEBUG=False
SSO_ALLOWED_HOSTS=localhost,127.0.0.1
SSO_ISSUER=http://127.0.0.1:8000
SSO_DB_ENGINE=sqlite
SSO_JWT_PRIVATE_KEY_PATH=/tmp/ssokeys/dev.private.pem
SSO_JWT_PUBLIC_KEY_PATHS=/tmp/ssokeys/dev.public.pem
SSO_CORS_ALLOWED_ORIGINS=http://127.0.0.1:5500
SSO_SSL_REDIRECT=False
SSO_COOKIE_SECURE=False
SSO_NUM_PROXIES=0
X
.venv/bin/python manage.py migrate && .venv/bin/python manage.py createsuperuser
.venv/bin/gunicorn ssoproject.wsgi:application -b 127.0.0.1:8000
```
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
| `SSO_DB_ENGINE` | `mysql` | `mysql` or `sqlite` |
| `SSO_DBHOST` / `SSO_DBPORT` / `SSO_DBNAME` / `SSO_DBUSER` / `SSO_DBPWD` | `127.0.0.1` / `3306` / `dcWebUsers` / — / — | MySQL connection (runtime account `sso_app`, DML only) |
| `SSO_DB_SSL_CA` / `SSO_DB_SSL_MODE` | — / — | Optional DB TLS. With a CA, the mode defaults to `VERIFY_CA`. Modes: `DISABLED`, `PREFERRED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`. A missing CA file stops start-up |
| `SSO_JWT_PRIVATE_KEY_PATH` | — | **Required.** Signing key |
| `SSO_JWT_PUBLIC_KEY_PATHS` | — | Comma list of **all** published or accepted public keys (rotation). The signing key's own public key is always included. The singular `SSO_JWT_PUBLIC_KEY_PATH` is still read as a fallback |
| `SSO_ACCESS_TTL_MIN` / `SSO_REFRESH_TTL_DAYS` | `15` / `7` | |
| `SSO_CORS_ALLOWED_ORIGINS` | — | Front-end origins. Also the allow-list for the cookie-mode `Origin` check |
| `SSO_COOKIE_DOMAIN` | host-only | e.g. `.example.com` so sibling sub-domains share the cookie |
| `SSO_CACHE_URL` | `locmemcache://` | Throttle counters. Use `redis://redis:6379/0` with more than one gunicorn worker. Keys are prefixed with `sso` |
| `SSO_NUM_PROXIES` | `1` | DRF `NUM_PROXIES`: the right-most `X-Forwarded-For` entry (set by nginx) is taken as the client IP |
| `SSO_ADMIN_PATH` | `sso-admin/` | Admin is not served at `/admin/` |
| `SSO_SSL_REDIRECT`, `SSO_HSTS_SECONDS`, `SSO_COOKIE_SECURE`, `SSO_THROTTLE_*`, `SSO_LOG_LEVEL` | secure defaults | Overrides for dev and tuning |
| Deployment parameters / compose only: `SSO_DOMAIN`, `SSO_HOSTNAME`, `SSO_HTTPS_PORT`, `SSO_HTTP_PORT`, `SSO_IMAGE_TAG`, `GUNICORN_WORKERS`, `SSO_KEYS_DIR`, `SSO_CERTS_DIR`, `SSO_TLS_CERT_FILE`, `SSO_TLS_KEY_FILE`, `SSO_ACME_WEBROOT`, `SSO_MYSQL_CA_DIR`, `SSO_ADMIN_ALLOW_DIR` | | Deployment plan §0. Nothing host-specific is built into code, compose or nginx. The derived app values (`SSO_ISSUER`, origins, cookie domain) are written out in `.env` |

With `SSO_DEBUG=False`, the process **refuses to start** (`ImproperlyConfigured` with a clear message) if any
of these is true: `SSO_SECRET_KEY` or `SSO_ISSUER` is empty, a key file is missing or unreadable, or a key
is not RSA or is under 2048 bits.

## 4. Key generation and rotation

```bash
scripts/gen_keys.sh /opt/sso/keys sso-2026-10          # 3072-bit default. Prints kid=<16 hex>
sudo chown 10001:10001 /opt/sso/keys/sso-2026-10.*.pem  # the container user must be able to read the key
```
The script uses `umask 077`, writes `<name>.private.pem` (0600) and `<name>.public.pem`, and never
overwrites existing files. Its `kid` (`openssl pkey -pubin -outform DER | sha256sum | cut -c1-16`) is
tested to equal the server's `kid`.

Rotation follows deployment plan §11 and spec §5.3:
1. Generate the new pair. Add the new public key to `SSO_JWT_PUBLIC_KEY_PATHS` (the old key keeps
   signing). Recreate `web`. JWKS now lists both kids.
2. After ≥ 24 h, point `SSO_JWT_PRIVATE_KEY_PATH` at the new private key and recreate `web`. Refresh and
   access tokens signed with the old key **stay valid** because verification picks the key by `kid`. A
   test covers this (`test_rotation_refresh_token_signed_with_old_key_still_refreshes`).
3. After ≥ 8 days (15 min + refresh TTL + margin), remove the old public key and recreate. Shred the old private key.

## 5. Database: first deployment and migrate procedure

`dcWebUsers` is shared with myFinance. This project uses the stock `auth.User` and adds only the
`sso_*` and `token_blacklist_*` tables. A test asserts that `makemigrations --check` is clean, that the
only migrations this project owns are `sso` and `token_blacklist`, and that the shared apps sit at the
same leaf migrations as Django 4.1 (so `migrate` does nothing to them).

**Never** run `clearsessions` or `remove_stale_contenttypes` from this project. `django_session` and
`django_content_type` are shared with myFinance.

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
   **Stop** unless the plan lists only `sso.*` and `token_blacklist.*`.
3. **Migrate**: `docker compose run --rm -e SSO_DBUSER -e SSO_DBPWD web python manage.py migrate`.
   The post-migrate step also inserts rows into `django_content_type` and `auth_permission` for the two
   new apps. That only adds rows and does not affect myFinance.
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

**Production/staging** (`docker-compose.yml`): `web` (gunicorn, uid 10001, read-only root fs, keys mounted
read-only at `/run/keys`), `redis` (internal network, no persistence), and `nginx` (the only published
service, with ports from `SSO_HTTP_PORT` / `SSO_HTTPS_PORT`). MySQL is remote. The image is Debian 13 slim
because its `libmariadb3` ships the `caching_sha2_password` client plugin that MySQL 8.4 accounts need. The
Dockerfile fails the build if the plugin is missing.
```bash
cp .env.example .env && chmod 600 .env     # fill in. SSO_IMAGE_TAG and SSO_HOSTNAME are required
docker compose build && docker compose up -d && docker compose ps
```
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

## 8. API summary

| Method and path | Auth | Notes |
|---|---|---|
| `POST /api/v1/auth/login` | — | `{username\|email, password, client: browser\|native}`. Throttled 10/min/IP and 5/min/username |
| `POST /api/v1/auth/refresh` | refresh token (body or cookie plus allowed `Origin`) | Rotates. Rejects tokens that are blacklisted, revoked, or belong to inactive users |
| `POST /api/v1/auth/logout` | same | 204. Blacklists the token and clears the cookie |
| `POST /api/v1/auth/logout-all` | Bearer access | 204. Blacklists all refresh tokens and sets `UserTokenRevocation` |
| `GET /api/v1/auth/me` | Bearer access | Fresh from the DB |
| `POST /api/v1/auth/introspect` | Basic (ServiceClient) | `{"active": true, sub, username, email, is_staff, groups, iat, exp, …}` or `{"active": false}` |
| `GET /.well-known/jwks.json` | — | All public keys. `Cache-Control: public, max-age=3600` |
| `GET /.well-known/openid-configuration` | — | `token_endpoint` = `/api/v1/auth/login`. No `authorization_endpoint` until phase 5 |
| `GET /healthz` | — | `200 {"status":"ok"}`, or `503 {"error":"unhealthy","detail":"database"}` |

Error codes: `invalid_request` 400, `invalid_credentials` 401, `token_invalid` 401, `invalid_client` 401,
`account_inactive` 403, `origin_not_allowed` 403, `forbidden` 403, `not_found` 404, `method_not_allowed` 405,
`unsupported_media_type` 415, `rate_limited` 429 (with `Retry-After`), `server_error` 500.

## 9. Spec §11 test mapping

| Spec §11 item | Test(s) |
|---|---|
| Legacy Django 4.1 PBKDF2 hash | `test_login.py::test_login_ok_native_with_legacy_django41_hash` (fixture `pbkdf2_sha256$390000$…`) |
| login ok / wrong password / unknown user / inactive user | `test_login.py::test_login_ok_*`, `test_login_wrong_password`, `test_login_unknown_user_same_error_and_runs_dummy_hash`, `test_login_inactive_user*` |
| email login | `test_login_by_email_case_insensitive`, `test_login_by_email_duplicate_rejected`, `test_empty_email_never_matches`, `test_login_unknown_email_runs_dummy_hash` |
| throttling | `test_throttle_per_ip`, `test_throttle_per_username_across_ips`, `test_throttle_uses_x_forwarded_for_with_one_proxy` |
| refresh rotation (old token rejected on reuse) | `test_token_flow.py::test_refresh_rotation_old_token_rejected_on_reuse`, `test_cookie_mode.py::test_cookie_refresh_with_allowed_origin_rotates_cookie` |
| logout blacklists | `test_logout_blacklists_refresh_token`, `test_cookie_logout_checks_origin_then_clears_cookie` |
| logout-all and introspect after revocation | `test_logout_all_blacklists_everything_and_revokes`, `test_introspect.py::test_introspect_inactive_after_logout_all` |
| access token rejected at /refresh | `test_access_token_rejected_at_refresh` |
| refresh token rejected by the §8.2 verifier | `test_verifier.py::test_verifier_rejects_refresh_token` |
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

1. ~~MySQL version of production `dcWebUsers`~~ **Answered: MySQL 8.4** (team lead, 2026-10-10). Django 5.2
   only is shipped (`requirements.lock`). The `requirements-django42*` fallback files are removed (deployment
   plan R9). The suite still passes on 4.2 as a portability check. Still to confirm: that the upgrade lands
   before go-live, and that `auth_user` is InnoDB.
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
10. QA's seed script (`qa/tests/fixtures/seed_test_data.py`) still needs the R27 guard
    (`SSO_ALLOW_SYNTHETIC_SEED=1` plus a local DB host). `qa/tests/conftest.py` still defaults to a real-domain
    origin (R10 note). Both files belong to QA, so this sprint did not change them.
