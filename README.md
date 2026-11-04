# sso-server

Single sign-on server for myFinance and related apps (Django 5.2 / DRF, Python 3.13). It runs against the existing,
shared **`dcWebUsers`** MySQL database with the stock `auth_user` table, so every existing user keeps their password.

* RS256 JWTs: a 15-min access token and a 7-day refresh token, rotated on every use (the old one is blacklisted).
  Each token carries a `kid`; JWKS publishes every public key. `perms` holds the user's `application.*` grants.
* Browser mode keeps the refresh token in an HttpOnly cookie and checks `Origin`; native mode returns it in the body.
* Services verify tokens locally with the JWKS (`examples/verifier`, `clients/python` = `sso-client`) or call
  introspection for revocation-aware checks.
* Admin REST API, service tokens, gateway devices and on-behalf-of calls, signed webhooks, and a server-rendered
  admin web UI at `/admin/` (Django admin stays at `/sso-admin/` as break-glass).

**Status:** feature level **v1.3d** on `main` (v1.0 core, v1.2a/b, v1.3a–d). Not built: hosted login page / PKCE,
sign-up, password reset, admin MFA ([TODOS.md](TODOS.md)).

## Documentation

| Read this | For |
|---|---|
| [docs/SSO-Setup.md](docs/SSO-Setup.md) | **Setup manual**: step by step on a Linux/WSL host, VPS from images only, DB upgrades, troubleshooting |
| [docs/API-REFERENCE-MANUAL.md](docs/API-REFERENCE-MANUAL.md) | **API** for client and service developers: endpoints, claims, error codes, admin API, devices, webhooks |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | **Architecture**: components, data model, workflows, failure handling, every environment variable (§10), security and deployment view, design decisions (§11.4), open questions (§12) |
| Design docs | [v1.0 spec](docs/SSO-server.md), [addendum v1.1](docs/DESIGN-ADDENDUM-v1.1.md), [app permissions](docs/sso-integration-design.md), [v1.2](docs/DESIGN-v1.2-requirements.md), [v1.3a admin API](docs/DESIGN-v1.3a-admin-api.md), [v1.3b devices](docs/DESIGN-v1.3b-devices-on-behalf-of.md), [v1.3c webhooks](docs/DESIGN-v1.3c-webhooks.md), [v1.3d admin UI](docs/DESIGN-v1.3d-admin-ui.md), [v1.3e session-bound jobs (+ v1.3f keep-jobs logout)](docs/DESIGN-v1.3e-session-bound-jobs.md), [sso-client library](docs/SSO-CLIENT-LIBRARY-DESIGN.md), [ecosystem integration](docs/ECOSYSTEM-INTEGRATION.md) |
| [devops/DEPLOYMENT-PLAN.md](devops/DEPLOYMENT-PLAN.md) | Deployment plan: environments, secrets, rotation runbook, rollout and rollback |
| [qa/TEST-PLAN.md](qa/TEST-PLAN.md), `qa/RESULTS-*.md` | Black-box test plan and results per release |
| [HISTORY.md](HISTORY.md), [TODOS.md](TODOS.md) | Change log; future items |

## Docker quick start (local / WSL)

Production compose file (`web`, `webhooks`, `redis`, `nginx`, one-shot `init`; no DB container) against an existing
`dcWebUsers`. Full detail, LAN/IP setups and every pitfall: [SSO-Setup.md](docs/SSO-Setup.md) steps 1–10.

1. **`.env`**: `cp .env.example .env && chmod 600 .env`; set `SSO_SECRET_KEY`, `SSO_WEBHOOK_SECRET_KEY`,
   `SSO_HOSTNAME`, `SSO_ISSUER`, `SSO_ALLOWED_HOSTS`, origins and the DB values (Setup §1–2).
2. **Keys and certificate**: nothing to do. On `up`, the `init` service generates the JWT pair and a self-signed
   certificate in the empty `SSO_KEYS_DIR` / `SSO_CERTS_DIR` (`scripts/init_secrets.sh`). By hand:
   `scripts/gen_keys.sh ./keys sso-2026-10` (prints `kid=`) and `scripts/gen_selfsigned_cert.sh localhost docker/certs`.
3. **Name the keys** in `.env` as file names in `SSO_KEYS_DIR` (mounted read-only at `/run/keys`):
   `SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem`, `SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem`.
4. **Key owner**: the container runs as `SSO_UID:SSO_GID` (default `10001`); `init` fixes the owner (Setup §4).
5. **Database**: accounts `sso_app` (DML only, in `.env`) and `sso_migrator` (DDL, never in `.env`), grants as in
   `docker/mysql-init/01-sso-accounts.sh`. `SSO_DBHOST=host.docker.internal` for a MySQL on the Docker host (Setup §5–6).
6. **Back up, then migrate** with the single upgrade path (it refuses any plan outside `sso`, `application`,
   `token_blacklist`; the `mysqldump` command is in Setup §7):
   ```bash
   read -rs -p 'sso_migrator password: ' SSO_DBPWD && export SSO_DBPWD && echo
   scripts/upgrade_db.sh --plan && scripts/upgrade_db.sh
   unset SSO_DBPWD
   ```
7. **Start and check**: `scripts/deploy.sh` (init, schema gate, `up --wait`, then `scripts/deploy_check.sh`, which
   prints `[PASS]`/`[WARN]`/`[FAIL]` with the fix). Then `curl -sk https://localhost/healthz` → `{"status":"ok"}`.
8. **Admin and app access**: `docker compose run --rm web python manage.py createsuperuser`. Superusers get **no**
   app access automatically: grant `application.app1` (and `application.sso_admin` + staff for the admin UI).
   `scripts/sso_login_check.py <username>` checks a real login and prints `perms`.

Something fails: [SSO-Setup.md Troubleshooting](docs/SSO-Setup.md#troubleshooting) or `scripts/deploy_check.sh`.

## 1. Layout

| Path | Purpose |
|---|---|
| `ssoproject/settings.py` | All configuration from env, fail-fast checks; `settings_test.py` for pytest (throw-away keys) |
| `sso/` | Core app: views, tokens (`KidTokenBackend`), keys/JWKS, auth, throttles, revocation, admin API (`admin_api`, `admin_ops`), service tokens, devices, webhooks, DB/deploy checks, management commands, `tests/` |
| `application/` | Central app permissions `application.<codename>` (`ApplicationAccess` anchor), registry, permission import |
| `adminui/` | v1.3d admin web UI |
| `clients/python/` | `sso-client` library for services |
| `examples/verifier/`, `examples/frontend/` | Spec §8.2 PyJWT verifier + FastAPI demo; test page with `auth.js` |
| `scripts/` | `gen_keys.sh`, `gen_selfsigned_cert.sh`, `init_secrets.sh`, `upgrade_db.sh`, `deploy.sh`, `deploy_check.sh`, `sso_login_check.py`, `sso_permissions_to_json.py`, `dev_setup.sh`, `test_both_django.sh` |
| `Dockerfile`, `docker/` | `sso-server` image; `Dockerfile.nginx` + `nginx.conf` (`sso-nginx` image), healthcheck, dbcheck, allow-list dirs, MySQL init |
| `docker-compose.yml` / `.dev.yml` / `.test.yml` | Production; local overlay (MySQL, demo); MySQL integration tests |
| `.env.example` (+ `.dev`, `.test`) | Every environment variable, annotated |
| `docs/db/` | DBA SQL per upgrade, with rollback notes |
| `qa/` | Black-box QA suite, harness, results |

## 2. Local setup and tests

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt     # Python 3.13 (= the image)
.venv/bin/pytest                      # SQLite in memory, no DB server, no key files; coverage report
.venv/bin/pytest -k rotation          # by keyword
scripts/test_both_django.sh           # Django 5.2 and 4.2 (portability), both --cov-fail-under=90
```

MySQL integration (Docker): `MYSQL_IMAGE` picks the server, default `mysql:8.0` (8.4 supported, one data volume per
version via `SSO_TEST_MYSQL_VOLUME`):
```bash
scripts/dev_setup.sh                  # creates .env.test once
T='docker compose --env-file .env.test -f docker-compose.test.yml'
$T run --rm --build tests                                                                  # MySQL 8.0
MYSQL_IMAGE=mysql:8.4 SSO_TEST_MYSQL_VOLUME=sso-test-mysql-8.4 $T run --rm --build tests   # MySQL 8.4
```

Without Docker (SQLite, plain HTTP): a `.env` with `SSO_DB_ENGINE=sqlite`, `SSO_KEYS_DIR`, the key names,
`SSO_SSL_REDIRECT=False`, `SSO_COOKIE_SECURE=False` and `SSO_CACHE_URL=filecache:///tmp/sso-cache` (with
`SSO_DEBUG=False` a shared cache is required), then `manage.py migrate` and
`.venv/bin/gunicorn ssoproject.wsgi:application -b 127.0.0.1:8000`. Never as root: with `SSO_DEBUG=False` the
process refuses uid 0. QA black-box suite: [qa/tests/README.md](qa/tests/README.md).

## 3. Environment variables

The complete annotated list is `.env.example`; the reference table with defaults is
[ARCHITECTURE.md §10](docs/ARCHITECTURE.md#10-configuration-reference). Required with `SSO_DEBUG=False` (else the
process refuses to start):

| Variable | Notes |
|---|---|
| `SSO_SECRET_KEY` | Django secret; need not match myFinance |
| `SSO_ISSUER` | Public base URL = JWT `iss`. Changing it later invalidates every token |
| `SSO_ALLOWED_HOSTS`, `SSO_HOSTNAME` | Django hosts; the only Host nginx answers |
| `SSO_JWT_PRIVATE_KEY`, `SSO_JWT_PUBLIC_KEYS` | Key **file names** in `SSO_KEYS_DIR` (precedence `SSO_JWT_KEYS_MOUNT` > `SSO_KEYS_DIR` > `/run/keys`); RSA ≥ 2048 bits |
| `SSO_CACHE_URL` | Shared cache for throttles; compose defaults to Redis. LocMem/dummy are refused |
| `SSO_DBHOST`, `SSO_DBPORT`, `SSO_DBNAME`, `SSO_DBUSER`, `SSO_DBPWD` | Runtime account `sso_app`; optional TLS `SSO_DB_SSL_CA` / `SSO_DB_SSL_MODE` |

Strongly recommended: `SSO_WEBHOOK_SECRET_KEY` (else derived from `SSO_SECRET_KEY`), `SSO_CORS_ALLOWED_ORIGINS`,
`SSO_CSRF_TRUSTED_ORIGINS`, `IMAGE_TAG` pinned on servers. Behaviour switches: `SSO_SUPERUSER_ALL_APPS` (default
`false`), `SSO_IP_BINDING_MODE` (`NOIP`; start with `WARNING`), `SSO_TRUSTED_PROXIES`.

## 4. Key generation and rotation

`scripts/gen_keys.sh [OUT_DIR] [NAME] [BITS]` (defaults `./keys`, `sso-YYYY-MM`, 3072) writes
`<name>.private.pem` (0600) and `<name>.public.pem`, prints the `kid`, never overwrites. Rotation (deployment plan
§11, spec §5.3; verification picks the key by `kid`, so old tokens stay valid):

1. Generate the new pair into `SSO_KEYS_DIR`; **append** its public key to `SSO_JWT_PUBLIC_KEYS`; recreate `web`.
   JWKS now lists both kids.
2. After ≥ 24 h, set `SSO_JWT_PRIVATE_KEY` to the new key; recreate `web`.
3. After ≥ 8 days (refresh TTL + margin), remove the old public key, recreate, shred the old private key.

## 5. Database: first deployment and migrate procedure

`dcWebUsers` is shared with myFinance. This project owns only the `sso`, `application` and `token_blacklist`
migrations (a test asserts it); shared apps stay at their Django 4.1 leaf migrations. The container never migrates
on its own; the runtime account is DML only.

* **Never** run `clearsessions` or `remove_stale_contenttypes`, here **or in myFinance**: the latter
  cascade-deletes every `application.*` permission and every grant of it
  ([ARCHITECTURE.md §5.1](docs/ARCHITECTURE.md#51-tables)).
* First install and every upgrade: full `mysqldump` backup, then `scripts/upgrade_db.sh` as `sso_migrator`
  (pre-check, plan, backup of the SSO tables, migrate, `sso_schema_check`, unchanged row counts):
  [SSO-Setup.md §7](docs/SSO-Setup.md#7-back-up-then-create-the-sso-schema-as-sso_migrator) and
  [§11](docs/SSO-Setup.md#11-upgrading-the-database-later). On a VPS a separate migration server runs it
  ([§12.6](docs/SSO-Setup.md#126-create-the-schema-db-team-on-the-migration-server)).
* New migration: append it to the MANIFEST in `scripts/upgrade_db.sh`, to `EXPECTED` in `sso_schema_check`, and add
  `docs/db/upgrade-<prev>-to-<ver>.sql` (`sso/tests/test_upgrade_manifest.py` enforces this).

## 6. Operating cheat sheet

Run commands as `docker compose exec web python manage.py …` (or `run --rm web`).

| Task | How |
|---|---|
| Register a ServiceClient (introspect, `client_ip` delegation) | `create_service_client <id> --name "…"` (secret printed once; `--rotate-secret`), or Django admin |
| New service with its app permission in one step | `register_service reporting --name "Reporting" --app app2 --app-name "Can use app2 (reporting)" [--notify-url …]` |
| Add an application permission | `create_app_permission app2 "Can use app2 (reports)"` (idempotent) |
| Grant app access | Admin UI or Django admin → user/group permissions → `application.<codename>`; effective at the next refresh |
| Admin REST API | grant `application.sso_admin` + staff; destructive calls need `POST /api/v1/admin/reauth` ([API §8](docs/API-REFERENCE-MANUAL.md#8-admin-rest-api-v13a)) |
| Admin web UI | `https://<host>/admin/`; restrict with `docker/nginx-admin-ui.d/*.conf` ([Setup §10](docs/SSO-Setup.md#10-admin-web-ui)) |
| Webhooks | set `notify_url`, `rotate_notify_secret <id>`; compose service `webhooks` delivers ([API §10](docs/API-REFERENCE-MANUAL.md#10-signed-webhooks-v13c)) |
| Cron | daily `flushexpiredtokens`, hourly `revoke_inactive_users`, certbot renewal ([Setup §12.8](docs/SSO-Setup.md#128-lets-encrypt-certificate)) |

### Application permissions (`application.<codename>`)

One permission per application, checked by that application in the `perms` claim. `application.app1`
(llm-wiki-svc) and `application.sso_admin` are code-defined and recreated by `migrate`; others come from
`create_app_permission`, `register_service --app` or the permission import. `perms` is computed from real
permission rows (user + groups), never `has_perm()`, so superusers get only explicit grants unless
`SSO_SUPERUSER_ALL_APPS=true`. Details: [ARCHITECTURE.md §6.11](docs/ARCHITECTURE.md#611-granting-applicationapp1-and-how-it-reaches-the-token).

## 7. Docker

* `docker-compose.yml`: `init` (one-shot), `web` (gunicorn, non-root, read-only, keys at `/run/keys`), `webhooks`,
  `redis` (internal), `nginx` (only published service; `docker/nginx.conf` is baked into the `sso-nginx` image,
  so rebuild after editing it), `certbot` (on demand). Images `${DOCKER_USER}/sso-server` and `/sso-nginx` with the
  same `IMAGE_TAG`. Design notes (image, container user, proxy trust, throttles):
  [ARCHITECTURE.md §11.2](docs/ARCHITECTURE.md#112-deployment-view).
* **VPS from images only**: deploy kit in `/app/deploy`, migration server + `scripts/deploy.sh`, Let's Encrypt,
  upgrades: [SSO-Setup.md §12](docs/SSO-Setup.md#12-deploy-to-a-vps-from-the-docker-images-only).
* **Local dev overlay** with its own MySQL (order per deployment plan §2.1):
  ```bash
  scripts/dev_setup.sh && set -a && . ./.env.test && set +a       # keys, cert, .env, .env.test
  alias dc='docker compose -f docker-compose.yml -f docker-compose.dev.yml'
  dc up -d --build db redis
  M="-e SSO_DBUSER=sso_migrator -e SSO_DBPWD=$SSO_TEST_MIGRATOR_PASSWORD"
  for app in contenttypes auth admin sessions; do dc run --rm $M web python manage.py migrate $app; done  # = myFinance's tables
  dc run --rm $M web python manage.py migrate && dc run --rm $M web python manage.py createsuperuser
  dc up -d --build      # test page https://localhost:8443/demo/, demo API https://localhost:8443/verifier/me
  ```

## 8. API summary

Full reference: [API-REFERENCE-MANUAL.md](docs/API-REFERENCE-MANUAL.md). All JSON; errors are `{"error","detail"}`.

| Area | Endpoints |
|---|---|
| User auth | `POST /api/v1/auth/login`, `/refresh`, `/logout`, `/logout-all`; `GET /api/v1/auth/me` |
| Services | `POST /api/v1/auth/introspect` (Basic), `POST /api/v1/auth/service-token`, `GET /api/v1/service/users/inactive`, `POST /api/v1/service/sessions/status` (v1.3e) |
| Devices | `POST`/`GET /api/v1/devices`, `DELETE /api/v1/devices/{client_id}` |
| Admin | `/api/v1/admin/*`: users, groups, permissions, services, apps import, devices, webhooks, audit, reauth |
| Public | `GET /.well-known/jwks.json`, `/.well-known/openid-configuration`, `/healthz` |

## 9. Spec §11 test mapping

| Spec §11 item | Test(s) |
|---|---|
| Legacy Django 4.1 PBKDF2 hash | `test_login.py::test_login_ok_native_with_legacy_django41_hash` (fixture `pbkdf2_sha256$390000$…`); corrupt hashes (QA LEGACY-06): `test_login_corrupt_stored_hash_is_401_not_500` |
| login ok / wrong password / unknown user / inactive user | `test_login.py::test_login_ok_*`, `test_login_wrong_password`, `test_login_unknown_user_same_error_and_runs_dummy_hash`, `test_login_inactive_user*` |
| email login | `test_login_by_email_case_insensitive`, `test_login_by_email_duplicate_rejected`, `test_empty_email_never_matches`, `test_login_unknown_email_runs_dummy_hash` |
| throttling | `test_throttle_per_ip`, `test_throttle_per_username_across_ips`, `test_throttle_uses_x_forwarded_for_with_one_proxy`, `test_x_forwarded_for_ignored_with_zero_proxies`; fail-fast cache: `test_keys_settings.py::test_settings_fail_fast_without_shared_cache` |
| refresh rotation (old token rejected on reuse) | `test_token_flow.py::test_refresh_rotation_old_token_rejected_on_reuse`, `test_cookie_mode.py::test_cookie_refresh_with_allowed_origin_rotates_cookie` |
| logout blacklists | `test_logout_blacklists_refresh_token`, `test_cookie_logout_checks_origin_then_clears_cookie` |
| v1.3e: logout / password change end the session and stop its jobs | `test_session_bound_jobs_v13e.py::test_logout_ends_the_session_but_not_other_sessions`, `test_logout_emits_token_revoked_with_sid_and_delivers_it`, `test_password_change_ends_every_session_and_emits_without_sid`, `test_status_*`; dummy-job end to end: `test_dummy_jobs_v13e.py` |
| v1.3f: logout with `keep_jobs` keeps the session's jobs running | `test_keep_jobs_v13f.py::test_keep_jobs_logout_ends_the_session_like_a_logout`, `test_keep_jobs_logout_emits_token_revoked_with_keep_jobs`, `test_status_detached_*`, `test_prune_keeps_detached_rows_until_a_later_user_wide_revocation`, `test_dummy_*` (incl. new login: `test_dummy_new_session_sees_detached_jobs_by_user_id`, `test_dummy_new_session_can_stop_a_detached_job`, `test_dummy_reattach_binds_the_job_to_the_new_session`) |
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

## 10. Design decisions (summary)

Full list with rationale: [ARCHITECTURE.md §11.4](docs/ARCHITECTURE.md#114-design-decisions-and-deviations-from-the-spec).

* Inactive users get 403 `account_inactive` only with the correct password; every login path runs exactly one hash.
* A token is revoked iff `iat < ceil(revoked_at)`; `/me` and `/logout-all` honour revocation, local verifiers only
  at `exp` (≤ 15 min) unless they introspect.
* Refresh builds a fresh pair from the DB, so group and permission changes apply at the next refresh.
* Corrupt stored hashes give 401, never 500. JSON-only parsers (form posts get 415).

## 11. Open questions

See [ARCHITECTURE.md §12.3](docs/ARCHITECTURE.md#123-open-questions).
