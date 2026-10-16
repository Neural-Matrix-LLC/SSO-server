# HISTORY

Change log for the SSO server, newest first. Each entry records goal, root cause (for bugs),
implementation, related files and test coverage.

## 2026-10-16 — fix: nginx 502 after redeploying web; webhooks container always unhealthy

**Goal.** Fix `GET /admin/` → 502 (`connect() failed (111: Connection refused) ... upstream:
"http://172.31.250.2:8000/admin/"`) and the permanently `unhealthy` `webhooks` container. Add worker logging.

**Root cause.**
- nginx resolved `server web:8000;` once at start-up. `web` and `webhooks` were recreated (image 0.1.1) while nginx
  kept running: web moved to 172.31.250.3 and the webhook worker took 172.31.250.2, so nginx proxied to the worker,
  which has no HTTP listener.
- The webhooks service inherited the image's `HEALTHCHECK` (HTTP `GET /healthz` on :8000), which can never succeed
  for the worker (`healthcheck failed: ConnectionRefusedError`). The worker also logged nothing while idle, so
  there was no sign that it was running.

**Implementation.**
- `docker/nginx.conf`: `resolver 127.0.0.11 valid=10s ipv6=off;` + `zone sso_web 64k;` +
  `server web:8000 resolve;` (nginx >= 1.27.3, image is 1.28), keepalive kept.
- `run_webhook_worker`: INFO logs on start (pid, poll, heartbeat path), SIGTERM/stop, non-empty delivery counts,
  recovery after failure; writes a JSON heartbeat (`ts`, `ok`, `last_ok`, `error`) atomically to
  `/tmp/sso-webhook-worker.heartbeat` after every loop (not in `--once`).
- `docker/healthcheck.py`: new `--worker` mode checking the heartbeat (`SSO_HEALTHCHECK_MAX_AGE`, default 300 s);
  both modes print the failure reason (shown in `docker inspect ... .State.Health`).
- `docker-compose.yml`: webhooks healthcheck `["CMD", "python", "/app/docker/healthcheck.py", "--worker"]`.

**Related files.** `docker/nginx.conf`, `docker/healthcheck.py`, `docker-compose.yml`,
`sso/management/commands/run_webhook_worker.py`, `sso/tests/test_webhook_worker_health.py`, `.env.example`,
`README.md`, `HISTORY.md`

**Test coverage.** New `sso/tests/test_webhook_worker_health.py`: loop logging and heartbeat across success, failure and recovery;
no heartbeat in `--once`; healthcheck worker mode (missing/corrupt/fresh/retrying/stale/never); web mode message;
compose and nginx config assertions. `nginx -t` passes on the rendered template (nginx:1.28-alpine).

## 2026-10-16 — docs: v1.3d design §19, reaching the admin UI from another LAN host

**Goal.** Record how to reach the SSO / admin UI from another machine on the LAN, after
`curl -k https://192.168.0.212/healthz` failed with `tlsv1 unrecognized name` (browser:
`ERR_SSL_UNRECOGNIZED_NAME_ALERT`).

**Root cause.** Not a bug: IP-literal URLs carry no SNI, so nginx's `:443` default server
(`ssl_reject_handshake on`) rejects the handshake by design. The server must be called by `SSO_HOSTNAME`.

**Implementation.** New §19 in the design: cause, `curl --resolve` quick check, `.env` + certificate changes for a
LAN hostname, and §19.1 on editing the Windows hosts file as Administrator (Notepad, PowerShell, WSL). No code,
config or env variable changes.

**Related files.** `docs/DESIGN-v1.3d-admin-ui.md`, `HISTORY.md`

**Test coverage.** Docs only. No tests added or removed.

## 2026-10-15 — v1.3d: admin web UI on the SSO server (`feat/v1.3d-admin-ui`)

**Goal.** Implement `docs/DESIGN-v1.3d-admin-ui.md`: the day-to-day admin UI as server-rendered pages at
`/<SSO_ADMIN_UI_PATH>` (default `/admin/`), sharing all business rules with the admin REST API.

**Implementation.**
- `sso/admin_ops.py`: domain layer moved out of `sso/admin_api.py` (guards, invariants, step-up check, users, groups,
  permissions, services, devices, apps/import, audit, webhooks); the REST API is now thin DRF views over it, URLs and
  responses unchanged except the additive audit `channel` field and `?channel=` filter.
- Audit `channel` (`api` | `ui` | `django_admin` reserved | `system`): migration `sso 0007_v13d_audit_channel`
  (AddField only), `sso_schema_check`, `scripts/upgrade_db.sh`, DBA file `docs/db/upgrade-v1.3-to-v1.3d.sql`.
- `adminui` app: own session cookie `__Host-sso_admin_sid` (Strict, HttpOnly, browser-session), CSRF cookie
  `__Host-sso_admin_csrf`, guard middleware (idle 30 min / max 8 h, IP binding, token revocation, admin re-check
  every request), login throttles, step-up page bound to the UI session and IP, CSP + security headers, all §10 pages,
  CSV exports (formula-safe), import preview/apply with HMAC digest, HTML error pages under the UI path.
- `application/permfile.py`: permission files are parsed with `ast` only (64 KiB cap), never executed.
- Deploy: nginx `location = /${SSO_ADMIN_UI_PATH}login/` (login rate limit) and `location /${SSO_ADMIN_UI_PATH}`,
  both including `sso-admin-ui.d/*.conf` (allow-list, `SSO_ADMIN_UI_ALLOW_DIR`); optional admin hostname via whole
  server blocks in `sso-admin-host.d/` (`SSO_ADMIN_UI_HOST_DIR`, sample provided) plus Django's Host check and
  system check `adminui.E001` (design updated to this approach). Compose and `.env.example` updated.
- QA fixes V13D-01..04 (see `qa/RESULTS-v1.3d.md`). MFA stays in TODOS.

**Related files.** `adminui/` (new), `sso/admin_ops.py` (new), `sso/admin_api.py`, `sso/stepup.py`, `sso/audit.py`,
`sso/models.py`, `sso/migrations/0007_v13d_audit_channel.py`, `application/permfile.py`,
`scripts/sso_permissions_to_json.py`, `ssoproject/settings.py`, `ssoproject/urls.py`, `docker/nginx.conf`,
`docker/nginx-admin-ui.d/`, `docker/nginx-admin-host.d/`, `docker-compose.yml`, `.env.example`,
`sso/management/commands/sso_schema_check.py`, `scripts/upgrade_db.sh`, `docs/db/upgrade-v1.3-to-v1.3d.sql`,
README, ARCHITECTURE, API-REFERENCE-MANUAL, DESIGN-v1.3d, `qa/blackbox/bb_v13d.py`, `qa/RESULTS-v1.3d.md`.

**Test coverage.** New `sso/tests/test_adminui_v13d.py` (58 test cases: auth matrix, cookies, timeouts, IP binding,
CSRF, step-up, guards, audit channel, import parse-never-execute, secrets, headers, hostname, settings validation);
new static check DEPLOY_21; DEPLOY_19 fixed. SQLite Django 5.2 and 4.2, MySQL 8.4 (539 passed) and 8.0 (538 passed),
black-box through nginx 33/33. Details in `qa/RESULTS-v1.3d.md`.

## 2026-10-15 — docs: admin UI moves from FUND to the SSO server (v1.3d design)

**Goal.** Record Thomas's decision (2026-10-15) that the admin UI lives on the SSO server's own `/admin`, not in
FUND (FUND is client-facing; the SSO owns administration), and design it as the last SSO-completion phase **v1.3d**,
before SGMCP v1.4.

**Implementation (docs only, branch `docs/sso-admin-ui`).** New `docs/DESIGN-v1.3d-admin-ui.md`: server-rendered
Django app `adminui` at `SSO_ADMIN_UI_PATH` (default `admin/`) on a shared domain layer `sso/admin_ops.py` (extracted
from `sso/admin_api.py`), session login with `__Host-` cookie + CSRF + IP binding, step-up page, pages, complete route
table, nginx allow-list `sso-admin-ui.d` + optional admin hostname, CSP, audit `channel` column, config, QA test plan,
rollout, open questions. Updated: `docs/ECOSYSTEM-INTEGRATION.md` (§7 rewritten, §9.1 phase plan with v1.3d and
v1.5b without admin UI, §5.6 / §8.2 suspend flows, §9.2 open questions, round 6 decision, pointer to the SGMCP v1.4
design folded in from the unpushed `docs/sso-v1.4-pointer` branch), `docs/ARCHITECTURE.md`,
`docs/API-REFERENCE-MANUAL.md` §11, `TODOS.md`, `README.md` §6c, `docs/SSO-Setup.md` §10 (appended).
Django admin stays as break-glass; the admin REST API is unchanged.

**Test coverage.** Docs only, no code change. All Mermaid diagrams in the changed files render with `mmdc`.

## 2026-10-15 — devops: database upgrade script v1.2 → v1.3 (`scripts/upgrade_db.sh`)

**Goal.** Upgrade an existing dcWebUsers database (e.g. at v1.2b: sso 0002, application 0001) to v1.3 (sso
0003-0006, application 0002) safely and repeatably, on WSL with Docker compose or from a bare venv, plus raw SQL
for a DBA.

**Implementation.** `scripts/upgrade_db.sh`: pre-check (`docker/dbcheck.py --strict`, new exit-code mode),
`showmigrations` + `migrate --plan` with a stop if any shared app would change (`--allow-shared-apps` only for
empty test databases), backup of the SSO-owned tables + their `django_migrations` rows with mysqldump (default on;
credentials only in a temporary mode-600 `--defaults-extra-file`; in compose mode the dump container joins the
`edge` network so the `sso_migrator@172.31.250.%` grant works), `migrate`, post-check with the new read-only
`manage.py sso_schema_check` (all SSO migrations applied, every v1.1-v1.3c table/column present; `--counts`) and
unchanged row counts; `--plan` dry run; idempotent; non-zero exit on failure. `docs/db/upgrade-v1.2-to-v1.3.sql`:
`sqlmigrate` output (MySQL 8.4) for sso 0002-0006 and application 0002 with `django_migrations` inserts,
verification queries and rollback notes. Docs: docs/SSO-Setup.md §9, README §5a. `backups/` git- and docker-ignored.

**Bug found while testing the rollback.** `migrate application 0001` with the v1.3 code failed after the DDL had run:
the `application` post_migrate permission sync read the v1.3 models on the rolled-back schema (`Unknown column
...description`). Fix: the sync is skipped when the migrate plan contains backward steps
(`application/permissions.py`). Also documented: a Django rollback needs DROP granted *before* it starts.

**Tests.** `sso/tests/test_schema_check.py` (7). On MySQL 8.4.11 and 8.0.46 (Docker, host network): v1.2b database
with sample data → `--plan` (no change) → upgrade (backup restorable, data of every pre-existing table identical,
schema OK) → re-run (nothing to apply) → wrong password (exit 1) → fresh database with only the shared apps
(all 20 SSO migrations) → empty database (stop, exit 3); then the v1.3 server as the DML-only `sso_app` on the
upgraded database: black-box suite 47/47 and a pre-upgrade service client still introspects. Compose mode tested on
8.0 with the production image. DBA SQL applied by hand on 8.4 → `migrate` has nothing to do, `sso_schema_check` OK,
no model drift; SQL rollback and Django rollback both bring the v1.2b code back to a clean state.

## 2026-10-15 — docs: WSL2 setup guide (`docs/SSO-Setup.md`)

**Goal.** Write down the complete local setup for the production compose stack on WSL2 (Docker Engine and
MySQL both inside WSL, `https://localhost` on port 443), including the three start-up failures hit
during the first local run and their fixes.

**Root causes of the failures documented.** These are environment problems, not code bugs:
1. `sso.db ... database unreachable at host.docker.internal:3306 (2002 ... (110))`: ufw enabled with
   `DEFAULT_INPUT_POLICY="DROP"` silently dropped traffic from the compose `edge` network
   (172.31.250.0/24) to the host's MySQL on 3306. Fix: `ufw allow from 172.31.250.0/24 to any port 3306 proto tcp`.
2. `curl: (7) ... port 443 ... Connection refused`: nginx was crash-looping because the certificate named in
   `.env` (`fullchain.pem` / `privkey.pem`) did not exist in `docker/certs/`. Fix: create a self-signed
   pair with `scripts/gen_selfsigned_cert.sh` and point `SSO_TLS_CERT_FILE` / `SSO_TLS_KEY_FILE` at it.
3. `curl: (35) ... tlsv1 unrecognized name`: `SSO_HOSTNAME` was still the placeholder `sso.example.com`,
   so nginx's default server (`ssl_reject_handshake on`) rejected SNI `localhost`. Fix: `SSO_HOSTNAME=localhost`.

**Implementation.** New guide with the setup steps: `.env` values, TLS cert, JWT keys, MySQL bind
address and accounts limited to the edge subnet, ufw rule, backup + migrate as `sso_migrator`, start and
verify, admin. It ends with a troubleshooting table that maps each symptom to its cause and fix. It links
to the README for details instead of duplicating them. No code, config or env variable changes.

**Related files.**
- `docs/SSO-Setup.md` (new)
- `HISTORY.md` (new)

**Test coverage.** Docs only. No tests added or removed. Ran the repo-only QA checks
(`cd qa/tests && ../../.venv/bin/python -m pytest -m static`): 34 passed, 1 skipped (`SSO_MANAGE_CMD` not
set, needs a running server).
