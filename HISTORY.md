# HISTORY

Change log for the SSO server, newest first. Each entry records goal, root cause (for bugs),
implementation, related files and test coverage.

## 2026-11-03 — v1.3e: long-running jobs bound to the login session (logout / password change stop them)

**Goal.** Decision (Thomas): a long-running job (SGMCP strategy, webhook subscription, auto-trade job) lives as long
as the login session that started it. Logout stops the jobs of that session; logout-all and password change stop
all the user's jobs. Until a future release offers "log out but keep my jobs", users keep the front end signed in.

**Root cause (gap).** Services run such jobs under their own service token with `owner_sub` (ECOSYSTEM §4.1), and
only suspend / delete ended them. A plain logout only blacklisted one refresh token: the session's access tokens
stayed valid at introspect until `exp` and no webhook told services that the user had logged out.

**Implementation.**
- `LogoutView`: a token with `sid` now calls `revoke_session(user, sid, "logout")` (session revoked, family
  blacklisted, step-up dropped, `token.revoked {sub, sid, reason: "logout"}` in the outbox). Access tokens of the
  session fail at `/me` and introspect at once. Tokens without `sid` are only blacklisted, as before.
- `revoke_session` emits only when it ends the session (a replay after logout keeps reason `logout`, no second
  event); the `session_revoked` log line is INFO for `logout`, WARNING otherwise.
- New `POST /api/v1/service/sessions/status` (ServiceClient Basic or service token, 1–100 `{sub, sid}`):
  `active` or `reason` (`logout`, `refresh_reuse`, `ip_mismatch`, `revoked`, `expired`, `user_inactive`,
  `user_deleted`); backstop sweep for lost webhooks and idle-expired sessions. `revocation.session_states()`.
- Password change: no server change (already emits `token.revoked {sub, reason: password_change}` without `sid`);
  now part of the contract. Known limit: changes written by myFinance are not seen (TODOS).
- No migration, no new setting or env var.

**Docs.** New `docs/DESIGN-v1.3e-session-bound-jobs.md`; ECOSYSTEM-INTEGRATION §4.1, §5.6, §8.2, §9.1, §10 round 7
(decision 20); API manual §2.6, logout, §3.3, §7, §8.2, §4 table, §10; DESIGN-v1.3c event table; ARCHITECTURE §6.6,
§7 token states, §8.3, components, status; README design-doc list, service endpoints, §9 test mapping; TODOS
(keep-jobs logout option, myFinance password changes); `qa/TEST-PLAN.md` LOGOUT-03.

**Files.** `sso/views.py`, `sso/revocation.py`, `sso/service_auth.py`, `ssoproject/urls.py`,
`sso/tests/test_session_bound_jobs_v13e.py` (new), `sso/tests/test_admin_api_v13a.py`, `qa/tests/test_logout.py`.

**Test coverage.** New `sso/tests/test_session_bound_jobs_v13e.py` (logout, password change, session status;
list in the design doc §7). Changed expectations: `test_plain_logout_kills_reauth` (the access token itself is now
`token_invalid` after logout) and black-box `test_LOGOUT_03` (`/me` after logout is 401, was 200).
End to end: `sso/tests/dummy_job_service.py` (a "dummy job" service, reference implementation for SGMCP / FUND:
introspect at start, `sso_client.WebhookReceiver`, status sweep) and `sso/tests/test_dummy_jobs_v13e.py` (18 cases:
logout, cookie logout, refresh keeps jobs, password change, admin set-password, same password, logout-all, lost
webhook + sweep, idle expiry, batching and SSO outage, suspend / reactivate, delete, duplicate and badly signed
deliveries, refused starts, on-behalf-of). Mutation check: with the pre-v1.3e logout, the 8 logout cases fail.

## 2026-10-29 — docs: manual curl health and login check in SSO-Setup

**Goal.** Record the curl commands that were verified against the test server at 192.168.0.213 (IP address,
self-signed certificate) so health and login can be checked by hand from another machine.

**Docs.** docs/SSO-Setup.md §9.1 (new): `/healthz`, native login, login + `/auth/me` with the access token, JWKS
and discovery, with the expected status codes (200/401/403/429) and the usual by-IP pitfalls (SNI, allowed hosts).
No code change.

## 2026-10-21 — docs: required network ports in SSO-Setup

**Goal.** First production deploy (0.1.3, Hostinger VPS) failed: `sso-nginx-1` could not bind `0.0.0.0:80`
(`address already in use`); the panel's Traefik holds 80 and 443 on the host.

**Docs.** docs/SSO-Setup.md §0.1 (new): every inbound, internal and outbound port, which are published, and the
"must be free on the host" check; §12.1 prerequisite points at it; Troubleshooting row for the bind error (stop the
other proxy, or move to free ports with the port in `SSO_ISSUER` / origins; don't chain behind it because nginx
overwrites `X-Forwarded-For`). No code change.

## 2026-10-20 — docs: README slimmed to a quick reference; setup, API and architecture docs brought up to v1.3d

**Goal.** With the server working, make README.md short enough for quick reference and have it point to the
detailed documents (setup manual, API, architecture, design), and verify those are current.

**Implementation.**
- `README.md` rewritten (713 → 235 lines): status (v1.3d), documentation map, 8-step quick start using
  `upgrade_db.sh` / `deploy.sh`, commands, required env vars only, key rotation, DB rules, operating cheat sheet,
  API overview, spec §11 test mapping (kept), design-decision summary. Section numbers cited by code comments and
  QA tests (§2–§5, §7, §9, §10, "Docker quick start", "Application permissions") are kept; the strings
  `test_DEPLOY_07` / `test_DEPLOY_17` look for are kept.
- Moved out of README: full env table → `docs/ARCHITECTURE.md` §10 (also added the 28 settings it lacked: DB/Redis
  timeouts, v1.3a–d, plus a compose-only table; fixed `SSO_NUM_PROXIES`/`SSO_TRUSTED_PROXIES` compose defaults);
  design decisions → ARCHITECTURE §11.4; open questions → §12.3; image / container user / proxy trust / throttle
  notes → §11.2; `mysqldump` backup, key-name and key-ownership detail, WORKER TIMEOUT and `webhooks` unhealthy rows
  → `docs/SSO-Setup.md` §4, §7, Troubleshooting.
- ARCHITECTURE: status now `main` @ `b749fae`; v1.3b/c in §3.2; §4 components for admin API, service tokens,
  devices, webhooks, admin UI, DB/deploy checks, init service; §5.1 v1.3 tables; §8.9 `/healthz` migrations-pending
  warning; §8.10 pointer to the API manual for v1.3 endpoints; §11.2 deployment view with `init`, `webhooks`,
  `certbot`, deploy kit and schema gate.
- API manual: header (as-built `main`), §4 table lists the v1.3 endpoint groups, `/healthz` warning, §7 renamed
  "Feature history" (webhooks done), stale branch status lines, garbled audit sentence in §11.
- SSO-Setup: no longer depends on README for the backup, env table or key details; deploy-kit list includes
  `deploy.sh` / `deploy_check.sh`.
- Status lines of DESIGN-v1.2, v1.3a/b/c/d and ECOSYSTEM-INTEGRATION updated (implemented, merged to `main`).
- CLAUDE.md: README role and env-var documentation rule.

**Tests.** Relative links and anchors in the edited docs checked by script (0 broken). `qa/tests -m static`: 36
passed, 1 failed — `test_DEPLOY_21` because of the local, untracked `docker/nginx-admin-ui.d/allow.conf`, not a
docs change. `sso/tests/test_upgrade_manifest.py`, `test_migrations.py`: pass.

## 2026-10-20 — devops: DB migration from a separate migration server, schema gate in `deploy.sh`

**Goal.** Revised process (Thomas): the DB migration is done from another server first; only then does Ops start
the containers on the VPS, whose `init` service creates the keys and certificates. The VPS must never migrate or
hold DDL credentials, and must not start a release whose schema is not migrated yet.

**Implementation.**
- `scripts/deploy.sh`: new **schema gate** between build/pull and `up`. A one-off `docker compose run --rm -T
  --pull never web` (its `depends_on` runs `init` first, so keys and certificate exist) runs
  `docker/dbcheck.py --strict && manage.py sso_schema_check` as the runtime account `sso_app` (read-only). On failure:
  `init` output, a STOP message naming the three causes (init, DB unreachable, schema not migrated → DB team runs
  `scripts/upgrade_db.sh` on the migration server), exit code 3, nothing (re)started, so on an upgrade the running
  release keeps running. `--skip-schema-gate` to start anyway. `up` now always runs with `--no-build` (the build is
  a separate step before the gate). Only this run's `init` output is printed (`logs --since`); before, a reused init
  container repeated an old "NEW key pair" warning.
- Fix texts: H01 (`sso/deploycheck.py`) and the `webhooks` D02 hint (`scripts/deploy_check.sh`) point at
  `upgrade_db.sh` on the migration server.
- Migration server = any Docker host that reaches the DB (not the VPS) with the same deploy kit and `.env`; `init`
  creates a throw-away key pair there (its kid is not in the VPS's JWKS, so nothing trusts it). No code change in
  `upgrade_db.sh`.

**Docs.** docs/SSO-Setup.md §12 intro (two hosts, two roles, order), §12.1 (`sso_migrator` granted from the
migration server's IP only; migration server prerequisite), §12.6 (DB team, on the migration server), §12.7 (Ops,
schema gate, exit 3), §12.10 (upgrade order across both hosts), §8 and the "migrations pending" Troubleshooting row.
README §7 VPS block. devops/DEPLOYMENT-PLAN.md v1.8: `<migration_host_ip>` placeholder, §4.1 (`sso_migrator` password
not on the VPS), §6.2 grants, DB firewall line, §12.2 P6/P7 and later releases.

**Tests.** `qa/tests/test_deploy_files.py` DEPLOY_23: `deploy.sh` runs `sso_schema_check` before
`up -d --no-build --wait` and contains no migrate call. Unit: 67 deploy-check/init tests pass. E2E (scratch copy,
dev overlay, empty MySQL, fresh key/cert folders): `deploy.sh` → init generated keys, gate stopped with exit 3
(`unapplied SSO migrations`), web/webhooks/nginx not created; `upgrade_db.sh` (as the migration server would);
`deploy.sh` again → gate `schema OK`, all checks PASS except the known dev-overlay `webhooks` DB gap (D02).

## 2026-10-19 — devops: automated deploy (auto-init of keys/certs, `deploy.sh` + post-start check)

**Goal.** A production deploy needed manual key and cert generation on the host (`install -d -o 10001`,
`docker run ... gen_keys.sh`, copying lines into `.env`, `gen_selfsigned_cert.sh`) and a long manual
troubleshooting pass. Make it as automated as possible: generate keys and certs when their folders are empty, and
after start-up check every known failure from the docs/SSO-Setup.md Troubleshooting and watch-outs tables.

**Implementation.**
- New one-shot compose service `init` (`scripts/init_secrets.sh`, `sso-server` image). web, webhooks and nginx
  `depend_on` it with `service_completed_successfully`.
  - Keys: when the folder has no `*.pem`, it generates the pair named by `SSO_JWT_PRIVATE_KEY` /
    `SSO_JWT_PUBLIC_KEYS`. It refuses if the public list holds more than that one key (lost keys, not a fresh
    install) and never writes into a non-empty folder; a missing named file there is an error. It always sets the
    owner to `SSO_UID:SSO_GID`, dir 0700, private 0600, public 0644.
  - Cert: when both files are missing and the names are plain, it creates a self-signed bootstrap cert for
    `SSO_HOSTNAME`. A Let's Encrypt `live/...` path or half a pair is an error. An existing self-signed cert that
    doesn't cover the hostname gets a WARN and is kept.
  - It runs as root (to create and chown bind-mounted host dirs) with `cap_drop: ALL` plus
    CHOWN/DAC_OVERRIDE/FOWNER, `network_mode: none`, read-only rootfs and no `env_file`. `SSO_AUTO_INIT=false`
    means check only.
- `scripts/gen_selfsigned_cert.sh`: optional CERT_NAME / KEY_NAME arguments (defaults unchanged).
- `sso/deploycheck.py` + `docker/deploy_check.py` (run in `web`):
  - C01–C07: `.env` consistency (issuer vs hostname and port, ALLOWED_HOSTS, IP needs SNI off, cookie domain,
    origin format, admin origin in CSRF, placeholders).
  - T01–T04: TLS to `nginx:443` with the client's SNI (handshake, SAN, expiry, self-signed on a DNS name).
  - H01: `/healthz` through nginx (444, 400, 502, 503, pending migrations).
  - J01: the signing kid is in the JWKS.
- `scripts/deploy_check.sh` (host side, docker CLI only):
  - D01–D02: init exit code, services running and healthy.
  - D03–D07: nginx network mode, edge network, `resolv.conf`, `nslookup web`, resolver/certificate log errors.
  - D08: DB errno in the web log mapped to its fix row.
  - D09: same image tag for web and nginx, no stale image.
  - D10: admin UI allow-list on a public host.
  - D11: the published port via curl.
  - It then merges the in-container results and exits 1 on any FAIL.
- `scripts/deploy.sh`: config check, pull (image-only VPS), `up -d --wait`, then always `deploy_check.sh`.
  Never migrates.
- Dockerfile: `init_secrets.sh` goes in `/app/scripts`, `deploy.sh` / `deploy_check.sh` in the deploy kit,
  `deploy_check.py` in `/app/docker`.
- `.env.example`: bootstrap cert names `selfsigned.crt/.key` and `SSO_AUTO_INIT`.
- Docs: SSO-Setup §3/§4/§8/§12.4/§12.5/§12.7/§12.10 and Troubleshooting, README quick start/§1/§3/§7,
  DEPLOYMENT-PLAN v1.7.

**Related files.** `docker-compose.yml`, `Dockerfile`, `scripts/init_secrets.sh`, `scripts/gen_selfsigned_cert.sh`,
`scripts/deploy.sh`, `scripts/deploy_check.sh`, `docker/deploy_check.py`, `sso/deploycheck.py`, `.env.example`,
`README.md`, `docs/SSO-Setup.md`, `devops/DEPLOYMENT-PLAN.md`, `qa/tests/test_deploy_files.py`.

**Test coverage.**
- `sso/tests/test_deploycheck.py`: every config rule; cert evaluation; network checks against a local fake nginx
  (SNI rejection, 444, 400/502/503, pending migrations, JWKS); the entry point in a fresh interpreter.
- `sso/tests/test_init_secrets.py`: generation, idempotence, names and modes, IP SAN, refusal cases,
  `SSO_AUTO_INIT=false`.
- QA static DEPLOY_22 updated, new DEPLOY_23 (init lockdown, dependencies, deploy kit).
- Whole suite: 621 passed, coverage 94%.
- End to end with the dev overlay from empty `keys/` and `docker/certs/`, in a scratch copy with its own
  project, ports and image tag:
  - init generated both with the right owner and modes.
  - Before migrating, the check reported H01 "migrations pending"; after migrating, all D/C/T/H/J checks passed.
  - D02 flagged `webhooks` unhealthy: the pre-existing dev-overlay gap where only `web` gets the dev DB host.
  - A wrong key name in a non-empty folder stopped init, and web was not started.

## 2026-10-19 — docs: production watch-out for nginx `127.0.0.11:53 Connection refused`

**Root cause.** On the VPS, nginx logged `recv() failed (111: Connection refused) while resolving, resolver:
127.0.0.11:53` and `web could not be resolved`: Docker's embedded DNS was not reachable from the nginx container
(not on the `edge` network / `network_mode: host`, an older compose file, or daemon DNS setup), so every proxied
request would get a 502.

**Implementation.** `docs/SSO-Setup.md`: new final section "Production deployment watch-outs" with the symptom,
four diagnostic commands (network mode, `resolv.conf`, lookup from nginx vs web, effective compose config / daemon)
and a result → cause → fix table. No code or config changes.

**Related files.** `docs/SSO-Setup.md`, `HISTORY.md`

**Test coverage.** Docs only. No tests added or removed.

## 2026-10-18 — keys: `gen_keys.sh` reports an unwritable OUT_DIR instead of a misleading openssl error

**Root cause.** Running the script from the image with an empty `$SSO_DIR` mounted a root-owned `/keys` on `/out`;
`openssl genpkey` failed silently (stderr to /dev/null) and the next step said
`Could not open file … sso-YYYY-MM.private.pem: No such file or directory`.

**Implementation.** `scripts/gen_keys.sh` checks that OUT_DIR is writable (prints uid/gid and the `install -d` fix)
and exits with a clear error if `genpkey` fails. `docs/SSO-Setup.md` §12.4 aborts when `SSO_DIR` is unset and
creates `"$SSO_DIR/keys"` (not `./keys`). Verified manually (read-only dir → clear error, rc 1; writable → rc 0).

## 2026-10-18 — devops: run a VPS from images only (`sso-nginx` image, tools and deploy kit in `sso-server`)

**Goal.** Deploy containers, not the repo (Thomas): the VPS gets no checkout, and keys/certs are still generated
on the VPS itself.

**Implementation.** New `docker/Dockerfile.nginx` (+ `.dockerignore`: only `docker/nginx.conf` in the context):
`nginx:1.28-alpine` with `nginx.conf` baked in as `/etc/nginx/templates/default.conf.template` and
`NGINX_ENVSUBST_FILTER=^SSO_` (moved out of compose). `templates/` is created before `COPY --chmod=0644`, which
would otherwise create it 0644. Compose `nginx` now uses `${DOCKER_USER}/sso-nginx:${IMAGE_TAG}` (with `build:`)
and no longer mounts the template; the dev overlay mounts it back for live edits. The `sso-server` image carries
`/app/scripts/gen_keys.sh` and `gen_selfsigned_cert.sh` (openssl/bash are in the base image), and the deploy kit
`/app/deploy/` (`docker-compose.yml`, `env.example`, `scripts/upgrade_db.sh`); `.dockerignore` re-includes
`.env.example` only. `gen_keys.sh` takes `HOST_KEYS_DIR` for the printed `.env` line when run in a container.
`upgrade_db.sh` skips the image build when there is no `Dockerfile` (image-only install). New on-demand compose
service `certbot` (profile; `certbot/certbot:v5.1.0`, `SSO_LETSENCRYPT_DIR`, ACME webroot) for Let's Encrypt
without a host package. `.gitignore`: `letsencrypt/`, `docker/prod-certs/`. CI draft: builds `sso-nginx`, checks
the deploy kit / generators / `nginx -t` from the images, runs the secret gate as a matrix over both images
(Alpine CA bundles `etc/ssl/cert.pem`, `etc/ssl1.1/cert.pem` allowlisted) and pushes both. Docs: README §3/§7
("VPS from images only" runbook), `.env.example`, deployment plan v1.6 (§3.2, §7, §12.2). `docs/SSO-Setup.md`:
new §12 "Deploy to a VPS from the Docker images only" (prerequisites incl. GHCR login and DB account host = VPS IP,
deploy kit, `.env`, keys and bootstrap cert from the image, pull + `upgrade_db.sh`, start/verify with `--resolve`,
Let's Encrypt via the certbot service + `/etc/cron.d/sso`, IP-only variant, admin allow-list, upgrades/rollback)
and VPS troubleshooting rows. Concrete `TAG=0.1.2` variable instead of `<tag>` placeholders (bash read `<` as a
redirect), plus the commands to build and push both images to GHCR. `docker pull "$IMG"` before using the image
(docker run reused a stale cached image of a re-pushed tag on the VPS) and an `SSO_DIR` variable instead of a
hard-coded `/opt/sso`; matching troubleshooting row.

**Tests.** QA static `test_DEPLOY_22_image_only_vps`. Manual: built both images; extracted the kit; generated a
key pair (owner 10001, 0600, kid equal to the host computation) and a cert from the image into host dirs;
`nginx -t` on the baked template; the CI per-layer forbidden-file / private-key scan and history check run
locally on both images; `docker compose run --rm certbot --version`.

## 2026-10-17 — devops: serve the SSO by IP address (`SSO_TLS_REJECT_UNKNOWN_SNI`)

**Goal.** Allow `SSO_HOSTNAME` / `SSO_ISSUER` to be an IP (e.g. `https://192.168.0.212` on a LAN).

**Root cause.** Clients send no SNI when connecting to an IP literal, so the handshake fell to nginx's `:443`
catch-all, whose `ssl_reject_handshake on` aborted it (`TLSV1_UNRECOGNIZED_NAME`). The dev cert also had no
IP SAN for the host IP.

**Implementation.** `docker/nginx.conf`: the catch-all's `ssl_reject_handshake` comes from
`SSO_TLS_REJECT_UNKNOWN_SNI` (compose default `on`, unchanged behaviour) and it now carries the SSO cert, so
with `off` the handshake completes and nginx routes by Host (SSO host -> SSO block, anything else -> 444).
`scripts/gen_selfsigned_cert.sh <IP>` writes an `IP:` SAN instead of `DNS:`. Documented in `.env.example` and the
README §3 table. `docs/SSO-Setup.md` rewritten: address choice (localhost vs LAN IP) as step 1, first install via
`scripts/upgrade_db.sh`, cert-verified checks and `sso_login_check.py`, admin UI (v1.3d) as shipped instead of
"planned", `sso.0007` in the migration table, unused `SSO_DOMAIN` dropped, troubleshooting moved to the end.

**Tests.** `nginx -t` on the rendered template with `on` and `off`; QA static checks.

## 2026-10-17 — scripts: `sso_login_check.py` (verify a user: login, print permissions, logout)

**Goal.** A quick operator check that a user can log in and which app permissions they receive.

**Implementation.** `scripts/sso_login_check.py` (stdlib only, no Django): `POST /api/v1/auth/login` in native
mode, prints id/username/email and groups/perms from the login response, `GET /api/v1/auth/me` and the access
token's claims (decoded unverified, display only), then `POST /api/v1/auth/logout` to blacklist the refresh
token. Password from `SSO_PASSWORD` or a prompt; tokens are never printed. `--url` defaults to `SSO_URL`, else
`SSO_ISSUER` from the repo `.env`, else `http://localhost:8000`; a bare host gets `https://`. For the issuer
host / localhost it pins the dev cert (`$SSO_CERTS_DIR/$SSO_TLS_CERT_FILE`): the server must present exactly
that cert, name not checked (it is issued for localhost). `--cacert` / `--insecure` override. Exit codes: 0 ok, 1 login refused
(401/403/429), 2 usage, 3 other failure.

**Tests.** Checked manually against a pytest-django `live_server` (success → rc 0 with `application.app1`
shown in all three sources; wrong password → rc 1 `invalid_credentials`). No test added to the suite.

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
