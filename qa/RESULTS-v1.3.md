# QA results: SSO-server v1.3a + v1.3b + v1.3c (feat/sso-v1.3)

Independent QA pass, 2026-10-15 (times PT, UTC-7). Not pushed; local commits only.

## Scope
- v1.3a admin API: auth matrix with the round-5 rule (active + **is_staff** + (`sso_admin` or superuser)), step-up,
  permission import, service tokens, inactive-users feed (incl. **deleted users via tombstone**), reauth token
  dropped on plain logout.
- v1.3b: device clients (Ed25519 private_key_jwt), on-behalf-of (`actor_token`), sso-client 0.2 token sources.
- v1.3c: signed webhooks (outbox + worker), `notify_secret` at rest, admin webhook endpoints, sso-client receiver.

## Results

| Run | Environment | Result |
|---|---|---|
| Developer suite, SQLite | Py 3.13.5, Django 5.2.18 | 467 passed / 7 skipped (MySQL-only) |
| Developer suite, SQLite | Py 3.13.5, Django 4.2.30 | 467 passed / 7 skipped |
| Developer suite, MySQL 8.4.11 | sso-test image, host network | 474 passed / 0 skipped, coverage 97.4 % |
| Developer suite, MySQL 8.0.46 | sso-test image, host network | 474 passed / 0 skipped, coverage 97.4 % |
| sso-client 0.2 tests | Py 3.13 venv | 90 passed |
| Black-box API (`qa/blackbox/bb_v13.py`), MySQL 8.4.11 | gunicorn (2 workers) + webhook worker in the sso-test image, Redis 7.2.5, local HTTPS receiver | 47/47 (two consecutive runs) |
| Black-box API, MySQL 8.0.46 | same, fresh database | 47/47 |

Black-box checks: A-01..A-15 (admin auth matrix incl. superuser-not-staff 403 and staff-without-sso_admin 403,
reauth from a logged-out session rejected, step-up, import dry-run/real/idempotent, inactive feed suspended + deleted),
B-01..B-11 (service tokens via `ServiceTokenSource`, `check_service`, on-behalf-of with `act`/`delegation_allowed`,
forged actor fails closed, device register/list/duplicate 409, `DeviceTokenSource`, suspended owner: device refused and
existing device token inactive), C-01..C-21 (rotate-notify-secret step-up and shown once, event filter validation,
`user.suspended` / `token.revoked(suspended)` / `user.reactivated` / `user.deleted` / `permission.changed` delivered
over verified TLS, signature verified with `sso_client.verify_webhook`, wrong secret rejected, subscription filter,
503 -> retry -> delivered, delivery history, redeliver keeps the event id, `keys.rotated` baseline, no secret in audit).

## Defects found and fixed

| Id | Severity | Found by | Defect | Fix |
|---|---|---|---|---|
| V13-01 | Medium | MySQL 8.4 suite | `run_webhook_worker` called `close_old_connections()` inside a caller's transaction: on MySQL this closed the connection (`OperationalError` in `test_worker_command_once`; would also break `call_command` from code holding a transaction). SQLite hid it. | Only close stale connections when not in an atomic block. Re-verified on 8.4 and 8.0. |

Test-script issues (not product defects), fixed in the script: wrong import payload keys, `require` must be
`application.app1`, permission grant is `POST`, earlier runs' services shared the receiver URL (now deactivated at start
with step-up, and only events newer than the run start count).

## Observations (no change made)
- Admin-initiated logout-all emits `token.revoked` with reason `admin`; the user's own logout-all emits `logout_all`.
- Deactivating a service needs step-up (by design, v1.3a), so stale QA services must be deactivated with a reauth token.
- The first worker start emits a `keys.rotated` baseline event to all subscribers.
- A retry already claimed by a worker when its service is deactivated is still sent once (the check runs at send time).
- DNS rebinding between the address check and the connect is possible (URLs are set by admins only); documented in the
  design.

## Teardown
Containers qa-bb-web, qa-bb-worker, qa-bb-mysql, qa-bb-redis, qa-mysql-8.4/8.0 removed; random DB passwords, the env file,
throw-away JWT keys and the receiver certificate were shredded/removed from /tmp/w. Logs are in qa/run/v13/ (git-ignored).
