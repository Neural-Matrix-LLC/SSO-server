# QA results: SSO-server v1.3d admin web UI (feat/v1.3d-admin-ui)

Independent QA pass, 2026-10-15 evening (times PT, UTC-7). Local commits only, nothing pushed.

## Scope
- `adminui` app: login/logout, own session cookie `__Host-sso_admin_sid`, CSRF (`__Host-sso_admin_csrf`), session
  guard (idle/absolute timeout, IP binding, revocation, admin re-check), step-up page, all §10 pages, error pages,
  CSP and security headers, optional admin hostname (`adminui.E001` + Host check).
- `sso/admin_ops.py` refactor (admin REST API now thin over it), audit `channel` (migration `sso 0007`), AST-only
  permission-file parser (`application/permfile.py`).
- Deploy: nginx UI locations + allow-list dir, admin-host include folder, compose/.env.example, `sso_schema_check`,
  `scripts/upgrade_db.sh`, `docs/db/upgrade-v1.3-to-v1.3d.sql`.

## Results

| Run | Environment | Result |
|---|---|---|
| `scripts/test_both_django.sh` (final commit) | Py 3.13.5, Django 5.2.18 / 4.2.30, SQLite | 532 passed / 7 skipped (MySQL-only) on both, coverage 93.1 %, exit 0 |
| Full suite, MySQL 8.4 | sso-test image, host network, final code | 539 passed / 0 skipped, coverage 96.2 % |
| Full suite, MySQL 8.0 | sso-test image, host network, QA-fix code | 538 passed / 0 skipped, coverage 96.2 % (the one test added later is a pure unit test) |
| First MySQL 8.4 run | before the QA fixes | 536 passed |
| Repo static checks (`qa/tests -m static`) | | 35 passed, 1 skipped (needs a running server) incl. new DEPLOY_21 |
| `sqlmigrate sso 0007` | MySQL 8.4 and 8.0 | identical; equals the DDL in `docs/db/upgrade-v1.3-to-v1.3d.sql` |
| DBA SQL file on a real v1.3 schema | MySQL 8.4: migrate to `sso 0006`, pipe the file into `mysql` | `migrate --check` 0, `makemigrations --check` no drift, `sso_schema_check` "schema OK ... v1.1-v1.3d" |
| `nginx -t` | nginx 1.28-alpine, template rendered | OK with empty dirs and with the admin-host sample enabled |
| Black-box UI (`qa/blackbox/bb_v13d.py`) | browser-less HTTPS client -> nginx 1.28 (host network, self-signed TLS) -> gunicorn 2 workers, SQLite, `SSO_DEBUG=False` | 31/31 (runs r3, r4), 33/33 after adding U-31/U-32 (r5) |
| nginx allow-list | `deny all` snippet in `sso-admin-ui.d` | UI login + pages 403; API and Django admin 200 |
| Admin hostname | `SSO_ADMIN_UI_HOSTNAME=admin.localhost` + sample block | UI on main host 404, on admin host 200; API on admin host 404 (nginx); static 200; `adminui.E001` when the name is missing from `SSO_ALLOWED_HOSTS` |

Black-box checks: U-01 anonymous -> login; U-02 CSP `default-src 'none'`, `frame-ancestors 'none'`, XFO DENY,
`no-store`, Referrer-Policy; U-03 CSRF cookie `__Host-`; U-04/05 wrong password and non-admin get the same generic
error and no session; U-06 session cookie Secure/HttpOnly/SameSite=Strict/Path=/, no Expires; U-07 dashboard; U-08
POST without CSRF 403; U-09 create user; U-10..14 step-up (redirect, wrong password, re-auth, confirm page,
suspend); U-15 audit page row; U-16/17 API `GET /admin/audit?channel=ui` returns only `ui` rows, bad channel 400;
U-18 UI cookie is not API auth (401); U-19 bearer is not UI auth; U-20..22 service secret shown once with
`no-store`, not on the detail page, rotate gives a new one; U-23/24 import preview then apply (HMAC digest); U-25
Python permission file rejected, never executed; U-26 audit CSV; U-27 dropped elevation asks again; U-28 replay of a
logged-out cookie fails; U-29 API logout-all ends a live UI session; U-30 Django admin separate; U-31/32 step-up from a
POST-only route returns to the form page.

## Defects found and fixed

| Id | Severity | Found by | Defect | Fix |
|---|---|---|---|---|
| V13D-00 | High (blocker) | developer tests | UI login did not stick: `auth_login(..., backend=ModelBackend)` named a backend not in `AUTHENTICATION_BACKENDS`, so the next request was anonymous | use the backend set by `authenticate()` |
| V13D-01 | Medium | code review | step-up required by a POST-only route (e.g. grant `sso_admin`) redirected to re-auth with `next=` the POST URL; after re-auth the GET answered 405 | `next` = the form's `back` field or the same-origin Referer page (still filtered by `safe_next`); test + U-31/32 |
| V13D-02 | Low | code review | login/re-auth throttle: `cache.incr` raises `ValueError` if the bucket expires between `add` and `incr` (500) | retry with a fresh bucket; unit test |
| V13D-03 | Low | code review | users CSV export ran one groups query per user | `prefetch_related("groups")` |
| V13D-04 | Low | code review | `audit.record` without a request would have stored `channel=api` | `channel=system` when there is no request; unit test |

Test fixes (expectations, not product defects): import test now allows the app-access record the importer creates by
design; `test_admin_is_not_at_default_path` now asserts `/admin/` is the UI login, not Django admin; stale
`test_DEPLOY_19` (SSO_TRUSTED_PROXIES).

## Observations (no change made, for Thomas)
- `channel = django_admin` is reserved: Django admin changes still go only to the `sso.audit` log, not to
  `sso_adminauditlog` (unchanged since v1.3). Design §13 now says so.
- With `SSO_ADMIN_UI_HOSTNAME` set, nginx still proxies `/admin/` on the main host; Django answers 404 there.
- Throttles: 5 UI logins/min per username. Repeated black-box runs within one minute hit it (expected).
- MFA not implemented (TODOS).
- Script artefact: `/tmp/myrun.sh` was edited while the 8.0 run was still executing, so the first lines of
  `q84-final.log` are connection errors from that run's tail; the 8.4 suite and DBA check below them are clean.

## Teardown
Containers qa-mysql-8.4/8.0 removed by the runner; qa-bb-nginx and the black-box gunicorn stopped after the pass;
throw-away passwords, secret key and SQLite DB under /tmp/bbd removed. Logs: qa/run/v13d/ (git-ignored).
