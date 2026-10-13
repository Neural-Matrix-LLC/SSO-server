# QA results: SSO-server v1.2a (feat/v1.2a @ c959c1f)

Status: **complete** (2026-10-13, ~05:10 PT). 1 defect (Low), 2 Info; MySQL concurrency BLOCKED.

## State
- Branch `feat/v1.2a` @ c959c1f (badede6, 3477b53, c959c1f on top of feat/app-permissions incl. QA bf3d708); local only.
  Tree clean before QA; QA changes only under `qa/`.
- Docker / docker compose / podman: **not installed**; no MySQL server (only the `mysql` client binary). Nothing installed.

## Progress log
- Developer suite (QA-run, fresh venvs under /workspace/tmp, Django 5.2.18): Py 3.13.16 **291 passed / 7 skipped**,
  Py 3.11.14 **291 passed / 7 skipped** (coverage 99%). Skips: 6 MySQL integration + 1 real-thread concurrent refresh
  (SQLite). Matches Philip's lead check.
- QA round Py 3.13 attempt 1 (kept in `qa/run/v12a-py3.13-attempt1`): 6 failures, 5 were harness/test issues
  (verifier CORS env missing; `/me` of a suspended user is 403 `account_inactive`, not 401 (by design, sso/errors.py);
  a forged-with-our-key token case was invalid) and fixed; 1 real defect (V12A-01).
- QA round Py 3.13 (final, `qa/run/v12a-py3.13`): functional 311 passed / 1 failed (V12A-01) / 2 skipped; throttle 5 passed.
- Interruption at ~04:30 PT during the Py 3.11 round: leftover processes (runner, pytest, 3 gunicorns, verifier) stopped by
  PID; Py 3.13 logs/junit intact, not redone; **Py 3.11 round redone from scratch**.
- Py 3.11 round (redo): functional 311 passed / 1 failed (V12A-01) / 2 skipped; throttle phase running.
- Py 3.11 round (redo) throttle: 5 passed. All processes stopped by PID; ports 8050-8059 free.

## Counts (servers and pytest on the same interpreter; Django 5.2.18; SQLite throw-away DBs)
| Area (file) | Py 3.13.16 | Py 3.11.14 |
|---|---|---|
| v1.2a (`test_v12a.py`, 50 items) | 49 pass, 1 fail (V12A-01) | 49 pass, 1 fail (V12A-01) |
| v1.1 regression: login 23, refresh 15, logout 8+1 skip, logout-all 7+1 skip, me 11, introspect 16, errors 25, security_jwt 43, cookies/origin 9, legacy 10, e2e (with verifier) 9, JWKS/disc/health 15 | 191 pass, 2 skip (Q-09/LOGOUT-07, known) | same |
| deploy (static) 35, key config 36 | 71 pass | 71 pass |
| throttle phase (spec rates, fresh DB) | 5 pass | 5 pass |
| **Total** | **316 pass, 1 fail, 2 skip** | **316 pass, 1 fail, 2 skip** |
| Developer suite | 291 pass / 7 skip | 291 pass / 7 skip |

v1.2a areas, both Pythons: suspend (SUSP-01..05) 5/5; update() gap + sweep (UPD-01..03) 5/5; sid (SID-01..03) 3/3;
refresh reuse (REUSE-01..07) 7/7; admin guards via HTTP UI (ADM-01..07b, 14 items) 13/14; commands (CMD-01..06, 15 items)
15/15; migration 0002 (MIG-01/02) 2/2.

## Defects
- **V12A-01 (Low): an admin can suspend themself through the user change form.** The guard exists only in the
  *Suspend* action (`sso/admin.py:150-154`); `SSOUserAdmin` (`sso/admin.py:168`) has no form/`save_model` check.
  Repro: log in to `/sso-admin/` as superuser X, open `/sso-admin/auth/user/<X>/change/`, untick *Active*, Save → 302,
  X `is_active=False`, all X's tokens revoked, X locked out of the admin (recoverable by another admin or the shell).
  Test: `test_V12A_ADM_01b_self_suspend_via_change_form`. Fix idea: refuse `is_active=False` for `obj.pk == request.user.pk`
  in `SSOUserAdmin.save_model` / form clean (or make the field read-only on one's own record).
- **V12A-02 (Info): `notify_url` missing scheme is handled differently.** Admin form (`sso/admin.py:29-32`,
  `assume_scheme="https"`) silently stores `svc.example.test/x` as `https://svc.example.test/x`; `register_service`
  refuses it. Both end with HTTPS-only values (requirement met); just inconsistent. http, `javascript:`, ftp are refused
  in both.
- **V12A-03 (Info, observation):** `/me` of a suspended user answers **403 `account_inactive`** (simplejwt `user_inactive`
  mapped in `sso/errors.py:106`), not 401; consistent with refresh (§5/§10). Tests expect 403.
- Pinned as designed (§10): UPD-03 residual gap (update() suspend + update() reactivate, no use, no sweep → old tokens
  survive); REUSE-04 replay after plain logout creates a `RevokedSession` row (open question in §10).
- Not a v1.2a finding: a refresh token validly signed with the server key but never issued (unknown jti) is accepted
  (simplejwt checks only the blacklist); requires the private key.

## Blocked
- **V12A-REUSE-08 / developer `sso/tests/test_sessions_reuse.py:152` (real-thread concurrent refresh) and the 6
  `test_mysql_integration.py` cases on MySQL 8.0 and 8.4**: Docker / docker compose are not installed (no MySQL server).
  Needed: Thomas's approval to install Docker Engine + compose plugin on the box, then
  `MYSQL_IMAGE=mysql:8.0 SSO_TEST_MYSQL_VOLUME=sso-test-mysql-8.0 docker compose -f docker-compose.test.yml -p sso-qa-v12a run --rm --build tests`,
  the same with `mysql:8.4` / `sso-test-mysql-8.4`, then `docker compose -p sso-qa-v12a down -v` for each. Nothing was installed.
  REUSE-07 covers the HTTP-level parallel refresh (serialised by 1 gunicorn worker), not the DB race.

## Artifacts (gitignored)
`qa/run/v12a-py3.13/`, `qa/run/v12a-py3.11/` (pytest logs, junit, server logs, server cmdlines);
`qa/run/v12a-py3.13-attempt1/`, `qa/run/v12a-py3.11-interrupted/` (superseded); developer-suite logs in `/workspace/tmp/`.
