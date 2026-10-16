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

## MySQL 8.4 run (2026-10-13, ~17:50-18:15 PT; approved by Thomas in chat; 8.4 only)
- **Install:** Docker Engine from the official Docker apt repo (`download.docker.com/linux/debian trixie stable`,
  key in `/etc/apt/keyrings/docker.asc`): docker-ce, docker-ce-cli, containerd.io, buildx and compose plugins.
  **Docker 29.9.0, Compose v5.6.0.** The box has no systemd (PID 1 = tini), so `dockerd` was started directly with sudo
  (log `/var/log/dockerd-qa.log`, pid `/run/dockerd-qa.pid`); it is left installed and running. No other system config changed.
- **Code under test:** `feat/v1.2a` @ c959c1f, built from a detached worktree (`/workspace/sso-v12a-c959c1f`, since removed)
  because the main tree had the Developer's uncommitted work at the time (since committed as 7e49116 / 2235188; neither
  touches the code exercised here: `sso/views.py`, `revocation.py`, `tokens.py`, `test_sessions_reuse.py`,
  `test_mysql_integration.py` are unchanged c959c1f..2235188). Throw-away `.env.test` with random passwords (shredded).
- **MySQL server:** `8.4.11` (MySQL Community Server - GPL), from `SELECT version()` inside the tests container.
  Test image: Python 3.13.16, Django 5.2.
- **Harness note (box limit, not a repo defect):** the prescribed
  `MYSQL_IMAGE=mysql:8.4 SSO_TEST_MYSQL_VOLUME=sso-test-mysql-8.4 docker compose -f docker-compose.test.yml -p sso-qa-v12a run --rm --build tests`
  built and started both services (mysql healthy), but container-to-container traffic on the compose bridge network
  does not work on this box (`/dev/tcp/mysql/3306` from a peer container times out; dockerd logs
  "Failed to delete conntrack state ... invalid argument"): 65 passed, 233 errors `(2002, "Can't connect to server on 'mysql' (115)")`
  (`qa/run/mysql84/full-suite.log`). Re-run with the SAME built image and the compose file's environment, joined to the
  mysql container's network namespace (`docker run --network container:sso-qa-v12a-mysql-1`, `SSO_DBHOST=127.0.0.1`).
- **Full developer suite on MySQL 8.4:** **296 passed, 2 failed, 0 skipped** (298 = 291 + the 7 previously skipped),
  coverage 99% (`qa/run/mysql84/full-suite-sharedns.log`).
- **The 7 previously skipped tests, run explicitly** (`qa/run/mysql84/previously-skipped-7.log`):

| Test | Result |
|---|---|
| test_mysql_integration::test_server_version_supported_and_as_expected | PASS |
| test_mysql_integration::test_init_script_accounts_use_caching_sha2_password[sso_app] | **FAIL (V12A-04)** |
| test_mysql_integration::test_init_script_accounts_use_caching_sha2_password[sso_migrator] | **FAIL (V12A-04)** |
| test_mysql_integration::test_client_logs_in_with_caching_sha2_password[sso_app] | PASS |
| test_mysql_integration::test_client_logs_in_with_caching_sha2_password[sso_migrator] | PASS |
| test_mysql_integration::test_tls_required_mode_works_against_server_auto_certs | PASS |
| test_sessions_reuse::test_concurrent_legit_refreshes_do_not_revoke_the_session (**REUSE-08**) | PASS |

- **REUSE-08 repeated 5×:** 5/5 passed (1.5-1.8 s each; `qa/run/mysql84/reuse08-repeat-{1..5}.log`). No flakiness seen.
- **V12A-04 (Low, test-only defect):** `sso/tests/test_mysql_integration.py:48` compares `rows == [("caching_sha2_password",)]`
  but mysqlclient's `fetchall()` returns a tuple: actual `(("caching_sha2_password",),)`. The accounts DO use
  caching_sha2_password (the value matches; the login-with-caching_sha2 tests pass). Fix: `assert list(rows) == [...]`.
  Repro: the compose run above on MySQL 8.4 (expected to fail the same way on 8.0; 8.0 not run per instructions).
- **Teardown:** `docker compose -p sso-qa-v12a down -v` (volume `sso-test-mysql-8.4` and network `sso-qa-v12a_default`
  removed); images `sso-qa-v12a-tests:latest` and `mysql:8.4` removed; build cache pruned (fresh install, all from this
  run). Afterwards: 0 containers, 0 images, 0 volumes, only Docker's default networks. Docker stays installed.
- **Blocked list update:** REUSE-08 and the MySQL integration tests are no longer blocked for 8.4; MySQL 8.0 not run (skipped as instructed).

## MySQL 8.4 run @ 2235188 (aborted, superseded by the run @ df06e10 below)
- Attempt 1: the compose build failed (deb.debian.org returned 500 on apt InRelease, a transient outage on the mirror side).
- Attempt 2: the prescribed `docker compose ... run --rm --build tests` command gave 65 passed / 235 errors, all `(2002) Can't connect to server on 'mysql' (115)`.
  This is the known compose bridge limit on this box, not a product issue.
- The shared-namespace rerun was stopped when df06e10 (the V12A-04 fix) landed. Per Philip's update, MySQL was rerun at df06e10 only.
- Lesson for the harness: stale `SSO_TEST_*` variables exported in the shell override `--env-file` (`sudo -E`).
  Take the credentials from the mysql container env, or unset those variables first.

## Fix verification @ 7e49116 (code at HEAD df06e10, Py3.13.16, Django 5.2.18, 2026-10-13 ~18:20-18:35 PT)
- **V12A-01 FIXED.**
  - ADM-01b: unticking is_active on your own change form now re-renders with "You cannot suspend yourself.", and is_active stays True.
  - New ADM-01c: another superuser can still suspend a superuser through the change form (302, is_active=False).
  - ADM-01: the action guard still refuses self-suspend.
- **V12A-02 FIXED.**
  - The admin form (`HttpsURLFormField`, sso/admin.py) now rejects a schemeless notify_url: 200 with a form error, nothing stored.
  - `register_service` already refused it (CMD-03), so both entry points are consistent and https-only, as the docs say.
  - ADM-07 expectation changed from "recorded" to rejected.
- **v1.2a + v1.1 regression on Py3.13** (`run_v12a_round.sh qa/.venv-py3.13.16 py3.13-df06e10`):
  - functional: 313 passed / 0 failed / 2 skipped (Q-09 and one other known skip);
  - throttle: 5/5;
  - total: 318 passed / 0 failed / 2 skipped (was 316 / 1F with V12A-01; +1 for the new ADM-01c);
  - all ports 8050-8059 were free after the run.
- **Developer suite, independent check:** 293 passed / 7 skipped on Py3.13.16 + Dj5.2 (`--cov-fail-under=90` met), which matches Philip's figure.
  The 7 skips are the MySQL-only tests.

## Fix verification @ df06e10 (MySQL 8.4, 2026-10-13 ~18:36 PT)
- Docker 29.9.0, Compose v5.6.0, MySQL **8.4.11** (`SELECT version()`).
- Built the tests image with compose at df06e10. Ran it with `--network container:sso-qa-v12a-mysql-1` and `SSO_DBHOST=127.0.0.1`
  (the bridge workaround).
- The 7 formerly skipped tests: **7/7 PASSED**.
  - 6 are in `test_mysql_integration.py`, including both `test_init_script_accounts_use_caching_sha2_password` cases.
  - The 7th is REUSE-08, `test_concurrent_legit_refreshes_do_not_revoke_the_session`.
- **V12A-04 FIXED.**
- REUSE-08 repeats: **5/5 passed**, 2.3 to 2.6 s each.
- Teardown:
  - ran `down -v` (volume `sso-test-mysql-8.4` and network removed);
  - removed the images `sso-qa-v12a-tests:latest` and `mysql:8.4`, and pruned the build cache (787.9 MB);
  - `.env.test` was shredded;
  - 0 containers / 0 images / 0 volumes remain;
  - Docker 29.9.0 is still installed, and dockerd is still running.
- Logs: `qa/run/mysql84-df06e10/`.

## Final verdict (v1.2a @ df06e10)
**PASS, ready to merge from a QA standpoint.**
- V12A-01, V12A-02 and V12A-04 are fixed and verified. V12A-03 (Info) is unchanged and not blocking.
- No new defects.
- Open item: MySQL 8.0 was not run (out of scope by Thomas' decision).
