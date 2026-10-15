# QA results: SSO-server v1.2b (feat/v1.2b)

## State
- Branch feat/v1.2b, HEAD a368f1f (docs) > 605873c (sso-client) > 6fdfe7f (server) > 107ae38 (qa v1.2a). Not pushed.
- Main tree clean at start (2026-10-14 14:16 PT), so no worktree needed.

## Progress log
- 14:16 PT: verified branch/SHAs/tree; started reading the spec (§4, §4.4, §4.5, §11; SSO-CLIENT-LIBRARY-DESIGN.md).
- 14:20 PT: the main tree picked up OTHERS' uncommitted work (16 modified files: SSO_CLIENT_IP_HEADER feature in
  sso/clientip.py, clients/python ip/config/adapters, docs, tests). So all QA runs happen in a temporary detached
  worktree `/workspace/tmp/wt-v12b` @ a368f1f; qa/ files are copied back and committed (qa/ paths only) at the end.
  A developer-suite run I had started in the main tree (contaminated) was stopped by PID and discarded.
- 14:22 PT: `pip install 'sso-client[fastapi,flask,django] @ git+file:///…/sso-server@a368f1f#subdirectory=clients/python'`
  into a fresh Py3.13.16 venv: OK (0.1.0). Library's own tests @ a368f1f: 57 passed. (Run against the dirty main tree's
  tests they give 14 failures, only because the uncommitted tests expect the uncommitted client_ip_header API.)
- 14:35 PT: developer suite @ a368f1f (worktree), Py3.13.16 + Django 5.2.18: **362 passed / 7 skipped** (cov >= 90),
  matches Philip. Skips: 6 MySQL integration + REUSE-08 (server DB needed).
- 14:40 PT: wrote qa/tests/test_v12b.py (self-starting servers on 8061-8068) and harness/run_v12b_round.sh
  (= v12a round + MODE arg exported as SSO_IP_BINDING_MODE for the main servers).
- 15:05 PT: qa/tests/test_v12b.py alone (fresh DB): 64 passed + new INTRO-05 probe -> **V12B-01** (introspect `ip`
  longer than 128 chars or non-string -> 400 instead of "no IP"). CACHE-02 measured 10.0 s worst case (separate caches).
- 15:15 PT: qa/tests_client (library, Py3.13.16 venv from pip git+file): 108 passed (IP parity 68 rows/values,
  check/cache/fail-closed/config 27, adapters 13).
- 15:16 PT: starting regression rounds: run_v12b_round.sh py3.13 NOIP (binding off), then ENFORCE (binding on).
- 15:28 PT: added TEST-PLAN §3.15 (40 cases) + §5.4 traceability + counts row. Round NOIP functional:
  378 passed / 5 failed (all INTRO-05 = V12B-01) / 2 skipped (known Q-09 etc.). Throttle phase running, then ENFORCE.
- 14:56 PT (steering): HEAD moved to b7570cf (+345eed7 custom client-IP header, c4a3fde SSOProtocolError.status_code,
  b7570cf introspect malformed claims -> inactive). The ENFORCE round @ a368f1f was stopped by PID during its throttle
  phase (functional part complete: 360 passed / 23 failed / 2 skipped, classified below). Worktree moved to b7570cf;
  everything re-run there. Added HDR-01..03 (server) and LIB-IP-07/08, LIB-ADP-06 (library).
- 15:45 PT @ b7570cf: dev suite 371 passed / 7 skipped (Philip's 362 was @ a368f1f; +9 developer tests in the new
  commits). Fresh pip-from-git venv @ b7570cf: library's own tests 71 passed. qa/tests_client: 124 passed.
- 16:20 PT @ b7570cf: round NOIP 390 passed / 5 failed (V12B-01) / 2 skipped + throttle 5/5; round ENFORCE with
  SSO_TEST_INTROSPECT_IP=127.0.0.1: 390 / 5 (V12B-01) / 2 + throttle 5/5. E2E 24/24. Redis 7.4.11: (a) 7/8 on
  3 workers shared Redis, INTRO-04 failed only because the shared Redis carried other servers' qa-service
  introspect history into the 5/min server (shared bucket = proof of cross-process sharing); rerun alone on a fresh
  Redis: pass. (b) login/refresh throttle suite on 1 gunicorn x 3 workers + Redis: 5/5.
- 16:22 PT: MySQL 8.4 developer suite next.
- 16:40 PT (resume after interrupt): the MySQL run had in fact finished; its log is intact (378 passed). No rerun needed.
  The stray container had already exited. Client suite rerun once (b2) to include the CHK-05 status_code assertion: 124 passed.

## MySQL 8.4 developer suite @ b7570cf
MySQL 8.4.11 (official mysql:8.4 image), Docker 29.9.0 / Compose 5.6.0. The test container shares the MySQL container's
network namespace (the box bridge is broken), with SSO_DBHOST=127.0.0.1 and stale MYSQL_* shell variables unset.
**378 passed, 0 skipped**, coverage 99.83% (the 7 SQLite-skipped MySQL-only tests ran and passed).
Log: qa/run/mysql84-v12b/full-sharedns.log.

## Teardown (16:42 PT)
`docker compose -p sso-qa-v12b down -v` removed container, volume sso-test-mysql-8.4-v12b and network sso-qa-v12b_default.
Removed images sso-qa-v12b-tests, mysql:8.4, redis:7 (the Redis container ran with --rm and is gone); builder prune
reclaimed 788.5 MB; `.env.test` shredded. Afterwards: 0 containers, 0 images, 0 volumes, no sso networks. Docker is still installed.
No listeners on 8050-8069. All servers were stopped by recorded PID.

## Summary @ b7570cf (Py3.13.16, Django 5.2)
| Area | binding OFF (NOIP) | binding ON (ENFORCE, regression with ip) |
|---|---|---|
| Developer suite SQLite (Philip's 362/7 @ a368f1f confirmed) | 371 passed / 7 skipped | n/a |
| Developer suite MySQL 8.4.11 | 378 / 0 | n/a |
| v1.1 + v1.2a regression (functional) | 313 passed / 2 skipped | 313 / 2 (needs SSO_TEST_INTROSPECT_IP; raw @ a368f1f: 18 fails, all legit, see above) |
| v1.2b BIND (each test sets its own mode) | 24 / 24 | same |
| BFF | 6 / 6 | same |
| INTRO | 12 passed, 5 failed (V12B-01) | same |
| PROXY | 19 / 19 | same |
| CACHE (worst-case staleness 10.0 s) | 4 / 4 | same |
| HDR (custom client-IP header) | 12 / 12 | same |
| Throttle suite | 5 / 5 | 5 / 5 |
| sso-client QA (qa/tests_client): IP 81, CHK 5, CACHE 5, FAIL 10, CFG 7, ADP 16 | 124 / 124 | (ENFORCE SSO on 8065) |
| sso-client's own tests | 71 passed | |
| pip install from git subdir, fresh venv | OK | |
| E2E (FastAPI / Flask / Django apps against a live SSO) | 24 / 24 | ENFORCE included |
| Real Redis 7.4.11, 3 gunicorn workers | cache/binding pass; INTRO-04 pass on a fresh Redis; throttle 5/5 | |

## Defects
- **V12B-01 (Low)**, sso/serializers.py:43. An introspect `ip` that is longer than 128 characters or is not a string returns 400.
  §11 says it should be treated as "no IP". In ENFORCE this means no revocation, and the library returns 503.
- **V12B-02 (Low)**, clients/python/src/sso_client/adapters/django.py:63. If a view uses the lazy `request.sso` without
  the decorator and the SSO is down, the SSOError is not handled and the response is 500 instead of 503.
- **V12B-03 (Info)**, docs/SSO-CLIENT-LIBRARY-DESIGN.md:247-255. The FastAPI sample imports `require_permission` from the
  wrong module (ImportError), and it wrongly says that install() adds client-IP middleware. The README is correct.
- Info notes, no defect: CheckResult.reason is always "inactive"; setting NUM_PROXIES and TRUSTED together gives no
  warning (TRUSTED wins, as the spec says); a cached active answer can outlive an ENFORCE revocation by up to 30 s, and a 429
  fails closed at once (both documented).

## Verdict
**PASS with 2 Low defects and 1 Info item.** None of them blocks release. V12B-01 should be fixed before ENFORCE is used in production.

# Re-verify @ b3dbd2a (2026-10-14, 18:05-19:00 PT)
Python 3.13.16. Fresh venvs: dev /workspace/tmp/v12b-dev-b3db (from requirements.lock + dev requirements) and lib
/workspace/tmp/v12b-lib2 (uv, `sso-client[fastapi,flask,django] @ git+file://…@b3dbd2a#subdirectory=clients/python`;
fresh-venv install from git: OK). The older venvs had been damaged by a box reset.

| Area | binding OFF (NOIP) | binding ON (ENFORCE, with ip) |
|---|---|---|
| Developer suite (SQLite) | 379 passed / 7 skipped | n/a |
| Functional round (v1.1 + v1.2a regression + v1.2b) | **395 passed / 0 failed / 2 skipped** | **395 / 0 / 2** |
| … of which v1.2b: BIND 24, BFF 6, INTRO 17, PROXY 19, CACHE 4, HDR 12 | all pass | all pass |
| Throttle phase | 5 / 5 | 5 / 5 |
| qa/tests_client (sso-client against live SSOs) | **124 / 124** | (ENFORCE SSO on 8065) |

- **V12B-01: fixed.** The 5 INTRO cases now pass in both modes: `ip` over 128 chars, list, object, bool → treated as
  no IP. Under ENFORCE that means inactive + revoke, not a 400.
- **V12B-02: fixed.** ADP-05 now requires the lazy `request.sso` without a token to give a JSON 401, and an
  unreachable SSO to give a JSON 503 `sso_unavailable` with Retry-After 5. Both pass.
- **V12B-03: fixed.** The §13 FastAPI sample was extracted from the design doc and run against sso-client: it runs
  without error. The comment now says install() adds exception handlers only.
- Accepted expectation change (Philip): the sso-client default is now 1 retry. V12B_LIB_FAIL_01[502/503/504] now
  expect 2 hits (was 3). FAIL_02 (connection refused) now expects one retry with a 0.1 s backoff (0.08-2 s). Both pass.
- MySQL 8.4: **not run.** The box reset removed Docker, so a quick run is no longer cheap (it needs a reinstall, image
  pulls and a build). The last MySQL result is 378/0 at b7570cf. b3dbd2a touches the serializer, the Django adapter
  and docs only; the developer suite above covers the MySQL-only tests' SQLite counterparts.
- Teardown: servers stopped by recorded PID; nothing listens on 8050-8069. No containers were used (Docker is absent).

**Verdict @ b3dbd2a: PASS. No open v1.2b defects.**
