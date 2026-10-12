# SSO server — Sprint 1 QA results

| | |
|---|---|
| Build under test | `master` @ `70c950c` (6 commits), working tree clean outside `qa/` and `devops/` |
| Date | 2026-10-10, 03:50–04:20 PT (UTC-7) |
| Environment | gunicorn 26.2 (1 worker), Django 5.2.18, SQLite throw-away DB `qa/run/sso-test.sqlite3`, plain HTTP `127.0.0.1:8000`, `SSO_DEBUG=False`, `SSO_NUM_PROXIES=0`, `SSO_COOKIE_DOMAIN=` (host-only), `SSO_COOKIE_SECURE=True`, CORS `https://example.com`, test RSA-2048 key from `scripts/gen_keys.sh` (`qa/run/keys/`). Verifier demo: `examples/verifier` under uvicorn on `127.0.0.1:8001`. No real DB was used |
| Suite | `qa/tests` (black-box pytest), in 2 phases: functional + security with high throttle limits (`-m "not throttle"`), then `-m throttle` after restarting the server at spec-default rates (10/min IP, 5/min user, 60/min refresh) |
| Raw output | `qa/run/pytest-functional.log`, `qa/run/junit-functional.xml`, `qa/run/pytest-throttle.log`, `qa/run/junit-throttle.xml`, server logs `qa/run/sso-server-*.log`, demo outputs `qa/run/defect-4-5-demo.txt`, `qa/run/manual-checks.txt` |
| Re-run | `qa/run/manage.sh` (DB), `qa/run/start_sso.sh PORT LOG [ENV=…]` (server), `. qa/run/test.env` (suite config). The seed needs `SSO_ALLOW_SYNTHETIC_SEED=1` |

## 1. Summary

| | Count |
|---|---|
| pytest items collected | 211 (206 + 5 throttle) |
| **Passed** | **206** |
| **Failed** | **3** items = **2 cases** (LEGACY-06 ×2 parameters, LOGOUT-05) |
| **Skipped** | **2** (LOGOUT-07, LOGOUT-ALL-07: the spec doesn't decide; see §6) |
| Errors | 0 |
| Manual cases executed | 11, all passed (§4) |
| **Blocked** (Docker / MySQL 8.4 not available) | 6 cases or areas (§5) |
| Not executed (other reasons) | 4 (§5) |

Every case marked A\* ran with its prerequisite present (private key, `SSO_MANAGE_CMD`, verifier demo), so nothing was skipped for a missing prerequisite.

QA test fixes made during the run (QA's own test bugs, not product issues):
- **SEC-04 [sub]**: the tamper value `"1"` equalled qa_alice's real `sub`, so the payload bytes didn't change and the token was still valid. Now uses `sub+1` and asserts the payload actually changed.
- **ERR-11 [GET logout-all]**: DRF authenticates before the method check, so an unauthenticated GET correctly gets 401. The test now sends a valid Bearer and then expects 405.
- New case **LOGOUT-ALL-08**: exact boundary of the `ceil(revoked_at)` revocation rule (added to the plan).

## 2. Failing cases

### F-1 — LEGACY-06: login for a user whose stored hash is malformed returns 500 (defect 2 confirmed)
- **Severity:** Medium. No data leaks (the body is the uniform envelope and the traceback stays server-side), but it is a 5xx on the login path. Such users get a server error instead of `invalid_credentials`, the attempt gets no structured `sso.auth` log line, and the response differs from the unknown-user answer, which reveals that the account exists. It affects only rows with corrupt hashes in the shared `dcWebUsers`, e.g. legacy imports or hand edits.
- **Repro** (seeded DB):
  ```bash
  curl -s -w ' HTTP %{http_code}\n' -X POST http://127.0.0.1:8000/api/v1/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"qa_malformed","password":"x","client":"native"}'
  # qa_malformed: auth_user.password = 'pbkdf2_sha256$notanumber$<salt>$AAAA'
  # qa_truncated: auth_user.password = 'pbkdf2_sha256$390000$<salt>'   (no digest)
  ```
- **Expected:** `401 {"error":"invalid_credentials",…}`, the same as a wrong password.
  **Actual:** `500 {"error":"server_error","detail":"Internal server error."}`.
  (`qa_unusable` `!…` and `qa_unknownalgo` `nosuchalgo$…` correctly return 401.)
- **Cause:** `sso/serializers.py:61` `authenticate(...)` is called from `sso/views.py:132`, then goes through `AllowAllUsersModelBackend` → `User.check_password` → `django/contrib/auth/hashers.py:59 verify_password` → `PBKDF2PasswordHasher.must_update/decode` (`hashers.py:337`), which raises `ValueError` (`int('notanumber')` / not enough `$` parts). Nothing catches it, and `sso/errors.py:115-119` turns it into a 500 (traceback in `qa/run/sso-server-functional.log`).
- **Suggested fix:** in `check_credentials` wrap `authenticate()` in `try/except (ValueError, TypeError)`, then run `_dummy_hash(password)`, log `invalid_credentials` and return `None`.

### F-2 — LOGOUT-05: cookie-mode logout with no token returns 204 (spec ambiguity Q-05, not a defect)
- **Severity:** Low (needs a decision; behaviour is harmless).
- **Repro:**
  ```bash
  curl -s -w ' HTTP %{http_code}\n' -X POST http://127.0.0.1:8000/api/v1/auth/logout \
    -H 'Content-Type: application/json' -H 'Origin: https://example.com' -d '{}'
  ```
- **Expected (QA assumption from Q-05):** `400 invalid_request` or `401 token_invalid`. **Actual:** `204`, with a Set-Cookie that clears `sso_refresh`.
- **Cause:** a deliberate design choice: `sso/views.py:168-173` ("idempotent logout"), documented in README §10. `/refresh` without a token correctly returns 401.
- **Action:** Philip to confirm. If 204 is accepted, QA will change LOGOUT-05 to expect 204 plus a cleared cookie. I didn't change it, so the result stays visible.

## 3. The five suspected defects

| # | Suspected defect | Result | Evidence |
|---|---|---|---|
| 1 | Inactive user with correct password never gets `account_inactive` | **Fixed / confirmed working** | LOGIN-09: `403 account_inactive` (correct password). LOGIN-10: `401 invalid_credentials` (wrong password, no existence leak). ME/refresh paths also map inactive users correctly (REFRESH-09 403, INTRO-10 inactive). Code: `ssoproject/settings.py` `AUTHENTICATION_BACKENDS=[AllowAllUsersModelBackend]`, `sso/views.py:132-138`. Timing (LOGIN-M1, 15 samples each): wrong password 162.3 ms, unknown user 163.6, unknown email 163.6, duplicate email 163.4, inactive+wrong 162.4, inactive+correct 162.7 (medians). No timing signal |
| 2 | Malformed stored hash → 500 | **Confirmed open** | F-1 above |
| 3 | `iat` (seconds) vs `revoked_at` (µs): same-second tokens | **Fixed / confirmed working** | Rule `iat < ceil(revoked_at)` (`sso/tokens.py:103-121`), and new logins wait past the boundary (`tokens.py:124-131`). LOGOUT-ALL-05 (login right after logout-all → introspect active, refresh 200) passed. LOGOUT-ALL-08: tokens minted with `iat=floor(revoked_at)` are rejected by introspect (inactive), `/me` (401) and `/refresh` (401). With `iat=ceil(revoked_at)` they are accepted (active / 200 / 200). REFRESH-10 and REFRESH-11 (B8, independent of the blacklist) passed. Note: the server also rejects pre-revocation access tokens at `/me` and `/logout-all` (README §10), which settles Q-09 |
| 4 | `X-Forwarded-For` spoofing bypasses the per-IP throttle | **Confirmed in a misconfiguration only; mitigated in the shipped deployment.** Severity **Low** (config hazard) | Side instance with the default `SSO_NUM_PROXIES=1` reached directly: 11th login → 429, then **20/20** logins with client-chosen XFF values → 401 (throttle bypassed) (`qa/run/defect-4-5-demo.txt`). With `SSO_NUM_PROXIES=0` (direct) SEC-33/35 passed. Shipped compose doesn't publish `web` (`docker-compose.yml:33`), and nginx **overwrites** XFF (`docker/nginx.conf:93 proxy_set_header X-Forwarded-For $remote_addr`), so production is fine. Residual: `settings.py:156` defaults to 1. Anyone running gunicorn without nginx (e.g. the "shared-nginx" variant with a careless host nginx config) is exposed. The Dockerfile also has `--forwarded-allow-ips '*'` (`Dockerfile:57`). Recommendation: say this explicitly in README §3/§7, or default to 0 outside compose. Can't be verified end to end through nginx (Docker blocked) |
| 5 | 3 gunicorn workers + LocMem → throttle per worker | **Confirmed in a misconfiguration only; mitigated in the shipped deployment.** Severity **Low** | Side instance with 3 workers and the default LocMem cache: **29 of 40** logins from one IP were accepted (spec limit 10/min) (`qa/run/defect-4-5-demo.txt`). Shipped `.env.example:42` sets `SSO_CACHE_URL=redis://redis:6379/0` and compose runs Redis. `sso/checks.py` warns (`sso.W001`) in `check --deploy`. Residual: if `.env` lacks `SSO_CACHE_URL`, `settings.py:152` silently falls back to LocMem with 3 workers. Recommendation: give `SSO_CACHE_URL: ${SSO_CACHE_URL:-redis://redis:6379/0}` a default in `docker-compose.yml` `web.environment`, or fail fast when `GUNICORN_WORKERS>1` and LocMem is used |

## 4. Manual cases executed (all passed)

| ID | Result |
|---|---|
| LOGIN-M1 timing (B4) | Pass: medians within 1.4 ms across all six failure paths (§3 #1) |
| LOGIN-M2 structured log (B13) | Pass: one JSON line per attempt on `sso.auth` with username, IP, result, client, user_id. Counts in the functional log: success 307, invalid_credentials 120, invalid_request 33, account_inactive 24 |
| SEC-29 no secrets in logs | Pass: 0 occurrences of `eyJ` (JWT prefix) and 0 of the test password in all server logs |
| SEC-37 admin path | Pass: `/admin/` → 404; `/sso-admin/` → 302 to login |
| HEALTH-03 DB down | Pass: `503 {"error":"unhealthy","detail":"database"}` (side instance with an unreachable SQLite path) |
| ERR-15 500 envelope | Pass: the 500 in F-1 has the uniform envelope with no traceback, settings or secret |
| DEPLOY-09 fail-fast (B12) | Pass: empty `SSO_SECRET_KEY` → `ImproperlyConfigured: SSO_SECRET_KEY is empty…`; missing private key → `…JWT private key (SSO_JWT_PRIVATE_KEY_PATH) not found…` |
| DEPLOY-10 gen_keys.sh | Pass: private key 0600, public 0644, RSA 2048 (as requested; default 3072), prints a kid that matches the server's JWKS kid |
| DEPLOY-11 migrations (B11) | Pass: `showmigrations` → SSO-owned migrations only in `sso` (0001) and `token_blacklist`. No `clearsessions`/`remove_stale_contenttypes` in scripts or entrypoint. DEPLOY-08 (`makemigrations --check`) passed automatically |
| DEPLOY-12 flushexpiredtokens | Pass: runs, exit 0 |
| JWKS-08 key rotation (B6, §5.3) | Pass: side instance signing with key 2 and publishing keys 1+2 → JWKS lists both kids. An access token signed with the old key is accepted at `/me` (200), an old-key refresh token refreshes (200), and new tokens carry the new kid |

## 5. Blocked and not executed

**Blocked: Docker and MySQL 8.4 aren't installed on the box (not installed, per instructions):**

| Case / area | Why blocked |
|---|---|
| E2E-10 `docker compose up` (prod and dev overlay), self-signed TLS via nginx, suite through `https://localhost:8443`, demo page at `/demo/` | needs Docker |
| MySQL 8.4 integration run (`docker-compose.test.yml`): `sso_app` DML-only grants, `caching_sha2_password`, utf8mb4 collation, username case-insensitivity on MySQL (Q-27), DB TLS (`SSO_DB_SSL_*`) | needs Docker + MySQL 8.4 |
| LEGACY-09 restored `dcWebUsers` copy: user count unchanged after `migrate`, sample real logins | needs MySQL and a dump (staging) |
| SEC-36 / nginx: http→https redirect, 444 default server, nginx login `limit_req`, XFF overwrite seen end to end (defect 4 in situ) | needs Docker/nginx |
| SEC-38 container hardening: keys mounted `:ro`, uid 10001, read-only rootfs, healthcheck | needs Docker |
| DEPLOY-13 suite against the MySQL-backed build | needs Docker + MySQL (the Django 4.2 portability part is no longer shipped, per R9, and was not run) |

**Not executed (not Docker-related):**
- LEGACY-08 myFinance ↔ SSO cross-login: myFinance isn't available on the box.
- E2E-09 interactive browser run of `examples/frontend/index.html`. Its HTTP-level flow was covered automatically by E2E-03/04 (passed); the visual and UI-message checks are still to do.
- E2E-11 verifier refetching JWKS after rotation.
- DEPLOY-14 the Developer's own pytest/coverage run (it would write `.coverage`/`.pytest_cache` in the repo root, outside `qa/`).

## 6. Skipped cases and spec questions answered by the code
- LOGOUT-07 (double logout, Q-06): still undecided in the docs; not run.
- LOGOUT-ALL-07 (Q-09): README §10 now says `/me` and `/logout-all` reject pre-revocation tokens, and LOGOUT-ALL-08 confirmed `/me` → 401. QA proposes turning LOGOUT-ALL-07 into a hard assertion.
- Answered by the implementation (tests passed): Q-01 (singular key var fallback), Q-02 (`SSO_THROTTLE_*`), Q-07 (missing Bearer → 401 `token_invalid`, with `WWW-Authenticate: Bearer realm="sso", error="invalid_token"`), Q-10 (`invalid_client`), Q-11 (kid over SPKI DER, JWKS-04 passed), Q-14 (`Cache-Control: no-store` on token responses, REFRESH-12 passed), Q-15 (JSON-only parser, LOGIN-19 passed), Q-16 (empty domain → host-only cookie, SEC-20 passed), Q-28 (healthz 503 envelope).
- Still open for Philip: Q-05 (F-2), Q-06, login-CSRF Origin check on `/login` (README Q9), Q-18 (myFinance settings), Q-22 (reuse detection).

## 7. Other observations (no test failed)
- **Verifier JWKS refetch** (Low): `examples/verifier/sso_verifier.py:26` uses `PyJWKClient`, which re-downloads the JWKS on **every** token with an unknown `kid`. Spec §8.1 asks for at most one refetch per minute. Attacker-chosen kids can make each service hammer `/.well-known/jwks.json`. Suggest a rate-limited refetch wrapper in the reference package (consumers will copy it).
- Introspect returns more than §6.6 lists (`email, is_staff, token_type, iat, iss, aud, client_id`). That's fine for a service-authenticated endpoint; noted for the spec.
- Discovery advertises `token_endpoint` = `/api/v1/auth/login` (allowed by B2). QA still recommends omitting it (Q-17).

## 8. QA-side changes in this round (all inside `qa/`)
- `qa/tests/fixtures/seed_test_data.py`: **R27 guard**. It refuses (exit code 2, clear message) unless `SSO_ALLOW_SYNTHETIC_SEED=1` (alias `QA_ALLOW_SEED=1`) **and** the DB is local or throw-away:
  - SQLite: `:memory:`, under the temp dir or a `qa/` dir, or a name containing test/qa.
  - MySQL: host localhost/127.0.0.1/::1/socket/`db`/`mysql`, or a host listed in `SSO_SEED_LOCAL_HOSTS`.

  Verified: refuses without the flag; refuses a non-QA SQLite path; refuses host `prod-db.example.net`; allows 127.0.0.1/`db`/socket and the QA DB. Residual risk: `127.0.0.1` could be an SSH tunnel to production; the explicit flag is the second safeguard.
- `qa/tests/conftest.py`: allowed origin from **`SSO_TEST_ALLOWED_ORIGIN`** (default `https://example.com`; `SSO_ALLOWED_ORIGIN` still read as a legacy alias). Hostile-origin variants are now derived from it (no real domains left in the suite). Documented in `qa/tests/README.md`.
- Test fixes SEC-04 / ERR-11 and new LOGOUT-ALL-08 (§1). `TEST-PLAN.md` synced.
- Run tooling under `qa/run/` (`manage.sh`, `start_sso.sh`, `sso.env` (mode 600, throw-away secret), `test.env`, test keys). All servers were stopped at the end.

---

# Retest @ 6e1b479

| | |
|---|---|
| Build under test | `master` @ `6e1b479` (fix commits `1647c95` LEGACY-06, `5763f84` proxy trust + shared-cache fail-fast, `6e1b479` verifier JWKS refetch limit). Checkout verified at `6e1b479`; nothing outside `qa/` (and the untracked `devops/`) is modified |
| Date | 2026-10-10, 04:26–04:45 PT (UTC-7) |
| Environment | As in the first run, plus `SSO_CACHE_URL=filecache:///tmp/qa-cache` in `qa/run/sso.env` (Redis isn't installed on the box). **Fresh** throw-away SQLite DB `qa/run/sso-retest.sqlite3` (migrated and seeded: 33 users). Main server: 1 worker, its own cache dir per phase (`/tmp/qa-cache-func`, `/tmp/qa-cache-throttle`). Verifier demo on `127.0.0.1:8001` |
| Raw output | `qa/run/retest-pytest-functional.log`, `retest-junit-functional.xml`, `retest-pytest-throttle.log`, `retest-junit-throttle.xml`, server logs `retest-sso-server-{functional,throttle}.log`, `retest-verifier.log`, defect demos `retest-defect-4-5-demo.txt` (+ `retest-sso-demo-defect*.log`), E2E-11 `retest-e2e11-rotation.txt` (+ `retest-e2e11-*.log`), fail-fast and default checks `retest-manual-checks.txt` |

## R1. Summary

| | Count |
|---|---|
| pytest items collected | 213 (208 + 5 throttle). New: LOGOUT-05b, E2E-13 |
| **Passed** | **211** (206 functional/security + 5 throttle) |
| **Failed** | **0** |
| **Skipped** | **2** (LOGOUT-07 Q-06, LOGOUT-ALL-07 Q-09; unchanged, see §6) |
| Errors | 0 |
| Manual retests | 6 (fail-fast, LEGACY-06 timing/log, defect 4, defect 5 ×2, E2E-11), all passed |
| Blocked | same 6 Docker/MySQL cases as §5 |
| New failures / regressions | **none** (2 Low/Info observations, §R4) |

Both earlier failures are closed: **F-1 fixed** (LEGACY-06 now passes), **F-2 resolved** (Q-05 accepted; LOGOUT-05 now expects 204).

## R2. Per-item results

| Item | Result | Evidence |
|---|---|---|
| **LEGACY-06** malformed stored hash (defect 2 / F-1) | **PASS: fixed** | `qa_malformed` (`pbkdf2_sha256$notanumber$…`), `qa_truncated` (no digest), `qa_unusable`, `qa_unknownalgo` → `401 invalid_credentials`, uniform envelope, no traceback in the log. Each attempt writes 2 `sso.auth` lines: `ERROR … "result": "stored_hash_invalid", "username": "qa_malformed"` and `WARNING … "result": "invalid_credentials", "client": "native"`, with no hash and no password. The stored rows are unchanged after the attempt. **Timing** (15 samples, medians): malformed 168.7 ms, truncated 168.4, wrong password 168.6, unknown user 168.5, unusable 168.7. Spread is 0.3 ms, so no existence signal. Fix: `sso/serializers.py:62-70` |
| **Q-05 / LOGOUT-05** | **PASS** (test updated) | Cookie mode, allowed Origin, no token → `204`, empty body, `sso_refresh` cleared (`Max-Age=0`, `Path=/api/v1/auth/`). New LOGOUT-05b: same request without Origin → `403 origin_not_allowed`, so the Origin check still runs before the idempotent 204 |
| **Defect 4** XFF spoofing | **PASS: fixed (secure defaults)** | `settings.py:195` defaults `SSO_NUM_PROXIES` to `0`. `Dockerfile:26,59` uses `--forwarded-allow-ips "${SSO_FORWARDED_ALLOW_IPS:-127.0.0.1}"`, and there's no `'*'` anywhere. Compose sets `SSO_NUM_PROXIES: "1"` and `SSO_FORWARDED_ALLOW_IPS` = edge subnet (`docker-compose.yml:23,25`), with nginx still **overwriting** XFF (`docker/nginx.conf:93`). Side instance (port 8002, `SSO_NUM_PROXIES` unset, `--forwarded-allow-ips 127.0.0.1`, reached directly): 10 × 401 then 429. Then **20/20** logins with a different client-chosen XFF each → **429**, and 5/5 multi-hop XFF chains → 429. Before the fix it was 20/20 bypass. Main-suite SEC-33/35 also pass |
| **Defect 5** per-worker throttle | **PASS: fixed** | Side instance with **3 workers** (3 worker PIDs booted) + shared `filecache`: 40 sequential logins from one IP → **exactly 10 × 401, then 30 × 429**. Before the fix it was 29/40 accepted. Concurrent burst (20 parallel, 40 total) → 11 accepted (see O-R1). **Fail-fast** with `SSO_DEBUG=False`: `SSO_CACHE_URL` unset → `ImproperlyConfigured: SSO_CACHE_URL is empty…`; `locmemcache://` / `dummycache://` → `ImproperlyConfigured: … not shared between gunicorn workers…`; `gunicorn` itself exits 3 ("Worker failed to boot"). With `SSO_DEBUG=True` it still falls back to LocMem (dev), and `filecache://` passes `check`. `settings.py:167-189`, `sso/checks.py` now `sso.E001` (Error, not deploy-only) |
| **Verifier JWKS refetch limit** (§8.1) | **PASS** | New automated **E2E-13** (`qa/tests/test_e2e.py:142`), which counts `GET /.well-known/jwks.json` in the SSO access log (`SSO_ACCESS_LOG`). 20 tokens with random unknown kids → **≤ 1** JWKS GET, all 401. After 61 s, 20 more → **exactly 1** GET. A valid token stays 200 throughout. Before the fix it was 1 GET per token. Code: `examples/verifier/sso_verifier.py` `JWKSCache` (`min_refetch_interval=60`, failed fetch keeps old keys and counts against the limit) |
| **E2E-11** verifier picks up a rotated key | **PASS** (manual, now executed) | Side SSO 8006 + verifier 8007. Step 1: signs with kid `465388a5…` → verifier 200 (JWKS GET #1). Then the SSO restarts signing with kid `2f838315…` and publishes both keys. At t+7 s the new-kid token gets **401** (refetch suppressed: last fetch < 60 s ago), and the old-kid token gets 200. At t+62 s the new-kid token gets **200** (JWKS GET #2), and 10 more calls get 200 with no further GETs. So the limit does not break rotation. It only delays recognition by ≤ 60 s if the signing switch happens without pre-publication. With the documented procedure (README §4 step 2: publish the new key ≥ 24 h before switching signing; verifier cache lifespan 1 h), verifiers already hold the new key, so there's no 401 window |

## R3. Regressions
None. The functional log has 0 tracebacks. There are 0 JWTs (`eyJ`) and 0 test passwords in any retest server/verifier log. `sso.auth` result counts in the functional log: success 96, invalid_credentials 92, stored_hash_invalid 32, invalid_request 11, account_inactive 3.

## R4. New observations (no test failed)
- **O-R1 (Low): the throttle counter isn't atomic under concurrency.** Repro: start 3 workers with `filecache` and fire 40 logins from one IP with 20 in parallel. Result: 11 accepted against a limit of 10 (`qa/run/retest-defect-4-5-demo.txt`). Cause: DRF `SimpleRateThrottle` read-modify-writes the history list (`cache.get` then `cache.set`, called from `sso/throttles.py`), so concurrent requests can each see N-1. This applies to Redis too, and it's inherent to DRF. The overshoot is roughly equal to the concurrency, and the nginx `limit_req` covers it in compose. Recommendation: accept and document it, or use an atomic `incr`-based counter later.
- **O-R2 (Low/Info): the shared-nginx variant trusts one XFF hop.** `docker-compose.yml:23` hard-codes `SSO_NUM_PROXIES: "1"` in `environment:` (this overrides `.env`). In the "shared-nginx" variant (`docker-compose.yml:39`, web published on `127.0.0.1:8001`), this is correct only if the host nginx sets or overwrites `X-Forwarded-For`, and any local process on the host can reach 8001 with a forged XFF. README §3 warns about this in general. Suggest a line in the shared-nginx instructions: "host nginx must `proxy_set_header X-Forwarded-For $remote_addr`."

## R5. QA-side changes in this round (all inside `qa/`)
- `tests/test_logout.py`: LOGOUT-05 expects 204 + cleared cookie. New LOGOUT-05b (no Origin → 403).
- `tests/test_e2e.py`: new E2E-13 (JWKS refetch limit, needs `SSO_ACCESS_LOG`, ~65 s, marked `slow`).
- `TEST-PLAN.md`: Q-05 marked resolved. LOGOUT-05/05b, REFRESH-08 wording, E2E-13 rows added. Totals are now 156 A / 2 S / 24 M = 182.
- `tests/README.md`: `SSO_ACCESS_LOG` and the shared-cache requirement.
- `run/sso.env`: `SSO_CACHE_URL=filecache:///tmp/qa-cache`, DB → `sso-retest.sqlite3`. New `run/retest.env` (`SSO_ACCESS_LOG`).
- All servers (main, verifier, side instances 8002/8003/8006/8007) were stopped, and the `/tmp/qa-cache-*` dirs were removed.

## R6. Blocked / not executed (unchanged)
BLOCKED (Docker/MySQL not available): E2E-10 compose + TLS via nginx; the MySQL 8.4 integration run (grants, caching_sha2_password, collation, Q-27, DB TLS); LEGACY-09 restored `dcWebUsers` copy; SEC-36 nginx checks (incl. defect 4 in situ through nginx); SEC-38 container hardening; DEPLOY-13 suite against MySQL. Not executed: LEGACY-08 (no myFinance), E2E-09 interactive browser run, DEPLOY-14 developer pytest/coverage (it writes outside `qa/`). Still open for Philip: Q-06, Q-09 (proposal to harden LOGOUT-ALL-07), login-CSRF on `/login`, Q-18, Q-22.

---

# Regression @ f22b2e0

| | |
|---|---|
| Build under test | branch `sso-server-sprint1` @ `f22b2e0` (`5737b5a` image name / `SSO_UID`/`SSO_GID` / Python 3.13.16, `f22b2e0` `MYSQL_IMAGE` 8.0 + 8.4; on top of `038da9c` docs and `283d2c6` QA/DevOps files). The main checkout was already on this branch at `f22b2e0`, so **no checkout or worktree was needed**. The only uncommitted changes are someone's edits to `devops/DEPLOYMENT-PLAN.md` and `devops/ci/pipeline.yml`; they were left untouched |
| Diff vs `6e1b479` (outside `qa/`, `devops/`) | 17 files, +263/−60: Dockerfile (base `python:3.13.16-slim-trixie`, runtime `ARG SSO_UID/SSO_GID=10001` with numeric/non-root validation, `USER ${SSO_UID}:${SSO_GID}`); compose `web.image ${DOCKER_USER:-thomaschoi}/sso-server:${IMAGE_TAG:-latest}` (replaces `SSO_IMAGE_TAG`), `build.args` + `user:` from the same vars, `SSO_NUM_PROXIES: ${SSO_NUM_PROXIES:-1}`; test/dev compose `image: ${MYSQL_IMAGE:-mysql:${QA_MYSQL_TAG:-8.0}}` with per-version named volumes; `Dockerfile.test` and verifier Dockerfile on 3.13.16; `.env.example`/README/dev_setup/gen_keys/`test_both_django.sh` (`PYTHON=` → `.venv-py<ver>-dj52/42`); new `sso/tests/test_mysql_integration.py`; `.gitignore` now ignores `qa/run/`. **No application code changes** (`sso/`, `ssoproject/` unchanged apart from tests) |
| Python | **CPython 3.13.16** (uv build `~/.local/share/uv/python/cpython-3.13.16-linux-x86_64-gnu`, the same interpreter as the Developer's `.venv-py3.13.16-dj52`). That venv has no gunicorn or requests, so QA built `qa/.venv-py3.13.16` from it with `requirements.lock` (all 15 pins exactly; mysqlclient left out because there's no MySQL) + verifier + QA test requirements (`qa/run/regression-venv-freeze.txt`). Confirmed: the `start_sso.sh` log line `QA start_sso: Python 3.13.16 …`, and `/proc/<pid>/exe` of the gunicorn master and worker (both phases) and of the uvicorn verifier → `…/cpython-3.13.16…/python3.13` (`qa/run/regression-interpreter.txt`). The verifier log starts with `QA verifier: Python 3.13.16`. pytest also ran on 3.13.16 (`python -VV` at the top of each pytest log) |
| Environment | As in the retest: fresh throw-away SQLite `qa/run/sso-regression.sqlite3` (migrated + seeded, 33 users), `SSO_DEBUG=False`, `SSO_NUM_PROXIES=0`, 1 worker, file cache per phase (`/tmp/qa-cache-regression-{func,throttle}`), verifier demo on :8001. `PYTHONWARNINGS=default::DeprecationWarning,default::PendingDeprecationWarning` for server/verifier/manage; pytest with `-X dev -W default` |
| Raw output | `qa/run/regression-pytest-{functional,throttle,static}.log`, `regression-junit-{functional,throttle,static}.xml`, `regression-sso-server-{functional,throttle}.log`, `regression-verifier.log`, `regression-migrate.log`, `regression-seed.log`, `regression-manual-checks.txt`, `regression-sso-demo-defect5.log`, `regression-interpreter.txt`, `regression-venv-freeze.txt` |

## G1. Summary

| | Count |
|---|---|
| pytest items | 229 (224 functional/security/static + 5 throttle). New: DEPLOY-15, 16, 16b ×9, 17 ×2, 17b, 18, 19 (= 16 items) |
| **Passed** | **227** (222 + 5) |
| **Failed / errors** | **0 / 0** |
| **Skipped** | 2 (LOGOUT-07 Q-06, LOGOUT-ALL-07 Q-09; unchanged) |
| Static deploy tests (`-m static`, separate run after a QA-side warning fix) | **31/31 passed**, 0 warnings |
| E2E-13 (JWKS refetch limit) | PASS |
| Manual sanity on 3.13.16 | fail-fast (no cache, locmem, empty secret) OK; 3 workers + filecache: 10 accepted / 30 × 429 with 40 different spoofed XFF values |
| Regressions | **none** |

## G2. Static deploy tests incl. the new parameters

| ID | Result | What was checked |
|---|---|---|
| DEPLOY-01..07 | PASS | unchanged checks. **DEPLOY-03 was fixed by QA**: it flagged `devops/DEPLOYMENT-PLAN.md` (working tree), whose text *mentions* `-----BEGIN … PRIVATE KEY-----`. The check now requires a real PEM block (BEGIN line + base64). Verified that it still detects `qa/run/keys/qa-test.private.pem` and ignores the doc mention. No private key is tracked; `qa/run/` (test keys, `sso.env`) is git-ignored and untracked |
| DEPLOY-08 | PASS | `makemigrations --check` on 3.13.16 |
| **DEPLOY-15** image name | PASS | `${DOCKER_USER:-thomaschoi}/sso-server:${IMAGE_TAG:-latest}`. Resolves to `thomaschoi/sso-server:latest` (tag unset or empty) and `acme/sso-server:0.1.1` with overrides. `.env.example`: `DOCKER_USER=thomaschoi`, `IMAGE_TAG=0.1.0`. No shipped file still uses `SSO_IMAGE_TAG` |
| **DEPLOY-16** uid/gid | PASS | `ARG SSO_UID=10001`/`SSO_GID=10001` inside the runtime stage (`Dockerfile:24-25`). Final `USER ${SSO_UID}:${SSO_GID}` (`:59`), with no root USER. `useradd --uid/--gid` from the args with nologin (`:42`). App files `--chown=root:root` (`:48-51`). Compose `build.args` and `user:` use the same vars/defaults (`docker-compose.yml:20-24`) → `10001:10001`, override `1500:1500`. `.env.example` 10001/10001 |
| **DEPLOY-16b** uid/gid validation | PASS (9 cases) | The Dockerfile's own lines `:37-38` run in `sh`: 10001, 1500, 1000:100 accepted; uid 0, gid 0, `abc`, empty, `-1`, `1e3` rejected |
| **DEPLOY-17** MYSQL_IMAGE (test + dev compose) | PASS | Default `mysql:8.0` (= README). `MYSQL_IMAGE=mysql:8.4`/`mysql:8.0` and `QA_MYSQL_TAG=8.4`/`8.0` both select; `MYSQL_IMAGE` wins over `QA_MYSQL_TAG`. Volumes `${SSO_TEST_MYSQL_VOLUME:-sso-test-mysql-8.0}` / `${SSO_DEV_MYSQL_VOLUME:-sso-dev-mysql-8.0}`. See G4 #1 on the default |
| **DEPLOY-17b** | PASS | `SSO_TEST_EXPECT_MYSQL` is the same expression as the image. The integration test accepts 8.0 and 8.4 and checks `caching_sha2_password`. The init script sets `caching_sha2_password` and never `mysql_native_password` |
| **DEPLOY-18** Python 3.13 | PASS | `ARG PYTHON_IMAGE=python:3.13.16-slim-trixie`. `docker/Dockerfile.test` and `examples/verifier/Dockerfile` use the same base. Digest comment is 64 hex. No `python:3.10–3.12` left outside `qa/`/`devops/` |
| **DEPLOY-19** defect 4/5 guards | PASS | no `--forwarded-allow-ips '*'`; `${SSO_FORWARDED_ALLOW_IPS:-127.0.0.1}`; code `SSO_NUM_PROXIES` default 0, compose default 1; compose `SSO_CACHE_URL` default `redis://redis:6379/0`; `web` not published; nginx `X-Forwarded-For $remote_addr` |

Not verifiable without Docker (BLOCKED): that the image actually builds on 3.13.16 with the args, `docker compose config --images`, that the container runs as the uid, and that a MySQL 8.0/8.4 login works.

## G3. Warnings (Python 3.13.16)
- **DeprecationWarning / PendingDeprecationWarning / RemovedInDjango\*: none.** That covers the server (both phases), the verifier, migrate, seed and pytest, with warnings enabled.
- `CacheKeyWarning` (Info, not a regression): `sso/throttles.py:52` keys the per-username throttle on the raw lowercased username (up to 254 chars). A long username in LOGIN tests gives a key over 250 chars, and Django warns it would fail on memcached. There's no effect on Redis or the file cache. The fix would be to hash the ident if memcached is ever used.
- `UserWarning: No directory at …/staticfiles/` (Info, environment): WhiteNoise, because `collectstatic` isn't run outside the image (the Dockerfile runs it at build time).
- `ResourceWarning` ×95 under `-X dev` in **QA's own** `test_deploy_files.py` (unclosed files). Fixed in QA (`_text()` helper); the static re-run shows 0 warnings.
- `check --deploy` W004/W008 (HSTS, SSL redirect) are expected for the plain-HTTP QA config (`SSO_HSTS_SECONDS=0`, `SSO_SSL_REDIRECT=False`).

## G4. Observations (no test failed)
1. **Low (docs / decision): the MYSQL_IMAGE default is inconsistent across documents.** Code and README default to `mysql:8.0` (`docker-compose.test.yml:18`, `docker-compose.dev.yml:36`, README §2 "default `mysql:8.0`", "prod 8.0 today"). The uncommitted DevOps draft `devops/DEPLOYMENT-PLAN.md` §2.1 and R29 still say `mysql:${QA_MYSQL_TAG:-8.4}` (lines 94, 853). The QA request for this round also assumed "defaults to 8.4". Both versions are selectable, and DEPLOY-17 asserts the compose default equals the README's documented default (8.0 today). Philip/DevOps need to pick one, after which the other document should be aligned.
2. **Low: `SSO_UID=0` with a pulled image runs the container as root.** The Dockerfile rejects 0 only at **build** time. `docker-compose.yml:24` `user: "${SSO_UID:-10001}:${SSO_GID:-10001}"` passes any value at **run** time, so `SSO_UID=0` in `.env` with a pre-built Docker Hub image would give a root container. `.env.example` says "Never 0", but nothing enforces it. Suggested fix: a startup check (e.g. in settings or `docker/healthcheck.py`: refuse if `os.getuid()==0` and not DEBUG).
3. **Info:** the Developer's `.venv-py3.13.16-dj52` (from `requirements-dev.txt`) has no gunicorn, so the documented `.venv/bin/gunicorn` dev command in README needs `pip install gunicorn` (or `requirements.txt`) in that venv. The pins in `requirements.lock` install cleanly on 3.13.16, which confirms the lock's claim apart from mysqlclient.

## G5. QA-side changes (inside `qa/` only)
- `tests/test_deploy_files.py`: new DEPLOY-15/16/16b/17/17b/18/19 (with a small compose `${…}` interpolator). DEPLOY-03 now matches real PEM blocks only. File reads are closed (`_text()`).
- `TEST-PLAN.md`: DEPLOY-15..19 rows; totals 163 A / 2 S / 24 M = 189.
- `run/start_sso.sh`, `run/manage.sh`: `SSO_VENV` selects the venv (default `.venv`); the server log's first line records the interpreter. `run/sso.env`: `SSO_VENV=qa/.venv-py3.13.16`, `PYTHONWARNINGS`, DB `sso-regression.sqlite3`, cache `filecache:///tmp/qa-cache-regression`. `run/regression.env` (`SSO_ACCESS_LOG`). New venv `qa/.venv-py3.13.16`.
- All servers stopped (8000, 8001, 8003). `/tmp/qa-cache*` removed.

## G6. Blocked / not executed (unchanged)
BLOCKED (no Docker/MySQL): E2E-10 compose + TLS via nginx; the MySQL integration run on **8.0 and 8.4** (`docker-compose.test.yml` incl. `test_mysql_integration.py`: version, `caching_sha2_password`, grants, TLS); building the image with `SSO_UID/SSO_GID` and checking the runtime uid; `docker compose config --images`; LEGACY-09; SEC-36 (nginx); SEC-38 (container hardening); DEPLOY-13 against MySQL. Not executed: LEGACY-08 (no myFinance), E2E-09 (browser), DEPLOY-14 (Developer pytest/coverage, writes outside `qa/`).

---

# Quick check @ 5666f8b

Branch `sso-server-sprint1`: local and `origin` were both already at `5666f8b` (contains `7979f6c` QA, `8ea535b` DevOps, `5666f8b` fix), and the tree was clean; `git pull --ff-only` → "Already up to date". Python 3.13.16 (`qa/.venv-py3.13.16`), throw-away SQLite, file cache. Evidence: `qa/run/quick-checks.txt`, `quick-sso-nonroot.log`, `readme-check.sh` / `readme-check.log`, `quick-pytest-static.log`, `quick-junit-static.xml`. 2026-10-10 12:53–12:58 PT.

| # | Check | Result |
|---|---|---|
| 1 | Real root (`sudo`, euid 0), `SSO_DEBUG=False`: `manage.py check`, `check --deploy`, gunicorn | **PASS.** All three stop with `ImproperlyConfigured: Refusing to run as root (uid 0) with SSO_DEBUG=False …` (manage exit 1, gunicorn exit 3 "Worker failed to boot"). **`sso.E002`**: with the normal config the settings guard fires *before* the checks run, so `check` cannot print E002. That's by design (E002 is for settings modules that change DEBUG after loading). Verified with a settings module that imports `ssoproject.settings` with `SSO_DEBUG=True` and then sets `DEBUG=False`: as root, `check` and `check --deploy` both report `(sso.E002) Refusing to run as root …`, exit 1 |
| 2a | Non-root (uid 1000), `SSO_DEBUG=False` | **PASS.** `check`: no issues. `check --deploy`: only W004/W008 (plain-HTTP QA config), no sso.E\*. gunicorn starts, `/healthz` → 200 `{"status":"ok"}`, master euid 1000 on 3.13.16 |
| 2b | Root, `SSO_DEBUG=True` | **PASS.** `check` no issues, migrate OK, gunicorn starts, `/healthz` → 200. No warning is logged (none expected per the commit/README). gunicorn 26 created `/root/.gunicorn/gunicorn.ctl` (control socket) |
| 3 | README §2 dev commands in a fresh `git archive HEAD` copy under `qa/run/readme-check/`, `.venv` there | **PASS.** Run verbatim from the README (setup line + "Run the server locally" block) with `python3.13` = 3.13.16 first on PATH. Two QA deviations: `createsuperuser --noinput` with `DJANGO_SUPERUSER_*` (it's interactive), and gunicorn backgrounded. `pip install -r requirements-dev.txt` now brings gunicorn 26.2.0 and requests 2.34.2. migrate OK, superuser created, `curl /healthz` → `{"status":"ok"}`, server process on 3.13.16 |
| 4 | Static deploy tests (`-m static`) | **PASS: 35/35** (31 earlier + new DEPLOY-20 ×3, DEPLOY-20b), 0 warnings under `-X dev -W default`. DEPLOY-20 runs the settings import in a fresh interpreter with `os.geteuid` patched, so no real root is needed |

Notes:
- At 12:53 a non-QA process briefly held `127.0.0.1:8000`. QA's non-root start there failed with "address in use", and the `/healthz` 503 `database` answer came from that other server. QA reran on port 8020 (PASS). QA's `pkill -f "gunicorn … -b 127.0.0.1:8000"` matches any server started with the README command line, so it may have stopped that other process. From now on QA uses its own ports and stops servers by PID.
- Cleanup: all servers stopped; root-created `/tmp/qa-quick-root*` and `/tmp/qa-cache-quick*`, plus the README's `/tmp/ssokeys` and `/tmp/sso-cache`, removed; nothing root-owned left in the repo. Nothing outside `qa/` changed.

## Key config @ d784f10 (feat/app-permissions; 610c9b8 + d784f10)

Tree clean before QA edits; both commits in HEAD (local branch is ahead of `origin/feat/app-permissions` = c041594, i.e.
610c9b8/d784f10 are not on the remote yet). qa/ is on both branches (sprint1 d866070 is an ancestor of feat/app-permissions).
Run with `qa/harness/run_keys_round.sh` (server started with the new variables; ports 8052/8050 for 3.13, 8053/8051 for 3.11;
stopped by PID; throw-away SQLite DBs `qa/run/sso-keys-<py>.sqlite3`). `manage.py check` with the new form: no issues.

| Python (server + pytest) | test_deploy_files | test_keys_config (new) | test_jwks_discovery_health | test_security_jwt | Total |
|---|---|---|---|---|---|
| 3.13.16 | 35 pass | 36 pass | 15 pass | 43 pass | **129 pass, 0 fail, 0 skip** |
| 3.11.14 | 35 pass | 36 pass | 15 pass | 43 pass | **129 pass, 0 fail, 0 skip** |

Findings (no failures):
- **K-01 (Info, by design):** a key value containing `/` is a path relative to the working directory, so
  `SSO_JWT_PRIVATE_KEY=../outside/x.pem` resolves outside the mount (KEYCFG-09); relative `sub/x.pem` is NOT mount-relative
  (KEYCFG-05). Documented in README §3 / .env.example; operator-controlled env only, no privilege boundary. Bare names cannot
  escape (`..`, `..%2Fx`, `..\x` → clean ImproperlyConfigured inside the mount). Optional hardening: reject `..` components or
  resolve relative paths against the mount.
- **K-02 (Info):** `.env.example` assigns `SSO_KEYS_DIR=./keys` twice (l.41 and l.94, same value).
- **K-03 (Info, doc drift):** `docs/SSO-server.md` (l.123, 471-472, 497-498) and `docs/DESIGN-ADDENDUM-v1.1.md` (l.29-30) still
  show the old `*_PATH` names.
- The deprecation log line goes to stdout (settings LOGGING console handler), not stderr; one line per old variable per process.
