# SSO server — Sprint 1 Test Plan

| | |
|---|---|
| Author | QA (Thomas Choi's team; lead: Philip) |
| Date | 2026-10-10 |
| Inputs | `docs/Request.txt`, `docs/SSO-server.md` (spec v1.0), `docs/DESIGN-ADDENDUM-v1.1.md` (addendum wins on conflicts) |
| Code status | Plan written from the docs. Late check of the Developer's first commit (df02306): URL paths match the spec exactly (no trailing slash); settings already cover several open questions (see §2.5) |
| Automation | `qa/tests/` (pytest, black-box). How to run: `qa/tests/README.md` |

Legend: **A** = automated in `qa/tests`, **A\*** = automated but needs an optional prerequisite (private key,
`SSO_MANAGE_CMD`, verifier demo), **M** = manual, **S** = automated test is skipped because the spec doesn't decide the behaviour yet.
Each automated test function starts with its case ID (`test_LOGIN_04_…` is LOGIN-04).

---

## 1. Scope

### 1.1 In scope (addendum §A = spec §10 phases 1 and 2 + phase 3 files + examples)
- Phase 1: project skeleton on `dcWebUsers`, RS256 keys, `POST /api/v1/auth/login`, `/refresh`, `/logout`, `GET /api/v1/auth/me`,
  `GET /.well-known/jwks.json`, `GET /healthz`. Existing myFinance users log in and the token verifies with the spec §8.2 code.
- Phase 2: browser cookie mode, CORS, throttling (per IP + per username, addendum B3), the §6.0 error format on every
  error (B10), `POST /api/v1/auth/logout-all`, `POST /api/v1/auth/introspect`, `ServiceClient` admin, Origin check for
  cookie mode (B9), revocation enforced at refresh (B8), `GET /.well-known/openid-configuration` with B2's rules.
- Phase 3 deployment **files**: Dockerfile, docker-compose.yml, nginx.conf, gen_keys.sh, .env.example, README
  (checked statically and by bringing them up once by hand; production deployment is not in scope).
- `examples/verifier/` (§8.2 PyJWT + a FastAPI demo endpoint) and `examples/frontend/index.html` (§7.2 `auth.js`).
- Addendum fixes B1–B14 where they can be seen from outside the server or checked by a short manual step.

### 1.2 Out of scope
- Phase 4 (first consumer: myFinance/rebalance secured with §8.3). Phase 5: `/sso/authorize`, `/api/v1/auth/token`,
  PKCE, hosted login page, `/sso/logout`, account endpoints (§6.8, §6.9). QA checks only that these paths **don't exist yet**
  (ERR-10) and are **not advertised** (DISC-03/04). An unused `AuthorizationCode` model is allowed.
- Running against production `dcWebUsers`, load/performance testing, MFA/social login (spec non-goals).
- The Developer's white-box unit tests (pytest-django, ≥ 90% coverage, spec §11 list). QA reviews the coverage report
  (DEPLOY-14) and does not rewrite those tests.
- Refresh-token reuse detection that revokes the whole token family. The spec only requires blacklisting the rotated
  token; see Q-22.

## 2. Environment and assumptions

### 2.1 Server under test
- Dev run: `SSO_DB_ENGINE=sqlite python manage.py migrate && python manage.py runserver 0.0.0.0:8000` →
  `SSO_BASE_URL=http://localhost:8000`.
- Integration run: `docker compose up` (nginx + self-signed TLS; addendum §C), with the MySQL 8 test DB from
  `docker-compose.test.yml` (B14) → `SSO_BASE_URL=https://localhost:8443`, `SSO_VERIFY_TLS=0`. The port is assumed;
  confirm it once the compose file exists.
- **Test-env requirements:** one gunicorn worker **or** a shared cache (`SSO_CACHE_URL`) so throttle counters are global (Q-03);
  `SSO_CORS_ALLOWED_ORIGINS` includes `SSO_TEST_ALLOWED_ORIGIN` (default `https://example.com`); `SSO_COOKIE_DOMAIN`
  empty or matching the host (Q-16); `SSO_DEBUG=False` for the error-format and stack-trace checks.
- Endpoint paths are exactly as in the spec, with **no trailing slash** (ERR-13 and HEALTH-02 check that APPEND_SLASH doesn't redirect).

### 2.2 Test data (`qa/tests/fixtures/seed_test_data.py`, data in `qa/tests/testdata.py`)
Run the seed script in the server's Django shell before every run. It is idempotent and only touches `qa_*` users and `qa-*` clients.
R27 guard: it exits with code 2 unless `SSO_ALLOW_SYNTHETIC_SEED=1` is set and the DB is a local or throw-away one (details in `qa/tests/README.md`).

| User(s) | Purpose |
|---|---|
| `qa_alice` (groups qa_trader, qa_beta), `qa_bob` (is_staff, no groups), `qa_carol` (mixed-case email) | claims/user object, email login |
| `qa_user01`…`qa_user12` | interchangeable pool that spreads the 5/min per-username throttle |
| `qa_inactive` | `is_active=False` |
| `qa_dup1`/`qa_dup2` (same email), `qa_noemail` (empty email) | B5 email rules |
| `qa_revoke`, `qa_disable`, `qa_fresh` | logout-all, deactivate-at-refresh, /me freshness |
| `qa_legacy41`, `qa_rehash` (pbkdf2_sha256$**390000**), `qa_legacy32` (260000), `qa_sha1` (pbkdf2_sha1) | legacy hashes |
| `qa_malformed`, `qa_truncated`, `qa_unusable` (`!…`), `qa_unknownalgo` | bad stored hashes |
| `qa_throttle1..3` | throttle cases |
| ServiceClient `qa-service` (active), `qa-service-inactive` | introspect |

**All** `qa_*` users get Django 4.1–format hashes, so every functional login also shows that legacy hashes still verify.
I checked the generated hashes with Django 5.2.18 `check_password` on the box.

### 2.3 Configuration (env vars, full list in `qa/tests/README.md`)
`SSO_BASE_URL`, `SSO_VERIFY_TLS`, `SSO_ISSUER`, `SSO_AUDIENCE`, `SSO_ACCESS_TTL_MIN`, `SSO_REFRESH_TTL_DAYS`, `SSO_ALLOWED_ORIGIN`,
`SSO_COOKIE_DOMAIN`. Optional prerequisites: `SSO_TEST_PRIVATE_KEY_PATH` (the test env's signing key, to mint validly signed tokens
with bad claims), `SSO_MANAGE_CMD` (Django shell access for DB-state cases), `VERIFIER_BASE_URL`/`VERIFIER_PROTECTED_PATH`/`VERIFIER_GROUP_PATH`
(examples/verifier demo). A case whose prerequisite is missing is **skipped** with its reason.

### 2.4 Working assumptions (each one is tied to an open question)
- A1: a request with a body `refresh_token` is native mode (no Origin check, token returned in the body). Without one, the request is cookie mode (Q-21).
- A2: a cookie-mode refresh returns the rotated token only in the cookie, like a browser login (Q-23).
- A3: a missing Bearer header on `/me` or `/logout-all` → `401 token_invalid` (Q-07).
- A4: an inactive user with the **wrong** password → `401 invalid_credentials`, so the account's existence isn't leaked (Q-04).
- A5: `kid` is computed over SubjectPublicKeyInfo DER (Q-11).
- A6: cookie `Max-Age` = `SSO_REFRESH_TTL_DAYS`×86400 (spec example 604800) (Q-29).

### 2.5 Late check of the code (commit df02306, after the plan was drafted)
- Paths: `ssoproject/urls.py` routes exactly the spec paths. Phase-5 names are reserved but not routed, which matches ERR-10/DISC-04.
- `SSO_JWT_PUBLIC_KEY_PATHS` is read, with the singular `SSO_JWT_PUBLIC_KEY_PATH` as fallback (answers Q-01).
- Throttle rates come from env: `SSO_THROTTLE_LOGIN`, `SSO_THROTTLE_LOGIN_USER`, `SSO_THROTTLE_REFRESH` (answers Q-02). Plan: run the functional
  suite with high rates (`-m "not throttle"`) and the throttle suite at spec defaults. Set `SSO_TEST_RATE_*` to match.
- `DEFAULT_PARSER_CLASSES = [JSONParser]` (answers the parser half of Q-15; LOGIN-19 still verifies it).
- `SSO_NUM_PROXIES` defaults to 1, which is right behind nginx. **When the suite hits gunicorn/runserver directly, set `SSO_NUM_PROXIES=0`**:
  with 1 and no proxy in front, DRF trusts the last client-supplied `X-Forwarded-For` entry and SEC-35 fails (Q-25).
- `SSO_COOKIE_SECURE` and `SSO_COOKIE_SAMESITE` are configurable. The test env must keep the defaults (True/Lax) for SEC-20.
- `SSO_COOKIE_DOMAIN=""` → no Domain attribute (host-only), which partly answers Q-16. Run with `SSO_COOKIE_DOMAIN=""` exported for the suite.

---

## 3. Test cases

Common expectations: success bodies are JSON with `Content-Type: application/json`. Every error is
`{"error": "<code>", "detail": "<text>"}` with `Content-Type: application/json`, contains no stack trace, and never echoes
passwords or tokens (helper `assert_error`). TTL values default to 900 s (access) and 604800 s (refresh) and are read from env.

### 3.1 Login — `POST /api/v1/auth/login` (spec §6.1, B4, B5)
| ID | Preconditions | Steps | Expected | Auto |
|---|---|---|---|---|
| LOGIN-01 | qa_alice | POST `{username,password,client:"native"}` | 200; `access_token` (JWT), `token_type:"Bearer"`, `expires_in:900`, `refresh_token` in body, `user`; **no** `sso_refresh` Set-Cookie | A |
| LOGIN-02 | qa_alice | same with `client:"browser"`, allowed Origin | 200; body has **no** `refresh_token`; `Set-Cookie: sso_refresh=<JWT>` (flags in SEC-20) | A |
| LOGIN-03 | pool user | omit `client` | behaves like browser (cookie set, no refresh in body) | A |
| LOGIN-04 | session login | decode access token | header `alg=RS256, typ=JWT, kid`(16 hex); claims `iss`=SSO_ISSUER, `aud`∋SSO_AUDIENCE, `sub`=str(user.id), `token_type=access`, `jti`, `iat`, `exp-iat=900`, `username`, `email`, `is_staff`, `groups`; no password/permissions/extra PII | A |
| LOGIN-05 | session login | decode refresh token | RS256, `token_type=refresh`, `exp-iat=7d`, own `jti`, carries `aud` (B7) | A |
| LOGIN-06 | | inspect `user` | keys id(int), username, email, first_name, last_name, is_staff, groups; values match DB; no password | A |
| LOGIN-07 | | wrong password | 401 `invalid_credentials`; password not echoed | A |
| LOGIN-08 | | unknown user vs wrong password | both 401 `invalid_credentials` with **identical** bodies | A |
| LOGIN-09 | qa_inactive | correct password | 403 `account_inactive` | A |
| LOGIN-10 | qa_inactive | wrong password | 401 `invalid_credentials` (A4) | A |
| LOGIN-11 | qa_carol `QA.Carol@Example.Test` | log in with lower- and upper-case email | 200, user qa_carol (email__iexact, B5) | A |
| LOGIN-12 | qa_dup1/qa_dup2 share email | log in by that email | 401 `invalid_credentials` | A |
| LOGIN-13 | | unknown email; `"@"` with qa_noemail's password | 401 (empty emails never match, B5); `"@"` gives 400/401, never 200/500 | A |
| LOGIN-14 | | missing/empty username or password; `{}` | 400 `invalid_request` | A |
| LOGIN-15 | | `client:"spaceship"` | 400 `invalid_request` | A |
| LOGIN-16 | qa_bob | login | token `is_staff:true`, `groups:[]` | A |
| LOGIN-17 | SSO_MANAGE_CMD | read `last_login`, log in, read again | `last_login` updated | A\* |
| LOGIN-18 | | log in twice | different access and refresh tokens | A |
| LOGIN-19 | | form-encoded body | 400/415 envelope, no cookie (all bodies are JSON; blocks login CSRF, Q-15) | A |
| LOGIN-M1 | | 30× unknown user vs 30× wrong password, by username **and** by email path, spaced to stay under the throttle | median latencies within ~20% (B4 timing-safe) | M |
| LOGIN-M2 | server logs | ok, bad and inactive logins | one structured line per attempt with username, IP, result; no password and no token (B13) | M |

### 3.2 Refresh — `POST /api/v1/auth/refresh` (spec §6.2, B8, B9)
| ID | Preconditions | Steps | Expected | Auto |
|---|---|---|---|---|
| REFRESH-01 | native session | POST `{refresh_token}` | 200, login-shaped body, **new** refresh token in body (rotated), new access token, no cookie | A |
| REFRESH-02 | | refresh, then reuse the old refresh token | second call 401 `token_invalid` (blacklisted after rotation) | A |
| REFRESH-03 | | chain 3 rotations | each 200 | A |
| REFRESH-04 | browser session | POST `{}` + cookie + allowed Origin | 200, no refresh in body, new `sso_refresh` cookie with a different value | A |
| REFRESH-05 | browser session | reuse the old cookie after rotation | 401 `token_invalid` | A |
| REFRESH-06 | | access token as refresh token | 401 `token_invalid` | A |
| REFRESH-07 | | `garbage`, `a.b.c`, a bogus JWT, `""` | 401 `token_invalid` (`""` may be 400 `invalid_request`) | A |
| REFRESH-08 | | no body token, no cookie | 401 `token_invalid` (server behaviour; 400 `invalid_request` also tolerated, Q-05) | A |
| REFRESH-09 | SSO_MANAGE_CMD, qa_disable | log in, set is_active=False, refresh | 403 `account_inactive`; user reactivated afterwards | A\* |
| REFRESH-10 | qa_revoke | log in, wait 1 s, logout-all, refresh | 401 `token_invalid` | A |
| REFRESH-11 | private key | mint a refresh token with the real key, an unknown jti (not blacklisted) and an iat before logout-all | 401: the B8 `iat < revoked_at` check works independently of the blacklist | A\* |
| REFRESH-12 | | inspect headers | `Cache-Control: no-store` recommended (xfail if absent; Q-14) | A |
| (throttle) | | 61 refreshes/min | see SEC-34 | A |

### 3.3 Logout — `POST /api/v1/auth/logout` (spec §6.3, B9)
| ID | Preconditions | Steps | Expected | Auto |
|---|---|---|---|---|
| LOGOUT-01 | native session | POST `{refresh_token}` | 204, empty body; that refresh token then gets 401 | A |
| LOGOUT-02 | browser session | POST + cookie + allowed Origin | 204; Set-Cookie clears `sso_refresh` (empty value, Max-Age=0 or past Expires, same Path `/api/v1/auth/` and Domain); the old cookie then gets 401 | A |
| LOGOUT-03 | | logout, then call `/me` with the access token | still 200 (access tokens stay valid until expiry) | A |
| LOGOUT-04 | | access token in body | 401 `token_invalid`; the real refresh token still works | A |
| LOGOUT-05 | | cookie mode (allowed Origin), no token | 204, empty body, `sso_refresh` cleared (Max-Age=0, Path `/api/v1/auth/`). Q-05 resolved | A |
| LOGOUT-05b | | cookie mode, no token, **no Origin** | 403 `origin_not_allowed` (Origin check still runs first) | A |
| LOGOUT-06 | | garbage token | 401 `token_invalid` | A |
| LOGOUT-07 | | logout twice with the same token | 204 or 401? (Q-06) | S |
| LOGOUT-08 | 2 sessions of one user | log out session A | session B's refresh token still works | A |

### 3.4 Logout-all — `POST /api/v1/auth/logout-all` (spec §6.4, §6.6, B8)
| ID | Preconditions | Steps | Expected | Auto |
|---|---|---|---|---|
| LOGOUT-ALL-01 | qa_revoke: 2 native sessions + 1 browser session | logout-all with Bearer | 204; all three refresh tokens and the cookie get 401 | A |
| LOGOUT-ALL-02 | | introspect another session's access token before and after | `active:true`, then `{"active":false}` | A |
| LOGOUT-ALL-03 | | no Authorization | 401 envelope (A3) | A |
| LOGOUT-ALL-04 | | refresh token as Bearer | 401 `token_invalid`; nothing revoked | A |
| LOGOUT-ALL-05 | | logout-all, then log in **in the same second** | new tokens work: introspect active, refresh 200 (iat/revoked_at granularity, Q-08) | A |
| LOGOUT-ALL-06 | | logout-all for qa_revoke | other users' sessions unaffected | A |
| LOGOUT-ALL-07 | | `/me` with an access token issued before logout-all | undecided (Q-09) | S |
| LOGOUT-ALL-08 | SSO_MANAGE_CMD + private key | read `revoked_at`; mint access and refresh tokens with iat = floor(revoked_at) and iat = ceil(revoked_at) | floor: introspect inactive, /me 401, refresh 401. ceil: active, 200, 200 (ceil rule) | A\* |

### 3.5 Me — `GET /api/v1/auth/me` (spec §6.5)
| ID | Steps | Expected | Auto |
|---|---|---|---|
| ME-01 | GET with Bearer | 200, user object equal to login's `user` | A |
| ME-02 | no Authorization | 401 envelope (A3) | A |
| ME-03 | `Basic …`, `Bearer`, `Bearer `, `Token x`, `bearer garbage` | 401 envelope | A |
| ME-04 | refresh token as Bearer | 401 `token_invalid` | A |
| ME-05 | POST | 405 envelope | A |
| ME-06 | change first_name in the DB (SSO_MANAGE_CMD), call /me with the old token | new value (read fresh from the DB) | A\* |
| ME-07 | validly signed token for a nonexistent `sub` | 401 | A\* |

### 3.6 Introspect — `POST /api/v1/auth/introspect` (spec §6.6, §9.2)
| ID | Steps | Expected | Auto |
|---|---|---|---|
| INTRO-01 | Basic qa-service + valid access token | 200 `{active:true, sub, username, groups, exp}` matching the token | A |
| INTRO-02 | no client auth | 401 envelope (code undefined, Q-10) | A |
| INTRO-03 | wrong secret | 401; secret not echoed | A |
| INTRO-04 | unknown client_id | 401 | A |
| INTRO-05 | inactive ServiceClient | 401 | A |
| INTRO-06 | user Bearer token instead of Basic | 401 | A |
| INTRO-07 | refresh token | 200 `{"active":false}` | A |
| INTRO-08 | garbage, `a.b.c`, alg=none | 200 `{"active":false}`, not 4xx/5xx | A |
| INTRO-09 | missing `token` field | 400 `invalid_request` | A |
| INTRO-10 | token of a user deactivated afterwards (SSO_MANAGE_CMD) | `{"active":false}` | A\* |
| INTRO-11 | expired token signed with the real key | `{"active":false}` | A\* |
| INTRO-12 | alg=none, tampered signature, attacker key with real kid, HS256 with the public key | `{"active":false}` | A |
| INTRO-13 | inactive response | contains **only** `active` | A |
| INTRO-14 | GET | 405 envelope | A |
| (revocation) | after logout-all | see LOGOUT-ALL-02 | A |

### 3.7 JWKS, discovery, healthz (spec §6.7, §5.3, B2, B6)
| ID | Steps | Expected | Auto |
|---|---|---|---|
| JWKS-01 | GET `/.well-known/jwks.json` | 200 JSON `keys[]`: `kty=RSA, use=sig, alg=RS256, e=AQAB`, kid 16 chars, modulus ≥ 2048 bits | A |
| JWKS-02 | headers | `Cache-Control: public, max-age=3600` | A |
| JWKS-03 | | no `d,p,q,dp,dq,qi,k` fields | A |
| JWKS-04 | rebuild each key from n/e | kid = first 16 hex of SHA-256 over SPKI DER (fails with a clear message if computed over PKCS#1, Q-11) | A |
| JWKS-05 | | token header kid is in JWKS; token verifies with the §8.2 code | A |
| JWKS-06 | | kids unique | A |
| JWKS-07 | with a garbage Bearer; POST | 200 (public); POST 405 | A |
| JWKS-08 | set `SSO_JWT_PUBLIC_KEY_PATHS=old,new`, restart; then switch the signing key | both keys published; tokens signed by either verify; JWKS lists every configured key (B6, §5.3 rotation runbook) | M |
| DISC-01 | GET openid-configuration | 200; `issuer`==SSO_ISSUER; `id_token_signing_alg_values_supported==["RS256"]` | A |
| DISC-02 | | `jwks_uri` = issuer + `/.well-known/jwks.json`, returns the same keys | A |
| DISC-03 | | `token_endpoint` absent or ends with `/api/v1/auth/login` (B2 overrides spec) | A |
| DISC-04 | | no `authorization_endpoint` | A |
| DISC-05 | | `issuer` equals the token `iss` | A |
| DISC-06 | | each advertised endpoint exists (GET → 405) | A |
| HEALTH-01 | GET `/healthz` | 200 `{"status":"ok"}` | A |
| HEALTH-02 | with a garbage Bearer | 200, no slash redirect | A |
| HEALTH-03 | stop the DB | non-200 (503 expected) with the §6.0 envelope, no stack trace (Q-28) | M |

### 3.8 Error format (spec §6.0, B9, B10)
| ID | Steps | Expected | Auto |
|---|---|---|---|
| ERR-01 | login with missing fields | 400 `invalid_request` envelope | A |
| ERR-02 | truncated JSON | 400 `invalid_request` | A |
| ERR-03 | JSON body `[]`, `"str"`, `123`, `null` | 400 `invalid_request` (no 500) | A |
| ERR-04 | wrong field types (list, null, object) | 400 `invalid_request` | A |
| ERR-05 | 10 kB username/password | 400/401 envelope, no 500 | A |
| ERR-06 | `Content-Type: text/plain` | 400/415 envelope | A |
| ERR-07 | wrong credentials | 401 `invalid_credentials` with a non-empty detail | A |
| ERR-08 | garbage token at /me, logout-all, refresh | 401 `token_invalid` | A |
| ERR-09 | inactive user | 403 `account_inactive` | A |
| ERR-10 | GET unknown paths incl. phase-5 `/api/v1/auth/token`, `/sso/authorize` | 404 envelope | A |
| ERR-11 | wrong HTTP method on POST-only endpoints | 405 envelope + `Allow: POST` | A |
| ERR-12 | wrong password / token values | never echoed in error bodies | A |
| ERR-13 | POST to the spec path without a trailing slash | not 301/302/307/308/500 | A |
| ERR-14 | trigger throttling | 429 `rate_limited` + integer `Retry-After` (asserted inside SEC-30..34) | A |
| ERR-15 | force a 500 (e.g. DB down during login) with SSO_DEBUG=False | §6.0 envelope, no traceback, no settings/secret leakage | M |
| ERR-16 | bad Origin in cookie mode | 403 `origin_not_allowed` (asserted in SEC-22..25) | A |

### 3.9 Legacy Django 4.1 PBKDF2 users (Request R-01/R-02, spec §4.3, §11, B14)
| ID | Steps | Expected | Auto |
|---|---|---|---|
| LEGACY-01 | log in qa_legacy41 (`pbkdf2_sha256$390000$…`) | 200 | A |
| LEGACY-02 | wrong password on a legacy hash | 401 `invalid_credentials` | A |
| LEGACY-03 | qa_legacy32 (260000 iterations, Django 3.2 era) | 200 | A |
| LEGACY-04 | qa_sha1 (`pbkdf2_sha1`) | 200 (hasher is in Django's default list) | A |
| LEGACY-05 | SSO_MANAGE_CMD: read qa_rehash's hash (390000), log in, read again | hash rewritten, still `pbkdf2_sha256`, iterations > 390000 (1,000,000 on Django 5.2 / 600,000 on 4.2), verifies with the Django 4.1 algorithm (myFinance compatible); login still works | A\* |
| LEGACY-06 | users with a malformed (`$notanumber$`), truncated, unusable (`!…`) or unknown-algorithm hash | 401 `invalid_credentials`, **never 500**. Note: Django's `check_password` raises ValueError for the first two (verified locally), so the view must handle it (Q-19) | A |
| LEGACY-07 | failed login | stored hash unchanged | A\* |
| LEGACY-08 | after an SSO login (rehashed), log in to myFinance (Django 4.1) with the same account; and the reverse | both succeed (spec §11 manual e2e) | M |
| LEGACY-09 | `SELECT COUNT(*) FROM auth_user` before/after `migrate` on a restored copy of `dcWebUsers`; sample-log-in N real accounts on the staging copy | count unchanged; logins work | M |

### 3.10 Security
**JWT handling, checked at the SSO server (`/me`) and with the §8.2 reference verifier** (the verifier demo gets the same attacks in E2E-05/06):

| ID | Attack | Expected | Auto |
|---|---|---|---|
| SEC-01 | `alg` none/None/NONE/nOnE, empty or junk signature | 401 `token_invalid`; reference verifier rejects | A |
| SEC-02 | HS256/384/512 signed with the RSA public key (SPKI PEM, without newline, PKCS#1 PEM, DER) | rejected | A |
| SEC-03 | one bit of the signature flipped | rejected | A |
| SEC-04 | payload changed (is_staff, sub, groups, exp, username) with the old signature | rejected | A |
| SEC-05 | attacker RSA key, unknown kid | rejected | A |
| SEC-06 | attacker key with the **real** kid | rejected | A |
| SEC-07 | attacker key with no kid / embedded `jwk` / `jku` / `x5u` header | rejected | A |
| SEC-08 | real key, wrong `iss` (other host, garbage, trailing-slash variant) | rejected | A\* |
| SEC-09 | real key, wrong or missing `aud` | rejected | A\* |
| SEC-10 | real key, `exp` = now−60 (beyond 30 s leeway) | rejected | A\* |
| SEC-11 | real key, `exp` = now−10 (inside leeway) | accepted (LEEWAY 30) | A\* |
| SEC-12 | real key, `nbf` = now+300 | rejected | A\* |
| SEC-13 | real key, `iat` = now+300 | reference verifier rejects (§8.1 #5); server behaviour undecided (Q-12) | A\* |
| SEC-14 | refresh token used as access (/me, reference verifier, logout-all) | rejected | A |
| SEC-15 | access token used as refresh (/refresh, /logout) | 401 | A |
| SEC-16 | real key, `token_type` missing/`refresh`/`id`/`ACCESS` | rejected | A\* |
| SEC-17 | real key, RS384/RS512/PS256 | rejected (RS256 only) | A\* |
| SEC-18 | real key, missing exp/sub/jti | rejected | A\* |
| SEC-19 | positive control: a real token passes the reference verifier | accepted | A |

**Cookie, Origin/CSRF and CORS (§6.1, §9.3, B9):**

| ID | Steps | Expected | Auto |
|---|---|---|---|
| SEC-20 | browser login | `sso_refresh` has HttpOnly, Secure, SameSite=Lax, Path=/api/v1/auth/, Max-Age=604800, Domain=SSO_COOKIE_DOMAIN (or host-only when that is empty) | A |
| SEC-21 | cookie refresh | the rotated cookie has the same flags | A |
| SEC-22 | cookie refresh with **no Origin** | 403 `origin_not_allowed`; the token isn't consumed (later valid-Origin refresh is 200) | A |
| SEC-23 | cookie refresh with evil, `null`, http-scheme, suffix-attack (`allowed.evil`), sibling subdomain and other-port Origins | 403 `origin_not_allowed` each time; token not consumed | A |
| SEC-24 | Referer header without Origin | 403 (Referer doesn't substitute) | A |
| SEC-25 | cookie logout with missing/bad Origin | 403; session survives | A |
| SEC-26 | native body-token refresh/logout with no Origin or an evil Origin | 200/204 (check skipped, B9) | A |
| SEC-27 | CORS preflight to login/refresh | allowed origin: ACAO=origin, ACAC=true, content-type allowed; evil origin: no ACAO | A |
| SEC-28 | actual login response | ACAO/ACAC for the allowed origin only; never `*` | A |

**Throttling (§6.1, §9.3, B3)**, file `test_zz_throttle.py`, which runs last and waits 61 s before each case:

| ID | Steps | Expected | Auto |
|---|---|---|---|
| SEC-30 | 5 bad logins for one username, then a 6th | first 5 → 401; 6th → 429 `rate_limited`, `Retry-After` integer 1..60 | A |
| SEC-31 | mix username case `qa_throttle2`/`QA_THROTTLE2`/… | they share one bucket (lower-cased key) → 429 on the 6th | A |
| SEC-32 | exhaust a username, then send the **correct** password | 429; after `Retry-After` the login succeeds (throttle, not permanent lockout) | A |
| SEC-33 | 10 logins with distinct usernames from one IP, then an 11th | 429 (per-IP 10/min) | A |
| SEC-35 | (inside SEC-33) add a spoofed `X-Forwarded-For` | still 429. With DRF `NUM_PROXIES` unset, DRF keys on the raw XFF header, so a client-supplied XFF would bypass the limit | A |
| SEC-34 | 60 refreshes, then a 61st | 429 (refresh 60/min) | A |

**Other security checks:**

| ID | Steps | Expected | Auto |
|---|---|---|---|
| SEC-29 | grep server/nginx logs after a full run | no access/refresh tokens, no passwords (B13, §9.6) | M |
| SEC-36 | `http://` to nginx | redirect to https or refused; HSTS recommended | M |
| SEC-37 | `/admin/` | admin not at the default path (§9.6) | M |
| SEC-38 | container and key files | private key chmod 600, mounted read-only, not in the image or git (DEPLOY-03/06) | M |

### 3.11 End-to-end (spec §7, §8, §10; addendum §A examples)
| ID | Flow | Expected | Auto |
|---|---|---|---|
| E2E-01 | phase 1 "done when": legacy user logs in (native) → token verified by the §8.2 code → /me | claims valid, sub = user.id | A |
| E2E-02 | §7.3 Python script: native login → verifier demo with Bearer → refresh → verifier → logout → refresh fails | 200, 200, 200, 204, 401 | A\* |
| E2E-03 | §7.2 auth.js sequence over HTTP: restoreSession (no cookie) fails → browser login → apiFetch to verifier → silent refresh (cookie) → logout → restoreSession fails | as described | A\* |
| E2E-04 | apiFetch retry: verifier returns 401 for an expired token → cookie refresh → retry 200 | as described | A\* |
| E2E-05 | verifier demo rejects missing token (401 + `WWW-Authenticate: Bearer`), garbage, refresh token, alg none, tampered, attacker key, HS256-public-key | 401 each | A\* |
| E2E-06 | verifier demo rejects expired, wrong iss, wrong aud, future iat, future nbf, token_type=refresh | 401 each | A\* |
| E2E-07 | group-protected demo endpoint: qa_alice (in group) vs qa_bob | 200 / 403 (if the demo has one, Q-13) | A\* |
| E2E-08 | verifier CORS preflight allows the `Authorization` header (§8.6) | allowed | A\* |
| E2E-09 | **Browser**: serve `examples/frontend/index.html` from the allowed origin; log in (wrong password shows "Wrong username or password", inactive shows the activation message, throttled shows "Too many attempts, try again in N s"); call the verifier; reload the page (silent restore, no login form); check in DevTools that the token isn't in localStorage/sessionStorage and the cookie is HttpOnly; log out and reload (login form shown); with `SSO_ACCESS_TTL_MIN=1`, confirm the auto-refresh about 60 s before expiry | §7.2/§7.4 behaviour | M |
| E2E-10 | `docker compose up` from a clean checkout with `.env` from `.env.example` and `gen_keys.sh`; run the whole suite against the nginx URL (TLS) | server starts; suite passes (addendum §C) | M |
| E2E-11 | key rotation seen by the verifier: add a new key (JWKS-08), switch signing; the verifier refetches on unknown kid (at most once a minute) | new tokens accepted without restarting the verifier | M |
| E2E-12 | same account used through myFinance and SSO | see LEGACY-08 | M |
| E2E-13 | verifier JWKS refetch limit (§8.1): warm the verifier, send 20 tokens with random unknown kids → ≤ 1 JWKS GET in the SSO access log; wait 61 s, 20 more → exactly 1 GET; all 401; valid token still 200. Needs `SSO_ACCESS_LOG` | as described | A\* (slow, ~65 s) |

### 3.12 Deployment files and docs (addendum §A, §C, B1, B11, B12)
| ID | Check | Auto |
|---|---|---|
| DEPLOY-01/01b | Dockerfile, docker-compose.yml, nginx.conf, scripts/gen_keys.sh, .env.example, README.md, manage.py, examples/verifier/, examples/frontend/index.html exist | A |
| DEPLOY-02 | `.env.example` lists every setting (incl. `SSO_JWT_PUBLIC_KEY_PATHS`, `SSO_CACHE_URL`, `SSO_COOKIE_DOMAIN`); `SSO_DEBUG=False`; no key material | A |
| DEPLOY-03 | no private key tracked in git; `keys/` gitignored | A |
| DEPLOY-04 | frontend uses `credentials: "include"` and the login/refresh paths; no localStorage/sessionStorage | A |
| DEPLOY-05 | nginx: `listen 443 ssl`, `proxy_set_header Host $http_host`, `X-Forwarded-Proto` | A |
| DEPLOY-06 | compose mounts keys at `/run/keys:ro` | A |
| DEPLOY-07 | README covers mysqldump backup, gen_keys, migrate, ServiceClient registration, SSO_CACHE_URL, .env | A |
| DEPLOY-08 | `makemigrations --check --dry-run` clean (B11) | A\* |
| DEPLOY-09 | start with `SSO_DEBUG=False` and an empty `SSO_SECRET_KEY` / missing key files → refuses with a clear message (B12) | M |
| DEPLOY-10 | `gen_keys.sh` makes an RSA ≥ 2048 key, private chmod 600, public PEM | M |
| DEPLOY-11 | `showmigrations`/`sqlmigrate`: SSO owns migrations only in `sso` and `token_blacklist`; nothing ALTERs existing tables; no `clearsessions`/`remove_stale_contenttypes` in scripts or cron (B11) | M |
| DEPLOY-12 | `flushexpiredtokens` cron documented and runs (§9.6) | M |
| DEPLOY-13 | suite passes on the Django 5.2 pin and on a Django 4.2 build (B1) | M |
| DEPLOY-14 | the Developer's `pytest` run: all §11 tests exist and pass, ≥ 90% line coverage on `sso/` (addendum §C) | M (review) |
| DEPLOY-15 | image name: `web.image` = `${DOCKER_USER:-thomaschoi}/sso-server:${IMAGE_TAG:-latest}`; resolves to `thomaschoi/sso-server:latest` (unset or empty tag) and `acme/sso-server:0.1.1` with overrides; `.env.example` sets `DOCKER_USER=thomaschoi` and pins a non-`latest` `IMAGE_TAG`; no shipped file still uses `SSO_IMAGE_TAG` | A |
| DEPLOY-16 | non-root uid/gid: `ARG SSO_UID=10001` / `SSO_GID=10001` declared **inside** the runtime stage; final `USER ${SSO_UID}:${SSO_GID}`, never root/0; `useradd` uses the args with `nologin`; app files `COPY --chown=root:root`; compose `build.args` and `user:` use the same variables/defaults (10001:10001, override 1500:1500); `.env.example` values numeric and ≠ 0 | A |
| DEPLOY-16b | the Dockerfile's own uid/gid validation lines executed in `sh`: 10001/1500/1000:100 accepted; 0 (uid or gid), `abc`, empty, `-1`, `1e3` rejected | A |
| DEPLOY-17 | `MYSQL_IMAGE` in `docker-compose.test.yml` (`mysql`) and `docker-compose.dev.yml` (`db`): default = the README's documented default (`mysql:8.0` at f22b2e0); `MYSQL_IMAGE=mysql:8.4`/`mysql:8.0` and `QA_MYSQL_TAG=8.4`/`8.0` select it; `MYSQL_IMAGE` wins over `QA_MYSQL_TAG`; data volume name parameterized per version with a default matching the default version | A |
| DEPLOY-17b | `SSO_TEST_EXPECT_MYSQL` uses the same expression as the MySQL image; `sso/tests/test_mysql_integration.py` accepts 8.0 and 8.4 and checks `caching_sha2_password`; init script sets `caching_sha2_password` and never `mysql_native_password` | A |
| DEPLOY-18 | Python 3.13: `ARG PYTHON_IMAGE=python:3.13.16-slim-trixie`; `docker/Dockerfile.test` and `examples/verifier/Dockerfile` on the same base; any pinned digest is 64 hex; no `python:3.10-3.12` left outside `qa/`/`devops/` | A |
| DEPLOY-19 | defect 4/5 guards: no `--forwarded-allow-ips '*'`; gunicorn uses `${SSO_FORWARDED_ALLOW_IPS:-127.0.0.1}`; `SSO_NUM_PROXIES` code default 0, compose default 1; compose `SSO_CACHE_URL` default `redis://redis:6379/0`; `web` not published; nginx overwrites XFF | A |
| DEPLOY-20 | uid-0 refusal: fresh interpreter with `os.geteuid` patched — euid 0 + `SSO_DEBUG=False` → `ImproperlyConfigured` (root message); euid 0 + `SSO_DEBUG=True` loads; euid 10001 + `SSO_DEBUG=False` passes the root guard (stops at the next guard) | A |
| DEPLOY-20b | root guard in `settings.py` before the other settings, `sso.E002` registered in `sso/checks.py`, `sso/runtime.py` uses `geteuid`, `docker/Dockerfile.test` runs as `10001:10001` | A |
| DOC-01 | `SSO-server.md` has a front-end integration section usable without help (§7) (R-06) | M |
| DOC-02 | `SSO-server.md` has a back-end verification section (§8) (R-07) | M |
| DOC-03 | Clarity review: QA built the automated client and verifier from the docs alone; every place we had to guess is listed in §6 (R-08) | M |

---

## 4. Automation approach
- Black-box pytest + `requests` (httpx is in requirements for async/HTTP2 follow-ups) against a running server. No imports from the server code.
- `sso_client.py` parses `Set-Cookie` by hand and replays it as an explicit `Cookie` header. Cookie flags can then be asserted exactly, and the
  `Secure` cookie still works on an http dev server.
- `jwt_forge.py` (PyJWT + cryptography) mints the attack tokens. Tokens that need the real signing key (bad claims with a valid signature) use
  `SSO_TEST_PRIVATE_KEY_PATH`, which may only point at the test environment's key.
- The few white-box checks (rehash, last_login, deactivate, DB freshness, makemigrations) go through `SSO_MANAGE_CMD` (the server's own Django
  shell) and skip when it isn't set.
- Login/refresh helpers wait out `429` + `Retry-After`, so the hard-coded 10/min per-IP login limit slows the suite but doesn't break it (Q-02).
- Markers: `throttle`, `slow`, `static`, `needs_private_key`, `needs_manage`, `needs_verifier`.

| File | Cases |
|---|---|
| `test_login.py` | LOGIN-01..19 |
| `test_refresh.py` | REFRESH-01..12 |
| `test_logout.py` | LOGOUT-01..08 |
| `test_logout_all.py` | LOGOUT-ALL-01..07 |
| `test_me.py` | ME-01..07 |
| `test_introspect.py` | INTRO-01..14 |
| `test_jwks_discovery_health.py` | JWKS-01..07, DISC-01..06, HEALTH-01..02 |
| `test_errors.py` | ERR-01..13 |
| `test_legacy_hashes.py` | LEGACY-01..07 |
| `test_security_jwt.py` | SEC-01..19 |
| `test_security_cookies_origin.py` | SEC-20..28 |
| `test_zz_throttle.py` | SEC-30..35, ERR-14 |
| `test_e2e.py` | E2E-01..08 |
| `test_deploy_files.py` | DEPLOY-01..08, DEPLOY-15..20 |

### 4.1 Case counts
| Area | Automated (A/A\*) | Skipped pending spec (S) | Manual (M) | Total |
|---|---|---|---|---|
| Login | 19 | 0 | 2 | 21 |
| Refresh | 12 | 0 | 0 | 12 |
| Logout | 8 | 1 | 0 | 9 |
| Logout-all | 7 | 1 | 0 | 8 |
| Me | 7 | 0 | 0 | 7 |
| Introspect | 14 | 0 | 0 | 14 |
| JWKS / discovery / healthz | 15 | 0 | 2 | 17 |
| Error format | 15 (ERR-14, ERR-16 asserted inside SEC cases) | 0 | 1 | 16 |
| Legacy PBKDF2 | 7 | 0 | 2 | 9 |
| Security | 34 (SEC-01..28, 30..35) | 0 | 4 | 38 |
| End-to-end | 9 | 0 | 4 | 13 |
| Deployment / docs | 18 | 0 | 9 | 27 |
| **Total** | **165** | **2** | **24** | **191** |

pytest collects 211 items because of parametrization (`pytest --collect-only` passes with no errors).

---

## 5. Traceability

### 5.1 Request.txt → tests
| R-ID | Request.txt item (abridged) | Tests | Status |
|---|---|---|---|
| R-01a | "reuse the same Django method of user login management" | LOGIN-01..19, LEGACY-01..07, REFRESH-09, INTRO-10 | Covered |
| R-01b | "…@myFinance/settings.py" | LEGACY-05 (hasher order still myFinance-compatible), LEGACY-08 | **Partial gap**: QA doesn't have myFinance `settings.py`, so parity of PASSWORD_HASHERS/AUTHENTICATION_BACKENDS can't be confirmed (Q-18) |
| R-01c | "…using the database dcWebUsers" | DEPLOY-08, DEPLOY-11, LEGACY-09, E2E-10 | **Partial**: black-box tests can't see which DB is used. Covered by manual config review and the staging copy |
| R-02 | "All the users are kept" | LEGACY-01..09, E2E-01; all seeded users have 4.1 hashes | Covered on synthetic users. **Real-data proof needs LEGACY-09 on a restored dcWebUsers copy (M)** |
| R-03 | "Support REST API for login" | LOGIN-*, REFRESH-*, LOGOUT-*, LOGOUT-ALL-*, ME-*, ERR-* | Covered |
| R-04 | "front-end login → SSO server and return a token" | LOGIN-02/04/05, SEC-20..28, JWKS-*, DISC-*, E2E-03, E2E-09 | Covered |
| R-05 | "front-end use the token to access services in other back-end server" | E2E-01..08, SEC-01..19, INTRO-* | Covered (needs the verifier demo running for E2E-02..08) |
| R-06 | "section to list the front-end approach to use the API" | DOC-01, E2E-09, DEPLOY-04, E2E-03 | Covered (doc review + example) |
| R-07 | "section … how the backend services … verify the user login (token)" | DOC-02, E2E-01, E2E-05/06, SEC-19 | Covered |
| R-08 | "new repo … SSO-server.md very clear for developer" | DOC-03, DEPLOY-01/07 | **Ambiguous** ("very clear" is subjective). Evidence: §6 lists 29 points where the doc forced QA to guess |

### 5.2 Addendum / spec §11 → tests (secondary)
| Item | Tests |
|---|---|
| B1 Django 4.2/5.2 | DEPLOY-13, LEGACY-05 |
| B2 discovery token_endpoint | DISC-03, DISC-04, DISC-06, ERR-10 |
| B3 per-username throttle, shared cache, 429 shape | SEC-30..35, ERR-14 |
| B4 timing-safe unknown user | LOGIN-08, LOGIN-M1 |
| B5 email login rules | LOGIN-11..13 |
| B6 kid / multiple public keys | LOGIN-04, JWKS-04/05/06, JWKS-08 |
| B7 aud on both tokens | LOGIN-04/05, SEC-09 |
| B8 revocation at refresh | REFRESH-10, REFRESH-11, LOGOUT-ALL-01 |
| B9 Origin check | SEC-22..26, ERR-16 |
| B10 error handler incl. 404/405/500 | ERR-*, all `assert_error` uses |
| B11 shared tables / migrations | DEPLOY-08, DEPLOY-11 |
| B12 settings / refuse to start | DEPLOY-02, DEPLOY-09 |
| B13 logging | LOGIN-M2, SEC-29 |
| B14 Django 4.1 hash fixtures | §2.2 seed, LEGACY-* |
| §11 login ok/wrong/unknown/inactive/email/throttle | LOGIN-01/07/08/09/11, SEC-30 |
| §11 rotation reuse rejected; logout blacklists | REFRESH-02/05, LOGOUT-01/02 |
| §11 logout-all + introspect after revocation | LOGOUT-ALL-01/02 |
| §11 access rejected at /refresh; refresh rejected by §8.2 | REFRESH-06, SEC-14 |
| §11 JWKS kid matches; expired/wrong aud/iss | JWKS-05, SEC-08/09/10 |
| §11 cookie HttpOnly/Secure + Origin | SEC-20..25 |

### 5.3 Gaps
1. R-01b: myFinance `settings.py` isn't available to QA (Q-18).
2. R-01c / R-02: real `dcWebUsers` data can only be checked by hand on a restored copy (LEGACY-09). The automated suite uses synthetic Django 4.1 hashes.
3. R-08: no objective acceptance criterion. The §6 question list is the clarity review.
4. Two cases are skipped until the spec decides (LOGOUT-07, LOGOUT-ALL-07). Several cases accept two outcomes until the questions are answered (REFRESH-08, LOGOUT-05, INTRO-02..06 error codes).

---

## 6. Open questions and document conflicts (for Philip / Developer)

**Doc conflicts**
- **Q-01** Public key env: spec §9.3/§9.4 `SSO_JWT_PUBLIC_KEY_PATH` (single) vs addendum B6 `SSO_JWT_PUBLIC_KEY_PATHS` (comma list). Addendum wins; DEPLOY-02 expects the plural. Is the singular still accepted? *(Code: yes, as a fallback.)*
- **Q-24** Phase numbering: spec §2, §5.4, §6.8, §6.9, §9.2 call hosted login/PKCE/account endpoints "phase 2", but the §10 table puts them in phase 5 and phase 2 = cookie mode/CORS/throttling. Addendum §A uses the §10 numbering, so QA treats §6.8/§6.9 as out of scope.
- Discovery: spec §6.7 advertises `token_endpoint=/api/v1/auth/token` and `authorization_endpoint`; addendum B2 forbids both for now (tests follow B2). **Q-17**: the minimal discovery doc lacks OIDC-required fields (`response_types_supported`, `subject_types_supported`), so strict OIDC libraries will reject it. Advertising `/login` as an OAuth `token_endpoint` may mislead OAuth clients. QA recommends omitting `token_endpoint` until phase 5.
- **Q-13** examples/verifier: §8.4 uses `HTTPBearer()`, which in older FastAPI versions answers a missing header with **403**, while §8.1/§8.6 require **401**. §8.4 also sends `WWW-Authenticate: Bearer` where §8.6 says `Bearer error="invalid_token"`. E2E-05 expects 401 and a header starting with `Bearer`. Also: what is the demo's endpoint path, and does it have a group-protected endpoint?
- Spec §3 names `ScopedRateThrottle` only; B3 adds the custom `LoginUserThrottle`. They complement each other; tests cover both.
- Spec §6.0 table lacks `origin_not_allowed`; B9 adds it. Covered.

**Likely defects to design out now (Developer heads-up)**
- **Q-04** Spec §6.1 says "`authenticate()` then reject inactive users", but Django's `ModelBackend.authenticate()` returns `None` for `is_active=False`. Implemented literally, inactive users get `invalid_credentials` and never `account_inactive` (LOGIN-09). The password must be checked separately, and an inactive user with a wrong password should still get 401 (LOGIN-10).
- **Q-19** Malformed stored hashes (`pbkdf2_sha256$notanumber$…`, a truncated hash) make Django's `check_password` raise `ValueError` (verified with Django 5.2.18). Unhandled, that is a 500 on login (LEGACY-06 expects 401).
- **Q-08** `revoked_at` has sub-second precision but JWT `iat` is whole seconds. With a naive `iat < revoked_at`, a token issued later **in the same second** as a logout-all is treated as revoked (LOGOUT-ALL-05). Which rule do you want (e.g. compare at second granularity with `<`)?
- **Q-25** (SEC-35) DRF uses the raw `X-Forwarded-For` header as the throttle key when `NUM_PROXIES` is unset. Behind nginx, set `NUM_PROXIES=1`, or clients can bypass the per-IP limit. *(Code: `SSO_NUM_PROXIES` defaults to 1. That is correct behind nginx but bypassable when gunicorn is exposed directly. Document it, and make the compose file not publish the gunicorn port.)*
- **Q-15** Login CSRF: DRF's default parsers accept form-encoded bodies. A cross-site HTML form could then log a victim's browser into an attacker account (sets `sso_refresh`). Restrict to `JSONParser` (spec: "All bodies are JSON"); LOGIN-19 checks this. *(Code: JSONParser only.)* Should browser-mode login also require an allowed Origin?
- **Q-03** docker-compose runs 3 gunicorn workers. With the default LocMem cache, each worker counts separately, so the effective limit is about 3× the spec. The test env needs one worker or a shared cache. Should compose ship with Redis or the DB cache?

**Undecided behaviour (tests accept both outcomes or are skipped)**
- **Q-02** Throttle rates are hard-coded in settings (§9.3). Can they be env-configurable (e.g. `SSO_THROTTLE_LOGIN`, `SSO_THROTTLE_LOGIN_USER`, `SSO_THROTTLE_REFRESH`)? QA could then run the functional suite quickly and the throttle suite at spec rates. *(Code: done.)*
- **Q-05 — RESOLVED (Philip, 2026-10-10):** `/logout` in cookie mode with no token → **204 + cookie cleared** (idempotent logout; LOGOUT-05). `/refresh` with no token stays **401 `token_invalid`** (REFRESH-08).
- **Q-06** Logout with an already-blacklisted refresh token: 204 (idempotent) or 401?
- **Q-07** Missing `Authorization` on `/me` and `/logout-all`: which `error` code (assumed `token_invalid`)? Should SSO 401s carry `WWW-Authenticate`?
- **Q-09** Must `/me` (and `/logout-all`) reject access tokens issued before `revoked_at`, or is only introspect revocation-aware (§6.3 suggests the latter)?
- **Q-10** `error` code for introspect client-auth failure (`invalid_client`?) is not in §6.0. Is introspect throttled?
- **Q-11** `kid` = SHA-256 of the public key's DER: SubjectPublicKeyInfo (`openssl rsa -pubout -outform DER`) assumed, not PKCS#1. Please confirm.
- **Q-12** Should the SSO server itself reject tokens with a future `iat` (simplejwt doesn't check it by default)? §8.1 only requires it of services.
- **Q-14** Token responses should send `Cache-Control: no-store` (RFC 6749 §5.1). Not in the spec; REFRESH-12 is an xfail recommendation.
- **Q-16** Cookie `Domain` in local/test environments: does an empty `SSO_COOKIE_DOMAIN` give a host-only cookie? Which origin and port will serve `examples/frontend/index.html` in dev (it must be in CORS, same-site, and https or localhost for the `Secure` cookie)?
- **Q-18** Please provide myFinance `settings.py` (or its PASSWORD_HASHERS, AUTHENTICATION_BACKENDS, Django version) to close R-01b. Does myFinance allow email login today?
- **Q-20** Rehash on login goes to 1,000,000 iterations (Django 5.2) or 600,000 (4.2). It writes to the shared `auth_user` and adds login latency. Acceptable?
- **Q-21** Request with both a body `refresh_token` and the cookie: which wins, and is the Origin check applied? (A1 assumes the body wins with no check.)
- **Q-22** Refresh-token reuse detection (revoke the whole family when a rotated token is replayed) isn't specified. Do we want it in sprint 1?
- **Q-23** Does a cookie-mode refresh omit `refresh_token` from the body like browser login? (assumed yes)
- **Q-26** Introspect active response: only `sub, username, groups, exp` are listed. Should it include `is_staff`, `token_type`, `iss`/`aud`?
- **Q-27** Username case: MySQL's default collation is case-insensitive, SQLite's isn't, so `QA_ALICE` may log in on MySQL only. What behaviour do we want? (not tested)
- **Q-28** `/healthz` with the DB down: status code (503?) and body?
- **Q-29** Cookie `Max-Age`: fixed 604800 (spec text) or follows `SSO_REFRESH_TTL_DAYS` (assumed)?

## 7. Entry / exit criteria
- **Entry:** the Developer reports the code ready; the server starts with the test config in §2.1; the seed script runs cleanly; endpoint paths match the spec (or `sso_client.py` is updated).
- **Exit (sprint 1):** all A/A\* cases pass, with prerequisites provided (private key, manage cmd, verifier demo); manual cases executed and recorded;
  no open Sev-1/2 defects (auth bypass, token forgery accepted, legacy users unable to log in, 500s leaking data); open questions answered,
  S cases converted to real assertions.
