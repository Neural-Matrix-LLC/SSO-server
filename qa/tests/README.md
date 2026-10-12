# SSO server QA suite (black-box)

Black-box pytest suite that talks to a **running** SSO server over HTTP(S). The plan, case IDs
and traceability live in `../TEST-PLAN.md`; every test function name starts with its case ID
(`test_LOGIN_04_...` = LOGIN-04).

## 1. Install

```bash
cd qa
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt
```

## 2. Start the server and seed test data

Use a **test** database (SQLite via `SSO_DB_ENGINE=sqlite`, or the MySQL 8 test container). Never seed
production `dcWebUsers`.

```bash
# from the repo root, in the server's environment
python manage.py migrate
SSO_ALLOW_SYNTHETIC_SEED=1 python manage.py shell -c "exec(open('qa/tests/fixtures/seed_test_data.py').read())"
# docker variant:
docker compose exec -T -e SSO_ALLOW_SYNTHETIC_SEED=1 web python manage.py shell < qa/tests/fixtures/seed_test_data.py
```

**Guard (R27):** the seed exits with code 2 unless `SSO_ALLOW_SYNTHETIC_SEED=1` is set *and* the DB is local/throw-away
(SQLite in a temp dir, a `qa/` dir or named `*test*`/`*qa*`; MySQL on localhost/127.0.0.1/::1/socket/`db`/`mysql` or a host
listed in `SSO_SEED_LOCAL_HOSTS`).

The seed creates `qa_*` users (Django 4.1 `pbkdf2_sha256$390000$` hashes plus a few deliberately
broken/legacy formats), groups `qa_trader`/`qa_beta`, and ServiceClients `qa-service` (active) and
`qa-service-inactive`. Re-run it before every suite run: some tests change state (rehash on login,
logout-all, deactivate/reactivate).

Server settings the suite assumes: `SSO_CORS_ALLOWED_ORIGINS` contains `SSO_TEST_ALLOWED_ORIGIN` (below),
**one gunicorn worker or a shared cache** (so throttle counters are global), `SSO_COOKIE_SECURE`/`SSO_COOKIE_SAMESITE` left at
defaults, and `SSO_NUM_PROXIES=0` when the suite talks to gunicorn/runserver directly (1 only behind nginx).
For a fast functional run, start the server with high `SSO_THROTTLE_LOGIN`/`SSO_THROTTLE_LOGIN_USER`/`SSO_THROTTLE_REFRESH`
and run `-m "not throttle"`; run `-m throttle` against defaults (or set `SSO_TEST_RATE_*` to the configured rates).

## 3. Configure (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SSO_BASE_URL` | `http://localhost:8000` | Server under test (nginx URL for TLS runs, e.g. `https://localhost:8443`) |
| `SSO_VERIFY_TLS` | `1` | `0` for self-signed certs, or a path to a CA bundle |
| `SSO_ISSUER` | discovery `issuer` | Expected `iss` (set it so the issuer is checked independently) |
| `SSO_AUDIENCE` | `myfin-services` | Expected `aud` |
| `SSO_ACCESS_TTL_MIN` / `SSO_REFRESH_TTL_DAYS` | `15` / `7` | Must match the server config |
| `SSO_TEST_ALLOWED_ORIGIN` | `https://example.com` | An origin that is in the server's `SSO_CORS_ALLOWED_ORIGINS` (used for browser/cookie-mode cases; every other origin is treated as hostile). `SSO_ALLOWED_ORIGIN` is still read as a legacy alias |
| `SSO_COOKIE_DOMAIN` | unset | Expected cookie `Domain`; unset = don't check; empty string = expect host-only cookie |
| `SSO_TEST_PRIVATE_KEY_PATH` | unset | The **test env's** signing key; enables validly-signed bad-claim cases (expired, wrong iss/aud, ...) |
| `SSO_MANAGE_CMD` | unset | e.g. `.venv/bin/python manage.py` or `docker compose exec -T web python manage.py`; enables DB-state cases |
| `SSO_REPO_DIR` | `../..` from this folder | Repo root (static DEPLOY checks and `SSO_MANAGE_CMD` cwd) |
| `VERIFIER_BASE_URL` | unset | examples/verifier FastAPI demo, enables E2E-02..08 |
| `VERIFIER_PROTECTED_PATH` | `/me` | Demo endpoint that requires a valid access token |
| `VERIFIER_GROUP_PATH` / `VERIFIER_GROUP_NAME` | unset / `qa_trader` | Demo endpoint that requires a group |
| `SSO_TEST_RATE_LOGIN_IP` / `_LOGIN_USER` / `_REFRESH` | `10` / `5` / `60` | Expected throttle rates |
| `SSO_TEST_MAX_THROTTLE_WAIT` | `240` | Max seconds a functional test waits out a 429 before failing |

Cases whose prerequisites are missing are **skipped** with the reason, not failed.

## 4. Run

```bash
cd qa/tests
../.venv/bin/python -m pytest                       # everything (throttle tests run last, ~5 min extra)
../.venv/bin/python -m pytest -m "not throttle"     # functional + security, no deliberate rate limiting
../.venv/bin/python -m pytest -m throttle           # rate-limit cases only
../.venv/bin/python -m pytest -m static             # repo/deployment file checks, no server
../.venv/bin/python -m pytest -k "LOGIN or REFRESH" # by case ID prefix
../.venv/bin/python -m pytest --collect-only -q     # list cases
```

Note: the login throttle (10/min per IP) also applies to the functional tests. The client waits out
`429` + `Retry-After` on login/refresh helpers, so a full run is slow (several minutes) unless the
test server is started with higher `SSO_THROTTLE_*` rates.

## 5. Layout

| File | Content |
|---|---|
| `conftest.py` | env config, `sso` client, JWKS/discovery, users, `manage` (Django shell) and `verifier` fixtures |
| `sso_client.py` | endpoint paths + requests wrapper, manual cookie handling, 429 back-off |
| `jwt_forge.py` | alg=none, HS256-with-public-key, tampering, attacker keys, kid computation |
| `reference_verifier.py` | spec 8.2 verifier (PyJWT) used as positive/negative control |
| `testdata.py` / `fixtures/seed_test_data.py` | test users and their Django 4.1 hashes; seeding script |
| `helpers.py` | error-envelope / token-response / user-object assertions |
| `test_*.py` | one file per area (see TEST-PLAN.md section 4) |


### JWKS refetch-limit test (E2E-13)

`test_e2e.py::test_E2E_13_verifier_jwks_refetch_rate_limited` counts `GET /.well-known/jwks.json` lines in the SSO server's gunicorn access log. Set `SSO_ACCESS_LOG=/path/to/access.log` (the file given to `--access-logfile`, or the combined log written by `qa/run/start_sso.sh`); without it the test is skipped. It sleeps 61 s (marker `slow`; deselect with `-m 'not slow'`).

### Shared cache

With `SSO_DEBUG=False` the server refuses to start without `SSO_CACHE_URL` (or with `locmemcache://`/`dummycache://`). `qa/run/sso.env` sets `filecache:///tmp/qa-cache`; give each side instance its own cache dir so throttle counters don't mix.

## Key configuration round (610c9b8 / d784f10)

`qa/harness/` (tracked) starts the server with the NEW key variables (`SSO_JWT_KEYS_MOUNT=qa/run/keys`,
`SSO_JWT_PRIVATE_KEY=qa-test.private.pem`, `SSO_JWT_PUBLIC_KEYS=qa-test.public.pem`; the deprecated `*_PATH` variables are
unset). Dedicated ports only (never 8000), stop by recorded PID:

```bash
qa/harness/run_keys_round.sh qa/.venv-py3.13.16 py3.13 8052 8050   # VENV TAG SERVER_PORT KEYROT_PORT
qa/harness/run_keys_round.sh qa/.venv-py3.11   py3.11 8053 8051
# or by hand: qa/harness/start_sso.sh 8052 /tmp/sso.log ; ... ; qa/harness/stop_sso.sh 8052
```

It migrates a throw-away SQLite DB under `qa/run/`, seeds it, runs `manage.py check`, starts gunicorn, runs
`test_deploy_files.py test_keys_config.py test_jwks_discovery_health.py test_security_jwt.py`, and writes
`qa/run/keys-<TAG>/{pytest.log,junit.xml,sso-server.log,server-cmdline.txt,check.log}`. `test_keys_config.py` needs
`QA_SSO_PYTHON` (the server venv's python; settings are loaded there in a fresh interpreter) and `QA_KEYS_PORT` (KEYROT-* start
and stop their own gunicorn on it).
