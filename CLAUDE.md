# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Django 5.2 / DRF single sign-on server (not a LangChain project: the global `~/.claude/CLAUDE.md` layout
`src/`, `tests/unit/` and the `pip freeze` workflow do **not** apply here). It issues RS256 JWTs for
myFinance and related apps and runs against the **shared, existing `dcWebUsers` MySQL database** (stock
`auth_user`). Specs that the code follows (and that comments cite by section, e.g. "spec §8.2",
"addendum B.12", "design v1.2"): `docs/SSO-server.md` (v1.0), `docs/DESIGN-ADDENDUM-v1.1.md`,
`docs/sso-integration-design.md` (app permissions / ServiceClient delegation), `devops/DEPLOYMENT-PLAN.md`
(R-numbers, §-numbers). `README.md` is the authoritative operator guide.

## Commands

Target runtime is **Python 3.13** (same as the image). Dependencies are hand-maintained ranges:
`requirements.txt` (runtime), `requirements-dev.txt` (tests, no mysqlclient), `requirements.lock` (exact image
pins). Edit these files directly; do not `pip freeze` into them.

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest                                   # whole suite (sso/tests), SQLite in memory, coverage for sso + application
.venv/bin/pytest sso/tests/test_login.py::test_login_wrong_password   # single test
.venv/bin/pytest -k rotation                       # by keyword
scripts/test_both_django.sh                        # Django 5.2 and 4.2 (portability), --cov-fail-under=90
PYTHON=python3.13 scripts/test_both_django.sh -k login
```

The unit suite needs no DB server and no key files: `ssoproject/settings_test.py` (set in `pytest.ini`)
generates throw-away RSA keys (`current`, `old` = published-only rotation key, `rogue` = never published),
exports their paths as `SSO_TEST_*` env vars, sets `SSO_ENV_FILE=""` so the local `.env` is ignored, and
swaps the cache to LocMem. Tests sign forged tokens via `sign()` / `claims()` in `sso/tests/conftest.py`.

MySQL integration (Docker; `sso/tests/test_mysql_integration.py` is skipped on SQLite):
```bash
scripts/dev_setup.sh                               # creates .env.test once
T='docker compose --env-file .env.test -f docker-compose.test.yml'
$T run --rm --build tests                          # MySQL 8.0; MYSQL_IMAGE=mysql:8.4 SSO_TEST_MYSQL_VOLUME=sso-test-mysql-8.4 for 8.4
```

Black-box QA suite (separate venv, talks to a running server over HTTP; case IDs like `test_LOGIN_04_*`
map to `qa/TEST-PLAN.md`): see `qa/tests/README.md`. Repo-only checks need no server:
`cd qa/tests && ../.venv/bin/python -m pytest -m static`. `qa/harness/run_keys_round.sh` runs the key-config
round on dedicated ports (never 8000).

Local server without Docker: README §2 (SQLite, `SSO_CACHE_URL=filecache:///...`, gunicorn). Docker: README
quick start / §7 (`docker-compose.yml` prod, `docker-compose.dev.yml` overlay).

## Architecture

**Settings are the fail-fast gate.** `ssoproject/settings.py` reads everything from env (django-environ,
`SSO_*` prefix) and, with `SSO_DEBUG=False`, raises `ImproperlyConfigured` at import for: empty
`SSO_SECRET_KEY`/`SSO_ISSUER`, missing/unreadable/non-RSA/<2048-bit keys, no shared cache
(`SSO_CACHE_URL`), running as uid 0, bad DB TLS config. It resolves key config via
`sso.keys.resolve_key_config` (name precedence `SSO_JWT_KEYS_MOUNT` > `SSO_KEYS_DIR` > `/run/keys`; deprecated
`*_PATH(S)` forms warn `sso.W001`, mixing old and new forms is an error) and builds `SSO_KEYSET` once, which
feeds `SIMPLE_JWT`. Tests for this live in `sso/tests/test_keys_settings.py` and load settings in a fresh
interpreter.

**Token flow** (`sso/tokens.py`, `sso/views.py`): `KidTokenBackend` extends simplejwt to sign with a `kid`
header (= sha256(DER SPKI)[:16], `sso/keys.py`) and verify by `kid` across all published keys, RS256 only,
with iss/aud. `issue_token_pair` always builds a fresh pair from the DB (groups, `perms`), so refresh picks
up permission changes. Refresh rotates and blacklists (simplejwt `token_blacklist`; the blacklist insert is
the race guard). `logout-all` writes `UserTokenRevocation`; a token is revoked if `iat < ceil(revoked_at)`.
Browser mode keeps the refresh token in an HttpOnly cookie and checks `Origin` against
`SSO_CORS_ALLOWED_ORIGINS`; native mode returns it in the body. Parsers are JSON-only.

**Auth details:** `AllowAllUsersModelBackend` so inactive users get 403 `account_inactive` only with a
correct password; every login path runs exactly one hash (dummy hash for unknown users, timing-safe).
`sso/errors.py` produces the uniform `{"error","detail"}` envelope for DRF and Django errors.
`sso/authentication.py`: Bearer access-token auth (honours revocation) and HTTP Basic for `ServiceClient`.
`sso/delegation.py`: a ServiceClient authenticated by Basic may pass `client_ip` on login/refresh so the
per-IP throttle uses the end user's IP (bad Basic → 401 `invalid_client`, no fallback).

**`application` app** = central app permissions `application.<codename>` anchored on the
`ApplicationAccess` model. `application.permissions.user_app_perms` computes the `perms` claim from real
permission rows (user + groups, filtered to `application.*`), never `has_perm()` — superusers get nothing
automatically unless `SSO_SUPERUSER_ALL_APPS=true`. A post-migrate hook recreates only code-defined
permissions (`app1`) and logs ERROR for lost ones; `create_app_permission` adds more without code changes.

## Constraints that are easy to break

- **Shared database.** `dcWebUsers` belongs to myFinance too. This project may only own migrations for
  `sso`, `application` and `token_blacklist`; shared apps must stay at their Django 4.1 leaf migrations
  (`sso/tests/test_migrations.py` asserts this and that `makemigrations --check` is clean). Never add models
  that change `auth_*`, and never run `clearsessions` / `remove_stale_contenttypes`.
- The runtime DB account is DML-only; the container never migrates on its own (migrations run as
  `sso_migrator`).
- Legacy Django 4.1 PBKDF2 hashes (`pbkdf2_sha256$390000$…`) must keep working; corrupt stored hashes must
  give 401, not 500.
- Never log tokens or passwords (`sso/logs.py` emits one structured JSON line per login attempt).
- Env var changes must be reflected in `.env.example` (and `.env.dev.example` / `.env.test.example` and the
  README §3 table where relevant); QA's `test_deploy_files.py` statically checks deployment files.

## Repo conventions

- Commit subjects are prefixed by area when not core code: `docs:`, `qa:`, `devops:`, `keys:`. QA results
  are recorded in `qa/RESULTS-*.md` against a commit hash.
- README §9 maps spec §11 requirements to test names; update it when renaming or adding such tests.
- Per the user's global rules, every change is logged in `HISTORY.md` at the repo root (not created yet:
  create it with the first logged change).

## Database migrations rule (Thomas, 2026-10-16)
`scripts/upgrade_db.sh` is the single upgrade path for every SSO database change. For each new migration in
`sso/` or `application/`: append it to the MANIFEST block at the top of `scripts/upgrade_db.sh`, add its
tables/columns to `EXPECTED` in `sso/management/commands/sso_schema_check.py`, and add a
`docs/db/upgrade-<prev>-to-<ver>.sql`. `sso/tests/test_upgrade_manifest.py` fails if any of these is missing.
