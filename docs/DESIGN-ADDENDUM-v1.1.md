# SSO-server design addendum v1.1 (team lead review)

Base spec: `docs/SSO-server.md` (v1.0). Where this addendum disagrees with it, the addendum wins.
Source requirement: `docs/Request.txt`.

## A. Sprint 1 scope
Build spec phases 1 and 2 (spec §10) and the phase 3 deployment *files* (Dockerfile, docker-compose.yml, nginx.conf,
gen_keys.sh, .env.example, README). Phase 4 (first consumer) and phase 5 (PKCE, account endpoints) are out of scope,
but leave the models/URL names ready for them (AuthorizationCode model may be added now, unused).
Also deliver a tiny reference back-end verifier package `examples/verifier/` (spec §8.2 PyJWT code + a FastAPI demo
endpoint) and a static test page `examples/frontend/index.html` using spec §7.2 `auth.js`, so QA can test end to end.

## B. Fixes and clarifications to the v1.0 spec
1. **MySQL version.** Django 5.2 needs MySQL >= 8.0.11 (MariaDB >= 10.5). If production `dcWebUsers` is older,
   fall back to Django 4.2 LTS (supports MySQL 5.7). Write code that works on both 4.2 and 5.2; pin 5.2 by default.
   (Open question to Thomas.)
2. **Discovery `token_endpoint`.** Until phase 5, `token_endpoint` must point to `/api/v1/auth/login` (or be
   omitted); do not advertise `/api/v1/auth/token` or `authorization_endpoint` before they exist.
3. **Per-username throttle.** DRF has no per-username throttle out of the box: implement `LoginUserThrottle`
   (SimpleRateThrottle, cache key = lowercased username/email from the request body). Use Django's cache; default
   LocMem in dev/tests, document that production with >1 gunicorn worker needs a shared cache (Redis or DB cache,
   `SSO_CACHE_URL`). Throttled responses return the spec §6.0 shape with `Retry-After`.
4. **Timing-safe unknown user.** For unknown users still run a dummy password hash so response time does not leak
   existence (Django's `ModelBackend` already does this; make sure the email lookup path does too).
5. **Email login.** Case-insensitive `email__iexact`; zero or >1 matches -> `invalid_credentials`. Empty emails
   never match.
6. **`kid` header.** Compute once at start-up from the public key (spec §5.3). simplejwt >= 5.3 supports
   `"JWK_URL"` for verification only; for signing, set the header by subclassing `TokenBackend` or by
   overriding `Token.__str__`. JWKS must list every public key in `SSO_JWT_PUBLIC_KEYS` (comma-separated
   file names, for rotation); signing key = `SSO_JWT_PRIVATE_KEY`. Both are resolved in `SSO_JWT_KEYS_MOUNT` >
   `SSO_KEYS_DIR` > `/run/keys` (compose mounts the host `SSO_KEYS_DIR` at `/run/keys`). Deprecated aliases:
   `SSO_JWT_PUBLIC_KEY_PATHS` / `SSO_JWT_PRIVATE_KEY_PATH` (full paths).
7. **Access token audience.** `aud` = `SSO_AUDIENCE`. Refresh tokens also carry `aud`, but services reject them via
   `token_type`.
8. **Revocation is enforced at refresh too.** `/refresh` must reject a refresh token whose `iat` < the user's
   `UserTokenRevocation.revoked_at`, in addition to blacklist checks.
9. **Cookie mode CSRF defence.** For cookie-based `/refresh` and `/logout`, require an `Origin` header that is in
   `CORS_ALLOWED_ORIGINS`; missing or unknown Origin -> `403 {"error":"origin_not_allowed"}` (add this code to
   the §6.0 table). Body-token (native) requests skip this check.
10. **Error handler.** Every error, including 404/405/500 from DRF views, uses the §6.0 shape. Never include
    tokens, passwords or stack traces.
11. **Shared Django tables.** `django_session`, `django_content_type`, `django_admin_log` are shared with myFinance.
    SSO must not run `clearsessions`, `remove_stale_contenttypes`, or any migration that alters existing tables.
    Add a test that asserts `makemigrations --check` shows no changes and that the only migrations SSO owns are in
    apps `sso` and `token_blacklist`.
12. **Settings.** Use `django-environ`. `SSO_DEBUG=False` by default; refuse to start in non-debug mode if
    `SSO_SECRET_KEY` is empty or key files are missing (clear error message).
13. **Logging.** Structured log line per login attempt: username (not password), IP, result. Never log tokens.
14. **Test DB.** Unit tests run on SQLite (`SSO_DB_ENGINE=sqlite` switch); an optional integration run uses a MySQL
    8 container (`docker compose -f docker-compose.test.yml`). Fixtures create users with a PBKDF2 hash in Django
    4.1 format (`pbkdf2_sha256$390000$...`) to prove legacy hashes verify.

## C. Definition of done (sprint 1)
- `pytest` passes with >= 90% line coverage on `sso/`.
- Every test in spec §11 exists and passes.
- `docker compose up` starts the server locally (self-signed TLS ok) and `examples/` work against it.
- README explains setup, key generation, env vars, migrate procedure (with mysqldump backup), and ServiceClient
  registration.

## D. Working location
Code lives in `/workspace/projects/sso-server` on the shared box (git init locally). Do not push anywhere until
Thomas approves and a GitHub login exists.
