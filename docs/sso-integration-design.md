# llm-wiki-svc ↔ SSO-server integration — technical design v1.0

Owner: Philip (team lead). Requirement from Thomas (2026-10-10):
1. Add a login page in llm-wiki-svc that authenticates through the SSO server.
2. Add a custom permission `application.app1` so one central database (SSO / `dcWebUsers`) controls access to
   many applications.
3. llm-wiki-svc becomes the first application that uses the SSO server.

SSO-server reference: branch `sso-server-sprint1` of `Neural-Matrix-LLC/SSO-server` (`docs/SSO-server.md`,
`docs/DESIGN-ADDENDUM-v1.1.md`, README). SSO deployment is ON HOLD; everything here runs locally.

Two repos change. Each gets a feature branch, no pushes until Philip reviews:
- SSO-server: branch `feat/app-permissions` from `sso-server-sprint1`.
- llm-wiki-svc: branch `feat/sso-login` from `main` (already created in /workspace/projects/llm-wiki-svc).

---------------------------------------------------------------------------------------------------------
## Part A — SSO-server: central application permissions

### A1. Permission model
Django permissions are named `<app_label>.<codename>`. To get `application.app1`:
- New Django app with label **`application`** (folder `application/`, no clash with myFinance's
  `main`, `predicts`, `rebalance`, `perfreports`, nor with `sso`).
- One model `ApplicationAccess` used only as the permission anchor:
  ```python
  class ApplicationAccess(models.Model):
      class Meta:
          managed = True              # tiny table, keeps Django happy; never holds rows
          default_permissions = ()    # no add/change/delete/view noise
          permissions = [("app1", "Can use app1 (llm-wiki-svc)")]
          verbose_name = "application access"
  ```
- Further applications are added **without code changes**: management command
  `python manage.py create_app_permission <codename> "<description>"` creates a `Permission` row on the
  `application.applicationaccess` content type (idempotent; codename must match `^[a-z][a-z0-9_]{1,62}$`).
  Also register a filtered admin for these permissions so staff can see them; assigning to users/groups uses
  the stock User/Group admin (user permissions and group permissions both count).
- Migration owned by app `application` (additive: one table + content type + permission). Update the
  migration-ownership test: SSO owns migrations only in `sso`, `application`, `token_blacklist`.

### A2. Token claims
Add to access tokens (and to the `user` object in login/refresh responses, `/me`, and `/introspect`):
```json
"perms": ["application.app1"]
```
- Value = sorted `[p for p in user.get_all_permissions() if p.startswith("application.")]`
  (direct + group permissions; superusers get all `application.*` permissions; inactive users get none).
- Only the `application.*` namespace is exported; the spec rule "no full permissions list" still holds.
- Refresh re-computes `perms`, so a granted/revoked permission takes effect on the next refresh (≤15 min).
  `/introspect` reads them fresh from the DB.
- Docs: update spec §5.1 payload, §6.1 user object, §8.1 step 7 ("authorize with `perms`/`groups`").

### A3. Shared-table risk (document in README)
`django_content_type` / `auth_permission` are shared with myFinance. Running `remove_stale_contenttypes` in
**myFinance** would delete `application.applicationaccess` and cascade-delete every app grant. Add a loud README
warning, and make SSO's post-migrate step recreate missing permissions (grants would still be lost — warn).

### A4. Tests
Permission via user, via group, superuser, inactive; `perms` claim present/absent; refresh picks up a new grant
and drops a revoked one; `/me` and `/introspect` show `perms`; management command idempotent + rejects bad
codenames; migration-ownership test updated. Both Django 5.2 and 4.2, Python 3.13.

---------------------------------------------------------------------------------------------------------
## Part B — llm-wiki-svc: SSO login and permission check

Current state: FastAPI app (`src/llmwiki/api/app.py`, `routes.py`), one static bearer token
`INGEST_API_TOKEN` (`require_token`) on write routes, `/dashboard?token=` for browsers; read routes
(`/search`, `/answer`, `/concepts`, `/page/*`, `GET /domains`, `/worker`, `/sources/*`, `/healthz`) are open.
Callers that cannot do an interactive login: Telegram/email channels (own secrets, unaffected), MCP clients,
scripts (`scripts/*.py`), iOS shortcuts.

### B1. Settings (pydantic-settings in `config.py`, env vars, `.env.example` documented)
| Env | Default | Meaning |
|---|---|---|
| `AUTH_MODE` | `static` | `static` (today's behaviour), `sso`, or `both` (SSO **or** static token accepted) |
| `SSO_BASE_URL` | "" | e.g. `https://sso.example.com` (server-to-server calls) |
| `SSO_ISSUER` | "" | must equal SSO's `iss` |
| `SSO_JWKS_URL` | `${SSO_BASE_URL}/.well-known/jwks.json` | |
| `SSO_AUDIENCE` | `myfin-services` | |
| `SSO_REQUIRED_PERMISSION` | `application.app1` | permission a user needs to use llm-wiki-svc |
| `SESSION_SECRET` | "" (required when AUTH_MODE≠static) | signs the browser session cookie |
| `SESSION_COOKIE_SECURE` | `true` | set false only for local http dev |
| `SSO_PROTECT_READS` | `false` | if true, read routes also need auth (keeps MCP/scripts working by default) |
Fail fast at startup when `AUTH_MODE` is `sso`/`both` and SSO_ISSUER / SSO_BASE_URL / SESSION_SECRET are missing.

### B2. Token verification (`src/llmwiki/auth/sso.py`, new package `llmwiki.auth`)
Port the SSO `examples/verifier` logic: PyJWT (`pyjwt[crypto]`), RS256 only, `iss`/`aud`/`exp`/`iat` checks,
30 s leeway, `token_type == "access"`, JWKS cache 1 h with at most one refetch per 60 s on unknown `kid`.
Return a `Principal(sub, username, email, is_staff, groups, perms, via="sso"|"static")`.
Permission check: `SSO_REQUIRED_PERMISSION in principal.perms`; missing → **403** `{"detail":"forbidden",
"error":"permission_denied"}` (never 401, so clients don't loop on refresh).

### B3. API auth dependency
Replace `require_token` with `require_auth` (same name kept as an alias so routes don't churn):
- `Authorization: Bearer <x>`: if `x` looks like a JWT (3 dot-separated parts) and mode allows SSO → verify
  as SSO token + permission; else if mode allows static → constant-time compare with `INGEST_API_TOKEN`.
- Else, browser session cookie (B4) if present and valid.
- 401 with `WWW-Authenticate: Bearer error="invalid_token"` when missing/invalid.
- Never log tokens (reuse existing `mask()`).
- `AUTH_MODE=static` must behave exactly as today (existing tests unchanged and green).
- When `SSO_PROTECT_READS=true`, read routes get the same dependency; `/healthz` and `/login*` stay public.

### B4. Login page and browser session (server-side, spec §7.3 "server-rendered app")
Chosen because domains/hostnames are undecided: no CORS, no shared-cookie-domain requirement, tokens never
reach browser JavaScript.
- `GET /login?next=/dashboard` → simple HTML form (username-or-email, password), same look as the dashboard,
  with CSRF token (double-submit: random value in a SameSite=Strict cookie + hidden field).
- `POST /login` (form) → server calls `POST {SSO_BASE_URL}/api/v1/auth/login` with `client:"native"`
  (httpx, 10 s timeout) → verifies the returned access token (B2) → checks permission:
  - no permission → page "Your account doesn't have access to llm-wiki (application.app1). Ask an admin."
    (do not create a session; call SSO `/logout` with the refresh token to discard it).
  - success → set session cookie and 303 redirect to `next` (only same-origin relative paths; otherwise `/dashboard`).
  - map SSO errors: `invalid_credentials` → "Wrong username or password", `account_inactive` → "Please activate
    your account…", `rate_limited` → "Too many attempts, try again in N s" (from Retry-After), SSO unreachable →
    "Login service unavailable" (502 page).
- Session cookie `llmwiki_session`: Starlette `SessionMiddleware`-style signed cookie (itsdangerous, key
  `SESSION_SECRET`), HttpOnly, Secure (configurable), SameSite=Lax, Path=/, max-age = refresh lifetime.
  Contents: access token, refresh token, access expiry, username. (Size ≈ 2 KB, under the 4 KB limit; assert in
  tests.) Document that the cookie is signed, not encrypted — it is HttpOnly and only ever sent to this service.
- Per request: if access token expires within 60 s, refresh server-side via SSO `/api/v1/auth/refresh`
  (`{"refresh_token": ...}`), rotate both tokens in the cookie. Refresh failure (401/403) → clear session,
  redirect browser to `/login?next=...` (HTML routes) or 401 (JSON routes).
- `POST /logout` (CSRF-protected) → SSO `/api/v1/auth/logout` with refresh token, clear cookie, redirect `/login`.
- `/dashboard`: accept session (new) or the existing `?token=`/Bearer (static mode/both). In `sso` mode the
  `?token=` query form is disabled (avoid tokens in URLs). Unauthenticated browser → 303 to `/login?next=/dashboard`.
- Show "Signed in as <username> · Log out" on the dashboard.

### B5. Telegram, email, MCP
Channels keep their own webhook secrets (unchanged). MCP and scripts keep using `INGEST_API_TOKEN` in
`both` mode; in `sso` mode they need an SSO access token (scripts: add `--sso` login helper in
`scripts/README.md` showing the native-client flow from spec §7.3). Note in docs; no MCP code change needed.

### B6. Dependencies, compatibility
Add `pyjwt[crypto]>=2.8`, `itsdangerous>=2.1` (already pulled by Starlette? confirm; pin explicitly), use
existing `httpx`. Keep `requires-python >=3.11`; also run the test suite on 3.13 (Thomas is moving to 3.13).

### B7. Tests (pytest, under tests/unit and tests/integration)
Unit (no network): JWT verification with a locally generated RSA key + fake JWKS (valid, expired, wrong iss,
wrong aud, refresh-type token, `alg=none`, HS256 confusion, unknown kid refetch limit); permission present/absent
→ 200/403; `AUTH_MODE` matrix static/sso/both on a protected route; `SSO_PROTECT_READS`; login page render;
login POST success/wrong password/inactive/rate-limited/no-permission/SSO down (SSO mocked with httpx
MockTransport or respx); open-redirect rejection on `next`; CSRF failure; session refresh + rotation; refresh
failure → redirect; logout calls SSO and clears cookie; cookie flags; no tokens in logs.
Integration (QA): real SSO server (gunicorn + SQLite, branch `feat/app-permissions`) + llm-wiki-svc on
dedicated ports, users with and without `application.app1` (direct and via group).

### B8. Definition of done
- Existing llm-wiki-svc tests pass unchanged in `AUTH_MODE=static`.
- New tests pass; SSO-server tests pass on Django 5.2 + 4.2, Python 3.13.
- README/docs: new env vars, how to grant `application.app1`, how to add `app2`, local dev recipe running both
  services, and the shared-content-type warning.
- Nothing pushed; Philip reviews, QA tests, then Philip pushes the two feature branches.
