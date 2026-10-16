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

---------------------------------------------------------------------------------------------------------
## v1.1 changes (Philip, after QA design review 2026-10-10) — these override v1.0 above

1. **MCP is protected (QA D-01).** `/mcp` is mounted outside the router, so wrap the mounted MCP ASGI app in an
   auth middleware using the same rules as `require_auth`: in `sso` mode SSO token + permission; in `both`
   mode SSO token or static token. In `static` mode behaviour is unchanged (still open) but log a WARNING at
   startup ("MCP is unauthenticated in AUTH_MODE=static"). Supersedes "no MCP code change needed".
2. **Server-side sessions (D-02, D-04, D-05, D-13).** Replace the signed-cookie design: cookie
   `llmwiki_session` holds only a random 256-bit session id; tokens live server-side in SQLite
   (`SESSION_DB_PATH`, default `<data dir>/sessions.sqlite3`), columns: id hash (SHA-256), username, sub,
   access, refresh, access_exp, csrf, created_at, last_seen. Logout and refresh failure delete the row.
   Absolute lifetime `SESSION_MAX_AGE_HOURS` (default 168); no sliding beyond it. Prune expired rows on start
   and hourly.
   Refresh race: a per-session lock (process-local asyncio lock + `BEGIN IMMEDIATE` row update) so only one
   refresh runs; concurrent requests wait and reuse the new access token. Document that multiple uvicorn
   workers share the SQLite file, so the DB transaction is the real guard.
3. **CSRF on cookie writes (D-06, Q-04).** Any non-GET request authenticated by the session cookie must send
   `X-CSRF-Token` equal to the session's csrf value (exposed to the dashboard page in a meta tag); forms use a
   hidden field. Bearer-authenticated requests are exempt.
4. **Per-user throttling at SSO (D-03).** SSO-server: `/api/v1/auth/login` and `/refresh` accept HTTP Basic auth
   from a registered, active `ServiceClient` plus a JSON field `client_ip`; only then the IP throttle and login log
   use `client_ip` (validated as an IP) instead of the caller address. Without valid Basic auth the field is
   ignored. llm-wiki gets `SSO_CLIENT_ID` / `SSO_CLIENT_SECRET` (required in sso/both mode) and sends the
   browser's IP. Per-username throttle unchanged.
5. **Static mode is byte-for-byte unchanged (D-07, D-08, Q-01).** In `static` mode: no `/login`/`/logout` routes
   (404), same 401 bodies and headers as today, `SSO_PROTECT_READS` still applies (requires the static token).
   Revert edits to existing tests (e.g. tests/unit/test_layering.py) unless a test is genuinely wrong — then
   explain it in the report.
6. **Static token fallback in `both` mode (D-09, Q-16).** Try SSO verification when the bearer parses as a JWT;
   if verification fails, fall back to the constant-time static compare. In `sso`/`both` mode refuse to start if
   `INGEST_API_TOKEN` is `changeme` or shorter than 24 chars; in `static` mode only warn.
7. **Session edge cases.** SSO unreachable/5xx during refresh: keep the session; if the access token is still
   valid continue, else 503 "Login service unavailable" (HTML) / 503 JSON — do not clear the session (Q-05).
   Refresh that no longer carries the permission → delete session, 403 page (Q-06). HTML route with an invalid
   explicit Bearer → 401; no credentials at all → 303 to `/login` (Q-07).
8. **SSO claim details.** `perms` is always present, `[]` when none (Q-11). ~~Superusers get every
   `application.*` permission (default true)~~ — SUPERSEDED 2026-10-11 by Thomas: superusers administer
   dcWebUsers only and get no automatic app access; `SSO_SUPERUSER_ALL_APPS` defaults to **false**. Post-migrate
   recreates only code-defined permissions (app1); command-created ones are documented (Q-13).
9. `SESSION_SECRET` is no longer needed (server-side sessions); drop it. Grant revocation can take up to the
   access lifetime (15 min) — documented, accepted (D-10).

### v1.2 clarifications (Philip, 2026-10-10, after QA plan v1.1)
- Session DB file mode 0600, its directory 0700 if created by us; refuse to start if the file is group/world-readable (D-16).
- Client IP (C-11/Q-25): `CLIENT_IP_HEADER` (default empty = peer address; e.g. `cf-connecting-ip` or `x-forwarded-for`)
  is honoured only when the peer is in `TRUSTED_PROXY_IPS` (CIDR list). Document cloudflared + uvicorn `--proxy-headers`.
- `static` + `SSO_PROTECT_READS=true` also requires the static token on `/mcp` (C-12).
- CSRF applies to POST/PUT/PATCH/DELETE only (C-13); failure → 403 `{"error":"csrf_failed"}` (Q-30).
- SSO unreachable → 503 everywhere, login included (C-14).
- Wrong service credentials: SSO answers 401 `invalid_client` (no silent fallback); llm-wiki logs an error and shows
  "Login service misconfigured" 503 (C-19). Leaked secret risk accepted; per-username throttle still applies; rotate via admin (C-18).
- Invalid `client_ip` with valid service credentials → 400 `invalid_request` (Q-28).
- Cookie Max-Age = remaining absolute lifetime (Q-26). Idle timeout `SESSION_IDLE_HOURS` default 12 (Q-27).
- An invalid explicit Bearer → 401 even if a valid cookie is present (Q-31). Missing `kid` → reject (Q-14).

### Implementation notes (Developer, 2026-10-10, after QA round 1) — descriptive, not new decisions
- `/mcp` accepts a Bearer token only (an SSO access token with the permission; the static token in `both`, and in
  `static` + `SSO_PROTECT_READS=true`). The `llmwiki_session` cookie is never accepted there, so `/mcp` has no
  CSRF surface (a browser cannot attach an `Authorization` header cross-site). QA open question 9.
- `last_seen` is written at most once a minute (to avoid a write per request), so the `SESSION_IDLE_HOURS` idle
  timeout can be off by up to 60 s. The absolute lifetime (`created_at`) is exact.
- `GET /login` while already signed in answers 303 to the sanitised `next` (default `/dashboard`; off-site or
  unsafe `next` values fall back to `/dashboard`) instead of showing the form (Q-08).
- A failed re-login (wrong password, no permission, unknown user, SSO error) keeps the existing session: the
  session row and cookie are untouched (Q-10).
- A successful login while a session cookie is present rotates the session: the old row is deleted, a new
  session id, cookie and CSRF value are issued, and the old refresh token is logged out at the SSO best effort
  (a failure or SSO outage is logged and does not block the login). The old cookie stops working at once.
- `Cache-Control: no-store` on every `/login`, `/logout` and `/dashboard` response in `sso`/`both` (Q-20); not in
  `static`, whose `/dashboard` stays byte-for-byte unchanged.

### Superusers and app access (decision relayed by Philip, 2026-10-11) — overrides v1.1 item 8's default
- Superusers are for administering `dcWebUsers`, not for automatic app access. `SSO_SUPERUSER_ALL_APPS` now
  defaults to **false**; the flag is kept (the design never said to remove it) as an explicit opt-in to the old rule.
- `perms` (tokens, `/me`, `/introspect`, the login `user` object) is computed from real permission rows: the user's
  `user_permissions` plus their groups' permissions, filtered to the `application` app. This replaces A2's
  `get_all_permissions()` formula, which (like `has_perm()`) returns everything for a superuser; no app-access
  check uses either. Normal users get the same result as before; inactive users still get `[]`.
