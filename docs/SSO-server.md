# SSO-server.md — Single Sign-On Server for myFinance and related apps

> Status: design spec. Implemented in a **new repository** (suggested name `sso-server`), not in `myFinance`.
> Audience: the developer building the SSO server, developers building front-ends that log in through it, and
> developers building back-end services that accept its tokens.

## 1. Goals

1. One login service for every app (myFinance, rebalance, future UIs and APIs).
2. Reuse Django's user management (password hashing, `is_active`, groups, admin) on the **existing**
   `dcWebUsers` MySQL database. **Every existing user keeps working with their current password.**
3. A REST API for login, refresh, logout and "who am I".
4. A token protocol: front-end logs in at the SSO server → gets a token → sends it to any back-end service.
5. Back-end services verify tokens **locally** with the SSO server's public key; they need no shared secret and
   no call per request.

Non-goals for v1: social login, MFA, multi-tenant orgs. They can be added later without changing the token format.

## 2. Protocol in one picture

```
 ┌──────────┐ 1. POST /api/v1/auth/login  {username,password}   ┌────────────┐
 │ Front-end│ ─────────────────────────────────────────────────▶│ SSO server │──▶ MySQL dcWebUsers
 │ (SPA/app)│ ◀──────── 2. {access_token (JWT, 15 min),          │  (Django)  │     (auth_user …)
 └────┬─────┘              refresh_token (7 days)}               └─────┬──────┘
      │ 3. GET /api/... Authorization: Bearer <access_token>           │ publishes public keys
      ▼                                                                ▼ GET /.well-known/jwks.json
 ┌──────────────┐ 4. verify JWT signature + iss/aud/exp with cached JWKS
 │ Back-end svc │ ─── no call to SSO per request ───
 └──────────────┘
 5. access token expires → front-end POST /api/v1/auth/refresh → new pair (refresh token rotates)
 6. logout → POST /api/v1/auth/logout → refresh token blacklisted
```

- **Access token**: JWT signed **RS256** (private key only on the SSO server), 15-minute lifetime.
- **Refresh token**: JWT, 7-day lifetime, **rotated** on each use, old one blacklisted. Only the SSO server accepts it.
- **Public keys**: served as JWKS so services can verify, and so keys can rotate without redeploying services.

Optional phase 2 adds a hosted login page with an authorization-code + PKCE redirect flow (§6.8), so a
user signed in to one app is signed in to the others without typing their password again.

## 3. Technology

| Item | Choice |
|---|---|
| Language/runtime | Python 3.12 |
| Framework | Django 5.2 LTS + Django REST Framework 3.15+ |
| Tokens | `djangorestframework-simplejwt` (RS256, rotation, blacklist) + `cryptography` |
| DB driver | `mysqlclient` (needs `build-essential pkg-config default-libmysqlclient-dev` to build) |
| CORS | `django-cors-headers` |
| Rate limiting | DRF throttling (`ScopedRateThrottle`) |
| Server | gunicorn behind nginx, Docker Compose, **HTTPS only** |
| Tests | pytest + pytest-django |

## 4. Reusing the existing users (`dcWebUsers`)

The users live in tables Django already created in `dcWebUsers`: `auth_user`, `auth_group`, `auth_user_groups`,
`auth_permission`, `django_session`, `django_content_type`, `django_admin_log`, `django_migrations`.

Rules:

1. **Use the stock user model.** Do *not* set `AUTH_USER_MODEL` and do not add a custom user model — myFinance
   uses `django.contrib.auth.models.User`, and the two projects share the same `auth_user` table.
2. **Point `DATABASES['default']` at `dcWebUsers`.** One database is enough; no router is needed.
3. **Keep the default password hasher order** (`PBKDF2PasswordHasher` first). Django 5.2 verifies the existing
   PBKDF2 hashes and, on login, re-hashes with more iterations; Django 4.1 (myFinance) can still verify those,
   because the iteration count is stored in the hash. Do **not** put Argon2/bcrypt first unless myFinance gets
   the same hasher, or myFinance logins will break for users who logged in via SSO.
4. **Migrations are additive only.** `auth`, `contenttypes`, `sessions` and `admin` migrations are already
   recorded in `django_migrations` (Django 5.2 adds no new `auth` migrations after 0012), so `migrate` is a no-op
   for them. It only creates the new tables: simplejwt's `token_blacklist_*` and this project's own app tables.
5. **Name the project's app `sso`** (not `main`, `predicts`, `rebalance` or `perfreports`): `django_migrations` is
   shared with myFinance, and a clashing app label would confuse both projects' migration state.
6. **Back up first**: `mysqldump dcWebUsers > dcWebUsers-pre-sso.sql` before the first `migrate`.
7. `is_active=False` users (registered but not email-activated) **cannot log in**, same as myFinance today.
8. `SECRET_KEY` does not need to match myFinance. Password hashes do not depend on it; it only signs sessions,
   CSRF and activation/reset links of the project that issues them.
9. Use a dedicated MySQL account for the SSO server with `SELECT, INSERT, UPDATE, DELETE` on `dcWebUsers`, plus
   `CREATE, ALTER, INDEX, REFERENCES` only while running migrations.

Verification that users are kept: before and after deploying, run `SELECT COUNT(*) FROM auth_user;`, and log in
through both myFinance and the SSO API with an existing account.

## 5. Token format

### 5.1 Access token (JWT, RS256)

Header: `{"alg":"RS256","typ":"JWT","kid":"<key id>"}`

Payload:

```json
{
  "iss": "https://sso.thomas-choi.com",
  "aud": "myfin-services",
  "sub": "42",
  "token_type": "access",
  "jti": "5f0c…",
  "iat": 1760000000,
  "exp": 1760000900,
  "username": "thomas",
  "email": "thomas@example.com",
  "is_staff": false,
  "groups": ["trader", "beta"],
  "perms": ["application.app1"]
}
```

- `sub` is `auth_user.id` as a string. Services should key their data on `sub`, not `username`.
- `groups` are Django group names. **Authorization uses groups**: a service decides what a group may do.
- `perms` (v1.1, docs/sso-integration-design.md A2): the user's `application.*` permissions only (direct + via
  groups; superusers only their explicit grants too, unless `SSO_SUPERUSER_ALL_APPS=true`; inactive users none),
  sorted, always present (`[]` when none). Login/refresh also accept ServiceClient Basic auth + `client_ip`
  for server-side callers (README §6a). An app checks its own permission,
  e.g. `application.app1`. Recomputed on every refresh.
- Keep the token small: no full permissions list (only `application.*`), no personal data beyond the above.

### 5.2 Refresh token
JWT with `token_type: "refresh"`, 7-day `exp`, its own `jti`. Services must **reject** refresh tokens; only
`/api/v1/auth/refresh` and `/api/v1/auth/logout` accept them.

### 5.3 Keys
- RSA 2048 (or 3072) key pair. Private key in a file mounted into the container: the host folder
  `SSO_KEYS_DIR` is mounted read-only at `/run/keys`, and `SSO_JWT_PRIVATE_KEY` names the file in it
  (resolved in `SSO_JWT_KEYS_MOUNT` > `SSO_KEYS_DIR` > `/run/keys`). Never in git and never in the image.
  (Deprecated alias: `SSO_JWT_PRIVATE_KEY_PATH`, a full path.)
- `kid` = first 16 hex characters of the SHA-256 of the public key's DER encoding.
- **Rotation**: generate the new key, publish *both* public keys in JWKS, wait 24 h (longer than JWKS cache
  time), switch signing to the new key, keep the old public key published for 15 min + refresh lifetime, then
  remove it.

### 5.4 Lifetimes (configurable via env)
| Token | Default | Env var |
|---|---|---|
| Access | 15 min | `SSO_ACCESS_TTL_MIN` |
| Refresh | 7 days | `SSO_REFRESH_TTL_DAYS` |
| Auth code (phase 2) | 60 s | `SSO_CODE_TTL_SEC` |

## 6. SSO server REST API

Base URL: `https://sso.thomas-choi.com` (example). All bodies are JSON. All endpoints require HTTPS.

### 6.0 Error format (every endpoint)
```json
{ "error": "invalid_credentials", "detail": "Username or password is incorrect." }
```

| HTTP | `error` | Meaning |
|---|---|---|
| 400 | `invalid_request` | Missing/malformed fields |
| 401 | `invalid_credentials` | Wrong username or password (same message for unknown user — don't leak existence) |
| 401 | `token_invalid` | Token bad, expired, wrong type, or blacklisted |
| 403 | `account_inactive` | User exists but `is_active = false` (not email-activated or disabled) |
| 429 | `rate_limited` | Too many attempts; `Retry-After` header set |

### 6.1 `POST /api/v1/auth/login`
Request:
```json
{ "username": "thomas", "password": "…", "client": "browser" }
```
`client` is `"browser"` (default) or `"native"` (scripts, mobile apps, server-side callers).

Response `200`:
```json
{
  "access_token": "eyJ…",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJ…",
  "user": { "id": 42, "username": "thomas", "email": "…", "first_name": "…", "last_name": "…",
            "is_staff": false, "groups": ["trader"], "perms": ["application.app1"] }
}
```
- `client: "browser"`: `refresh_token` is **omitted from the body**. The server sets it as a cookie instead:
  `sso_refresh=<token>; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/; Max-Age=604800;
  Domain=<SSO_COOKIE_DOMAIN>`.
- `client: "native"`: `refresh_token` comes in the body, and no cookie is set.
- Implementation: `django.contrib.auth.authenticate()`, then reject inactive users. Update `last_login` (the
  `user_logged_in` signal does this). Throttle scope `login`: 10/min per IP plus 5/min per username.
- Users may log in by **email** as well as username: if `username` contains `@`, look up by `email`
  (case-insensitive). If several users share that email, reject with `invalid_credentials`.

### 6.2 `POST /api/v1/auth/refresh`
Request (native): `{ "refresh_token": "eyJ…" }`. Request (browser): empty body, with the cookie sent
(`credentials: "include"`).
Response `200`: same shape as login (new access token; new refresh token in the body or cookie). The old refresh
token is blacklisted (`ROTATE_REFRESH_TOKENS=True`, `BLACKLIST_AFTER_ROTATION=True`).
Also re-check `is_active`. A disabled user's refresh fails with `403 account_inactive`.

### 6.3 `POST /api/v1/auth/logout`
Same input as refresh. Blacklists the refresh token and clears the cookie. Response `204`.
Access tokens already issued stay valid until they expire (≤15 min). Services needing instant revocation use §6.6.

### 6.4 `POST /api/v1/auth/logout-all` (Bearer access token)
Blacklists all outstanding refresh tokens for the user (`OutstandingToken` → `BlacklistedToken`). Response `204`.

### 6.5 `GET /api/v1/auth/me` (Bearer access token)
Returns the `user` object from §6.1, read fresh from the DB.

### 6.6 `POST /api/v1/auth/introspect` (service-authenticated)
For services that need revocation or freshness checks (e.g. admin actions). Auth: HTTP Basic with a registered
service's `client_id:client_secret` (§9 `ServiceClient`).
Request `{ "token": "eyJ…" }` → `200 { "active": true, "sub": "42", "username": "thomas", "groups": [...],
"perms": [...], "exp": 1760000900 }` (`perms` read fresh from the DB), or `{ "active": false }`. `active` is false if the signature, expiry or type is bad, the
user is inactive, or the user's tokens were revoked after `iat` (`sso.UserTokenRevocation.revoked_at`, which
`logout-all` and password changes set).

### 6.7 Discovery and keys
- `GET /.well-known/jwks.json` → `{"keys":[{"kty":"RSA","kid":"…","use":"sig","alg":"RS256","n":"…","e":"AQAB"}]}`.
  Sent with `Cache-Control: public, max-age=3600`.
- `GET /.well-known/openid-configuration` → minimal document: `issuer`, `jwks_uri`, `token_endpoint`
  (`/api/v1/auth/token`), `authorization_endpoint` (`/sso/authorize`, phase 2),
  `id_token_signing_alg_values_supported: ["RS256"]`. Standard JWT libraries can then auto-configure.
- `GET /healthz` → `200 {"status":"ok"}` (checks DB connectivity).

### 6.8 Phase 2 — hosted login and cross-app SSO (authorization code + PKCE)
Use this when apps live on different domains, or when users should sign in once for all apps.
1. App redirects the browser to
   `GET /sso/authorize?client_id=myfin-web&redirect_uri=https://fin.thomas-choi.com/auth/callback&response_type=code&state=<random>&code_challenge=<S256(verifier)>&code_challenge_method=S256`.
2. If the browser has no SSO Django session, the SSO server shows its own login page (a Django template; it
   reuses `AuthenticationForm`). With a session, it skips the login page. This is the "single" in single sign-on.
3. SSO redirects to `redirect_uri?code=<one-time code>&state=<same>`. `redirect_uri` must exactly match one
   registered for that client.
4. App calls `POST /api/v1/auth/token` with
   `{ "grant_type":"authorization_code", "code":"…", "code_verifier":"…", "client_id":"myfin-web", "redirect_uri":"…" }`
   and gets the same response as login.
5. `GET /sso/logout?post_logout_redirect_uri=…` ends the SSO session and redirects.

Codes are single-use, 60 s TTL, stored hashed in `sso.AuthorizationCode`.

### 6.9 Optional account endpoints (phase 2)
`POST /api/v1/account/register` (sends the same activation email flow as myFinance: user `is_active=False` until
`GET /api/v1/account/activate/<uidb64>/<token>`), `POST /api/v1/account/password/change` (Bearer),
`POST /api/v1/account/password/reset` and `/password/reset/confirm`. Reuse Django's `PasswordResetTokenGenerator`
and `password_validation`. A password change sets `UserTokenRevocation`.

## 7. Front-end integration guide

### 7.1 Rules
- **Access token is kept in memory only** (a JS variable or state store). Never put it in `localStorage`.
- **Browser apps** use `client: "browser"`. The refresh token lives in an HttpOnly cookie that JS cannot read, and
  every call to `/api/v1/auth/*` uses `credentials: "include"`.
- **Native apps/scripts** use `client: "native"` and store the refresh token in the OS secure store (Keychain or
  Keystore) or a file with mode 0600.
- Send the token to services as `Authorization: Bearer <access_token>`.
- On page load, call `/refresh` silently. If it succeeds, the user is still logged in, and no login form is needed.
- Refresh ~60 s before `expires_in` runs out, or on the first `401 token_invalid` from a service, then retry once.
- Your app's origin must be listed in the SSO server's `SSO_CORS_ALLOWED_ORIGINS`. Ask the SSO admin to add it.
- For the cookie to work across apps, apps and SSO must be same-site (e.g. `*.thomas-choi.com`). Otherwise use
  the phase 2 redirect flow (§6.8).

### 7.2 Reference client (vanilla JS, works in any framework)
```js
// auth.js
const SSO = "https://sso.thomas-choi.com";
let accessToken = null, refreshTimer = null, user = null;

async function call(path, body) {
  const r = await fetch(SSO + path, {
    method: "POST", credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const data = r.status === 204 ? {} : await r.json();
  if (!r.ok) throw Object.assign(new Error(data.detail || r.statusText), { code: data.error, status: r.status });
  return data;
}

function accept(data) {
  accessToken = data.access_token; user = data.user;
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => refresh().catch(() => {}), (data.expires_in - 60) * 1000);
  return user;
}

export const login   = (username, password) => call("/api/v1/auth/login", { username, password, client: "browser" }).then(accept);
export const refresh = () => call("/api/v1/auth/refresh").then(accept);
export async function logout() {
  clearTimeout(refreshTimer); accessToken = null; user = null;
  await call("/api/v1/auth/logout").catch(() => {});
}
export const currentUser = () => user;

// Use this for every call to a back-end service.
export async function apiFetch(url, opts = {}) {
  const go = () => fetch(url, { ...opts, headers: { ...opts.headers, Authorization: `Bearer ${accessToken}` } });
  let r = await go();
  if (r.status === 401) {               // expired: refresh once and retry
    try { await refresh(); } catch { await logout(); throw new Error("login_required"); }
    r = await go();
  }
  return r;
}

// On app start:
export const restoreSession = () => refresh().catch(() => null); // null => show login form
```

Usage:
```js
await restoreSession() ?? showLoginForm();
await login(form.username.value, form.password.value);   // catch: e.code === "invalid_credentials" | "account_inactive" | "rate_limited"
const res = await apiFetch("https://api.thomas-choi.com/rebalance/portfolio");
```

### 7.3 Other client types
- **Server-rendered app (e.g. Django/Flask)**: call `/login` server-side with `client: "native"`, store both
  tokens in the app's own server session, and call services with the access token. The browser never sees the
  tokens.
- **Python script / cron job**:
  ```python
  import requests
  t = requests.post(f"{SSO}/api/v1/auth/login", json={"username": u, "password": p, "client": "native"}).json()
  requests.get(f"{API}/rebalance/portfolio", headers={"Authorization": f"Bearer {t['access_token']}"})
  # refresh: requests.post(f"{SSO}/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
  ```
- **Phase 2 redirect flow**: use any standard OIDC/OAuth PKCE library (`oidc-client-ts`, `react-oidc-context`,
  AppAuth on mobile), configured with the discovery URL from §6.7 and your registered `client_id`.

### 7.4 UI checklist
Login form (username-or-email, password). Map the errors: `invalid_credentials` → "Wrong username or password",
`account_inactive` → "Please activate your account from the email we sent", `rate_limited` → "Too many attempts,
try again in N s". Also: a logout button, a silent restore on load, and a redirect to login on `login_required`.

## 8. Back-end service integration guide

### 8.1 Verification checklist (every request)
1. Read `Authorization: Bearer <token>`. If it is missing → `401`.
2. Verify the **RS256 signature** with the key from JWKS whose `kid` matches the header. Accept **only** `RS256`,
   never `none` and never HS*.
3. `iss` == `SSO_ISSUER` exactly.
4. `aud` contains `myfin-services` (or your configured audience).
5. `exp` is in the future and `iat` is not in the future (allow 30 s clock skew).
6. `token_type` == `"access"`.
7. Authorize with `perms` / `groups` / `is_staff`: e.g. the app's own `application.<codename>` permission in
   `perms`, then groups for finer rules. If not allowed → `403` (never 401, so clients don't loop on refresh).
8. Optional, for sensitive operations: call `/api/v1/auth/introspect` (§6.6) to get revocation-aware status.

JWKS caching: fetch on start-up, cache for 1 h, and on an unknown `kid` re-fetch once (rate-limited to once per
minute). Services never need the private key or any SSO DB access.

Service configuration (env):
```
SSO_ISSUER=https://sso.thomas-choi.com
SSO_JWKS_URL=https://sso.thomas-choi.com/.well-known/jwks.json
SSO_AUDIENCE=myfin-services
```

### 8.2 Python (any framework) — PyJWT
```python
import os, jwt
from jwt import PyJWKClient

_jwks = PyJWKClient(os.environ["SSO_JWKS_URL"], cache_keys=True, lifespan=3600)

def verify_access_token(token: str) -> dict:
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"],
                        audience=os.environ["SSO_AUDIENCE"], issuer=os.environ["SSO_ISSUER"],
                        leeway=30, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
    if claims.get("token_type") != "access":
        raise jwt.InvalidTokenError("not an access token")
    return claims
```

### 8.3 Django / DRF service (e.g. myFinance `rebalance` exposed as an API)
```python
# sso_auth.py
from types import SimpleNamespace
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
import jwt
from .jwt_verify import verify_access_token   # §8.2

class SSOUser(SimpleNamespace):
    is_authenticated = True
    def in_group(self, g): return g in self.groups

class SSOJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        parts = get_authorization_header(request).split()
        if len(parts) != 2 or parts[0].lower() != b"bearer":
            return None
        try:
            c = verify_access_token(parts[1].decode())
        except jwt.PyJWTError as e:
            raise AuthenticationFailed(f"token_invalid: {e}")
        return SSOUser(id=int(c["sub"]), username=c["username"], email=c.get("email"),
                       is_staff=c.get("is_staff", False), groups=c.get("groups", [])), c
    def authenticate_header(self, request):
        return 'Bearer realm="api"'
```
In settings: `REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["yourapp.sso_auth.SSOJWTAuthentication"],
"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}`.
A Django service that shares `dcWebUsers` (like myFinance) may instead map `sub` to `User.objects.get(pk=...)`
to get a real `User`.

### 8.4 FastAPI
```python
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
bearer = HTTPBearer()

def current_user(cred: HTTPAuthorizationCredentials = Security(bearer)) -> dict:
    try:
        return verify_access_token(cred.credentials)
    except Exception:
        raise HTTPException(401, "token_invalid", headers={"WWW-Authenticate": "Bearer"})

def require_group(g: str):
    def dep(u: dict = Depends(current_user)):
        if g not in u.get("groups", []): raise HTTPException(403, "forbidden")
        return u
    return dep
```

### 8.5 Node.js — `jose`
```js
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL(process.env.SSO_JWKS_URL));
export async function verify(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: process.env.SSO_ISSUER, audience: process.env.SSO_AUDIENCE,
    algorithms: ["RS256"], clockTolerance: 30 });
  if (payload.token_type !== "access") throw new Error("not an access token");
  return payload;
}
```

### 8.6 Service responses
`401` + `WWW-Authenticate: Bearer error="invalid_token"` for missing, invalid or expired tokens (the front-end
then refreshes). `403` for a valid token without the right group (the front-end does **not** refresh).
Services must allow CORS from the front-end origins and allow the `Authorization` header.

## 9. SSO server internals (for the implementer)

### 9.1 Repo layout
```
sso-server/
├── manage.py
├── ssoproject/  settings.py  urls.py  wsgi.py
├── sso/                         # the only app (label "sso")
│   ├── models.py                # ServiceClient, UserTokenRevocation, AuthorizationCode (phase 2)
│   ├── tokens.py                # custom simplejwt token classes adding claims, kid header
│   ├── serializers.py           # LoginSerializer (username-or-email), UserSerializer
│   ├── views.py                 # login/refresh/logout/logout-all/me/introspect/jwks/discovery/healthz
│   ├── throttles.py             # per-username login throttle
│   ├── admin.py                 # ServiceClient admin
│   ├── templates/sso/login.html # phase 2 hosted login
│   └── tests/                   # pytest
├── keys/                        # gitignored (SSO_KEYS_DIR); <name>.private.pem / .public.pem, mounted at /run/keys
├── scripts/gen_keys.sh          # openssl genrsa / rsa -pubout
├── Dockerfile  docker-compose.yml  docker/nginx.conf
├── requirements.txt  .env.example  README.md
```

### 9.2 Models (all new tables, created by `migrate`)
- `ServiceClient`: `client_id` (unique slug), `name`, `client_secret_hash` (Django `make_password`),
  `redirect_uris` (JSON list, phase 2), `allowed_origins` (JSON list), `is_active`, `created`. Registered in the
  admin and used by introspect and by phase 2.
- `UserTokenRevocation`: `user` (OneToOne `auth.User`), `revoked_at`. Any access token with `iat < revoked_at`
  is reported inactive by introspect, and refresh is refused.
- `AuthorizationCode` (phase 2): `code_hash`, `client`, `user`, `redirect_uri`, `code_challenge`, `expires_at`, `used`.

### 9.3 Key settings
```python
INSTALLED_APPS = [..., "rest_framework", "rest_framework_simplejwt.token_blacklist", "corsheaders", "sso"]
DATABASES = {"default": {"ENGINE": "django.db.backends.mysql", "NAME": "dcWebUsers",
    "HOST": env("SSO_DBHOST"), "PORT": env("SSO_DBPORT"), "USER": env("SSO_DBUSER"), "PASSWORD": env("SSO_DBPWD"),
    "OPTIONS": {"charset": "utf8mb4"}}}
SIMPLE_JWT = {
    "ALGORITHM": "RS256",
    # key_path(): file name joined to the keys mount (SSO_JWT_KEYS_MOUNT > SSO_KEYS_DIR > /run/keys);
    # implemented by sso.keys.resolve_key_config
    "SIGNING_KEY": open(key_path(env("SSO_JWT_PRIVATE_KEY"))).read(),
    "VERIFYING_KEY": open(key_path(env.list("SSO_JWT_PUBLIC_KEYS")[0])).read(),  # all of them go into JWKS
    "ISSUER": env("SSO_ISSUER"), "AUDIENCE": env("SSO_AUDIENCE", "myfin-services"),
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(env("SSO_ACCESS_TTL_MIN", 15))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(env("SSO_REFRESH_TTL_DAYS", 7))),
    "ROTATE_REFRESH_TOKENS": True, "BLACKLIST_AFTER_ROTATION": True, "UPDATE_LAST_LOGIN": True,
    "USER_ID_CLAIM": "sub", "USER_ID_FIELD": "id", "TOKEN_TYPE_CLAIM": "token_type", "LEEWAY": 30,
}
REST_FRAMEWORK = {"DEFAULT_THROTTLE_RATES": {"login": "10/min", "login_user": "5/min", "refresh": "60/min"},
                  "EXCEPTION_HANDLER": "sso.views.error_handler"}   # produces the §6.0 shape
CORS_ALLOWED_ORIGINS = env_list("SSO_CORS_ALLOWED_ORIGINS"); CORS_ALLOW_CREDENTIALS = True
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = True; SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
# PASSWORD_HASHERS: leave Django's default (PBKDF2 first) — see §4.3
```
Custom claims: subclass `RefreshToken.for_user` (in `tokens.py`) to add `username`, `email`, `is_staff` and
`groups`, and set the `kid` header (override `TokenBackend.encode` or pass `headers={"kid": KID}`).
The JSON API views are token-based, so they are CSRF-exempt. The cookie-mode `/refresh` and `/logout` must also
check the `Origin` header against `CORS_ALLOWED_ORIGINS` (CSRF defence for the cookie).

### 9.4 `.env.example`
```
SSO_SECRET_KEY=           SSO_DEBUG=False
SSO_ALLOWED_HOSTS=sso.thomas-choi.com
SSO_DBHOST=  SSO_DBPORT=3306  SSO_DBUSER=  SSO_DBPWD=
SSO_ISSUER=https://sso.thomas-choi.com
SSO_AUDIENCE=myfin-services
SSO_KEYS_DIR=./keys                       # host folder, mounted ro at /run/keys
SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem   # file names in the mount (SSO_JWT_KEYS_MOUNT, compose: /run/keys)
SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem    # comma list (rotation)
# deprecated aliases: SSO_JWT_PRIVATE_KEY_PATH / SSO_JWT_PUBLIC_KEY_PATHS (full paths)
SSO_ACCESS_TTL_MIN=15  SSO_REFRESH_TTL_DAYS=7
SSO_CORS_ALLOWED_ORIGINS=https://fin.thomas-choi.com
SSO_COOKIE_DOMAIN=.thomas-choi.com
E_HOST=  E_PORT=  EMAIL_USER=  EMAIL_PWD=     # phase 2 account emails
```

### 9.5 Deployment
Docker Compose with `web` (gunicorn, 3 workers) and `nginx` (TLS termination, `proxy_set_header Host $http_host`,
`X-Forwarded-Proto`). Keys are mounted read-only at `/run/keys`. There is no DB container: MySQL is remote, as
for myFinance. First deploy: `mysqldump` backup, then `docker compose run --rm web python manage.py migrate`,
`createsuperuser` only if needed (existing staff users already work for `/admin/`), and register `ServiceClient`s.

### 9.6 Security checklist
HTTPS everywhere. RS256 only. Short access TTL. Refresh rotation + blacklist. Login throttling. Generic
credential errors. Never log tokens or passwords. Private key `chmod 600`, outside git. Admin at a non-default
path. Run `python manage.py flushexpiredtokens` daily (cron) to prune the blacklist tables.

## 10. Implementation phases

| Phase | Deliverable | Done when |
|---|---|---|
| 1 | Project skeleton, DB on `dcWebUsers`, keys, `/login` `/refresh` `/logout` `/me` `/jwks.json` `/healthz` | An existing myFinance user logs in through the API, and the token verifies with §8.2 code |
| 2 | Browser cookie mode, CORS, throttling, error format, `logout-all`, introspect, `ServiceClient` admin | The §7.2 client works from a test page on an allowed origin |
| 3 | Docker/nginx/TLS deployment, key rotation runbook, `flushexpiredtokens` cron | Running at `https://sso…` |
| 4 | First consumer: a myFinance/rebalance API secured with §8.3 | Front-end → SSO → API works end to end |
| 5 (opt.) | Hosted login + auth-code/PKCE (§6.8), account endpoints (§6.9) | Login in app A gives silent login in app B |

## 11. Tests (pytest-django, in the new repo)
Use a test MySQL DB (or SQLite for unit tests) and create users with `make_password` in **Django 4.1 PBKDF2 format**
to prove that legacy hashes work. Cover: login ok / wrong password / unknown user / inactive user / email login /
throttling; refresh rotation (old token rejected on reuse); logout blacklists; `logout-all` and introspect after
revocation; access token rejected at `/refresh`; refresh token rejected by §8.2 verifier; JWKS `kid` matches the
token header; `expired` and `wrong aud/iss` rejected; cookie mode sets HttpOnly/Secure and checks Origin.

Manual end-to-end:
```bash
curl -s -X POST https://sso.thomas-choi.com/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"thomas","password":"…","client":"native"}' | jq
curl -s https://sso.thomas-choi.com/api/v1/auth/me -H "Authorization: Bearer $ACCESS" | jq
curl -s https://sso.thomas-choi.com/.well-known/jwks.json | jq
```
Then log in to myFinance with the same account, to confirm the two projects share the user table without breaking it.
