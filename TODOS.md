# TODOS — future-phase and not-planned items

Agreed scope for v1.2a / v1.2b / v1.3c is in [docs/DESIGN-v1.2-requirements.md](docs/DESIGN-v1.2-requirements.md)
(decisions of 2026-10-13). Everything below is **out of that scope**. Known as-built gaps are listed in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §12.

## Future phase (wanted, not scheduled)

- [ ] **Online sign-up** — `POST /api/v1/account/signup` + `activate`. Open: open vs. invite/approval only; email provider for activation mail.
- [ ] **Password change** — `POST /api/v1/account/password/change` (Bearer + old/new; revokes all tokens, returns a fresh pair).
- [ ] **Password reset** — `password/reset` + `reset/confirm` (same 204 for unknown addresses; revokes all tokens).
- [ ] **Hosted login page + authorization-code flow with PKCE** (uses `ServiceClient.redirect_uris`; adds `authorization_endpoint` to discovery).
- [ ] **Client push notifications (SSE or WebSocket)** — only if clients need proactive "token expired/revoked" messages; today clients learn by rejection (401). Services already get signed webhooks (v1.3c).
- [ ] **Cross-tab refresh coordination in the browser helper** (BroadcastChannel / Web Locks) so the losing tab is not logged out.
- [ ] **Hosted self-service account page** (profile, active sessions list, "log out this session").
- [ ] **Webhook admin tooling** — redeliver failed events, rotate `notify_secret` (API exists since v1.3c; UI in v1.3d).
- [ ] **MFA for admin logins** (TOTP or WebAuthn) for the v1.3d admin UI — open question whether it is needed before go-live.
- [ ] **Decommission myFinance** — after it is phased out, move `dcWebUsers` ownership fully to the SSO, drop shared-DB compatibility constraints (Django version pinning, stock User model).

## Scheduled follow-ups

- [x] **v1.2b: prune `sso_revokedsession`** (done on `feat/v1.2b`) — the `revoke_inactive_users` sweep deletes rows older than the refresh-token lifetime + 1 day (their sessions can no longer refresh).
- [x] **v1.2b: Redis cache for revoked sessions** (done on `feat/v1.2b`, shared Django cache) — cache `sid` revocation lookups in Redis so refresh / introspect skip the DB hit.
- [ ] **sso-client 0.2: deferred library features** — local JWKS pre-check (`[jwt]`), circuit breaker, `cached` fail mode, `Retry-After` on 429, generic WSGI/ASGI middleware classes.
- [ ] **v1.2b follow-up: llm-wiki-svc on `sso-client`** (branch `feat/sso-client`), incl. `client_ip` on logout.
- [x] **v1.3c: encrypt `notify_secret` at rest** (Fernet, `SSO_WEBHOOK_SECRET_KEY`; on `feat/sso-v1.3`).

## Phase plan (component order decided 2026-10-15, see [ECOSYSTEM-INTEGRATION.md §9.1](docs/ECOSYSTEM-INTEGRATION.md))

### 1. SSO-server completion
- [x] **v1.3a** ([design](docs/DESIGN-v1.3a-admin-api.md)): admin REST API `/api/v1/admin/…` + `sso_adminauditlog`; step-up reauth (`POST /api/v1/admin/reauth` → `X-SSO-Reauth`); permission import `PUT /api/v1/admin/apps/{app}/permissions` (idempotent, dry-run, never deletes, marks missing deprecated) + `scripts/sso_permissions_to_json.py`; per-service credentials (ServiceClient perms, rotate-secret, `POST /api/v1/auth/service-token`, no IP binding); inactive-users feed `GET /api/v1/service/users/inactive`.
- [x] **v1.3b**: device clients `POST /api/v1/devices` (`kind=device`, owner, Ed25519 `private_key_jwt`, revoked on suspend); on-behalf-of headers; `sso-client` 0.2 (service tokens, on-behalf-of).
- [x] **v1.3c**: signed webhooks (`user.suspended` etc.), encrypt `notify_secret` at rest, webhook receiver in `sso-client`. (v1.3a-c done on `feat/sso-v1.3`, pushed.)
- [ ] **v1.3d** ([design](docs/DESIGN-v1.3d-admin-ui.md), decision 2026-10-15: admin UI moves from FUND to the SSO): admin web UI at `/<SSO_ADMIN_UI_PATH>` (default `/admin/`), server-rendered Django app `adminui`; domain layer `sso/admin_ops.py` shared with the REST API; session login (active + `is_staff` + `sso_admin`/superuser), `__Host-` cookie, CSRF, IP binding, idle/absolute timeout, step-up page; users, groups, permissions, apps + import diff, services, devices, webhooks, audit (+ CSV); audit `channel` column (migration `0007`, upgrade script + SQL); nginx `sso-admin-ui.d` allow-list + optional admin hostname; strict CSP; a11y basics. → SSO server complete.

### 2. SGMCP migration
- [ ] **v1.4 (SGMCP + local broker gateway)**: `sso_permissions.py`; API/MCP on `sso-client`; `gateway-relay`, pairing, device credentials, outbound WSS (long-poll fallback), heartbeats + offline alerts, `WAITING_GATEWAY`/halt, `UNKNOWN` in-flight orders + reconcile, one live connection per broker account (cold standby), suspend → stop/delete strategies (positions untouched) + disconnect; `delete_strategy` soft delete, never purge orders/fills, no `DELETE` grant on history tables.

### 3. FUND migration (last)
- [ ] **v1.5a**: `sso_permissions.py` + `AUTH_PROVIDER=legacy|both|sso` (start `both`); agents on `sso-client`, one ServiceClient per service; llm-wiki behind `/proxy/llmwiki/`.
- [ ] **v1.5b**: cloud-strategy UI (the admin UI moved to SSO v1.3d) (submit, broker pick, stay-on warnings, per-PC heartbeat status).
- [ ] **v1.5c**: `AUTH_PROVIDER=sso`, retire `fund-auth`.

### Other
- [ ] **TBD:** llm-wiki deployment host and domain.
- [ ] **Later:** delegated tokens (RFC 8693).

## Not planned (recorded ideas)

- DPoP sender-constrained tokens (RFC 9449) — rejected 2026-10-13; IP binding is sufficient.
- Device-bound refresh tokens / mTLS for service clients — only if DPoP-like protection is reconsidered.
- Per-service audience (`aud` per app) — rejected; one token for all services.
- IP prefix binding (/24, /64) and refresh "rebind" policy — rejected; exact IP, re-login on change.
- myFinance → SSO password sync — not needed; myFinance is phasing out.

## Client libraries

- `sso-client` (Python) is planned for v1.2b ([design](docs/SSO-CLIENT-LIBRARY-DESIGN.md)). Future: webhook receiver (v1.3c), clients for other languages (JS/Go) if non-Python services appear, publishing to a private package index.
