# TODOS — future-phase and not-planned items

Agreed scope for v1.2a / v1.2b / v1.4 is in [docs/DESIGN-v1.2-requirements.md](docs/DESIGN-v1.2-requirements.md)
(decisions of 2026-10-13). Everything below is **out of that scope**. Known as-built gaps are listed in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §12.

## Future phase (wanted, not scheduled)

- [ ] **Online sign-up** — `POST /api/v1/account/signup` + `activate`. Open: open vs. invite/approval only; email provider for activation mail.
- [ ] **Password change** — `POST /api/v1/account/password/change` (Bearer + old/new; revokes all tokens, returns a fresh pair).
- [ ] **Password reset** — `password/reset` + `reset/confirm` (same 204 for unknown addresses; revokes all tokens).
- [ ] **Hosted login page + authorization-code flow with PKCE** (uses `ServiceClient.redirect_uris`; adds `authorization_endpoint` to discovery).
- [ ] **Client push notifications (SSE or WebSocket)** — only if clients need proactive "token expired/revoked" messages; today clients learn by rejection (401). Services already get signed webhooks (v1.4).
- [ ] **Cross-tab refresh coordination in the browser helper** (BroadcastChannel / Web Locks) so the losing tab is not logged out.
- [ ] **Hosted self-service account page** (profile, active sessions list, "log out this session").
- [ ] **Webhook admin tooling** — redeliver failed events, rotate `notify_secret`.
- [ ] **Decommission myFinance** — after it is phased out, move `dcWebUsers` ownership fully to the SSO, drop shared-DB compatibility constraints (Django version pinning, stock User model).

## Scheduled follow-ups

- [ ] **v1.2b: prune `sso_revokedsession`** — the `revoke_inactive_users` sweep deletes rows older than the refresh-token lifetime + 1 day (their sessions can no longer refresh).
- [ ] **v1.2b: Redis cache for revoked sessions** — cache `sid` revocation lookups in Redis so refresh / introspect skip the DB hit.
- [ ] **v1.4: encrypt `notify_secret` at rest** (webhook signing secret).

## Ecosystem (decisions 2026-10-14, see [ECOSYSTEM-INTEGRATION.md](docs/ECOSYSTEM-INTEGRATION.md))

- [ ] **v1.3a: SSO admin REST API** `/api/v1/admin/…` (users, groups, permissions, services, apps, audit) + `sso_adminauditlog`.
- [ ] **v1.3a: bulk permission import** `PUT /api/v1/admin/apps/{app}/permissions` (idempotent, dry-run, never deletes; missing → deprecated).
- [ ] **v1.3a: service tokens** `POST /api/v1/auth/service-token` (client credentials, `typ=service`, no IP binding) + on-behalf-of (`X-SSO-User-Token`, `X-SSO-Client-IP`).
- [ ] **v1.3a: inactive-users feed** `GET /api/v1/service/users/inactive?since=` for the suspend sweep.
- [ ] **v1.3b (FUND): `config.py` permissions + `AUTH_PROVIDER=legacy|both|sso`** in root `.env`; all endpoints need a token in `both`/`sso`; agents on `sso-client`.
- [ ] **v1.3b (FUND): llm-wiki-svc behind `/proxy/llmwiki/`** (configurable upstream); llm-wiki local `/login` optional.
- [ ] **v1.3c (FUND): Admin UI `/admin`** incl. Applications → Import and interim suspend-cleanup call.
- [ ] **v1.3d (SGMCP + auto-trade):** service-token auth, `owner_sub`, `gateway_trade` / `gateway_live`, suspend-cleanup endpoint + 60 s sweep (stop and delete owner's strategies).
- [ ] **v1.3e (FUND): `AUTH_PROVIDER=sso`, retire `fund-auth`** and `AUTH_SECRET_KEY`.
- [ ] **v1.4: `user.suspended` webhook** replaces the interim suspend call in SGMCP and auto-trade.
- [ ] **TBD:** gateway and llm-wiki deployment hosts and domains (ongoing development; all configurable).
- [ ] **Later:** delegated tokens (RFC 8693) for long-running on-behalf-of work; SSO login for SGMCP `/ui`; `Local_login.md` access list keyed by SSO `sub`; admin step-up re-auth.

## Not planned (recorded ideas)

- DPoP sender-constrained tokens (RFC 9449) — rejected 2026-10-13; IP binding is sufficient.
- Device-bound refresh tokens / mTLS for service clients — only if DPoP-like protection is reconsidered.
- Per-service audience (`aud` per app) — rejected; one token for all services.
- IP prefix binding (/24, /64) and refresh "rebind" policy — rejected; exact IP, re-login on change.
- myFinance → SSO password sync — not needed; myFinance is phasing out.

## Client libraries

- `sso-client` (Python) is planned for v1.2b ([design](docs/SSO-CLIENT-LIBRARY-DESIGN.md)). Future: webhook receiver (v1.4), clients for other languages (JS/Go) if non-Python services appear, publishing to a private package index.
