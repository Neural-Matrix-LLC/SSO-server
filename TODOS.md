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

## Not planned (recorded ideas)

- DPoP sender-constrained tokens (RFC 9449) — rejected 2026-10-13; IP binding is sufficient.
- Device-bound refresh tokens / mTLS for service clients — only if DPoP-like protection is reconsidered.
- Per-service audience (`aud` per app) — rejected; one token for all services.
- IP prefix binding (/24, /64) and refresh "rebind" policy — rejected; exact IP, re-login on change.
- myFinance → SSO password sync — not needed; myFinance is phasing out.
