# HISTORY

Change log for the SSO server, newest first. Each entry records goal, root cause (for bugs),
implementation, related files and test coverage.

## 2026-10-15 — docs: WSL2 setup guide (`docs/SSO-Setup.md`)

**Goal.** Write down the complete local setup for the production compose stack on WSL2 (Docker Engine and
MySQL both inside WSL, `https://localhost` on port 443), including the three start-up failures hit
during the first local run and their fixes.

**Root causes of the failures documented.** These are environment problems, not code bugs:
1. `sso.db ... database unreachable at host.docker.internal:3306 (2002 ... (110))`: ufw enabled with
   `DEFAULT_INPUT_POLICY="DROP"` silently dropped traffic from the compose `edge` network
   (172.31.250.0/24) to the host's MySQL on 3306. Fix: `ufw allow from 172.31.250.0/24 to any port 3306 proto tcp`.
2. `curl: (7) ... port 443 ... Connection refused`: nginx was crash-looping because the certificate named in
   `.env` (`fullchain.pem` / `privkey.pem`) did not exist in `docker/certs/`. Fix: create a self-signed
   pair with `scripts/gen_selfsigned_cert.sh` and point `SSO_TLS_CERT_FILE` / `SSO_TLS_KEY_FILE` at it.
3. `curl: (35) ... tlsv1 unrecognized name`: `SSO_HOSTNAME` was still the placeholder `sso.example.com`,
   so nginx's default server (`ssl_reject_handshake on`) rejected SNI `localhost`. Fix: `SSO_HOSTNAME=localhost`.

**Implementation.** New guide with the setup steps: `.env` values, TLS cert, JWT keys, MySQL bind
address and accounts limited to the edge subnet, ufw rule, backup + migrate as `sso_migrator`, start and
verify, admin. It ends with a troubleshooting table that maps each symptom to its cause and fix. It links
to the README for details instead of duplicating them. No code, config or env variable changes.

**Related files.**
- `docs/SSO-Setup.md` (new)
- `HISTORY.md` (new)

**Test coverage.** Docs only. No tests added or removed. Ran the repo-only QA checks
(`cd qa/tests && ../../.venv/bin/python -m pytest -m static`): 34 passed, 1 skipped (`SSO_MANAGE_CMD` not
set, needs a running server).
