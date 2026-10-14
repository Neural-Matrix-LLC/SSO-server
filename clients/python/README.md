# sso-client

Python library for services of the SSO-server (v1.2b): **client-IP derivation** identical to the SSO
(design v1.2 §4.5) and the **permission query** (`POST /api/v1/auth/introspect`, design §4.4).
Design: [docs/SSO-CLIENT-LIBRARY-DESIGN.md](../../docs/SSO-CLIENT-LIBRARY-DESIGN.md).

## Install (pip from git, subdirectory)

```bash
pip install "sso-client[fastapi] @ git+https://github.com/Neural-Matrix-LLC/SSO-server.git@sso-client-v0.1.0#subdirectory=clients/python"
# extras: [django] [fastapi] [flask]; local checkout: pip install -e clients/python
```

Python 3.11+ (3.13 is the target). Runtime dependency: `httpx`.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `SSO_BASE_URL` | required | e.g. `https://sso.example.com` (https only unless `SSO_ALLOW_HTTP=true`) |
| `SSO_CLIENT_ID` | required | this service's ServiceClient |
| `SSO_CLIENT_SECRET` / `SSO_CLIENT_SECRET_FILE` | required | secret or a file holding it (preferred in Docker) |
| `SSO_TRUSTED_PROXIES` | empty (trust nobody) | IPs/CIDRs of *your* reverse proxies; never `0.0.0.0/0` |
| `SSO_TIMEOUT` | `2.0` | seconds per attempt (connect 1 s) |
| `SSO_RETRIES` | `2` | only connect errors, timeouts, 502/503/504 |
| `SSO_CACHE_TTL` | `30` | seconds, capped at 30; `0` disables |

## Behaviour

- `get_client_ip(peer, headers, trusted)`: the socket peer; `X-Forwarded-For` is read only when the peer is a
  trusted proxy, walked right to left (first untrusted entry wins, malformed entry stops the walk). IPv6 is
  normalised, `::ffff:a.b.c.d` becomes `a.b.c.d`, ports / brackets / zone ids are stripped.
- `SSOClient().check(token, client_ip, require=[...])` / `await AsyncSSOClient().check(...)` return a
  `CheckResult` (`active`, `user`, `permissions`, `ip_binding`, `ip_match`, `session_id`, `expires_at`).
  Raise `TokenInactive` (401), `PermissionDenied` (403), `NotAuthenticated` (401), `SSOUnavailable` (503).
- **Fail closed**: SSO unreachable, 5xx or 429 → `SSOUnavailable` → adapters answer **503** + `Retry-After: 5`.
  An unverified token is never accepted.
- **Cache**: only active answers, keyed by `sha256(token):ip`, at most 30 s and never past `exp`; `active:false`
  is never cached. `require` is checked locally against the (cached) permission set. A revocation can therefore
  take up to 30 s to reach a service (agreed trade-off, decision 15).
- Tokens and secrets are never logged (tokens appear as `sha256[:12]`); `ip_mismatch` (WARNING mode) is logged
  at INFO on logger `sso_client`.

## Usage

FastAPI:

```python
from fastapi import Depends, FastAPI
from sso_client import CheckResult
from sso_client.adapters.fastapi import SSO

app = FastAPI()
sso = SSO.from_env()
sso.install(app)                     # 401 / 403 / 503 JSON handlers

@app.get("/pages")
async def pages(u: CheckResult = Depends(sso.require_permission("application.app1"))):
    return {"user": u.user.username}
```

Django:

```python
MIDDLEWARE = [..., "sso_client.adapters.django.SSOMiddleware"]   # request.client_ip, lazy request.sso
SSO_CLIENT = {"TRUSTED_PROXIES": ["172.18.0.0/16"]}               # other values from SSO_* env

from sso_client.adapters.django import require_permission

@require_permission("application.app2")
def report(request):
    return JsonResponse({"user": request.sso.user.username})
```

Flask:

```python
from sso_client.adapters.flask import SSO
sso = SSO(app)

@app.get("/report")
@sso.require_permission("application.app2")
def report():
    return {"user": g.sso.user.username}
```

Raw socket / BFF:

```python
ip = get_client_ip(peer_from_socket(conn), {}, [])
result = SSOClient().check(token, ip, require=["application.app3"])
```

A BFF (server-side login) must also pass the **browser's** IP as `client_ip` on its own
`/login`, `/refresh` and `/logout` calls to the SSO (with its ServiceClient Basic auth).

Do not let the framework rewrite the peer from headers (Werkzeug `ProxyFix`, uvicorn
`--forwarded-allow-ips='*'`), or configure it for exactly the same proxies.

## Testing utilities

```python
from sso_client.testing import FakeSSO
fake = FakeSSO("ENFORCE")
token = fake.issue("alice", perms=["application.app1"], ip="203.0.113.7")
client = fake.client()            # or fake.async_client(); fake.revoke(token); fake.down()
```

The package registers a pytest plugin with `fake_sso` and `sso_client` fixtures; `wsgi_environ()` and
`asgi_scope()` build requests with a given peer and `X-Forwarded-For`.

## Development

```bash
python3.13 -m venv .venv && .venv/bin/pip install -e ".[test]" && .venv/bin/pytest -q
```

Not implemented in 0.1.0 (see the design): local JWKS pre-check (`[jwt]`), circuit breaker, `cached` stale
fail mode, webhook receiver (v1.4), generic WSGI/ASGI middleware classes.
