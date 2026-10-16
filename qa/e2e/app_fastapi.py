"""E2E sample service (FastAPI + sso_client). Env: SSO_BASE_URL, SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_ALLOW_HTTP, SSO_TRUSTED_PROXIES."""
from fastapi import Depends, FastAPI, Request
from sso_client import CheckResult
from sso_client.adapters.fastapi import SSO

app = FastAPI()
sso = SSO.from_env()
sso.install(app)


@app.get("/healthz")
def health():
    return {"ok": True}


@app.get("/app1")
async def app1(request: Request, u: CheckResult = Depends(sso.require_permission("application.app1"))):
    return {"user": u.user.username, "ip": request.state.client_ip, "ip_match": u.ip_match}


@app.get("/app2")
async def app2(u: CheckResult = Depends(sso.require_permission("application.app2"))):
    return {"user": u.user.username}
