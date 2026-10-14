"""E2E sample service (Flask + sso_client)."""
from flask import Flask, g
from sso_client.adapters.flask import SSO

app = Flask(__name__)
sso = SSO(app)


@app.get("/healthz")
def health():
    return {"ok": True}


@app.get("/app1")
@sso.require_permission("application.app1")
def app1():
    return {"user": g.sso.user.username, "ip": g.client_ip, "ip_match": g.sso.ip_match}


@app.get("/app2")
@sso.require_permission("application.app2")
def app2():
    return {"user": g.sso.user.username}
