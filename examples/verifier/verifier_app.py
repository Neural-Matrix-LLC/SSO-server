"""FastAPI demo service protected by SSO access tokens (spec §8.4, §8.6).

    SSO_ISSUER=https://localhost SSO_JWKS_URL=https://localhost/.well-known/jwks.json \
    VERIFIER_CORS_ORIGINS=https://localhost uvicorn verifier_app:app --port 8001

Endpoints:
  GET /healthz             no auth
  GET /me                  any valid access token -> the token's claims
  GET /group/{name}        403 unless the token's groups contain {name}
  GET /staff               403 unless is_staff
"""
from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import sso_verifier

app = FastAPI(title="SSO verifier demo")
origins = [o.strip() for o in os.environ.get("VERIFIER_CORS_ORIGINS", "").split(",") if o.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET"],
                       allow_headers=["Authorization"])

bearer = HTTPBearer(auto_error=False)
_UNAUTH = {"WWW-Authenticate": 'Bearer error="invalid_token"'}


def current_user(cred: HTTPAuthorizationCredentials | None = Security(bearer)) -> dict:
    if cred is None:
        raise HTTPException(401, "token_invalid", headers=_UNAUTH)
    try:
        return sso_verifier.verify_access_token(cred.credentials)
    except sso_verifier.TokenInvalid:
        raise HTTPException(401, "token_invalid", headers=_UNAUTH) from None


def require_group(group: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if group not in user.get("groups", []):
            raise HTTPException(403, "forbidden")
        return user
    return dep


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return {"sub": user["sub"], "username": user.get("username"), "groups": user.get("groups", []),
            "is_staff": user.get("is_staff", False)}


@app.get("/group/{name}")
def group(name: str, user: dict = Depends(current_user)):
    return require_group(name)(user) and {"ok": True, "group": name, "sub": user["sub"]}


@app.get("/staff")
def staff(user: dict = Depends(current_user)):
    if not user.get("is_staff"):
        raise HTTPException(403, "forbidden")
    return {"ok": True, "sub": user["sub"]}
