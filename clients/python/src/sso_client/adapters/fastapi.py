"""FastAPI / Starlette adapter.

    sso = SSO.from_env()          # AsyncSSOClient inside
    sso.install(app)              # exception handlers (401 / 403 / 503 JSON)

    @app.get("/pages")
    async def pages(user: CheckResult = Depends(sso.require_permission("application.app1"))): ...

The peer is ``request.client.host`` (ASGI ``scope["client"]``). Run uvicorn WITHOUT
``--forwarded-allow-ips='*'`` / proxy-headers rewriting, or with the same trusted list.
"""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from ..client import AsyncSSOClient, bearer_token
from ..config import SSOConfig
from ..errors import NotAuthenticated, SSOError
from ..ip import get_client_ip
from ..models import CheckResult
from ..responses import error_response


def request_client_ip(request: Request, trusted, client_ip_header: str = "") -> str | None:
    peer = request.client.host if request.client else None
    return get_client_ip(peer, request.headers, trusted, client_ip_header)


class SSO:
    def __init__(self, client: AsyncSSOClient):
        self.client = client

    @classmethod
    def from_env(cls, **overrides) -> "SSO":
        return cls(AsyncSSOClient(SSOConfig.from_env(**overrides)))

    def install(self, app) -> None:
        async def handler(request: Request, exc: SSOError):
            status, body, headers = error_response(exc)
            return JSONResponse(body, status_code=status, headers=headers)

        app.add_exception_handler(SSOError, handler)

    def client_ip(self, request: Request) -> str | None:
        """Dependency: the trusted client IP."""
        cfg = self.client.config
        ip = request_client_ip(request, cfg.trusted_proxies, cfg.client_ip_header)
        request.state.client_ip = ip
        return ip

    async def check(self, request: Request, require=()) -> CheckResult:
        token = bearer_token(request.headers.get("authorization"))
        if token is None:
            raise NotAuthenticated("no bearer token")
        return await self.client.check(token, self.client_ip(request), require)

    async def user(self, request: Request) -> CheckResult:
        """Dependency: active token, any permissions."""
        return await self.check(request)

    def require_permission(self, *perms: str):
        async def dep(request: Request) -> CheckResult:
            return await self.check(request, perms)

        return dep
