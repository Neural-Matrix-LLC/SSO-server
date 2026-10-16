"""Uniform error bodies for the adapters (library design §7)."""
from __future__ import annotations

from .errors import NotAuthenticated, PermissionDenied, SSOError, TokenInactive


def error_response(exc: SSOError) -> tuple[int, dict, dict]:
    """(status, json body, headers)."""
    if isinstance(exc, NotAuthenticated):
        return 401, {"detail": "not_authenticated"}, {"WWW-Authenticate": "Bearer"}
    if isinstance(exc, TokenInactive):
        return 401, {"detail": "token_inactive", "reason": exc.reason}, {
            "WWW-Authenticate": 'Bearer error="invalid_token"'}
    if isinstance(exc, PermissionDenied):
        return 403, {"detail": "permission_denied", "missing": list(exc.missing)}, {}
    return 503, {"detail": "sso_unavailable"}, {"Retry-After": "5"}  # fail closed
