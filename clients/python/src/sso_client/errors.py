"""Typed exceptions (library design §10). All subclass SSOError."""
from __future__ import annotations


class SSOError(Exception):
    status = 500


class SSOConfigError(SSOError):
    pass


class NotAuthenticated(SSOError):
    """No (or a malformed) bearer token."""
    status = 401


class TokenInactive(SSOError):
    """The SSO answered active:false (expired, revoked, suspended user, IP mismatch under ENFORCE)."""
    status = 401

    def __init__(self, reason: str = "inactive"):
        super().__init__(reason)
        self.reason = reason


class PermissionDenied(SSOError):
    status = 403

    def __init__(self, missing):
        self.missing = tuple(missing)
        super().__init__("missing permission(s): " + ", ".join(self.missing))


class SSOUnavailable(SSOError):
    """SSO unreachable / 5xx / throttled: fail closed (503)."""
    status = 503


class SSOProtocolError(SSOError):
    """Unexpected answer (bad JSON, 401 invalid_client = wrong service credentials, 4xx)."""
    status = 503
