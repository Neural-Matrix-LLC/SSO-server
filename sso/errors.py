"""Uniform error shape ``{"error": code, "detail": message}`` for every endpoint (spec §6.0, B.10).

Error codes (spec table + additions):
  400 invalid_request, 401 invalid_credentials, 401 token_invalid, 401 invalid_client,
  403 account_inactive, 403 origin_not_allowed, 403 forbidden, 404 not_found,
  405 method_not_allowed, 406 not_acceptable, 415 unsupported_media_type, 429 rate_limited,
  500 server_error, 503 service_unavailable.
Messages never contain tokens, passwords or stack traces.
"""
from __future__ import annotations

import logging

from django.http import JsonResponse
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.views import set_rollback

logger = logging.getLogger("sso.errors")


class SSOError(exceptions.APIException):
    error_code = "invalid_request"
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Invalid request."

    def __init__(self, detail: str | None = None):
        super().__init__(detail or self.default_detail)


class InvalidRequest(SSOError):
    pass


class InvalidCredentials(SSOError):
    error_code = "invalid_credentials"
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Username or password is incorrect."


class TokenInvalid(SSOError):
    error_code = "token_invalid"
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Token is invalid, expired, of the wrong type or revoked."


class InvalidClient(SSOError, exceptions.AuthenticationFailed):
    error_code = "invalid_client"
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Service client authentication failed."


class AccountInactive(SSOError):
    error_code = "account_inactive"
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "This account is not active. Activate it from the email you received, or contact support."


class OriginNotAllowed(SSOError):
    error_code = "origin_not_allowed"
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Request origin is not allowed."


class ReauthRequired(SSOError):
    error_code = "reauth_required"
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "This action needs a recent password confirmation: POST /api/v1/admin/reauth, then send X-SSO-Reauth."


class AdminForbidden(SSOError):
    error_code = "admin_forbidden"
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "SSO administrator permission (application.sso_admin) required."


class NotFound(SSOError):
    error_code = "not_found"
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "Not found."


class Conflict(SSOError):
    error_code = "conflict"
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Conflict."


class SelfActionForbidden(Conflict):
    error_code = "self_action_forbidden"
    default_detail = "You cannot do this to your own account."


class LastAdmin(Conflict):
    error_code = "last_admin"
    default_detail = "This would leave no active SSO administrator."


class VersionConflict(Conflict):
    error_code = "version_conflict"
    default_detail = "The stored permissions version is newer; use force=true to import anyway."


class UnsupportedGrantType(SSOError):
    error_code = "unsupported_grant_type"
    default_detail = "Only grant_type=client_credentials is supported."


GENERIC = {
    400: ("invalid_request", "Missing or malformed fields."),
    401: ("token_invalid", "Authentication credentials were missing or invalid."),
    403: ("forbidden", "You do not have permission to perform this action."),
    404: ("not_found", "Not found."),
    405: ("method_not_allowed", "Method not allowed."),
    406: ("not_acceptable", "Requested response format is not available."),
    415: ("unsupported_media_type", "Request body must be JSON (Content-Type: application/json)."),
    429: ("rate_limited", "Too many attempts. Try again later."),
    500: ("server_error", "Internal server error."),
    503: ("service_unavailable", "Service unavailable."),
}


def error_body(code: str, detail: str) -> dict:
    return {"error": code, "detail": str(detail)}


def _validation_detail(exc: exceptions.ValidationError) -> str:
    data = exc.detail
    if isinstance(data, dict):
        fields = sorted(str(k) for k in data.keys())
        if fields and fields != ["non_field_errors"]:
            return "Missing or malformed fields: " + ", ".join(fields) + "."
    return GENERIC[400][1]


def _classify(exc: Exception, response_status: int) -> tuple[str, str]:
    if isinstance(exc, SSOError):
        return exc.error_code, str(exc.detail)
    if isinstance(exc, exceptions.ValidationError):
        return "invalid_request", _validation_detail(exc)
    if isinstance(exc, exceptions.ParseError):
        return "invalid_request", "Malformed JSON body."
    if isinstance(exc, exceptions.Throttled):
        wait = int(exc.wait) if exc.wait is not None else None
        return "rate_limited", (f"Too many attempts. Try again in {wait} s." if wait else GENERIC[429][1])
    if isinstance(exc, (exceptions.AuthenticationFailed, exceptions.NotAuthenticated)):
        # DRF style: code on the ErrorDetail; simplejwt style: detail={"detail": ..., "code": ...}
        code = exc.detail.get("code") if isinstance(exc.detail, dict) else exc.get_codes()
        if str(code) == "user_inactive":
            return AccountInactive.error_code, AccountInactive.default_detail
        return "token_invalid", TokenInvalid.default_detail
    return GENERIC.get(response_status, ("error", "Request failed."))


def error_handler(exc: Exception, context: dict) -> Response:
    """DRF EXCEPTION_HANDLER."""
    response = drf_exception_handler(exc, context)
    if response is None:
        # Unhandled exception: log the traceback server-side only, answer with the uniform shape.
        logger.exception("unhandled error in %s", context.get("view").__class__.__name__)
        set_rollback()
        return Response(error_body(*GENERIC[500]), status=500)
    code, detail = _classify(exc, response.status_code)
    if isinstance(exc, (exceptions.AuthenticationFailed, exceptions.NotAuthenticated)) and code == "account_inactive":
        response.status_code = 403
    response.data = error_body(code, detail)
    return response


# ----------------------------------------------------------------- Django-level handlers (non-DRF URLs)
def _json(status_code: int) -> JsonResponse:
    return JsonResponse(error_body(*GENERIC[status_code]), status=status_code)


def handler400(request, exception=None):
    return _json(400)


def handler403(request, exception=None):
    return _json(403)


def handler404(request, exception=None):
    return _json(404)


def handler500(request):
    return _json(500)
