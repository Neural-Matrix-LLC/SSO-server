"""SSO REST API (spec §6, addendum B)."""
from __future__ import annotations

import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.db import DatabaseError, connection, transaction
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from application.permissions import user_app_perms

from .authentication import ServiceClientBasicAuthentication, ServicePrincipal, SSOAccessTokenAuthentication
from .errors import AccountInactive, InvalidClient, InvalidCredentials, InvalidRequest, OriginNotAllowed, TokenInvalid
from .logs import log_login, log_token_event
from .revocation import is_session_revoked, revoke_session, revoke_user_tokens
from .serializers import (
    IntrospectSerializer,
    LoginSerializer,
    RefreshInputSerializer,
    UserSerializer,
    check_credentials,
)
from .throttles import LoginIPThrottle, LoginUserThrottle, RefreshThrottle
from .tokens import (
    SID_CLAIM,
    SSOAccessToken,
    SSORefreshToken,
    access_ttl_seconds,
    is_revoked,
    issue_token_pair,
    refresh_ttl_seconds,
    replayed_refresh,
    user_groups,
)

logger = logging.getLogger("sso.views")


# --------------------------------------------------------------------------- helpers
def set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.SSO_COOKIE_NAME,
        token,
        max_age=refresh_ttl_seconds(),
        path=settings.SSO_COOKIE_PATH,
        domain=settings.SSO_COOKIE_DOMAIN,
        secure=settings.SSO_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SSO_COOKIE_SAMESITE,
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        settings.SSO_COOKIE_NAME,
        path=settings.SSO_COOKIE_PATH,
        domain=settings.SSO_COOKIE_DOMAIN,
        samesite=settings.SSO_COOKIE_SAMESITE,
    )


def token_response(user: User, *, browser: bool, sid: str | None = None) -> Response:
    refresh, access = issue_token_pair(user, sid=sid)
    body = {
        "access_token": str(access),
        "token_type": "Bearer",
        "expires_in": access_ttl_seconds(),
        "user": UserSerializer(user).data,
    }
    if browser:
        response = Response(body)
        set_refresh_cookie(response, str(refresh))
    else:
        body["refresh_token"] = str(refresh)
        response = Response(body)
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


def check_origin(request) -> None:
    """Cookie-mode CSRF defence (addendum B.9): Origin must be an allowed CORS origin."""
    origin = request.headers.get("Origin")
    if not origin or origin not in settings.CORS_ALLOWED_ORIGINS:
        raise OriginNotAllowed()


def read_refresh_input(request) -> tuple[str | None, bool]:
    """Return (raw refresh token or None, cookie_mode). Body token = native, else cookie mode."""
    data = request.data if isinstance(request.data, dict) else None
    if data is None:
        raise InvalidRequest("Request body must be a JSON object.")
    ser = RefreshInputSerializer(data=data)
    ser.is_valid(raise_exception=True)
    raw = ser.validated_data.get("refresh_token")
    if raw:
        return raw, False
    check_origin(request)
    return request.COOKIES.get(settings.SSO_COOKIE_NAME) or None, True


def load_refresh(raw: str, *, require_active: bool = False) -> tuple[SSORefreshToken, User]:
    """Validate a refresh token: signature (by kid), iss, aud, exp, type, blacklist, user, revocation.

    ``require_active``: a suspended user gets 403 ``account_inactive`` (design §5) even though suspending
    also revoked the token; checked before the revocation so the client sees why.
    """
    try:
        token = SSORefreshToken(raw)
    except TokenError:
        if require_active:  # suspending blacklisted it: still say why
            used = replayed_refresh(raw)
            if used is not None and User.objects.filter(pk=used.get("sub"), is_active=False).exists():
                raise AccountInactive() from None
        raise TokenInvalid() from None
    user = User.objects.select_related("sso_token_revocation").filter(pk=token.get("sub")).first()
    if user is None:
        raise TokenInvalid()
    if require_active and not user.is_active:
        revoke_if_inactive(user, token.get("iat"))
        raise AccountInactive()
    if is_revoked(user, token.get("iat")) or is_session_revoked(token.get(SID_CLAIM)):
        raise TokenInvalid()
    return token, user


def handle_refresh_reuse(request, raw: str) -> None:
    """A refresh token was rejected. If it is one of ours that was already used (blacklisted), this is a
    replay: revoke its whole session (design v1.2a "refresh-reuse family revocation").

    Grace: a reuse within ``SSO_REFRESH_REUSE_GRACE_SECONDS`` of the token being blacklisted is treated as
    two legitimate concurrent refreshes (two tabs, a client retry after a lost response). The late request
    still gets 401 and no tokens, but the session survives. Tokens without ``sid`` (issued before v1.2a) have
    no session to revoke.
    """
    token = replayed_refresh(raw)
    if token is None:
        return
    user = User.objects.filter(pk=token.get("sub")).first()
    sid = token.get(SID_CLAIM)
    if user is None or not sid or not user.is_active:  # inactive: suspension blacklisted it, all revoked
        return
    used = BlacklistedToken.objects.filter(token__jti=token["jti"]).values_list("blacklisted_at", flat=True).first()
    if used is not None and (timezone.now() - used).total_seconds() < settings.SSO_REFRESH_REUSE_GRACE_SECONDS:
        log_token_event(request, "refresh", "reuse_within_grace", user_id=user.pk)
        return
    log_token_event(request, "refresh", "reuse_detected", user_id=user.pk)
    revoke_session(user, sid, "refresh_reuse")


def revoke_if_inactive(user: User, iat) -> None:
    """Defence in depth for suspensions that bypassed the model signal (``QuerySet.update()``, myFinance
    writing auth_user): a still-valid token of an inactive user revokes all of the user's tokens, so they
    stay dead after a later reactivation."""
    if user is not None and not user.is_active and not is_revoked(user, iat):
        revoke_user_tokens(user)


# --------------------------------------------------------------------------- auth endpoints
class _ServiceClientChallenge:
    """Login/refresh/logout accept optional ServiceClient Basic auth (sso/delegation.py). Without an
    authenticate header DRF would turn its 401 ``invalid_client`` into a 403."""

    def get_authenticate_header(self, request):
        return 'Basic realm="sso-service-client"'


class LoginView(_ServiceClientChallenge, APIView):
    throttle_classes = [LoginIPThrottle, LoginUserThrottle]

    def post(self, request):
        if not isinstance(request.data, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        ser = LoginSerializer(data=request.data)
        if not ser.is_valid():
            log_login(request, str(request.data.get("username", ""))[:254], "invalid_request")
            ser.is_valid(raise_exception=True)
        identifier = ser.validated_data["username"]
        client = ser.validated_data["client"]
        user = check_credentials(request._request, identifier, ser.validated_data["password"])
        if user is None:
            log_login(request, identifier, "invalid_credentials", client=client)
            raise InvalidCredentials()
        if not user.is_active:
            log_login(request, identifier, "account_inactive", client=client, user_id=user.pk)
            raise AccountInactive()
        user_logged_in.send(sender=user.__class__, request=request._request, user=user)  # updates last_login
        log_login(request, identifier, "success", client=client, user_id=user.pk)
        return token_response(user, browser=(client == "browser"))


class RefreshView(_ServiceClientChallenge, APIView):
    throttle_classes = [RefreshThrottle]

    def post(self, request):
        raw, cookie_mode = read_refresh_input(request)
        if not raw:
            raise TokenInvalid("No refresh token supplied.")
        try:
            token, user = load_refresh(raw, require_active=True)
        except AccountInactive:
            log_token_event(request, "refresh", "account_inactive")
            raise
        except TokenInvalid:
            handle_refresh_reuse(request, raw)
            raise
        try:
            with transaction.atomic():
                _, created = token.blacklist()
                if not created:  # lost a race with a concurrent refresh of the same token: no revocation
                    raise TokenInvalid()
        except TokenInvalid:
            handle_refresh_reuse(request, raw)
            raise
        log_token_event(request, "refresh", "success", user_id=user.pk)
        return token_response(user, browser=cookie_mode, sid=token.get(SID_CLAIM))


class LogoutView(_ServiceClientChallenge, APIView):
    throttle_classes = [RefreshThrottle]

    def post(self, request):
        raw, cookie_mode = read_refresh_input(request)
        if not raw:
            if not cookie_mode:  # pragma: no cover - serializer guarantees a value in native mode
                raise InvalidRequest()
            response = Response(status=status.HTTP_204_NO_CONTENT)
            clear_refresh_cookie(response)
            return response
        try:
            token, user = load_refresh(raw)
        except TokenInvalid:
            if cookie_mode:
                response = Response(
                    {"error": "token_invalid", "detail": TokenInvalid.default_detail}, status=401
                )
                clear_refresh_cookie(response)
                return response
            raise
        token.blacklist()
        log_token_event(request, "logout", "success", user_id=user.pk)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        if cookie_mode:
            clear_refresh_cookie(response)
        return response


class LogoutAllView(APIView):
    authentication_classes = [SSOAccessTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        revoke_user_tokens(user)
        log_token_event(request, "logout_all", "success", user_id=user.pk)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        clear_refresh_cookie(response)
        return response


class MeView(APIView):
    authentication_classes = [SSOAccessTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = User.objects.get(pk=request.user.pk)  # fresh from the DB
        return Response(UserSerializer(user).data)


class IntrospectView(APIView):
    authentication_classes = [ServiceClientBasicAuthentication]

    def post(self, request):
        if not isinstance(request.user, ServicePrincipal):
            raise InvalidClient()
        if not isinstance(request.data, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        ser = IntrospectSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        inactive = Response({"active": False}, headers={"Cache-Control": "no-store"})
        try:
            token = SSOAccessToken(ser.validated_data["token"])
        except TokenError:
            return inactive
        user = User.objects.select_related("sso_token_revocation").filter(pk=token.get("sub")).first()
        if user is not None and not user.is_active:
            revoke_if_inactive(user, token.get("iat"))
            return inactive
        if user is None or is_revoked(user, token.get("iat")) or is_session_revoked(token.get(SID_CLAIM)):
            return inactive
        return Response(
            {
                "active": True,
                "sub": str(user.pk),
                "username": user.get_username(),
                "email": user.email or "",
                "is_staff": bool(user.is_staff),
                "groups": user_groups(user),
                "perms": user_app_perms(user),  # fresh from the DB (design A2)
                "token_type": "access",
                "iat": token.get("iat"),
                "exp": token.get("exp"),
                "iss": settings.SSO_ISSUER,
                "aud": settings.SSO_AUDIENCE,
                "client_id": request.user.client_id,
            },
            headers={"Cache-Control": "no-store"},
        )


# --------------------------------------------------------------------------- discovery / health
class JWKSView(APIView):
    def get(self, request):
        return Response(settings.SSO_KEYSET.jwks(), headers={"Cache-Control": "public, max-age=3600"})


class DiscoveryView(APIView):
    def get(self, request):
        issuer = settings.SSO_ISSUER
        # Addendum B.2: no /api/v1/auth/token or authorization_endpoint until phase 5 exists.
        return Response(
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
                "token_endpoint": f"{issuer}/api/v1/auth/login",
                "id_token_signing_alg_values_supported": ["RS256"],
            },
            headers={"Cache-Control": "public, max-age=3600"},
        )


class HealthView(APIView):
    def get(self, request):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except DatabaseError:
            logger.error("healthz: database check failed")
            return Response({"error": "unhealthy", "detail": "database"}, status=503)
        return Response({"status": "ok"}, headers={"Cache-Control": "no-store"})
