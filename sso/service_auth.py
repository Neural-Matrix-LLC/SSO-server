"""Per-service credentials (DESIGN-v1.3a §6, §7): service tokens and the inactive-users feed."""
from __future__ import annotations

from datetime import timezone as dt_timezone

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import authentication, exceptions
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError

from .authentication import ServiceClientBasicAuthentication, ServicePrincipal
from .errors import InvalidClient, InvalidRequest, UnsupportedGrantType
from .models import ServiceClient, UserTokenRevocation, UserTombstone
from .tokens import SSOServiceToken, issue_service_token, secret_generation, service_token_ttl_seconds

FEED_LIMIT = 500


def load_service_token(raw: str) -> tuple[SSOServiceToken, ServiceClient] | None:
    """A valid service token whose client is still active and was not rotated after ``iat``; else None."""
    try:
        token = SSOServiceToken(raw)
    except (TokenError, TypeError, ValueError, OverflowError):
        return None
    client = (ServiceClient.objects.select_related("owner")
              .filter(client_id=token.get("client_id"), is_active=True).first())
    if client is None:
        return None
    if client.kind == "device":  # v1.3b: owner must still be active (checked live)
        if (token.get("sub") != f"dev:{client.client_id}" or client.owner is None or not client.owner.is_active
                or token.get("owner") != str(client.owner_id)):
            return None
    elif token.get("sub") != f"svc:{client.client_id}":
        return None
    if token.get("rot") != secret_generation(client):  # issued under an older (rotated) secret
        return None
    return token, client


def is_service_token(raw: str) -> bool:
    import jwt

    try:
        claims = jwt.decode(raw, options={"verify_signature": False})
    except jwt.PyJWTError:
        return False
    return isinstance(claims, dict) and claims.get("token_type") == "service"


class ServiceTokenAuthentication(authentication.BaseAuthentication):
    """``Authorization: Bearer <service token>`` (``token_type=service``)."""

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).split()
        if not header or header[0].lower() != b"bearer":
            return None
        if len(header) != 2:
            raise exceptions.AuthenticationFailed("Invalid Authorization header.")
        if not is_service_token(header[1].decode("latin-1")):
            return None  # a user token: let the next authentication class handle it
        loaded = load_service_token(header[1].decode("latin-1"))
        if loaded is None:
            raise exceptions.AuthenticationFailed("Service token is invalid.", code="token_invalid")
        return ServicePrincipal(client=loaded[1]), loaded[0]

    def authenticate_header(self, request):
        return 'Bearer realm="sso-service"'


class ServiceTokenThrottle(SimpleRateThrottle):
    scope = "service_token"

    def get_cache_key(self, request, view):
        client_id = getattr(request.user, "client_id", None)
        if not client_id and isinstance(getattr(request, "data", None), dict):
            iss = _assertion_iss(request.data.get("client_assertion"))  # device: per claimed device id
            client_id = f"dev:{iss}" if iss else None
        if not client_id:
            return None
        return self.cache_format % {"scope": self.scope, "ident": client_id}


def _assertion_iss(raw) -> str | None:
    import jwt

    if not isinstance(raw, str) or len(raw) > 8192:
        return None
    try:
        iss = jwt.decode(raw, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError:
        return None
    return iss[:100] if isinstance(iss, str) else None


class ServiceTokenView(APIView):
    authentication_classes = [ServiceClientBasicAuthentication]
    throttle_classes = [ServiceTokenThrottle]

    def post(self, request):
        if not isinstance(request.data, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        assertion = request.data.get("client_assertion")
        if assertion is not None:  # v1.3b device: private_key_jwt (RFC 7523)
            from .devices import ASSERTION_TYPE, verify_assertion

            if isinstance(request.user, ServicePrincipal) or request.data.get("client_assertion_type") != ASSERTION_TYPE \
                    or not isinstance(assertion, str) or len(assertion) > 8192:
                raise InvalidClient()
            if request.data.get("grant_type") != "client_credentials":
                raise UnsupportedGrantType()
            client = verify_assertion(assertion)
        else:
            if not isinstance(request.user, ServicePrincipal):
                raise InvalidClient()
            if request.data.get("grant_type") != "client_credentials":
                raise UnsupportedGrantType()
            client = request.user.client
        token = issue_service_token(client)
        return Response({"access_token": str(token), "token_type": "Bearer", "expires_in": service_token_ttl_seconds()},
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


class InactiveUsersView(APIView):
    """Users suspended or deleted since ``since`` (oldest first), for the suspend sweep of SGMCP / FUND."""

    authentication_classes = [ServiceClientBasicAuthentication, ServiceTokenAuthentication]

    def get_authenticate_header(self, request):
        return 'Basic realm="sso-service"'

    def get(self, request):
        if not isinstance(request.user, ServicePrincipal):
            raise InvalidClient()
        raw = request.query_params.get("since", "")
        since = parse_datetime(raw.replace("Z", "+00:00")) if raw else None
        if since is None:
            raise InvalidRequest("since is required (ISO 8601 timestamp).")
        if timezone.is_naive(since):
            since = since.replace(tzinfo=dt_timezone.utc)
        events = []
        for rev in (UserTokenRevocation.objects.filter(revoked_at__gt=since, user__is_active=False)
                    .select_related("user").order_by("revoked_at")[:FEED_LIMIT]):
            events.append({"id": rev.user_id, "username": rev.user.username, "event": "suspended",
                           "at": rev.revoked_at})
        for tomb in UserTombstone.objects.filter(deleted_at__gt=since).order_by("deleted_at")[:FEED_LIMIT]:
            events.append({"id": tomb.user_id, "username": tomb.username, "event": "deleted", "at": tomb.deleted_at})
        events.sort(key=lambda e: e["at"])
        events = events[:FEED_LIMIT]
        next_since = _iso(events[-1]["at"]) if events else _iso(since)
        return Response({"users": [{**e, "at": _iso(e["at"])} for e in events], "next_since": next_since},
                        headers={"Cache-Control": "no-store"})
