"""Per-service credentials (DESIGN-v1.3a §6, §7): service tokens and the inactive-users feed."""
from __future__ import annotations

from datetime import timezone as dt_timezone

from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import authentication, exceptions
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError

from .authentication import ServiceClientBasicAuthentication, ServicePrincipal
from .errors import InvalidClient, InvalidRequest, UnsupportedGrantType
from .models import AdminAuditLog, ServiceClient, UserTokenRevocation
from .tokens import SSOServiceToken, issue_service_token, secret_generation, service_token_ttl_seconds

FEED_LIMIT = 500


def load_service_token(raw: str) -> tuple[SSOServiceToken, ServiceClient] | None:
    """A valid service token whose client is still active and was not rotated after ``iat``; else None."""
    try:
        token = SSOServiceToken(raw)
    except (TokenError, TypeError, ValueError, OverflowError):
        return None
    client = ServiceClient.objects.filter(client_id=token.get("client_id"), is_active=True).first()
    if client is None or token.get("sub") != f"svc:{client.client_id}":
        return None
    if token.get("rot") != secret_generation(client):  # issued under an older (rotated) secret
        return None
    return token, client


class ServiceTokenAuthentication(authentication.BaseAuthentication):
    """``Authorization: Bearer <service token>`` (``token_type=service``)."""

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).split()
        if not header or header[0].lower() != b"bearer":
            return None
        if len(header) != 2:
            raise exceptions.AuthenticationFailed("Invalid Authorization header.")
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
        if not client_id:
            return None
        return self.cache_format % {"scope": self.scope, "ident": client_id}


class ServiceTokenView(APIView):
    authentication_classes = [ServiceClientBasicAuthentication]
    throttle_classes = [ServiceTokenThrottle]

    def post(self, request):
        if not isinstance(request.user, ServicePrincipal):
            raise InvalidClient()
        if not isinstance(request.data, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        if request.data.get("grant_type") != "client_credentials":
            raise UnsupportedGrantType()
        token = issue_service_token(request.user.client)
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
        for row in (AdminAuditLog.objects.filter(action="user.delete", result="ok", ts__gt=since)
                    .order_by("ts")[:FEED_LIMIT]):
            try:
                uid = int(row.target_id)
            except ValueError:
                continue
            events.append({"id": uid, "username": (row.before or {}).get("username", ""), "event": "deleted",
                           "at": row.ts})
        # a user suspended then deleted shows both events; deleted users have no revocation row any more
        still = set(User.objects.filter(pk__in=[e["id"] for e in events if e["event"] == "deleted"])
                    .values_list("pk", flat=True))
        events = [e for e in events if not (e["event"] == "deleted" and e["id"] in still)]
        events.sort(key=lambda e: e["at"])
        events = events[:FEED_LIMIT]
        next_since = _iso(events[-1]["at"]) if events else _iso(since)
        return Response({"users": [{**e, "at": _iso(e["at"])} for e in events], "next_since": next_since},
                        headers={"Cache-Control": "no-store"})
