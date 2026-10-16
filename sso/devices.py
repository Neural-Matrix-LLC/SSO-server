"""v1.3b device clients of the local broker gateway (DESIGN-v1.3b §3-§4, §7).

A device is a ``ServiceClient(kind="device")`` owned by a user, with an Ed25519 public key and no secret. It gets
5-minute device tokens with an RFC 7523 client assertion (``private_key_jwt``, EdDSA). Owner suspended → devices
deactivated (they stay off after a reactivation); owner deleted → devices deleted (CASCADE).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.utils import timezone

from .errors import InvalidClient, ServiceUnavailable
from .models import ServiceClient

logger = logging.getLogger("sso.auth")
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CLOCK_SKEW = 60


def parse_public_key(value) -> tuple[str, str]:
    """Ed25519 public key as PEM or base64url raw 32 bytes → (PEM, sha256 hex of the raw key). ValueError if bad."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        raise ValueError("public_key: Ed25519 public key (PEM or base64url raw 32 bytes) required")
    value = value.strip()
    try:
        if value.startswith("-----BEGIN"):
            key = serialization.load_pem_public_key(value.encode("ascii"))
        else:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("public_key: not a valid Ed25519 public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public_key: must be an Ed25519 key")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return pem, hashlib.sha256(raw).hexdigest()


def new_device_id() -> str:
    return "dev_" + secrets.token_hex(8)


def create_device(owner, name: str, pem: str, fingerprint: str, app_codename: str | None) -> ServiceClient:
    dev = ServiceClient(client_id=new_device_id(), name=f"device {name}"[:200], kind="device", owner=owner,
                        device_name=name, public_key=pem, public_key_fingerprint=fingerprint,
                        app_codename=app_codename)
    dev.client_secret_hash = make_password(None)  # unusable: Basic auth never works for a device
    dev.save()
    return dev


def assertion_audience() -> str:
    return settings.SSO_ISSUER.rstrip("/") + "/api/v1/auth/service-token"


def verify_assertion(raw: str) -> ServiceClient:
    """Verify a device's client assertion. Any failure → 401 invalid_client (no detail)."""
    try:
        unverified = jwt.decode(raw, options={"verify_signature": False})
        header = jwt.get_unverified_header(raw)
    except jwt.PyJWTError:
        raise InvalidClient() from None
    if header.get("alg") != "EdDSA" or not isinstance(unverified.get("iss"), str):
        raise InvalidClient()
    dev = (ServiceClient.objects.select_related("owner")
           .filter(client_id=unverified["iss"], kind="device", is_active=True).first())
    if dev is None or not dev.public_key or dev.owner is None or not dev.owner.is_active:
        raise InvalidClient()
    try:
        key = serialization.load_pem_public_key(dev.public_key.encode("ascii"))
        claims = jwt.decode(raw, key, algorithms=["EdDSA"], audience=assertion_audience(), issuer=dev.client_id,
                            options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"]}, leeway=CLOCK_SKEW)
    except (jwt.PyJWTError, ValueError):
        raise InvalidClient() from None
    now = time.time()
    if (claims.get("sub") != dev.client_id or not isinstance(claims.get("jti"), str) or len(claims["jti"]) > 128
            or claims["iat"] > now + CLOCK_SKEW
            or claims["exp"] - claims["iat"] > settings.SSO_DEVICE_ASSERTION_MAX_AGE):
        raise InvalidClient()
    ttl = max(1, int(claims["exp"] - now) + CLOCK_SKEW)
    try:
        fresh = cache.add(f"dev_jti:{dev.client_id}:{claims['jti']}", 1, ttl)
    except Exception:  # noqa: BLE001 - cannot check replay: fail closed
        raise ServiceUnavailable("Replay check unavailable.") from None
    if not fresh:
        logger.warning(json.dumps({"event": "device_assertion_replay", "client_id": dev.client_id}))
        raise InvalidClient()
    ServiceClient.objects.filter(pk=dev.pk).update(last_used=timezone.now())
    return dev


def deactivate_owner_devices(user) -> int:
    return ServiceClient.objects.filter(owner=user, kind="device", is_active=True).update(is_active=False)


def ser_device(d: ServiceClient) -> dict:
    iso = lambda dt: dt.isoformat().replace("+00:00", "Z") if dt else None  # noqa: E731
    return {"client_id": d.client_id, "kind": d.kind, "device_name": d.device_name,
            "owner": str(d.owner_id) if d.owner_id else None, "app_codename": d.app_codename,
            "is_active": d.is_active, "created": iso(d.created), "last_used": iso(d.last_used),
            "public_key_fingerprint": d.public_key_fingerprint}


# --------------------------------------------------------------------------- views
from django.db import transaction  # noqa: E402
from rest_framework import status  # noqa: E402
from rest_framework.response import Response  # noqa: E402
from rest_framework.views import APIView  # noqa: E402

from .authentication import ServicePrincipal, SSOAccessTokenAuthentication  # noqa: E402
from .errors import Conflict, Forbidden, InvalidRequest, NotFound, TokenInvalid  # noqa: E402


class DevicesView(APIView):
    """POST: a registering service on behalf of the user (pairing). GET: the user's own devices."""

    def get_authenticators(self):
        from .service_auth import ServiceTokenAuthentication

        return [ServiceTokenAuthentication(), SSOAccessTokenAuthentication()]

    def get_authenticate_header(self, request):
        return 'Bearer realm="sso-devices"'

    def post(self, request):
        from . import audit
        from .onbehalf import from_headers

        principal = request.user
        if not isinstance(principal, ServicePrincipal):
            raise InvalidClient("A registering service token is required.")
        client = principal.client
        if client.kind != "service" or not client.can_register_devices:
            raise Forbidden("This service client may not register devices.")
        user, _token, _ip, _match = from_headers(request, client.client_id)
        if client.app_codename:
            from application.permissions import user_app_perms

            if f"application.{client.app_codename}" not in user_app_perms(user):
                raise Forbidden(f"The user lacks application.{client.app_codename}.")
        data = request.data if isinstance(request.data, dict) else None
        if data is None:
            raise InvalidRequest("Request body must be a JSON object.")
        name = data.get("device_name")
        if not isinstance(name, str) or not name.strip() or len(name) > 100:
            raise InvalidRequest("Missing or malformed fields: device_name.")
        try:
            pem, fp = parse_public_key(data.get("public_key"))
        except ValueError as exc:
            raise InvalidRequest(str(exc)) from None
        with transaction.atomic():
            active = ServiceClient.objects.select_for_update().filter(owner=user, kind="device", is_active=True)
            if active.count() >= settings.SSO_DEVICE_MAX_PER_USER:
                raise Conflict(f"At most {settings.SSO_DEVICE_MAX_PER_USER} active devices per user.")
            if ServiceClient.objects.filter(public_key_fingerprint=fp).exists():
                raise Conflict("This public key is already registered.")
            dev = create_device(user, name.strip(), pem, fp, client.app_codename)
            audit.record(request, "device.create", "device", dev.client_id,
                         after={"owner": str(user.pk), "device_name": dev.device_name, "via": client.client_id,
                                "fingerprint": fp})
        body = ser_device(dev)
        body["token_endpoint"] = assertion_audience()
        body["assertion_audience"] = assertion_audience()
        return Response(body, status=status.HTTP_201_CREATED)

    def get(self, request):
        user = request.user
        if user is None or isinstance(user, ServicePrincipal):
            raise TokenInvalid()
        return Response({"results": [ser_device(d) for d in ServiceClient.objects.filter(owner=user, kind="device")]})


class DeviceView(APIView):
    authentication_classes = [SSOAccessTokenAuthentication]

    def get_authenticate_header(self, request):
        return 'Bearer realm="sso-devices"'

    def delete(self, request, client_id):
        from . import audit

        user = request.user
        if user is None:
            raise TokenInvalid()
        dev = ServiceClient.objects.filter(client_id=client_id, kind="device", owner=user).first()
        if dev is None:
            raise NotFound("Unknown device.")
        with transaction.atomic():
            before = ser_device(dev)
            dev.delete()
            audit.record(request, "device.delete", "device", client_id, before=before)
        return Response(status=status.HTTP_204_NO_CONTENT)
