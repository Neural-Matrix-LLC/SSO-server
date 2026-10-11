"""Trusted end-user IP for server-side callers (docs/sso-integration-design.md v1.1 item 4).

An application that logs users in server-side (llm-wiki-svc's /login) calls ``/api/v1/auth/login`` and
``/refresh`` from its own address, so the per-IP throttle would count every user of that app as one
client. Such an app may authenticate as a registered, active ``ServiceClient`` with HTTP Basic and add
``"client_ip": "<the browser's IP>"`` to the JSON body. Only then do the IP throttle and the login log
use ``client_ip``; without valid Basic auth the field is ignored (and an invalid Basic header is
ignored too, so a mistyped secret degrades to "throttled as the app's own IP", never to an open door).
The per-username throttle is unchanged either way.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import logging

from .models import ServiceClient

logger = logging.getLogger("sso.auth")
_ATTR = "_sso_delegated_ip"
_MISSING = object()


def _basic_client(request) -> ServiceClient | None:
    """The active ServiceClient named by a valid ``Authorization: Basic`` header, else None. Never raises."""
    from .authentication import _dummy_check

    header = request.META.get("HTTP_AUTHORIZATION", "").split()
    if len(header) != 2 or header[0].lower() != "basic":
        return None
    try:
        client_id, sep, secret = base64.b64decode(header[1], validate=True).decode("utf-8").partition(":")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not sep or not client_id:
        return None
    client = ServiceClient.objects.filter(client_id=client_id, is_active=True).first()
    if client is None:
        _dummy_check(secret)
        return None
    return client if client.check_secret(secret) else None


def delegated_client_ip(request) -> str | None:
    """``client_ip`` from the body when the caller is an authenticated ServiceClient, else None.

    ``request`` is a DRF Request (body parsed) or a Django HttpRequest. Cached per request.
    """
    django_request = getattr(request, "_request", request)
    cached = getattr(django_request, _ATTR, _MISSING)
    if cached is not _MISSING:
        return cached
    result: str | None = None
    if django_request.META.get("HTTP_AUTHORIZATION", "").lower().startswith("basic "):
        data = getattr(request, "data", None)
        raw = data.get("client_ip") if isinstance(data, dict) else None
        client = _basic_client(django_request)
        if client is None:
            logger.warning('{"event": "service_client_auth", "result": "invalid", "note": "client_ip ignored"}')
        elif isinstance(raw, str) and raw.strip():
            try:
                result = str(ipaddress.ip_address(raw.strip()))
            except ValueError:
                logger.warning('{"event": "service_client_auth", "result": "bad_client_ip", '
                               f'"client_id": "{client.client_id}"}}')
    setattr(django_request, _ATTR, result)
    return result
