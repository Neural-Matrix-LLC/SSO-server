"""Trusted end-user IP for server-side callers (docs/sso-integration-design.md v1.1 item 4, v1.2).

An application that logs users in server-side (llm-wiki-svc's /login) calls ``/api/v1/auth/login`` and
``/refresh`` from its own address, so the per-IP throttle would count every user of that app as one
client. Such an app authenticates as a registered, active ``ServiceClient`` with HTTP Basic and adds
``"client_ip": "<the browser's IP>"`` to the JSON body; then the IP throttle and the login log use
``client_ip``. Without an ``Authorization: Basic`` header the field is ignored. v1.2 (C-19, Q-28):

* a Basic header that does not authenticate an active ServiceClient -> 401 ``invalid_client``
  (no silent fallback to the caller's address);
* valid credentials but a ``client_ip`` that is not an IP address -> 400 ``invalid_request``;
* valid credentials without ``client_ip`` -> the caller's address, as before.

The per-username throttle is unchanged either way.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import logging

from .errors import InvalidClient, InvalidRequest
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

    Raises InvalidClient / InvalidRequest as described in the module docstring. ``request`` is a
    DRF Request (body parsed) or a Django HttpRequest. A successful result is cached per request.
    """
    django_request = getattr(request, "_request", request)
    cached = getattr(django_request, _ATTR, _MISSING)
    if cached is not _MISSING:
        return cached
    result: str | None = None
    if django_request.META.get("HTTP_AUTHORIZATION", "").lower().startswith("basic"):
        client = _basic_client(django_request)
        if client is None:
            logger.warning('{"event": "service_client_auth", "result": "invalid_client"}')
            raise InvalidClient()
        data = getattr(request, "data", None)
        raw = data.get("client_ip") if isinstance(data, dict) else None
        if raw is not None:
            try:
                if not isinstance(raw, str):
                    raise ValueError(raw)
                result = str(ipaddress.ip_address(raw.strip()))
            except ValueError:
                logger.warning('{"event": "service_client_auth", "result": "bad_client_ip", '
                               f'"client_id": "{client.client_id}"}}')
                raise InvalidRequest("client_ip must be an IP address.") from None
    setattr(django_request, _ATTR, result)
    return result
