"""Client-IP token binding (design v1.2 §4.2, decisions 1-3).

``SSO_IP_BINDING_MODE``:
* ``NOIP`` (default): no ``cip`` claim, no check.
* ``WARNING``: ``cip`` issued; a mismatch (or a missing / unparseable IP) is allowed and logged (``ip_mismatch``).
* ``ENFORCE``: ``cip`` issued; a mismatch makes introspect answer inactive and refresh 401, and revokes the
  session (``sid``).

``cip = base64url_nopad(HMAC-SHA256(SSO_IP_BINDING_KEY, canonical_ip))``: keyed so that the 2^32 IPv4 space
cannot be brute-forced from a token. Only user logins are bound (the IP is the end user's, also when a
ServiceClient logs in on a browser's behalf with ``client_ip``); service credentials are never bound
(ECOSYSTEM-INTEGRATION §4.1).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging

from django.conf import settings

from .clientip import normalize_ip

CIP_CLAIM = "cip"
MODES = ("NOIP", "WARNING", "ENFORCE")
logger = logging.getLogger("sso.auth")


def mode() -> str:
    return settings.SSO_IP_BINDING_MODE


def binding_enabled() -> bool:
    return mode() != "NOIP"


def cip_for(ip: str | None) -> str | None:
    ip = normalize_ip(ip)
    if ip is None:
        return None
    mac = hmac.new(settings.SSO_IP_BINDING_KEY, ip.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def ip_matches(token_cip: str | None, ip: str | None) -> bool | None:
    """None: no check (NOIP, or a token without ``cip``). False also for a missing / unparseable IP."""
    if not binding_enabled() or not token_cip:
        return None
    expected = cip_for(ip)
    return expected is not None and hmac.compare_digest(expected, str(token_cip))


def log_mismatch(where: str, *, user_id, ip: str | None, client_id: str | None = None) -> None:
    event = {"event": "ip_mismatch", "where": where, "mode": mode(), "user_id": user_id, "ip": ip}
    if client_id:
        event["client_id"] = client_id
    logger.warning(json.dumps(event, sort_keys=True))
