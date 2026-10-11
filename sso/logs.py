"""Structured security logging (addendum B.13): one JSON line per login attempt. No secrets."""
from __future__ import annotations

import json
import logging

from rest_framework.throttling import BaseThrottle

logger = logging.getLogger("sso.auth")


def client_ip(request) -> str:
    """Client IP honouring REST_FRAMEWORK['NUM_PROXIES'] (nginx sets X-Forwarded-For).

    For a ServiceClient calling server-side with ``client_ip`` (sso/delegation.py), that end-user IP.
    """
    from .delegation import delegated_client_ip

    return delegated_client_ip(request) or BaseThrottle().get_ident(request)


def log_login(request, username: str, result: str, *, client: str | None = None, user_id: int | None = None) -> None:
    event = {
        "event": "login",
        "result": result,
        "username": (username or "")[:254],
        "ip": client_ip(request),
    }
    if client:
        event["client"] = client
    if user_id is not None:
        event["user_id"] = user_id
    level = logging.INFO if result == "success" else logging.WARNING
    logger.log(level, json.dumps(event, ensure_ascii=True, sort_keys=True))


def log_token_event(request, event: str, result: str, *, user_id: int | None = None) -> None:
    payload = {"event": event, "result": result, "ip": client_ip(request)}
    if user_id is not None:
        payload["user_id"] = user_id
    logger.info(json.dumps(payload, ensure_ascii=True, sort_keys=True))


def log_stored_hash_error(request, username: str) -> None:
    """The user's stored password hash could not be parsed. Logs neither the hash nor the password."""
    payload = {"event": "login", "result": "stored_hash_invalid", "username": (username or "")[:254],
               "ip": client_ip(request)}
    logger.error(json.dumps(payload, ensure_ascii=True, sort_keys=True))
