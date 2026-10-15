"""Admin audit trail (DESIGN-v1.3a §8): one ``sso_adminauditlog`` row per change, plus a ``sso.admin`` JSON line.

``record()`` must be called inside the transaction of the change, so the row and the change commit or roll back
together. ``record_denied()`` writes in its own transaction (the change itself was rolled back or never made).
Never pass secrets, passwords or tokens in ``before``/``after``.
"""
from __future__ import annotations

import json
import logging
import re
import uuid

from django.db import transaction

from .models import AdminAuditLog

logger = logging.getLogger("sso.admin")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def request_id(request) -> str:
    """``X-Request-ID`` if well-formed, else a new UUID4; memoised on the request."""
    django_request = getattr(request, "_request", request)
    rid = getattr(django_request, "_sso_request_id", None)
    if rid is None:
        given = django_request.headers.get("X-Request-ID", "")
        rid = given if _REQUEST_ID_RE.fullmatch(given or "") else str(uuid.uuid4())
        django_request._sso_request_id = rid
    return rid


def actor_of(request) -> tuple[str, str]:
    from .authentication import ServicePrincipal

    user = getattr(request, "user", None)
    if isinstance(user, ServicePrincipal):
        return "service", f"svc:{user.client_id}"
    if user is not None and getattr(user, "pk", None) is not None:
        return "user", str(user.pk)
    return "system", ""


def _emit(row: AdminAuditLog) -> None:
    logger.info(json.dumps({
        "event": "admin_audit", "action": row.action, "actor": f"{row.actor_type}:{row.actor_id}",
        "ip": row.actor_ip, "target": f"{row.target_type}:{row.target_id}", "result": row.result,
        "stepup": row.stepup, "request_id": row.request_id}, sort_keys=True, default=str))


def _build(request, action, target_type, target_id, before, after, result, stepup) -> AdminAuditLog:
    from .logs import client_ip

    actor_type, actor_id = actor_of(request)
    return AdminAuditLog(actor_type=actor_type, actor_id=actor_id, actor_ip=client_ip(request) or "",
                         action=action, target_type=target_type, target_id=str(target_id or "")[:191],
                         before=before, after=after, request_id=request_id(request), result=result,
                         stepup=bool(stepup))


def record(request, action: str, target_type: str = "", target_id="", *, before=None, after=None,
           stepup: bool = False) -> AdminAuditLog:
    row = _build(request, action, target_type, target_id, before, after, "ok", stepup)
    row.save()
    transaction.on_commit(lambda: _emit(row))
    return row


def record_denied(request, action: str, target_type: str = "", target_id="", *, reason: str = "",
                  stepup: bool = False) -> None:
    """Best effort: a failing audit write must not mask the original error."""
    row = _build(request, action, target_type, target_id, None, {"reason": reason} if reason else None,
                 "denied", stepup)
    try:
        with transaction.atomic():
            row.save()
    except Exception:  # noqa: BLE001
        logger.exception("audit write failed for denied %s", action)
        return
    _emit(row)
