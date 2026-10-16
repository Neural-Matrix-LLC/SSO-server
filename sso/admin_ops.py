"""Admin domain layer shared by the REST API (sso/admin_api.py) and the admin web UI (adminui/), v1.3d.

DESIGN-v1.3d-admin-ui.md §3: every admin rule lives here exactly once — guards (self action, last admin,
code-defined permissions), step-up, audit (one row in the same transaction as the change) and webhook events.
Callers pass ``ctx`` (a DRF ``Request`` or a Django ``HttpRequest``; ``ctx.user`` is the acting admin or a
``ServicePrincipal``) and plain Python values. Errors are the typed ``sso.errors`` exceptions: the API maps them to
JSON, the UI to form errors / flash messages.

Step-up: ``require_stepup(ctx, …)`` asks ``sso.stepup.is_valid(ctx)``, which checks the ``X-SSO-Reauth`` header
for API calls and the session-bound proof for UI requests (``sso.stepup.UI_ATTR``).
"""
from __future__ import annotations

import re
from datetime import timezone as dt_timezone

from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import URLValidator
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from application.importer import ImportError_, VersionTooOld, import_permissions
from application.models import CODENAME_RE, Application, ApplicationPermissionRecord
from application.permissions import (PREFIX, anchor_content_type, app_permissions, code_defined_codenames,
                                     delete_permission, ensure_permission, user_app_perms, validate_codename)

from . import audit, stepup
from .authentication import ServicePrincipal
from .errors import (AdminForbidden, Conflict, InvalidCredentials, InvalidRequest, LastAdmin, NotFound,
                     SelfActionForbidden, VersionConflict)
from .models import AdminAuditLog, ServiceClient
from .revocation import revoke_user_tokens
from .serializers import check_credentials
from .tokens import service_client_perms

ADMIN_CODENAME = "sso_admin"
CLIENT_ID_RE = r"^[-a-zA-Z0-9_]+$"


# --------------------------------------------------------------------------- who is an admin
def admin_permission() -> Permission | None:
    return Permission.objects.filter(content_type=anchor_content_type(), codename=ADMIN_CODENAME).first()


def admins_qs():
    perm = admin_permission()
    q = Q(is_superuser=True)
    if perm is not None:
        q |= Q(user_permissions=perm) | Q(groups__permissions=perm)
    # active + is_staff + (sso_admin or superuser): Thomas 2026-10-15, so Django admin, API and UI agree on staff
    return User.objects.filter(is_active=True, is_staff=True).filter(q).distinct()


def is_sso_admin(user) -> bool:
    if user is None or not getattr(user, "pk", None) or isinstance(user, ServicePrincipal):
        return False
    return admins_qs().filter(pk=user.pk).exists()


def check_invariants(actor) -> None:
    """After a change, inside its transaction: the actor is still an admin, and some admin remains."""
    if isinstance(actor, ServicePrincipal):
        if not admins_qs().exists():
            raise LastAdmin()
        return
    if not is_sso_admin(actor):
        raise SelfActionForbidden("You cannot remove your own SSO administrator access.")
    if not admins_qs().exists():  # pragma: no cover - the actor is one
        raise LastAdmin()


def require_stepup(ctx, action, target_type="", target_id="") -> None:
    if not stepup.is_valid(ctx):
        audit.record_denied(ctx, action, target_type, target_id, reason="reauth_required", stepup=True)
        raise stepup.reauth_error(ctx)


# --------------------------------------------------------------------------- small helpers
def bool_param(value) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if str(value).lower() in ("1", "true", "yes", "on"):
        return True
    if str(value).lower() in ("0", "false", "no", "off"):
        return False
    raise InvalidRequest("Boolean query parameters take true or false.")


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def str_field(data, key, max_len, *, required=False, allow_blank=True):
    if key not in data:
        if required:
            raise InvalidRequest(f"Missing or malformed fields: {key}.")
        return None
    value = data[key]
    if not isinstance(value, str) or len(value) > max_len or (not allow_blank and not value.strip()):
        raise InvalidRequest(f"Missing or malformed fields: {key}.")
    return value.strip() if not allow_blank else value


def parse_since(value):
    since = parse_datetime(value.replace("Z", "+00:00")) if isinstance(value, str) else None
    if since is None:
        raise InvalidRequest("since must be an ISO 8601 timestamp.")
    if timezone.is_naive(since):
        since = since.replace(tzinfo=dt_timezone.utc)
    return since


def _codename(raw: str) -> str:
    code = raw[len(PREFIX):] if raw.startswith(PREFIX) else raw
    try:
        return validate_codename(code)
    except ValueError:
        raise NotFound("Unknown permission.") from None


def get_permission(raw: str) -> Permission:
    perm = app_permissions().filter(codename=_codename(raw)).first()
    if perm is None:
        raise NotFound("Unknown permission.")
    return perm


def validate_pw(password, user):
    try:
        validate_password(password, user)
    except DjangoValidationError as exc:
        raise InvalidRequest("Password rejected: " + " ".join(exc.messages)) from None


# --------------------------------------------------------------------------- serializers (API shapes)
def ser_user(u: User) -> dict:
    return {"id": u.pk, "username": u.username, "email": u.email or "", "first_name": u.first_name,
            "last_name": u.last_name, "is_active": u.is_active, "is_staff": u.is_staff,
            "is_superuser": u.is_superuser, "groups": sorted(g.name for g in u.groups.all()),
            "perms": user_app_perms(u) if u.is_active else granted_perms(u),
            "last_login": iso(u.last_login), "date_joined": iso(u.date_joined)}


def granted_perms(u: User) -> list[str]:
    perms = Permission.objects.filter(content_type__app_label="application").filter(
        Q(user=u) | Q(group__user=u))
    return sorted({PREFIX + c for c in perms.values_list("codename", flat=True)})


def ser_group(g: Group) -> dict:
    return {"id": g.pk, "name": g.name,
            "perms": sorted(PREFIX + c for c in g.permissions.filter(
                content_type__app_label="application").values_list("codename", flat=True)),
            "members": sorted(g.user_set.values_list("pk", flat=True))}


def ser_permission(p: Permission, rec: ApplicationPermissionRecord | None = None, counts=True) -> dict:
    if rec is None:
        rec = ApplicationPermissionRecord.objects.filter(codename=p.codename).first()
    out = {"codename": p.codename, "perm": PREFIX + p.codename, "name": p.name,
           "description": rec.description if rec else "", "app_codename": rec.app_codename if rec else None,
           "deprecated": bool(rec and rec.deprecated_at), "deprecated_at": iso(rec.deprecated_at) if rec else None,
           "code_defined": p.codename in code_defined_codenames()}
    if counts:
        out["users"] = p.user_set.count()
        out["groups"] = p.group_set.count()
    return out


def ser_service(c: ServiceClient) -> dict:
    return {"client_id": c.client_id, "name": c.name, "app_codename": c.app_codename, "notify_url": c.notify_url,
            "is_active": c.is_active, "perms": service_client_perms(c), "created": iso(c.created),
            "secret_rotated_at": iso(c.secret_rotated_at), "kind": c.kind, "can_delegate": c.can_delegate,
            "can_register_devices": c.can_register_devices, "notify_events": c.notify_events or [],
            "has_notify_secret": bool(c.notify_secret_enc)}


def ser_audit(a: AdminAuditLog) -> dict:
    return {"id": a.pk, "ts": iso(a.ts), "actor_type": a.actor_type, "actor_id": a.actor_id,
            "actor_ip": a.actor_ip, "action": a.action, "target_type": a.target_type, "target_id": a.target_id,
            "before": a.before, "after": a.after, "request_id": a.request_id, "result": a.result,
            "stepup": a.stepup, "channel": a.channel}


def snap_user(u: User) -> dict:
    return {"username": u.username, "email": u.email, "first_name": u.first_name, "last_name": u.last_name,
            "is_active": u.is_active, "groups": sorted(g.name for g in u.groups.all())}


def ser_app(a: Application, with_perms=False) -> dict:
    recs = ApplicationPermissionRecord.objects.filter(app_codename=a.app_codename)
    out = {"app_codename": a.app_codename, "name": a.name, "description": a.description, "version": a.version,
           "updated": iso(a.updated), "permission_count": recs.count(),
           "deprecated_count": recs.filter(deprecated_at__isnull=False).count()}
    if with_perms:
        perms = {p.codename: p for p in app_permissions().filter(codename__in=[r.codename for r in recs])}
        out["permissions"] = [ser_permission(perms[r.codename], r) for r in recs if r.codename in perms]
    return out


def ser_event(e) -> dict:
    return {"id": e.pk, "type": e.type, "time": iso(e.created), "data": e.data}


def ser_delivery(d) -> dict:
    return {"id": d.pk, "event_id": d.event_id, "event_type": d.event.type, "client_id": d.client.client_id,
            "status": d.status, "attempts": d.attempts, "next_attempt_at": iso(d.next_attempt_at),
            "last_status": d.last_status, "last_error": d.last_error, "delivered_at": iso(d.delivered_at)}


# --------------------------------------------------------------------------- step-up (API token flavour)
def reauth(ctx, password) -> tuple[str, int]:
    if not isinstance(password, str) or not password or len(password) > 4096:
        raise InvalidRequest("Missing or malformed fields: password.")
    django_request = getattr(ctx, "_request", ctx)
    ok = check_credentials(django_request, ctx.user.get_username(), password)
    if ok is None or ok.pk != ctx.user.pk:
        audit.record_denied(ctx, "reauth", "user", ctx.user.pk, reason="invalid_credentials")
        raise InvalidCredentials("Password is incorrect.")
    with transaction.atomic():
        raw, ttl = stepup.issue(ctx)
        audit.record(ctx, "reauth", "user", ctx.user.pk)
    return raw, ttl


# --------------------------------------------------------------------------- users
def get_user(pk) -> User:
    user = User.objects.filter(pk=pk).first()
    if user is None:
        raise NotFound("Unknown user.")
    return user


def users_qs(q="", active=None, group=None, staff=None):
    qs = User.objects.all().order_by("username").prefetch_related("groups")
    q = (q or "").strip()
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(email__icontains=q) | Q(first_name__icontains=q)
                       | Q(last_name__icontains=q))
    if active is not None:
        qs = qs.filter(is_active=active)
    if group:
        qs = qs.filter(groups__name=group)
    if staff is not None:
        qs = qs.filter(is_staff=staff)
    return qs.distinct()


def create_user(ctx, data: dict) -> User:
    username = str_field(data, "username", 150, required=True, allow_blank=False)
    email = str_field(data, "email", 254) or ""
    first = str_field(data, "first_name", 150) or ""
    last = str_field(data, "last_name", 150) or ""
    password = data.get("password")
    is_active = data.get("is_active", True)
    is_staff = data.get("is_staff", False)
    groups = data.get("groups", [])
    if (not isinstance(is_active, bool) or not isinstance(is_staff, bool) or not isinstance(groups, list)
            or not all(isinstance(g, str) for g in groups)):
        raise InvalidRequest("Missing or malformed fields: is_active, groups.")
    if is_staff and not getattr(ctx.user, "is_superuser", False):
        raise AdminForbidden("Only a superuser can create staff accounts.")
    user = User(username=username, email=email, first_name=first, last_name=last, is_active=is_active,
                is_staff=is_staff)
    try:
        user.full_clean(exclude=["password"], validate_unique=False)
    except DjangoValidationError as exc:
        raise InvalidRequest("Invalid fields: " + ", ".join(sorted(exc.message_dict))) from None
    if password is not None:
        if not isinstance(password, str):
            raise InvalidRequest("Missing or malformed fields: password.")
        validate_pw(password, user)
    group_objs = list(Group.objects.filter(name__in=groups))
    if len(group_objs) != len(set(groups)):
        raise InvalidRequest("Unknown group in groups.")
    if User.objects.filter(username__iexact=username).exists():
        raise Conflict("A user with this username exists.")
    with transaction.atomic():
        if password is not None:
            user.set_password(password)
        else:
            user.set_unusable_password()
        try:
            user.save()
        except IntegrityError:
            raise Conflict("A user with this username exists.") from None
        user.groups.set(group_objs)
        audit.record(ctx, "user.create", "user", user.pk, after=snap_user(user))
    return user


def update_user(ctx, pk, data: dict) -> User:
    unknown = set(data) - {"email", "first_name", "last_name"}
    if unknown:
        raise InvalidRequest("Not editable here: " + ", ".join(sorted(unknown)) + ".")
    user = get_user(pk)
    before = snap_user(user)
    for key, max_len in (("email", 254), ("first_name", 150), ("last_name", 150)):
        value = str_field(data, key, max_len)
        if value is not None:
            setattr(user, key, value)
    try:
        user.full_clean(exclude=["password"], validate_unique=False)
    except DjangoValidationError as exc:
        raise InvalidRequest("Invalid fields: " + ", ".join(sorted(exc.message_dict))) from None
    with transaction.atomic():
        user.save(update_fields=["email", "first_name", "last_name"])
        audit.record(ctx, "user.update", "user", user.pk, before=before, after=snap_user(user))
    return user


def delete_user(ctx, pk) -> None:
    user = get_user(pk)
    if user.pk == ctx.user.pk:
        raise SelfActionForbidden("You cannot delete your own account.")
    require_stepup(ctx, "user.delete", "user", user.pk)
    with transaction.atomic():
        before = snap_user(user)
        revoke_user_tokens(user, None)  # user.deleted is emitted by the post_delete signal
        audit.record(ctx, "user.delete", "user", user.pk, before=before, stepup=True)
        user.delete()
        check_invariants(ctx.user)


def suspend_user(ctx, pk) -> User:
    user = get_user(pk)
    if user.pk == ctx.user.pk:
        raise SelfActionForbidden("You cannot suspend yourself.")
    require_stepup(ctx, "user.suspend", "user", user.pk)
    with transaction.atomic():
        was = user.is_active
        user.is_active = False
        user.save()  # the v1.2a signal revokes every token and session
        if was is False:
            revoke_user_tokens(user, "suspended")
        audit.record(ctx, "user.suspend", "user", user.pk, before={"is_active": was},
                     after={"is_active": False}, stepup=True)
        check_invariants(ctx.user)
    return user


def unsuspend_user(ctx, pk) -> User:
    user = get_user(pk)
    with transaction.atomic():
        was = user.is_active
        user.is_active = True
        user.save()
        audit.record(ctx, "user.unsuspend", "user", user.pk, before={"is_active": was}, after={"is_active": True})
    return user


def logout_all_user(ctx, pk) -> None:
    user = get_user(pk)
    with transaction.atomic():
        revoke_user_tokens(user, "admin")
        audit.record(ctx, "user.logout_all", "user", user.pk)


def set_user_password(ctx, pk, password) -> None:
    user = get_user(pk)
    if not isinstance(password, str) or not password:
        raise InvalidRequest("Missing or malformed fields: password.")
    require_stepup(ctx, "user.set_password", "user", user.pk)
    validate_pw(password, user)
    with transaction.atomic():
        user.set_password(password)
        user.save()  # the password signal revokes and emits token.revoked(password_change)
        audit.record(ctx, "user.set_password", "user", user.pk, after={"password": "changed"}, stepup=True)


def user_permissions(pk) -> dict:
    user = get_user(pk)
    direct = sorted(PREFIX + c for c in user.user_permissions.filter(
        content_type__app_label="application").values_list("codename", flat=True))
    via = {g.name: sorted(PREFIX + c for c in g.permissions.filter(
        content_type__app_label="application").values_list("codename", flat=True))
        for g in user.groups.all()}
    return {"direct": direct, "via_groups": via, "effective": user_app_perms(user)}


def change_user_permission(ctx, pk, codename, grant: bool) -> None:
    user = get_user(pk)
    perm = get_permission(codename)
    action = "user.grant" if grant else "user.revoke"
    is_admin_perm = perm.codename == ADMIN_CODENAME
    if is_admin_perm and not grant and user.pk == ctx.user.pk:
        raise SelfActionForbidden("You cannot remove your own SSO administrator access.")
    if is_admin_perm:
        require_stepup(ctx, action, "user", user.pk)
    with transaction.atomic():
        (user.user_permissions.add if grant else user.user_permissions.remove)(perm)
        audit.record(ctx, action, "user", user.pk, after={"perm": PREFIX + perm.codename}, stepup=is_admin_perm)
        check_invariants(ctx.user)


def admin_group_ids() -> set[int]:
    perm = admin_permission()
    return set(perm.group_set.values_list("pk", flat=True)) if perm else set()


def set_user_groups(ctx, pk, names) -> User:
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise InvalidRequest("Missing or malformed fields: groups.")
    user = get_user(pk)
    groups = list(Group.objects.filter(name__in=names))
    if len(groups) != len(set(names)):
        raise InvalidRequest("Unknown group in groups.")
    old_ids = set(user.groups.values_list("pk", flat=True))
    touches_admin = bool((old_ids ^ {g.pk for g in groups}) & admin_group_ids())
    if touches_admin:
        require_stepup(ctx, "user.groups", "user", user.pk)
    with transaction.atomic():
        before = sorted(user.groups.values_list("name", flat=True))
        user.groups.set(groups)
        audit.record(ctx, "user.groups", "user", user.pk, before={"groups": before},
                     after={"groups": sorted(g.name for g in groups)}, stepup=touches_admin)
        check_invariants(ctx.user)
    return user


# --------------------------------------------------------------------------- groups
def get_group(pk) -> Group:
    group = Group.objects.filter(pk=pk).first()
    if group is None:
        raise NotFound("Unknown group.")
    return group


def groups_qs(q=""):
    qs = Group.objects.all().order_by("name")
    q = (q or "").strip()
    return qs.filter(name__icontains=q) if q else qs


def create_group(ctx, name) -> Group:
    name = str_field({"name": name}, "name", 150, required=True, allow_blank=False)
    if Group.objects.filter(name=name).exists():
        raise Conflict("A group with this name exists.")
    with transaction.atomic():
        group = Group.objects.create(name=name)
        audit.record(ctx, "group.create", "group", group.pk, after={"name": name})
    return group


def rename_group(ctx, pk, name) -> Group:
    group = get_group(pk)
    name = str_field({"name": name}, "name", 150, required=True, allow_blank=False)
    if Group.objects.filter(name=name).exclude(pk=group.pk).exists():
        raise Conflict("A group with this name exists.")
    with transaction.atomic():
        before = group.name
        group.name = name
        group.save()
        audit.record(ctx, "group.update", "group", group.pk, before={"name": before}, after={"name": name})
    return group


def delete_group(ctx, pk) -> None:
    group = get_group(pk)
    require_stepup(ctx, "group.delete", "group", group.pk)
    with transaction.atomic():
        before = ser_group(group)
        from .webhooks import emit

        # Django deletes the M2M rows without m2m_changed: tell services the members lost the group
        for uid in before["members"]:
            emit("permission.changed", sub=str(uid), group=group.name, granted=False)
        group.delete()
        audit.record(ctx, "group.delete", "group", pk, before=before, stepup=True)
        check_invariants(ctx.user)


def set_group_members(ctx, pk, ids) -> Group:
    group = get_group(pk)
    if not isinstance(ids, list) or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
        raise InvalidRequest("Missing or malformed fields: user_ids.")
    users = list(User.objects.filter(pk__in=ids))
    if len(users) != len(set(ids)):
        raise InvalidRequest("Unknown user id in user_ids.")
    is_admin_group = group.pk in admin_group_ids()
    if is_admin_group:
        require_stepup(ctx, "group.members", "group", group.pk)
    with transaction.atomic():
        before = sorted(group.user_set.values_list("pk", flat=True))
        group.user_set.set(users)
        audit.record(ctx, "group.members", "group", group.pk, before={"members": before},
                     after={"members": sorted(ids)}, stepup=is_admin_group)
        check_invariants(ctx.user)
    return group


def change_group_permission(ctx, pk, codename, grant: bool) -> None:
    group = get_group(pk)
    perm = get_permission(codename)
    action = "group.grant" if grant else "group.revoke"
    is_admin_perm = perm.codename == ADMIN_CODENAME
    if is_admin_perm:
        require_stepup(ctx, action, "group", group.pk)
    with transaction.atomic():
        (group.permissions.add if grant else group.permissions.remove)(perm)
        audit.record(ctx, action, "group", group.pk, after={"perm": PREFIX + perm.codename}, stepup=is_admin_perm)
        check_invariants(ctx.user)


# --------------------------------------------------------------------------- permissions
def permissions_list(app=None, deprecated=None) -> list:
    """[(Permission, ApplicationPermissionRecord|None)] filtered by app / deprecated."""
    records = {r.codename: r for r in ApplicationPermissionRecord.objects.all()}
    out = []
    for p in app_permissions():
        rec = records.get(p.codename)
        if app and (rec is None or rec.app_codename != app):
            continue
        if deprecated is not None and bool(rec and rec.deprecated_at) != deprecated:
            continue
        out.append((p, rec))
    return out


def create_permission(ctx, data: dict) -> Permission:
    code = str_field(data, "codename", 63, required=True, allow_blank=False)
    name = str_field(data, "name", 255, required=True, allow_blank=False)
    desc = str_field(data, "description", 1000) or ""
    try:
        validate_codename(code)
    except ValueError:
        raise InvalidRequest(f"codename must match {CODENAME_RE}") from None
    if app_permissions().filter(codename=code).exists():
        raise Conflict("This permission exists.")
    with transaction.atomic():
        perm, _ = ensure_permission(code, name)
        ApplicationPermissionRecord.objects.filter(codename=code).update(description=desc)
        audit.record(ctx, "permission.create", "permission", code, after={"name": name, "description": desc})
    return perm


def update_permission(ctx, codename, data: dict) -> Permission:
    perm = get_permission(codename)
    unknown = set(data) - {"name", "description"}
    if unknown:
        raise Conflict("Only name and description can be changed (codename is immutable).")
    name = str_field(data, "name", 255, allow_blank=False)
    desc = str_field(data, "description", 1000)
    before = ser_permission(perm, counts=False)
    with transaction.atomic():
        if name is not None:
            ensure_permission(perm.codename, name)
        if desc is not None:
            ensure_permission(perm.codename, name or perm.name)
            ApplicationPermissionRecord.objects.filter(codename=perm.codename).update(description=desc)
        perm.refresh_from_db()
        after = ser_permission(perm, counts=False)
        audit.record(ctx, "permission.update", "permission", perm.codename,
                     before={k: before[k] for k in ("name", "description")},
                     after={k: after[k] for k in ("name", "description")})
    return perm


def delete_permission_op(ctx, codename, revoke_all: bool = False) -> None:
    perm = get_permission(codename)
    if perm.codename in code_defined_codenames():
        raise Conflict(f"{PREFIX}{perm.codename} is defined in code and cannot be deleted.")
    users, groups = perm.user_set.count(), perm.group_set.count()
    services = perm.sso_service_clients.count()
    if (users or groups or services) and not revoke_all:
        raise Conflict(f"Still granted to {users} user(s), {groups} group(s), {services} service(s); "
                       "pass revoke_all=true to delete anyway.")
    require_stepup(ctx, "permission.delete", "permission", perm.codename)
    with transaction.atomic():
        before = ser_permission(perm)
        delete_permission(perm)
        audit.record(ctx, "permission.delete", "permission", before["codename"], before=before, stepup=True)
        check_invariants(ctx.user)


# --------------------------------------------------------------------------- services
def get_service(client_id) -> ServiceClient:
    client = ServiceClient.objects.filter(client_id=client_id).first()
    if client is None:
        raise NotFound("Unknown service client.")
    return client


def services_qs(kind=None):
    qs = ServiceClient.objects.all().order_by("client_id")
    return qs.filter(kind=kind) if kind else qs


def service_perms(value) -> list[Permission]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InvalidRequest("Missing or malformed fields: perms.")
    perms = []
    for raw in value:
        try:
            perms.append(get_permission(raw))
        except NotFound:
            raise InvalidRequest(f"Unknown permission {raw!r}.") from None
    return perms


def _apply_service_fields(client, data):
    if "name" in data:
        client.name = str_field(data, "name", 200, allow_blank=False).strip()
    if "app_codename" in data:
        app = data["app_codename"]
        if app is not None:
            try:
                validate_codename(app if isinstance(app, str) else "")
            except ValueError:
                raise InvalidRequest("app_codename must be a valid codename or null.") from None
        client.app_codename = app
    if "notify_url" in data:
        url = data["notify_url"]
        if url is not None:
            try:
                if not isinstance(url, str) or len(url) > 500:
                    raise DjangoValidationError("bad")
                URLValidator(schemes=["https"])(url)
            except DjangoValidationError:
                raise InvalidRequest("notify_url must be an https URL or null.") from None
        client.notify_url = url


def create_service(ctx, data: dict) -> tuple[ServiceClient, str]:
    client_id = str_field(data, "client_id", 100, required=True, allow_blank=False)
    if not re.fullmatch(CLIENT_ID_RE, client_id):
        raise InvalidRequest("client_id must be a slug.")
    str_field(data, "name", 200, required=True, allow_blank=False)
    unknown = set(data) - {"client_id", "name", "app_codename", "notify_url", "perms"}
    if unknown:
        raise InvalidRequest("Unknown fields: " + ", ".join(sorted(unknown)) + ".")
    perms = service_perms(data.get("perms", []))
    if ServiceClient.objects.filter(client_id=client_id).exists():
        raise Conflict("A service client with this client_id exists.")
    client = ServiceClient(client_id=client_id)
    _apply_service_fields(client, data)
    secret = ServiceClient.generate_secret()
    client.set_secret(secret)
    with transaction.atomic():
        try:
            client.save()
        except IntegrityError:
            raise Conflict("A service client with this client_id exists.") from None
        client.permissions.set(perms)
        audit.record(ctx, "service.create", "service", client_id, after=ser_service(client))
    return client, secret


def update_service(ctx, client_id, data: dict) -> ServiceClient:
    client = get_service(client_id)
    unknown = set(data) - {"name", "app_codename", "notify_url", "is_active", "perms", "can_delegate",
                           "can_register_devices", "notify_events"}
    if unknown:
        raise InvalidRequest("Not editable: " + ", ".join(sorted(unknown)) + ".")
    for flag in ("is_active", "can_delegate", "can_register_devices"):
        if flag in data and not isinstance(data[flag], bool):
            raise InvalidRequest(f"Missing or malformed fields: {flag}.")
    if client.kind == "device" and (data.get("can_delegate") or data.get("can_register_devices")):
        raise InvalidRequest("A device cannot delegate or register devices.")
    perms = service_perms(data["perms"]) if "perms" in data else None
    deactivate = data.get("is_active") is False and client.is_active
    # v1.3b: granting delegation / device registration is security-relevant -> step-up
    elevate = any(data.get(f) is True and not getattr(client, f) for f in ("can_delegate", "can_register_devices"))
    needs_stepup = deactivate or elevate
    if needs_stepup:
        require_stepup(ctx, "service.update", "service", client_id)
    before = ser_service(client)
    _apply_service_fields(client, data)
    for flag in ("is_active", "can_delegate", "can_register_devices"):
        if flag in data:
            setattr(client, flag, data[flag])
    if "notify_events" in data:
        from .webhooks import EVENT_TYPES

        ev = data["notify_events"]
        if not isinstance(ev, list) or not all(isinstance(e, str) and e in EVENT_TYPES for e in ev):
            raise InvalidRequest("notify_events: list of " + ", ".join(EVENT_TYPES) + " ([] = all).")
        client.notify_events = sorted(set(ev))
    with transaction.atomic():
        client.save()
        if perms is not None:
            client.permissions.set(perms)
        audit.record(ctx, "service.update", "service", client_id, before=before, after=ser_service(client),
                     stepup=needs_stepup)
    return client


def delete_service(ctx, client_id) -> None:
    client = get_service(client_id)
    require_stepup(ctx, "service.delete", "service", client_id)
    with transaction.atomic():
        before = ser_service(client)
        client.delete()
        audit.record(ctx, "service.delete", "service", client_id, before=before, stepup=True)


def rotate_service_secret(ctx, client_id) -> str:
    client = get_service(client_id)
    require_stepup(ctx, "service.rotate_secret", "service", client_id)
    secret = ServiceClient.generate_secret()
    with transaction.atomic():
        client.set_secret(secret)
        client.secret_rotated_at = timezone.now()
        client.save(update_fields=["client_secret_hash", "secret_rotated_at"])
        audit.record(ctx, "service.rotate_secret", "service", client_id, stepup=True)
    return secret


def rotate_notify_secret(ctx, client_id) -> str:
    from .webhook_secrets import encrypt, generate

    client = get_service(client_id)
    if client.kind != "service":
        raise InvalidRequest("Devices do not receive webhooks.")
    require_stepup(ctx, "service.rotate_notify_secret", "service", client_id)
    secret = generate()
    with transaction.atomic():
        client.notify_secret_enc = encrypt(secret)
        client.save(update_fields=["notify_secret_enc"])
        audit.record(ctx, "service.rotate_notify_secret", "service", client_id, stepup=True)
    return secret


# --------------------------------------------------------------------------- applications
def get_app(app) -> Application:
    a = Application.objects.filter(app_codename=app).first()
    if a is None:
        raise NotFound("Unknown application.")
    return a


def import_app(ctx, app, payload, *, dry_run: bool, force: bool):
    if isinstance(ctx.user, ServicePrincipal) and ctx.user.client.app_codename != app:
        audit.record_denied(ctx, "app.import", "app", app, reason="service client of another app")
        raise AdminForbidden("A service client may import only its own application's permissions.")
    try:
        with transaction.atomic():
            result = import_permissions(app, payload, dry_run=dry_run, force=force)
            if not dry_run and result.changed:
                from .webhooks import emit

                emit("permission.changed", app=app, created=result.created, updated=result.updated,
                     deprecated=result.deprecated)
            if not dry_run:
                action = "app.import" if result.changed else "app.import_noop"
                audit.record(ctx, action, "app", app, after=result.as_dict())
    except ImportError_ as exc:
        raise InvalidRequest(str(exc)) from None
    except VersionTooOld as exc:
        raise VersionConflict(f"Stored version {exc.stored} is newer than {exc.given}; use force=true.") from None
    return result


# --------------------------------------------------------------------------- audit
AUDIT_CHANNELS = ("api", "ui", "django_admin", "system")


def audit_qs(actor=None, action=None, target_type=None, target_id=None, since=None, channel=None, result=None):
    qs = AdminAuditLog.objects.all()
    if actor:
        qs = qs.filter(actor_id=actor)
    if action:
        qs = qs.filter(action=action)
    if target_type:
        qs = qs.filter(target_type=target_type)
    if target_id:
        qs = qs.filter(target_id=target_id)
    if since:
        qs = qs.filter(ts__gte=parse_since(since))
    if channel:
        if channel not in AUDIT_CHANNELS:
            raise InvalidRequest("channel must be one of " + ", ".join(AUDIT_CHANNELS) + ".")
        qs = qs.filter(channel=channel)
    if result:
        qs = qs.filter(result=result)
    return qs


# --------------------------------------------------------------------------- devices (v1.3b)
def devices_qs(owner=None):
    qs = ServiceClient.objects.filter(kind="device").order_by("client_id")
    if owner:
        if not str(owner).isdigit():
            raise InvalidRequest("owner must be a user id.")
        qs = qs.filter(owner_id=int(owner))
    return qs


def get_device(client_id) -> ServiceClient:
    dev = ServiceClient.objects.filter(client_id=client_id, kind="device").first()
    if dev is None:
        raise NotFound("Unknown device.")
    return dev


def delete_device(ctx, client_id) -> None:
    from .devices import ser_device

    dev = get_device(client_id)
    require_stepup(ctx, "device.delete", "device", client_id)
    with transaction.atomic():
        before = ser_device(dev)
        dev.delete()
        audit.record(ctx, "device.delete", "device", client_id, before=before, stepup=True)


# --------------------------------------------------------------------------- webhooks (v1.3c)
def events_qs(type_=None, since=None):
    from .models import WebhookEvent

    qs = WebhookEvent.objects.all()
    if type_:
        qs = qs.filter(type=type_)
    if since:
        qs = qs.filter(created__gte=parse_since(since))
    return qs


def deliveries_qs(status=None, client_id=None, event=None):
    from .models import WebhookDelivery

    qs = WebhookDelivery.objects.select_related("event", "client")
    if status:
        if status not in WebhookDelivery.STATUSES:
            raise InvalidRequest("Unknown status.")
        qs = qs.filter(status=status)
    if client_id:
        qs = qs.filter(client__client_id=client_id)
    if event:
        if not str(event).isdigit():
            raise InvalidRequest("event must be an id.")
        qs = qs.filter(event_id=int(event))
    return qs


def redeliver(ctx, pk):
    from .models import WebhookDelivery

    d = WebhookDelivery.objects.select_related("event", "client").filter(pk=pk).first()
    if d is None:
        raise NotFound("Unknown delivery.")
    now = timezone.now()
    with transaction.atomic():
        WebhookDelivery.objects.filter(pk=d.pk).update(status="pending", attempts=0, next_attempt_at=now,
                                                       window_start=now, claimed_at=None)
        audit.record(ctx, "webhook.redeliver", "delivery", d.pk, before={"status": d.status})
    d.refresh_from_db()
    return d
