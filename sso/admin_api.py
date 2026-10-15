"""SSO admin REST API ``/api/v1/admin/…`` (DESIGN-v1.3a-admin-api.md §3-§4).

Caller: an active user holding ``application.sso_admin`` (direct or via a group) or a superuser, with a Bearer
user access token, checked in the DB on every call (token ``perms`` are not trusted). IP binding applies.
Exception: an application's own ServiceClient (Basic) may import its own permissions.

Every change writes one audit row in the same transaction (sso/audit.py). Destructive actions need step-up
(``X-SSO-Reauth``, sso/stepup.py). Guards: no self-suspend/delete, never remove your own admin right, at least
one active admin remains (checked after the change, inside the transaction, so a violation rolls it back).
"""
from __future__ import annotations

from datetime import timezone as dt_timezone

from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import URLValidator
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from application.importer import ImportError_, VersionTooOld, import_permissions
from application.models import CODENAME_RE, Application, ApplicationPermissionRecord
from application.permissions import (PREFIX, anchor_content_type, app_permissions, code_defined_codenames,
                                     delete_permission, ensure_permission, user_app_perms, validate_codename)

from . import audit, stepup
from .authentication import ServiceClientBasicAuthentication, ServicePrincipal, SSOAccessTokenAuthentication
from .errors import (AdminForbidden, Conflict, InvalidCredentials, InvalidRequest, LastAdmin, NotFound,
                     SelfActionForbidden, TokenInvalid, VersionConflict)
from .ipbinding import CIP_CLAIM, ip_matches, log_mismatch, mode as ip_mode
from .logs import client_ip
from .models import AdminAuditLog, ServiceClient
from .revocation import revoke_session, revoke_user_tokens
from .serializers import check_credentials
from .tokens import SID_CLAIM, service_client_perms

ADMIN_CODENAME = "sso_admin"
MAX_PAGE_SIZE = 200


# --------------------------------------------------------------------------- auth
class AdminTokenAuthentication(SSOAccessTokenAuthentication):
    """Bearer user access token (like /me) plus the v1.2b IP binding (ENFORCE mismatch revokes the session)."""

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None
        user, token = result
        ip = client_ip(request)
        if ip_matches(token.get(CIP_CLAIM), ip) is False:
            log_mismatch("admin", user_id=user.pk, ip=ip)
            if ip_mode() == "ENFORCE":
                if token.get(SID_CLAIM):
                    revoke_session(user, token[SID_CLAIM], "ip_mismatch")
                raise TokenInvalid()
        return user, token


def admin_permission() -> Permission | None:
    return Permission.objects.filter(content_type=anchor_content_type(), codename=ADMIN_CODENAME).first()


def admins_qs():
    perm = admin_permission()
    q = Q(is_superuser=True)
    if perm is not None:
        q |= Q(user_permissions=perm) | Q(groups__permissions=perm)
    return User.objects.filter(is_active=True).filter(q).distinct()


def is_sso_admin(user) -> bool:
    if user is None or not getattr(user, "pk", None):
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


class AdminThrottle(SimpleRateThrottle):
    scope = "admin"

    def get_cache_key(self, request, view):
        user = request.user
        ident = f"svc:{user.client_id}" if isinstance(user, ServicePrincipal) else getattr(user, "pk", None)
        if ident is None:
            return None
        return self.cache_format % {"scope": self.scope, "ident": ident}


class ReauthThrottle(AdminThrottle):
    scope = "admin_reauth"


class AdminAPIView(APIView):
    authentication_classes = [AdminTokenAuthentication]
    throttle_classes = [AdminThrottle]
    allow_service_import = False

    def get_authenticate_header(self, request):
        return 'Bearer realm="sso-admin", error="invalid_token"'

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)  # authentication, then throttles

    def check_permissions(self, request):
        user = request.user
        if user is None:
            raise TokenInvalid("Authentication credentials were missing or invalid.")
        if isinstance(user, ServicePrincipal):
            if self.allow_service_import:
                return  # the view checks app ownership
            self._deny(request, "service client")
        if not is_sso_admin(user):
            self._deny(request, "not an sso admin")

    def _deny(self, request, reason):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            audit.record_denied(request, "admin.denied", "endpoint", request.path[:191], reason=reason)
        raise AdminForbidden()

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["X-Request-ID"] = audit.request_id(request)
        response["Cache-Control"] = "no-store"
        return response

    # helpers
    def stepup(self, request, action, target_type="", target_id=""):
        if not stepup.is_valid(request):
            audit.record_denied(request, action, target_type, target_id, reason="reauth_required", stepup=True)
            stepup.require_stepup(request)

    def body(self, request) -> dict:
        if not isinstance(request.data, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        return request.data


def paginate(request, qs, ser):
    try:
        page = max(1, int(request.query_params.get("page", 1)))
        size = min(MAX_PAGE_SIZE, max(1, int(request.query_params.get("page_size", 50))))
    except ValueError:
        raise InvalidRequest("page and page_size must be integers.") from None
    count = qs.count()
    items = qs[(page - 1) * size: page * size]
    return Response({"count": count, "page": page, "page_size": size, "results": [ser(o) for o in items]})


def _bool_param(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    if value.lower() in ("1", "true", "yes"):
        return True
    if value.lower() in ("0", "false", "no"):
        return False
    raise InvalidRequest("Boolean query parameters take true or false.")


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _str_field(data, key, max_len, *, required=False, allow_blank=True):
    if key not in data:
        if required:
            raise InvalidRequest(f"Missing or malformed fields: {key}.")
        return None
    value = data[key]
    if not isinstance(value, str) or len(value) > max_len or (not allow_blank and not value.strip()):
        raise InvalidRequest(f"Missing or malformed fields: {key}.")
    return value.strip() if not allow_blank else value


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


# --------------------------------------------------------------------------- serializers
def ser_user(u: User) -> dict:
    return {"id": u.pk, "username": u.username, "email": u.email or "", "first_name": u.first_name,
            "last_name": u.last_name, "is_active": u.is_active, "is_staff": u.is_staff,
            "is_superuser": u.is_superuser, "groups": sorted(g.name for g in u.groups.all()),
            "perms": user_app_perms(u) if u.is_active else _granted_perms(u),
            "last_login": _iso(u.last_login), "date_joined": _iso(u.date_joined)}


def _granted_perms(u: User) -> list[str]:
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
           "deprecated": bool(rec and rec.deprecated_at), "deprecated_at": _iso(rec.deprecated_at) if rec else None,
           "code_defined": p.codename in code_defined_codenames()}
    if counts:
        out["users"] = p.user_set.count()
        out["groups"] = p.group_set.count()
    return out


def ser_service(c: ServiceClient) -> dict:
    return {"client_id": c.client_id, "name": c.name, "app_codename": c.app_codename, "notify_url": c.notify_url,
            "is_active": c.is_active, "perms": service_client_perms(c), "created": _iso(c.created),
            "secret_rotated_at": _iso(c.secret_rotated_at)}


def ser_audit(a: AdminAuditLog) -> dict:
    return {"id": a.pk, "ts": _iso(a.ts), "actor_type": a.actor_type, "actor_id": a.actor_id,
            "actor_ip": a.actor_ip, "action": a.action, "target_type": a.target_type, "target_id": a.target_id,
            "before": a.before, "after": a.after, "request_id": a.request_id, "result": a.result,
            "stepup": a.stepup}


def snap_user(u: User) -> dict:
    return {"username": u.username, "email": u.email, "first_name": u.first_name, "last_name": u.last_name,
            "is_active": u.is_active, "groups": sorted(g.name for g in u.groups.all())}


# --------------------------------------------------------------------------- reauth
class ReauthView(AdminAPIView):
    throttle_classes = [ReauthThrottle]

    def post(self, request):
        data = self.body(request)
        password = data.get("password")
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise InvalidRequest("Missing or malformed fields: password.")
        ok = check_credentials(request._request, request.user.get_username(), password)
        if ok is None or ok.pk != request.user.pk:
            audit.record_denied(request, "reauth", "user", request.user.pk, reason="invalid_credentials")
            raise InvalidCredentials("Password is incorrect.")
        with transaction.atomic():
            raw, ttl = stepup.issue(request)
            audit.record(request, "reauth", "user", request.user.pk)
        return Response({"reauth_token": raw, "expires_in": ttl})


# --------------------------------------------------------------------------- users
def get_user(pk) -> User:
    user = User.objects.filter(pk=pk).first()
    if user is None:
        raise NotFound("Unknown user.")
    return user


class UsersView(AdminAPIView):
    def get(self, request):
        qs = User.objects.all().order_by("username").prefetch_related("groups")
        q = request.query_params.get("q", "").strip()
        if q:
            qs = qs.filter(Q(username__icontains=q) | Q(email__icontains=q) | Q(first_name__icontains=q)
                           | Q(last_name__icontains=q))
        active = _bool_param(request.query_params.get("active"))
        if active is not None:
            qs = qs.filter(is_active=active)
        group = request.query_params.get("group")
        if group:
            qs = qs.filter(groups__name=group)
        return paginate(request, qs.distinct(), ser_user)

    def post(self, request):
        data = self.body(request)
        username = _str_field(data, "username", 150, required=True, allow_blank=False)
        email = _str_field(data, "email", 254) or ""
        first = _str_field(data, "first_name", 150) or ""
        last = _str_field(data, "last_name", 150) or ""
        password = data.get("password")
        is_active = data.get("is_active", True)
        groups = data.get("groups", [])
        if not isinstance(is_active, bool) or not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
            raise InvalidRequest("Missing or malformed fields: is_active, groups.")
        user = User(username=username, email=email, first_name=first, last_name=last, is_active=is_active)
        try:
            user.full_clean(exclude=["password"], validate_unique=False)
        except DjangoValidationError as exc:
            raise InvalidRequest("Invalid fields: " + ", ".join(sorted(exc.message_dict))) from None
        if password is not None:
            if not isinstance(password, str):
                raise InvalidRequest("Missing or malformed fields: password.")
            _validate_pw(password, user)
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
            audit.record(request, "user.create", "user", user.pk, after=snap_user(user))
        return Response(ser_user(user), status=status.HTTP_201_CREATED)


def _validate_pw(password, user):
    try:
        validate_password(password, user)
    except DjangoValidationError as exc:
        raise InvalidRequest("Password rejected: " + " ".join(exc.messages)) from None


class UserView(AdminAPIView):
    def get(self, request, pk):
        return Response(ser_user(get_user(pk)))

    def patch(self, request, pk):
        data = self.body(request)
        unknown = set(data) - {"email", "first_name", "last_name"}
        if unknown:
            raise InvalidRequest("Not editable here: " + ", ".join(sorted(unknown)) + ".")
        user = get_user(pk)
        before = snap_user(user)
        for key, max_len in (("email", 254), ("first_name", 150), ("last_name", 150)):
            value = _str_field(data, key, max_len)
            if value is not None:
                setattr(user, key, value)
        try:
            user.full_clean(exclude=["password"], validate_unique=False)
        except DjangoValidationError as exc:
            raise InvalidRequest("Invalid fields: " + ", ".join(sorted(exc.message_dict))) from None
        with transaction.atomic():
            user.save(update_fields=["email", "first_name", "last_name"])
            audit.record(request, "user.update", "user", user.pk, before=before, after=snap_user(user))
        return Response(ser_user(user))

    def delete(self, request, pk):
        user = get_user(pk)
        if user.pk == request.user.pk:
            raise SelfActionForbidden("You cannot delete your own account.")
        self.stepup(request, "user.delete", "user", user.pk)
        with transaction.atomic():
            before = snap_user(user)
            revoke_user_tokens(user)
            audit.record(request, "user.delete", "user", user.pk, before=before, stepup=True)
            user.delete()
            check_invariants(request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserActionView(AdminAPIView):
    def post(self, request, pk, action):
        user = get_user(pk)
        if action == "suspend":
            if user.pk == request.user.pk:
                raise SelfActionForbidden("You cannot suspend yourself.")
            self.stepup(request, "user.suspend", "user", user.pk)
            with transaction.atomic():
                was = user.is_active
                user.is_active = False
                user.save()  # the v1.2a signal revokes every token and session
                if was is False:
                    revoke_user_tokens(user)
                audit.record(request, "user.suspend", "user", user.pk, before={"is_active": was},
                             after={"is_active": False}, stepup=True)
                check_invariants(request.user)
            return Response(ser_user(user))
        if action == "unsuspend":
            with transaction.atomic():
                was = user.is_active
                user.is_active = True
                user.save()
                audit.record(request, "user.unsuspend", "user", user.pk, before={"is_active": was},
                             after={"is_active": True})
            return Response(ser_user(user))
        if action == "logout-all":
            with transaction.atomic():
                revoke_user_tokens(user)
                audit.record(request, "user.logout_all", "user", user.pk)
            return Response(status=status.HTTP_204_NO_CONTENT)
        if action == "set-password":
            data = self.body(request)
            password = data.get("password")
            if not isinstance(password, str) or not password:
                raise InvalidRequest("Missing or malformed fields: password.")
            self.stepup(request, "user.set_password", "user", user.pk)
            _validate_pw(password, user)
            with transaction.atomic():
                user.set_password(password)
                user.save()
                revoke_user_tokens(user)
                audit.record(request, "user.set_password", "user", user.pk, after={"password": "changed"},
                             stepup=True)
            return Response(status=status.HTTP_204_NO_CONTENT)
        raise NotFound()


class UserPermissionsView(AdminAPIView):
    def get(self, request, pk):
        user = get_user(pk)
        direct = sorted(PREFIX + c for c in user.user_permissions.filter(
            content_type__app_label="application").values_list("codename", flat=True))
        via = {g.name: sorted(PREFIX + c for c in g.permissions.filter(
            content_type__app_label="application").values_list("codename", flat=True))
            for g in user.groups.all()}
        return Response({"direct": direct, "via_groups": via, "effective": user_app_perms(user)})


class UserPermissionView(AdminAPIView):
    def _change(self, request, pk, codename, grant: bool):
        user = get_user(pk)
        perm = get_permission(codename)
        action = "user.grant" if grant else "user.revoke"
        is_admin_perm = perm.codename == ADMIN_CODENAME
        if is_admin_perm and not grant and user.pk == request.user.pk:
            raise SelfActionForbidden("You cannot remove your own SSO administrator access.")
        if is_admin_perm:
            self.stepup(request, action, "user", user.pk)
        with transaction.atomic():
            (user.user_permissions.add if grant else user.user_permissions.remove)(perm)
            audit.record(request, action, "user", user.pk, after={"perm": PREFIX + perm.codename},
                         stepup=is_admin_perm)
            check_invariants(request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def post(self, request, pk, codename):
        return self._change(request, pk, codename, True)

    def delete(self, request, pk, codename):
        return self._change(request, pk, codename, False)


def _admin_group_ids() -> set[int]:
    perm = admin_permission()
    return set(perm.group_set.values_list("pk", flat=True)) if perm else set()


class UserGroupsView(AdminAPIView):
    def put(self, request, pk):
        data = self.body(request)
        names = data.get("groups")
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise InvalidRequest("Missing or malformed fields: groups.")
        user = get_user(pk)
        groups = list(Group.objects.filter(name__in=names))
        if len(groups) != len(set(names)):
            raise InvalidRequest("Unknown group in groups.")
        old_ids = set(user.groups.values_list("pk", flat=True))
        touches_admin = bool((old_ids ^ {g.pk for g in groups}) & _admin_group_ids())
        if touches_admin:
            self.stepup(request, "user.groups", "user", user.pk)
        with transaction.atomic():
            before = sorted(user.groups.values_list("name", flat=True))
            user.groups.set(groups)
            audit.record(request, "user.groups", "user", user.pk, before={"groups": before},
                         after={"groups": sorted(g.name for g in groups)}, stepup=touches_admin)
            check_invariants(request.user)
        return Response(ser_user(user))


# --------------------------------------------------------------------------- groups
def get_group(pk) -> Group:
    group = Group.objects.filter(pk=pk).first()
    if group is None:
        raise NotFound("Unknown group.")
    return group


class GroupsView(AdminAPIView):
    def get(self, request):
        qs = Group.objects.all().order_by("name")
        q = request.query_params.get("q", "").strip()
        if q:
            qs = qs.filter(name__icontains=q)
        return paginate(request, qs, ser_group)

    def post(self, request):
        name = _str_field(self.body(request), "name", 150, required=True, allow_blank=False)
        if Group.objects.filter(name=name).exists():
            raise Conflict("A group with this name exists.")
        with transaction.atomic():
            group = Group.objects.create(name=name)
            audit.record(request, "group.create", "group", group.pk, after={"name": name})
        return Response(ser_group(group), status=status.HTTP_201_CREATED)


class GroupView(AdminAPIView):
    def get(self, request, pk):
        return Response(ser_group(get_group(pk)))

    def patch(self, request, pk):
        group = get_group(pk)
        name = _str_field(self.body(request), "name", 150, required=True, allow_blank=False)
        if Group.objects.filter(name=name).exclude(pk=group.pk).exists():
            raise Conflict("A group with this name exists.")
        with transaction.atomic():
            before = group.name
            group.name = name
            group.save()
            audit.record(request, "group.update", "group", group.pk, before={"name": before}, after={"name": name})
        return Response(ser_group(group))

    def delete(self, request, pk):
        group = get_group(pk)
        self.stepup(request, "group.delete", "group", group.pk)
        with transaction.atomic():
            before = ser_group(group)
            group.delete()
            audit.record(request, "group.delete", "group", pk, before=before, stepup=True)
            check_invariants(request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupMembersView(AdminAPIView):
    def put(self, request, pk):
        group = get_group(pk)
        ids = self.body(request).get("user_ids")
        if not isinstance(ids, list) or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
            raise InvalidRequest("Missing or malformed fields: user_ids.")
        users = list(User.objects.filter(pk__in=ids))
        if len(users) != len(set(ids)):
            raise InvalidRequest("Unknown user id in user_ids.")
        is_admin_group = group.pk in _admin_group_ids()
        if is_admin_group:
            self.stepup(request, "group.members", "group", group.pk)
        with transaction.atomic():
            before = sorted(group.user_set.values_list("pk", flat=True))
            group.user_set.set(users)
            audit.record(request, "group.members", "group", group.pk, before={"members": before},
                         after={"members": sorted(ids)}, stepup=is_admin_group)
            check_invariants(request.user)
        return Response(ser_group(group))


class GroupPermissionView(AdminAPIView):
    def _change(self, request, pk, codename, grant):
        group = get_group(pk)
        perm = get_permission(codename)
        action = "group.grant" if grant else "group.revoke"
        is_admin_perm = perm.codename == ADMIN_CODENAME
        if is_admin_perm:
            self.stepup(request, action, "group", group.pk)
        with transaction.atomic():
            (group.permissions.add if grant else group.permissions.remove)(perm)
            audit.record(request, action, "group", group.pk, after={"perm": PREFIX + perm.codename},
                         stepup=is_admin_perm)
            check_invariants(request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def post(self, request, pk, codename):
        return self._change(request, pk, codename, True)

    def delete(self, request, pk, codename):
        return self._change(request, pk, codename, False)


# --------------------------------------------------------------------------- permissions
class PermissionsView(AdminAPIView):
    def get(self, request):
        records = {r.codename: r for r in ApplicationPermissionRecord.objects.all()}
        perms = list(app_permissions())
        app = request.query_params.get("app")
        deprecated = _bool_param(request.query_params.get("deprecated"))
        out = []
        for p in perms:
            rec = records.get(p.codename)
            if app and (rec is None or rec.app_codename != app):
                continue
            if deprecated is not None and bool(rec and rec.deprecated_at) != deprecated:
                continue
            out.append((p, rec))
        return paginate(request, _ListQS(out), lambda pr: ser_permission(pr[0], pr[1]))

    def post(self, request):
        data = self.body(request)
        code = _str_field(data, "codename", 63, required=True, allow_blank=False)
        name = _str_field(data, "name", 255, required=True, allow_blank=False)
        desc = _str_field(data, "description", 1000) or ""
        try:
            validate_codename(code)
        except ValueError:
            raise InvalidRequest(f"codename must match {CODENAME_RE}") from None
        if app_permissions().filter(codename=code).exists():
            raise Conflict("This permission exists.")
        with transaction.atomic():
            perm, _ = ensure_permission(code, name)
            ApplicationPermissionRecord.objects.filter(codename=code).update(description=desc)
            audit.record(request, "permission.create", "permission", code, after={"name": name, "description": desc})
        return Response(ser_permission(perm), status=status.HTTP_201_CREATED)


class _ListQS(list):
    def count(self):
        return len(self)


class PermissionView(AdminAPIView):
    def get(self, request, codename):
        return Response(ser_permission(get_permission(codename)))

    def patch(self, request, codename):
        perm = get_permission(codename)
        data = self.body(request)
        unknown = set(data) - {"name", "description"}
        if unknown:
            raise Conflict("Only name and description can be changed (codename is immutable).")
        name = _str_field(data, "name", 255, allow_blank=False)
        desc = _str_field(data, "description", 1000)
        before = ser_permission(perm, counts=False)
        with transaction.atomic():
            if name is not None:
                ensure_permission(perm.codename, name)
            if desc is not None:
                ensure_permission(perm.codename, name or perm.name)
                ApplicationPermissionRecord.objects.filter(codename=perm.codename).update(description=desc)
            perm.refresh_from_db()
            after = ser_permission(perm, counts=False)
            audit.record(request, "permission.update", "permission", perm.codename,
                         before={k: before[k] for k in ("name", "description")},
                         after={k: after[k] for k in ("name", "description")})
        return Response(ser_permission(perm))

    def delete(self, request, codename):
        perm = get_permission(codename)
        if perm.codename in code_defined_codenames():
            raise Conflict(f"{PREFIX}{perm.codename} is defined in code and cannot be deleted.")
        revoke_all = _bool_param(request.query_params.get("revoke_all")) or False
        users, groups = perm.user_set.count(), perm.group_set.count()
        services = perm.sso_service_clients.count()
        if (users or groups or services) and not revoke_all:
            raise Conflict(f"Still granted to {users} user(s), {groups} group(s), {services} service(s); "
                           "pass revoke_all=true to delete anyway.")
        self.stepup(request, "permission.delete", "permission", perm.codename)
        with transaction.atomic():
            before = ser_permission(perm)
            delete_permission(perm)
            audit.record(request, "permission.delete", "permission", before["codename"], before=before, stepup=True)
            check_invariants(request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- services
def get_service(client_id) -> ServiceClient:
    client = ServiceClient.objects.filter(client_id=client_id).first()
    if client is None:
        raise NotFound("Unknown service client.")
    return client


def _service_perms(value) -> list[Permission]:
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
        client.name = _str_field(data, "name", 200, allow_blank=False).strip()
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


class ServicesView(AdminAPIView):
    def get(self, request):
        return paginate(request, ServiceClient.objects.all().order_by("client_id"), ser_service)

    def post(self, request):
        data = self.body(request)
        client_id = _str_field(data, "client_id", 100, required=True, allow_blank=False)
        import re
        if not re.fullmatch(r"^[-a-zA-Z0-9_]+$", client_id):
            raise InvalidRequest("client_id must be a slug.")
        _str_field(data, "name", 200, required=True, allow_blank=False)
        unknown = set(data) - {"client_id", "name", "app_codename", "notify_url", "perms"}
        if unknown:
            raise InvalidRequest("Unknown fields: " + ", ".join(sorted(unknown)) + ".")
        perms = _service_perms(data.get("perms", []))
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
            audit.record(request, "service.create", "service", client_id, after=ser_service(client))
        body = ser_service(client)
        body["client_secret"] = secret
        return Response(body, status=status.HTTP_201_CREATED)


class ServiceView(AdminAPIView):
    def get(self, request, client_id):
        return Response(ser_service(get_service(client_id)))

    def patch(self, request, client_id):
        client = get_service(client_id)
        data = self.body(request)
        unknown = set(data) - {"name", "app_codename", "notify_url", "is_active", "perms"}
        if unknown:
            raise InvalidRequest("Not editable: " + ", ".join(sorted(unknown)) + ".")
        if "is_active" in data and not isinstance(data["is_active"], bool):
            raise InvalidRequest("Missing or malformed fields: is_active.")
        perms = _service_perms(data["perms"]) if "perms" in data else None
        deactivate = data.get("is_active") is False and client.is_active
        if deactivate:
            self.stepup(request, "service.update", "service", client_id)
        before = ser_service(client)
        _apply_service_fields(client, data)
        if "is_active" in data:
            client.is_active = data["is_active"]
        with transaction.atomic():
            client.save()
            if perms is not None:
                client.permissions.set(perms)
            audit.record(request, "service.update", "service", client_id, before=before, after=ser_service(client),
                         stepup=deactivate)
        return Response(ser_service(client))

    def delete(self, request, client_id):
        client = get_service(client_id)
        self.stepup(request, "service.delete", "service", client_id)
        with transaction.atomic():
            before = ser_service(client)
            client.delete()
            audit.record(request, "service.delete", "service", client_id, before=before, stepup=True)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ServiceRotateView(AdminAPIView):
    def post(self, request, client_id):
        client = get_service(client_id)
        self.stepup(request, "service.rotate_secret", "service", client_id)
        secret = ServiceClient.generate_secret()
        with transaction.atomic():
            client.set_secret(secret)
            client.secret_rotated_at = timezone.now()
            client.save(update_fields=["client_secret_hash", "secret_rotated_at"])
            audit.record(request, "service.rotate_secret", "service", client_id, stepup=True)
        return Response({"client_id": client.client_id, "client_secret": secret})


# --------------------------------------------------------------------------- applications
def ser_app(a: Application, with_perms=False) -> dict:
    recs = ApplicationPermissionRecord.objects.filter(app_codename=a.app_codename)
    out = {"app_codename": a.app_codename, "name": a.name, "description": a.description, "version": a.version,
           "updated": _iso(a.updated), "permission_count": recs.count(),
           "deprecated_count": recs.filter(deprecated_at__isnull=False).count()}
    if with_perms:
        perms = {p.codename: p for p in app_permissions().filter(codename__in=[r.codename for r in recs])}
        out["permissions"] = [ser_permission(perms[r.codename], r) for r in recs if r.codename in perms]
    return out


class AppsView(AdminAPIView):
    def get(self, request):
        return paginate(request, Application.objects.all(), ser_app)


class AppView(AdminAPIView):
    def get(self, request, app):
        a = Application.objects.filter(app_codename=app).first()
        if a is None:
            raise NotFound("Unknown application.")
        return Response(ser_app(a, with_perms=True))


class AppPermissionsImportView(AdminAPIView):
    authentication_classes = [AdminTokenAuthentication, ServiceClientBasicAuthentication]
    allow_service_import = True

    def get_authenticate_header(self, request):
        return 'Bearer realm="sso-admin", error="invalid_token"'

    def put(self, request, app):
        if isinstance(request.user, ServicePrincipal) and request.user.client.app_codename != app:
            audit.record_denied(request, "app.import", "app", app, reason="service client of another app")
            raise AdminForbidden("A service client may import only its own application's permissions.")
        dry_run = _bool_param(request.query_params.get("dry_run")) or False
        force = _bool_param(request.query_params.get("force")) or False
        try:
            with transaction.atomic():
                result = import_permissions(app, request.data, dry_run=dry_run, force=force)
                if not dry_run:
                    action = "app.import" if result.changed else "app.import_noop"
                    audit.record(request, action, "app", app, after=result.as_dict())
        except ImportError_ as exc:
            raise InvalidRequest(str(exc)) from None
        except VersionTooOld as exc:
            raise VersionConflict(f"Stored version {exc.stored} is newer than {exc.given}; use force=true.") from None
        return Response(result.as_dict())


# --------------------------------------------------------------------------- audit
class AuditView(AdminAPIView):
    def get(self, request):
        qs = AdminAuditLog.objects.all()
        p = request.query_params
        if p.get("actor"):
            qs = qs.filter(actor_id=p["actor"])
        for key in ("action", "target_type", "target_id"):
            if p.get(key):
                qs = qs.filter(**{key: p[key]})
        if p.get("since"):
            since = parse_datetime(p["since"].replace("Z", "+00:00")) if isinstance(p["since"], str) else None
            if since is None:
                raise InvalidRequest("since must be an ISO 8601 timestamp.")
            if timezone.is_naive(since):
                since = since.replace(tzinfo=dt_timezone.utc)
            qs = qs.filter(ts__gte=since)
        return paginate(request, qs, ser_audit)
