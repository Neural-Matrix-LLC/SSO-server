"""SSO admin REST API ``/api/v1/admin/…`` (DESIGN-v1.3a-admin-api.md §3-§4).

Caller: an active **staff** (``is_staff``) user holding ``application.sso_admin`` (direct or via a group) or a
superuser, with a Bearer user access token, checked in the DB on every call (token ``perms`` are not trusted). IP
binding applies. Exception: an application's own ServiceClient (Basic) may import its own permissions.

v1.3d: the views are thin HTTP adapters; every rule (guards, step-up, audit, webhooks) lives in
``sso/admin_ops.py``, which the admin web UI (``adminui/``) uses too. The JSON contract is unchanged, plus the
additive audit ``channel`` field / filter.
"""
from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from . import admin_ops as ops
from . import audit
from .admin_ops import (ADMIN_CODENAME, admin_permission, admins_qs, check_invariants, is_sso_admin,  # noqa: F401
                        ser_app, ser_audit, ser_delivery, ser_event, ser_group, ser_permission, ser_service,
                        ser_user)
from .authentication import ServiceClientBasicAuthentication, ServicePrincipal, SSOAccessTokenAuthentication
from .errors import AdminForbidden, InvalidRequest, NotFound, TokenInvalid
from .ipbinding import CIP_CLAIM, ip_matches, log_mismatch, mode as ip_mode
from .logs import client_ip
from .revocation import revoke_session
from .tokens import SID_CLAIM

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

    def check_permissions(self, request):
        user = request.user
        if user is None:
            raise TokenInvalid("Authentication credentials were missing or invalid.")
        if isinstance(user, ServicePrincipal):
            if self.allow_service_import:
                return  # admin_ops.import_app checks app ownership
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
    count = qs.count() if hasattr(qs, "count") and not isinstance(qs, list) else len(qs)
    items = qs[(page - 1) * size: page * size]
    return Response({"count": count, "page": page, "page_size": size, "results": [ser(o) for o in items]})


def _q(request, key):
    return request.query_params.get(key)


# --------------------------------------------------------------------------- reauth
class ReauthView(AdminAPIView):
    throttle_classes = [ReauthThrottle]

    def post(self, request):
        raw, ttl = ops.reauth(request, self.body(request).get("password"))
        return Response({"reauth_token": raw, "expires_in": ttl})


# --------------------------------------------------------------------------- users
class UsersView(AdminAPIView):
    def get(self, request):
        qs = ops.users_qs(_q(request, "q"), ops.bool_param(_q(request, "active")), _q(request, "group"))
        return paginate(request, qs, ser_user)

    def post(self, request):
        return Response(ser_user(ops.create_user(request, self.body(request))), status=status.HTTP_201_CREATED)


class UserView(AdminAPIView):
    def get(self, request, pk):
        return Response(ser_user(ops.get_user(pk)))

    def patch(self, request, pk):
        return Response(ser_user(ops.update_user(request, pk, self.body(request))))

    def delete(self, request, pk):
        ops.delete_user(request, pk)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserActionView(AdminAPIView):
    def post(self, request, pk, action):
        if action == "suspend":
            return Response(ser_user(ops.suspend_user(request, pk)))
        if action == "unsuspend":
            return Response(ser_user(ops.unsuspend_user(request, pk)))
        if action == "logout-all":
            ops.logout_all_user(request, pk)
            return Response(status=status.HTTP_204_NO_CONTENT)
        if action == "set-password":
            ops.get_user(pk)
            ops.set_user_password(request, pk, self.body(request).get("password"))
            return Response(status=status.HTTP_204_NO_CONTENT)
        raise NotFound()


class UserPermissionsView(AdminAPIView):
    def get(self, request, pk):
        return Response(ops.user_permissions(pk))


class UserPermissionView(AdminAPIView):
    def post(self, request, pk, codename):
        ops.change_user_permission(request, pk, codename, True)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def delete(self, request, pk, codename):
        ops.change_user_permission(request, pk, codename, False)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserGroupsView(AdminAPIView):
    def put(self, request, pk):
        return Response(ser_user(ops.set_user_groups(request, pk, self.body(request).get("groups"))))


# --------------------------------------------------------------------------- groups
class GroupsView(AdminAPIView):
    def get(self, request):
        return paginate(request, ops.groups_qs(_q(request, "q")), ser_group)

    def post(self, request):
        data = self.body(request)
        ops.str_field(data, "name", 150, required=True, allow_blank=False)
        return Response(ser_group(ops.create_group(request, data["name"])), status=status.HTTP_201_CREATED)


class GroupView(AdminAPIView):
    def get(self, request, pk):
        return Response(ser_group(ops.get_group(pk)))

    def patch(self, request, pk):
        data = self.body(request)
        ops.get_group(pk)
        ops.str_field(data, "name", 150, required=True, allow_blank=False)
        return Response(ser_group(ops.rename_group(request, pk, data["name"])))

    def delete(self, request, pk):
        ops.delete_group(request, pk)
        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupMembersView(AdminAPIView):
    def put(self, request, pk):
        ops.get_group(pk)
        return Response(ser_group(ops.set_group_members(request, pk, self.body(request).get("user_ids"))))


class GroupPermissionView(AdminAPIView):
    def post(self, request, pk, codename):
        ops.change_group_permission(request, pk, codename, True)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def delete(self, request, pk, codename):
        ops.change_group_permission(request, pk, codename, False)
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- permissions
class PermissionsView(AdminAPIView):
    def get(self, request):
        rows = ops.permissions_list(_q(request, "app"), ops.bool_param(_q(request, "deprecated")))
        return paginate(request, rows, lambda pr: ser_permission(pr[0], pr[1]))

    def post(self, request):
        return Response(ser_permission(ops.create_permission(request, self.body(request))),
                        status=status.HTTP_201_CREATED)


class PermissionView(AdminAPIView):
    def get(self, request, codename):
        return Response(ser_permission(ops.get_permission(codename)))

    def patch(self, request, codename):
        ops.get_permission(codename)
        return Response(ser_permission(ops.update_permission(request, codename, self.body(request))))

    def delete(self, request, codename):
        ops.delete_permission_op(request, codename, ops.bool_param(_q(request, "revoke_all")) or False)
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- services
class ServicesView(AdminAPIView):
    def get(self, request):
        return paginate(request, ops.services_qs(_q(request, "kind")), ser_service)

    def post(self, request):
        client, secret = ops.create_service(request, self.body(request))
        body = ser_service(client)
        body["client_secret"] = secret
        return Response(body, status=status.HTTP_201_CREATED)


class ServiceView(AdminAPIView):
    def get(self, request, client_id):
        return Response(ser_service(ops.get_service(client_id)))

    def patch(self, request, client_id):
        ops.get_service(client_id)
        return Response(ser_service(ops.update_service(request, client_id, self.body(request))))

    def delete(self, request, client_id):
        ops.delete_service(request, client_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ServiceRotateView(AdminAPIView):
    def post(self, request, client_id):
        secret = ops.rotate_service_secret(request, client_id)
        return Response({"client_id": client_id, "client_secret": secret})


# --------------------------------------------------------------------------- applications
class AppsView(AdminAPIView):
    def get(self, request):
        from application.models import Application

        return paginate(request, Application.objects.all(), ser_app)


class AppView(AdminAPIView):
    def get(self, request, app):
        return Response(ser_app(ops.get_app(app), with_perms=True))


class AppPermissionsImportView(AdminAPIView):
    authentication_classes = [AdminTokenAuthentication, ServiceClientBasicAuthentication]
    allow_service_import = True

    def put(self, request, app):
        result = ops.import_app(request, app, request.data,
                                dry_run=ops.bool_param(_q(request, "dry_run")) or False,
                                force=ops.bool_param(_q(request, "force")) or False)
        return Response(result.as_dict())


# --------------------------------------------------------------------------- audit
class AuditView(AdminAPIView):
    def get(self, request):
        p = request.query_params
        qs = ops.audit_qs(actor=p.get("actor"), action=p.get("action"), target_type=p.get("target_type"),
                          target_id=p.get("target_id"), since=p.get("since"), channel=p.get("channel"))
        return paginate(request, qs, ser_audit)


# --------------------------------------------------------------------------- devices (v1.3b)
class AdminDevicesView(AdminAPIView):
    def get(self, request):
        from .devices import ser_device

        return paginate(request, ops.devices_qs(_q(request, "owner")), ser_device)


class AdminDeviceView(AdminAPIView):
    def delete(self, request, client_id):
        ops.delete_device(request, client_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- webhooks (v1.3c)
class ServiceNotifySecretView(AdminAPIView):
    def post(self, request, client_id):
        secret = ops.rotate_notify_secret(request, client_id)
        return Response({"client_id": client_id, "notify_secret": secret})


class WebhookEventsView(AdminAPIView):
    def get(self, request):
        return paginate(request, ops.events_qs(_q(request, "type"), _q(request, "since")), ser_event)


class WebhookDeliveriesView(AdminAPIView):
    def get(self, request):
        p = request.query_params
        return paginate(request, ops.deliveries_qs(p.get("status"), p.get("client_id"), p.get("event")),
                        ser_delivery)


class WebhookRedeliverView(AdminAPIView):
    def post(self, request, pk):
        return Response(ser_delivery(ops.redeliver(request, pk)))
