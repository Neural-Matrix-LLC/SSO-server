from django.conf import settings
from django.contrib import admin
from django.urls import path, re_path

from sso import admin_api as adm
from sso import devices, service_auth, views

admin.site.site_header = "SSO server administration"

urlpatterns = [
    path("api/v1/auth/login", views.LoginView.as_view(), name="sso-login"),
    path("api/v1/auth/refresh", views.RefreshView.as_view(), name="sso-refresh"),
    path("api/v1/auth/logout", views.LogoutView.as_view(), name="sso-logout"),
    path("api/v1/auth/logout-all", views.LogoutAllView.as_view(), name="sso-logout-all"),
    path("api/v1/auth/me", views.MeView.as_view(), name="sso-me"),
    path("api/v1/auth/introspect", views.IntrospectView.as_view(), name="sso-introspect"),
    # Reserved for phase 5 (not routed yet): api/v1/auth/token "sso-token", sso/authorize "sso-authorize",
    # sso/logout "sso-session-logout", api/v1/account/* (spec §6.8/§6.9).
    # v1.3a (docs/DESIGN-v1.3a-admin-api.md)
    path("api/v1/auth/service-token", service_auth.ServiceTokenView.as_view(), name="sso-service-token"),
    path("api/v1/service/users/inactive", service_auth.InactiveUsersView.as_view(), name="sso-inactive-users"),
    path("api/v1/admin/reauth", adm.ReauthView.as_view(), name="sso-admin-reauth"),
    path("api/v1/admin/users", adm.UsersView.as_view(), name="sso-admin-users"),
    path("api/v1/admin/users/<int:pk>", adm.UserView.as_view(), name="sso-admin-user"),
    path("api/v1/admin/users/<int:pk>/permissions", adm.UserPermissionsView.as_view()),
    path("api/v1/admin/users/<int:pk>/permissions/<str:codename>", adm.UserPermissionView.as_view()),
    path("api/v1/admin/users/<int:pk>/groups", adm.UserGroupsView.as_view()),
    re_path(r"^api/v1/admin/users/(?P<pk>[0-9]+)/(?P<action>suspend|unsuspend|logout-all|set-password)$",
            adm.UserActionView.as_view()),
    path("api/v1/admin/groups", adm.GroupsView.as_view()),
    path("api/v1/admin/groups/<int:pk>", adm.GroupView.as_view()),
    path("api/v1/admin/groups/<int:pk>/members", adm.GroupMembersView.as_view()),
    path("api/v1/admin/groups/<int:pk>/permissions/<str:codename>", adm.GroupPermissionView.as_view()),
    path("api/v1/admin/permissions", adm.PermissionsView.as_view()),
    path("api/v1/admin/permissions/<str:codename>", adm.PermissionView.as_view()),
    path("api/v1/admin/services", adm.ServicesView.as_view()),
    path("api/v1/admin/services/<slug:client_id>", adm.ServiceView.as_view()),
    path("api/v1/admin/services/<slug:client_id>/rotate-secret", adm.ServiceRotateView.as_view()),
    path("api/v1/admin/apps", adm.AppsView.as_view()),
    path("api/v1/admin/apps/<str:app>", adm.AppView.as_view()),
    path("api/v1/admin/apps/<str:app>/permissions", adm.AppPermissionsImportView.as_view()),
    path("api/v1/admin/audit", adm.AuditView.as_view()),
    # v1.3b (docs/DESIGN-v1.3b-devices-on-behalf-of.md)
    path("api/v1/devices", devices.DevicesView.as_view(), name="sso-devices"),
    path("api/v1/devices/<slug:client_id>", devices.DeviceView.as_view()),
    path("api/v1/admin/devices", adm.AdminDevicesView.as_view()),
    path("api/v1/admin/devices/<slug:client_id>", adm.AdminDeviceView.as_view()),
    path(".well-known/jwks.json", views.JWKSView.as_view(), name="sso-jwks"),
    path(".well-known/openid-configuration", views.DiscoveryView.as_view(), name="sso-discovery"),
    path("healthz", views.HealthView.as_view(), name="sso-healthz"),
    path(settings.SSO_ADMIN_PATH, admin.site.urls),
]

handler400 = "sso.errors.handler400"
handler403 = "sso.errors.handler403"
handler404 = "sso.errors.handler404"
handler500 = "sso.errors.handler500"
