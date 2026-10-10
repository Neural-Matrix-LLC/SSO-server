from django.conf import settings
from django.contrib import admin
from django.urls import path

from sso import views

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
    path(".well-known/jwks.json", views.JWKSView.as_view(), name="sso-jwks"),
    path(".well-known/openid-configuration", views.DiscoveryView.as_view(), name="sso-discovery"),
    path("healthz", views.HealthView.as_view(), name="sso-healthz"),
    path(settings.SSO_ADMIN_PATH, admin.site.urls),
]

handler400 = "sso.errors.handler400"
handler403 = "sso.errors.handler403"
handler404 = "sso.errors.handler404"
handler500 = "sso.errors.handler500"
