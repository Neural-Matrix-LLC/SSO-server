"""E2E sample service (single-file Django + sso_client). Run: python app_django.py PORT"""
import sys

import django
from django.conf import settings

settings.configure(DEBUG=False, ALLOWED_HOSTS=["127.0.0.1", "localhost"], ROOT_URLCONF=__name__, SECRET_KEY="qa-e2e",
                   MIDDLEWARE=["sso_client.adapters.django.SSOMiddleware"], INSTALLED_APPS=[])
django.setup()
from django.http import JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402
from sso_client.adapters.django import require_permission  # noqa: E402


def health(request):
    return JsonResponse({"ok": True})


@require_permission("application.app1")
def app1(request):
    return JsonResponse({"user": request.sso.user.username, "ip": request.client_ip, "ip_match": request.sso.ip_match})


@require_permission("application.app2")
def app2(request):
    return JsonResponse({"user": request.sso.user.username})


urlpatterns = [path("healthz", health), path("app1", app1), path("app2", app2)]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    execute_from_command_line([sys.argv[0], "runserver", "--noreload", "--nothreading", f"127.0.0.1:{sys.argv[1]}"])
