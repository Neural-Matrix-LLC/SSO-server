"""URLconf for the V12B-02 test: a view that reads the lazy ``request.sso`` with no decorator."""
from django.http import JsonResponse
from django.urls import path


def plain(request):
    return JsonResponse({"user": request.sso.user.username})


def boom(request):
    raise ValueError("not an SSO error")


urlpatterns = [path("plain", plain), path("boom", boom)]
