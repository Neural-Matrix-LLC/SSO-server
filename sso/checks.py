"""System checks for deployment pitfalls.

settings.py already refuses to start (ImproperlyConfigured) with a per-process cache or as root when
SSO_DEBUG=False; these checks (sso.E001, sso.E002) also catch settings overridden after that, e.g. in a
custom settings module.
"""
from django.conf import settings
from django.core.checks import Error, register

from .runtime import ROOT_MESSAGE, running_as_root

PER_PROCESS = ("django.core.cache.backends.locmem.LocMemCache", "django.core.cache.backends.dummy.DummyCache")


@register()
def per_process_cache_in_production(app_configs, **kwargs):
    backend = settings.CACHES.get("default", {}).get("BACKEND", "")
    if not settings.DEBUG and backend in PER_PROCESS:
        return [
            Error(
                f"Throttling uses a per-process or no-op cache ({backend.rsplit('.', 1)[-1]}).",
                hint="Set SSO_CACHE_URL=redis://... (or filecache://... on a single host); addendum B.3.",
                id="sso.E001",
            )
        ]
    return []


@register()
def not_root_in_production(app_configs, **kwargs):
    """Mirrors the settings fail-fast (sso.E002), for settings modules that override DEBUG afterwards."""
    if not settings.DEBUG and running_as_root():
        return [Error(ROOT_MESSAGE, hint="Set SSO_UID/SSO_GID (non-zero) and run as that user.", id="sso.E002")]
    return []
