"""System checks for deployment pitfalls.

settings.py already refuses to start with a per-process cache when SSO_DEBUG=False; this check also
catches a CACHES setting overridden after that (e.g. in a custom settings module).
"""
from django.conf import settings
from django.core.checks import Error, register

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
