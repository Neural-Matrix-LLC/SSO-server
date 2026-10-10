"""System checks for deployment pitfalls."""
from django.conf import settings
from django.core.checks import Warning, register


@register(deploy=True)
def locmem_cache_in_production(app_configs, **kwargs):
    backend = settings.CACHES.get("default", {}).get("BACKEND", "")
    if not settings.DEBUG and backend.endswith("LocMemCache"):
        return [
            Warning(
                "Throttling uses a per-process LocMem cache.",
                hint="With more than one gunicorn worker set SSO_CACHE_URL=redis://... (addendum B.3).",
                id="sso.W001",
            )
        ]
    return []
