"""System checks for deployment pitfalls.

settings.py already refuses to start (ImproperlyConfigured) with a per-process cache or as root when
SSO_DEBUG=False; these checks (sso.E001, sso.E002) also catch settings overridden after that, e.g. in a
custom settings module.
"""
from django.conf import settings
from django.core.checks import Error, Warning, register  # noqa: A004

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


@register()
def deprecated_num_proxies(app_configs, **kwargs):
    """sso.W002 (v1.2b): SSO_NUM_PROXIES is the deprecated fallback for SSO_TRUSTED_PROXIES (design §4.5.2)."""
    if getattr(settings, "SSO_NUM_PROXIES", 0) and not getattr(settings, "SSO_TRUSTED_PROXIES_PARSED", ()):
        return [Warning("SSO_NUM_PROXIES is deprecated; use SSO_TRUSTED_PROXIES (IPs/CIDRs of your proxies).",
                        hint="e.g. SSO_TRUSTED_PROXIES=172.18.0.0/16 (the compose network of nginx)", id="sso.W002")]
    return []


def deprecated_key_messages() -> list[str]:
    from .keys import DEPRECATED_KEY_VARS

    return [f"{var} is deprecated; use {DEPRECATED_KEY_VARS[var]} "
            "(file names in SSO_JWT_KEYS_MOUNT, default /run/keys)."
            for var in getattr(settings, "SSO_KEY_DEPRECATED_VARS", ())]


@register()
def deprecated_key_variables(app_configs, **kwargs):
    """sso.W001: the old *_PATH key variables still work but should be replaced (README "Docker quick start")."""
    return [Warning(msg, hint='e.g. SSO_JWT_PRIVATE_KEY=sso-2026-10.private.pem, '
                              'SSO_JWT_PUBLIC_KEYS=sso-2026-10.public.pem', id="sso.W001")
            for msg in deprecated_key_messages()]
