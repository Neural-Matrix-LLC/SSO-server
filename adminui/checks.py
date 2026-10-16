from django.conf import settings
from django.core.checks import Error, register


@register()
def admin_ui_settings(app_configs, **kwargs):
    """adminui.E001: the UI needs CSRF-protected forms from its own origin (DESIGN-v1.3d §5.1)."""
    errors = []
    host = settings.SSO_ADMIN_UI_HOSTNAME
    if settings.SSO_ADMIN_UI_ENABLED and host and settings.ALLOWED_HOSTS and "*" not in settings.ALLOWED_HOSTS \
            and host not in settings.ALLOWED_HOSTS:
        errors.append(Error(f"SSO_ADMIN_UI_HOSTNAME {host!r} is not in SSO_ALLOWED_HOSTS.",
                            hint="Add it to SSO_ALLOWED_HOSTS and SSO_CSRF_TRUSTED_ORIGINS.", id="adminui.E001"))
    return errors
