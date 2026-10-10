from django.apps import AppConfig


class SsoConfig(AppConfig):
    name = "sso"
    label = "sso"  # must not clash with myFinance app labels in the shared django_migrations (spec §4.5)
    verbose_name = "Single sign-on"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from . import checks, signals  # noqa: F401
