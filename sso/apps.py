from django.apps import AppConfig


class SsoConfig(AppConfig):
    name = "sso"
    label = "sso"  # must not clash with myFinance app labels in the shared django_migrations (spec §4.5)
    verbose_name = "Single sign-on"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        import logging

        from . import checks, signals  # noqa: F401

        # once per process (gunicorn does not run system checks; sso.W001 covers manage.py)
        for msg in checks.deprecated_key_messages():
            logging.getLogger("sso").warning(msg)
