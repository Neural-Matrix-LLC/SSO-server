from django.apps import AppConfig


class ApplicationConfig(AppConfig):
    """Central per-application permissions: ``application.<codename>`` (docs/sso-integration-design.md A1)."""

    name = "application"
    label = "application"  # no clash with myFinance's main/predicts/rebalance/perfreports, nor with sso
    verbose_name = "Applications"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.db.models.signals import post_migrate

        from .permissions import sync_after_migrate

        # runs after contenttypes/auth's own post_migrate handlers (they are connected earlier)
        post_migrate.connect(sync_after_migrate, sender=self, dispatch_uid="application_sync_permissions")
