from django.apps import AppConfig


class AdminUIConfig(AppConfig):
    """v1.3d SSO admin web UI (docs/DESIGN-v1.3d-admin-ui.md). No models, no migrations."""

    name = "adminui"
    label = "adminui"
    verbose_name = "SSO admin UI"

    def ready(self) -> None:
        from . import checks  # noqa: F401  (registers system checks)
