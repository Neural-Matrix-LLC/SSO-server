"""Process-level facts used by the settings fail-fast and the system checks."""
from __future__ import annotations

import os

ROOT_MESSAGE = (
    "Refusing to run as root (uid 0) with SSO_DEBUG=False. Run the server and manage.py as the non-root "
    "container user SSO_UID:SSO_GID (default 10001:10001; docker-compose.yml sets user: accordingly), "
    "e.g. docker compose exec web ... or docker run --user 10001:10001 ..."
)


def running_as_root() -> bool:
    """True if the effective uid is 0. Platforms without os.geteuid (Windows) never count as root."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0
