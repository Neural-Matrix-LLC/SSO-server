"""Database connectivity check shared by /healthz and the container start-up check.

Every failure is logged at ERROR on the ``sso.db`` logger (stdout in the container) with the DB host,
port and name and the exception class/message. The password is never logged.
"""
import logging

from django.db import connections

logger = logging.getLogger("sso.db")


def db_target(alias: str = "default") -> str:
    s = connections.databases[alias]
    return f"{s.get('HOST') or 'localhost'}:{s.get('PORT') or 'default'} db={s.get('NAME')}"


def check_database(context: str, alias: str = "default") -> bool:
    """Run SELECT 1. Returns True on success; logs an ERROR and returns False on any failure."""
    conn = connections[alias]
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as exc:  # noqa: BLE001 - any driver/network error means "unhealthy"
        logger.error(
            "%s: database unreachable at %s (%s: %s). Check MySQL is reachable from the container "
            "(bind-address, firewall, user host, SSO_DBHOST/SSO_DBPORT).",
            context, db_target(alias), exc.__class__.__name__, exc,
        )
        try:  # drop the broken connection so the next request reconnects
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        return False
    return True
