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


# SSO-owned Django apps whose migrations this server needs (the shared dcWebUsers DB also holds other apps'
# tables, which are not our business).
SSO_MIGRATION_APPS = ("sso", "application", "token_blacklist")

_last_pending_log = 0.0


def pending_migrations(alias: str = "default") -> list[str]:
    """Return 'app.migration' names of SSO-owned migrations not yet applied to the database."""
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connections[alias])
    targets = executor.loader.graph.leaf_nodes()
    plan = executor.migration_plan(targets)
    return [f"{m.app_label}.{m.name}" for m, backwards in plan
            if not backwards and m.app_label in SSO_MIGRATION_APPS]


def check_migrations(context: str, alias: str = "default", min_interval: float = 0.0) -> bool:
    """Log an ERROR if SSO migrations are pending (schema older than the code). Returns True when up to date.

    ``min_interval`` (seconds) rate-limits the ERROR line for repeated callers such as /healthz. Never raises.
    """
    global _last_pending_log
    import time

    try:
        pending = pending_migrations(alias)
    except Exception as exc:  # noqa: BLE001 - DB down is reported by check_database
        logger.error("%s: could not check database migrations at %s (%s: %s)",
                     context, db_target(alias), exc.__class__.__name__, exc)
        return False
    if not pending:
        return True
    now = time.monotonic()
    if not min_interval or now - _last_pending_log >= min_interval:
        _last_pending_log = now
        logger.error(
            "%s: database schema at %s is behind the code: %d pending migration(s): %s. "
            "Run scripts/upgrade_db.sh (docs/SSO-Setup.md, 'Upgrading the database').",
            context, db_target(alias), len(pending), ", ".join(pending),
        )
    return False
