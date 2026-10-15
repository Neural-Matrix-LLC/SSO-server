"""Verify that the SSO-owned schema is at the code's level (used by scripts/upgrade_db.sh after ``migrate``).

    python manage.py sso_schema_check            # exit 0 = complete, 1 = something missing / unapplied

Checks (read-only): every SSO migration (sso, application, token_blacklist) is applied, and the tables and
columns each version added exist. The list is written out by hand on purpose, so it is an independent check
of what the migrations did (docs/db/upgrade-v1.2-to-v1.3.sql lists the same objects).
"""
from django.core.management.base import BaseCommand
from django.db import DEFAULT_DB_ALIAS, connections
from django.db.migrations.executor import MigrationExecutor

OWNED_APPS = ("sso", "application", "token_blacklist")

# version -> {table: [columns added in that version]}; a table listed first time = created in that version
EXPECTED = {
    "v1.1": {
        "sso_serviceclient": ["id", "client_id", "name", "client_secret_hash", "is_active", "created"],
        "sso_authorizationcode": ["id"],
        "sso_usertokenrevocation": ["id", "user_id", "revoked_at"],
        "sso_application_access": ["id"],
        "sso_application_permission_record": ["id", "codename", "name", "permission_id"],
        "token_blacklist_outstandingtoken": ["id", "jti"],
        "token_blacklist_blacklistedtoken": ["id", "token_id"],
    },
    "v1.2": {
        "sso_serviceclient": ["app_codename", "notify_url"],
        "sso_revokedsession": ["id", "sid", "revoked_at", "reason", "user_id"],
    },
    "v1.3a": {
        "sso_serviceclient": ["secret_rotated_at"],
        "sso_serviceclient_permissions": ["id", "serviceclient_id", "permission_id"],
        "sso_adminauditlog": ["id", "ts", "actor_type", "actor_id", "actor_ip", "action", "target_type", "target_id",
                              "before", "after", "request_id", "result", "stepup"],
        "sso_adminreauth": ["id", "token_hash", "sid", "ip", "created", "user_id"],
        "sso_application": ["id", "app_codename", "name", "description", "version"],
        "sso_application_permission_record": ["app_codename", "deprecated_at", "description"],
        "sso_usertombstone": ["id", "user_id", "username", "deleted_at"],
    },
    "v1.3b": {
        "sso_serviceclient": ["can_delegate", "can_register_devices", "device_name", "kind", "last_used", "owner_id",
                              "public_key", "public_key_fingerprint"],
    },
    "v1.3c": {
        "sso_serviceclient": ["notify_events", "notify_secret_enc"],
        "sso_webhookevent": ["id", "type", "created", "data"],
        "sso_webhookdelivery": ["id", "event_id", "client_id", "status", "attempts", "next_attempt_at",
                                "window_start", "claimed_at", "last_status", "last_error", "delivered_at"],
    },
}


class Command(BaseCommand):
    help = "Read-only check that all SSO migrations are applied and the v1.1-v1.3 tables/columns exist."

    def add_arguments(self, parser):
        parser.add_argument("--database", default=DEFAULT_DB_ALIAS)
        parser.add_argument("--counts", action="store_true",
                            help="only print 'COUNT <table> <rows>' for auth_user and the SSO tables that exist; "
                                 "no checks (upgrade_db.sh compares before/after)")

    def handle(self, database, counts=False, **options):
        conn = connections[database]
        if counts:
            with conn.cursor() as cur:
                tables = set(conn.introspection.table_names(cur))
                wanted = ["auth_user", "auth_group", "auth_user_groups", "auth_user_user_permissions",
                          "auth_permission"] + sorted({t for spec in EXPECTED.values() for t in spec})
                for t in wanted:
                    if t in tables:
                        cur.execute(f"SELECT COUNT(*) FROM {conn.ops.quote_name(t)}")
                        self.stdout.write(f"COUNT {t} {cur.fetchone()[0]}")
            return
        problems = []
        executor = MigrationExecutor(conn)
        targets = executor.loader.graph.leaf_nodes()
        pending = [m for m, _ in executor.migration_plan(targets)]
        own = [f"{m.app_label}.{m.name}" for m in pending if m.app_label in OWNED_APPS]
        other = [f"{m.app_label}.{m.name}" for m in pending if m.app_label not in OWNED_APPS]
        if own:
            problems.append("unapplied SSO migrations: " + ", ".join(own))
        if other:  # shared apps (auth, admin, ...) must never be migrated from here: report only
            self.stdout.write("NOTE shared-app migrations pending (not ours, not applied): " + ", ".join(other))
        with conn.cursor() as cur:
            tables = set(conn.introspection.table_names(cur))
            cols_cache = {}
            for version, spec in EXPECTED.items():
                missing = []
                for table, cols in spec.items():
                    if table not in tables:
                        missing.append(f"table {table}")
                        continue
                    if table not in cols_cache:
                        cols_cache[table] = {c.name for c in conn.introspection.get_table_description(cur, table)}
                    missing += [f"{table}.{c}" for c in cols if c not in cols_cache[table]]
                self.stdout.write(f"{'OK ' if not missing else 'MISSING'} {version}: "
                                  + (f"{len(spec)} tables checked" if not missing else ", ".join(missing)))
                if missing:
                    problems.append(f"{version}: " + ", ".join(missing))
        if problems:
            for p in problems:
                self.stderr.write("ERROR " + p)
            raise SystemExit(1)
        self.stdout.write("schema OK: all SSO migrations applied, v1.1-v1.3c tables and columns present")
