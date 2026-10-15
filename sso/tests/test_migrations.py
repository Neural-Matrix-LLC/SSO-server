"""Addendum B.11: no migrations that touch shared tables; makemigrations --check is clean."""
from __future__ import annotations

import pytest
from django.core.management import call_command
from django.db import connection
from django.db.migrations import operations as ops
from django.db.migrations.loader import MigrationLoader

SHARED_APPS = {"auth", "contenttypes", "sessions", "admin"}
OWNED_APPS = {"sso", "application", "token_blacklist"}  # design A1
# Leaf migrations of Django's shared apps; identical from Django 4.1 (myFinance) to 5.2, so `migrate`
# is a no-op for them on dcWebUsers (spec §4.4).
EXPECTED_SHARED_LEAVES = {
    ("auth", "0012_alter_user_first_name_max_length"),
    ("contenttypes", "0002_remove_content_type_name"),
    ("sessions", "0001_initial"),
    ("admin", "0003_logentry_add_action_flag_choices"),
}


def test_makemigrations_check_reports_no_changes(db):
    # raises SystemExit(1) if any model change lacks a migration
    call_command("makemigrations", "--check", "--dry-run", verbosity=0)


def test_only_sso_application_and_token_blacklist_own_migrations(db):
    loader = MigrationLoader(connection, ignore_no_migrations=True)
    apps_with_migrations = {app for app, _ in loader.disk_migrations}
    assert apps_with_migrations == SHARED_APPS | OWNED_APPS
    leaves = {(a, n) for a, n in loader.graph.leaf_nodes() if a in SHARED_APPS}
    assert leaves == EXPECTED_SHARED_LEAVES
    for (app, name), migration in loader.disk_migrations.items():
        if app in SHARED_APPS:
            # shared apps' migrations must be Django's own, not overridden by this project
            assert type(migration).__module__.startswith(f"django.contrib.{app}.migrations"), (app, name)


def test_sso_migrations_only_create_or_alter_sso_models(db):
    loader = MigrationLoader(connection, ignore_no_migrations=True)
    allowed = (ops.CreateModel, ops.AddField, ops.AlterField, ops.AddIndex, ops.AlterModelOptions,
               ops.AddConstraint, ops.RemoveField, ops.DeleteModel, ops.RenameField)
    for (app, _name), migration in loader.disk_migrations.items():
        if app not in {"sso", "application"}:
            continue
        for op in migration.operations:
            assert isinstance(op, allowed), op  # no RunSQL/RunPython against shared tables
        for dep_app, _ in migration.dependencies:
            assert dep_app in {"sso", "application", "auth", "__setting__"}


def test_sso_tables_are_prefixed(db):
    from django.apps import apps

    for label in ("sso", "application"):
        for model in apps.get_app_config(label).get_models():
            if model._meta.proxy:  # ApplicationPermission: proxy over auth.Permission, no table of its own
                assert model._meta.db_table == "auth_permission"
                continue
            assert model._meta.db_table.startswith("sso_"), model


def test_application_migration_creates_no_shared_tables(db):
    """The proxy model must not create or alter auth_permission; only the two sso_application_* tables."""
    loader = MigrationLoader(connection, ignore_no_migrations=True)
    created = []
    for (app, _name), migration in loader.disk_migrations.items():
        if app != "application":
            continue
        for op in migration.operations:
            if isinstance(op, ops.AddField):  # v1.3a: new nullable columns on our own registry table
                assert op.model_name == "applicationpermissionrecord", op
                continue
            if isinstance(op, ops.AlterModelOptions):  # v1.3a: sso_admin added to Meta.permissions
                assert op.name == "applicationaccess", op
                continue
            assert isinstance(op, ops.CreateModel), op
            if not op.options.get("proxy"):
                created.append(op.options["db_table"])
    assert sorted(created) == ["sso_application", "sso_application_access", "sso_application_permission_record"]
