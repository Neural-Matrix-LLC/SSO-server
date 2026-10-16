"""v1.3d (DESIGN-v1.3d-admin-ui.md §13): sso_adminauditlog.channel = api | ui | django_admin | system.

Additive and reversible (the column is dropped on rollback). Existing rows get the default "api" (before v1.3d only
the admin API wrote audit rows). No RunPython/RunSQL (shared-database rule, sso/tests/test_migrations.py).
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sso', '0006_v13c'),
    ]

    operations = [
        migrations.AddField(
            model_name='adminauditlog',
            name='channel',
            field=models.CharField(db_index=True, default='api', max_length=16),
        ),
    ]
