"""Seed for bb_v13d.py: run with manage.py shell -c "exec(open('qa/blackbox/bb_v13d_seed.py').read())".
Creates qa_admin (staff + application.sso_admin) and qa_plain (no admin rights) with passwords from env."""
import os

from django.contrib.auth.models import Permission, User

a, _ = User.objects.get_or_create(username="qa_admin", defaults={"email": "qa_admin@example.org"})
a.is_staff = True
a.is_active = True
a.set_password(os.environ["BB_PW"])
a.save()
a.user_permissions.add(Permission.objects.get(content_type__app_label="application", codename="sso_admin"))
p, _ = User.objects.get_or_create(username="qa_plain", defaults={"email": "qa_plain@example.org"})
p.set_password(os.environ["BB_PLAIN_PW"])
p.save()
print("seeded")
