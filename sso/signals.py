"""A password change made through this Django project revokes the user's tokens (spec §6.6/§6.9).

Note: password changes made in myFinance write ``auth_user`` from another process and do not
fire this signal (see README "Open questions").
"""
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver


@receiver(pre_save, sender=User, dispatch_uid="sso_revoke_on_password_change")
def revoke_on_password_change(sender, instance: User, raw=False, update_fields=None, **kwargs):
    if raw or instance.pk is None:
        return
    if update_fields is not None and "password" not in update_fields:
        return
    # set_password() keeps the raw password in _password until save(). Django's transparent
    # re-hash on login (more PBKDF2 iterations) clears it first, so it never revokes.
    new_raw = getattr(instance, "_password", None)
    if new_raw is None:
        return
    old_hash = sender.objects.filter(pk=instance.pk).values_list("password", flat=True).first()
    if old_hash is None or check_password(new_raw, old_hash):
        return
    from .models import UserTokenRevocation

    UserTokenRevocation.revoke(instance)
