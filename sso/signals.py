"""Token revocation driven by changes to ``auth_user`` made through this Django project.

* Password change (spec §6.6/§6.9): revokes all of the user's tokens.
* Suspend (design v1.2a, decision 6): ``is_active`` True -> False through ``Model.save()`` (admin form or
  action, shell, any code) revokes all of the user's tokens at once: ``UserTokenRevocation`` marker plus
  every outstanding refresh token blacklisted, in the same transaction as the save.
* Reactivate (False -> True) revokes again. Tokens issued before the reactivation therefore stay dead even
  when the suspension itself bypassed the signal (see below); new logins work.

Not covered by signals: ``QuerySet.update(is_active=False)`` and writes from other processes (myFinance) do
not send ``pre_save``/``post_save``. Those are handled by defence in depth: every token check (refresh,
introspect, ``/me``) rejects an inactive user, and a still-valid token of an inactive user revokes the user
on sight (``sso.views.revoke_if_inactive``); ``manage.py revoke_inactive_users`` sweeps all inactive users.
"""
import json
import logging

from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver

admin_logger = logging.getLogger("sso.admin")


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


@receiver(pre_save, sender=User, dispatch_uid="sso_note_is_active_change")
def note_is_active_change(sender, instance: User, raw=False, update_fields=None, **kwargs):
    instance._sso_is_active_change = None
    if raw or instance.pk is None:
        return
    if update_fields is not None and "is_active" not in update_fields:
        return
    old = sender.objects.filter(pk=instance.pk).values_list("is_active", flat=True).first()
    if old is not None and bool(old) != bool(instance.is_active):
        instance._sso_is_active_change = bool(instance.is_active)


@receiver(post_save, sender=User, dispatch_uid="sso_revoke_on_suspend")
def revoke_on_is_active_change(sender, instance: User, created=False, raw=False, **kwargs):
    now_active = getattr(instance, "_sso_is_active_change", None)
    instance._sso_is_active_change = None
    if raw or created or now_active is None:
        return
    from .revocation import revoke_user_tokens

    revoke_user_tokens(instance)
    if not now_active:  # v1.3b: the owner's gateway devices are cut off with the suspension (stay off after)
        from .devices import deactivate_owner_devices

        deactivate_owner_devices(instance)
    event = "user.reactivated" if now_active else "user.suspended"
    admin_logger.info(json.dumps({"event": event, "user_id": instance.pk, "tokens_revoked": True},
                                 sort_keys=True))


@receiver(post_delete, sender=User, dispatch_uid="sso_user_tombstone")
def write_tombstone(sender, instance: User, **kwargs):
    """v1.3a: every deletion leaves a tombstone for the inactive-users feed (and v1.3c ``user.deleted``)."""
    from .models import UserTombstone

    UserTombstone.objects.create(user_id=instance.pk, username=instance.get_username())
    admin_logger.info(json.dumps({"event": "user.deleted", "user_id": instance.pk}, sort_keys=True))
