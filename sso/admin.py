"""Admin for ServiceClient (spec §9.2) and read-only revocation markers."""
from django import forms
from django.contrib import admin, messages

from .models import ServiceClient, UserTokenRevocation


class ServiceClientForm(forms.ModelForm):
    regenerate_secret = forms.BooleanField(
        required=False,
        help_text="Generate a new client secret. It is shown ONCE after saving; only its hash is stored.",
    )

    class Meta:
        model = ServiceClient
        fields = ["client_id", "name", "is_active", "allowed_origins", "redirect_uris"]


@admin.register(ServiceClient)
class ServiceClientAdmin(admin.ModelAdmin):
    form = ServiceClientForm
    list_display = ["client_id", "name", "is_active", "created"]
    list_filter = ["is_active"]
    search_fields = ["client_id", "name"]
    readonly_fields = ["created"]

    def save_model(self, request, obj, form, change):
        if not change or form.cleaned_data.get("regenerate_secret"):
            secret = ServiceClient.generate_secret()
            obj.set_secret(secret)
            messages.warning(
                request,
                f"Client secret for '{obj.client_id}': {secret} -- copy it now, it will not be shown again.",
            )
        super().save_model(request, obj, form, change)


@admin.register(UserTokenRevocation)
class UserTokenRevocationAdmin(admin.ModelAdmin):
    list_display = ["user", "revoked_at"]
    search_fields = ["user__username", "user__email"]
    raw_id_fields = ["user"]
