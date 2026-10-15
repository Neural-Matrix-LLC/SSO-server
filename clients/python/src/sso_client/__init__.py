"""sso-client: client-IP derivation and the SSO permission query for services (SSO design v1.2 §4.4-4.5)."""
from .cache import TTLCache
from .client import AsyncSSOClient, SSOClient, bearer_token, on_behalf_of_headers, resolve_request
from .config import SSOConfig
from .errors import (
    NotAuthenticated,
    PermissionDenied,
    SSOConfigError,
    SSOError,
    SSOProtocolError,
    SSOUnavailable,
    TokenInactive,
)
from .ip import get_client_ip, normalize_ip, parse_trusted, peer_from_socket
from .models import CheckResult, ServiceCheck, User
from .tokens import DeviceTokenSource, ServiceTokenSource, generate_device_key
from .responses import error_response
from .webhooks import WebhookReceiver, WebhookVerificationError, verify_webhook

__version__ = "0.2.0"
__all__ = [
    "AsyncSSOClient", "CheckResult", "NotAuthenticated", "PermissionDenied", "SSOClient", "SSOConfig",
    "SSOConfigError", "SSOError", "SSOProtocolError", "SSOUnavailable", "TTLCache", "TokenInactive", "User",
    "DeviceTokenSource", "ServiceCheck", "ServiceTokenSource", "generate_device_key", "on_behalf_of_headers",
    "resolve_request", "bearer_token", "error_response", "get_client_ip", "normalize_ip", "parse_trusted", "peer_from_socket",
    "WebhookReceiver", "WebhookVerificationError", "verify_webhook", "__version__",
]
