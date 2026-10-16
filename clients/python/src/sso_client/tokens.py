"""0.2: obtaining tokens for outgoing calls (SSO design v1.3a §6, v1.3b §4).

* ``ServiceTokenSource(config)``: client-credentials service token (Basic client_id:secret), cached and renewed
  ``margin`` seconds before ``exp``. Thread-safe.
* ``DeviceTokenSource(base_url, client_id, private_key_pem)``: device token with an RFC 7523 ``private_key_jwt``
  assertion signed by the device's Ed25519 key (extra ``sso-client[device]``: PyJWT + cryptography).
Tokens are never logged.
"""
from __future__ import annotations

import threading
import time
import uuid

import httpx

from .config import SSOConfig
from .errors import SSOConfigError, SSOProtocolError, SSOUnavailable

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
PATH = "/api/v1/auth/service-token"


class _Source:
    def __init__(self, base_url: str, *, http: httpx.Client | None, margin: float, timeout: float):
        self.url = base_url.rstrip("/") + PATH
        self.http = http or httpx.Client()
        self.margin = margin
        self.timeout = timeout
        self._lock = threading.Lock()
        self._token: str | None = None
        self._exp = 0.0

    def _request(self) -> httpx.Response:  # pragma: no cover - overridden
        raise NotImplementedError

    def get(self) -> str:
        with self._lock:
            if self._token and time.time() < self._exp - self.margin:
                return self._token
            try:
                resp = self._request()
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                raise SSOUnavailable(f"SSO unreachable: {type(exc).__name__}") from None
            if resp.status_code == 429 or resp.status_code >= 500:
                raise SSOUnavailable(f"SSO answered {resp.status_code}")
            if resp.status_code != 200:
                raise SSOProtocolError(f"SSO answered {resp.status_code}", resp.status_code)
            body = resp.json()
            self._token = body["access_token"]
            self._exp = time.time() + float(body.get("expires_in", 300))
            return self._token

    def invalidate(self) -> None:
        with self._lock:
            self._token, self._exp = None, 0.0


class ServiceTokenSource(_Source):
    def __init__(self, config: SSOConfig, *, http: httpx.Client | None = None, margin: float = 30.0):
        super().__init__(config.base_url, http=http, margin=margin, timeout=config.timeout)
        self._auth = httpx.BasicAuth(config.client_id, config.client_secret)

    def _request(self) -> httpx.Response:
        return self.http.post(self.url, json={"grant_type": "client_credentials"}, auth=self._auth,
                              timeout=self.timeout)


class DeviceTokenSource(_Source):
    def __init__(self, base_url: str, client_id: str, private_key_pem: bytes, *, http: httpx.Client | None = None,
                 margin: float = 30.0, timeout: float = 5.0, assertion_ttl: int = 120, allow_http: bool = False,
                 audience: str | None = None):
        if not base_url.startswith("https://") and not (allow_http and base_url.startswith("http://")):
            raise SSOConfigError("SSO base_url must be https://")
        try:
            import jwt  # noqa: F401
            from cryptography.hazmat.primitives import serialization
        except ImportError:  # pragma: no cover
            raise SSOConfigError("DeviceTokenSource needs the 'device' extra: pip install sso-client[device]") from None
        super().__init__(base_url, http=http, margin=margin, timeout=timeout)
        self.client_id = client_id
        self._key = serialization.load_pem_private_key(private_key_pem, password=None)
        self.audience = audience or self.url
        self.assertion_ttl = assertion_ttl

    def assertion(self) -> str:
        import jwt

        now = int(time.time())
        return jwt.encode({"iss": self.client_id, "sub": self.client_id, "aud": self.audience, "iat": now,
                           "exp": now + self.assertion_ttl, "jti": uuid.uuid4().hex}, self._key, algorithm="EdDSA")

    def _request(self) -> httpx.Response:
        return self.http.post(self.url, json={"grant_type": "client_credentials", "client_assertion_type": ASSERTION_TYPE,
                                              "client_assertion": self.assertion()}, timeout=self.timeout)


def generate_device_key() -> tuple[bytes, str]:
    """(private key PEM, public key PEM) of a new Ed25519 key pair. Keep the private key on the device only."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub.decode()
