from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .errors import SSOConfigError
from .ip import Network, parse_trusted

MAX_CACHE_TTL = 30.0


def _bool(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class SSOConfig:
    """Library configuration (design §9). ``SSOConfig.from_env()`` reads the ``SSO_*`` variables."""

    base_url: str
    client_id: str
    client_secret: str = field(repr=False)
    trusted_proxies: tuple[Network, ...] = ()
    client_ip_header: str = ""  # e.g. "cf-connecting-ip"; only from trusted proxies
    timeout: float = 2.0
    connect_timeout: float = 1.0
    retries: int = 2
    cache_ttl: float = 30.0
    cache_size: int = 10_000
    allow_http: bool = False

    def __post_init__(self):
        if not self.base_url or not self.client_id or not self.client_secret:
            raise SSOConfigError("base_url, client_id and client_secret are required")
        url = self.base_url.rstrip("/")
        if not url.startswith("https://") and not (self.allow_http and url.startswith("http://")):
            raise SSOConfigError("SSO base_url must be https:// (set allow_http / SSO_ALLOW_HTTP=true for tests)")
        object.__setattr__(self, "base_url", url)
        if isinstance(self.trusted_proxies, str) or any(isinstance(t, str) for t in self.trusted_proxies):
            try:
                object.__setattr__(self, "trusted_proxies", parse_trusted(self.trusted_proxies))
            except ValueError as exc:
                raise SSOConfigError(f"trusted_proxies: {exc}") from None
        if self.client_ip_header and not self.trusted_proxies:
            raise SSOConfigError("client_ip_header (SSO_CLIENT_IP_HEADER) needs trusted_proxies (SSO_TRUSTED_PROXIES)")
        if self.cache_ttl < 0 or self.timeout <= 0 or self.retries < 0:
            raise SSOConfigError("cache_ttl >= 0, timeout > 0, retries >= 0")
        object.__setattr__(self, "cache_ttl", min(float(self.cache_ttl), MAX_CACHE_TTL))  # agreed maximum

    @property
    def introspect_url(self) -> str:
        return self.base_url + "/api/v1/auth/introspect"

    @classmethod
    def from_env(cls, env: dict | None = None, **overrides) -> "SSOConfig":
        e = os.environ if env is None else env
        secret = e.get("SSO_CLIENT_SECRET", "")
        if not secret and e.get("SSO_CLIENT_SECRET_FILE"):
            try:
                secret = Path(e["SSO_CLIENT_SECRET_FILE"]).read_text().strip()
            except OSError as exc:
                raise SSOConfigError(f"SSO_CLIENT_SECRET_FILE: {exc.strerror}") from None
        try:
            kw = dict(
                base_url=e.get("SSO_BASE_URL", ""), client_id=e.get("SSO_CLIENT_ID", ""), client_secret=secret,
                trusted_proxies=e.get("SSO_TRUSTED_PROXIES", ""),
                client_ip_header=e.get("SSO_CLIENT_IP_HEADER", "").strip(), timeout=float(e.get("SSO_TIMEOUT", "2.0")),
                retries=int(e.get("SSO_RETRIES", "2")), cache_ttl=float(e.get("SSO_CACHE_TTL", "30")),
                allow_http=_bool(e.get("SSO_ALLOW_HTTP", "false")))
        except ValueError as exc:
            raise SSOConfigError(str(exc)) from None
        kw.update(overrides)
        return cls(**kw)
