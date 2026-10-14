from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class User:
    id: str
    username: str
    email: str = ""
    is_staff: bool = False
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckResult:
    active: bool
    user: User | None = None
    permissions: frozenset[str] = field(default_factory=frozenset)
    ip_binding: str | None = None        # NOIP | WARNING | ENFORCE
    ip_match: bool | None = None         # None: not checked (NOIP or unbound token)
    session_id: str | None = None        # sid
    expires_at: datetime | None = None
    allowed: bool | None = None          # answer to "require", when sent
    client_ip: str | None = None
    reason: str | None = None

    def has(self, *perms: str) -> bool:
        return self.active and set(perms) <= self.permissions

    @classmethod
    def from_response(cls, body: dict, client_ip: str | None) -> "CheckResult":
        if not body.get("active"):
            return cls(active=False, client_ip=client_ip, reason="inactive")
        exp = body.get("exp")
        return cls(
            active=True,
            user=User(id=str(body.get("sub", "")), username=body.get("username", ""), email=body.get("email", ""),
                      is_staff=bool(body.get("is_staff")), groups=tuple(body.get("groups") or ())),
            permissions=frozenset(body.get("perms") or ()),
            ip_binding=body.get("ip_binding"),
            ip_match=body.get("ip_match"),
            session_id=body.get("sid"),
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc) if isinstance(exp, (int, float)) else None,
            allowed=body.get("allowed"),
            client_ip=client_ip,
        )
