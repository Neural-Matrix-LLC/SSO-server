"""Client-IP derivation (SSO design v1.2 §4.5). Pure functions, no I/O, no framework imports.

Must stay identical to ``sso/clientip.py`` in the SSO-server: the IP the SSO binds into a token and the IP a
service reports to introspect have to be derived the same way.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Mapping, Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
__all__ = ["normalize_ip", "parse_trusted", "get_client_ip", "peer_from_socket", "walk"]


def normalize_ip(value) -> str | None:
    """Canonical text form or None: strips port, brackets, zone id and quotes; ``::ffff:a.b.c.d`` -> ``a.b.c.d``;
    IPv6 compressed lower case. Accepts (host, port, ...) tuples."""
    if isinstance(value, (tuple, list)):
        value = value[0] if value else None
    if not isinstance(value, str):
        return None
    v = value.strip().strip('"').strip()
    if not v:
        return None
    if v.startswith("["):
        end = v.find("]")
        if end < 0:
            return None
        v = v[1:end]
    elif v.count(":") == 1:
        v = v.split(":", 1)[0]
    v = v.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_trusted(value: str | Iterable[str | Network] | None) -> tuple[Network, ...]:
    """``"127.0.0.1, 172.18.0.0/16"`` or a list -> networks. ValueError on a bad entry or ``/0``."""
    if value is None:
        return ()
    items = value.split(",") if isinstance(value, str) else list(value)
    nets: list[Network] = []
    for item in items:
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            nets.append(item)
            continue
        item = item.strip()
        if not item:
            continue
        net = ipaddress.ip_network(item, strict=False)
        if net.prefixlen == 0:
            raise ValueError(f"refusing to trust every address ({item})")
        if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None \
                and net.prefixlen >= 96:
            net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
        nets.append(net)
    return tuple(nets)


def _trusted(ip: str, nets: Sequence[Network]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr.version == n.version and addr in n for n in nets)


def _text(v) -> str:
    return v.decode("latin-1") if isinstance(v, bytes) else str(v)


def _header_values(headers, name: str) -> list[str]:
    """Every value of header ``name``, in order. ``headers``: a mapping (dict, Django ``request.headers``,
    Starlette / Werkzeug headers with ``getlist``) or (name, value) pairs (ASGI raw headers)."""
    if not headers:
        return []
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        return [_text(v) for v in getlist(name)]
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    wanted = name.lower()
    return [_text(v) for k, v in pairs if _text(k).lower() == wanted]


def _xff_values(headers) -> list[str]:
    return _header_values(headers, "X-Forwarded-For")


def walk(peer_ip: str, values: Iterable[str], trusted: Sequence[Network]) -> tuple[str, bool]:
    """Right-to-left walk of comma-separated header ``values`` from a trusted ``peer_ip`` (§4.5.2).
    Returns (ip, whether any valid entry was used)."""
    ip, used = peer_ip, False
    entries = [e for value in values for e in value.split(",")]
    for raw in reversed(entries):
        entry = normalize_ip(raw)
        if entry is None:
            break  # malformed: keep the last good value
        ip, used = entry, True
        if not _trusted(entry, trusted):
            break
    return ip, used


def get_client_ip(peer_addr, headers=None, trusted_proxies: Sequence[Network | str] | str = (),
                  client_ip_header: str | None = None) -> str | None:
    """The client IP: the socket peer, or (only when the peer is a trusted proxy) the right-to-left walk of
    ``X-Forwarded-For``: first untrusted entry; malformed entry -> last good one; all trusted -> leftmost.

    ``client_ip_header`` (e.g. ``cf-connecting-ip``, ``x-real-ip``; ``SSO_CLIENT_IP_HEADER``): a header set by
    your trusted proxy. Read only when the peer is trusted, with the same walk; when it is absent or holds no
    valid IP, the X-Forwarded-For logic applies. Never configure a header that clients can set directly
    through a trusted hop."""
    trusted = parse_trusted(trusted_proxies) if isinstance(trusted_proxies, str) or any(
        isinstance(t, str) for t in trusted_proxies) else tuple(trusted_proxies)
    ip = normalize_ip(peer_addr)
    if ip is None or not trusted or not _trusted(ip, trusted):
        return ip
    name = (client_ip_header or "").strip()
    if name and name.lower() != "x-forwarded-for":
        found, used = walk(ip, _header_values(headers, name), trusted)
        if used:
            return found
    return walk(ip, _xff_values(headers), trusted)[0]


def peer_from_socket(sock: socket.socket) -> str | None:
    """``getpeername()`` of a TCP socket (AF_INET / AF_INET6); None for AF_UNIX or a closed socket."""
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return None
    try:
        return normalize_ip(sock.getpeername())
    except OSError:
        return None
