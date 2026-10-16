"""Client-IP derivation (design v1.2 §4.5), the same algorithm as ``sso_client.get_client_ip``.

* Root of trust: the socket peer (``REMOTE_ADDR``).
* ``SSO_TRUSTED_PROXIES`` (IPs / CIDRs): only when the peer is trusted is ``X-Forwarded-For`` read, walked right to
  left; the first untrusted entry is the client (malformed entry: stop, keep the last good one; all trusted: the
  leftmost valid entry).
* ``SSO_NUM_PROXIES`` (deprecated, warning sso.W002): used only when ``SSO_TRUSTED_PROXIES`` is unset, with DRF's
  hop-count logic as before.
* Normalisation (§4.5.4): ports, brackets and IPv6 zone ids stripped, ``::ffff:a.b.c.d`` -> ``a.b.c.d``, IPv6 in
  canonical compressed form; unparseable -> None.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def normalize_ip(value) -> str | None:
    """Canonical text form of an IP address, or None. Accepts ``1.2.3.4:80``, ``[::1]:443``, ``fe80::1%eth0``,
    ``"for=..."``-style quoting and (host, port, ...) tuples."""
    if isinstance(value, (tuple, list)):
        value = value[0] if value else None
    if not isinstance(value, str):
        return None
    v = value.strip().strip('"').strip()
    if not v:
        return None
    if v.startswith("["):  # [v6] or [v6]:port
        end = v.find("]")
        if end < 0:
            return None
        v = v[1:end]
    elif v.count(":") == 1:  # v4:port
        v = v.split(":", 1)[0]
    v = v.split("%", 1)[0]  # IPv6 zone id
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_trusted(value: str | Iterable[str | Network] | None) -> tuple[Network, ...]:
    """``"127.0.0.1, 172.18.0.0/16"`` or a list -> networks. Raises ValueError on a bad entry."""
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


def _walk(ip: str, values: Iterable[str], trusted: Sequence[Network]) -> tuple[str, bool]:
    used = False
    entries = [e for value in values for e in value.split(",")]
    for raw in reversed(entries):
        entry = normalize_ip(raw)
        if entry is None:
            break  # malformed: keep the last good value
        ip, used = entry, True
        if not _trusted(entry, trusted):
            break
    return ip, used


def walk_forwarded(peer, xff_values: Iterable[str], trusted: Sequence[Network],
                   header_values: Iterable[str] | None = None) -> str | None:
    """§4.5.2. ``xff_values``: every X-Forwarded-For header value (joined in order). ``header_values``: the
    values of a custom client-IP header (``SSO_CLIENT_IP_HEADER``), preferred when it holds a valid IP."""
    ip = normalize_ip(peer)
    if ip is None or not trusted or not _trusted(ip, trusted):
        return ip
    if header_values is not None:
        found, used = _walk(ip, header_values, trusted)
        if used:
            return found
    return _walk(ip, xff_values, trusted)[0]


def request_ip(request) -> str | None:
    """Trusted client IP of a Django / DRF request (socket peer + trusted-proxy walk)."""
    from django.conf import settings

    django_request = getattr(request, "_request", request)
    meta = django_request.META
    trusted = getattr(settings, "SSO_TRUSTED_PROXIES_PARSED", ())
    if trusted:
        xff = meta.get("HTTP_X_FORWARDED_FOR")
        name = getattr(settings, "SSO_CLIENT_IP_HEADER", "")
        custom = None
        if name and name.lower() != "x-forwarded-for":
            value = meta.get("HTTP_" + name.upper().replace("-", "_"))
            custom = [value] if value else []
        return walk_forwarded(meta.get("REMOTE_ADDR"), [xff] if xff else [], trusted, custom)
    # deprecated fallback: DRF hop count (SSO_NUM_PROXIES), then normalised
    from rest_framework.throttling import BaseThrottle

    return normalize_ip(BaseThrottle().get_ident(django_request))
