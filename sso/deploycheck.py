"""Post-start deployment checks run inside the ``web`` container (``docker/deploy_check.py``, called by
``scripts/deploy_check.sh``). Each check covers one or more rows of the Troubleshooting table in
docs/SSO-Setup.md and returns the documented fix; the host script adds the Docker-level checks (container
state, nginx networking/DNS, logs) that cannot be seen from in here.

Config checks read the raw ``SSO_*`` values from the environment (compose passes .env with env_file). The
network checks talk to nginx over the compose ``edge`` network with the same SNI and Host header a real client
sends for ``SSO_HOSTNAME``. Stdlib + ``cryptography`` only; never prints tokens or secrets."""
from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit

from cryptography import x509

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
GUIDE = "docs/SSO-Setup.md"
PLACEHOLDERS = ("sso.dev.com", "example.com", "example.org")
CERT_EXPIRY_WARN_DAYS = 21


@dataclass
class Result:
    id: str
    status: str
    title: str
    detail: str = ""
    fix: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "status": self.status, "title": self.title, "detail": self.detail, "fix": self.fix}


def _list(env: Mapping[str, str], name: str) -> list[str]:
    return [v.strip() for v in env.get(name, "").split(",") if v.strip()]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _https_port(env: Mapping[str, str]) -> int:
    try:
        return int(env.get("SSO_HTTPS_PORT") or 443)
    except ValueError:
        return 443


def public_origin(env: Mapping[str, str], host: str | None = None) -> str:
    """https://<host>[:port] as clients see it (port omitted for 443)."""
    host = host or env.get("SSO_HOSTNAME", "")
    port = _https_port(env)
    return f"https://{host}" + ("" if port == 443 else f":{port}")


# ---------------------------------------------------------------- configuration (no network)

def check_issuer(env: Mapping[str, str]) -> Result:
    title = "SSO_ISSUER matches SSO_HOSTNAME and SSO_HTTPS_PORT"
    issuer = env.get("SSO_ISSUER", "").rstrip("/")
    want = public_origin(env)
    if not env.get("SSO_HOSTNAME"):
        return Result("C01", FAIL, title, "SSO_HOSTNAME is empty", "Set SSO_HOSTNAME in .env (step 1)")
    if issuer != want:
        return Result("C01", FAIL, title, f"SSO_ISSUER={issuer!r}, expected {want!r}",
                      "Use one address everywhere (step 1). Changing SSO_ISSUER invalidates issued tokens and every "
                      "app's issuer setting must match (Troubleshooting: 'issuer error')")
    return Result("C01", PASS, title, issuer)


def check_allowed_hosts(env: Mapping[str, str]) -> Result:
    from django.http.request import validate_host

    title = "SSO_HOSTNAME is in SSO_ALLOWED_HOSTS"
    host, allowed = env.get("SSO_HOSTNAME", ""), _list(env, "SSO_ALLOWED_HOSTS")
    if host and validate_host(host.lower(), allowed):
        return Result("C02", PASS, title, ",".join(allowed))
    return Result("C02", FAIL, title, f"{host!r} not matched by {allowed}",
                  "Add SSO_HOSTNAME to SSO_ALLOWED_HOSTS, recreate web (Troubleshooting: 'HTTP 400 Bad Request')")


def check_ip_sni(env: Mapping[str, str]) -> Result:
    title = "TLS SNI setting fits the address type"
    host = env.get("SSO_HOSTNAME", "")
    sni = (env.get("SSO_TLS_REJECT_UNKNOWN_SNI") or "on").strip().lower()
    if is_ip(host) and sni != "off":
        return Result("C03", FAIL, title, f"SSO_HOSTNAME={host} is an IP and SSO_TLS_REJECT_UNKNOWN_SNI={sni}",
                      "Set SSO_TLS_REJECT_UNKNOWN_SNI=off, docker compose up -d --force-recreate nginx "
                      "(step 1 option B; Troubleshooting: 'tlsv1 unrecognized name')")
    return Result("C03", PASS, title, f"{'IP' if is_ip(host) else 'name'}, reject unknown SNI={sni}")


def check_cookie_domain(env: Mapping[str, str]) -> Result:
    title = "SSO_COOKIE_DOMAIN fits SSO_HOSTNAME"
    dom = env.get("SSO_COOKIE_DOMAIN", "").strip().lower()
    host = env.get("SSO_HOSTNAME", "").lower()
    if not dom:
        return Result("C04", PASS, title, "empty (host-only cookie)")
    fix = "Leave SSO_COOKIE_DOMAIN= empty, or a parent domain of SSO_HOSTNAME (Troubleshooting: 'refresh fails')"
    if is_ip(host) or host == "localhost":
        return Result("C04", FAIL, title, f"a domain cookie {dom!r} cannot be set for {host}", fix)
    bare = dom.lstrip(".")
    if host != bare and not host.endswith("." + bare):
        return Result("C04", FAIL, title, f"{dom!r} is not a parent domain of {host!r}", fix)
    return Result("C04", PASS, title, dom)


def _bad_origin(origin: str) -> str | None:
    parts = urlsplit(origin)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "not scheme://host[:port]"
    if parts.path or parts.query or parts.fragment or origin.endswith("/"):
        return "has a path or trailing '/'"
    return None


def check_origins(env: Mapping[str, str]) -> Result:
    title = "CORS / CSRF origins are well-formed"
    bad = []
    for var in ("SSO_CORS_ALLOWED_ORIGINS", "SSO_CSRF_TRUSTED_ORIGINS"):
        for origin in _list(env, var):
            why = _bad_origin(origin)
            if why:
                bad.append(f"{var}: {origin!r} {why}")
    if bad:
        return Result("C05", FAIL, title, "; ".join(bad),
                      "Use exact origins: scheme, host, port, nothing else (Troubleshooting: 'rejected on Origin')")
    return Result("C05", PASS, title)


def check_admin_csrf(env: Mapping[str, str]) -> Result:
    title = "admin origin is in SSO_CSRF_TRUSTED_ORIGINS"
    if (env.get("SSO_ADMIN_UI_ENABLED") or "true").strip().lower() in ("false", "0", "no"):
        return Result("C06", SKIP, title, "admin UI disabled")
    host = (env.get("SSO_ADMIN_UI_HOSTNAME") or "").strip().lower() or env.get("SSO_HOSTNAME", "")
    want = public_origin(env, host)
    trusted = [o.rstrip("/") for o in _list(env, "SSO_CSRF_TRUSTED_ORIGINS")]
    if want in trusted:
        return Result("C06", PASS, title, want)
    return Result("C06", FAIL, title, f"{want} missing from {trusted}",
                  "Add the exact admin origin, recreate web (Troubleshooting: 'Admin UI: 403 CSRF verification failed')")


def check_placeholders(env: Mapping[str, str]) -> Result:
    title = "no template placeholders left in .env"
    names = ("SSO_HOSTNAME", "SSO_ISSUER", "SSO_ALLOWED_HOSTS", "SSO_CORS_ALLOWED_ORIGINS",
             "SSO_CSRF_TRUSTED_ORIGINS", "SSO_COOKIE_DOMAIN", "SSO_ADMIN_UI_HOSTNAME")
    hits = [f"{n}={env.get(n)}" for n in names if any(p in (env.get(n) or "").lower() for p in PLACEHOLDERS)]
    if hits:
        return Result("C07", WARN, title, "; ".join(hits),
                      "Replace sso.dev.com / example.com with the real addresses (step 2): they break the TLS "
                      "handshake, the refresh cookie or CORS")
    return Result("C07", PASS, title)


CONFIG_CHECKS: tuple[Callable[[Mapping[str, str]], Result], ...] = (
    check_issuer, check_allowed_hosts, check_ip_sni, check_cookie_domain, check_origins, check_admin_csrf,
    check_placeholders,
)


# ---------------------------------------------------------------- certificate (pure)

def cert_covers(cert: x509.Certificate, host: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    if is_ip(host):
        return ipaddress.ip_address(host.strip("[]")) in san.get_values_for_type(x509.IPAddress)
    host = host.lower().rstrip(".")
    for name in san.get_values_for_type(x509.DNSName):
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False


def evaluate_cert(der: bytes, host: str, now: dt.datetime | None = None) -> list[Result]:
    cert = x509.load_der_x509_certificate(der)
    now = now or dt.datetime.now(dt.timezone.utc)
    out = []
    if cert_covers(cert, host):
        out.append(Result("T02", PASS, "certificate covers SSO_HOSTNAME", host))
    else:
        out.append(Result("T02", FAIL, "certificate covers SSO_HOSTNAME",
                          f"issued for {cert.subject.rfc4514_string()}, not {host}",
                          "Regenerate for the address from step 1 (move the self-signed pair away and "
                          "'docker compose up -d' re-creates it), or fix SSO_TLS_CERT_FILE (Troubleshooting: "
                          "'curl: (60) hostname mismatch')"))
    days = (cert.not_valid_after_utc - now).total_seconds() / 86400
    if days < 0:
        out.append(Result("T03", FAIL, "certificate validity", f"expired {-days:.0f} days ago",
                          "Renew (§12.8 cron) or regenerate the self-signed certificate"))
    elif days < CERT_EXPIRY_WARN_DAYS:
        out.append(Result("T03", WARN, "certificate validity", f"expires in {days:.0f} days",
                          "Check the certbot renew cron (§12.8) or regenerate the self-signed certificate"))
    else:
        out.append(Result("T03", PASS, "certificate validity", f"{days:.0f} days left"))
    if cert.issuer == cert.subject and not is_ip(host) and host != "localhost":
        out.append(Result("T04", WARN, "publicly trusted certificate",
                          "self-signed certificate on a DNS name: clients must pin or import it",
                          "Switch to Let's Encrypt (SSO-Setup §12.8)"))
    return out


# ---------------------------------------------------------------- network (via nginx)

def tls_connect(target: str, port: int, host: str, timeout: float = 5.0) -> ssl.SSLSocket:
    """TLS to nginx as a client of SSO_HOSTNAME would connect: SNI = host, none for an IP. No verification."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((target, port), timeout=timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=None if is_ip(host) else host)
    except Exception:
        raw.close()
        raise


def https_get(target: str, port: int, host: str, host_header: str, path: str, timeout: float = 5.0):
    """GET over tls_connect; returns (status, body bytes). An empty reply (nginx 444) raises RemoteDisconnected."""
    sock = tls_connect(target, port, host, timeout)
    try:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n"
                     f"User-Agent: sso-deploy-check\r\n\r\n".encode("ascii"))
        resp = http.client.HTTPResponse(sock)
        resp.begin()
        return resp.status, resp.read()
    finally:
        sock.close()


def check_tls(env: Mapping[str, str], target: str, port: int,
              connect: Callable = tls_connect) -> list[Result]:
    host = env.get("SSO_HOSTNAME", "")
    title = f"TLS handshake with nginx ({'no SNI' if is_ip(host) else 'SNI ' + host})"
    try:
        sock = connect(target, port, host)
    except ssl.SSLError as exc:
        fix = ("Set SSO_HOSTNAME to the address clients use; for an IP also SSO_TLS_REJECT_UNKNOWN_SNI=off, then "
               "docker compose up -d --force-recreate nginx (Troubleshooting: 'tlsv1 unrecognized name')")
        return [Result("T01", FAIL, title, f"{exc.__class__.__name__}: {exc}", fix)]
    except OSError as exc:
        return [Result("T01", FAIL, title, f"{target}:{port}: {exc}",
                       "nginx is not serving 443: docker compose logs nginx (Troubleshooting: 'Connection refused "
                       "... port 443', 'cannot load certificate')")]
    try:
        der = sock.getpeercert(binary_form=True)
    finally:
        sock.close()
    return [Result("T01", PASS, title, f"{target}:{port}")] + evaluate_cert(der, host)


def check_health(env: Mapping[str, str], target: str, port: int, get: Callable = https_get) -> Result:
    host = env.get("SSO_HOSTNAME", "")
    hh = host if _https_port(env) == 443 else f"{host}:{_https_port(env)}"
    title = "GET /healthz through nginx"
    try:
        status, body = get(target, port, host, hh, "/healthz")
    except (http.client.RemoteDisconnected, http.client.BadStatusLine) as exc:
        return Result("H01", FAIL, title, f"empty reply ({exc.__class__.__name__}): nginx answered 444",
                      "The Host header must be exactly SSO_HOSTNAME (Troubleshooting: 'curl: (52) Empty reply')")
    except (OSError, ssl.SSLError) as exc:
        return Result("H01", FAIL, title, f"{exc.__class__.__name__}: {exc}", "See T01")
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        data = {}
    if status == 400:
        return Result("H01", FAIL, title, "HTTP 400 from Django",
                      "Add SSO_HOSTNAME to SSO_ALLOWED_HOSTS, recreate web (Troubleshooting: 'HTTP 400')")
    if status == 502:
        return Result("H01", FAIL, title, "HTTP 502 from nginx: web unreachable",
                      "See the nginx DNS checks (SSO-Setup 'Production deployment watch-outs')")
    if status == 503:
        return Result("H01", FAIL, title, "HTTP 503: database unreachable",
                      "docker compose logs web | grep 'sso.db': errno 110 = firewall (step 6), 111 = bind-address "
                      "(step 5.1), 1045/1130 = accounts (step 5.2)")
    if status != 200:
        return Result("H01", FAIL, title, f"HTTP {status}", "docker compose logs web nginx")
    if data.get("warning"):
        return Result("H01", FAIL, title, data["warning"],
                      "The DB team runs scripts/upgrade_db.sh on the migration server, then deploy again (§12.6 / §11; "
                      "Troubleshooting: 'migrations pending')")
    return Result("H01", PASS, title, "200 ok")


def check_jwks(env: Mapping[str, str], target: str, port: int, kid: str, get: Callable = https_get) -> Result:
    host = env.get("SSO_HOSTNAME", "")
    hh = host if _https_port(env) == 443 else f"{host}:{_https_port(env)}"
    title = "JWKS publishes the signing key"
    try:
        status, body = get(target, port, host, hh, "/.well-known/jwks.json")
        kids = [k.get("kid") for k in json.loads(body).get("keys", [])] if status == 200 else []
    except Exception as exc:  # noqa: BLE001
        return Result("J01", FAIL, title, f"{exc.__class__.__name__}: {exc}", "See H01")
    if status != 200:
        return Result("J01", FAIL, title, f"HTTP {status}", "See H01")
    if kid not in kids:
        return Result("J01", FAIL, title, f"signing kid {kid} not in {kids}",
                      "SSO_JWT_PUBLIC_KEYS must include the public key of SSO_JWT_PRIVATE_KEY (README §4)")
    return Result("J01", PASS, title, f"kid {kid} ({len(kids)} key(s) published)")


def run_all(env: Mapping[str, str], target: str = "nginx", port: int = 443, kid: str | None = None) -> list[Result]:
    results = [check(env) for check in CONFIG_CHECKS]
    tls = check_tls(env, target, port)
    results += tls
    if tls[0].status == PASS:
        results.append(check_health(env, target, port))
        if kid:
            results.append(check_jwks(env, target, port, kid))
    return results
