"""sso/deploycheck.py: post-start deployment checks (docs/SSO-Setup.md Troubleshooting rows, scripts/deploy_check.sh).

Config rules are pure; the network checks run against a throw-away local TLS server that mimics nginx (SNI-aware,
444 = close without a reply for an unknown Host)."""
import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sso import deploycheck as dc

ENV = {
    "SSO_HOSTNAME": "sso.acme.test",
    "SSO_HTTPS_PORT": "443",
    "SSO_ISSUER": "https://sso.acme.test",
    "SSO_ALLOWED_HOSTS": "sso.acme.test",
    "SSO_CSRF_TRUSTED_ORIGINS": "https://sso.acme.test",
    "SSO_CORS_ALLOWED_ORIGINS": "https://fin.acme.test,http://localhost:3000",
    "SSO_COOKIE_DOMAIN": "",
}


def env(**kw):
    e = dict(ENV)
    e.update({k: v for k, v in kw.items() if v is not None})
    return e


def status(result):
    return result.status


# ---------------------------------------------------------------- config rules

def test_good_config_all_pass():
    assert [r.status for r in (c(ENV) for c in dc.CONFIG_CHECKS)] == [dc.PASS] * len(dc.CONFIG_CHECKS)


@pytest.mark.parametrize("issuer, port, ok", [
    ("https://sso.acme.test", "443", True),
    ("https://sso.acme.test/", "443", True),
    ("https://sso.acme.test:8443", "8443", True),
    ("https://sso.acme.test", "8443", False),
    ("https://other.test", "443", False),
    ("http://sso.acme.test", "443", False),
])
def test_issuer(issuer, port, ok):
    r = dc.check_issuer(env(SSO_ISSUER=issuer, SSO_HTTPS_PORT=port))
    assert r.status == (dc.PASS if ok else dc.FAIL)
    assert ok or "issuer" in r.fix


def test_issuer_without_hostname():
    assert dc.check_issuer(env(SSO_HOSTNAME="")).status == dc.FAIL


def test_https_port_garbage_means_443():
    assert dc.public_origin(env(SSO_HTTPS_PORT="x")) == "https://sso.acme.test"


@pytest.mark.parametrize("allowed, ok", [
    ("sso.acme.test", True), (".acme.test", True), ("*", True), ("localhost,127.0.0.1", False), ("", False),
])
def test_allowed_hosts(allowed, ok):
    assert dc.check_allowed_hosts(env(SSO_ALLOWED_HOSTS=allowed)).status == (dc.PASS if ok else dc.FAIL)


@pytest.mark.parametrize("host, sni, ok", [
    ("sso.acme.test", None, True), ("192.168.0.212", "off", True), ("192.168.0.212", None, False),
    ("192.168.0.212", "on", False), ("192.168.0.212", "OFF", True),
])
def test_ip_needs_sni_off(host, sni, ok):
    e = env(SSO_HOSTNAME=host, SSO_TLS_REJECT_UNKNOWN_SNI=sni)
    assert dc.check_ip_sni(e).status == (dc.PASS if ok else dc.FAIL)


@pytest.mark.parametrize("host, dom, ok", [
    ("sso.acme.test", "", True), ("sso.acme.test", ".acme.test", True), ("sso.acme.test", "acme.test", True),
    ("sso.acme.test", ".example.com", False), ("localhost", ".acme.test", False), ("10.0.0.5", "10.0.0.5", False),
    ("sso.acme.test", "sso.acme.test", True),
])
def test_cookie_domain(host, dom, ok):
    assert dc.check_cookie_domain(env(SSO_HOSTNAME=host, SSO_COOKIE_DOMAIN=dom)).status == (dc.PASS if ok else dc.FAIL)


@pytest.mark.parametrize("origin, ok", [
    ("https://fin.acme.test", True), ("http://localhost:3000", True), ("https://fin.acme.test/", False),
    ("https://fin.acme.test/app", False), ("fin.acme.test", False), ("ftp://x.test", False),
])
def test_origins(origin, ok):
    assert dc.check_origins(env(SSO_CORS_ALLOWED_ORIGINS=origin)).status == (dc.PASS if ok else dc.FAIL)


def test_admin_origin_in_csrf():
    assert dc.check_admin_csrf(env(SSO_CSRF_TRUSTED_ORIGINS="https://fin.acme.test")).status == dc.FAIL
    assert dc.check_admin_csrf(env(SSO_ADMIN_UI_HOSTNAME="admin.acme.test")).status == dc.FAIL
    e = env(SSO_ADMIN_UI_HOSTNAME="admin.acme.test", SSO_CSRF_TRUSTED_ORIGINS="https://admin.acme.test")
    assert dc.check_admin_csrf(e).status == dc.PASS
    e = env(SSO_HTTPS_PORT="8443", SSO_CSRF_TRUSTED_ORIGINS="https://sso.acme.test:8443")
    assert dc.check_admin_csrf(e).status == dc.PASS
    assert dc.check_admin_csrf(env(SSO_ADMIN_UI_ENABLED="false", SSO_CSRF_TRUSTED_ORIGINS="")).status == dc.SKIP


def test_placeholders_warn():
    r = dc.check_placeholders(env(SSO_CORS_ALLOWED_ORIGINS="https://fin.example.com"))
    assert r.status == dc.WARN and "SSO_CORS_ALLOWED_ORIGINS" in r.detail
    assert dc.check_placeholders(env(SSO_HOSTNAME="sso.dev.com")).status == dc.WARN


# ---------------------------------------------------------------- certificates

def make_cert(names, days=365, self_signed=True, ips=()):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "x")])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = dt.datetime.now(dt.timezone.utc)
    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=days)))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(key, hashes.SHA256()), key


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def by_id(results):
    return {r.id: r for r in results}


def test_cert_covers_dns_wildcard_ip():
    cert, _ = make_cert(["sso.acme.test", "*.apps.acme.test"], ips=["192.168.0.212"])
    assert dc.cert_covers(cert, "sso.acme.test")
    assert dc.cert_covers(cert, "SSO.acme.test.")
    assert dc.cert_covers(cert, "x.apps.acme.test")
    assert not dc.cert_covers(cert, "a.b.apps.acme.test")
    assert not dc.cert_covers(cert, "other.test")
    assert dc.cert_covers(cert, "192.168.0.212")
    assert not dc.cert_covers(cert, "192.168.0.1")
    no_san, _ = make_cert([])
    assert not dc.cert_covers(no_san, "x")


def test_evaluate_cert_good_public():
    cert, _ = make_cert(["sso.acme.test"], self_signed=False)
    r = by_id(dc.evaluate_cert(der(cert), "sso.acme.test"))
    assert r["T02"].status == dc.PASS and r["T03"].status == dc.PASS and "T04" not in r


def test_evaluate_cert_mismatch_expiry_selfsigned():
    cert, _ = make_cert(["localhost"], days=5)
    r = by_id(dc.evaluate_cert(der(cert), "sso.acme.test"))
    assert r["T02"].status == dc.FAIL and "mismatch" in r["T02"].fix
    assert r["T03"].status == dc.WARN
    assert r["T04"].status == dc.WARN and "12.8" in r["T04"].fix
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)
    assert by_id(dc.evaluate_cert(der(cert), "localhost", now=later))["T03"].status == dc.FAIL


def test_selfsigned_on_ip_or_localhost_is_fine():
    cert, _ = make_cert(["localhost"], ips=["10.0.0.5"])
    assert "T04" not in by_id(dc.evaluate_cert(der(cert), "10.0.0.5"))
    assert "T04" not in by_id(dc.evaluate_cert(der(cert), "localhost"))


# ---------------------------------------------------------------- fake nginx

class FakeNginx:
    """TLS server on 127.0.0.1: rejects unknown SNI like ssl_reject_handshake, answers by Host like nginx."""

    def __init__(self, tmp_path, hostname, routes, reject_unknown_sni=True, cert_names=None):
        cert, key = make_cert(cert_names or [hostname])
        crt, kp = tmp_path / "c.pem", tmp_path / "k.pem"
        crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, kp)
        if reject_unknown_sni:
            def sni_cb(sock, name, ctx):
                if name != hostname:
                    return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            self.ctx.sni_callback = sni_cb
        self.hostname, self.routes = hostname, routes
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                raw, _ = self.srv.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(raw, server_side=True) as s:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    lines = data.decode().split("\r\n")
                    path = lines[0].split(" ")[1]
                    host = next(l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("host:"))
                    if host.split(":")[0] != self.hostname:
                        continue  # 444
                    code, body = self.routes.get(path, (404, b"{}"))
                    s.sendall(b"HTTP/1.1 %d X\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                              % (code, len(body), body))
            except (ssl.SSLError, OSError, StopIteration, IndexError):
                pass

    def close(self):
        self.srv.close()


@pytest.fixture
def nginx(tmp_path):
    servers = []

    def start(**kw):
        kw.setdefault("hostname", "sso.acme.test")
        kw.setdefault("routes", {"/healthz": (200, b'{"status":"ok"}'),
                                 "/.well-known/jwks.json": (200, json.dumps({"keys": [{"kid": "abc"}]}).encode())})
        s = FakeNginx(tmp_path, **kw)
        servers.append(s)
        return s
    yield start
    for s in servers:
        s.close()


def test_run_all_against_healthy_nginx(nginx):
    srv = nginx()
    results = by_id(dc.run_all(ENV, "127.0.0.1", srv.port, kid="abc"))
    assert results["T01"].status == dc.PASS
    assert results["H01"].status == dc.PASS
    assert results["J01"].status == dc.PASS
    assert results["T04"].status == dc.WARN  # fake cert is self-signed on a DNS name


def test_wrong_hostname_fails_handshake(nginx):
    srv = nginx()
    r = dc.check_tls(env(SSO_HOSTNAME="other.acme.test"), "127.0.0.1", srv.port)
    assert len(r) == 1 and r[0].id == "T01" and r[0].status == dc.FAIL and "unrecognized name" in r[0].fix


def test_ip_hostname_sends_no_sni(nginx):
    srv = nginx(hostname="127.0.0.1", reject_unknown_sni=True)
    r = dc.check_tls(env(SSO_HOSTNAME="127.0.0.1"), "127.0.0.1", srv.port)
    assert r[0].status == dc.FAIL  # SNI on + IP = every handshake rejected (Troubleshooting row 35)
    srv2 = nginx(hostname="127.0.0.1", reject_unknown_sni=False, cert_names=["localhost"])
    r = by_id(dc.check_tls(env(SSO_HOSTNAME="127.0.0.1"), "127.0.0.1", srv2.port))
    assert r["T01"].status == dc.PASS and r["T02"].status == dc.FAIL


def test_nothing_listening():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = dc.check_tls(ENV, "127.0.0.1", port)
    assert r[0].status == dc.FAIL and "443" in r[0].fix


def test_run_all_stops_after_failed_tls():
    results = dc.run_all(env(SSO_HOSTNAME="x.test"), "127.0.0.1", 1, kid="abc")
    assert {r.id for r in results}.isdisjoint({"H01", "J01"})


@pytest.mark.parametrize("code, body, needle", [
    (400, b"bad", "SSO_ALLOWED_HOSTS"),
    (502, b"", "DNS"),
    (503, b'{"error":"unhealthy"}', "step 6"),
    (500, b"oops", "logs"),
    (200, b'{"status":"ok","warning":"database migrations pending"}', "upgrade_db.sh"),
])
def test_health_failures(nginx, code, body, needle):
    srv = nginx(routes={"/healthz": (code, body)})
    r = dc.check_health(ENV, "127.0.0.1", srv.port)
    assert r.status == dc.FAIL and needle in r.fix


def test_health_empty_reply_is_host_header(nginx):
    srv = nginx()
    r = dc.check_health(env(SSO_HOSTNAME="sso.acme.test"), "127.0.0.1", srv.port,
                        get=lambda t, p, h, hh, path: dc.https_get(t, p, h, "wrong.test", path))
    assert r.status == dc.FAIL and "Empty reply" in r.fix


def test_health_and_jwks_on_custom_port(nginx):
    srv = nginx()
    e = env(SSO_HTTPS_PORT="8443", SSO_ISSUER="https://sso.acme.test:8443")
    assert dc.check_health(e, "127.0.0.1", srv.port).status == dc.PASS
    assert dc.check_jwks(e, "127.0.0.1", srv.port, "abc").status == dc.PASS


def test_health_network_error():
    def boom(*a):
        raise ConnectionRefusedError("refused")
    assert dc.check_health(ENV, "x", 1, get=boom).status == dc.FAIL


def test_jwks_failures(nginx):
    srv = nginx()
    r = dc.check_jwks(ENV, "127.0.0.1", srv.port, "zzz")
    assert r.status == dc.FAIL and "SSO_JWT_PUBLIC_KEYS" in r.fix
    srv = nginx(routes={"/.well-known/jwks.json": (500, b"")})
    assert dc.check_jwks(ENV, "127.0.0.1", srv.port, "abc").detail == "HTTP 500"
    srv = nginx(routes={"/.well-known/jwks.json": (200, b"not json")})
    assert dc.check_jwks(ENV, "127.0.0.1", srv.port, "abc").status == dc.FAIL


def test_result_as_dict():
    assert dc.Result("X", dc.PASS, "t").as_dict() == {"id": "X", "status": "PASS", "title": "t", "detail": "",
                                                       "fix": ""}


# ---------------------------------------------------------------- docker/deploy_check.py entry point

def test_entry_point_output(tmp_path):
    """Fresh interpreter with the test settings: config checks pass, nothing listens -> T01 FAIL, exit 1."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    e = dict(os.environ, **ENV, DJANGO_SETTINGS_MODULE="ssoproject.settings_test")
    p = subprocess.run([sys.executable, os.path.join(root, "docker", "deploy_check.py"), "--target", "127.0.0.1",
                        "--port", "1"], capture_output=True, text=True, env=e, cwd=root, timeout=60)
    assert p.returncode == 1, p.stderr
    rows = [line.split("\t") for line in p.stdout.splitlines()]
    assert all(len(r) == 5 for r in rows)
    assert {r[1]: r[0] for r in rows}["T01"] == "FAIL"
    assert "K01" not in {r[1] for r in rows}
    p = subprocess.run([sys.executable, os.path.join(root, "docker", "deploy_check.py"), "--json", "--target",
                        "127.0.0.1", "--port", "1"], capture_output=True, text=True, env=e, cwd=root, timeout=60)
    assert json.loads(p.stdout.splitlines()[0])["id"] == "C01"
