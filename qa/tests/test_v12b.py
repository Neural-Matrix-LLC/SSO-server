"""v1.2b black-box QA (TEST-PLAN §3.15): IP binding NOIP/WARNING/ENFORCE (cip HMAC, exact match, IPv6/::ffff:
normalisation, no rebind, sid revocation), BFF client_ip, introspect require/allowed + throttle, SSO_TRUSTED_PROXIES
(right-to-left walk, CIDRs, spoofing, /0, W002), revoked-session cache (<=10 s across workers) and pruning.

Each case starts its own gunicorn(s) on 8061-8068 against the round's throw-away SQLite DB (same keys / secret as
the main server), with the setting under test; stopped by recorded PID (harness/stop_sso.sh). The client IP is
steered with X-Forwarded-For through SSO_TRUSTED_PROXIES=127.0.0.1/32 (the socket peer is always 127.0.0.1).
White-box helpers (manage.sh shell) only for user setup, the HMAC key derivation and RevokedSession rows.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import time
import uuid
from pathlib import Path

import jwt
import pytest
import requests

import testdata

HERE = Path(__file__).resolve().parent
QA = HERE.parent
HARNESS = QA / "harness"
RUN = QA / "run"
PW = "Qa12b-Passw0rd!xyz"
SVC = (testdata.SERVICE_CLIENT_ID, testdata.SERVICE_CLIENT_SECRET)
BAD_SVC = (testdata.INACTIVE_SERVICE_CLIENT_ID, testdata.INACTIVE_SERVICE_CLIENT_SECRET)
FAST = ["SSO_THROTTLE_LOGIN=10000/min", "SSO_THROTTLE_LOGIN_USER=10000/min", "SSO_THROTTLE_REFRESH=10000/min"]
TRUST_LO = "SSO_TRUSTED_PROXIES=127.0.0.1/32"
LOGIN, REFRESH, LOGOUT, ME, INTRO = ("/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
                                    "/api/v1/auth/me", "/api/v1/auth/introspect")
PORTS = list(range(8061, 8069))
TAG = os.environ.get("QA_V12B_TAG", "x")

pytestmark = pytest.mark.skipif(not os.environ.get("SSO_MANAGE_CMD"), reason="needs the QA harness (SSO_MANAGE_CMD)")


# --------------------------------------------------------------------------- servers
class Srv:
    def __init__(self, port: int, log: Path):
        self.port, self.log = port, log
        self.url = f"http://127.0.0.1:{port}"

    def post(self, path, body=None, *, xff=None, auth=None, bearer=None, timeout=15):
        h = {}
        if xff is not None:
            h["X-Forwarded-For"] = xff
        if bearer:
            h["Authorization"] = f"Bearer {bearer}"
        return requests.post(self.url + path, json=body if body is not None else {}, headers=h, auth=auth,
                             timeout=timeout)

    def login(self, name, *, xff=None, auth=None, client_ip=None, pw=PW):
        body = {"username": name, "password": pw, "client": "native"}
        if client_ip is not None:
            body["client_ip"] = client_ip
        r = self.post(LOGIN, body, xff=xff, auth=auth)
        assert r.status_code == 200, (r.status_code, r.text[:300])
        return r.json()

    def refresh(self, rt, *, xff=None, auth=None, client_ip=None):
        body = {"refresh_token": rt}
        if client_ip is not None:
            body["client_ip"] = client_ip
        return self.post(REFRESH, body, xff=xff, auth=auth)

    def intro(self, tok, ip=..., *, require=..., auth=SVC):
        body = {"token": tok}
        if ip is not ...:
            body["ip"] = ip
        if require is not ...:
            body["require"] = require
        return self.post(INTRO, body, auth=auth)

    def events(self, event=None, **match):
        out = []
        for line in self.log.read_text(errors="replace").splitlines():
            m = re.search(r"(\{.*\})\s*$", line)
            if not m:
                continue
            try:
                d = json.loads(m.group(1))
            except ValueError:
                continue
            if (event is None or d.get("event") == event) and all(d.get(k) == v for k, v in match.items()):
                out.append(d)
        return out


class Servers:
    """Factory: ``servers.start("enf", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)``; one per name, reused."""

    def __init__(self):
        self.live: dict[str, Srv] = {}
        self.free = list(PORTS)

    def start(self, name: str, *env: str, workers: int = 1, cache: str | None = None) -> Srv:
        if name in self.live:
            return self.live[name]
        if not self.free:  # recycle the oldest server
            self.stop(next(iter(self.live)))
        port = self.free.pop(0)
        log = RUN / f"v12b-{TAG}-srv-{name}-{port}.log"
        e = dict(os.environ)
        # QA_V12B_CACHE_URL (e.g. redis://127.0.0.1:8069/0): one shared cache for every server (REDIS-01);
        # QA_V12B_WORKERS: minimum gunicorn workers per server
        e["SSO_CACHE_URL"] = os.environ.get("QA_V12B_CACHE_URL") or f"filecache:///tmp/qa-cache-v12b-{TAG}-{cache or name}"
        e["GUNICORN_WORKERS"] = str(max(workers, int(os.environ.get("QA_V12B_WORKERS", "1"))))
        e.update({"SSO_IP_BINDING_MODE": "NOIP", "SSO_TRUSTED_PROXIES": "", "SSO_NUM_PROXIES": "0",
                  "SSO_REVOKED_SESSION_CACHE_SECONDS": "10"})  # round env must not leak; args override
        p = subprocess.run([str(HARNESS / "start_sso.sh"), str(port), str(log), *FAST, *env], env=e,
                           capture_output=True, text=True, timeout=30)
        assert p.returncode == 0, p.stderr
        s = Srv(port, log)
        for _ in range(80):
            try:
                if requests.get(s.url + "/healthz", timeout=2).status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(0.25)
        else:
            raise AssertionError(f"{name} on {port} not up: {log.read_text()[-1500:]}")
        self.live[name] = s
        return s

    def stop(self, name: str):
        s = self.live.pop(name, None)
        if s:
            subprocess.run([str(HARNESS / "stop_sso.sh"), str(s.port)], capture_output=True, timeout=30)
            self.free.insert(0, s.port)

    def stop_all(self):
        for n in list(self.live):
            self.stop(n)


@pytest.fixture(scope="module")
def servers():
    s = Servers()
    yield s
    s.stop_all()


def manage(*args, env=None, check=True):
    """manage.py with harness/sso.env, then the overrides (sso.env itself pins SSO_NUM_PROXIES=0)."""
    over = {"SSO_IP_BINDING_MODE": "NOIP", "SSO_TRUSTED_PROXIES": "", "SSO_NUM_PROXIES": "0", **(env or {})}
    exports = " ".join(f"{k}={shlex.quote(v)}" for k, v in over.items())
    script = (f'. {shlex.quote(str(HARNESS / "sso.env"))}; export {exports}; cd {shlex.quote(str(QA.parent))}; '
              'exec "${SSO_VENV:-.venv}/bin/python" manage.py "$@"')
    p = subprocess.run(["bash", "-c", script, "manage", *args], env=dict(os.environ), capture_output=True,
                       text=True, timeout=120)
    if check:
        assert p.returncode == 0, p.stderr[-2000:]
    return p


def shell(code: str) -> str:
    return manage("shell", "-c", code).stdout.strip().splitlines()[-1]


@pytest.fixture(scope="module")
def mk_user():
    def make(tag="u", perms=()):
        name = f"qa12b_{tag}_{uuid.uuid4().hex[:6]}"
        grant = "".join(f"u.user_permissions.add(app_permissions().get(codename={c!r}));" for c in perms)
        pk = shell("from django.contrib.auth.models import User; from application.permissions import app_permissions;"
                   f"u=User.objects.create_user({name!r}, password={PW!r});{grant}print(u.pk)")
        return name, int(pk)
    return make


def claims(tok):
    return jwt.decode(tok, options={"verify_signature": False})


@pytest.fixture(scope="module")
def ip_key() -> bytes:
    """SSO_IP_BINDING_KEY default = HMAC-SHA256(SSO_SECRET_KEY, "sso-ip-binding-v1") (§11)."""
    secret = (RUN / "secret_key").read_text().strip()
    return hmac.new(secret.encode(), b"sso-ip-binding-v1", hashlib.sha256).digest()


def hmac_cip(key: bytes, ip: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(key, ip.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()


def revoked(sid: str) -> bool:
    return shell(f"from sso.models import RevokedSession as R; print(R.objects.filter(sid={sid!r}).exists())") == "True"


# =========================================================================== BIND: modes, claim, match
def test_V12B_BIND_01_noip_no_cip_and_null_match(servers, mk_user):
    s = servers.start("noip", TRUST_LO)
    name, _ = mk_user("noip")
    b = s.login(name, xff="203.0.113.7")
    assert "cip" not in claims(b["access_token"]) and "cip" not in claims(b["refresh_token"])
    j = s.intro(b["access_token"], "198.51.100.1").json()
    assert j["active"] is True and j["ip_binding"] == "NOIP" and j["ip_match"] is None
    j = s.intro(b["access_token"]).json()                # ip optional in NOIP
    assert j["active"] is True and j["ip_match"] is None


@pytest.mark.parametrize("mode", ["WARNING", "ENFORCE"])
def test_V12B_BIND_02_cip_is_keyed_hmac_no_raw_ip(servers, mk_user, ip_key, mode):
    s = servers.start(mode.lower(), f"SSO_IP_BINDING_MODE={mode}", TRUST_LO)
    name, _ = mk_user("hmac")
    ip = "203.0.113.77"
    b = s.login(name, xff=ip)
    a, r = claims(b["access_token"]), claims(b["refresh_token"])
    assert a["cip"] == r["cip"] == hmac_cip(ip_key, ip)
    plain_sha = base64.urlsafe_b64encode(hashlib.sha256(ip.encode()).digest()).rstrip(b"=").decode()
    assert a["cip"] != plain_sha and a["cip"] != hashlib.sha256(ip.encode()).hexdigest()
    for tok in (b["access_token"], b["refresh_token"]):
        raw = base64.urlsafe_b64decode(tok.split(".")[1] + "==").decode()
        assert ip not in raw and "203.0.113" not in raw, raw
    b2 = s.login(name, xff="203.0.113.78")
    assert claims(b2["access_token"])["cip"] != a["cip"]


def test_V12B_BIND_03_enforce_exact_match_and_mismatch_revokes_only_that_sid(servers, mk_user, ip_key):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("enf")
    one = s.login(name, xff="203.0.113.10")
    two = s.login(name, xff="203.0.113.10")          # second session of the same user
    j = s.intro(one["access_token"], "203.0.113.10").json()
    assert j["active"] is True and j["ip_match"] is True and j["ip_binding"] == "ENFORCE"
    assert j["sid"] == claims(one["access_token"])["sid"]
    # one address off: exact match only (no prefix)
    assert s.intro(one["access_token"], "203.0.113.11").json() == {"active": False}
    sid = claims(one["access_token"])["sid"]
    assert revoked(sid)
    assert s.intro(one["access_token"], "203.0.113.10").json() == {"active": False}, "session must stay revoked"
    r = s.refresh(one["refresh_token"], xff="203.0.113.10")
    assert r.status_code == 401 and r.json()["error"] == "token_invalid", r.text
    # the other session of the same user is unaffected
    assert s.intro(two["access_token"], "203.0.113.10").json()["active"] is True
    assert s.refresh(two["refresh_token"], xff="203.0.113.10").status_code == 200
    ev = s.events("ip_mismatch", where="introspect")
    assert any(e.get("mode") == "ENFORCE" and e.get("ip") == "203.0.113.11" for e in ev), ev[-3:]


@pytest.mark.parametrize("ip", [..., None, "", "not-an-ip", "203.0.113.10/32", "999.1.1.1"])
def test_V12B_BIND_04_enforce_missing_or_unparseable_ip_is_mismatch(servers, mk_user, ip):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("noipq")
    b = s.login(name, xff="203.0.113.10")
    r = s.intro(b["access_token"], ip)
    assert r.status_code == 200 and r.json() == {"active": False}, (r.status_code, r.text)
    assert revoked(claims(b["access_token"])["sid"])


@pytest.mark.parametrize("login_ip,intro_ip", [
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
    ("2001:db8::1", "[2001:db8::1]:443"),
    ("2001:db8::1", "2001:db8::1%eth0"),
    ("2001:db8::1", "2001:0db8:0000::0001"),
    ("::ffff:198.51.100.4", "198.51.100.4"),
    ("198.51.100.4", "::ffff:198.51.100.4"),
    ("198.51.100.4", "[::ffff:198.51.100.4]:8443"),
    ("198.51.100.4", "198.51.100.4:5678"),
])
def test_V12B_BIND_05_normalisation_ipv6_and_mapped(servers, mk_user, ip_key, login_ip, intro_ip):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("norm")
    b = s.login(name, xff=login_ip)
    canon = {"2001:DB8:0:0:0:0:0:1": "2001:db8::1", "::ffff:198.51.100.4": "198.51.100.4"}.get(login_ip, login_ip)
    assert claims(b["access_token"])["cip"] == hmac_cip(ip_key, canon)
    j = s.intro(b["access_token"], intro_ip).json()
    assert j.get("active") is True and j["ip_match"] is True, j


def test_V12B_BIND_06_enforce_refresh_same_ip_keeps_cip_other_ip_ends_session(servers, mk_user):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("rf")
    b = s.login(name, xff="203.0.113.20")
    cip = claims(b["access_token"])["cip"]
    r = s.refresh(b["refresh_token"], xff="203.0.113.20")
    assert r.status_code == 200
    n = r.json()
    assert claims(n["access_token"])["cip"] == claims(n["refresh_token"])["cip"] == cip
    r2 = s.refresh(n["refresh_token"], xff="198.51.100.20")
    assert r2.status_code == 401 and r2.json()["error"] == "token_invalid", r2.text
    assert revoked(claims(n["access_token"])["sid"])
    assert s.intro(n["access_token"], "203.0.113.20").json() == {"active": False}
    assert any(e.get("where") == "refresh" for e in s.events("ip_mismatch", ip="198.51.100.20"))


def test_V12B_BIND_07_warning_allows_logs_and_never_rebinds(servers, mk_user):
    s = servers.start("warning", "SSO_IP_BINDING_MODE=WARNING", TRUST_LO)
    name, pk = mk_user("warn")
    b = s.login(name, xff="203.0.113.30")
    cip = claims(b["access_token"])["cip"]
    j = s.intro(b["access_token"], "198.51.100.30").json()
    assert j["active"] is True and j["ip_match"] is False and j["ip_binding"] == "WARNING"
    j = s.intro(b["access_token"]).json()                 # no ip: also a (logged) mismatch
    assert j["active"] is True and j["ip_match"] is False
    assert s.intro(b["access_token"], "203.0.113.30").json()["ip_match"] is True
    r = s.refresh(b["refresh_token"], xff="198.51.100.30")
    assert r.status_code == 200, r.text
    assert claims(r.json()["access_token"])["cip"] == cip, "WARNING must not rebind to the new IP"
    assert not revoked(claims(b["access_token"])["sid"])
    ev = s.events("ip_mismatch", user_id=pk)
    wh = {(e["where"], e.get("ip")) for e in ev}
    assert ("introspect", "198.51.100.30") in wh and ("refresh", "198.51.100.30") in wh and ("introspect", None) in wh
    assert all(e["mode"] == "WARNING" for e in ev)
    assert any(e.get("client_id") == SVC[0] for e in ev if e["where"] == "introspect")


def test_V12B_BIND_08_noip_token_unbound_then_bound_on_first_refresh(servers, mk_user, ip_key):
    noip = servers.start("noip", TRUST_LO)
    enf = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("migr")
    b = noip.login(name, xff="203.0.113.40")
    j = enf.intro(b["access_token"], "198.51.100.40").json()
    assert j["active"] is True and j["ip_match"] is None       # unbound until refreshed
    r = enf.refresh(b["refresh_token"], xff="198.51.100.41")
    assert r.status_code == 200
    assert claims(r.json()["access_token"])["cip"] == hmac_cip(ip_key, "198.51.100.41")
    # back to NOIP: next refresh drops cip
    r2 = noip.refresh(r.json()["refresh_token"], xff="198.51.100.41")
    assert r2.status_code == 200 and "cip" not in claims(r2.json()["access_token"])


def test_V12B_BIND_09_logout_and_me_do_not_check_binding(servers, mk_user):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("melo")
    b = s.login(name, xff="203.0.113.50")
    me = requests.get(s.url + ME, headers={"Authorization": f"Bearer {b['access_token']}",
                                         "X-Forwarded-For": "198.51.100.50"}, timeout=10)
    assert me.status_code == 200
    assert not revoked(claims(b["access_token"])["sid"])
    lo = s.post(LOGOUT, {"refresh_token": b["refresh_token"]}, xff="198.51.100.50")
    assert lo.status_code in (200, 204), lo.text


def test_V12B_BIND_10_bad_mode_is_fatal():
    p = manage("check", env={"SSO_IP_BINDING_MODE": "STRICT"}, check=False)
    assert p.returncode != 0 and "SSO_IP_BINDING_MODE" in p.stderr
    p = manage("check", env={"SSO_IP_BINDING_MODE": "enforce"}, check=False)     # case-insensitive accepted
    assert p.returncode == 0, p.stderr[-500:]


def test_V12B_BIND_11_service_clients_never_bound(servers, mk_user, ip_key):
    """A ServiceClient authenticates with Basic only (no token of its own to bind); a BFF login binds the
    END USER's delegated IP, never the service's socket address; introspect by the client is not IP-checked
    against the service."""
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("svc")
    b = s.login(name, auth=SVC, client_ip="198.51.100.60")
    assert claims(b["access_token"])["cip"] == hmac_cip(ip_key, "198.51.100.60")
    assert claims(b["access_token"])["cip"] != hmac_cip(ip_key, "127.0.0.1")
    # a ServiceClient's own credentials yield no token at all
    r = s.post(LOGIN, {"username": SVC[0], "password": SVC[1], "client": "native"})
    assert r.status_code in (400, 401), r.text
    # introspect from the service's address works when it forwards the user IP
    assert s.intro(b["access_token"], "198.51.100.60").json()["ip_match"] is True


# =========================================================================== BFF client_ip
@pytest.mark.parametrize("client_ip,canon", [("198.51.100.21:5678", "198.51.100.21"),
                                             ("[2001:db8::7]:443", "2001:db8::7"),
                                             ("::ffff:198.51.100.22", "198.51.100.22"),
                                             (" 198.51.100.23 ", "198.51.100.23")])
def test_V12B_BFF_01_client_ip_port_stripped_and_normalised(servers, mk_user, ip_key, client_ip, canon):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, pk = mk_user("bff")
    b = s.login(name, auth=SVC, client_ip=client_ip)
    assert claims(b["access_token"])["cip"] == hmac_cip(ip_key, canon)
    assert any(e.get("ip") == canon for e in s.events("login", user_id=pk))
    r = s.refresh(b["refresh_token"], auth=SVC, client_ip=client_ip)
    assert r.status_code == 200, r.text


def test_V12B_BFF_02_client_ip_ignored_without_service_auth(servers, mk_user, ip_key):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, pk = mk_user("bffno")
    b = s.login(name, client_ip="198.51.100.24", xff="203.0.113.24")
    assert claims(b["access_token"])["cip"] == hmac_cip(ip_key, "203.0.113.24")
    # plain caller refreshing with a forged client_ip: ignored, its own (trusted) IP is used -> match
    assert s.refresh(b["refresh_token"], client_ip="198.51.100.99", xff="203.0.113.24").status_code == 200


def test_V12B_BFF_03_client_ip_rules_for_service_callers(servers, mk_user):
    s = servers.start("enforce", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO)
    name, _ = mk_user("bffbad")
    r = s.post(LOGIN, {"username": name, "password": PW, "client": "native", "client_ip": "nope"}, auth=SVC)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request", r.text
    r = s.post(LOGIN, {"username": name, "password": PW, "client": "native", "client_ip": "198.51.100.1"},
               auth=BAD_SVC)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client", r.text
    b = s.login(name, auth=SVC, client_ip="198.51.100.25")
    r = s.refresh(b["refresh_token"], auth=SVC, client_ip="198.51.100.26")       # browser moved
    assert r.status_code == 401 and r.json()["error"] == "token_invalid"


# =========================================================================== INTRO: require / allowed / throttle
def test_V12B_INTRO_01_require_allowed(servers, mk_user):
    s = servers.start("noip", TRUST_LO)
    name, _ = mk_user("req", perms=["app1"])
    tok = s.login(name)["access_token"]
    j = s.intro(tok).json()
    assert "allowed" not in j and "application.app1" in j["perms"]
    for req, ok in [("application.app1", True), (["application.app1"], True), ("application.app2", False),
                    (["application.app1", "application.app2"], False), ("app1", False)]:
        j = s.intro(tok, require=req).json()
        assert j["active"] is True and j["allowed"] is ok, (req, j)
    shell("from django.contrib.auth.models import User; from application.permissions import ensure_permission;"
          f"u=User.objects.get(username={name!r}); u.user_permissions.add(ensure_permission('app2', 'QA app2')[0])")
    j = s.intro(tok, require=["application.app1", "application.app2"]).json()
    assert j["allowed"] is True, "perms must be current DB values"


@pytest.mark.parametrize("req", [[], [""], [1], {"a": 1}, 5, ["x"] * 51, ["a" * 256], None])
def test_V12B_INTRO_02_bad_require_is_400(servers, mk_user, req):
    s = servers.start("noip", TRUST_LO)
    name, _ = mk_user("reqbad")
    tok = s.login(name)["access_token"]
    r = s.intro(tok, require=req)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request", (r.status_code, r.text)


def test_V12B_INTRO_03_require_ignored_for_inactive(servers, mk_user):
    s = servers.start("noip", TRUST_LO)
    r = s.intro("garbage", require="application.app1")
    assert r.status_code == 200 and r.json() == {"active": False}


def test_V12B_INTRO_04_introspect_throttle_per_service_client(servers, mk_user):
    s = servers.start("ithr", "SSO_THROTTLE_INTROSPECT=5/min", TRUST_LO)
    name, _ = mk_user("ithr")
    tok = s.login(name)["access_token"]
    other = "qa12b-svc-" + uuid.uuid4().hex[:6]
    shell("from django.contrib.auth.hashers import make_password; from sso.models import ServiceClient;"
          f"ServiceClient.objects.create(client_id={other!r}, name='qa', client_secret_hash=make_password('qa-other-secret-123456'), is_active=True); print(1)")
    codes = [s.intro(tok).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429], codes
    r = s.intro(tok)
    assert r.headers.get("Retry-After"), r.headers
    assert s.intro(tok, auth=(other, "qa-other-secret-123456")).status_code == 200, "other client throttled too"
    r = s.post(INTRO, {"token": tok})                       # no Basic: 401, never 429
    assert r.status_code == 401, r.status_code
    r = s.post(INTRO, {"token": tok}, auth=(SVC[0], "wrong-secret"))
    assert r.status_code == 401, r.status_code


# =========================================================================== PROXY: SSO_TRUSTED_PROXIES
def _login_ip(s: Srv, name: str, pk: int, xff) -> str:
    s.login(name, xff=xff)
    return s.events("login", user_id=pk)[-1]["ip"]


@pytest.mark.parametrize("trusted,xff,want", [
    ("127.0.0.1/32", "203.0.113.9", "203.0.113.9"),
    ("127.0.0.1/32", "198.51.100.1, 203.0.113.9", "203.0.113.9"),           # leftmost is client-controlled
    ("127.0.0.1/32,10.0.0.0/8", "198.51.100.1, 203.0.113.9, 10.1.2.3", "203.0.113.9"),
    ("127.0.0.1/32,10.0.0.0/8", "10.0.0.1, 10.0.0.2", "10.0.0.1"),          # all trusted -> leftmost
    ("127.0.0.1/32,10.0.0.0/8", "203.0.113.9, garbage, 10.0.0.2", "10.0.0.2"),  # malformed: last good
    ("127.0.0.1/32", "", "127.0.0.1"),
    ("127.0.0.1/32", "unknown", "127.0.0.1"),
    ("127.0.0.1/32", "203.0.113.9:5555", "203.0.113.9"),
    ("127.0.0.1/32", "[2001:db8::9]:443", "2001:db8::9"),
    ("::ffff:127.0.0.1/128", "203.0.113.9", "203.0.113.9"),                  # mapped CIDR -> IPv4
    ("127.0.0.0/8,2001:db8::/32", "198.51.100.3, 2001:db8::1", "198.51.100.3"),
    ("10.0.0.0/8", "203.0.113.9", "127.0.0.1"),                              # untrusted peer: header ignored
])
def test_V12B_PROXY_01_trusted_walk(servers, mk_user, trusted, xff, want):
    key = "px-" + hashlib.sha1(trusted.encode()).hexdigest()[:6]
    s = servers.start(key, f"SSO_TRUSTED_PROXIES={trusted}")
    name, pk = mk_user("px")
    assert _login_ip(s, name, pk, xff) == want


def test_V12B_PROXY_02_spoofed_xff_from_untrusted_peer_cannot_bind(servers, mk_user, ip_key):
    s = servers.start("enf-notrust", "SSO_IP_BINDING_MODE=ENFORCE")
    name, _ = mk_user("spoof")
    b = s.login(name, xff="203.0.113.99")
    assert claims(b["access_token"])["cip"] == hmac_cip(ip_key, "127.0.0.1")


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "127.0.0.1,0.0.0.0/0", "not-a-cidr", "10.0.0.0/33"])
def test_V12B_PROXY_03_bad_trusted_list_fatal(value):
    p = manage("check", env={"SSO_TRUSTED_PROXIES": value}, check=False)
    assert p.returncode != 0 and "SSO_TRUSTED_PROXIES" in p.stderr, p.stderr[-800:]


def test_V12B_PROXY_04_num_proxies_deprecated_w002_and_precedence(servers, mk_user):
    p = manage("check", env={"SSO_NUM_PROXIES": "1", "SSO_TRUSTED_PROXIES": ""}, check=False)
    out = p.stdout + p.stderr
    assert p.returncode == 0 and "sso.W002" in out, out[-800:]
    p = manage("check", env={"SSO_NUM_PROXIES": "0", "SSO_TRUSTED_PROXIES": ""}, check=False)
    assert "sso.W002" not in p.stdout + p.stderr
    p = manage("check", env={"SSO_NUM_PROXIES": "1", "SSO_TRUSTED_PROXIES": "127.0.0.1/32"}, check=False)
    both = p.stdout + p.stderr
    # deprecated fallback still works (DRF hop count: trusts XFF from ANY peer, rightmost entry)
    s = servers.start("np1", "SSO_NUM_PROXIES=1", "SSO_TRUSTED_PROXIES=")
    name, pk = mk_user("np")
    assert _login_ip(s, name, pk, "198.51.100.1, 203.0.113.9") == "203.0.113.9"
    # both set: TRUSTED wins (peer 127.0.0.1 not in 10/8 -> header ignored even though NUM_PROXIES=1)
    s2 = servers.start("np1t", "SSO_NUM_PROXIES=1", "SSO_TRUSTED_PROXIES=10.0.0.0/8")
    assert _login_ip(s2, name, pk, "203.0.113.9") == "127.0.0.1"
    print("W002 with both set:", "sso.W002" in both)
    assert "sso.W002" not in both


# =========================================================================== CACHE: revoked sessions
def _revoke_by_mismatch(s: Srv, tok: str):
    assert s.intro(tok, "192.0.2.250").json() == {"active": False}


def test_V12B_CACHE_01_revocation_seen_at_once_across_workers_shared_cache(servers, mk_user):
    s = servers.start("enf-2w", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO, workers=2)
    name, _ = mk_user("c2w")
    b = s.login(name, xff="203.0.113.60")
    tok = b["access_token"]
    pids = set()
    for _ in range(20):                                # prime "not revoked" in the shared cache (both workers)
        r = requests.post(s.url + INTRO, json={"token": tok, "ip": "203.0.113.60"}, auth=SVC, timeout=10,
                          headers={"Connection": "close"})
        assert r.json()["active"] is True
    _revoke_by_mismatch(s, tok)
    t0 = time.monotonic()
    answers = [requests.post(s.url + INTRO, json={"token": tok, "ip": "203.0.113.60"}, auth=SVC, timeout=10,
                             headers={"Connection": "close"}).json()["active"] for _ in range(20)]
    assert not any(answers), answers
    assert time.monotonic() - t0 < 10


def test_V12B_CACHE_02_separate_caches_stale_at_most_10s(servers, mk_user):
    """Worst case: worker B holds its own negative entry (separate cache). It must see the revocation <= 10 s."""
    a = servers.start("enf-ca", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO, cache="ca")
    b_ = servers.start("enf-cb", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO, cache="cb")
    name, _ = mk_user("csep")
    tok = a.login(name, xff="203.0.113.61")["access_token"]
    assert b_.intro(tok, "203.0.113.61").json()["active"] is True        # B caches "not revoked" (10 s)
    t_neg = time.monotonic()
    _revoke_by_mismatch(a, tok)
    seen = None
    while time.monotonic() - t_neg < 15:
        if b_.intro(tok, "203.0.113.61").json()["active"] is False:
            seen = time.monotonic() - t_neg
            break
        time.sleep(0.2)
    print(f"CACHE-02: B saw the revocation after {seen} s")
    assert seen is not None and seen <= 10.5, seen


def test_V12B_CACHE_03_cache_off_is_immediate(servers, mk_user):
    a = servers.start("enf-oa", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO, "SSO_REVOKED_SESSION_CACHE_SECONDS=0",
                      cache="oa")
    b_ = servers.start("enf-ob", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO, "SSO_REVOKED_SESSION_CACHE_SECONDS=0",
                       cache="ob")
    name, _ = mk_user("coff")
    tok = a.login(name, xff="203.0.113.62")["access_token"]
    assert b_.intro(tok, "203.0.113.62").json()["active"] is True
    _revoke_by_mismatch(a, tok)
    assert b_.intro(tok, "203.0.113.62").json() == {"active": False}
    servers.stop("enf-oa"), servers.stop("enf-ob")


def test_V12B_CACHE_04_prune_old_revoked_session_rows(mk_user):
    name, pk = mk_user("prune")
    tag = uuid.uuid4().hex[:8]
    shell("from datetime import timedelta; from django.conf import settings; from django.utils import timezone;"
          "from sso.models import RevokedSession as R;"
          "old=timezone.now()-settings.SSO_REFRESH_TTL-timedelta(days=1, minutes=5);"
          "edge=timezone.now()-settings.SSO_REFRESH_TTL-timedelta(hours=23);"
          f"R.objects.create(sid='qaold1{tag}', user_id={pk}, reason='qa', revoked_at=old);"
          f"R.objects.create(sid='qaold2{tag}', user_id={pk}, reason='qa', revoked_at=old);"
          f"R.objects.create(sid='qaedge{tag}', user_id={pk}, reason='qa', revoked_at=edge);"
          f"R.objects.create(sid='qanew{tag}', user_id={pk}, reason='qa'); print(1)")
    count = f"from sso.models import RevokedSession as R; print(R.objects.filter(sid__endswith={tag!r}).count())"
    dry = manage("revoke_inactive_users", "--dry-run").stdout
    m = re.search(r"would prune (\d+)", dry)
    assert m and int(m.group(1)) >= 2, dry
    assert shell(count) == "4"
    out = manage("revoke_inactive_users").stdout
    assert re.search(r"pruned (\d+)", out), out
    left = shell(f"from sso.models import RevokedSession as R; print(sorted(r.sid.removesuffix({tag!r}) for r in R.objects.filter(sid__endswith={tag!r})))")
    assert left == "['qaedge', 'qanew']", left
    assert "would prune 0" in manage("revoke_inactive_users", "--dry-run").stdout


@pytest.mark.parametrize("ip", ["1" * 129, "x" * 300, 12345, ["203.0.113.10"], {"ip": "203.0.113.10"}, True])
def test_V12B_INTRO_05_odd_ip_values_are_no_ip_not_400(servers, mk_user, ip):
    """§11: "An unparseable ip is treated as no IP (a mismatch for a bound token), not as 400"."""
    s = servers.start("warning", "SSO_IP_BINDING_MODE=WARNING", TRUST_LO)
    name, _ = mk_user("oddip")
    tok = s.login(name, xff="203.0.113.10")["access_token"]
    r = s.intro(tok, ip)
    print(f"INTRO-05 ip={str(ip)[:20]!r} -> {r.status_code} {r.text[:120]}")
    assert r.status_code == 200 and r.json()["active"] is True and r.json()["ip_match"] is False, r.text[:300]


# =========================================================================== HDR: SSO_CLIENT_IP_HEADER (345eed7)
def _login_ip_h(s: Srv, name: str, pk: int, headers: dict) -> str:
    r = requests.post(s.url + LOGIN, json={"username": name, "password": PW, "client": "native"}, headers=headers,
                      timeout=10)
    assert r.status_code == 200, r.text
    return s.events("login", user_id=pk)[-1]["ip"]


@pytest.mark.parametrize("trusted,headers,want", [
    ("127.0.0.1/32", {"CF-Connecting-IP": "203.0.113.9"}, "203.0.113.9"),
    ("127.0.0.1/32", {"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "198.51.100.1"}, "203.0.113.9"),  # header wins
    ("127.0.0.1/32", {"X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"),                     # absent -> XFF
    ("127.0.0.1/32", {"CF-Connecting-IP": "garbage", "X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"),
    ("127.0.0.1/32", {"CF-Connecting-IP": "", "X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"),
    ("127.0.0.1/32,10.0.0.0/8", {"CF-Connecting-IP": "203.0.113.9, 10.0.0.2"}, "203.0.113.9"),  # same walk
    ("127.0.0.1/32,10.0.0.0/8", {"CF-Connecting-IP": "10.0.0.3"}, "10.0.0.3"),
    ("127.0.0.1/32", {"CF-Connecting-IP": "[2001:db8::5]:443"}, "2001:db8::5"),
    ("127.0.0.1/32", {"CF-Connecting-IP": "::ffff:203.0.113.9"}, "203.0.113.9"),
    ("10.0.0.0/8", {"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "198.51.100.1"}, "127.0.0.1"),  # untrusted peer
])
def test_V12B_HDR_01_custom_header_only_from_trusted_peer(servers, mk_user, trusted, headers, want):
    key = "hdr-" + hashlib.sha1(trusted.encode()).hexdigest()[:6]
    s = servers.start(key, f"SSO_TRUSTED_PROXIES={trusted}", "SSO_CLIENT_IP_HEADER=cf-connecting-ip")
    name, pk = mk_user("hdr")
    assert _login_ip_h(s, name, pk, headers) == want


def test_V12B_HDR_02_header_needs_trusted_proxies_and_xff_name_is_plain_xff(servers, mk_user):
    p = manage("check", env={"SSO_CLIENT_IP_HEADER": "cf-connecting-ip", "SSO_TRUSTED_PROXIES": ""}, check=False)
    assert p.returncode != 0 and "SSO_CLIENT_IP_HEADER" in p.stderr, p.stderr[-600:]
    s = servers.start("hdr-xff", TRUST_LO, "SSO_CLIENT_IP_HEADER=X-Forwarded-For")
    name, pk = mk_user("hdrx")
    assert _login_ip_h(s, name, pk, {"X-Forwarded-For": "198.51.100.1, 203.0.113.9"}) == "203.0.113.9"


def test_V12B_HDR_03_enforce_binding_uses_header_ip(servers, mk_user, ip_key):
    s = servers.start("hdr-enf", "SSO_IP_BINDING_MODE=ENFORCE", TRUST_LO, "SSO_CLIENT_IP_HEADER=x-real-ip")
    name, _ = mk_user("hdre")
    r = requests.post(s.url + LOGIN, json={"username": name, "password": PW, "client": "native"},
                      headers={"X-Real-IP": "203.0.113.120", "X-Forwarded-For": "198.51.100.120"}, timeout=10)
    b = r.json()
    assert claims(b["access_token"])["cip"] == hmac_cip(ip_key, "203.0.113.120")
    ok = requests.post(s.url + REFRESH, json={"refresh_token": b["refresh_token"]},
                       headers={"X-Real-IP": "203.0.113.120"}, timeout=10)
    assert ok.status_code == 200
    bad = requests.post(s.url + REFRESH, json={"refresh_token": ok.json()["refresh_token"]},
                        headers={"X-Real-IP": "198.51.100.120", "X-Forwarded-For": "203.0.113.120"}, timeout=10)
    assert bad.status_code == 401, "header IP (not XFF) is the client IP"
