"""LIB-IP: sso_client.get_client_ip / normalize_ip vs the server's sso/clientip.py on ONE table of inputs."""
from __future__ import annotations

import json

import pytest

from conftest import shell
from sso_client import get_client_ip, normalize_ip, parse_trusted

T1 = "127.0.0.1/32"
T2 = "127.0.0.1/32, 10.0.0.0/8, 2001:db8:ffff::/48"
TM = "::ffff:10.0.0.0/104"
# (peer, [XFF header values], trusted)
CASES = [
    ("203.0.113.5", ["198.51.100.1"], T1),                 # untrusted peer: header ignored
    ("127.0.0.1", ["198.51.100.1"], T1),
    ("127.0.0.1", ["198.51.100.1, 203.0.113.9"], T1),
    ("127.0.0.1", ["198.51.100.1", "203.0.113.9"], T1),    # two header instances
    ("127.0.0.1", ["1.1.1.1, 10.0.0.1, 10.0.0.2"], T2),
    ("127.0.0.1", ["10.0.0.1, 10.0.0.2"], T2),             # all trusted -> leftmost
    ("127.0.0.1", ["203.0.113.9, garbage, 10.0.0.2"], T2),
    ("127.0.0.1", ["garbage"], T2),
    ("127.0.0.1", ["unknown, 10.0.0.2"], T2),
    ("127.0.0.1", [""], T2),
    ("127.0.0.1", [], T2),
    ("127.0.0.1", ["203.0.113.9,,10.0.0.2"], T2),          # empty entry = malformed
    ("127.0.0.1", ["  203.0.113.9 ,  10.0.0.2  "], T2),
    ("127.0.0.1", ["203.0.113.9:5555"], T1),
    ("127.0.0.1", ["[2001:DB8::9]:443"], T1),
    ("127.0.0.1", ["2001:db8::9%eth0"], T1),
    ("127.0.0.1", ["::ffff:198.51.100.7"], T1),
    ("127.0.0.1", ['"198.51.100.7"'], T1),
    ("127.0.0.1", ["198.51.100.7, 2001:db8:ffff::1"], T2),
    ("127.0.0.1", ["2001:db8:fffe::1, 2001:db8:ffff::1"], T2),
    ("::ffff:127.0.0.1", ["198.51.100.8"], T1),            # mapped peer
    ("::1", ["198.51.100.8"], T1),                          # v6 loopback not trusted by a v4 net
    ("::1", ["198.51.100.8"], "::1/128"),
    ("[::1]:5000", ["198.51.100.8"], "::1"),
    ("127.0.0.1:5000", ["198.51.100.8"], T1),
    ("10.1.2.3", ["198.51.100.9"], TM),                     # ::ffff: CIDR mapped to IPv4
    ("::ffff:10.1.2.3", ["198.51.100.9, ::ffff:10.9.9.9"], TM),
    ("fe80::1%eth0", ["198.51.100.9"], "fe80::/10"),
    ("not-an-ip", ["198.51.100.9"], T1),
    ("", ["198.51.100.9"], T1),
    ("127.0.0.1", ["198.51.100.1, 999.1.1.1"], T1),
    ("127.0.0.1", ["198.51.100.1, 203.0.113.9/32"], T1),
    ("127.0.0.1", ["for=198.51.100.1"], T1),
    ("127.0.0.1", ["1.2.3.4:80:90"], T1),
    ("127.0.0.1", ["2001:db8::1:443"], T1),                 # ambiguous: valid v6, no port strip
    ("127.0.0.1", ["[2001:db8::1"], T1),
    ("127.0.0.1", ["0:0:0:0:0:ffff:c633:6401"], T1),
    ("127.0.0.1", ["127.0.0.1"], T1),                        # all trusted incl. client -> leftmost
    ("127.0.0.1", ["198.51.100.1, 127.0.0.1, 127.0.0.1"], T1),
]
NORM = ["1.2.3.4", " 1.2.3.4 ", "1.2.3.4:80", "[::1]:443", "::FFFF:1.2.3.4", "2001:DB8:0::1", "fe80::1%25eth0",
        "fe80::1%eth0", '"[2001:db8::1]:8443"', "1.2.3", "01.2.3.4", "1.2.3.4.5", "", "   ", "::", "::ffff:0:0",
        "[1.2.3.4]:80", "1.2.3.4%x", "::ffff:1.2.3.4%eth0", "localhost", "0x7f000001", "١.٢.٣.٤"]


# custom header (345eed7): (peer, [header values] or None = absent, [XFF values], trusted)
HCASES = [
    ("127.0.0.1", ["203.0.113.9"], ["198.51.100.1"], T1),
    ("127.0.0.1", None, ["198.51.100.1"], T1),
    ("127.0.0.1", ["garbage"], ["198.51.100.1"], T1),
    ("127.0.0.1", [""], ["198.51.100.1"], T1),
    ("127.0.0.1", ["203.0.113.9, 10.0.0.2"], [], T2),
    ("127.0.0.1", ["10.0.0.3"], ["198.51.100.1"], T2),
    ("127.0.0.1", ["198.51.100.1", "203.0.113.9"], [], T1),
    ("127.0.0.1", ["[2001:db8::5]:443"], [], T1),
    ("127.0.0.1", ["garbage, 203.0.113.9"], [], T1),
    ("127.0.0.1", ["203.0.113.9, garbage"], ["198.51.100.1"], T1),
    ("203.0.113.200", ["203.0.113.9"], ["198.51.100.1"], T1),
    ("::ffff:127.0.0.1", ["203.0.113.9"], [], T1),
]


@pytest.fixture(scope="module")
def server_answers():
    payload = json.dumps({"cases": CASES, "norm": NORM, "h": HCASES})
    out = shell("import json; from sso.clientip import walk_forwarded, normalize_ip, parse_trusted;"
                f"d=json.loads({payload!r});"
                "print(json.dumps({'walk':[walk_forwarded(p, x, parse_trusted(t)) for p,x,t in d['cases']],"
                "'norm':[normalize_ip(v) for v in d['norm']],"
                "'h':[walk_forwarded(p, x, parse_trusted(t), [', '.join(h)] if h else []) for p,h,x,t in d['h']]}))")
    return json.loads(out)


@pytest.mark.parametrize("i", range(len(HCASES)))
def test_V12B_LIB_IP_07_custom_header_parity(server_answers, i):
    """Server: request_ip passes the (WSGI-joined) header value, or [] when absent. Library: all instances."""
    peer, hv, xff, trusted = HCASES[i]
    hdrs = [("X-Forwarded-For", v) for v in xff] + [("CF-Connecting-IP", v) for v in (hv or [])]
    lib = get_client_ip(peer, hdrs, trusted, "cf-connecting-ip")
    assert lib == server_answers["h"][i], (HCASES[i], lib, server_answers["h"][i])


def test_V12B_LIB_IP_08_header_config_needs_trusted():
    from sso_client import SSOConfig
    from sso_client.errors import SSOConfigError
    with pytest.raises(SSOConfigError):
        SSOConfig(base_url="https://s.example", client_id="c", client_secret="s", client_ip_header="x-real-ip")
    c = SSOConfig.from_env({"SSO_BASE_URL": "https://s.example", "SSO_CLIENT_ID": "c", "SSO_CLIENT_SECRET": "s",
                            "SSO_TRUSTED_PROXIES": "10.0.0.0/8", "SSO_CLIENT_IP_HEADER": " x-real-ip "})
    assert c.client_ip_header == "x-real-ip"


@pytest.mark.parametrize("i", range(len(CASES)))
def test_V12B_LIB_IP_01_walk_parity(server_answers, i):
    peer, xff, trusted = CASES[i]
    lib = get_client_ip(peer, [("X-Forwarded-For", v) for v in xff], trusted)
    lib_dict = get_client_ip(peer, {"X-Forwarded-For": ", ".join(xff)} if xff else {}, parse_trusted(trusted))
    assert lib == server_answers["walk"][i], (CASES[i], lib, server_answers["walk"][i])
    if not any(v == "" for v in xff):
        assert lib_dict == lib


@pytest.mark.parametrize("i", range(len(NORM)))
def test_V12B_LIB_IP_02_normalize_parity(server_answers, i):
    assert normalize_ip(NORM[i]) == server_answers["norm"][i], NORM[i]


def test_V12B_LIB_IP_03_expected_values_spot_check(server_answers):
    w = dict(zip(range(len(CASES)), server_answers["walk"]))
    assert w[0] == "203.0.113.5" and w[2] == "203.0.113.9" and w[5] == "10.0.0.1" and w[6] == "10.0.0.2"
    assert w[14] == "2001:db8::9" and w[16] == "198.51.100.7" and w[25] == "198.51.100.9" and w[21] == "::1"


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "::/0", "x", "1.2.3.4/40"])
def test_V12B_LIB_IP_04_parse_trusted_rejects(bad):
    with pytest.raises(ValueError):
        parse_trusted(bad)


def test_V12B_LIB_IP_05_spoofing_property():
    import random
    rnd = random.Random(7)
    for _ in range(500):
        peer = f"{rnd.randint(11, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
        xff = ", ".join(f"10.{rnd.randint(0, 255)}.0.{rnd.randint(1, 9)}" for _ in range(rnd.randint(0, 4)))
        assert get_client_ip(peer, {"X-Forwarded-For": xff}, "10.0.0.0/8,127.0.0.1") == peer
        assert get_client_ip("::ffff:" + peer, {}, ()) == get_client_ip(peer, {}, ())


def test_V12B_LIB_IP_06_peer_from_socket():
    import socket
    from sso_client import peer_from_socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    c = socket.create_connection(srv.getsockname()); conn, _ = srv.accept()
    try:
        assert peer_from_socket(conn) == "127.0.0.1"
        a, b = socket.socketpair(socket.AF_UNIX)
        assert peer_from_socket(a) is None
        a.close(); b.close()
    finally:
        conn.close(); c.close(); srv.close()
