"""Contract: the SSO (sso/clientip.py) and the sso-client library (clients/python) derive the client IP the same
way (design §4.5: "implemented once in the library and mirrored in the SSO")."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "clients" / "python" / "src"))
lib = pytest.importorskip("sso_client.ip")

from sso import clientip  # noqa: E402

VALUES = ["1.2.3.4", "1.2.3.4:80", "::ffff:1.2.3.4", "[::ffff:1.2.3.4]:9", "2001:DB8::0:1", "[2001:db8::1]:443",
          "fe80::1%eth0", '"10.0.0.1"', ("::1", 80, 0, 0), "", "x", None, "[::1", "1.2.3.4.5", " 8.8.8.8 "]
TRUSTED = "127.0.0.1,172.18.0.0/16,::1,::ffff:10.0.0.0/104"
CASES = [
    ("203.0.113.7", ["1.1.1.1"]), ("127.0.0.1", []), ("127.0.0.1", ["9.9.9.9, 203.0.113.7"]),
    ("127.0.0.1", ["203.0.113.7, 172.18.0.2"]), ("127.0.0.1", ["172.18.0.3, 172.18.0.2"]),
    ("127.0.0.1", ["203.0.113.7, junk, 172.18.0.2"]), ("::ffff:127.0.0.1", ["[::ffff:203.0.113.7]:4"]),
    ("::1", ["2001:db8::5, 10.1.2.3"]), (None, ["1.1.1.1"]), ("10.9.9.9", ["a, b"]),
]


@pytest.mark.parametrize("value", VALUES)
def test_normalize_same(value):
    assert clientip.normalize_ip(value) == lib.normalize_ip(value)


def test_trusted_same():
    assert clientip.parse_trusted(TRUSTED) == lib.parse_trusted(TRUSTED)


@pytest.mark.parametrize("peer,xff", CASES)
def test_walk_same(peer, xff):
    nets = clientip.parse_trusted(TRUSTED)
    assert clientip.walk_forwarded(peer, xff, nets) == lib.get_client_ip(
        peer, [("X-Forwarded-For", v) for v in xff], nets)
