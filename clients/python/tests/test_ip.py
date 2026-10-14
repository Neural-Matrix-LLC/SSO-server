import socket

import pytest

from sso_client import get_client_ip, normalize_ip, parse_trusted, peer_from_socket

A = "203.0.113.7"
T = "127.0.0.1,172.18.0.0/16"


@pytest.mark.parametrize("raw,want", [
    ("1.2.3.4", "1.2.3.4"), ("1.2.3.4:80", "1.2.3.4"), ("::ffff:1.2.3.4", "1.2.3.4"), ("[::ffff:1.2.3.4]:1", "1.2.3.4"),
    ("2001:DB8::0:1", "2001:db8::1"), ("[2001:db8::1]:443", "2001:db8::1"), ("fe80::1%eth0", "fe80::1"),
    ('"10.0.0.1"', "10.0.0.1"), (("::1", 80, 0, 0), "::1"), (("1.2.3.4", 5), "1.2.3.4"), ((), None),
    ("", None), ("x", None), (None, None), ("[::1", None), (1, None),
])
def test_normalize(raw, want):
    assert normalize_ip(raw) == want


def test_parse_trusted():
    assert [str(n) for n in parse_trusted(" 10.0.0.0/8 ,::1, ::ffff:192.168.0.0/112")] == [
        "10.0.0.0/8", "::1/128", "192.168.0.0/16"]
    assert parse_trusted(None) == () and parse_trusted("") == ()
    for bad in ("0.0.0.0/0", "::/0", "nope"):
        with pytest.raises(ValueError):
            parse_trusted(bad)


@pytest.mark.parametrize("peer,headers,want", [
    (A, {"X-Forwarded-For": "1.1.1.1"}, A),                              # untrusted peer: spoof ignored
    ("127.0.0.1", {}, "127.0.0.1"),
    ("127.0.0.1", {"x-forwarded-for": f"9.9.9.9, {A}"}, A),
    ("127.0.0.1", [(b"x-forwarded-for", b"9.9.9.9"), (b"x-forwarded-for", f"{A}, 172.18.0.2".encode())], A),
    ("127.0.0.1", {"X-Forwarded-For": "172.18.0.3, 172.18.0.2"}, "172.18.0.3"),
    ("127.0.0.1", {"X-Forwarded-For": f"{A}, bad, 172.18.0.2"}, "172.18.0.2"),
    (("::ffff:127.0.0.1", 9), {"X-Forwarded-For": f"[::ffff:{A}]:4"}, A),
    (None, {"X-Forwarded-For": A}, None),
])
def test_get_client_ip(peer, headers, want):
    assert get_client_ip(peer, headers, T) == want
    assert get_client_ip(peer, headers, parse_trusted(T)) == want


def test_no_trusted_means_peer():
    assert get_client_ip("127.0.0.1", {"X-Forwarded-For": A}) == "127.0.0.1"


def test_getlist_headers():
    from starlette.datastructures import Headers

    h = Headers(raw=[(b"x-forwarded-for", b"9.9.9.9"), (b"x-forwarded-for", A.encode())])
    assert get_client_ip("127.0.0.1", h, T) == A


@pytest.mark.parametrize("spoof", ["1.1.1.1", "127.0.0.1", "172.18.0.9, 10.0.0.1", "garbage", ""])
def test_spoofed_xff_from_untrusted_peer_never_changes_result(spoof):
    assert get_client_ip(A, {"X-Forwarded-For": spoof}, T) == A


def test_peer_from_socket():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept()
    try:
        assert peer_from_socket(conn) == "127.0.0.1"
        assert get_client_ip(peer_from_socket(conn), {}, []) == "127.0.0.1"
    finally:
        conn.close(), cli.close(), srv.close()
    assert peer_from_socket(conn) is None  # closed
    a, b = socket.socketpair(socket.AF_UNIX)
    assert peer_from_socket(a) is None
    a.close(), b.close()
