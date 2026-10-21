#!/usr/bin/env python3
"""Verify a user against a running SSO server: log in, print the permissions, then log out.

    python scripts/sso_login_check.py USERNAME [--url https://sso.dev.com] [--cacert ca.pem | --insecure]

The password is read from SSO_PASSWORD or prompted for (never pass it on the command line). The base URL
defaults to SSO_URL, else SSO_ISSUER from the repo's .env, else http://localhost:8000; a bare host gets
https://. TLS: without --cacert/--insecure, a request to the issuer host or localhost pins the dev cert
($SSO_CERTS_DIR/$SSO_TLS_CERT_FILE from .env, default docker/certs/selfsigned.crt) when it exists: the server
must present exactly that certificate (its CN/SAN is not checked, it is usually issued for localhost);
any other host uses the system trust store. Login uses native mode (refresh token in the body), the
groups/perms are printed from the login response, from GET /api/v1/auth/me and from the access token's
claims (decoded without verification, for display only), and the refresh token is then blacklisted via
POST /api/v1/auth/logout. Tokens are never printed. Stdlib only, no Django needed.

Exit codes: 0 ok, 1 login refused (bad credentials, inactive, throttled), 2 usage, 3 other failure.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def read_dotenv(path: str) -> dict[str, str]:
    """Minimal KEY=VALUE reader (no interpolation); a missing file gives {}."""
    env: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    env[key.strip()] = value.strip().strip("'\"")
    except OSError:
        pass
    return env


def tls_context(url: str, cacert: str | None, insecure: bool, dotenv: dict[str, str]):
    if not url.startswith("https://"):
        return None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if cacert:
        return ssl.create_default_context(cafile=cacert)
    host = urllib.parse.urlsplit(url).hostname
    issuer_host = urllib.parse.urlsplit(dotenv.get("SSO_ISSUER", "")).hostname
    certs_dir = dotenv.get("SSO_CERTS_DIR", "./docker/certs")
    dev_cert = os.path.join(REPO, certs_dir, dotenv.get("SSO_TLS_CERT_FILE", "selfsigned.crt"))
    if host in {issuer_host, "localhost", "127.0.0.1"} and os.path.isfile(dev_cert):
        # pin: only a chain ending in this self-signed cert verifies; the name is ignored (cert is for localhost)
        ctx = ssl.create_default_context(cafile=dev_cert)
        ctx.check_hostname = False
        print(f"(TLS: pinned to {os.path.relpath(dev_cert)})", file=sys.stderr)
        return ctx
    return ssl.create_default_context()


def call(base: str, path: str, ctx, *, body: dict | None = None, token: str | None = None):
    """Return (status, parsed JSON or None). HTTP errors are returned, not raised."""
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, {"error": "non_json_response", "detail": raw[:200].decode(errors="replace")}


def jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def show(title: str, groups, perms) -> None:
    print(f"{title}:")
    print(f"  groups: {', '.join(groups) if groups else '(none)'}")
    print(f"  perms : {', '.join(perms) if perms else '(none)'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("username", help="username or email")
    dotenv = read_dotenv(os.path.join(REPO, ".env"))
    default_url = os.environ.get("SSO_URL") or dotenv.get("SSO_ISSUER") or "http://localhost:8000"
    ap.add_argument("--url", default=default_url, help=f"SSO base URL (default: {default_url})")
    tls = ap.add_mutually_exclusive_group()
    tls.add_argument("--cacert", help="CA bundle to verify the server certificate (e.g. a self-signed cert)")
    tls.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    args = ap.parse_args(argv)

    url = args.url if "://" in args.url else "https://" + args.url
    try:
        ctx = tls_context(url, args.cacert, args.insecure, dotenv)
    except (OSError, ssl.SSLError) as exc:
        print(f"error: cannot load CA file {args.cacert}: {exc}", file=sys.stderr)
        return 2
    base = url.rstrip("/")
    password = os.environ.get("SSO_PASSWORD") or getpass.getpass(f"Password for {args.username}: ")

    try:
        status, data = call(base, "/api/v1/auth/login", ctx,
                            body={"username": args.username, "password": password, "client": "native"})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"error: cannot reach {base}: {exc}", file=sys.stderr)
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            print("hint: pass --cacert <server cert/CA>, or --insecure for a quick dev check", file=sys.stderr)
        return 3
    if status != 200:
        err = data or {}
        print(f"LOGIN FAILED ({status}): {err.get('error')} - {err.get('detail')}", file=sys.stderr)
        return 1 if status in (401, 403, 429) else 3

    access, refresh, user = data["access_token"], data["refresh_token"], data["user"]
    print(f"LOGIN OK  user id={user['id']} username={user['username']} email={user.get('email') or '-'}"
          f" staff={user.get('is_staff')}  (access token expires in {data.get('expires_in')}s)")
    show("Login response", user.get("groups"), user.get("perms"))

    rc = 0
    status, me = call(base, "/api/v1/auth/me", ctx, token=access)
    if status == 200:
        show("GET /auth/me", me.get("groups"), me.get("perms"))
    else:
        print(f"GET /auth/me failed ({status}): {(me or {}).get('error')}", file=sys.stderr)
        rc = 3

    try:
        c = jwt_claims(access)
        show(f"Access token claims (unverified, iss={c.get('iss')}, aud={c.get('aud')})",
             c.get("groups"), c.get("perms"))
    except (IndexError, ValueError) as exc:
        print(f"cannot decode access token claims: {exc}", file=sys.stderr)

    status, out = call(base, "/api/v1/auth/logout", ctx, body={"refresh_token": refresh})
    if status == 204:
        print("LOGOUT OK (refresh token blacklisted; the access token stays valid until it expires)")
    else:
        print(f"LOGOUT FAILED ({status}): {(out or {}).get('error')} - {(out or {}).get('detail')}", file=sys.stderr)
        rc = 3
    return rc


if __name__ == "__main__":
    sys.exit(main())
