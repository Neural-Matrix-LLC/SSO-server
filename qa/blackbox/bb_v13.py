"""Black-box QA for SSO v1.3a/b/c against a RUNNING server (qa/RESULTS-v1.3.md).

Env: BB_BASE (http://127.0.0.1:8091), BB_HOOK_PORT (9443), BB_TLS_DIR (cert.pem/key.pem of the local receiver),
BB_ADMIN_PW, BB_ALICE_PW, BB_STAFF_PW, BB_NOSTAFF_PW. Users qaadmin (superuser+staff), alice (app1), nostaff
(superuser, not staff), staffonly (staff, no sso_admin), staffadm (staff + sso_admin) must exist.
The server needs SSO_WEBHOOK_ALLOW_LOOPBACK=true and SSO_WEBHOOK_CA_FILE=<the receiver cert> and a running worker.
Prints one line per check: PASS/FAIL id description. Exit code = number of failures.
"""
from __future__ import annotations

import http.server
import json
import os
import ssl
import threading
import time
import uuid

import httpx

from sso_client import (DeviceTokenSource, ServiceTokenSource, SSOClient, SSOConfig, TokenInactive,
                        WebhookVerificationError, generate_device_key, verify_webhook)

BASE = os.environ.get("BB_BASE", "http://127.0.0.1:8091")
HOOK_PORT = int(os.environ.get("BB_HOOK_PORT", "9443"))
TLS = os.environ["BB_TLS_DIR"]
A = BASE + "/api/v1/admin"
IP = "203.0.113.50"
H = httpx.Client(timeout=10)
RESULTS: list[tuple[str, bool, str]] = []
HOOKS: list[tuple[dict, bytes]] = []
FAIL_NEXT = {"n": 0}
BASE_EVENT = {"id": 0}  # only events newer than the start of this run count


def check(cid, ok, desc, detail=""):
    RESULTS.append((cid, bool(ok), desc))
    print(("PASS" if ok else "FAIL"), cid, desc, "" if ok else f"-- {detail}"[:400], flush=True)


# ------------------------------------------------------------------ local HTTPS receiver
class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if FAIL_NEXT["n"] > 0:
            FAIL_NEXT["n"] -= 1
            self.send_response(503)
            self.end_headers()
            return
        HOOKS.append(({k: v for k, v in self.headers.items()}, body))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


def start_receiver():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", HOOK_PORT), Hook)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{TLS}/cert.pem", f"{TLS}/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def wait_hook(pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        for h, b in list(HOOKS):
            ev = json.loads(b)
            if ev["id"] > BASE_EVENT["id"] and pred(ev):
                return h, b, ev
        time.sleep(0.3)
    return None


# ------------------------------------------------------------------ helpers
def login(user, pw, ip=IP):
    r = H.post(BASE + "/api/v1/auth/login", json={"username": user, "password": pw, "client": "native"},
               headers={"X-Forwarded-For": ip})
    return r


def auth(t, reauth=None):
    h = {"Authorization": "Bearer " + t}
    if reauth:
        h["X-SSO-Reauth"] = reauth
    return h


def get_reauth(t, pw):
    r = H.post(A + "/reauth", json={"password": pw}, headers=auth(t))
    return r.json().get("reauth_token") if r.status_code == 200 else None


def main():
    start_receiver()
    apw, alpw, spw, nspw = (os.environ[k] for k in ("BB_ADMIN_PW", "BB_ALICE_PW", "BB_STAFF_PW", "BB_NOSTAFF_PW"))

    # ---------------- v1.3a admin auth matrix (is_staff decision)
    r = login("qaadmin", apw)
    check("A-01", r.status_code == 200, "admin login", r.text)
    at = r.json()["access_token"]
    check("A-02", H.get(A + "/users", headers=auth(at)).status_code == 200, "superuser+staff -> admin API 200")
    for u, pw, cid in (("nostaff", nspw, "A-03"), ("staffonly", spw, "A-04")):
        t = login(u, pw).json()["access_token"]
        r = H.get(A + "/users", headers=auth(t))
        check(cid, r.status_code == 403 and r.json().get("error") == "admin_forbidden", f"{u} -> 403", r.text)
    t = login("staffadm", spw).json()["access_token"]
    check("A-05", H.get(A + "/users", headers=auth(t)).status_code == 200, "staff + sso_admin -> 200")
    check("A-06", H.get(A + "/users").status_code == 401, "anonymous -> 401")

    # ---------------- step-up + logout drops reauth
    t2 = login("qaadmin", apw).json()
    ra = get_reauth(t2["access_token"], apw)
    check("A-07", bool(ra), "reauth token issued")
    H.post(BASE + "/api/v1/auth/logout", json={"refresh": t2.get("refresh_token", "")},
           headers=auth(t2["access_token"]))
    r = H.post(A + "/users", json={"username": "x" + uuid.uuid4().hex[:6], "password": "Zz9-very-long-pw!"},
               headers=auth(at, ra))
    # create is not step-up gated; test a gated action instead
    uid = r.json().get("id")
    r = H.post(f"{A}/users/{uid}/set-password", json={"password": "Zz9-other-long-pw!"}, headers=auth(at, ra))
    check("A-08", r.status_code == 401 and r.json().get("error") == "reauth_required",
          "reauth token from a logged-out session is rejected", r.text)
    ra = get_reauth(at, apw)
    r = H.post(f"{A}/users/{uid}/set-password", json={"password": "Zz9-other-long-pw!"}, headers=auth(at, ra))
    check("A-09", r.status_code == 204, "step-up action with a valid reauth", r.text)

    # ---------------- permission import
    body = {"app_name": "QA app", "version": 1, "permissions": [{"codename": "qaapp_read", "name": "Read QA"}]}
    r = H.put(A + "/apps/qaapp/permissions?dry_run=true", json=body, headers=auth(at, ra))
    check("A-10", r.status_code in (200, 201), "import dry-run", r.text)
    r = H.put(A + "/apps/qaapp/permissions", json=body, headers=auth(at, ra))
    check("A-11", r.status_code in (200, 201), "import", r.text)
    r2 = H.put(A + "/apps/qaapp/permissions", json=body, headers=auth(at, ra))
    check("A-12", r2.status_code in (200, 201) and not r2.json()["created"] and not r2.json()["updated"], "import idempotent", r2.text)

    ev0 = (H.get(A + "/webhooks/events", headers=auth(at)).json()["results"] or [{"id": 0}])[0]["id"]
    BASE_EVENT["id"] = ev0
    # ---------------- service + webhook setup (v1.3c); isolate from earlier runs (same receiver URL)
    for old in H.get(A + "/services", params={"page_size": 200}, headers=auth(at)).json()["results"]:
        if old["client_id"].startswith("qa-svc-") and old["is_active"]:
            H.patch(f"{A}/services/{old['client_id']}", json={"is_active": False}, headers=auth(at, ra))
    cid = "qa-svc-" + uuid.uuid4().hex[:6]
    r = H.post(A + "/services", json={"client_id": cid, "name": "QA svc", "app_codename": "app1",
                                      "notify_url": f"https://127.0.0.1:{HOOK_PORT}/hook"}, headers=auth(at))
    check("C-01", r.status_code == 201 and r.json().get("has_notify_secret") is False, "create service", r.text)
    secret = r.json()["client_secret"]
    r = H.post(f"{A}/services/{cid}/rotate-notify-secret", headers=auth(at))
    check("C-02", r.status_code == 401, "rotate-notify-secret needs step-up", r.text)
    r = H.post(f"{A}/services/{cid}/rotate-notify-secret", headers=auth(at, ra))
    nsec = r.json().get("notify_secret")
    check("C-03", r.status_code == 200 and nsec, "rotate-notify-secret", r.text)
    s = H.get(f"{A}/services/{cid}", headers=auth(at)).json()
    check("C-04", s.get("has_notify_secret") is True and "notify_secret" not in json.dumps(s).replace(
        "has_notify_secret", ""), "secret never shown again")
    r = H.patch(f"{A}/services/{cid}", json={"notify_events": ["bogus"]}, headers=auth(at))
    check("C-05", r.status_code == 400, "unknown event type -> 400", r.text)
    r = H.patch(f"{A}/services/{cid}", json={"can_register_devices": True, "can_delegate": True}, headers=auth(at, ra))
    check("B-01", r.status_code == 200 and r.json()["can_delegate"], "enable devices + delegation (step-up)", r.text)

    # ---------------- service tokens + sso-client 0.2
    cfg = SSOConfig(base_url=BASE, client_id=cid, client_secret=secret, allow_http=True)
    sts = ServiceTokenSource(cfg)
    st = sts.get()
    check("B-02", bool(st), "ServiceTokenSource gets a service token")
    cl = SSOClient(cfg)
    sc = cl.check_service(st)
    check("B-03", getattr(sc, "client_id", None) == cid, "check_service(service token)", repr(sc))

    # ---------------- on-behalf-of
    al = login("alice", alpw).json()["access_token"]
    res = cl.check(al, IP, "application.app1", actor_token=st)
    check("B-04", res.active and res.delegation_allowed is True and cid in str(res.via)
          and "application.app1" in res.permissions, "on-behalf-of check with actor token", repr(res))
    try:
        r = cl.check(al, IP, "application.app1", actor_token="garbage." + st[8:])
        check("B-05", not r.active, "forged actor token fails closed", repr(r))
    except TokenInactive:
        check("B-05", True, "forged actor token fails closed")

    # ---------------- devices
    priv, pub = generate_device_key()
    r = H.post(BASE + "/api/v1/devices", json={"device_name": "qa-pc", "public_key": pub},
               headers={"Authorization": "Bearer " + st, "X-SSO-User-Token": al, "X-SSO-Client-IP": IP})
    check("B-06", r.status_code == 201, "register device", r.text)
    dev = r.json().get("client_id")
    dts = DeviceTokenSource(BASE, dev, priv, allow_http=True)
    dt = dts.get()
    dc = cl.check_service(dt)
    check("B-07", getattr(dc, "typ", None) == "device" or "dev:" in repr(dc), "device token + introspect", repr(dc))
    r = H.get(BASE + "/api/v1/devices", headers=auth(al))
    check("B-08", any(d["client_id"] == dev for d in r.json().get("results", [])), "owner lists device", r.text)
    r = H.post(BASE + "/api/v1/devices", json={"device_name": "dup", "public_key": pub},
               headers={"Authorization": "Bearer " + st, "X-SSO-User-Token": al, "X-SSO-Client-IP": IP})
    check("B-09", r.status_code == 409, "duplicate key -> 409", r.text)

    # ---------------- suspend -> webhook + devices off + feed
    alice_id = H.get(A + "/users?q=alice", headers=auth(at)).json()["results"][0]["id"]
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
    r = H.post(f"{A}/users/{alice_id}/suspend", headers=auth(at, ra))
    check("C-06", r.status_code in (200, 204), "suspend alice", r.text)
    got = wait_hook(lambda e: e["type"] == "user.suspended" and e.get("sub") == str(alice_id))
    check("C-07", got is not None, "user.suspended delivered to the HTTPS receiver")
    if got:
        h, b, _ = got
        try:
            verify_webhook(b, h, [nsec])
            check("C-08", True, "signature verifies with sso_client.verify_webhook")
        except WebhookVerificationError as exc:
            check("C-08", False, "signature verifies", str(exc))
        try:
            verify_webhook(b, h, ["wrong"])
            check("C-09", False, "wrong secret rejected")
        except WebhookVerificationError:
            check("C-09", True, "wrong secret rejected")
    check("C-10", wait_hook(lambda e: e["type"] == "token.revoked" and e.get("reason") == "suspended") is not None,
          "token.revoked(suspended) delivered")
    dts.invalidate()
    try:
        dts.get()
        check("B-10", False, "device of a suspended owner cannot get tokens")
    except Exception as exc:  # noqa: BLE001
        check("B-10", "401" in str(exc) or "invalid" in str(exc).lower(), "device of a suspended owner refused", str(exc))
    try:
        cl.check_service(dt)
        check("B-11", False, "existing device token inactive after suspend")
    except TokenInactive:
        check("B-11", True, "existing device token inactive after suspend")
    feed = H.get(BASE + "/api/v1/service/users/inactive", params={"since": since}, headers=auth(sts.get())).json()
    check("A-13", any(u["id"] == alice_id and u["event"] == "suspended" for u in feed.get("users", [])),
          "inactive feed lists the suspended user", json.dumps(feed))
    H.post(f"{A}/users/{alice_id}/unsuspend", headers=auth(at, ra))
    check("C-11", wait_hook(lambda e: e["type"] == "user.reactivated") is not None, "user.reactivated delivered")

    # ---------------- delete -> tombstone + user.deleted
    r = H.delete(f"{A}/users/{uid}", headers=auth(at, ra))
    check("A-14", r.status_code in (200, 204), "delete user", r.text)
    feed = H.get(BASE + "/api/v1/service/users/inactive", params={"since": since}, headers=auth(sts.get())).json()
    check("A-15", any(u["id"] == uid and u["event"] == "deleted" for u in feed.get("users", [])),
          "inactive feed lists the deleted user (tombstone)", json.dumps(feed))
    check("C-12", wait_hook(lambda e: e["type"] == "user.deleted" and e.get("sub") == str(uid)) is not None,
          "user.deleted delivered")

    # ---------------- permission.changed + filter
    r = H.patch(f"{A}/services/{cid}", json={"notify_events": ["permission.changed"]}, headers=auth(at))
    check("C-13", r.status_code == 200 and r.json()["notify_events"] == ["permission.changed"], "subscribe filter")
    n0 = len(HOOKS)
    H.post(f"{A}/users/{alice_id}/permissions/qaapp_read", headers=auth(at, ra))
    got = wait_hook(lambda e: e["type"] == "permission.changed" and e.get("perm") == "application.qaapp_read")
    check("C-14", got is not None, "permission.changed delivered on grant")
    H.post(f"{A}/users/{alice_id}/logout-all", headers=auth(at, ra))
    time.sleep(4)
    check("C-15", all(json.loads(b)["type"] == "permission.changed" for _, b in HOOKS[n0:]),
          "filtered: no token.revoked after logout-all", str([json.loads(b) for _, b in HOOKS[n0:]]))

    # ---------------- retry + redeliver
    FAIL_NEXT["n"] = 1
    H.delete(f"{A}/users/{alice_id}/permissions/qaapp_read", headers=auth(at, ra))
    got = wait_hook(lambda e: e["type"] == "permission.changed" and e.get("granted") is False, timeout=30)
    check("C-16", got is not None, "delivery retried after a 503 and then delivered")
    if got:
        ev_id = got[2]["id"]
        d = H.get(A + "/webhooks/deliveries", params={"event": ev_id, "client_id": cid}, headers=auth(at)).json()
        d = d["results"][0] if len(d["results"]) == 1 else {"many": d["results"]}
        check("C-17", d["status"] == "delivered" and d["attempts"] == 2, "delivery shows 2 attempts", json.dumps(d))
        n1 = len(HOOKS)
        r = H.post(f"{A}/webhooks/deliveries/{d['id']}/redeliver", headers=auth(at))
        check("C-18", r.status_code == 200, "redeliver", r.text)
        end = time.time() + 15
        while time.time() < end and not any(json.loads(b)["id"] == ev_id for _, b in HOOKS[n1:]):
            time.sleep(0.3)
        check("C-19", any(json.loads(b)["id"] == ev_id for _, b in HOOKS[n1:]), "redelivered with the same id")
    r = H.get(A + "/webhooks/events", params={"type": "keys.rotated"}, headers=auth(at))
    check("C-20", r.status_code == 200 and r.json()["results"], "keys.rotated baseline event recorded", r.text)
    r = H.get(A + "/audit", params={"action": "service.rotate_notify_secret"}, headers=auth(at))
    check("C-21", r.status_code == 200 and "notify_secret\":\"" + str(nsec) not in r.text, "audit has no secret")

    fails = [c for c in RESULTS if not c[1]]
    print(f"TOTAL {len(RESULTS)} checks, {len(RESULTS) - len(fails)} passed, {len(fails)} failed")
    return len(fails)


if __name__ == "__main__":
    raise SystemExit(main())
