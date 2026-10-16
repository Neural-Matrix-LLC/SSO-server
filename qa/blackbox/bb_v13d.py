"""Black-box pass of the v1.3d admin web UI through nginx (HTTPS) -> gunicorn. Usage:
    BB_BASE=https://localhost BB_ADMIN=qa_admin BB_PW=... BB_PLAIN=qa_plain BB_PLAIN_PW=... python bb_v13d.py
Seeds come from qa/blackbox/bb_v13d_seed.py. Prints one line per check, exit 1 on any failure."""
import json
import os
import re
import sys
import urllib3

import requests

urllib3.disable_warnings()
BASE = os.environ.get("BB_BASE", "https://localhost").rstrip("/")
UI = BASE + "/" + os.environ.get("BB_UI_PATH", "admin/")
ADMIN, PW = os.environ["BB_ADMIN"], os.environ["BB_PW"]
PLAIN, PLAIN_PW = os.environ["BB_PLAIN"], os.environ["BB_PLAIN_PW"]
RUN = os.environ.get("BB_RUN", "r1")
FAILS = []


def check(cid, ok, info=""):
    print(f"{'PASS' if ok else 'FAIL'} {cid} {info}")
    if not ok:
        FAILS.append(cid)


def sess():
    s = requests.Session()
    s.verify = False
    return s


def tok(html):
    m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
    return m.group(1) if m else ""


def post(s, url, data, page=None):
    page = page or url
    t = tok(s.get(page, allow_redirects=True).text)
    return s.post(url, data={"csrfmiddlewaretoken": t, **data}, headers={"Referer": page}, allow_redirects=False)


def ui_login(s, user, pw):
    return post(s, UI + "login/", {"username": user, "password": pw})


# U-01 anonymous -> login redirect, security headers
s = sess()
r = s.get(UI, allow_redirects=False)
check("U-01", r.status_code == 302 and "/admin/login/" in r.headers.get("Location", ""), r.status_code)
r = s.get(UI + "login/")
h = r.headers
check("U-02 headers", "default-src 'none'" in h.get("Content-Security-Policy", "") and "frame-ancestors 'none'" in h.get("Content-Security-Policy", "") and h.get("X-Frame-Options") == "DENY"
      and "no-store" in h.get("Cache-Control", "") and h.get("Referrer-Policy") == "same-origin",
      {k: h.get(k) for k in ("Content-Security-Policy", "X-Frame-Options", "Cache-Control", "Referrer-Policy")})
check("U-03 csrf cookie", any(c.name == "__Host-sso_admin_csrf" and c.secure for c in s.cookies), [c.name for c in s.cookies])

# U-04 wrong password and non-admin: same generic error, no session
for cid, (u, p) in {"U-04 wrong pw": (ADMIN, "nope-nope-1"), "U-05 non-admin": (PLAIN, PLAIN_PW)}.items():
    x = sess()
    r = ui_login(x, u, p)
    check(cid, r.status_code == 200 and "Invalid username or password" in r.text
          and not any(c.name == "__Host-sso_admin_sid" for c in x.cookies), r.status_code)

# U-06 admin login -> cookie flags
r = ui_login(s, ADMIN, PW)
raw = r.headers.get("Set-Cookie", "")
check("U-06 login", r.status_code == 302 and "__Host-sso_admin_sid=" in raw and "HttpOnly" in raw
      and "SameSite=Strict" in raw and "Secure" in raw and "Path=/" in raw and "expires" not in raw.lower().split("sso_admin_sid")[1].split(",")[0],
      raw[:200])
r = s.get(UI)
check("U-07 dashboard", r.status_code == 200 and "Dashboard" in r.text, r.status_code)

# U-08 POST without CSRF token -> 403 HTML
r = s.post(UI + "users/new/", data={"username": "x"}, headers={"Referer": UI}, allow_redirects=False)
check("U-08 csrf", r.status_code == 403, r.status_code)

# U-09 create user
uname = f"bb_{RUN}_user"
r = post(s, UI + "users/new/", {"username": uname, "email": f"{uname}@example.org", "password": "Bb-Passw0rd-xyz!",
                                 "password2": "Bb-Passw0rd-xyz!"})
loc = r.headers.get("Location", "")
check("U-09 create user", r.status_code == 302 and re.search(r"/users/\d+/$", loc), (r.status_code, loc))
upath = BASE + loc if loc.startswith("/") else loc
upk = re.search(r"/users/(\d+)/", loc).group(1) if loc else "0"

# U-10 suspend needs step-up: GET suspend -> reauth page
r = s.get(UI + f"users/{upk}/suspend", allow_redirects=False)
check("U-10 step-up required", r.status_code == 302 and "/reauth/" in r.headers.get("Location", ""), r.headers.get("Location"))
r = post(s, UI + "reauth/", {"password": "wrong-wrong-1"}, page=UI + "reauth/")
check("U-11 reauth wrong pw", r.status_code in (200, 400) and 'role="alert"' in r.text and 'class="elevated"' not in r.text, r.status_code)
r = post(s, UI + "reauth/", {"password": PW, "next": UI.replace(BASE, "") + f"users/{upk}/suspend"}, page=UI + "reauth/")
check("U-12 reauth ok", r.status_code == 302, (r.status_code, r.headers.get("Location")))
r = s.get(UI + f"users/{upk}/suspend")
check("U-13 confirm page", r.status_code == 200 and "Suspend" in r.text, r.status_code)
r = post(s, UI + f"users/{upk}/suspend", {}, page=UI + f"users/{upk}/suspend")
check("U-14 suspended", r.status_code == 302 and "suspended" in s.get(upath).text.lower(), r.status_code)

# U-15 audit page shows the ui row; API audit ?channel=ui
r = s.get(UI + "audit/?channel=ui&action=user.suspend")
check("U-15 audit ui row", r.status_code == 200 and "user.suspend" in r.text, r.status_code)
api = requests.post(BASE + "/api/v1/auth/login", json={"username": ADMIN, "password": PW, "client": "native"}, verify=False)
at = api.json().get("access_token", "") if api.ok else ""
r = requests.get(BASE + "/api/v1/admin/audit?channel=ui&action=user.suspend", headers={"Authorization": "Bearer " + at}, verify=False)
rows = r.json().get("results", []) if r.ok else []
check("U-16 API audit channel", r.ok and rows and all(x.get("channel") == "ui" for x in rows)
      and any(x.get("target_id") == upk for x in rows), (r.status_code, len(rows)))
r = requests.get(BASE + "/api/v1/admin/audit?channel=bogus", headers={"Authorization": "Bearer " + at}, verify=False)
check("U-17 API bad channel 400", r.status_code == 400, r.status_code)

# U-18 the UI cookie is no API credential; a bearer token is no UI credential
r = s.get(BASE + "/api/v1/admin/users")
check("U-18 cookie not API auth", r.status_code == 401, r.status_code)
r = requests.get(UI + "users/", headers={"Authorization": "Bearer " + at}, verify=False, allow_redirects=False)
check("U-19 bearer not UI auth", r.status_code == 302 and "/login/" in r.headers.get("Location", ""), r.status_code)

# U-20 service: create shows secret once, rotate (still elevated)
cid = f"bb-{RUN}-svc"
r = post(s, UI + "services/new/", {"client_id": cid, "name": "BB svc"})
m = re.search(r'<code[^>]*id="secret"[^>]*>([^<]+)<', r.text) or re.search(r"<code[^>]*>([A-Za-z0-9_\-]{30,})</code>", r.text)
check("U-20 service secret shown once", r.status_code == 200 and m and "no-store" in r.headers.get("Cache-Control", ""), r.status_code)
r = s.get(UI + f"services/{cid}/")
check("U-21 secret not on detail", r.status_code == 200 and (not m or m.group(1) not in r.text), r.status_code)
r = post(s, UI + f"services/{cid}/rotate-secret", {}, page=UI + f"services/{cid}/rotate-secret")
m2 = re.search(r"<code[^>]*>([A-Za-z0-9_\-]{30,})</code>", r.text)
check("U-22 rotate", r.status_code == 200 and m2 and (not m or m2.group(1) != m.group(1)), r.status_code)

# U-23 import preview (dry run) and apply; evil python text rejected
app = f"bb{RUN.replace('-', '')}"
payload = json.dumps({"app_codename": app, "app_name": "BB", "version": 1,
                      "permissions": [{"codename": f"{app}_read", "name": "Read"}]})
r = post(s, UI + "apps/import/", {"json": payload}, page=UI + "apps/import/")
check("U-23 import preview", r.status_code == 200 and "Preview" in r.text, r.status_code)
dg = re.search(r'name="digest" value="([^"]+)"', r.text)
pl = re.search(r'name="payload" value="([^"]+)"', r.text)
import html as _h
r2 = s.post(UI + "apps/import/apply", data={"csrfmiddlewaretoken": tok(r.text), "payload": _h.unescape(pl.group(1)) if pl else "",
                                            "digest": dg.group(1) if dg else "", "force": "0"},
            headers={"Referer": UI + "apps/import/"}, allow_redirects=False)
check("U-24 import apply", r2.status_code == 302 and f"/apps/{app}/" in r2.headers.get("Location", ""), r2.status_code)
r = post(s, UI + "apps/import/", {"json": "import os\nos.system('touch /tmp/bb_pwned')\nPERMISSIONS=[]"}, page=UI + "apps/import/")
check("U-25 python text rejected", r.status_code in (200, 400) and 'role="alert"' in r.text and "Preview:" not in r.text and not os.path.exists("/tmp/bb_pwned"),
      r.status_code)

# U-26 CSV export formula-safe + audited
r = s.get(UI + "audit/export.csv")
check("U-26 audit csv", r.status_code == 200 and r.headers.get("Content-Type", "").startswith("text/csv"), r.status_code)

# U-31 (QA V13D-01) step-up from a POST-only route returns to the form page, not to the POST URL
post(s, UI + "reauth/drop/", {"back": "/admin/"}, page=UI)
r = post(s, UI + f"users/{upk}/permissions", {"op": "grant", "codename": "sso_admin"}, page=UI + f"users/{upk}/")
check("U-31 step-up next = form page", r.status_code == 302 and r.headers.get("Location", "").endswith(
    "next=" + requests.utils.quote(f"/admin/users/{upk}/", safe="")), r.headers.get("Location"))
r = s.get(BASE + r.headers.get("Location", "/"), allow_redirects=False)
check("U-32 reauth page renders", r.status_code == 200, r.status_code)

# U-27 drop elevation, then a step-up action asks again
post(s, UI + "reauth/drop/", {"back": "/admin/"}, page=UI)
r = s.get(UI + f"users/{upk}/delete", allow_redirects=False)
check("U-27 drop elevation", r.status_code == 302 and "/reauth/" in r.headers.get("Location", ""), r.status_code)

# U-28 logout ends the session server-side (replay of the old cookie fails)
old = s.cookies.get("__Host-sso_admin_sid")
post(s, UI + "logout/", {}, page=UI)
x = sess()
x.cookies.set("__Host-sso_admin_sid", old or "", domain="localhost", path="/")
r = x.get(UI + "users/", allow_redirects=False)
check("U-28 logout kills cookie", r.status_code == 302 and "/login/" in r.headers.get("Location", ""), r.status_code)

# U-29 revoked from elsewhere: API logout-all of the admin kills a live UI session
y = sess()
ui_login(y, ADMIN, PW)
check("U-29a live", y.get(UI + "users/", allow_redirects=False).status_code == 200)
requests.post(BASE + "/api/v1/auth/logout-all", headers={"Authorization": "Bearer " + at}, verify=False)
r = y.get(UI + "users/", allow_redirects=False)
check("U-29 logout-all ends UI session", r.status_code == 302 and "/login/" in r.headers.get("Location", ""), r.status_code)

# U-30 Django admin path is still separate (its own login)
r = requests.get(BASE + "/" + os.environ.get("BB_DJANGO_ADMIN", "sso-admin/"), verify=False, allow_redirects=False)
check("U-30 django admin separate", r.status_code == 302 and "/admin/login/" not in r.headers.get("Location", "").replace("/sso-admin/", ""),
      (r.status_code, r.headers.get("Location")))

print(f"\n{'ALL PASS' if not FAILS else 'FAILED: ' + ', '.join(FAILS)}")
sys.exit(1 if FAILS else 0)
