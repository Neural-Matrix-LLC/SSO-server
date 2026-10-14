"""E2E: live SSO (gunicorn, ENFORCE, trusts 127.0.0.1 = "nginx") + three sample services (FastAPI/uvicorn,
Flask/werkzeug, Django/runserver) using sso_client, each trusting 127.0.0.1 so the user IP arrives via XFF.
Ports: SSO 8062, fastapi 8063, flask 8064, django 8065. Every process stopped by its recorded PID."""
import json, os, signal, subprocess, sys, time, uuid
from pathlib import Path
import httpx

QA = Path(__file__).resolve().parent.parent
H, RUN = QA / "harness", QA / "run"
OUT = Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
LIBPY = sys.executable
SSO_PORT, APPS = 8062, {"fastapi": 8063, "flask": 8064, "django": 8065}
SVC = ("qa-service", "qa-service-secret-123456")
PW = "Qa12b-Passw0rd!xyz"
U1, U2 = "203.0.113.150", "198.51.100.150"
SSO_ENV = [f"SSO_IP_BINDING_MODE=ENFORCE", "SSO_TRUSTED_PROXIES=127.0.0.1/32", "SSO_THROTTLE_LOGIN=10000/min",
           "SSO_THROTTLE_LOGIN_USER=10000/min", "SSO_THROTTLE_REFRESH=10000/min"] + sys.argv[2:]
results, procs = [], {}


def rec(step, ok, **kw):
    results.append({"step": step, "ok": bool(ok), **kw}); print(("PASS " if ok else "FAIL ") + step, kw, flush=True)


def wait(url):
    for _ in range(80):
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    return False


def start_sso():
    subprocess.run([str(H / "start_sso.sh"), str(SSO_PORT), str(OUT / "sso.log"), *SSO_ENV], check=True,
                   capture_output=True)
    assert wait(f"http://127.0.0.1:{SSO_PORT}/healthz")


def stop_sso():
    subprocess.run([str(H / "stop_sso.sh"), str(SSO_PORT)], capture_output=True)


def start_apps():
    env = dict(os.environ, SSO_BASE_URL=f"http://127.0.0.1:{SSO_PORT}", SSO_CLIENT_ID=SVC[0], SSO_CLIENT_SECRET=SVC[1],
               SSO_ALLOW_HTTP="true", SSO_TRUSTED_PROXIES="127.0.0.1/32", SSO_RETRIES="1", SSO_TIMEOUT="1.0")
    cmds = {"fastapi": [LIBPY, "-m", "uvicorn", "app_fastapi:app", "--host", "127.0.0.1", "--port", "8063",
                        "--no-proxy-headers"],
            "flask": [LIBPY, "-m", "flask", "--app", "app_flask", "run", "--host", "127.0.0.1", "--port", "8064"],
            "django": [LIBPY, "app_django.py", "8065"]}
    for n, c in cmds.items():
        log = open(OUT / f"app-{n}.log", "w")
        procs[n] = subprocess.Popen(c, cwd=Path(__file__).parent, env=env, stdout=log, stderr=subprocess.STDOUT)
        (RUN / f"e2e-{n}.pid").write_text(str(procs[n].pid))
    for n, p in APPS.items():
        assert wait(f"http://127.0.0.1:{p}/healthz"), n


def stop_apps():
    for n, p in procs.items():
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        (RUN / f"e2e-{n}.pid").unlink(missing_ok=True)


def shell(code):
    p = subprocess.run([str(H / "manage.sh"), "shell", "-c", code], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout.strip().splitlines()[-1]


def login(name, ip):
    r = httpx.post(f"http://127.0.0.1:{SSO_PORT}/api/v1/auth/login", headers={"X-Forwarded-For": ip},
                   json={"username": name, "password": PW, "client": "native"}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()


def get(app, path, tok=None, ip=U1):
    h = {"X-Forwarded-For": ip}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    r = httpx.get(f"http://127.0.0.1:{APPS[app]}{path}", headers=h, timeout=15)
    try:
        body = r.json()
    except ValueError:
        body = r.text[:200]
    return r.status_code, body, r.headers


try:
    start_sso(); start_apps()
    name = f"qa12b_e2e_{uuid.uuid4().hex[:6]}"
    shell("from django.contrib.auth.models import User; from application.permissions import ensure_permission;"
          f"u=User.objects.create_user({name!r}, password={PW!r}); u.user_permissions.add(ensure_permission('app1','QA app1')[0]); print(1)")
    for app in APPS:
        b = login(name, U1)
        tok, sid = b["access_token"], None
        st, body, h = get(app, "/app1")
        rec(f"{app}: no token -> 401", st == 401 and h.get("www-authenticate") == "Bearer", status=st, body=body)
        st, body, _ = get(app, "/app1", tok)
        rec(f"{app}: real login, /app1 from bound IP -> 200", st == 200 and body.get("ip") == U1 and body.get("ip_match") is True, status=st, body=body)
        st, body, _ = get(app, "/app2", tok)
        rec(f"{app}: /app2 missing permission -> 403", st == 403 and body.get("missing") == ["application.app2"], status=st, body=body)
        st, body, _ = get(app, "/app1", tok, ip=U2)
        rec(f"{app}: copied token from other IP -> 401 token_inactive", st == 401 and body.get("detail") == "token_inactive", status=st, body=body)
        r = httpx.post(f"http://127.0.0.1:{SSO_PORT}/api/v1/auth/refresh", headers={"X-Forwarded-For": U1},
                       json={"refresh_token": b["refresh_token"]}, timeout=10)
        rec(f"{app}: legit client's refresh after replay -> 401 (session revoked)", r.status_code == 401, status=r.status_code)
        st, body, _ = get(app, "/app1", tok)
        rec(f"{app}: legit IP within service cache window (<=30 s) still 200 (documented)", st == 200, status=st)
    # SSO killed: uncached token -> 503 on every service; cached token keeps working <= 30 s
    cached = login(name, U1)["access_token"]
    for app in APPS:
        get(app, "/app1", cached)
    fresh = login(name, U1)["access_token"]
    stop_sso()
    for app in APPS:
        t0 = time.monotonic()
        st, body, h = get(app, "/app1", fresh)
        rec(f"{app}: SSO killed -> 503 + Retry-After", st == 503 and h.get("retry-after") == "5" and body == {"detail": "sso_unavailable"},
            status=st, body=body, seconds=round(time.monotonic() - t0, 2))
        st, _, _ = get(app, "/app1", cached)
        rec(f"{app}: SSO killed, token cached < 30 s -> 200 (cache)", st == 200, status=st)
finally:
    stop_apps(); stop_sso()
    (OUT / "e2e-results.json").write_text(json.dumps(results, indent=1))
    print(f"E2E: {sum(r['ok'] for r in results)}/{len(results)} passed")
