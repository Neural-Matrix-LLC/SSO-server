"""sso-client (clients/python) QA: run with the venv that pip-installed the library from git
(harness/run_v12b_client.sh). Separate directory: qa/tests/sso_client.py (the QA HTTP helper) would shadow the
library's import name. Live SSO servers are started on 8065 (ENFORCE, trusts 127.0.0.1) and 8066 (NOIP)."""
from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

QA = Path(__file__).resolve().parent.parent
HARNESS, RUN = QA / "harness", QA / "run"
PW = "Qa12b-Passw0rd!xyz"
SVC = ("qa-service", "qa-service-secret-123456")
FAST = ["SSO_THROTTLE_LOGIN=10000/min", "SSO_THROTTLE_LOGIN_USER=10000/min", "SSO_THROTTLE_REFRESH=10000/min",
        "SSO_THROTTLE_INTROSPECT=100000/min"]


def _start(port, name, *env):
    log = RUN / f"v12b-client-{name}-{port}.log"
    e = dict(os.environ, SSO_CACHE_URL=f"filecache:///tmp/qa-cache-v12b-client-{name}", SSO_IP_BINDING_MODE="NOIP",
             SSO_TRUSTED_PROXIES="", GUNICORN_WORKERS="1")
    subprocess.run([str(HARNESS / "start_sso.sh"), str(port), str(log), *FAST, *env], env=e, check=True,
                   capture_output=True, timeout=30)
    for _ in range(80):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2).status_code == 200:
                return f"http://127.0.0.1:{port}"
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise AssertionError(log.read_text()[-1500:])


@pytest.fixture(scope="session")
def sso_enf():
    if not os.environ.get("SSO_SQLITE_PATH"):
        pytest.skip("run via harness/run_v12b_client.sh")
    url = _start(8065, "enf", "SSO_IP_BINDING_MODE=ENFORCE", "SSO_TRUSTED_PROXIES=127.0.0.1/32")
    yield url
    subprocess.run([str(HARNESS / "stop_sso.sh"), "8065"], capture_output=True)


@pytest.fixture(scope="session")
def sso_noip():
    if not os.environ.get("SSO_SQLITE_PATH"):
        pytest.skip("run via harness/run_v12b_client.sh")
    url = _start(8066, "noip")
    yield url
    subprocess.run([str(HARNESS / "stop_sso.sh"), "8066"], capture_output=True)


def shell(code: str) -> str:
    p = subprocess.run([str(HARNESS / "manage.sh"), "shell", "-c", code], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-1500:]
    return p.stdout.strip().splitlines()[-1]


@pytest.fixture(scope="session")
def mk_user():
    def make(tag="lib", perms=()):
        name = f"qa12b_{tag}_{uuid.uuid4().hex[:6]}"
        grant = "".join(f"u.user_permissions.add(ensure_permission({c!r}, 'QA {c}')[0]);" for c in perms)
        shell("from django.contrib.auth.models import User; from application.permissions import ensure_permission;"
              f"u=User.objects.create_user({name!r}, password={PW!r});{grant}print(u.pk)")
        return name
    return make


def login(base, name, xff=None):
    h = {"X-Forwarded-For": xff} if xff else {}
    r = httpx.post(base + "/api/v1/auth/login", json={"username": name, "password": PW, "client": "native"},
                   headers=h, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()
