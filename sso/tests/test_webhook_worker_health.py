"""Webhook worker heartbeat + `docker/healthcheck.py --worker`, and nginx re-resolving the web upstream.

Background (2026-10-16): the webhooks container inherited the image's HTTP /healthz probe (always unhealthy, it has
no port), and nginx kept web's start-up IP after web was recreated, proxying to the worker that took it over (502)."""
from __future__ import annotations

import importlib.util
import json
import logging
import time
from pathlib import Path

import pytest
from django.core.management import call_command

from sso.management.commands import run_webhook_worker as worker_cmd

REPO = Path(__file__).resolve().parents[2]


def _healthcheck():
    spec = importlib.util.spec_from_file_location("sso_docker_healthcheck", REPO / "docker" / "healthcheck.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Stop(Exception):
    pass


@pytest.fixture
def hb_path(tmp_path, monkeypatch):
    path = tmp_path / "hb"
    monkeypatch.setattr(worker_cmd, "HEARTBEAT_FILE", str(path))
    return path


def _run_loop(monkeypatch, results, on_sleep):
    """Run the worker loop over `results` (dicts returned / exceptions raised by process_once)."""
    it = iter(results)

    def fake_process_once():
        r = next(it)
        if isinstance(r, Exception):
            raise r
        return r

    calls = {"n": 0}

    def fake_sleep(_s):
        calls["n"] += 1
        on_sleep(calls["n"])
        if calls["n"] >= len(results):
            raise _Stop

    monkeypatch.setattr(worker_cmd, "process_once", fake_process_once)
    monkeypatch.setattr(worker_cmd.time, "sleep", fake_sleep)
    with pytest.raises(_Stop):
        call_command("run_webhook_worker")


def test_worker_logs_and_writes_heartbeat(db, hb_path, monkeypatch, caplog):
    seen = []
    caplog.set_level(logging.INFO, logger="sso.webhooks")
    _run_loop(monkeypatch, [{"delivered": 2}, RuntimeError("db down"), {}],
              lambda n: seen.append(json.loads(hb_path.read_text())))
    ok1, failed, ok2 = seen
    assert ok1["ok"] is True and ok1["last_ok"] == ok1["ts"] and ok1["error"] == ""
    assert failed["ok"] is False and failed["error"] == "RuntimeError: db down"
    assert failed["last_ok"] is not None and failed["last_ok"] <= failed["ts"]  # keeps the last success
    assert ok2["ok"] is True
    msgs = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("webhook worker started") and str(hb_path) in m for m in msgs)
    assert 'webhook worker processed {"delivered": 2}' in msgs
    assert "webhook worker iteration failed" in msgs and "webhook worker recovered" in msgs
    assert sum("processed" in m for m in msgs) == 1  # idle iterations stay quiet


def test_worker_once_writes_no_heartbeat(db, hb_path):
    call_command("run_webhook_worker", "--once")
    assert not hb_path.exists()


def test_heartbeat_write_failure_only_warns(tmp_path, caplog):
    worker_cmd.write_heartbeat(str(tmp_path / "missing-dir" / "hb"), ok=True)
    assert "could not write heartbeat" in caplog.text


@pytest.mark.parametrize("hb, rc, text", [
    (None, 1, "no heartbeat file"),
    ("not json", 1, "unreadable heartbeat"),
    ({"ts": 990, "ok": True, "last_ok": 990, "error": ""}, 0, "worker healthy"),
    ({"ts": 995, "ok": False, "last_ok": 900, "error": "OperationalError: x"}, 0, "retrying after error"),
    ({"ts": 995, "ok": False, "last_ok": 500, "error": "OperationalError: x"}, 1, "500s ago (max 300s)"),
    ({"ts": 995, "ok": False, "last_ok": None, "error": "OperationalError: x"}, 1, "never"),
])
def test_healthcheck_worker_mode(tmp_path, capsys, monkeypatch, hb, rc, text):
    monkeypatch.delenv("SSO_HEALTHCHECK_MAX_AGE", raising=False)
    path = tmp_path / "hb"
    if hb is not None:
        path.write_text(hb if isinstance(hb, str) else json.dumps(hb))
    assert _healthcheck().check_worker(str(path), now=1000) == rc
    out, err = capsys.readouterr()
    assert text in (out if rc == 0 else err)


def test_healthcheck_worker_reads_real_heartbeat(tmp_path):
    path = tmp_path / "hb"
    worker_cmd.write_heartbeat(str(path), ok=True)
    assert _healthcheck().check_worker(str(path), now=time.time()) == 0


def test_heartbeat_path_shared_by_worker_and_healthcheck():
    assert _healthcheck().HEARTBEAT_FILE == worker_cmd.HEARTBEAT_FILE
    assert worker_cmd.HEARTBEAT_FILE.startswith("/tmp/")  # the compose tmpfs; the root fs is read-only


def test_healthcheck_web_mode_reports_target(capsys, monkeypatch):
    monkeypatch.setenv("SSO_HEALTHCHECK_PORT", "1")  # nothing listens there
    assert _healthcheck().check_web() == 1
    assert "127.0.0.1:1/healthz" in capsys.readouterr().err


def test_compose_webhooks_uses_worker_healthcheck():
    compose = (REPO / "docker-compose.yml").read_text()
    webhooks = compose[compose.index("\n  webhooks:"):compose.index("\n  redis:")]
    assert '["CMD", "python", "/app/docker/healthcheck.py", "--worker"]' in webhooks
    assert "tmpfs:\n      - /tmp" in webhooks


def test_nginx_re_resolves_web_upstream():
    conf = (REPO / "docker" / "nginx.conf").read_text()
    upstream = conf.split("upstream sso_web {")[1].split("}")[0]
    assert "server web:8000 resolve;" in upstream and "zone sso_web" in upstream
    assert "resolver 127.0.0.11" in conf
