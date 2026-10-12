"""Dockerfile CMD / compose consistency for gunicorn on a read-only root fs (WSL report 2026-10-11).

gunicorn >= 25.1 opens a control socket at $XDG_RUNTIME_DIR/gunicorn.ctl or $HOME/.gunicorn/gunicorn.ctl;
in the image HOME is /nonexistent on a read-only root fs, so it logged "[ERROR] Control server error".
The CMD disables it with --no-control-socket.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _cmd_args() -> list[str]:
    line = next(line for line in (REPO / "Dockerfile").read_text().splitlines() if line.startswith("CMD "))
    argv = json.loads(line[4:])
    assert argv[:2] == ["sh", "-c"]
    args = shlex.split(argv[2])
    assert args[:2] == ["exec", "gunicorn"]
    return args[2:]


def test_cmd_disables_the_control_socket():
    assert "--no-control-socket" in _cmd_args()


def test_gunicorn_parses_the_cmd_and_disables_the_control_socket():
    """Use the installed gunicorn's own parser: the flag names are real, not guessed."""
    config = pytest.importorskip("gunicorn.config")
    cfg = config.Config()
    args = [a.replace("${GUNICORN_WORKERS:-3}", "3").replace("${SSO_FORWARDED_ALLOW_IPS:-127.0.0.1}", "127.0.0.1")
            for a in _cmd_args()]
    parsed = cfg.parser().parse_args(args)
    for key, value in vars(parsed).items():
        if value is not None and key != "args":
            cfg.set(key.lower(), value)
    assert cfg.control_socket_disable is True
    assert cfg.worker_tmp_dir == "/dev/shm"


def test_writable_paths_match_compose():
    """The CMD writes only to /dev/shm (always a tmpfs in Docker); compose keeps the root fs read-only with a
    tmpfs /tmp, and the healthcheck is the same script as the Dockerfile's."""
    compose = (REPO / "docker-compose.yml").read_text()
    web = compose[compose.index("\n  web:"):compose.index("\n  redis:")]
    assert "read_only: true" in web and "tmpfs:\n      - /tmp" in web
    assert '["CMD", "python", "/app/docker/healthcheck.py"]' in web
    # SSO_DBHOST=host.docker.internal works with Docker Engine on Linux/WSL too
    assert 'extra_hosts:\n      - "host.docker.internal:host-gateway"' in web
    assert 'CMD ["python", "/app/docker/healthcheck.py"]' in (REPO / "Dockerfile").read_text()
    args = _cmd_args()
    assert args[args.index("--worker-tmp-dir") + 1] == "/dev/shm"
