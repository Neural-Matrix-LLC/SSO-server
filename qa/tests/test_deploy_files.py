"""DEPLOY-xx: phase-3 deployment files and examples exist and match spec 9.4/9.5 + addendum
A/B3/B6/B12 (static checks of the repo, no server needed)."""
import glob
import os
import re
import subprocess

import pytest

pytestmark = pytest.mark.static


@pytest.fixture(scope="module")
def repo(cfg):
    return cfg.repo_dir


def _find(repo, pattern):
    return [p for p in glob.glob(os.path.join(repo, "**", pattern), recursive=True)
            if "/qa/" not in p and "/.venv/" not in p and "/node_modules/" not in p]


@pytest.mark.parametrize("rel", ["Dockerfile", "docker-compose.yml", ".env.example", "README.md",
                                 "scripts/gen_keys.sh", "examples/frontend/index.html", "manage.py"])
def test_DEPLOY_01_required_files(repo, rel):
    assert os.path.isfile(os.path.join(repo, rel)), f"missing {rel}"


def test_DEPLOY_01b_nginx_conf_and_verifier_package(repo):
    assert _find(repo, "nginx.conf"), "nginx.conf missing"
    assert os.path.isdir(os.path.join(repo, "examples", "verifier")), "examples/verifier/ missing"


def test_DEPLOY_02_env_example_lists_all_settings(repo):
    text = open(os.path.join(repo, ".env.example")).read()
    required = ["SSO_SECRET_KEY", "SSO_DEBUG", "SSO_ALLOWED_HOSTS", "SSO_DBHOST", "SSO_DBPORT", "SSO_DBUSER",
                "SSO_DBPWD", "SSO_ISSUER", "SSO_AUDIENCE", "SSO_JWT_PRIVATE_KEY_PATH", "SSO_JWT_PUBLIC_KEY_PATHS",
                "SSO_ACCESS_TTL_MIN", "SSO_REFRESH_TTL_DAYS", "SSO_CORS_ALLOWED_ORIGINS", "SSO_COOKIE_DOMAIN",
                "SSO_CACHE_URL"]
    missing = [v for v in required if not re.search(rf"^\s*{v}\s*=", text, re.M)]
    assert not missing, f".env.example missing {missing}"
    assert re.search(r"^\s*SSO_DEBUG\s*=\s*False", text, re.M | re.I), "SSO_DEBUG must default to False (B12)"
    assert "PRIVATE KEY" not in text


def test_DEPLOY_03_no_private_keys_tracked(repo):
    p = subprocess.run(["git", "-C", repo, "ls-files"], capture_output=True, text=True)
    tracked = [f for f in p.stdout.splitlines() if not f.startswith("qa/")]
    for f in tracked:
        path = os.path.join(repo, f)
        if os.path.isfile(path) and os.path.getsize(path) < 1_000_000:
            with open(path, "rb") as fh:
                assert b"PRIVATE KEY-----" not in fh.read(), f"private key committed: {f}"
    gi = os.path.join(repo, ".gitignore")
    assert os.path.isfile(gi) and re.search(r"^/?keys/?", open(gi).read(), re.M), "keys/ not gitignored"


def test_DEPLOY_04_frontend_follows_7_1_rules(repo):
    html = open(os.path.join(repo, "examples", "frontend", "index.html")).read()
    js = html + "".join(open(p).read() for p in _find(os.path.join(repo, "examples", "frontend"), "*.js"))
    assert 'credentials: "include"' in js or "credentials:'include'" in js or "credentials: 'include'" in js
    assert "/api/v1/auth/refresh" in js and "/api/v1/auth/login" in js
    assert "localStorage" not in js and "sessionStorage" not in js, "access token must be memory-only"


def test_DEPLOY_05_nginx_forwards_proto_and_host(repo):
    conf = "".join(open(p).read() for p in _find(repo, "nginx.conf"))
    assert re.search(r"proxy_set_header\s+X-Forwarded-Proto", conf)
    assert re.search(r"proxy_set_header\s+Host\s+\$http_host", conf)
    assert re.search(r"listen\s+\S*443\s+ssl", conf)


def test_DEPLOY_06_compose_mounts_keys_readonly(repo):
    compose = open(os.path.join(repo, "docker-compose.yml")).read()
    assert re.search(r"/run/keys:ro", compose), "keys must be mounted read-only at /run/keys"


def test_DEPLOY_07_readme_covers_required_topics(repo):
    readme = open(os.path.join(repo, "README.md")).read().lower()
    for topic in ["mysqldump", "gen_keys", "migrate", "serviceclient", "sso_cache_url", ".env"]:
        assert topic in readme, f"README missing {topic}"


@pytest.mark.needs_manage
def test_DEPLOY_08_no_pending_migrations(manage):
    """Addendum B11: makemigrations --check shows no changes."""
    import shlex
    argv = shlex.split(manage.cmd) + ["makemigrations", "--check", "--dry-run"]
    p = subprocess.run(argv, cwd=manage.cwd, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
