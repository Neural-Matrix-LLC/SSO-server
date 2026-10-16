"""DEPLOY-xx: phase-3 deployment files and examples exist and match spec 9.4/9.5 + addendum
A/B3/B6/B12 (static checks of the repo, no server needed)."""
import glob
import os
import re
import subprocess

import pytest


def _text(path, **kw):
    with open(path, **kw) as fh:
        return fh.read()

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
    text = _text(os.path.join(repo, ".env.example"))
    required = ["SSO_SECRET_KEY", "SSO_DEBUG", "SSO_ALLOWED_HOSTS", "SSO_DBHOST", "SSO_DBPORT", "SSO_DBUSER",
                "SSO_DBPWD", "SSO_ISSUER", "SSO_AUDIENCE",
                # key config @ 610c9b8/d784f10: host folder + file NAMES (resolved in SSO_JWT_KEYS_MOUNT, /run/keys)
                "SSO_KEYS_DIR", "SSO_JWT_PRIVATE_KEY", "SSO_JWT_PUBLIC_KEYS",
                "SSO_ACCESS_TTL_MIN", "SSO_REFRESH_TTL_DAYS", "SSO_CORS_ALLOWED_ORIGINS", "SSO_COOKIE_DOMAIN",
                "SSO_CACHE_URL"]
    missing = [v for v in required if not re.search(rf"^\s*{v}\s*=", text, re.M)]
    assert not missing, f".env.example missing {missing}"
    # names, not paths: no '/' in the values (a '/' would make them paths relative to the working directory)
    for v in ("SSO_JWT_PRIVATE_KEY", "SSO_JWT_PUBLIC_KEYS"):
        val = re.search(rf"^[ \t]*{v}[ \t]*=[ \t]*(\S*)", text, re.M).group(1)
        assert val and "/" not in val, f"{v}={val!r} should be a file name"
    # deprecated *_PATH forms: if listed at all, they must be EMPTY (old + new together = ImproperlyConfigured)
    for v in ("SSO_JWT_PRIVATE_KEY_PATH", "SSO_JWT_PUBLIC_KEY_PATHS", "SSO_JWT_PUBLIC_KEY_PATH"):
        m = re.search(rf"^[ \t]*{v}[ \t]*=[ \t]*(\S*)", text, re.M)
        assert m is None or m.group(1) == "", f"{v} set in .env.example together with the new form"
    assert re.search(r"^\s*SSO_DEBUG\s*=\s*False", text, re.M | re.I), "SSO_DEBUG must default to False (B12)"
    assert "PRIVATE KEY" not in text


def test_DEPLOY_03_no_private_keys_tracked(repo):
    # A real PEM block: the BEGIN line on its own, followed by a base64 line. Docs and CI scripts that only
    # *mention* "-----BEGIN ... PRIVATE KEY-----" (e.g. a grep pattern) are not key material.
    pem = re.compile(rb"^-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{16,}", re.M)
    p = subprocess.run(["git", "-C", repo, "ls-files"], capture_output=True, text=True)
    tracked = [f for f in p.stdout.splitlines() if not f.startswith("qa/")]
    for f in tracked:
        path = os.path.join(repo, f)
        if os.path.isfile(path) and os.path.getsize(path) < 1_000_000:
            with open(path, "rb") as fh:
                assert not pem.search(fh.read()), f"private key committed: {f}"
    gi = os.path.join(repo, ".gitignore")
    assert os.path.isfile(gi) and re.search(r"^/?keys/?", _text(gi), re.M), "keys/ not gitignored"


def test_DEPLOY_04_frontend_follows_7_1_rules(repo):
    html = _text(os.path.join(repo, "examples", "frontend", "index.html"))
    js = html + "".join(_text(p) for p in _find(os.path.join(repo, "examples", "frontend"), "*.js"))
    assert 'credentials: "include"' in js or "credentials:'include'" in js or "credentials: 'include'" in js
    assert "/api/v1/auth/refresh" in js and "/api/v1/auth/login" in js
    assert "localStorage" not in js and "sessionStorage" not in js, "access token must be memory-only"


def test_DEPLOY_05_nginx_forwards_proto_and_host(repo):
    conf = "".join(_text(p) for p in _find(repo, "nginx.conf"))
    assert re.search(r"proxy_set_header\s+X-Forwarded-Proto", conf)
    assert re.search(r"proxy_set_header\s+Host\s+\$http_host", conf)
    assert re.search(r"listen\s+\S*443\s+ssl", conf)


def test_DEPLOY_06_compose_mounts_keys_readonly(repo):
    compose = _text(os.path.join(repo, "docker-compose.yml"))
    assert re.search(r"\$\{SSO_KEYS_DIR:-\./keys\}:/run/keys:ro", compose), "SSO_KEYS_DIR must be mounted ro at /run/keys"
    assert re.search(r"^\s+SSO_JWT_KEYS_MOUNT:\s*/run/keys\s*$", compose, re.M), "web must pin SSO_JWT_KEYS_MOUNT"


def test_DEPLOY_07_readme_covers_required_topics(repo):
    readme = _text(os.path.join(repo, "README.md")).lower()
    for topic in ["mysqldump", "gen_keys", "migrate", "serviceclient", "sso_cache_url", ".env"]:
        assert topic in readme, f"README missing {topic}"


@pytest.mark.needs_manage
def test_DEPLOY_08_no_pending_migrations(manage):
    """Addendum B11: makemigrations --check shows no changes."""
    import shlex
    argv = shlex.split(manage.cmd) + ["makemigrations", "--check", "--dry-run"]
    p = subprocess.run(argv, cwd=manage.cwd, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr


# --------------------------------------------------------------------------------------------------
# Regression @ f22b2e0: image name, non-root uid/gid parameters, MYSQL_IMAGE (8.0 / 8.4), Python 3.13.
# Static only (no Docker): compose files are read as text and their ${...} defaults are resolved with a
# small interpolator that follows compose's rules for ${VAR}, ${VAR:-default} (nested) and ${VAR:?msg}.

def _read(repo, rel):
    return _text(os.path.join(repo, rel))


def _interpolate(s, env):
    """Resolve compose-style ${...} (innermost first). ':-' uses default when unset OR empty."""
    pat = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])([^${}]*))?\}")
    for _ in range(10):
        def sub(m):
            name, op, arg = m.group(1), m.group(2), m.group(3) or ""
            val = env.get(name)
            if op in (":-",):
                return val if val else arg
            if op == "-":
                return arg if val is None else val
            if op in (":?", "?"):
                if not val:
                    raise KeyError(f"{name}: {arg}")
                return val
            return val or ""
        new = pat.sub(sub, s)
        if new == s:
            break
        s = new
    return s


def _service_block(compose_text, service):
    m = re.search(rf"^  {service}:\n((?:    .*\n|\s*\n)+)", compose_text, re.M)
    assert m, f"service {service} not found"
    return m.group(1)


def _yaml_value(block, key):
    m = re.search(rf"^\s+{key}:\s*(.+?)\s*$", block, re.M)
    assert m, f"{key} not found"
    return m.group(1).strip().strip('"').strip("'")


def test_DEPLOY_15_image_name_parameterized(repo):
    compose = _read(repo, "docker-compose.yml")
    image = _yaml_value(_service_block(compose, "web"), "image")
    assert image == "${DOCKER_USER:-thomaschoi}/sso-server:${IMAGE_TAG:-latest}", image
    assert _interpolate(image, {}) == "thomaschoi/sso-server:latest"
    assert _interpolate(image, {"IMAGE_TAG": ""}) == "thomaschoi/sso-server:latest"  # empty -> latest
    assert _interpolate(image, {"DOCKER_USER": "acme", "IMAGE_TAG": "0.1.1"}) == "acme/sso-server:0.1.1"
    env_ex = _read(repo, ".env.example")
    assert re.search(r"^DOCKER_USER=thomaschoi\s*$", env_ex, re.M)
    tag = re.search(r"^IMAGE_TAG=(\S*)\s*$", env_ex, re.M)
    assert tag and tag.group(1) and tag.group(1) != "latest", "servers should pin IMAGE_TAG in .env.example"
    # the old variable is gone from everything shipped (deployment plan replaces SSO_IMAGE_TAG)
    p = subprocess.run(["git", "-C", repo, "ls-files"], capture_output=True, text=True)
    stale = [f for f in p.stdout.splitlines()
             if not f.startswith(("qa/", "devops/")) and os.path.isfile(os.path.join(repo, f))
             and "SSO_IMAGE_TAG" in _text(os.path.join(repo, f), errors="replace")]
    assert not stale, f"SSO_IMAGE_TAG still referenced in {stale}"


def _runtime_stage(dockerfile):
    m = re.search(r"^FROM\s+\S+\s+AS\s+runtime\s*$(.*)", dockerfile, re.M | re.S | re.I)
    assert m, "no runtime stage"
    return m.group(1)


def test_DEPLOY_16_uid_gid_build_args_and_non_root_user(repo):
    df = _read(repo, "Dockerfile")
    rt = _runtime_stage(df)
    # ARGs must be declared inside the runtime stage (an ARG before FROM is not visible after it)
    assert re.search(r"^ARG\s+SSO_UID=10001\s*$", rt, re.M), "ARG SSO_UID=10001 missing in runtime stage"
    assert re.search(r"^ARG\s+SSO_GID=10001\s*$", rt, re.M), "ARG SSO_GID=10001 missing in runtime stage"
    users = re.findall(r"^USER\s+(\S+)", rt, re.M)
    assert users and users[-1] == "${SSO_UID}:${SSO_GID}", f"final USER is {users}"
    assert not any(u.split(":")[0] in ("root", "0") for u in users), users
    assert re.search(r'useradd[^\n]*--uid "\$\{SSO_UID\}" --gid "\$\{SSO_GID\}"', rt), "useradd must use the args"
    assert re.search(r"--shell /usr/sbin/nologin", rt)
    # application code is root-owned (read-only to the runtime user)
    for line in re.findall(r"^COPY\s+(?!--from).*$", rt, re.M):
        if "requirements.lock" in line:
            continue
        assert "--chown=root:root" in line, f"app files should be root-owned: {line}"
    # compose: build args and runtime user come from the same variables with the same defaults
    web = _service_block(_read(repo, "docker-compose.yml"), "web")
    assert re.search(r"SSO_UID:\s*\$\{SSO_UID:-10001\}", web) and re.search(r"SSO_GID:\s*\$\{SSO_GID:-10001\}", web)
    user = _yaml_value(web, "user")
    assert user == "${SSO_UID:-10001}:${SSO_GID:-10001}", user
    assert _interpolate(user, {}) == "10001:10001"
    assert _interpolate(user, {"SSO_UID": "1500", "SSO_GID": "1500"}) == "1500:1500"
    env_ex = _read(repo, ".env.example")
    for v in ("SSO_UID", "SSO_GID"):
        m = re.search(rf"^{v}=(\d+)\s*$", env_ex, re.M)
        assert m and int(m.group(1)) != 0, f"{v} in .env.example"


@pytest.mark.parametrize("uid,gid,ok", [
    ("10001", "10001", True), ("1500", "1500", True), ("1000", "100", True),
    ("0", "10001", False), ("10001", "0", False), ("abc", "10001", False), ("", "10001", False),
    ("10001", "-1", False), ("1e3", "1000", False),
])
def test_DEPLOY_16b_uid_gid_validation_snippet(repo, uid, gid, ok):
    """Runs the Dockerfile's own numeric / non-root validation lines in sh (no Docker needed)."""
    rt = _runtime_stage(_read(repo, "Dockerfile"))
    lines = [l.strip().lstrip("&").strip().rstrip("\\").strip() for l in rt.splitlines()
             if "SSO_UID/SSO_GID must" in l]
    assert len(lines) == 2, lines
    script = "set -e\n" + "\n".join(lines) + "\necho VALID\n"
    p = subprocess.run(["sh", "-c", script], env={"SSO_UID": uid, "SSO_GID": gid, "PATH": os.environ["PATH"]},
                       capture_output=True, text=True)
    assert (p.returncode == 0 and "VALID" in p.stdout) is ok, (p.returncode, p.stdout, p.stderr)


MYSQL_COMPOSE = [("docker-compose.test.yml", "mysql", "SSO_TEST_MYSQL_VOLUME", "sso-test-mysql"),
                 ("docker-compose.dev.yml", "db", "SSO_DEV_MYSQL_VOLUME", "sso-dev-mysql")]


def _documented_mysql_default(repo):
    m = re.search(r"default `mysql:(8\.\d)`", _read(repo, "README.md"))
    assert m, "README does not state the MYSQL_IMAGE default"
    return m.group(1)


@pytest.mark.parametrize("rel,service,volvar,volprefix", MYSQL_COMPOSE)
def test_DEPLOY_17_mysql_image_8_0_and_8_4(repo, rel, service, volvar, volprefix):
    text = _read(repo, rel)
    image = _yaml_value(_service_block(text, service), "image")
    assert "MYSQL_IMAGE" in image, f"{rel}: {service} image not parameterized: {image}"
    default = _documented_mysql_default(repo)
    assert _interpolate(image, {}) == f"mysql:{default}", f"{rel}: default differs from README"
    assert _interpolate(image, {"MYSQL_IMAGE": "mysql:8.4"}) == "mysql:8.4"
    assert _interpolate(image, {"MYSQL_IMAGE": "mysql:8.0"}) == "mysql:8.0"
    assert _interpolate(image, {"QA_MYSQL_TAG": "8.4"}) == "mysql:8.4"
    assert _interpolate(image, {"QA_MYSQL_TAG": "8.0"}) == "mysql:8.0"
    assert _interpolate(image, {"MYSQL_IMAGE": "mysql:8.4.3", "QA_MYSQL_TAG": "8.0"}) == "mysql:8.4.3"  # MYSQL_IMAGE wins
    # one named volume per version, overridable, default matching the default version
    m = re.search(r"^\s+name:\s*(\$\{" + volvar + r":-([^}]+)\})\s*$", text, re.M)
    assert m, f"{rel}: data volume name not parameterized with {volvar}"
    assert m.group(2) == f"{volprefix}-{default}", m.group(2)


def test_DEPLOY_17b_integration_test_expects_the_selected_mysql(repo):
    text = _read(repo, "docker-compose.test.yml")
    image = _yaml_value(_service_block(text, "mysql"), "image")
    expect = re.search(r"SSO_TEST_EXPECT_MYSQL:\s*(\S+)", text)
    assert expect and expect.group(1) == image, "tests must assert the same MySQL the compose file starts"
    it = _read(repo, "sso/tests/test_mysql_integration.py")
    assert "SSO_TEST_EXPECT_MYSQL" in it and "caching_sha2_password" in it
    assert re.search(r"8\.0", it) and re.search(r"8\.4", it), "integration test must accept 8.0 and 8.4"
    init = _read(repo, "docker/mysql-init/01-sso-accounts.sh")
    assert "caching_sha2_password" in init, "init script should set the auth plugin explicitly (8.0 and 8.4)"
    assert "mysql_native_password" not in re.sub(r"#.*", "", init), "SSO accounts must not use mysql_native_password"


def test_DEPLOY_18_python_3_13_everywhere(repo):
    base = "python:3.13.16-slim-trixie"
    df = _read(repo, "Dockerfile")
    assert re.search(rf"^ARG\s+PYTHON_IMAGE={re.escape(base)}\s*$", df, re.M)
    for rel in ("docker/Dockerfile.test", "examples/verifier/Dockerfile"):
        assert re.search(rf"^FROM\s+{re.escape(base)}\b", _read(repo, rel), re.M), rel
    digests = re.findall(r"python:3\.13\.16-slim-trixie@sha256:([0-9a-f]+)", df)
    assert all(len(d) == 64 for d in digests), digests
    p = subprocess.run(["git", "-C", repo, "grep", "-n", "-E", r"python:3\.1[0-2]|python3\.1[0-2]\b", "--",
                        ".", ":!qa", ":!devops"], capture_output=True, text=True)
    assert p.stdout.strip() == "", f"old Python references:\n{p.stdout}"


def test_DEPLOY_19_proxy_and_cache_hardening_still_in_place(repo):
    """Regression guards for defects 4/5 (fixed in 5763f84)."""
    df = _read(repo, "Dockerfile")
    assert "--forwarded-allow-ips '*'" not in df and '--forwarded-allow-ips "*"' not in df
    assert '--forwarded-allow-ips \\"${SSO_FORWARDED_ALLOW_IPS:-127.0.0.1}\\"' in df
    assert re.search(r"SSO_NUM_PROXIES\s*=\s*env\.int\(\"SSO_NUM_PROXIES\",\s*default=0\)",
                     _read(repo, "ssoproject/settings.py"))
    web = _service_block(_read(repo, "docker-compose.yml"), "web")
    # b2ec20e: SSO_NUM_PROXIES (deprecated) replaced by SSO_TRUSTED_PROXIES = the nginx edge network
    assert "SSO_NUM_PROXIES" not in web, "compose must not set the deprecated SSO_NUM_PROXIES"
    assert _interpolate(_yaml_value(web, "SSO_TRUSTED_PROXIES"), {}) == "172.31.250.0/24"
    assert _interpolate(_yaml_value(web, "SSO_CACHE_URL"), {}) == "redis://redis:6379/0"
    assert not re.search(r"^\s+ports:", web, re.M), "web must not be published"
    conf = "".join(_text(p) for p in _find(repo, "nginx.conf"))
    assert re.search(r"proxy_set_header\s+X-Forwarded-For\s+\$remote_addr;", conf), "nginx must overwrite XFF"


# Quick check @ 5666f8b: refuse to run as root with SSO_DEBUG=False (sso/runtime.py, settings.py, sso.E002).
_ROOT_HARNESS = r"""
import os, sys
sys.path.insert(0, os.environ["QA_REPO"])
if os.environ["QA_FAKE_EUID"] != "real":
    os.geteuid = lambda: int(os.environ["QA_FAKE_EUID"])
try:
    import ssoproject.settings as s  # noqa: F401
except Exception as exc:  # ImproperlyConfigured
    print("RAISED", type(exc).__name__, str(exc)[:80])
else:
    print("LOADED DEBUG=%s" % s.DEBUG)
"""


@pytest.mark.parametrize("euid,debug,expect", [
    ("0", "False", "RAISED ImproperlyConfigured Refusing to run as root"),
    ("0", "True", "LOADED DEBUG=True"),
    ("10001", "False", "RAISED ImproperlyConfigured SSO_SECRET_KEY is empty"),  # gets past the root guard
])
def test_DEPLOY_20_settings_refuse_uid0_without_debug(repo, euid, debug, expect):
    """Harness: os.geteuid monkeypatched in a fresh interpreter (no real root needed); minimal env, so a
    non-root non-debug load stops at the next guard (empty secret), which proves the root guard passed."""
    import sys
    env = {"PATH": os.environ["PATH"], "QA_REPO": repo, "QA_FAKE_EUID": euid, "SSO_DEBUG": debug,
           "SSO_ENV_FILE": "", "PYTHONDONTWRITEBYTECODE": "1"}
    p = subprocess.run([sys.executable, "-c", _ROOT_HARNESS], env=env, capture_output=True, text=True,
                       cwd=repo, timeout=60)
    assert expect in p.stdout, (p.stdout, p.stderr[-2000:])


def test_DEPLOY_20b_root_guard_wired_into_settings_and_checks(repo):
    settings = _read(repo, "ssoproject/settings.py")
    guard = re.search(r"^if not DEBUG and running_as_root\(\):\n\s+raise ImproperlyConfigured\(ROOT_MESSAGE\)",
                      settings, re.M)
    assert guard, "settings must raise ImproperlyConfigured when not DEBUG and running as root"
    assert guard.start() < settings.index("SECRET_KEY = "), "root guard should run before the other settings"
    checks = _read(repo, "sso/checks.py")
    assert re.search(r'id="sso\.E002"', checks) and "running_as_root()" in checks
    runtime = _read(repo, "sso/runtime.py")
    assert "geteuid" in runtime
    # images never start as root: final USER is the non-root uid (DEPLOY-16) and the test image too
    assert re.search(r"^USER\s+10001:10001\s*$", _read(repo, "docker/Dockerfile.test"), re.M)
