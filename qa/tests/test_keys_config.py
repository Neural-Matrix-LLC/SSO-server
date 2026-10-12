"""KEYCFG-xx / KEYROT-xx: JWT key configuration after 610c9b8 / d784f10 (feat/app-permissions).

New form: SSO_JWT_PRIVATE_KEY (file name) and SSO_JWT_PUBLIC_KEYS (comma-separated file names), resolved in
mount = SSO_JWT_KEYS_MOUNT > SSO_KEYS_DIR > /run/keys. A value containing '/' is a path (absolute, or relative to
the working directory). Old *_PATH variables: deprecated (sso.W001 + one log line per process); old + new form of
the same setting -> ImproperlyConfigured (also with SSO_DEBUG=True).

Settings are loaded in a fresh interpreter of the SERVER's venv (QA_SSO_PYTHON, default qa/.venv-py3.13.16) with a
minimal environment (SSO_ENV_FILE='' so no .env is read). KEYROT starts throw-away gunicorn processes on a dedicated
port (QA_KEYS_PORT, default 8050) and stops them by their own process group (PID), never by name or port.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

pytestmark = pytest.mark.keys

REPO = Path(os.environ.get("SSO_REPO_DIR", Path(__file__).resolve().parents[2]))
PY = os.environ.get("QA_SSO_PYTHON", str(REPO / "qa" / ".venv-py3.13.16" / "bin" / "python"))
PORT = int(os.environ.get("QA_KEYS_PORT", "8050"))
KEY_VARS = ("SSO_JWT_KEYS_MOUNT", "SSO_KEYS_DIR", "SSO_JWT_PRIVATE_KEY", "SSO_JWT_PUBLIC_KEYS",
            "SSO_JWT_PRIVATE_KEY_PATH", "SSO_JWT_PUBLIC_KEY_PATHS", "SSO_JWT_PUBLIC_KEY_PATH")


# ---------------------------------------------------------------- helpers
def _pair(directory: Path, name: str) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv, pub = directory / f"{name}.private.pem", directory / f"{name}.public.pem"
    priv.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    pub.write_bytes(k.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(priv, 0o600)
    return priv, pub


def _kid(pub: Path) -> str:
    """kid = first 16 hex chars of sha256(DER SubjectPublicKeyInfo) (spec §5.3, JWKS-04)."""
    import hashlib
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(pub.read_bytes())
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


@pytest.fixture(scope="module")
def keydir(tmp_path_factory):
    """mount/ with keys a, b, c; outside/ (sibling of mount) with key 'outside'; host/ (a stand-in SSO_KEYS_DIR)."""
    root = tmp_path_factory.mktemp("keys")
    mount, outside, host = root / "mount", root / "outside", root / "host"
    for d in (mount, outside, host):
        d.mkdir()
    keys = {n: _pair(mount, n) for n in ("a", "b", "c")}
    keys["outside"] = _pair(outside, "outside")
    keys["host"] = _pair(host, "host")
    (mount / "sub").mkdir()
    keys["sub"] = _pair(mount / "sub", "sub")
    return {"root": root, "mount": mount, "outside": outside, "host": host, "keys": keys}


def _base_env(tmp: Path, **over) -> dict:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp), "PYTHONDONTWRITEBYTECODE": "1",
           "SSO_ENV_FILE": "", "SSO_DEBUG": "False",
           "SSO_SECRET_KEY": "Zq3-vT8_pL1xN6rW0yK4bF7mC2hJ9sD5gA8eR1uI3oP6tY0wQ4zX7cV2nB5mL8k",
           "SSO_ISSUER": "https://sso.qa.test", "SSO_ALLOWED_HOSTS": "127.0.0.1,localhost",
           "SSO_DB_ENGINE": "sqlite", "SSO_SQLITE_PATH": str(tmp / "qa-keys.sqlite3"),
           "SSO_CACHE_URL": f"filecache://{tmp}/cache", "SSO_SSL_REDIRECT": "False", "SSO_HSTS_SECONDS": "0",
           "SSO_NUM_PROXIES": "0", "SSO_CORS_ALLOWED_ORIGINS": "https://example.com"}
    env.update({k: v for k, v in over.items() if v is not None})
    return env


_PROBE = r"""
import json, logging, os, sys
sys.path.insert(0, os.getcwd() if os.path.isfile("manage.py") else os.environ["QA_REPO"])
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ssoproject.settings")
try:
    import django
    django.setup()
    from django.conf import settings as s
except Exception as exc:
    print(json.dumps({"error": type(exc).__name__, "msg": str(exc)}))
    sys.exit(0)
c = s.SSO_KEY_CONFIG
print(json.dumps({"mount": c.mount, "mount_source": c.mount_source, "private": c.private.path,
                  "private_origin": c.private.origin, "publics": [k.path for k in c.publics],
                  "deprecated": list(c.deprecated), "kids": [pk.kid for pk in s.SSO_KEYSET.public_keys],
                  "signing_kid": s.SSO_KEYSET.signing_kid, "debug": s.DEBUG}))
"""


def _probe(tmp: Path, cwd: Path | None = None, **env) -> dict:
    e = _base_env(tmp, QA_REPO=str(REPO), **env)
    p = subprocess.run([PY, "-c", _PROBE], cwd=str(cwd or REPO), env=e, capture_output=True, text=True, timeout=90)
    lines = [ln for ln in p.stdout.splitlines() if ln.startswith("{")]
    assert lines, (p.returncode, p.stdout[-800:], p.stderr[-2000:])
    out = json.loads(lines[-1])
    out["_stderr"] = p.stderr + p.stdout   # LOGGING writes to stdout (settings.LOGGING console handler)
    return out


def _manage(tmp: Path, *args, **env) -> subprocess.CompletedProcess:
    return subprocess.run([PY, "manage.py", *args], cwd=str(REPO), env=_base_env(tmp, **env),
                          capture_output=True, text=True, timeout=120)


def _keyset_kids(tmp, **env):
    """kids actually published (JWKS) and the signing kid, from the server's own keyset object."""
    code = ("import json,os,sys,django; sys.path.insert(0, os.environ['QA_REPO']); "
            "os.environ.setdefault('DJANGO_SETTINGS_MODULE','ssoproject.settings'); django.setup(); "
            "from django.conf import settings as s; ks=s.SSO_KEYSET; "
            "print(json.dumps({'signing': ks.signing_kid, 'kids': [pk.kid for pk in ks.public_keys]}))")
    p = subprocess.run([PY, "-c", code], cwd=str(REPO), env=_base_env(tmp, QA_REPO=str(REPO), **env),
                       capture_output=True, text=True, timeout=90)
    assert p.returncode == 0, p.stderr[-1500:]
    return json.loads(p.stdout.strip().splitlines()[-1])


# ================================================================ resolution
def test_KEYCFG_01_bare_private_name_resolves_under_mount(keydir, tmp_path):
    m = keydir["mount"]
    out = _probe(tmp_path, SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY="a.private.pem",
                 SSO_JWT_PUBLIC_KEYS="a.public.pem")
    assert "error" not in out, out
    assert out["mount"] == str(m) and out["mount_source"] == "SSO_JWT_KEYS_MOUNT"
    assert out["private"] == str(m / "a.private.pem")
    assert out["deprecated"] == []
    assert "W001" not in out["_stderr"] and "is deprecated" not in out["_stderr"]


@pytest.mark.parametrize("raw", ["a.public.pem,b.public.pem,c.public.pem", " a.public.pem , b.public.pem,,c.public.pem ,"])
def test_KEYCFG_02_multi_entry_public_list(keydir, tmp_path, raw):
    """Comma list (spaces and empty entries tolerated): every entry resolved under the mount, in order, and every
    key published in JWKS (plus the signing key's own public key, which is a)."""
    m, k = keydir["mount"], keydir["keys"]
    out = _probe(tmp_path, SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY="a.private.pem", SSO_JWT_PUBLIC_KEYS=raw)
    assert "error" not in out, out
    assert out["publics"] == [str(m / f"{n}.public.pem") for n in "abc"]
    kids = _keyset_kids(tmp_path, SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY="a.private.pem",
                        SSO_JWT_PUBLIC_KEYS=raw)["kids"]
    assert sorted(kids) == sorted({_kid(k[n][1]) for n in "abc"}), kids


def test_KEYCFG_02b_signing_key_public_always_published(keydir, tmp_path):
    m, k = keydir["mount"], keydir["keys"]
    kids = _keyset_kids(tmp_path, SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY="a.private.pem",
                        SSO_JWT_PUBLIC_KEYS="b.public.pem")["kids"]
    assert set(kids) == {_kid(k["a"][1]), _kid(k["b"][1])}, kids


@pytest.mark.parametrize("case", ["mount_wins", "keys_dir_only", "default"])
def test_KEYCFG_03_mount_precedence(keydir, tmp_path, case):
    m, h = keydir["mount"], keydir["host"]
    if case == "mount_wins":
        out = _probe(tmp_path, SSO_JWT_KEYS_MOUNT=str(m), SSO_KEYS_DIR=str(h), SSO_JWT_PRIVATE_KEY="a.private.pem",
                     SSO_JWT_PUBLIC_KEYS="a.public.pem")
        assert out["mount_source"] == "SSO_JWT_KEYS_MOUNT" and out["private"] == str(m / "a.private.pem"), out
    elif case == "keys_dir_only":
        out = _probe(tmp_path, SSO_KEYS_DIR=str(h), SSO_JWT_PRIVATE_KEY="host.private.pem",
                     SSO_JWT_PUBLIC_KEYS="host.public.pem")
        assert out["mount_source"] == "SSO_KEYS_DIR" and out["private"] == str(h / "host.private.pem"), out
    else:
        out = _probe(tmp_path, SSO_JWT_PRIVATE_KEY="qa-nonexistent.private.pem", SSO_JWT_PUBLIC_KEYS="x.pem")
        assert out.get("error") == "ImproperlyConfigured", out
        assert "/run/keys/qa-nonexistent.private.pem" in out["msg"] and "default mount" in out["msg"], out["msg"]


def test_KEYCFG_03b_relative_keys_dir_is_relative_to_cwd(keydir, tmp_path):
    """SSO_KEYS_DIR=./keys (the .env.example value) outside Docker: relative to the working directory."""
    root = keydir["root"]
    out = _probe(tmp_path, cwd=REPO, SSO_KEYS_DIR=os.path.relpath(keydir["host"], REPO),
                 SSO_JWT_PRIVATE_KEY="host.private.pem", SSO_JWT_PUBLIC_KEYS="host.public.pem")
    assert out.get("private") == str(keydir["host"] / "host.private.pem"), out
    assert root  # (fixture kept alive)


# ================================================================ path passthrough
def test_KEYCFG_04_absolute_paths_used_as_given(keydir, tmp_path):
    """Absolute paths bypass the mount (private, and mixed with bare names in the public list)."""
    m, o = keydir["mount"], keydir["outside"]
    out = _probe(tmp_path, SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY=str(o / "outside.private.pem"),
                 SSO_JWT_PUBLIC_KEYS=f"a.public.pem,{o / 'outside.public.pem'}")
    assert "error" not in out, out
    assert out["private"] == str(o / "outside.private.pem")
    assert out["publics"] == [str(m / "a.public.pem"), str(o / "outside.public.pem")]
    assert "is a path" in out["private_origin"], out["private_origin"]


def test_KEYCFG_05_relative_path_with_slash_is_relative_to_cwd_not_mount(keydir, tmp_path):
    """'sub/sub.private.pem' contains '/', so it is a path relative to the WORKING DIRECTORY, not to the mount.
    With cwd = repo it does not find mount/sub/...; with cwd = mount it does. Documented in README §3 / .env.example
    ('A value containing / is a path'), but easy to misread: recorded."""
    m = keydir["mount"]
    env = dict(SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY="sub/sub.private.pem", SSO_JWT_PUBLIC_KEYS="a.public.pem")
    from_repo = _probe(tmp_path, cwd=REPO, **env)
    assert from_repo.get("error") == "ImproperlyConfigured", from_repo
    assert str(REPO / "sub" / "sub.private.pem") in from_repo["msg"], from_repo["msg"]
    assert "relative to the working directory" in from_repo["msg"], from_repo["msg"]
    from_mount = _probe(tmp_path, cwd=m, **env)
    assert from_mount.get("private") == str(m / "sub" / "sub.private.pem"), from_mount


# ================================================================ deprecated *_PATH
OLD_FORMS = {
    "SSO_JWT_PRIVATE_KEY_PATH": lambda k: {"SSO_JWT_PRIVATE_KEY_PATH": str(k["a"][0]),
                                           "SSO_JWT_PUBLIC_KEYS": "a.public.pem"},
    "SSO_JWT_PUBLIC_KEY_PATHS": lambda k: {"SSO_JWT_PRIVATE_KEY": "a.private.pem",
                                           "SSO_JWT_PUBLIC_KEY_PATHS": f"{k['a'][1]},{k['b'][1]}"},
    "SSO_JWT_PUBLIC_KEY_PATH": lambda k: {"SSO_JWT_PRIVATE_KEY": "a.private.pem",
                                          "SSO_JWT_PUBLIC_KEY_PATH": str(k["b"][1])},
}


@pytest.mark.parametrize("old", list(OLD_FORMS))
def test_KEYCFG_06_deprecated_var_gives_W001_in_manage_check(keydir, tmp_path, old):
    env = OLD_FORMS[old](keydir["keys"]) | {"SSO_JWT_KEYS_MOUNT": str(keydir["mount"])}
    p = _manage(tmp_path, "check", **env)
    out = p.stdout + p.stderr
    assert p.returncode == 0, out[-1500:]       # a warning, not an error
    assert "sso.W001" in out and f"{old} is deprecated" in out, out[-1500:]
    replacement = "SSO_JWT_PRIVATE_KEY" if "PRIVATE" in old else "SSO_JWT_PUBLIC_KEYS"
    assert f"use {replacement}" in out


def test_KEYCFG_06b_all_old_vars_still_work(keydir, tmp_path):
    k = keydir["keys"]
    out = _probe(tmp_path, SSO_JWT_PRIVATE_KEY_PATH=str(k["a"][0]),
                 SSO_JWT_PUBLIC_KEY_PATHS=f"{k['a'][1]},{k['b'][1]}")
    assert "error" not in out, out
    assert out["private"] == str(k["a"][0]) and out["publics"] == [str(k["a"][1]), str(k["b"][1])]
    assert out["deprecated"] == ["SSO_JWT_PRIVATE_KEY_PATH", "SSO_JWT_PUBLIC_KEY_PATHS"]
    # one log line per deprecated variable per process (gunicorn runs no system checks)
    assert out["_stderr"].count("is deprecated") == 2, out["_stderr"][-800:]


def test_KEYCFG_06c_new_form_no_W001_and_empty_old_vars_ignored(keydir, tmp_path):
    """.env.example ships the old variables EMPTY next to the new ones: that is neither a conflict nor a W001."""
    p = _manage(tmp_path, "check", SSO_JWT_KEYS_MOUNT=str(keydir["mount"]), SSO_JWT_PRIVATE_KEY="a.private.pem",
                SSO_JWT_PUBLIC_KEYS="a.public.pem", SSO_JWT_PRIVATE_KEY_PATH="", SSO_JWT_PUBLIC_KEY_PATHS=" ")
    out = p.stdout + p.stderr
    assert p.returncode == 0 and "W001" not in out and "deprecated" not in out, out[-1000:]


CONFLICTS = [("SSO_JWT_PRIVATE_KEY", "SSO_JWT_PRIVATE_KEY_PATH"), ("SSO_JWT_PUBLIC_KEYS", "SSO_JWT_PUBLIC_KEY_PATHS"),
             ("SSO_JWT_PUBLIC_KEYS", "SSO_JWT_PUBLIC_KEY_PATH")]


@pytest.mark.parametrize("debug", ["False", "True"])
@pytest.mark.parametrize("new,old", CONFLICTS, ids=[f"{n}+{o}" for n, o in CONFLICTS])
def test_KEYCFG_07_old_and_new_together_improperly_configured(keydir, tmp_path, new, old, debug):
    k = keydir["keys"]
    env = {"SSO_DEBUG": debug, "SSO_JWT_KEYS_MOUNT": str(keydir["mount"]),
           "SSO_JWT_PRIVATE_KEY": "a.private.pem", "SSO_JWT_PUBLIC_KEYS": "a.public.pem",
           old: str(k["a"][0] if "PRIVATE" in old else k["a"][1])}
    out = _probe(tmp_path, **env)
    assert out.get("error") == "ImproperlyConfigured", out
    assert new in out["msg"] and old in out["msg"], out["msg"]
    assert "BEGIN" not in out["msg"]


# ================================================================ errors
@pytest.mark.parametrize("which", ["private", "public"])
def test_KEYCFG_08_missing_file_clear_error(keydir, tmp_path, which):
    m = keydir["mount"]
    env = {"SSO_JWT_KEYS_MOUNT": str(m), "SSO_JWT_PRIVATE_KEY": "a.private.pem", "SSO_JWT_PUBLIC_KEYS": "a.public.pem"}
    env["SSO_JWT_PRIVATE_KEY" if which == "private" else "SSO_JWT_PUBLIC_KEYS"] = "qa-missing.pem"
    out = _probe(tmp_path, **env)
    assert out.get("error") == "ImproperlyConfigured", out
    msg = out["msg"]
    var = "SSO_JWT_PRIVATE_KEY" if which == "private" else "SSO_JWT_PUBLIC_KEYS"
    assert str(m / "qa-missing.pem") in msg and var in msg and "SSO_JWT_KEYS_MOUNT" in msg, msg
    assert re.search(r"not found|does not exist|No such file", msg, re.I), msg
    assert "Traceback" not in msg


def test_KEYCFG_08b_unset_private_key(tmp_path):
    out = _probe(tmp_path)
    assert out.get("error") == "ImproperlyConfigured" and "SSO_JWT_PRIVATE_KEY" in out["msg"], out


def test_KEYCFG_08c_debug_missing_key_falls_back_to_ephemeral(keydir, tmp_path):
    out = _probe(tmp_path, SSO_DEBUG="True", SSO_JWT_KEYS_MOUNT=str(keydir["mount"]),
                 SSO_JWT_PRIVATE_KEY="qa-missing.pem", SSO_JWT_PUBLIC_KEYS="")
    assert "error" not in out and out["debug"] is True, out


# ================================================================ traversal
@pytest.mark.parametrize("value,expect", [
    ("../outside/outside.private.pem", "escapes"),   # contains '/': a path relative to cwd
    ("..", "error"),                                  # bare name: mount/.. is a directory
    ("..%2Foutside.private.pem", "error"),            # no decoding: literal file name in the mount
    ("..\\outside.private.pem", "error"),             # backslash is not a separator on POSIX
])
def test_KEYCFG_09_traversal_in_names(keydir, tmp_path, value, expect):
    """A bare name cannot leave the mount (no '/' -> joined to the mount). '../x' contains '/', so by the documented
    rule it is a PATH relative to the working directory: with cwd = mount it reaches mount/../outside, i.e. outside
    the mount. Operator-controlled config only (env), so no privilege boundary is crossed; flagged Info."""
    m = keydir["mount"]
    out = _probe(tmp_path, cwd=m, SSO_JWT_KEYS_MOUNT=str(m), SSO_JWT_PRIVATE_KEY=value, SSO_JWT_PUBLIC_KEYS="a.public.pem")
    if expect == "escapes":
        assert out.get("private") == str(keydir["outside"] / "outside.private.pem"), out
        assert not out["private"].startswith(str(m) + os.sep)
        print("KEYCFG-09 '../x' resolves OUTSIDE the mount:", out["private"])
    else:
        assert out.get("error") == "ImproperlyConfigured", out
        assert "Traceback" not in out["msg"]
        assert str(m) in out["msg"], out["msg"]


# ================================================================ compose / examples (static)
def _read(rel):
    return (REPO / rel).read_text()


def test_KEYCFG_10_compose_mounts_keys_dir_ro_with_matching_env():
    compose = _read("docker-compose.yml")
    web = compose[compose.index("\n  web:"):compose.index("\n  redis:")]
    assert re.search(r"^\s+- \$\{SSO_KEYS_DIR:-\./keys\}:/run/keys:ro\s*$", web, re.M), "SSO_KEYS_DIR -> /run/keys:ro"
    pinned = re.search(r"^\s+SSO_JWT_KEYS_MOUNT:\s*(\S+)\s*$", web, re.M)
    assert pinned and pinned.group(1) == "/run/keys", "web must pin SSO_JWT_KEYS_MOUNT=/run/keys (literal)"
    assert "${SSO_JWT_KEYS_MOUNT" not in web, "the pin must not be overridable from .env"
    assert not re.search(r"SSO_JWT_\w*_PATH", web), "compose must not use the deprecated *_PATH variables"
    # every compose file that runs the app mounts the same way
    for rel in ("docker-compose.dev.yml", "docker-compose.test.yml"):
        t = _read(rel)
        assert "_KEY_PATH" not in t, rel


def test_KEYCFG_10b_env_example_through_compose_resolves_to_run_keys(tmp_path):
    """.env.example as env_file + compose's environment pin -> resolve_key_config gives /run/keys/<name>, no
    conflict, no deprecation (pure function, run in the server venv)."""
    env = {}
    for line in _read(".env.example").splitlines():
        m = re.match(r"^\s*([A-Z0-9_]+)=(.*)$", line)
        if m:
            env[m.group(1)] = m.group(2).split(" #")[0].strip()
    env["SSO_JWT_KEYS_MOUNT"] = "/run/keys"
    code = ("import json,os,sys; sys.path.insert(0, os.environ['QA_REPO']); from sso.keys import resolve_key_config; "
            "c = resolve_key_config(json.loads(sys.argv[1])); "
            "print(json.dumps([c.private.path, [k.path for k in c.publics], c.mount_source, list(c.deprecated)]))")
    p = subprocess.run([PY, "-c", code, json.dumps(env)], cwd=str(REPO), capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"], "QA_REPO": str(REPO)}, timeout=60)
    assert p.returncode == 0, p.stderr[-1500:]
    private, publics, source, deprecated = json.loads(p.stdout)
    assert private == f"/run/keys/{env['SSO_JWT_PRIVATE_KEY']}" and private.endswith(".private.pem")
    assert publics and all(x.startswith("/run/keys/") for x in publics)
    assert source == "SSO_JWT_KEYS_MOUNT" and deprecated == []
    assert env.get("SSO_KEYS_DIR") == "./keys"


def test_KEYCFG_10c_examples_and_gen_keys_use_new_names():
    for rel in (".env.example", ".env.dev.example"):
        t = _read(rel)
        assert re.search(r"^SSO_JWT_PRIVATE_KEY=\S+\.private\.pem$", t, re.M), rel
        assert re.search(r"^SSO_JWT_PUBLIC_KEYS=\S+\.public\.pem", t, re.M), rel
        assert not re.search(r"^SSO_JWT_\w+_PATHS?=\S", t, re.M), f"{rel}: old *_PATH set to a value"
    g = _read("scripts/gen_keys.sh")
    assert "SSO_JWT_PRIVATE_KEY=$NAME.private.pem" in g and "SSO_JWT_PUBLIC_KEYS=$NAME.public.pem" in g


def test_KEYCFG_10d_env_example_duplicate_keys():
    """Recorded: duplicate assignments in .env.example (compose/env_file keep the LAST one)."""
    names = re.findall(r"^\s*([A-Z0-9_]+)=", _read(".env.example"), re.M)
    dups = sorted({n for n in names if names.count(n) > 1})
    print("KEYCFG-10d duplicates in .env.example:", dups)
    assert "SSO_JWT_PRIVATE_KEY" not in dups and "SSO_JWT_PUBLIC_KEYS" not in dups, dups


# ================================================================ live: JWKS + rotation with the new variables
def _start(tmp: Path, name: str, **env) -> tuple[subprocess.Popen, Path]:
    gunicorn = str(Path(PY).with_name("gunicorn"))
    log = tmp / f"{name}.log"
    fh = open(log, "w")
    p = subprocess.Popen([gunicorn, "ssoproject.wsgi:application", "-b", f"127.0.0.1:{PORT}", "--workers", "1",
                          "--access-logfile", "-", "--error-logfile", "-"], cwd=str(REPO),
                         env=_base_env(tmp, SSO_ISSUER=f"http://127.0.0.1:{PORT}", **env),
                         stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
    (tmp / f"{name}.pid").write_text(str(p.pid))
    for _ in range(120):
        if p.poll() is not None:
            raise AssertionError(f"{name} exited {p.returncode}: {log.read_text()[-2000:]}")
        try:
            if requests.get(f"http://127.0.0.1:{PORT}/healthz", timeout=1).status_code == 200:
                return p, log
        except requests.RequestException:
            pass
        time.sleep(0.5)
    _stop(p)
    raise AssertionError(f"{name} did not come up: {log.read_text()[-2000:]}")


def _stop(p: subprocess.Popen) -> None:
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)  # our own process group (start_new_session), by PID
        try:
            p.wait(15)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(5)


@pytest.fixture(scope="module")
def live_db(tmp_path_factory):
    """Throw-away SQLite DB: migrate + one QA user (qa_keys_user)."""
    if subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{PORT}"], capture_output=True).returncode == 0:
        pytest.skip(f"port {PORT} busy")
    tmp = tmp_path_factory.mktemp("live")
    keys = {n: _pair(tmp, n) for n in ("k1", "k2")}
    env = dict(SSO_JWT_KEYS_MOUNT=str(tmp), SSO_JWT_PRIVATE_KEY="k1.private.pem", SSO_JWT_PUBLIC_KEYS="k1.public.pem")
    assert _manage(tmp, "migrate", "--noinput", **env).returncode == 0
    code = ("from django.contrib.auth.models import User; "
            "User.objects.filter(username='qa_keys_user').delete(); "
            "User.objects.create_user('qa_keys_user', password='QaKeys-Passw0rd!x')")
    p = _manage(tmp, "shell", "-c", code, **env)
    assert p.returncode == 0, p.stderr[-1000:]
    return tmp, keys


def _login(base):
    r = requests.post(f"{base}/api/v1/auth/login", json={"username": "qa_keys_user", "password": "QaKeys-Passw0rd!x",
                                                         "client": "native"}, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()


def _verify(base, token):
    import jwt
    jwks = requests.get(f"{base}/.well-known/jwks.json", timeout=10).json()
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    assert jwk, f"kid {kid} not published"
    key = jwt.PyJWK(jwk).key
    jwt.decode(token, key, algorithms=["RS256"], audience="myfin-services", issuer=base)
    return kid, [k["kid"] for k in jwks["keys"]]


def test_KEYROT_01_rotation_with_new_variables(live_db):
    """Rotation per README §4 with the new names: T0 sign k1, publish k1; T1 publish k1,k2 (append); T2 sign k2,
    publish k1,k2: old k1 tokens still verify; T3 retire k1: only k2 published."""
    tmp, keys = live_db
    base = f"http://127.0.0.1:{PORT}"
    kid1, kid2 = _kid(keys["k1"][1]), _kid(keys["k2"][1])
    common = dict(SSO_JWT_KEYS_MOUNT=str(tmp))
    steps = [("t0", "k1.private.pem", "k1.public.pem", kid1, {kid1}),
             ("t1", "k1.private.pem", "k1.public.pem,k2.public.pem", kid1, {kid1, kid2}),
             ("t2", "k2.private.pem", "k1.public.pem,k2.public.pem", kid2, {kid1, kid2}),
             ("t3", "k2.private.pem", "k2.public.pem", kid2, {kid2})]
    old_token = None
    for name, priv, pubs, sign_kid, published in steps:
        p, log = _start(tmp, name, SSO_JWT_PRIVATE_KEY=priv, SSO_JWT_PUBLIC_KEYS=pubs, **common)
        try:
            tok = _login(base)["access_token"]
            kid, kids = _verify(base, tok)
            assert kid == sign_kid and set(kids) == published, (name, kid, kids)
            if name == "t1":
                old_token = tok
            if name == "t2":
                assert _verify(base, old_token)[0] == kid1, "k1 token must still verify after the switch"
            if name == "t3":
                jw = requests.get(f"{base}/.well-known/jwks.json", timeout=10).json()
                assert kid1 not in [k["kid"] for k in jw["keys"]]
            assert "deprecated" not in log.read_text()
        finally:
            _stop(p)


def test_KEYROT_02_deprecated_vars_still_serve_and_log_once(live_db):
    tmp, keys = live_db
    base = f"http://127.0.0.1:{PORT}"
    p, log = _start(tmp, "old", SSO_JWT_PRIVATE_KEY_PATH=str(keys["k1"][0]), SSO_JWT_PUBLIC_KEY_PATHS=str(keys["k1"][1]))
    try:
        kid, _ = _verify(base, _login(base)["access_token"])
        assert kid == _kid(keys["k1"][1])
        text = log.read_text()
        assert text.count("SSO_JWT_PRIVATE_KEY_PATH is deprecated") == 1, text[-1500:]
        assert text.count("SSO_JWT_PUBLIC_KEY_PATHS is deprecated") == 1, text[-1500:]
    finally:
        _stop(p)


def test_KEYROT_03_conflict_refuses_to_start(live_db):
    tmp, keys = live_db
    gunicorn = str(Path(PY).with_name("gunicorn"))
    p = subprocess.run([gunicorn, "ssoproject.wsgi:application", "-b", f"127.0.0.1:{PORT}", "--workers", "1"],
                       cwd=str(REPO), capture_output=True, text=True, timeout=60,
                       env=_base_env(tmp, SSO_JWT_KEYS_MOUNT=str(tmp), SSO_JWT_PRIVATE_KEY="k1.private.pem",
                                     SSO_JWT_PUBLIC_KEYS="k1.public.pem",
                                     SSO_JWT_PRIVATE_KEY_PATH=str(keys["k1"][0])),
                       start_new_session=True)
    assert p.returncode != 0
    assert "ImproperlyConfigured" in p.stdout + p.stderr and "SSO_JWT_PRIVATE_KEY_PATH" in p.stdout + p.stderr
