"""Key loading / kid (spec §5.3, deployment plan R26) and fail-fast settings (addendum B.12)."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sso import keys

REPO = Path(__file__).resolve().parents[2]


def _write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_kid_is_sha256_of_spki_der_first16():
    import hashlib
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    der = k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert keys.compute_kid(k) == hashlib.sha256(der).hexdigest()[:16]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_gen_keys_script_kid_matches_app(tmp_path):
    out = subprocess.run(["bash", str(REPO / "scripts/gen_keys.sh"), str(tmp_path), "testkey", "2048"],
                         capture_output=True, text=True, check=True)
    priv, pub = tmp_path / "testkey.private.pem", tmp_path / "testkey.public.pem"
    assert priv.exists() and pub.exists()
    assert oct(priv.stat().st_mode & 0o777) == "0o600"
    script_kid = [line.split("=", 1)[1] for line in out.stdout.splitlines() if line.startswith("kid=")][0]
    assert script_kid == keys.compute_kid(keys.load_public_key(str(pub)))
    assert script_kid == keys.load_keyset(str(priv), []).signing_kid
    # refuses to overwrite
    again = subprocess.run(["bash", str(REPO / "scripts/gen_keys.sh"), str(tmp_path), "testkey", "2048"],
                           capture_output=True, text=True)
    assert again.returncode != 0 and "exists" in again.stderr


def test_load_errors(tmp_path):
    with pytest.raises(keys.KeyConfigError, match="not found"):
        keys.load_private_key(str(tmp_path / "missing.pem"))
    with pytest.raises(keys.KeyConfigError, match="not found"):
        keys.load_private_key("")
    junk = _write(tmp_path, "junk.pem", b"hello")
    with pytest.raises(keys.KeyConfigError, match="unencrypted PEM"):
        keys.load_private_key(junk)
    with pytest.raises(keys.KeyConfigError, match="PEM public key"):
        keys.load_public_key(junk)
    eck = ec.generate_private_key(ec.SECP256R1())
    ec_priv = _write(tmp_path, "ec.pem", eck.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ec_pub = _write(tmp_path, "ecpub.pem", eck.public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(keys.KeyConfigError, match="not an RSA"):
        keys.load_private_key(ec_priv)
    with pytest.raises(keys.KeyConfigError, match="not an RSA"):
        keys.load_public_key(ec_pub)
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    small_p = _write(tmp_path, "small.pem", small.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(keys.KeyConfigError, match="need >= 2048"):
        keys.load_private_key(small_p)


def test_keyset_dedupes_and_puts_signing_key_first():
    a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ks = keys.build_keyset(a, [b.public_key(), a.public_key(), b.public_key()])
    assert [pk.kid for pk in ks.public_keys] == [keys.compute_kid(a.public_key()), keys.compute_kid(b.public_key())]
    assert ks.by_kid("nope") is None
    assert len(ks.jwks()["keys"]) == 2
    eph = keys.generate_ephemeral_keyset()
    assert len(eph.public_keys) == 1 and eph.signing_public.kid == eph.signing_kid


def _run_settings(env_over: dict) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    env.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
                "SSO_SQLITE_PATH": ":memory:", "PYTHONPATH": str(REPO)})
    env.update(env_over)
    code = "import django; django.setup(); from django.conf import settings; print('KID', settings.SSO_KEYSET.signing_kid)"
    return subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env, capture_output=True, text=True, timeout=60)


GOOD = {
    "SSO_SECRET_KEY": "Zq3-vT8_pL1xN6rW0yK4bF7mC2hJ9sD5gA8eR1uI3oP6tY0wQ4zX7cV2nB5mL8k",
    "SSO_ISSUER": "https://sso.test",
    "SSO_JWT_KEYS_MOUNT": os.environ["SSO_TEST_KEYDIR"],
    "SSO_JWT_PRIVATE_KEY": "current.private.pem",
    "SSO_JWT_PUBLIC_KEYS": "current.public.pem",
    "SSO_CACHE_URL": "redis://127.0.0.1:6379/0",
}
NEW_KEY_VARS = ("SSO_JWT_KEYS_MOUNT", "SSO_JWT_PRIVATE_KEY", "SSO_JWT_PUBLIC_KEYS")


def _old_form(**extra) -> dict:
    """GOOD with the deprecated *_PATH variables instead of the new names."""
    env = {k: v for k, v in GOOD.items() if k not in NEW_KEY_VARS}
    env.update({"SSO_JWT_PRIVATE_KEY_PATH": os.environ["SSO_TEST_CURRENT_PRIVATE"],
                "SSO_JWT_PUBLIC_KEY_PATHS": os.environ["SSO_TEST_CURRENT_PUBLIC"]}, **extra)
    return env


def test_settings_start_with_full_config():
    r = _run_settings(GOOD)
    assert r.returncode == 0, r.stderr
    assert "KID " in r.stdout


@pytest.mark.parametrize("override,message", [
    ({"SSO_SECRET_KEY": ""}, "SSO_SECRET_KEY is empty"),
    ({"SSO_ISSUER": ""}, "SSO_ISSUER is empty"),
    ({"SSO_JWT_PRIVATE_KEY": "missing.private.pem"}, "JWT private key"),
    ({"SSO_JWT_PUBLIC_KEYS": "missing.public.pem"}, "JWT public key"),
    ({"SSO_DB_ENGINE": "postgres"}, "SSO_DB_ENGINE must be"),
])
def test_settings_fail_fast_in_non_debug(override, message):
    r = _run_settings({**GOOD, **override})
    assert r.returncode != 0
    assert "ImproperlyConfigured" in r.stderr and message in r.stderr


def test_debug_mode_falls_back_to_ephemeral_key_and_dev_secret():
    r = _run_settings({"SSO_DEBUG": "True"})
    assert r.returncode == 0, r.stderr
    assert "EPHEMERAL" in r.stderr


def test_singular_public_key_env_still_supported():
    env = _old_form()
    del env["SSO_JWT_PUBLIC_KEY_PATHS"]
    env["SSO_JWT_PUBLIC_KEY_PATH"] = os.environ["SSO_TEST_OLD_PUBLIC"]
    code = ("import django; django.setup(); from django.conf import settings; "
            "print(len(settings.SSO_KEYSET.public_keys))")
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
              "SSO_SQLITE_PATH": ":memory:", **env})
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=e, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == "2"
    assert "SSO_JWT_PUBLIC_KEY_PATH is deprecated" in r.stderr and "deprecated" not in r.stdout


def test_deploy_check_passes_with_prod_like_env():
    """Deployment plan R13 / CI stage 4: check --deploy with SSO_DEBUG=False and a shared cache."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    env.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
                "SSO_SQLITE_PATH": ":memory:", "SSO_ALLOWED_HOSTS": "sso.test",
                "SSO_CACHE_URL": "redis://127.0.0.1:6379/0", **GOOD})
    r = subprocess.run([sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"],
                       cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


def test_per_process_cache_check_is_an_error(settings):
    from sso.checks import per_process_cache_in_production

    settings.DEBUG = False
    for backend in ("django.core.cache.backends.locmem.LocMemCache", "django.core.cache.backends.dummy.DummyCache"):
        settings.CACHES = {"default": {"BACKEND": backend}}
        errors = per_process_cache_in_production(None)
        assert [e.id for e in errors] == ["sso.E001"] and errors[0].is_serious()
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": "redis://x"}}
    assert per_process_cache_in_production(None) == []
    settings.DEBUG = True
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    assert per_process_cache_in_production(None) == []


@pytest.mark.parametrize("cache_url,message", [
    ("", "SSO_CACHE_URL is empty"),
    ("locmemcache://x", "uses the locmem backend"),
    ("dummycache://", "uses the dummy backend"),
])
def test_settings_fail_fast_without_shared_cache(cache_url, message):
    r = _run_settings({**GOOD, "SSO_CACHE_URL": cache_url})
    assert r.returncode != 0
    assert "ImproperlyConfigured" in r.stderr and message in r.stderr


def test_shared_cache_backends_accepted(tmp_path):
    assert _run_settings({**GOOD, "SSO_CACHE_URL": f"filecache://{tmp_path}"}).returncode == 0
    assert _run_settings({**GOOD, "SSO_CACHE_URL": "redis://redis:6379/0"}).returncode == 0
    # debug mode may still use the in-process default
    r = _run_settings({**GOOD, "SSO_CACHE_URL": "", "SSO_DEBUG": "True"})
    assert r.returncode == 0, r.stderr


def test_manage_check_reports_error_for_locmem_override(tmp_path):
    """The Django check (not only the import-time guard) fails when CACHES is overridden afterwards."""
    mod = tmp_path / "override_settings.py"
    mod.write_text("from ssoproject.settings import *\n"
                   "CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    env.update({"DJANGO_SETTINGS_MODULE": "override_settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
                "SSO_SQLITE_PATH": ":memory:", "SSO_ALLOWED_HOSTS": "sso.test",
                "PYTHONPATH": f"{tmp_path}:{REPO}", **GOOD})
    r = subprocess.run([sys.executable, "manage.py", "check"], cwd=REPO, env=env, capture_output=True,
                       text=True, timeout=60)
    assert r.returncode != 0 and "sso.E001" in r.stderr


def test_num_proxies_defaults_to_zero():
    code = ("import django; django.setup(); from rest_framework.settings import api_settings; "
            "print(api_settings.NUM_PROXIES)")
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
              "SSO_SQLITE_PATH": ":memory:", **GOOD})
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=e, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0"


def test_env_file_is_read(tmp_path):
    envfile = tmp_path / "test.env"
    envfile.write_text("\n".join(f"{k}={v}" for k, v in GOOD.items()) + "\nSSO_AUDIENCE=from-env-file\n")
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": str(envfile),
              "SSO_DB_ENGINE": "sqlite", "SSO_SQLITE_PATH": ":memory:"})
    code = "import django; django.setup(); from django.conf import settings; print(settings.SSO_AUDIENCE)"
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=e, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "from-env-file"


def _db_options(extra: dict) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "mysql",
              "SSO_DBHOST": "db.internal", "SSO_DBPORT": "3307", **GOOD, **extra})
    code = ("from django.conf import settings; import json; d = settings.DATABASES['default']; "
            "print(json.dumps({'host': d['HOST'], 'port': d['PORT'], 'options': d['OPTIONS']}))")
    return subprocess.run([sys.executable, "-c", code], cwd=REPO, env=e, capture_output=True, text=True, timeout=60)


def test_mysql_settings_host_port_and_tls_options(tmp_path):
    import json
    r = _db_options({})
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"host": "db.internal", "port": "3307", "options": {"charset": "utf8mb4", "connect_timeout": 3, "read_timeout": 15, "write_timeout": 15}}
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy")
    r = _db_options({"SSO_DB_SSL_CA": str(ca)})
    assert json.loads(r.stdout)["options"] == {"charset": "utf8mb4", "connect_timeout": 3, "read_timeout": 15, "write_timeout": 15, "ssl": {"ca": str(ca)}, "ssl_mode": "VERIFY_CA"}
    r = _db_options({"SSO_DB_SSL_MODE": "required"})
    assert json.loads(r.stdout)["options"]["ssl_mode"] == "REQUIRED"


@pytest.mark.parametrize("extra,message", [
    ({"SSO_DB_SSL_MODE": "sometimes"}, "SSO_DB_SSL_MODE must be one of"),
    ({"SSO_DB_SSL_MODE": "VERIFY_IDENTITY"}, "needs SSO_DB_SSL_CA"),
    ({"SSO_DB_SSL_CA": "/nonexistent/ca.pem"}, "SSO_DB_SSL_CA file not found"),
])
def test_mysql_tls_settings_fail_fast(extra, message):
    r = _db_options(extra)
    assert r.returncode != 0 and message in r.stderr


# ---------------------------------------------------------------- non-root fail-fast (R2)
def _run_as_uid(uid, env_over: dict, code: str = "import django; django.setup(); print('OK')"):
    """Load the real settings in a subprocess whose os.geteuid() returns ``uid`` (None = no geteuid)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    env.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
                "SSO_SQLITE_PATH": ":memory:", "PYTHONPATH": str(REPO)})
    env.update(env_over)
    patch = "import os\n" + ("del os.geteuid\n" if uid is None else f"os.geteuid = lambda: {uid}\n")
    return subprocess.run([sys.executable, "-c", patch + code], cwd=REPO, env=env, capture_output=True,
                          text=True, timeout=60)


def test_root_without_debug_refuses_to_start():
    r = _run_as_uid(0, GOOD)
    assert r.returncode != 0
    assert "ImproperlyConfigured" in r.stderr and "Refusing to run as root (uid 0)" in r.stderr
    assert "SSO_UID" in r.stderr


def test_root_with_debug_is_allowed():
    r = _run_as_uid(0, {**GOOD, "SSO_DEBUG": "True"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().endswith("OK")


@pytest.mark.parametrize("uid", [10001, 1000, None])  # None: platform without os.geteuid (Windows)
def test_non_root_or_no_geteuid_starts(uid):
    r = _run_as_uid(uid, GOOD)
    assert r.returncode == 0, r.stderr


def test_running_as_root_helper(monkeypatch):
    from sso import runtime

    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert runtime.running_as_root() is True
    monkeypatch.setattr(os, "geteuid", lambda: 10001, raising=False)
    assert runtime.running_as_root() is False
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert runtime.running_as_root() is False


def test_root_system_check_is_an_error(settings, monkeypatch):
    from sso.checks import not_root_in_production

    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    settings.DEBUG = False
    errors = not_root_in_production(None)
    assert [e.id for e in errors] == ["sso.E002"] and errors[0].is_serious()
    settings.DEBUG = True
    assert not_root_in_production(None) == []
    settings.DEBUG = False
    monkeypatch.setattr(os, "geteuid", lambda: 10001, raising=False)
    assert not_root_in_production(None) == []


def test_dockerfile_collectstatic_still_works_as_root(tmp_path):
    """The image build runs collectstatic as root (before USER). It uses a throw-away SSO_DEBUG=True config,
    so the root guard must not fire. Run that exact environment as uid 0 into a temp STATIC_ROOT."""
    dockerfile = (REPO / "Dockerfile").read_text()
    step = dockerfile[dockerfile.index("RUN SSO_ENV_FILE="):dockerfile.index("collectstatic")]
    assert "SSO_DEBUG=True" in step and "SSO_DB_ENGINE=sqlite" in step
    assert dockerfile.index("collectstatic") < dockerfile.index("\nUSER ")  # i.e. it does run as root
    (tmp_path / "build_settings.py").write_text(
        f"from ssoproject.settings import *  # noqa\nSTATIC_ROOT = {str(tmp_path / 'static')!r}\n")
    env = {"SSO_DEBUG": "True", "SSO_DB_ENGINE": "sqlite", "SSO_SQLITE_PATH": str(tmp_path / "build.sqlite3"),
           "DJANGO_SETTINGS_MODULE": "build_settings", "PYTHONPATH": f"{tmp_path}:{REPO}"}
    code = ("import warnings; warnings.simplefilter('ignore')\n"
            "from django.core.management import execute_from_command_line\n"
            "execute_from_command_line(['manage.py', 'collectstatic', '--noinput', '-v', '0'])\n")
    r = _run_as_uid(0, env, code)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "static" / "admin").is_dir()


# ---------------------------------------------------------------- missing vs not readable (WSL report)
_as_root = hasattr(os, "geteuid") and os.geteuid() == 0
needs_non_root = pytest.mark.skipif(_as_root, reason="root bypasses file permissions")


def _rsa_pem() -> tuple[bytes, bytes]:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def test_missing_key_file_says_not_found(tmp_path):
    with pytest.raises(keys.KeyConfigError, match=r"not found: .*missing\.pem.*gen_keys\.sh"):
        keys.load_private_key(str(tmp_path / "missing.pem"))
    with pytest.raises(keys.KeyConfigError, match="not found"):
        keys.load_public_key(str(tmp_path / "nodir" / "public.pem"))


def test_readable_key_files_load(tmp_path):
    priv, pub = _rsa_pem()
    p = _write(tmp_path, "private.pem", priv)
    os.chmod(p, 0o600)
    q = _write(tmp_path, "public.pem", pub)
    os.chmod(q, 0o640)
    assert keys.load_private_key(p).key_size == 2048
    assert keys.load_public_key(q).key_size == 2048


@needs_non_root
def test_unreadable_key_file_is_not_reported_as_missing(tmp_path):
    priv, _ = _rsa_pem()
    p = _write(tmp_path, "private.pem", priv)
    os.chmod(p, 0o000)
    try:
        with pytest.raises(keys.KeyConfigError) as info:
            keys.load_private_key(p)
    finally:
        os.chmod(p, 0o600)
    msg = str(info.value)
    assert msg == (f"JWT private key (SSO_JWT_PRIVATE_KEY) {p!r} exists but is not readable by uid "
                   f"{os.geteuid()}; chown to SSO_UID:SSO_GID or set SSO_UID")
    assert "not found" not in msg and "PRIVATE KEY" not in msg and "BEGIN" not in msg


@needs_non_root
def test_key_in_an_unreadable_directory_is_not_reported_as_missing(tmp_path):
    d = tmp_path / "keys"
    d.mkdir()
    priv, pub = _rsa_pem()
    q = _write(d, "public.pem", pub)
    os.chmod(d, 0o000)
    try:
        with pytest.raises(keys.KeyConfigError) as info:
            keys.load_public_key(q)
    finally:
        os.chmod(d, 0o700)
    msg = str(info.value)
    assert "not found" not in msg and "BEGIN" not in msg
    assert f"cannot be reached by uid {os.geteuid()}" in msg and repr(str(d)) in msg
    assert "chown to SSO_UID:SSO_GID or set SSO_UID" in msg


def test_key_path_that_is_a_directory(tmp_path):
    with pytest.raises(keys.KeyConfigError, match="is not a regular file"):
        keys.load_private_key(str(tmp_path))


def test_other_stat_errors_are_reported(tmp_path):
    f = _write(tmp_path, "file", b"x")
    with pytest.raises(keys.KeyConfigError, match="is not readable: .*Not a directory"):
        keys.load_private_key(f + "/private.pem")


# ---------------------------------------------------------------- key names, mount precedence, old variables
KEYDIR = os.environ["SSO_TEST_KEYDIR"]


def _cfg(**env):
    return keys.resolve_key_config(env)


def test_names_resolve_in_the_default_mount():
    c = _cfg(SSO_JWT_PRIVATE_KEY="sso-2026-10.private.pem", SSO_JWT_PUBLIC_KEYS="sso-2026-10.public.pem")
    assert (c.mount, c.mount_source) == ("/run/keys", "default")
    assert c.private.path == "/run/keys/sso-2026-10.private.pem"
    assert [k.path for k in c.publics] == ["/run/keys/sso-2026-10.public.pem"]
    assert c.private.origin == "SSO_JWT_PRIVATE_KEY='sso-2026-10.private.pem' in the default mount '/run/keys'"
    assert c.deprecated == ()


def test_sso_keys_dir_is_the_fallback_mount(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    c = _cfg(SSO_KEYS_DIR="./keys", SSO_JWT_PRIVATE_KEY="a.private.pem")
    assert (c.mount, c.mount_source) == (str(tmp_path / "keys"), "SSO_KEYS_DIR")  # relative -> cwd
    assert c.private.path == str(tmp_path / "keys" / "a.private.pem")
    assert f"in SSO_KEYS_DIR={str(tmp_path / 'keys')!r}" in c.private.origin


def test_explicit_mount_wins_over_sso_keys_dir():
    """The compose pitfall: env_file passes the HOST SSO_KEYS_DIR into the container; compose's environment sets
    SSO_JWT_KEYS_MOUNT=/run/keys, which must win."""
    c = _cfg(SSO_KEYS_DIR="/home/thomas/sso/keys", SSO_JWT_KEYS_MOUNT="/run/keys",
             SSO_JWT_PRIVATE_KEY="a.private.pem", SSO_JWT_PUBLIC_KEYS="a.public.pem, b.public.pem")
    assert (c.mount, c.mount_source) == ("/run/keys", "SSO_JWT_KEYS_MOUNT")
    assert [k.path for k in (c.private, *c.publics)] == ["/run/keys/a.private.pem", "/run/keys/a.public.pem",
                                                          "/run/keys/b.public.pem"]


def test_compose_pins_the_mount_for_web():
    compose = (REPO / "docker-compose.yml").read_text()
    web = compose[compose.index("\n  web:"):compose.index("\n  redis:")]
    assert "SSO_JWT_KEYS_MOUNT: /run/keys" in web
    assert "- ${SSO_KEYS_DIR:-./keys}:/run/keys:ro" in web


def test_a_value_with_a_slash_is_a_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    c = _cfg(SSO_JWT_KEYS_MOUNT="/run/keys", SSO_JWT_PRIVATE_KEY="/abs/dir/k.pem", SSO_JWT_PUBLIC_KEYS="rel/k.pub,n.pub")
    assert c.private.path == "/abs/dir/k.pem" and "is a path" in c.private.origin
    assert [k.path for k in c.publics] == [str(tmp_path / "rel" / "k.pub"), "/run/keys/n.pub"]
    assert f"relative to the working directory {str(tmp_path)!r}" in c.publics[0].origin


def test_old_variables_still_work_and_are_flagged():
    c = _cfg(SSO_KEYS_DIR="/ignored", SSO_JWT_PRIVATE_KEY_PATH="/x/old.private.pem",
             SSO_JWT_PUBLIC_KEY_PATHS="/x/a.pub,/x/b.pub", SSO_JWT_PUBLIC_KEY_PATH="/x/singular.pub")
    assert c.private.path == "/x/old.private.pem"
    assert [k.path for k in c.publics] == ["/x/a.pub", "/x/b.pub"]  # PATHS wins over the singular, as before
    assert c.deprecated == ("SSO_JWT_PRIVATE_KEY_PATH", "SSO_JWT_PUBLIC_KEY_PATHS")


def test_old_variables_give_a_check_warning_and_a_log_line(settings, caplog):
    from sso import checks

    settings.SSO_KEY_DEPRECATED_VARS = ("SSO_JWT_PRIVATE_KEY_PATH",)
    [w] = checks.deprecated_key_variables(None)
    assert w.id == "sso.W001" and "SSO_JWT_PRIVATE_KEY_PATH is deprecated; use SSO_JWT_PRIVATE_KEY" in w.msg
    from django.apps import apps

    caplog.set_level("WARNING", logger="sso.config")
    apps.get_app_config("sso").ready()
    assert "SSO_JWT_PRIVATE_KEY_PATH is deprecated" in caplog.text
    settings.SSO_KEY_DEPRECATED_VARS = ()
    assert checks.deprecated_key_variables(None) == []


def test_old_variables_log_once_at_startup():
    r = _run_settings(_old_form())
    assert r.returncode == 0, r.stderr
    assert r.stderr.count("WARNING sso.config SSO_JWT_PRIVATE_KEY_PATH is deprecated") == 1
    assert r.stderr.count("WARNING sso.config SSO_JWT_PUBLIC_KEY_PATHS is deprecated") == 1
    assert "deprecated" not in r.stdout


def test_new_variables_log_no_deprecation():
    r = _run_settings(GOOD)
    assert r.returncode == 0, r.stderr
    assert "deprecated" not in r.stdout + r.stderr


def _old_form_manage(*args: str) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
              "SSO_SQLITE_PATH": ":memory:", **_old_form()})
    return subprocess.run([sys.executable, "manage.py", *args], cwd=REPO, env=e, capture_output=True, text=True,
                          timeout=120)


def test_manage_py_logs_the_deprecation_once_on_stderr():
    r = _old_form_manage("check", "--deploy", "--fail-level", "ERROR")
    assert r.returncode == 0, r.stderr
    # one log line from ready(); the check framework's own sso.W001 report also goes to stderr
    assert r.stderr.count("WARNING sso.config SSO_JWT_PRIVATE_KEY_PATH is deprecated") == 1
    assert "(sso.W001) SSO_JWT_PRIVATE_KEY_PATH is deprecated" in r.stderr
    assert "deprecated" not in r.stdout


def test_gunicorn_logs_the_deprecation_once_per_worker_on_stderr(tmp_path):
    """Under gunicorn (which runs no system checks) the line reaches stderr exactly once per worker process."""
    pytest.importorskip("gunicorn")
    import shutil
    import socket
    import time

    gunicorn = shutil.which("gunicorn", path=os.path.dirname(sys.executable))
    if not gunicorn:
        pytest.skip("gunicorn not installed in this venv")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
              "SSO_SQLITE_PATH": ":memory:", "SSO_ALLOWED_HOSTS": "127.0.0.1", "SSO_SSL_REDIRECT": "False",
              **_old_form()})
    err, out = tmp_path / "err", tmp_path / "out"
    with open(err, "w") as fe, open(out, "w") as fo:
        p = subprocess.Popen([gunicorn, "ssoproject.wsgi:application", "--bind", f"127.0.0.1:{port}",
                              "--workers", "2", "--no-control-socket", "--worker-tmp-dir", str(tmp_path)],
                             cwd=REPO, env=e, stdout=fo, stderr=fe)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and err.read_text().count("sso.config") < 2:
                time.sleep(0.2)
        finally:
            p.terminate()
            p.wait(timeout=15)
    text = err.read_text()
    assert text.count("WARNING sso.config SSO_JWT_PRIVATE_KEY_PATH is deprecated") == 2, text  # 2 workers
    assert "deprecated" not in out.read_text()


@pytest.mark.parametrize("old", [{"SSO_JWT_PRIVATE_KEY_PATH": "/x/p.pem"}])
def test_old_and_new_private_key_together_is_an_error(old):
    with pytest.raises(keys.KeyConfigConflict, match="Both SSO_JWT_PRIVATE_KEY and the deprecated SSO_JWT_PRIVATE_KEY_PATH"):
        _cfg(SSO_JWT_PRIVATE_KEY="p.pem", **old)


@pytest.mark.parametrize("old", ["SSO_JWT_PUBLIC_KEY_PATHS", "SSO_JWT_PUBLIC_KEY_PATH"])
def test_old_and_new_public_keys_together_is_an_error(old):
    with pytest.raises(keys.KeyConfigConflict, match=f"Both SSO_JWT_PUBLIC_KEYS and the deprecated {old}"):
        _cfg(SSO_JWT_PUBLIC_KEYS="p.pub", **{old: "/x/p.pub"})


@pytest.mark.parametrize("debug", ["False", "True"])
def test_both_forms_stop_the_settings_even_in_debug(debug):
    r = _run_settings({**GOOD, "SSO_DEBUG": debug, "SSO_JWT_PRIVATE_KEY_PATH": os.environ["SSO_TEST_CURRENT_PRIVATE"]})
    assert r.returncode != 0
    assert "ImproperlyConfigured" in r.stderr and "Both SSO_JWT_PRIVATE_KEY and the deprecated" in r.stderr


def test_rotation_publishes_every_public_key_and_signs_with_the_private_one(tmp_path):
    for name in ("old", "new"):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (tmp_path / f"{name}.private.pem").write_bytes(k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (tmp_path / f"{name}.public.pem").write_bytes(k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    # T0: old signs, both published
    c = _cfg(SSO_KEYS_DIR=str(tmp_path), SSO_JWT_PRIVATE_KEY="old.private.pem",
             SSO_JWT_PUBLIC_KEYS="old.public.pem,new.public.pem")
    ks = keys.load_keyset(c.private, c.publics)
    old_kid, new_kid = (keys.compute_kid(keys.load_public_key(str(tmp_path / f"{n}.public.pem"))) for n in ("old", "new"))
    assert ks.signing_kid == old_kid and [k["kid"] for k in ks.jwks()["keys"]] == [old_kid, new_kid]
    # switch: new signs; old still published
    c = _cfg(SSO_KEYS_DIR=str(tmp_path), SSO_JWT_PRIVATE_KEY="new.private.pem",
             SSO_JWT_PUBLIC_KEYS="old.public.pem,new.public.pem")
    ks = keys.load_keyset(c.private, c.publics)
    assert ks.signing_kid == new_kid and [k["kid"] for k in ks.jwks()["keys"]] == [new_kid, old_kid]
    # unchanged behaviour: the signing key's own public half is published even if not listed
    c = _cfg(SSO_KEYS_DIR=str(tmp_path), SSO_JWT_PRIVATE_KEY="new.private.pem", SSO_JWT_PUBLIC_KEYS="old.public.pem")
    assert [k["kid"] for k in keys.load_keyset(c.private, c.publics).jwks()["keys"]] == [new_kid, old_kid]


def test_settings_publish_the_rotation_keys_in_jwks(client):
    body = client.get("/.well-known/jwks.json").json()
    cur = keys.compute_kid(keys.load_public_key(os.environ["SSO_TEST_CURRENT_PUBLIC"]))
    old = keys.compute_kid(keys.load_public_key(os.environ["SSO_TEST_OLD_PUBLIC"]))
    assert [k["kid"] for k in body["keys"]] == [cur, old]


def test_missing_key_message_shows_resolved_path_and_how_it_was_built(tmp_path):
    c = _cfg(SSO_JWT_KEYS_MOUNT=str(tmp_path), SSO_JWT_PRIVATE_KEY="nope.private.pem")
    with pytest.raises(keys.KeyConfigError) as info:
        keys.load_keyset(c.private, c.publics)
    resolved = str(tmp_path / "nope.private.pem")
    assert str(info.value) == (f"JWT private key (SSO_JWT_PRIVATE_KEY='nope.private.pem' in SSO_JWT_KEYS_MOUNT="
                               f"{str(tmp_path)!r}) not found: {resolved!r}. Generate keys with scripts/gen_keys.sh.")


@needs_non_root
def test_unreadable_key_message_shows_resolved_path_origin_and_uid(tmp_path):
    pub = _write(tmp_path, "k.public.pem", _rsa_pem()[1])
    os.chmod(pub, 0o000)
    c = _cfg(SSO_JWT_KEYS_MOUNT=str(tmp_path), SSO_JWT_PRIVATE_KEY=os.environ["SSO_TEST_CURRENT_PRIVATE"],
             SSO_JWT_PUBLIC_KEYS="k.public.pem")
    try:
        with pytest.raises(keys.KeyConfigError) as info:
            keys.load_keyset(c.private, c.publics)
    finally:
        os.chmod(pub, 0o644)
    assert str(info.value) == (f"JWT public key (SSO_JWT_PUBLIC_KEYS='k.public.pem' in SSO_JWT_KEYS_MOUNT="
                               f"{str(tmp_path)!r}) {pub!r} exists but is not readable by uid {os.geteuid()}; "
                               "chown to SSO_UID:SSO_GID or set SSO_UID")


def test_unset_private_key_is_not_found():
    c = _cfg()
    assert c.private.path == "" and c.publics == ()
    with pytest.raises(keys.KeyConfigError, match="not found"):
        keys.load_keyset(c.private, c.publics)
