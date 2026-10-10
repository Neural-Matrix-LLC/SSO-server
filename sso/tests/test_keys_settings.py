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
    "SSO_JWT_PRIVATE_KEY_PATH": os.environ["SSO_TEST_CURRENT_PRIVATE"],
    "SSO_JWT_PUBLIC_KEY_PATHS": os.environ["SSO_TEST_CURRENT_PUBLIC"],
    "SSO_CACHE_URL": "redis://127.0.0.1:6379/0",
}


def test_settings_start_with_full_config():
    r = _run_settings(GOOD)
    assert r.returncode == 0, r.stderr
    assert "KID " in r.stdout


@pytest.mark.parametrize("override,message", [
    ({"SSO_SECRET_KEY": ""}, "SSO_SECRET_KEY is empty"),
    ({"SSO_ISSUER": ""}, "SSO_ISSUER is empty"),
    ({"SSO_JWT_PRIVATE_KEY_PATH": "/nonexistent/private.pem"}, "JWT private key"),
    ({"SSO_JWT_PUBLIC_KEY_PATHS": "/nonexistent/public.pem"}, "JWT public key"),
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
    env = dict(GOOD)
    del env["SSO_JWT_PUBLIC_KEY_PATHS"]
    env["SSO_JWT_PUBLIC_KEY_PATH"] = os.environ["SSO_TEST_OLD_PUBLIC"]
    code = ("import django; django.setup(); from django.conf import settings; "
            "print(len(settings.SSO_KEYSET.public_keys))")
    e = {k: v for k, v in os.environ.items() if not k.startswith("SSO_")}
    e.update({"DJANGO_SETTINGS_MODULE": "ssoproject.settings", "SSO_ENV_FILE": "", "SSO_DB_ENGINE": "sqlite",
              "SSO_SQLITE_PATH": ":memory:", **env})
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=e, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "2"


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
    assert json.loads(r.stdout) == {"host": "db.internal", "port": "3307", "options": {"charset": "utf8mb4"}}
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy")
    r = _db_options({"SSO_DB_SSL_CA": str(ca)})
    assert json.loads(r.stdout)["options"] == {"charset": "utf8mb4", "ssl": {"ca": str(ca)}, "ssl_mode": "VERIFY_CA"}
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
