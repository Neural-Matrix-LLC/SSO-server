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


def test_locmem_deploy_warning(settings):
    from sso.checks import locmem_cache_in_production

    settings.DEBUG = False
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    assert [w.id for w in locmem_cache_in_production(None)] == ["sso.W001"]
    settings.DEBUG = True
    assert locmem_cache_in_production(None) == []


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
