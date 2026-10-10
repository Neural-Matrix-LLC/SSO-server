"""Test settings: SQLite, throw-away RSA keys, fast-but-real configuration.

Generates two key pairs in a temp dir before the real settings module is imported:
``current`` (signing) and ``old`` (published only, as during rotation). Paths are exported as
SSO_TEST_* env vars so tests can sign tokens with the old key.
"""
import atexit
import os
import shutil
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_KEYDIR = tempfile.mkdtemp(prefix="sso-test-keys-")
atexit.register(shutil.rmtree, _KEYDIR, ignore_errors=True)


def _write_pair(name: str) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = os.path.join(_KEYDIR, f"{name}.private.pem")
    pub = os.path.join(_KEYDIR, f"{name}.public.pem")
    with open(priv, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(pub, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


_cur_priv, _cur_pub = _write_pair("current")
_old_priv, _old_pub = _write_pair("old")
_rogue_priv, _rogue_pub = _write_pair("rogue")  # never published

os.environ.update(
    {
        "SSO_ENV_FILE": "",
        "SSO_DEBUG": "False",
        "SSO_SECRET_KEY": "test-secret-key-" + "x" * 40,
        "SSO_ISSUER": "https://sso.test",
        "SSO_AUDIENCE": "myfin-services",
        "SSO_ALLOWED_HOSTS": "testserver,sso.test,localhost",
        "SSO_DB_ENGINE": os.environ.get("SSO_DB_ENGINE", "sqlite"),
        "SSO_JWT_PRIVATE_KEY_PATH": _cur_priv,
        "SSO_JWT_PUBLIC_KEY_PATHS": f"{_cur_pub},{_old_pub}",
        "SSO_CORS_ALLOWED_ORIGINS": "https://fin.example.test,https://app.example.test",
        "SSO_COOKIE_DOMAIN": ".example.test",
        "SSO_SSL_REDIRECT": "False",
        "SSO_CACHE_URL": "locmemcache://sso-tests",
        "SSO_TEST_KEYDIR": _KEYDIR,
        "SSO_TEST_CURRENT_PRIVATE": _cur_priv,
        "SSO_TEST_CURRENT_PUBLIC": _cur_pub,
        "SSO_TEST_OLD_PRIVATE": _old_priv,
        "SSO_TEST_OLD_PUBLIC": _old_pub,
        "SSO_TEST_ROGUE_PRIVATE": _rogue_priv,
    }
)
if os.environ["SSO_DB_ENGINE"] == "sqlite":
    os.environ["SSO_SQLITE_PATH"] = ":memory:"

from .settings import *  # noqa: E402,F401,F403
