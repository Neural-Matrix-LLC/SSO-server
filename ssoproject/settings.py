"""Settings for the SSO server.

All configuration comes from environment variables (optionally a ``.env`` file), read with
django-environ (addendum B.12). In non-debug mode the process refuses to start when
``SSO_SECRET_KEY``, ``SSO_ISSUER`` or the JWT key files are missing, when ``SSO_CACHE_URL`` is not a
shared cache, or when it runs as root (uid 0).
"""
from __future__ import annotations

import os
import sys
import warnings
from datetime import timedelta
from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

from sso.keys import (KeyConfigConflict, KeyConfigError, generate_ephemeral_keyset, load_keyset,
                      resolve_key_config)
from sso.runtime import ROOT_MESSAGE, running_as_root

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
_env_file = os.environ.get("SSO_ENV_FILE", str(BASE_DIR / ".env"))
if _env_file and Path(_env_file).is_file():
    env.read_env(_env_file)

DEBUG = env.bool("SSO_DEBUG", default=False)

# Non-root only (deployment plan R2): with SSO_DEBUG=False the process refuses to start as uid 0, the
# same way as for a missing secret or a per-process cache. sso.E002 repeats it as a system check.
if not DEBUG and running_as_root():
    raise ImproperlyConfigured(ROOT_MESSAGE)

# --------------------------------------------------------------------------- core / fail-fast
SECRET_KEY = env.str("SSO_SECRET_KEY", default="")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "SSO_SECRET_KEY is empty. Set it in the environment or .env "
            "(e.g. python -c 'import secrets; print(secrets.token_urlsafe(50))')."
        )
    SECRET_KEY = "insecure-dev-only-key-do-not-use-in-production"

SSO_ISSUER = env.str("SSO_ISSUER", default="").rstrip("/")
if not SSO_ISSUER:
    if not DEBUG:
        raise ImproperlyConfigured("SSO_ISSUER is empty (the public base URL, e.g. https://sso.example.com).")
    SSO_ISSUER = "http://localhost:8000"
SSO_AUDIENCE = env.str("SSO_AUDIENCE", default="myfin-services")
# Superusers get every application.* permission in the perms claim (Django's rule). false = only explicit
# grants count for them too (docs/sso-integration-design.md v1.1 item 8; pending Thomas's confirmation).
# Superusers administer users; they get app access only through explicit grants unless this is
# set to true (old Django-style "superuser has everything" rule). Decision relayed 2026-10-11.
SSO_SUPERUSER_ALL_APPS = env.bool("SSO_SUPERUSER_ALL_APPS", default=False)

ALLOWED_HOSTS = env.list("SSO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"] if DEBUG else [])
CSRF_TRUSTED_ORIGINS = env.list("SSO_CSRF_TRUSTED_ORIGINS", default=[])

# --------------------------------------------------------------------------- JWT keys
# SSO_JWT_PRIVATE_KEY / SSO_JWT_PUBLIC_KEYS are file NAMES in the keys mount (README §3, "Docker quick start"):
# mount = SSO_JWT_KEYS_MOUNT > SSO_KEYS_DIR > /run/keys (compose pins SSO_JWT_KEYS_MOUNT=/run/keys for web).
# A value with '/' is a path. The old SSO_JWT_PRIVATE_KEY_PATH / SSO_JWT_PUBLIC_KEY_PATHS still work (deprecated,
# sso.W001); old and new form of the same setting together are an error even with SSO_DEBUG=True.
try:
    SSO_KEY_CONFIG = resolve_key_config(os.environ)
except KeyConfigConflict as exc:
    raise ImproperlyConfigured(f"JWT key configuration error: {exc}") from exc
SSO_JWT_KEYS_MOUNT = SSO_KEY_CONFIG.mount
SSO_JWT_PRIVATE_KEY_PATH = SSO_KEY_CONFIG.private.path  # resolved paths (kept for compatibility)
SSO_JWT_PUBLIC_KEY_PATHS = [k.path for k in SSO_KEY_CONFIG.publics]
SSO_KEY_DEPRECATED_VARS = SSO_KEY_CONFIG.deprecated
try:
    SSO_KEYSET = load_keyset(SSO_KEY_CONFIG.private, SSO_KEY_CONFIG.publics)
except KeyConfigError as exc:
    if not DEBUG:
        raise ImproperlyConfigured(f"JWT key configuration error: {exc}") from exc
    warnings.warn(f"{exc} -- SSO_DEBUG=True so an EPHEMERAL signing key is used.", stacklevel=1)
    SSO_KEYSET = generate_ephemeral_keyset()

# --------------------------------------------------------------------------- apps
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "sso",
    "application",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ssoproject.urls"
WSGI_APPLICATION = "ssoproject.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# --------------------------------------------------------------------------- database
# Default: MySQL dcWebUsers (spec §4). SSO_DB_ENGINE=sqlite for unit tests / local dev (addendum B.14).
SSO_DB_ENGINE = env.str("SSO_DB_ENGINE", default="mysql").lower()
if SSO_DB_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": env.str("SSO_SQLITE_PATH", default=str(BASE_DIR / "db.sqlite3")),
        }
    }
elif SSO_DB_ENGINE == "mysql":
    # Optional DB TLS (deployment plan §6.0 / R28). mysqlclient emulates ssl_mode on MariaDB Connector/C:
    # REQUIRED -> TLS enforced, VERIFY_CA / VERIFY_IDENTITY -> server certificate verified against the CA.
    # Network timeouts (seconds). Without them libmariadb waits for the OS TCP timeout (~2 min) when the
    # DB host drops packets (firewall, wrong bind-address, WSL host-gateway), so a request such as the
    # /healthz probe outlives gunicorn's --timeout and the worker is SIGKILLed ("WORKER TIMEOUT").
    _db_options: dict = {
        "charset": "utf8mb4",
        "connect_timeout": env.int("SSO_DB_CONNECT_TIMEOUT", default=3),
        "read_timeout": env.int("SSO_DB_READ_TIMEOUT", default=15),
        "write_timeout": env.int("SSO_DB_WRITE_TIMEOUT", default=15),
    }
    SSO_DB_SSL_CA = env.str("SSO_DB_SSL_CA", default="")
    SSO_DB_SSL_MODE = env.str("SSO_DB_SSL_MODE", default="").upper() or ("VERIFY_CA" if SSO_DB_SSL_CA else "")
    _SSL_MODES = {"DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"}
    if SSO_DB_SSL_MODE and SSO_DB_SSL_MODE not in _SSL_MODES:
        raise ImproperlyConfigured(f"SSO_DB_SSL_MODE must be one of {sorted(_SSL_MODES)}, got {SSO_DB_SSL_MODE!r}")
    if SSO_DB_SSL_MODE in {"VERIFY_CA", "VERIFY_IDENTITY"} and not SSO_DB_SSL_CA:
        raise ImproperlyConfigured(f"SSO_DB_SSL_MODE={SSO_DB_SSL_MODE} needs SSO_DB_SSL_CA (path to the server CA cert)")
    if SSO_DB_SSL_CA:
        if not Path(SSO_DB_SSL_CA).is_file():
            raise ImproperlyConfigured(f"SSO_DB_SSL_CA file not found: {SSO_DB_SSL_CA}")
        _db_options["ssl"] = {"ca": SSO_DB_SSL_CA}
    if SSO_DB_SSL_MODE:
        _db_options["ssl_mode"] = SSO_DB_SSL_MODE
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": env.str("SSO_DBNAME", default="dcWebUsers"),
            "HOST": env.str("SSO_DBHOST", default="127.0.0.1"),
            "PORT": env.str("SSO_DBPORT", default="3306"),
            "USER": env.str("SSO_DBUSER", default=""),
            "PASSWORD": env.str("SSO_DBPWD", default=""),
            "CONN_MAX_AGE": env.int("SSO_DB_CONN_MAX_AGE", default=60),
            "OPTIONS": _db_options,
            "TEST": {"NAME": env.str("SSO_TEST_DBNAME", default="test_dcWebUsers")},
        }
    }
else:
    raise ImproperlyConfigured(f"SSO_DB_ENGINE must be 'mysql' or 'sqlite', got {SSO_DB_ENGINE!r}")

# Our own tables get BigAutoField; shared Django tables keep whatever their apps declare.
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --------------------------------------------------------------------------- auth
# Stock User model, no AUTH_USER_MODEL (spec §4.1). Default PASSWORD_HASHERS (PBKDF2 first, §4.3).
# AllowAllUsersModelBackend returns inactive users too, so the login view can answer
# 403 account_inactive after exactly one password hash (no extra timing signal).
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.AllowAllUsersModelBackend"]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --------------------------------------------------------------------------- cache (throttling)
# Throttle counters must be shared by all gunicorn workers (addendum B.3, QA defect 5). With
# SSO_DEBUG=False the server refuses to start without SSO_CACHE_URL or with a per-process (locmem)
# or no-op (dummy) cache. Use redis://... (compose default) or, for a single-host run without Redis,
# filecache:///path (shared between the workers of one host).
_PER_PROCESS_CACHES = {
    "django.core.cache.backends.locmem.LocMemCache": "locmem",
    "django.core.cache.backends.dummy.DummyCache": "dummy",
}
_cache_url = env.str("SSO_CACHE_URL", default="")
if not _cache_url:
    if not DEBUG:
        raise ImproperlyConfigured(
            "SSO_CACHE_URL is empty: set a shared cache for throttling, e.g. redis://redis:6379/0 "
            "(SSO_DEBUG=False never falls back to a per-process cache)."
        )
    _cache_url = "locmemcache://sso-default"
CACHES = {"default": env.cache_url_config(_cache_url)}
if not DEBUG and CACHES["default"]["BACKEND"] in _PER_PROCESS_CACHES:
    raise ImproperlyConfigured(
        f"SSO_CACHE_URL uses the {_PER_PROCESS_CACHES[CACHES['default']['BACKEND']]} backend, which is not "
        "shared between gunicorn workers, so login throttling would not work. Use redis://... or filecache://..."
    )
if "redis" in CACHES["default"]["BACKEND"].lower():
    # fail fast instead of hanging a worker when Redis is unreachable
    _redis_opts = CACHES["default"].setdefault("OPTIONS", {})
    _redis_opts.setdefault("socket_connect_timeout", env.float("SSO_CACHE_CONNECT_TIMEOUT", default=3.0))
    _redis_opts.setdefault("socket_timeout", env.float("SSO_CACHE_SOCKET_TIMEOUT", default=3.0))
CACHES["default"].setdefault("KEY_PREFIX", "sso")  # namespaced throttle keys (deployment plan R12)

# --------------------------------------------------------------------------- DRF / SimpleJWT
# Number of trusted reverse proxies in front of gunicorn. Default 0 = X-Forwarded-For is ignored, so a
# directly reachable server cannot be tricked out of its per-IP throttle (QA defect 4). docker-compose.yml
# sets 1, which is correct only because nginx overwrites X-Forwarded-For and web is not published.
SSO_NUM_PROXIES = env.int("SSO_NUM_PROXIES", default=0)
# v1.2b (design §4.5.2): trusted reverse proxies as IPs / CIDRs. X-Forwarded-For is read only when the socket
# peer is one of them, walked right to left (same algorithm as sso_client.get_client_ip). When set, it replaces
# SSO_NUM_PROXIES (deprecated fallback, warning sso.W002, used only while this is empty).
SSO_TRUSTED_PROXIES = env.list("SSO_TRUSTED_PROXIES", default=[])
try:
    from sso.clientip import parse_trusted as _parse_trusted

    SSO_TRUSTED_PROXIES_PARSED = _parse_trusted(SSO_TRUSTED_PROXIES)
except ValueError as _exc:
    raise ImproperlyConfigured(f"SSO_TRUSTED_PROXIES: {_exc}") from None
# optional header written by a trusted proxy with the client IP (e.g. cf-connecting-ip, x-real-ip); read only
# when the peer is in SSO_TRUSTED_PROXIES and it holds a valid IP, else X-Forwarded-For (design §4.5.2)
SSO_CLIENT_IP_HEADER = env.str("SSO_CLIENT_IP_HEADER", default="").strip()
if SSO_CLIENT_IP_HEADER and not SSO_TRUSTED_PROXIES_PARSED:
    raise ImproperlyConfigured("SSO_CLIENT_IP_HEADER needs SSO_TRUSTED_PROXIES")
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    "UNAUTHENTICATED_USER": None,
    "DEFAULT_THROTTLE_RATES": {
        "login": env.str("SSO_THROTTLE_LOGIN", default="10/min"),
        "login_user": env.str("SSO_THROTTLE_LOGIN_USER", default="5/min"),
        "refresh": env.str("SSO_THROTTLE_REFRESH", default="60/min"),
        # v1.2b: per ServiceClient for /introspect (design §4.4)
        "introspect": env.str("SSO_THROTTLE_INTROSPECT", default="6000/min"),
        # v1.3a (DESIGN-v1.3a-admin-api.md §10)
        "admin": env.str("SSO_THROTTLE_ADMIN", default="120/min"),
        "admin_reauth": env.str("SSO_THROTTLE_ADMIN_REAUTH", default="5/min"),
        "service_token": env.str("SSO_THROTTLE_SERVICE_TOKEN", default="60/min"),
    },
    "NUM_PROXIES": SSO_NUM_PROXIES,
    "EXCEPTION_HANDLER": "sso.errors.error_handler",
}

# v1.3a: step-up window and service token lifetime (DESIGN-v1.3a-admin-api.md §11)
SSO_ADMIN_REAUTH_SECONDS = env.int("SSO_ADMIN_REAUTH_SECONDS", default=300)
SSO_SERVICE_TOKEN_TTL_SECONDS = env.int("SSO_SERVICE_TOKEN_TTL_SECONDS", default=300)
# v1.3b devices (DESIGN-v1.3b §10)
SSO_DEVICE_MAX_PER_USER = env.int("SSO_DEVICE_MAX_PER_USER", default=10)
SSO_DEVICE_ASSERTION_MAX_AGE = env.int("SSO_DEVICE_ASSERTION_MAX_AGE", default=300)

SSO_ACCESS_TTL = timedelta(minutes=env.int("SSO_ACCESS_TTL_MIN", default=15))
SSO_REFRESH_TTL = timedelta(days=env.int("SSO_REFRESH_TTL_DAYS", default=7))
# Refresh-token reuse (v1.2a): presenting an already-used refresh token revokes its whole session (sid),
# unless it was used less than this many seconds ago (two legitimate concurrent refreshes, a retry after a
# lost response). The late request gets 401 either way; only the session revocation is skipped.
SSO_REFRESH_REUSE_GRACE_SECONDS = env.int("SSO_REFRESH_REUSE_GRACE_SECONDS", default=10)
if SSO_REFRESH_REUSE_GRACE_SECONDS < 0:
    raise ImproperlyConfigured("SSO_REFRESH_REUSE_GRACE_SECONDS must be >= 0")
# v1.2b client-IP token binding (design §4.2): NOIP (default) | WARNING | ENFORCE
SSO_IP_BINDING_MODE = env.str("SSO_IP_BINDING_MODE", default="NOIP").strip().upper()
if SSO_IP_BINDING_MODE not in ("NOIP", "WARNING", "ENFORCE"):
    raise ImproperlyConfigured("SSO_IP_BINDING_MODE must be NOIP, WARNING or ENFORCE")
# HMAC key for the cip claim; default derived from SSO_SECRET_KEY with a fixed label (changing either one makes
# every bound token mismatch: rotate only together with a logout of all users or in NOIP/WARNING).
import hmac as _hmac  # noqa: E402

_ip_key = env.str("SSO_IP_BINDING_KEY", default="")
SSO_IP_BINDING_KEY = (_ip_key.encode("utf-8") if _ip_key else
                      _hmac.new(SECRET_KEY.encode("utf-8"), b"sso-ip-binding-v1", "sha256").digest())
# revoked-session lookups (v1.2b): cached in the shared cache (Redis); "not revoked" answers only this long
SSO_REVOKED_SESSION_CACHE_SECONDS = env.int("SSO_REVOKED_SESSION_CACHE_SECONDS", default=10)
SSO_CODE_TTL = timedelta(seconds=env.int("SSO_CODE_TTL_SEC", default=60))  # phase 5 (unused)

SIMPLE_JWT = {
    "ALGORITHM": "RS256",
    "SIGNING_KEY": SSO_KEYSET.signing_pem,
    "VERIFYING_KEY": SSO_KEYSET.signing_public.pem,
    "ISSUER": SSO_ISSUER,
    "AUDIENCE": SSO_AUDIENCE,
    "ACCESS_TOKEN_LIFETIME": SSO_ACCESS_TTL,
    "REFRESH_TOKEN_LIFETIME": SSO_REFRESH_TTL,
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    # last_login is updated by the login view via the user_logged_in signal instead.
    "UPDATE_LAST_LOGIN": False,
    "USER_ID_CLAIM": "sub",
    "USER_ID_FIELD": "id",
    "TOKEN_TYPE_CLAIM": "token_type",
    "LEEWAY": 30,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_TOKEN_CLASSES": ("sso.tokens.SSOAccessToken",),
}

# --------------------------------------------------------------------------- CORS / cookies
CORS_ALLOWED_ORIGINS = env.list("SSO_CORS_ALLOWED_ORIGINS", default=[])
CORS_ALLOW_CREDENTIALS = True
CORS_URLS_REGEX = r"^/(api/|\.well-known/).*$"

SSO_COOKIE_NAME = "sso_refresh"
SSO_COOKIE_PATH = "/api/v1/auth/"
SSO_COOKIE_DOMAIN = env.str("SSO_COOKIE_DOMAIN", default="") or None
SSO_COOKIE_SECURE = env.bool("SSO_COOKIE_SECURE", default=True)
SSO_COOKIE_SAMESITE = env.str("SSO_COOKIE_SAMESITE", default="Lax")

SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = env.bool("SSO_SECURE_COOKIES", default=True)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# TLS terminates at nginx, which sends X-Forwarded-Proto: https (healthchecks must send it too).
SECURE_SSL_REDIRECT = env.bool("SSO_SSL_REDIRECT", default=not DEBUG)
SECURE_REDIRECT_EXEMPT = [r"^healthz$"]
SECURE_HSTS_SECONDS = env.int("SSO_HSTS_SECONDS", default=0 if DEBUG else 31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool("SSO_HSTS_INCLUDE_SUBDOMAINS", default=True)
SECURE_HSTS_PRELOAD = env.bool("SSO_HSTS_PRELOAD", default=False)
# HSTS preload is a whole-domain commitment (all subdomains, hard to undo): a decision for the
# domain owner, not this app, so its deploy-check warning is silenced (README open questions).
SILENCED_SYSTEM_CHECKS = ["security.W021"]

SSO_ADMIN_PATH = env.str("SSO_ADMIN_PATH", default="sso-admin/").strip("/") + "/"

# --------------------------------------------------------------------------- i18n / static
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

# --------------------------------------------------------------------------- logging
# One structured (JSON) line per login attempt on logger "sso.auth" (B.13). Never tokens/passwords.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {
        "console": {"class": "logging.StreamHandler", "stream": sys.stdout, "formatter": "plain"},
        # start-up configuration warnings (e.g. deprecated key variables): stderr, like gunicorn's own
        # --error-logfile - and Django's system-check output
        "stderr": {"class": "logging.StreamHandler", "stream": sys.stderr, "formatter": "plain"},
    },
    "root": {"handlers": ["console"], "level": env.str("SSO_LOG_LEVEL", default="INFO")},
    "loggers": {
        "django.request": {"level": "ERROR"},
        "sso.config": {"handlers": ["stderr"], "level": "WARNING", "propagate": False},
        # DB connectivity failures (healthz, start-up check): ERROR on stdout, i.e. `docker compose logs web`
        "sso.db": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
