"""Settings for the SSO server.

All configuration comes from environment variables (optionally a ``.env`` file), read with
django-environ (addendum B.12). In non-debug mode the process refuses to start when
``SSO_SECRET_KEY``, ``SSO_ISSUER`` or the JWT key files are missing.
"""
from __future__ import annotations

import os
import sys
import warnings
from datetime import timedelta
from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

from sso.keys import KeyConfigError, generate_ephemeral_keyset, load_keyset

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
_env_file = os.environ.get("SSO_ENV_FILE", str(BASE_DIR / ".env"))
if _env_file and Path(_env_file).is_file():
    env.read_env(_env_file)

DEBUG = env.bool("SSO_DEBUG", default=False)

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

ALLOWED_HOSTS = env.list("SSO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"] if DEBUG else [])
CSRF_TRUSTED_ORIGINS = env.list("SSO_CSRF_TRUSTED_ORIGINS", default=[])

# --------------------------------------------------------------------------- JWT keys
SSO_JWT_PRIVATE_KEY_PATH = env.str("SSO_JWT_PRIVATE_KEY_PATH", default="")
# Comma-separated list for rotation (addendum B.6). Falls back to the singular v1.0 name.
SSO_JWT_PUBLIC_KEY_PATHS = env.list(
    "SSO_JWT_PUBLIC_KEY_PATHS", default=env.list("SSO_JWT_PUBLIC_KEY_PATH", default=[])
)
try:
    SSO_KEYSET = load_keyset(SSO_JWT_PRIVATE_KEY_PATH, SSO_JWT_PUBLIC_KEY_PATHS)
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
    _db_options: dict = {"charset": "utf8mb4"}
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
# LocMem is per-process: production with >1 gunicorn worker needs SSO_CACHE_URL=redis://... (B.3)
CACHES = {"default": env.cache_url("SSO_CACHE_URL", default="locmemcache://sso-default")}
CACHES["default"].setdefault("KEY_PREFIX", "sso")  # namespaced throttle keys (deployment plan R12)

# --------------------------------------------------------------------------- DRF / SimpleJWT
SSO_NUM_PROXIES = env.int("SSO_NUM_PROXIES", default=1)
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
    },
    "NUM_PROXIES": SSO_NUM_PROXIES,
    "EXCEPTION_HANDLER": "sso.errors.error_handler",
}

SSO_ACCESS_TTL = timedelta(minutes=env.int("SSO_ACCESS_TTL_MIN", default=15))
SSO_REFRESH_TTL = timedelta(days=env.int("SSO_REFRESH_TTL_DAYS", default=7))
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
    "handlers": {"console": {"class": "logging.StreamHandler", "stream": sys.stdout, "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": env.str("SSO_LOG_LEVEL", default="INFO")},
    "loggers": {
        "django.request": {"level": "ERROR"},
    },
}
