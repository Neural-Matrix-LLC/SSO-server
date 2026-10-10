# syntax=docker/dockerfile:1
# SSO server image (deployment plan §15 R1-R9).
#   docker build -t sso-server:<tag> .
# Keys, .env and certs are NEVER copied in: they are mounted at runtime (/run/keys:ro, env_file).
# Debian 13 (trixie) slim: its libmariadb3 (Connector/C 3.4) ships the caching_sha2_password client plugin
# that MySQL 8.4 accounts need (R1). Pin by digest in CI if wanted: python:3.12.15-slim-trixie@sha256:...
ARG PYTHON_IMAGE=python:3.12.15-slim-trixie

# ---------------------------------------------------------------- builder: compiles mysqlclient wheels
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config default-libmysqlclient-dev \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.lock /tmp/
RUN pip wheel --wheel-dir /wheels -r /tmp/requirements.lock

# ---------------------------------------------------------------- runtime: no compilers
FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DJANGO_SETTINGS_MODULE=ssoproject.settings \
    GUNICORN_WORKERS=3
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmariadb3 \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg -L libmariadb3 | grep -q '/plugin/caching_sha2_password.so$' \
 && groupadd --system --gid 10001 sso \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sso
COPY --from=builder /wheels /wheels
COPY requirements.lock /tmp/
RUN pip install --no-index --find-links /wheels -r /tmp/requirements.lock && rm -rf /wheels /tmp/requirements.lock

WORKDIR /app
COPY --chown=root:root manage.py ./
COPY --chown=root:root ssoproject ./ssoproject
COPY --chown=root:root sso ./sso
COPY --chown=root:root docker/healthcheck.py ./docker/healthcheck.py
# Admin static files are collected at build time and served by WhiteNoise (R4). A throw-away DEBUG
# config is used only for this step (ephemeral key in memory, nothing written but staticfiles/).
RUN SSO_ENV_FILE= SSO_DEBUG=True SSO_DB_ENGINE=sqlite SSO_SQLITE_PATH=/tmp/build.sqlite3 \
    python -W ignore manage.py collectstatic --noinput -v 0 \
 && rm -f /tmp/build.sqlite3 \
 && rm -rf sso/tests

USER 10001:10001
EXPOSE 8000

# R7: send the Host Django expects and X-Forwarded-Proto: https (no curl needed).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s \
  CMD ["python", "/app/docker/healthcheck.py"]

# R5/R6: gunicorn only. No migrate/createsuperuser/clearsessions/flushexpiredtokens at start-up.
# Default access log format logs no headers; web is never published, so trusting all forwarders is safe.
CMD ["sh", "-c", "exec gunicorn ssoproject.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-3} --timeout 30 --worker-tmp-dir /dev/shm --access-logfile - --error-logfile - --forwarded-allow-ips '*'"]
