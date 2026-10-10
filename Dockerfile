# syntax=docker/dockerfile:1
# SSO server image (deployment plan §15 R1-R9).
#   docker build -t sso-server:<tag> .
#   docker build --build-arg REQUIREMENTS=requirements-django42.lock -t sso-server:<tag>-dj42 .   # MySQL 5.7 fallback
# Keys, .env and certs are NEVER copied in: they are mounted at runtime (/run/keys:ro, env_file).
ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm

# ---------------------------------------------------------------- builder: compiles mysqlclient wheels
FROM ${PYTHON_IMAGE} AS builder
ARG REQUIREMENTS=requirements.lock
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config default-libmysqlclient-dev \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.lock requirements-django42.lock /tmp/
RUN pip wheel --wheel-dir /wheels -r /tmp/${REQUIREMENTS}

# ---------------------------------------------------------------- runtime: no compilers
FROM ${PYTHON_IMAGE} AS runtime
ARG REQUIREMENTS=requirements.lock
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DJANGO_SETTINGS_MODULE=ssoproject.settings \
    GUNICORN_WORKERS=3
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmariadb3 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 sso \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sso
COPY --from=builder /wheels /wheels
COPY requirements.lock requirements-django42.lock /tmp/
RUN pip install --no-index --find-links /wheels -r /tmp/${REQUIREMENTS} && rm -rf /wheels /tmp/*.lock

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
