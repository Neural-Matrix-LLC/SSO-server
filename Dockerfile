# syntax=docker/dockerfile:1
# SSO server image (deployment plan §15 R1-R9).
#   docker build -t <docker-user>/sso-server:<tag> .            (or: docker compose build)
#   docker build --build-arg SSO_UID=1500 --build-arg SSO_GID=1500 ...   (match host key-file owner; default 10001)
# Keys, .env and certs are NEVER copied in: they are mounted at runtime (/run/keys:ro, env_file).
# Python 3.13 on Debian 13 (trixie) slim (R1). Its libmariadb3 (Connector/C 3.4) ships the
# caching_sha2_password client plugin, the default auth plugin for new accounts on MySQL 8.0 and 8.4.
# Patch pinned; digest of python:3.13.16-slim-trixie on 2026-10-10 (multi-arch index), if you want to pin harder:
#   python:3.13.16-slim-trixie@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
ARG PYTHON_IMAGE=python:3.13.16-slim-trixie

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
# Non-root runtime user (R2). Default 10001; override to match the owner of the host key files.
ARG SSO_UID=10001
ARG SSO_GID=10001
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DJANGO_SETTINGS_MODULE=ssoproject.settings \
    GUNICORN_WORKERS=3 \
    SSO_FORWARDED_ALLOW_IPS=127.0.0.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmariadb3 \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg -L libmariadb3 | grep -q '/plugin/caching_sha2_password.so$' \
 && for id in "${SSO_UID}" "${SSO_GID}"; do case "$id" in ''|*[!0-9]*) echo "SSO_UID/SSO_GID must be numeric, got '$id'" >&2; exit 1;; esac; done \
 && if [ "${SSO_UID}" -eq 0 ] || [ "${SSO_GID}" -eq 0 ]; then echo "SSO_UID/SSO_GID must not be 0 (root)" >&2; exit 1; fi \
 && if ! getent group "${SSO_GID}" >/dev/null; then groupadd --system --gid "${SSO_GID}" sso; fi \
 && if getent passwd "${SSO_UID}" >/dev/null; then \
      echo "uid ${SSO_UID} already exists in the base image ($(getent passwd "${SSO_UID}" | cut -d: -f1)); pick another" >&2; exit 1; fi \
 && useradd --system --uid "${SSO_UID}" --gid "${SSO_GID}" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sso
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

USER ${SSO_UID}:${SSO_GID}
EXPOSE 8000

# R7: send the Host Django expects and X-Forwarded-Proto: https (no curl needed).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s \
  CMD ["python", "/app/docker/healthcheck.py"]

# R5/R6: gunicorn only. No migrate/createsuperuser/clearsessions/flushexpiredtokens at start-up.
# Default access log format logs no headers. gunicorn trusts X-Forwarded-* only from
# SSO_FORWARDED_ALLOW_IPS (comma list of IPs/CIDRs; image default 127.0.0.1, compose sets the nginx network).
CMD ["sh", "-c", "exec gunicorn ssoproject.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-3} --timeout 30 --worker-tmp-dir /dev/shm --access-logfile - --error-logfile - --forwarded-allow-ips \"${SSO_FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
