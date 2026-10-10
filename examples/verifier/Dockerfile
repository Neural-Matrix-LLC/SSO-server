# Demo back-end service for QA (not part of the SSO image).
FROM python:3.12.15-slim-bookworm
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY sso_verifier.py verifier_app.py ./
USER 10001:10001
EXPOSE 8001
CMD ["uvicorn", "verifier_app:app", "--host", "0.0.0.0", "--port", "8001", "--proxy-headers"]
