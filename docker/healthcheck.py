"""Container healthcheck (deployment plan R7): GET /healthz with the Host Django allows and
X-Forwarded-Proto: https, so neither ALLOWED_HOSTS nor SECURE_SSL_REDIRECT gets in the way."""
import http.client
import os
import sys

host = (os.environ.get("SSO_ALLOWED_HOSTS", "localhost").split(",")[0].strip() or "localhost").lstrip(".")
try:
    conn = http.client.HTTPConnection("127.0.0.1", int(os.environ.get("SSO_HEALTHCHECK_PORT", "8000")), timeout=4)
    conn.request("GET", "/healthz", headers={"Host": host, "X-Forwarded-Proto": "https"})
    status = conn.getresponse().status
except Exception as exc:  # noqa: BLE001
    print(f"healthcheck failed: {exc.__class__.__name__}", file=sys.stderr)
    sys.exit(1)
sys.exit(0 if status == 200 else 1)
