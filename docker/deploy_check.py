"""In-container part of scripts/deploy_check.sh (runs in ``web``): configuration consistency, TLS and HTTP checks
through nginx, see sso/deploycheck.py. Prints one line per check, STATUS<TAB>ID<TAB>title<TAB>detail<TAB>fix (the
host script needs no jq/python), or with --json one JSON object per line ({"id","status","title","detail","fix"}).

    python /app/docker/deploy_check.py [--target nginx] [--port 443] [--json]

Exit code 1 when any check FAILs, 0 otherwise."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # /app

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ssoproject.settings")

import django  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="nginx", help="host that serves the public TLS port (default nginx)")
    parser.add_argument("--port", type=int, default=443, help="its TLS port inside the network (default 443)")
    parser.add_argument("--json", action="store_true", help="JSON lines instead of tab-separated lines")
    args = parser.parse_args()

    from sso.deploycheck import FAIL, Result, run_all

    kid, pre = None, []
    try:
        django.setup()
        from django.conf import settings

        kid = settings.SSO_KEYSET.signing_kid
    except Exception as exc:  # noqa: BLE001
        pre.append(Result("K01", FAIL, "settings and keys load", f"{exc.__class__.__name__}: {exc}",
                          "docker compose logs web (Troubleshooting: 'web keeps restarting, log mentions keys')"))
    results = pre + run_all(os.environ, args.target, args.port, kid)
    for r in results:
        if args.json:
            print(json.dumps(r.as_dict()))
        else:
            print("\t".join(" ".join(str(v).split()) for v in (r.status, r.id, r.title, r.detail, r.fix)))
    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
