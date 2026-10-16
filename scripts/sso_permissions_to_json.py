#!/usr/bin/env python3
"""Convert an application's ``sso_permissions.py`` into the v1.3a import payload (DESIGN-v1.3a §5.1).

    python scripts/sso_permissions_to_json.py path/to/sso_permissions.py > payload.json

The file is NEVER imported or executed: it is parsed with ``ast`` and only top-level ``NAME = <literal>``
assignments are read with ``ast.literal_eval``. Any other statement (import, call, def) is an error.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from application.permfile import PermFileError, parse  # noqa: E402  (no Django needed)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as f:
            data = parse(f.read())
    except (OSError, PermFileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
