#!/usr/bin/env python3
"""Convert an application's ``sso_permissions.py`` into the v1.3a import payload (DESIGN-v1.3a §5.1).

    python scripts/sso_permissions_to_json.py path/to/sso_permissions.py > payload.json

The file is NEVER imported or executed: it is parsed with ``ast`` and only top-level ``NAME = <literal>``
assignments are read with ``ast.literal_eval``. Any other statement (import, call, def) is an error.
"""
from __future__ import annotations

import ast
import json
import sys

NAMES = {"APP_CODENAME", "APP_NAME", "APP_DESCRIPTION", "PERMISSIONS_VERSION", "PERMISSIONS"}


def parse(source: str) -> dict:
    tree = ast.parse(source)
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue  # docstring
        if not (isinstance(node, (ast.Assign, ast.AnnAssign))):
            raise ValueError(f"line {node.lineno}: only NAME = <literal> assignments are allowed")
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            raise ValueError(f"line {node.lineno}: only NAME = <literal> assignments are allowed")
        name = targets[0].id
        if name in NAMES:
            values[name] = ast.literal_eval(node.value)
    missing = sorted({"APP_CODENAME", "APP_NAME", "PERMISSIONS_VERSION", "PERMISSIONS"} - set(values))
    if missing:
        raise ValueError("missing: " + ", ".join(missing))
    perms = []
    for item in values["PERMISSIONS"]:
        if not isinstance(item, (tuple, list)) or len(item) not in (2, 3):
            raise ValueError(f"PERMISSIONS entry {item!r}: expected (codename, name[, description])")
        perms.append({"codename": item[0], "name": item[1], "description": item[2] if len(item) == 3 else ""})
    return {"app_codename": values["APP_CODENAME"], "app_name": values["APP_NAME"],
            "description": values.get("APP_DESCRIPTION", ""), "version": values["PERMISSIONS_VERSION"],
            "permissions": perms}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as f:
            data = parse(f.read())
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
