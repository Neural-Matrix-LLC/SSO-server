"""Parse an application's ``sso_permissions.py`` into the import payload (DESIGN-v1.3a §5.1, v1.3d §8.2).

The file is NEVER imported or executed: it is parsed with ``ast`` and only top-level ``NAME = <literal>``
assignments are read with ``ast.literal_eval``. Any other statement (import, call, def, …) is an error. No Django
imports here: ``scripts/sso_permissions_to_json.py`` uses this module stand-alone.
"""
from __future__ import annotations

import ast

MAX_SOURCE_BYTES = 64 * 1024
NAMES = {"APP_CODENAME", "APP_NAME", "APP_DESCRIPTION", "PERMISSIONS_VERSION", "PERMISSIONS"}


class PermFileError(ValueError):
    pass


def parse(source: str) -> dict:
    if len(source.encode("utf-8", "surrogatepass")) > MAX_SOURCE_BYTES:
        raise PermFileError(f"file is larger than {MAX_SOURCE_BYTES // 1024} KiB")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise PermFileError(f"line {exc.lineno}: syntax error") from None
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue  # docstring
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            raise PermFileError(f"line {node.lineno}: only NAME = <literal> assignments are allowed")
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            raise PermFileError(f"line {node.lineno}: only NAME = <literal> assignments are allowed")
        name = targets[0].id
        if name in NAMES:
            try:
                values[name] = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                raise PermFileError(f"line {node.lineno}: {name} must be a literal") from None
    missing = sorted({"APP_CODENAME", "APP_NAME", "PERMISSIONS_VERSION", "PERMISSIONS"} - set(values))
    if missing:
        raise PermFileError("missing: " + ", ".join(missing))
    if not isinstance(values["PERMISSIONS"], (list, tuple)):
        raise PermFileError("PERMISSIONS must be a list")
    perms = []
    for item in values["PERMISSIONS"]:
        if not isinstance(item, (tuple, list)) or len(item) not in (2, 3):
            raise PermFileError(f"PERMISSIONS entry {item!r:.80}: expected (codename, name[, description])")
        perms.append({"codename": item[0], "name": item[1], "description": item[2] if len(item) == 3 else ""})
    return {"app_codename": values["APP_CODENAME"], "app_name": values["APP_NAME"],
            "description": values.get("APP_DESCRIPTION", ""), "version": values["PERMISSIONS_VERSION"],
            "permissions": perms}
