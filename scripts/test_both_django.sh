#!/usr/bin/env bash
# Run the suite on Django 5.2 (the shipped target) and Django 4.2 (code-portability check only;
# 4.2 is not shipped: deployment plan R9).
#
#   scripts/test_both_django.sh                    # python3 from PATH -> .venv (5.2), .venv-dj42 (4.2)
#   PYTHON=python3.13 scripts/test_both_django.sh  # any interpreter -> .venv-py<X.Y.Z>-dj52 / -dj42
#   scripts/test_both_django.sh -k login           # extra args go to pytest
#
# Venvs are created on first use and are gitignored. An existing venv built with a different
# Python version is never reused silently: the script stops and says so.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
PYVER="$("$PY" -c 'import platform; print(platform.python_version())')"
if [[ -n "${PYTHON:-}" ]]; then
  V52=".venv-py${PYVER}-dj52"; V42=".venv-py${PYVER}-dj42"
else
  V52=".venv"; V42=".venv-dj42"
fi
run() {
  local venv="$1" spec="$2"; shift 2
  if [[ ! -x "$venv/bin/pytest" ]]; then
    "$PY" -m venv "$venv"
    "$venv/bin/pip" install -q --upgrade pip
    "$venv/bin/pip" install -q -r requirements-dev.txt "$spec"
  fi
  local have
  have="$("$venv/bin/python" -c 'import platform; print(platform.python_version())')"
  if [[ "$have" != "$PYVER" ]]; then
    echo "$venv was built with Python $have, not $PYVER ($PY). Remove it or set PYTHON." >&2
    exit 2
  fi
  echo "=== Python $have, $("$venv/bin/python" -c 'import django; print("Django", django.get_version())') ($venv) ==="
  "$venv/bin/pytest" -q --cov-fail-under=90 "$@"
}
run "$V52" "Django>=5.2,<5.3" "$@"
run "$V42" "Django>=4.2,<4.3" "$@"
