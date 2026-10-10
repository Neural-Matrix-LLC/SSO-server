#!/usr/bin/env bash
# Run the suite on Django 5.2 (the shipped target) and Django 4.2 (code-portability check only;
# 4.2 is not shipped: deployment plan R9).
# Creates .venv (5.2) and .venv-dj42 (4.2) on first use. Both are gitignored.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
run() {
  local venv="$1" spec="$2"
  if [[ ! -x "$venv/bin/pytest" ]]; then
    "$PY" -m venv "$venv"
    "$venv/bin/pip" install -q --upgrade pip
    "$venv/bin/pip" install -q -r requirements-dev.txt "$spec"
  fi
  echo "=== $("$venv/bin/python" -c 'import django; print("Django", django.get_version())') ==="
  "$venv/bin/pytest" -q --cov-fail-under=90 "${@:3}"
}
run .venv "Django>=5.2,<5.3" "$@"
run .venv-dj42 "Django>=4.2,<4.3" "$@"
