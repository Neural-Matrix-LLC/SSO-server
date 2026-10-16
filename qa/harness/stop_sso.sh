#!/usr/bin/env bash
# stop_sso.sh PORT -- stop the gunicorn started by start_sso.sh, by its recorded PID (process group) only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PIDF="$HERE/../run/sso-$1.pid"
[[ -f "$PIDF" ]] || { echo "no pid file $PIDF"; exit 0; }
PID="$(cat "$PIDF")"
if kill -0 "$PID" 2>/dev/null && grep -q gunicorn "/proc/$PID/cmdline"; then
  kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID"
  for _ in $(seq 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
fi
rm -f "$PIDF"; echo "stopped $PID"
