#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi
# Must stay in sync with scripts/run-foreground.sh and the systemd unit.
# When RUNTIME_DIR is unset, probe the same writable fallback locations so a
# standalone stop.sh can find a foreground service started under systemd.
if [ -z "${RUNTIME_DIR:-}" ]; then
  if [ -d "$ROOT_DIR/runtime" ] && [ -w "$ROOT_DIR/runtime" ]; then
    RUNTIME_DIR=$ROOT_DIR/runtime
  elif [ -d /var/lib/headful-auth-tunnel ] && [ -w /var/lib/headful-auth-tunnel ]; then
    RUNTIME_DIR=/var/lib/headful-auth-tunnel
  elif [ -d /run/headful-auth-tunnel ] && [ -w /run/headful-auth-tunnel ]; then
    RUNTIME_DIR=/run/headful-auth-tunnel
  else
    RUNTIME_DIR=$ROOT_DIR/runtime
  fi
fi
PID_FILE=${PID_FILE:-$RUNTIME_DIR/tunnel.pid}
XVFB_PID_FILE=${XVFB_PID_FILE:-$RUNTIME_DIR/xvfb.pid}

stop_owned_process() {
  pid_file=$1
  pattern=$2
  label=$3
  [ -f "$pid_file" ] || return 0
  pid=$(cat "$pid_file" 2>/dev/null || true)
  if [ -z "$pid" ] || [ ! -r "/proc/$pid/cmdline" ]; then
    rm -f "$pid_file"
    return 0
  fi
  if ! tr '\000' ' ' < "/proc/$pid/cmdline" | grep -F "$pattern" >/dev/null 2>&1; then
    echo "Refusing to stop pid $pid: it is not $label" >&2
    rm -f "$pid_file"
    return 1
  fi
  kill "$pid" 2>/dev/null || true
  i=0
  while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
  echo "Stopped $label (pid $pid)"
}

# set -e would abort the script on a refusal, orphaning Xvfb; run both and
# still clean up. Refusal exits 0 after removing the stale pid file.
stop_owned_process "$PID_FILE" "headful" "Headful Auth Tunnel" || true
stop_owned_process "$XVFB_PID_FILE" "Xvfb" "Xvfb" || true
