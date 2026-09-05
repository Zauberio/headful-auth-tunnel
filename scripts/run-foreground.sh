#!/bin/sh
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi
DISPLAY=${DISPLAY:-:99}
SCREEN_WIDTH=${SCREEN_WIDTH:-1440}
SCREEN_HEIGHT=${SCREEN_HEIGHT:-1100}
export DISPLAY SCREEN_WIDTH SCREEN_HEIGHT
# $ROOT_DIR/runtime is read-only under systemd ProtectSystem=strict.
# This block must stay in sync with scripts/stop.sh and the systemd unit's
# RUNTIME_DIR so a standalone stop.sh can find the foreground service.
if [ -z "${RUNTIME_DIR:-}" ]; then
  if mkdir -p "$ROOT_DIR/runtime" 2>/dev/null && [ -w "$ROOT_DIR/runtime" ]; then
    RUNTIME_DIR=$ROOT_DIR/runtime
  elif mkdir -p /var/lib/headful-auth-tunnel 2>/dev/null && [ -w /var/lib/headful-auth-tunnel ]; then
    RUNTIME_DIR=/var/lib/headful-auth-tunnel
  else
    RUNTIME_DIR=/run/headful-auth-tunnel
  fi
fi
XVFB_PID_FILE=${XVFB_PID_FILE:-$RUNTIME_DIR/xvfb.pid}
PID_FILE=${PID_FILE:-$RUNTIME_DIR/tunnel.pid}
mkdir -p "$RUNTIME_DIR"

# Termination helper and cleanup must be installed BEFORE starting Xvfb
# so a failed pid-file write (set -e) cannot orphan the display server,
# and so PID files remain until children have actually exited.
terminate_child() {
  pid=$1
  [ -z "$pid" ] && return 0
  kill "$pid" 2>/dev/null || true
  i=0
  while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
}

xvfb_pid=""
app_pid=""
cleanup() {
  # Bounded wait before removing PID files — a slow child must not remain
  # alive without a record that a later scripts/stop.sh could use.
  [ -z "$app_pid" ] || terminate_child "$app_pid"
  [ -z "$xvfb_pid" ] || terminate_child "$xvfb_pid"
  rm -f "$PID_FILE" "$XVFB_PID_FILE"
}
trap cleanup EXIT INT TERM

Xvfb "$DISPLAY" -screen 0 "${SCREEN_WIDTH}x${SCREEN_HEIGHT}x24" -nolisten tcp -ac &
xvfb_pid=$!
printf '%s\n' "$xvfb_pid" > "$XVFB_PID_FILE"
sleep 1

if [ "$#" -gt 0 ]; then
  "$@" &
elif command -v headful-auth-tunnel >/dev/null 2>&1; then
  headful-auth-tunnel &
else
  python3 -m headful_auth_tunnel.server &
fi
app_pid=$!
printf '%s\n' "$app_pid" > "$PID_FILE"
wait "$app_pid"
