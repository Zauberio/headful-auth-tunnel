#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

RUNTIME_DIR=${RUNTIME_DIR:-$ROOT_DIR/runtime}
PROFILE_DIR=${PROFILE_DIR:-$ROOT_DIR/profile}
TOKEN_FILE=${TOKEN_FILE:-$RUNTIME_DIR/token}
LOG_FILE=${LOG_FILE:-$RUNTIME_DIR/tunnel.log}
PID_FILE=${PID_FILE:-$RUNTIME_DIR/tunnel.pid}
XVFB_PID_FILE=${XVFB_PID_FILE:-$RUNTIME_DIR/xvfb.pid}
DISPLAY=${DISPLAY:-:99}
SCREEN_WIDTH=${SCREEN_WIDTH:-1440}
SCREEN_HEIGHT=${SCREEN_HEIGHT:-1100}
PORT=${PORT:-19192}

mkdir -p "$RUNTIME_DIR" "$PROFILE_DIR"
chmod 700 "$RUNTIME_DIR" "$PROFILE_DIR" 2>/dev/null || true
export PROFILE_DIR TOKEN_FILE DISPLAY SCREEN_WIDTH SCREEN_HEIGHT PORT

process_matches() {
  pid=$1
  pattern=$2
  [ -r "/proc/$pid/cmdline" ] || return 1
  tr '\000' ' ' < "/proc/$pid/cmdline" | grep -F "$pattern" >/dev/null 2>&1
}

if [ -f "$PID_FILE" ]; then
  old_pid=$(cat "$PID_FILE" 2>/dev/null || true)
  if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null && process_matches "$old_pid" "headful"; then
    echo "Already running (pid $old_pid)"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

xnum=${DISPLAY#:}
xnum=${xnum%%.*}
xsocket=/tmp/.X11-unix/X$xnum
started_xvfb=0
if [ ! -S "$xsocket" ]; then
  command -v Xvfb >/dev/null 2>&1 || { echo "Xvfb is required" >&2; exit 1; }
  Xvfb "$DISPLAY" -screen 0 "${SCREEN_WIDTH}x${SCREEN_HEIGHT}x24" -nolisten tcp -ac \
    >"$RUNTIME_DIR/xvfb.log" 2>&1 &
  xvfb_pid=$!
  printf '%s\n' "$xvfb_pid" > "$XVFB_PID_FILE"
  started_xvfb=1
  i=0
  while [ ! -S "$xsocket" ] && [ "$i" -lt 40 ]; do
    kill -0 "$xvfb_pid" 2>/dev/null || break
    sleep 0.25
    i=$((i + 1))
  done
  if [ ! -S "$xsocket" ]; then
    echo "Xvfb failed to start; see $RUNTIME_DIR/xvfb.log" >&2
    exit 1
  fi
fi

if [ -x "$ROOT_DIR/.venv/bin/headful-auth-tunnel" ]; then
  set -- "$ROOT_DIR/.venv/bin/headful-auth-tunnel"
else
  set -- python3 -m headful_auth_tunnel.server
fi

if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  readiness_nonce=$("$ROOT_DIR/.venv/bin/python" -c 'import secrets; print(secrets.token_hex(16))')
else
  readiness_nonce=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
fi
HEADFUL_READINESS_NONCE=$readiness_nonce
export HEADFUL_READINESS_NONCE

cd "$ROOT_DIR"
nohup "$@" >"$LOG_FILE" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$PID_FILE"

scheme=http
[ -z "${TLS_CERT:-}" ] || scheme=https
i=0
ready=0
while [ "$i" -lt 60 ]; do
  if ! kill -0 "$pid" 2>/dev/null; then
    break
  fi
  if command -v curl >/dev/null 2>&1; then
    if [ "$scheme" = https ] && [ -n "${TLS_CA_FILE:-}" ] && [ -f "$TLS_CA_FILE" ]; then
      health=$(curl -fsS --max-time 2 --cacert "$TLS_CA_FILE" "$scheme://127.0.0.1:$PORT/health" 2>/dev/null || true)
    else
      health=$(curl -kfsS --max-time 2 "$scheme://127.0.0.1:$PORT/health" 2>/dev/null || true)
    fi
    if kill -0 "$pid" 2>/dev/null && printf '%s' "$health" | grep -Fq "\"readiness_nonce\":\"$readiness_nonce\""; then
      ready=1
      break
    fi
  fi
  sleep 0.5
  i=$((i + 1))
done

if [ "$ready" -ne 1 ]; then
  echo "Tunnel failed readiness check; last log lines:" >&2
  tail -30 "$LOG_FILE" >&2 2>/dev/null || true
  kill "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  if [ "$started_xvfb" -eq 1 ]; then
    kill "$xvfb_pid" 2>/dev/null || true
    rm -f "$XVFB_PID_FILE"
  fi
  exit 1
fi

host=${BIND_HOST:-127.0.0.1}
echo "Started Headful Auth Tunnel (pid $pid)"
echo "URL: $scheme://$host:$PORT/"
echo "Token file: $TOKEN_FILE"
