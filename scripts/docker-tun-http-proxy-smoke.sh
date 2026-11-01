#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: docker-tun-http-proxy-smoke.sh --core /path/to/Clash.Core

Runs an end-to-end Linux TUN smoke inside the current namespace:
1. starts a fake local SOCKS5 proxy server
2. starts the Rust Clash.Core with a named TUN device
3. installs a /32 route through the TUN
4. verifies a TCP exchange reaches the fake proxy via SOCKS5 CONNECT

This script is intended to run inside a Linux container with:
- /dev/net/tun available
- CAP_NET_ADMIN
- iproute2 and python3 installed
EOF
}

CORE=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --core) CORE="${2-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$CORE" ] || { echo "missing --core" >&2; usage >&2; exit 2; }
[ -f "$CORE" ] || { echo "core not found: $CORE" >&2; exit 1; }
[ -c /dev/net/tun ] || { echo "/dev/net/tun is required" >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
DEVICE_NAME="mihsmoke0"
TARGET_IP="203.0.113.10"
TARGET_PORT="443"
TARGET_ADDR="${TARGET_IP}:${TARGET_PORT}"
PROXY_PORT="38080"
CORE_PID=""
PROXY_PID=""

cleanup() {
  ip route del "${TARGET_IP}/32" dev "${DEVICE_NAME}" >/dev/null 2>&1 || true
  if [ -n "$CORE_PID" ]; then
    kill "$CORE_PID" >/dev/null 2>&1 || true
    wait "$CORE_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}

trap cleanup EXIT INT TERM

cat >"$WORKDIR/proxy.py" <<'PY'
import socket

listener = socket.create_server(("127.0.0.1", 38080), reuse_port=False)
conn, _ = listener.accept()
conn.settimeout(5)

greeting = conn.recv(3)
if greeting != b"\x05\x01\x00":
    raise RuntimeError(f"unexpected socks5 greeting: {greeting!r}")
conn.sendall(b"\x05\x00")

request = conn.recv(10)
expected = b"\x05\x01\x00\x01\xcb\x00\x71\x0a\x01\xbb"
if request != expected:
    raise RuntimeError(f"unexpected socks5 connect request: {request!r}")

conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x90")
payload = conn.recv(4096)
if payload != b"ping-through-tun":
    raise RuntimeError(f"unexpected payload: {payload!r}")
conn.sendall(b"pong-through-tun")
conn.shutdown(socket.SHUT_WR)
conn.close()
listener.close()
PY

cat >"$WORKDIR/config.yaml" <<EOF
mode: rule
tun:
  enable: true
  stack: system
  device: ${DEVICE_NAME}
  mtu: 1400
  inet4-address:
    - 198.19.0.1/30
proxies:
  - type: socks5
    name: edge-socks5
    server: 127.0.0.1
    port: ${PROXY_PORT}
    udp: true
rules:
  - MATCH,edge-socks5
EOF

python3 "$WORKDIR/proxy.py" &
PROXY_PID="$!"

MIHOMO_FORCE_NATIVE_RUNTIME=1 \
  "$CORE" -d "$WORKDIR" -f "$WORKDIR/config.yaml" >"$WORKDIR/core.log" 2>&1 &
CORE_PID="$!"

deadline=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$CORE_PID" 2>/dev/null; then
    echo "core exited early" >&2
    cat "$WORKDIR/core.log" >&2 || true
    exit 1
  fi
  if ip link show dev "$DEVICE_NAME" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ip link show dev "$DEVICE_NAME" >/dev/null 2>&1 || {
  echo "tun device did not appear" >&2
  cat "$WORKDIR/core.log" >&2 || true
  exit 1
}

ip route replace "${TARGET_IP}/32" dev "$DEVICE_NAME"

python3 - <<'PY'
import socket

sock = socket.create_connection(("203.0.113.10", 443), timeout=5)
sock.settimeout(5)
sock.sendall(b"ping-through-tun")
reply = sock.recv(4096)
if reply != b"pong-through-tun":
    raise RuntimeError(f"unexpected reply: {reply!r}")
sock.close()
PY

wait "$PROXY_PID"
echo "docker_tun_socks5_proxy_smoke=ok"
