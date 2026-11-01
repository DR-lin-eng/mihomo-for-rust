#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: docker-auto-redirect-smoke.sh --core /path/to/Clash.Core [--native]

Runs a Linux smoke for the Rust tun auto-redirect wiring:
1. starts a fake local SOCKS5 proxy server
2. starts Clash.Core with tun.auto-redirect + redir-port + tproxy-port
3. installs a REDIRECT rule that sends TCP flows into redir-port
4. verifies the transparently redirected TCP flow exits via the configured proxy

With `--native`, the script skips the manual host OUTPUT REDIRECT and instead
verifies host-local auto-redirect wiring entirely through the core's own rules.

This script is intended to run inside a Linux container with:
- /dev/net/tun available
- CAP_NET_ADMIN
- iproute2, iptables and python3 installed
EOF
}

CORE=""
NATIVE=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --core) CORE="${2-}"; shift 2 ;;
    --native) NATIVE=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$CORE" ] || { echo "missing --core" >&2; usage >&2; exit 2; }
[ -f "$CORE" ] || { echo "core not found: $CORE" >&2; exit 1; }
[ -c /dev/net/tun ] || { echo "/dev/net/tun is required" >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 is required" >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "iptables is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
DEVICE_NAME="mihauto0"
TARGET_IP="203.0.113.10"
TARGET_PORT="443"
PROXY_PORT="38080"
REDIR_PORT="17891"
TPROXY_PORT="1536"
CORE_PID=""
PROXY_PID=""

cleanup() {
  if [ "$NATIVE" -eq 0 ]; then
    iptables -t nat -D OUTPUT -p tcp -d "${TARGET_IP}" --dport "${TARGET_PORT}" -j REDIRECT --to-ports "${REDIR_PORT}" >/dev/null 2>&1 || true
  fi
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
if payload != b"ping-auto-redirect":
    raise RuntimeError(f"unexpected payload: {payload!r}")
conn.sendall(b"pong-auto-redirect")
conn.shutdown(socket.SHUT_WR)
conn.close()
listener.close()
PY

cat >"$WORKDIR/config.yaml" <<EOF
mode: rule
allow-lan: true
redir-port: ${REDIR_PORT}
tproxy-port: ${TPROXY_PORT}
tun:
  enable: true
  stack: system
  device: ${DEVICE_NAME}
  auto-route: true
  auto-redirect: true
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

deadline=$(( $(date +%s) + 20 ))
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

if [ "$NATIVE" -eq 0 ]; then
  iptables -t nat -I OUTPUT -p tcp -d "${TARGET_IP}" --dport "${TARGET_PORT}" -j REDIRECT --to-ports "${REDIR_PORT}"
fi

python3 - <<'PY'
import socket

sock = socket.create_connection(("203.0.113.10", 443), timeout=5)
sock.settimeout(5)
sock.sendall(b"ping-auto-redirect")
reply = sock.recv(4096)
if reply != b"pong-auto-redirect":
    raise RuntimeError(f"unexpected reply: {reply!r}")
sock.close()
PY

wait "$PROXY_PID"
echo "docker_auto_redirect_smoke=ok"
