#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: docker-auto-redirect-lan-smoke.sh --core /path/to/Clash.Core [--stack system|mixed]

Runs a Linux smoke for tun auto-redirect using a simulated LAN client:
1. starts a fake local SOCKS5 proxy server
2. creates a veth pair and client network namespace
3. starts Clash.Core with tun.auto-redirect
4. verifies TCP traffic from the LAN-side PREROUTING path is redirected and proxied

This script is intended to run inside a Linux container with:
- /dev/net/tun available
- CAP_NET_ADMIN or --privileged
- iproute2, iptables, python3, unshare and nsenter installed
EOF
}

CORE=""
STACK="system"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --core) CORE="${2-}"; shift 2 ;;
    --stack) STACK="${2-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$CORE" ] || { echo "missing --core" >&2; usage >&2; exit 2; }
[ -f "$CORE" ] || { echo "core not found: $CORE" >&2; exit 1; }
[ "$STACK" = "system" ] || [ "$STACK" = "mixed" ] || { echo "unsupported --stack: $STACK" >&2; usage >&2; exit 2; }
[ -c /dev/net/tun ] || { echo "/dev/net/tun is required" >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 is required" >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "iptables is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v unshare >/dev/null 2>&1 || { echo "unshare is required" >&2; exit 1; }
command -v nsenter >/dev/null 2>&1 || { echo "nsenter is required" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
DEVICE_NAME="mihlan0"
TARGET_IP="203.0.113.10"
TARGET_PORT="443"
PROXY_PORT="38080"
REDIR_PORT="17891"
TPROXY_PORT="1536"
HOST_VETH="mihlan-host"
CLIENT_VETH="mihlan-peer"
HOST_IP="192.0.2.1"
CLIENT_IP="192.0.2.2"
CORE_PID=""
PROXY_PID=""
CLIENT_PID=""

cleanup() {
  ip link del "${HOST_VETH}" >/dev/null 2>&1 || true
  if [ -n "$CLIENT_PID" ]; then
    kill "$CLIENT_PID" >/dev/null 2>&1 || true
    wait "$CLIENT_PID" >/dev/null 2>&1 || true
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
if payload != b"ping-lan-auto-redirect":
    raise RuntimeError(f"unexpected payload: {payload!r}")
conn.sendall(b"pong-lan-auto-redirect")
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
  stack: ${STACK}
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

unshare -n sh -c 'sleep 600' &
CLIENT_PID="$!"
sleep 1

ip link add "${HOST_VETH}" type veth peer name "${CLIENT_VETH}"
ip link set "${CLIENT_VETH}" netns "${CLIENT_PID}"
ip addr add "${HOST_IP}/24" dev "${HOST_VETH}"
ip link set "${HOST_VETH}" up
nsenter -t "${CLIENT_PID}" -n ip addr add "${CLIENT_IP}/24" dev "${CLIENT_VETH}"
nsenter -t "${CLIENT_PID}" -n ip link set lo up
nsenter -t "${CLIENT_PID}" -n ip link set "${CLIENT_VETH}" up
nsenter -t "${CLIENT_PID}" -n ip route add default via "${HOST_IP}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

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

nsenter -t "${CLIENT_PID}" -n python3 - <<'PY'
import socket

sock = socket.socket()
sock.settimeout(5)
sock.connect(("203.0.113.10", 443))
sock.sendall(b"ping-lan-auto-redirect")
reply = sock.recv(4096)
if reply != b"pong-lan-auto-redirect":
    raise RuntimeError(f"unexpected reply: {reply!r}")
sock.close()
PY

wait "$PROXY_PID"
echo "docker_auto_redirect_lan_smoke=ok"
