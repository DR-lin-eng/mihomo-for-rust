#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: docker-provider-tun-healthcheck-smoke.sh --core /path/to/Clash.Core

Runs an end-to-end Linux smoke inside the current namespace that covers:
1. provider-loaded SOCKS5 node
2. controller-triggered provider healthcheck
3. TUN traffic routed through the provider-selected group

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
DEVICE_NAME="mihprov0"
TARGET_IP="203.0.113.10"
TARGET_PORT="443"
PROXY_PORT="38080"
CONTROLLER_PORT="19090"
SECRET="123456"
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

cat >"$WORKDIR/provider-socks5.py" <<'PY'
import socket

listener = socket.create_server(("127.0.0.1", 38080), reuse_port=False)

def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise RuntimeError("connection closed early")
        data += chunk
    return data

healthcheck_reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
handled_tun_payload = False

while True:
    conn, _ = listener.accept()
    conn.settimeout(5)

    greeting = recv_exact(conn, 3)
    if greeting != b"\x05\x01\x00":
        raise RuntimeError(f"unexpected socks5 greeting: {greeting!r}")
    conn.sendall(b"\x05\x00")

    head = recv_exact(conn, 4)
    atyp = head[3]
    if head[:3] != b"\x05\x01\x00":
        raise RuntimeError(f"unexpected socks5 request head: {head!r}")
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(conn, 4))
    elif atyp == 3:
        host = recv_exact(conn, 1)
        host = recv_exact(conn, host[0]).decode()
    else:
        raise RuntimeError(f"unexpected atyp: {atyp!r}")
    port = int.from_bytes(recv_exact(conn, 2), "big")

    conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x90")
    if (host, port) == ("127.0.0.1", 18080):
        payload = recv_exact(conn, len(b"GET /delay HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
        if payload != b"GET /delay HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n":
            raise RuntimeError(f"unexpected healthcheck payload: {payload!r}")
        conn.sendall(healthcheck_reply)
    elif (host, port) == ("203.0.113.10", 443):
        payload = recv_exact(conn, len(b"ping-through-provider-tun"))
        if payload != b"ping-through-provider-tun":
            raise RuntimeError(f"unexpected tun payload: {payload!r}")
        conn.sendall(b"pong-through-provider-tun")
        handled_tun_payload = True
    else:
        raise RuntimeError(f"unexpected connect target: {(host, port)!r}")
    conn.shutdown(socket.SHUT_WR)
    conn.close()
    if handled_tun_payload:
        break

listener.close()
PY

cat >"$WORKDIR/provider.yaml" <<EOF
proxies:
  - name: provider-a
    type: socks5
    server: 127.0.0.1
    port: ${PROXY_PORT}
    udp: true
EOF

cat >"$WORKDIR/config.yaml" <<EOF
mode: rule
external-controller: 127.0.0.1:${CONTROLLER_PORT}
secret: "${SECRET}"
tun:
  enable: true
  stack: system
  device: ${DEVICE_NAME}
  mtu: 1400
  inet4-address:
    - 198.19.0.1/30
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
    health-check:
      enable: true
      url: http://127.0.0.1:18080/delay
      expected-status: 204
proxy-groups:
  - name: auto
    type: select
    use:
      - provider1
rules:
  - MATCH,auto
EOF

python3 "$WORKDIR/provider-socks5.py" &
PROXY_PID="$!"
echo "provider_proxy_started=ok"

MIHOMO_FORCE_NATIVE_RUNTIME=1 \
  "$CORE" -d "$WORKDIR" -f "$WORKDIR/config.yaml" >"$WORKDIR/core.log" 2>&1 &
CORE_PID="$!"
echo "core_started=ok"

for _ in $(seq 1 20); do
  if ! kill -0 "$CORE_PID" 2>/dev/null; then
    echo "core exited early" >&2
    cat "$WORKDIR/core.log" >&2 || true
    exit 1
  fi
  if curl -fsS -H "Authorization: Bearer ${SECRET}" "http://127.0.0.1:${CONTROLLER_PORT}/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS -H "Authorization: Bearer ${SECRET}" \
  "http://127.0.0.1:${CONTROLLER_PORT}/providers/proxies/provider1/healthcheck?url=http%3A%2F%2F127.0.0.1%3A18080%2Fdelay&timeout=5000&expected=204" >/dev/null
echo "provider_healthcheck_triggered=ok"

python3 - <<'PY'
import json, time, urllib.request
req = urllib.request.Request(
    "http://127.0.0.1:19090/providers/proxies/provider1",
    headers={"Authorization": "Bearer 123456"},
)
for _ in range(20):
    data = json.load(urllib.request.urlopen(req, timeout=5))
    proxies = data.get("proxies", [])
    if proxies and proxies[0].get("alive") and proxies[0].get("history"):
        break
    time.sleep(0.5)
else:
    print(json.dumps(data))
    raise SystemExit(1)
PY
echo "provider_healthcheck_observed=ok"

for _ in $(seq 1 20); do
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
echo "tun_route_installed=ok"

python3 - <<'PY'
import socket

sock = socket.create_connection(("203.0.113.10", 443), timeout=5)
sock.settimeout(5)
sock.sendall(b"ping-through-provider-tun")
reply = sock.recv(4096)
if reply != b"pong-through-provider-tun":
    raise RuntimeError(f"unexpected reply: {reply!r}")
sock.close()
PY
echo "provider_tun_tcp_roundtrip=ok"

wait "$PROXY_PID"
echo "docker_provider_tun_healthcheck_smoke=ok"
