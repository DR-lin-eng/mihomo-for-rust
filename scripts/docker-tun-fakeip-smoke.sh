#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: docker-tun-fakeip-smoke.sh --core /path/to/Clash.Core

Runs an end-to-end Linux TUN smoke for fake-ip backed routing:
1. starts a fake local SOCKS5 proxy server
2. starts Clash.Core with TUN + fake-ip DNS + a domain-based rule
3. allocates a fake IP for a domain through the controller DNS runtime
4. routes a TCP flow to that fake IP through the TUN device
5. verifies the domain rule is selected and the proxy receives CONNECT to the original target

This script is intended to run inside a Linux container with:
- /dev/net/tun available
- CAP_NET_ADMIN or --privileged
- iproute2, python3 and curl installed
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
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
DEVICE_NAME="mihfake0"
TARGET_DOMAIN="edge.example.com"
TARGET_IP="203.0.113.10"
TARGET_PORT="443"
PROXY_PORT="38080"
CONTROLLER_PORT="19091"
DNS_PORT="1053"
SECRET="123456"
CORE_PID=""
PROXY_PID=""

cleanup() {
  if [ -n "${FAKE_IP:-}" ]; then
    ip route del "${FAKE_IP}/32" dev "${DEVICE_NAME}" >/dev/null 2>&1 || true
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

head = conn.recv(5)
if head[:3] != b"\x05\x01\x00":
    raise RuntimeError(f"unexpected socks5 request head: {head!r}")
atyp = head[3]
if atyp == 1:
    request = head + conn.recv(5)
    expected = b"\x05\x01\x00\x01\xcb\x00\x71\x0a\x01\xbb"
    if request != expected:
        raise RuntimeError(f"unexpected socks5 ipv4 connect request: {request!r}")
elif atyp == 3:
    domain_len = head[4]
    domain = conn.recv(domain_len).decode()
    port = int.from_bytes(conn.recv(2), "big")
    if domain != "edge.example.com" or port != 443:
        raise RuntimeError(f"unexpected socks5 domain connect request: {(domain, port)!r}")
else:
    raise RuntimeError(f"unexpected socks5 atyp: {atyp!r}")

conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x90")
payload = conn.recv(4096)
if payload != b"ping-through-fakeip-tun":
    raise RuntimeError(f"unexpected payload: {payload!r}")
conn.sendall(b"pong-through-fakeip-tun")
conn.shutdown(socket.SHUT_WR)
conn.close()
listener.close()
PY

cat >"$WORKDIR/config.yaml" <<EOF
mode: rule
external-controller: 127.0.0.1:${CONTROLLER_PORT}
secret: "${SECRET}"
tun:
  enable: true
  stack: system
  device: ${DEVICE_NAME}
  mtu: 1400
  dns-hijack:
    - 0.0.0.0:53
  inet4-address:
    - 198.19.0.1/30
dns:
  enable: true
  listen: 127.0.0.1:${DNS_PORT}
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - system://
proxies:
  - type: socks5
    name: edge-socks5
    server: 127.0.0.1
    port: ${PROXY_PORT}
    udp: true
rules:
  - DOMAIN-SUFFIX,example.com,edge-socks5
  - MATCH,DIRECT
EOF

python3 "$WORKDIR/proxy.py" &
PROXY_PID="$!"

MIHOMO_FORCE_NATIVE_RUNTIME=1 \
  "$CORE" -d "$WORKDIR" -f "$WORKDIR/config.yaml" >"$WORKDIR/core.log" 2>&1 &
CORE_PID="$!"

for _ in $(seq 1 20); do
  if ! kill -0 "$CORE_PID" 2>/dev/null; then
    echo "core exited early" >&2
    cat "$WORKDIR/core.log" >&2 || true
    exit 1
  fi
  if ip link show dev "$DEVICE_NAME" >/dev/null 2>&1 && \
     curl -fsS -H "Authorization: Bearer ${SECRET}" "http://127.0.0.1:${CONTROLLER_PORT}/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ip link show dev "$DEVICE_NAME" >/dev/null 2>&1 || {
  echo "tun device did not appear" >&2
  cat "$WORKDIR/core.log" >&2 || true
  exit 1
}

python3 - <<'PY'
import socket
import time

deadline = time.time() + 10
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    try:
        sock.sendto(b"\x00", ("127.0.0.1", 1053))
        break
    except OSError:
        time.sleep(0.2)
    finally:
        sock.close()
else:
    raise SystemExit("dns listener did not become ready")
PY

FAKE_IP="$(python3 - <<'PY'
import socket
import struct

def build_query(name: str, qid: int = 0x4321) -> bytes:
    parts = name.split(".")
    qname = b"".join(bytes([len(part)]) + part.encode() for part in parts) + b"\x00"
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    return header + question

def parse_a_answer(packet: bytes, qid: int = 0x4321) -> str:
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if rid != qid or ancount < 1:
        raise RuntimeError("unexpected dns response header")
    offset = 12
    while packet[offset] != 0:
        offset += 1 + packet[offset]
    offset += 1 + 4
    if packet[offset] & 0xC0 == 0xC0:
        offset += 2
    else:
        raise RuntimeError("expected compressed answer name")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset+10])
    offset += 10
    if rtype != 1 or rclass != 1 or rdlen != 4:
        raise RuntimeError("unexpected answer record")
    return socket.inet_ntoa(packet[offset:offset+4])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(build_query("edge.example.com"), ("127.0.0.1", 1053))
data, _ = sock.recvfrom(2048)
print(parse_a_answer(data))
sock.close()
PY
)"

case "$FAKE_IP" in
  198.18.*) ;;
  *)
    echo "unexpected fake ip: $FAKE_IP" >&2
    exit 1
    ;;
esac

SELECTED="$(python3 - <<'PY'
import json
import urllib.request

req = urllib.request.Request(
    "http://127.0.0.1:19091/proxies",
    headers={"Authorization": "Bearer 123456"},
)
data = json.load(urllib.request.urlopen(req, timeout=5))
print(data["proxies"]["GLOBAL"]["now"])
PY
)" || true
echo "controller_global_now=${SELECTED:-<unavailable>}"

ip route replace "${FAKE_IP}/32" dev "${DEVICE_NAME}"

FAKE_IP="$FAKE_IP" python3 - <<'PY'
import socket
import os

sock = socket.create_connection((os.environ["FAKE_IP"], 443), timeout=5)
sock.settimeout(5)
sock.sendall(b"ping-through-fakeip-tun")
reply = sock.recv(4096)
if reply != b"pong-through-fakeip-tun":
    raise RuntimeError(f"unexpected reply: {reply!r}")
sock.close()
PY

wait "$PROXY_PID"
echo "docker_tun_fakeip_smoke=ok fake_ip=${FAKE_IP}"
