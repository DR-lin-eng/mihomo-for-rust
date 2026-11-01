#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: docker-openwrt-like-provider-fakeip-lan-smoke.sh --core /path/to/Clash.Core [--stack system|mixed]

Runs a stronger router-style Linux smoke that combines:
1. a provider-backed SOCKS5 node
2. controller-triggered provider healthcheck
3. fake-ip DNS allocation for a domain
4. a simulated LAN client namespace
5. tun auto-redirect on the PREROUTING path

This script is intended to run inside a Linux container with:
- /dev/net/tun available
- CAP_NET_ADMIN or --privileged
- iproute2, iptables, python3, curl, unshare and nsenter installed
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
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v unshare >/dev/null 2>&1 || { echo "unshare is required" >&2; exit 1; }
command -v nsenter >/dev/null 2>&1 || { echo "nsenter is required" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
DEVICE_NAME="mihreal0"
HOST_VETH="mihreal-host"
CLIENT_VETH="mihreal-peer"
HOST_IP="192.0.2.1"
CLIENT_IP="192.0.2.2"
TARGET_DOMAIN="edge.example.com"
TARGET_IP="203.0.113.10"
TARGET_PORT="443"
PROXY_PORT="38080"
HEALTH_PORT="18080"
CONTROLLER_PORT="19092"
DNS_PORT="1053"
REDIR_PORT="17891"
TPROXY_PORT="1536"
SECRET="123456"
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

cat >"$WORKDIR/provider-socks5.py" <<'PY'
import socket

listener = socket.create_server(("127.0.0.1", 38080), reuse_port=False)
healthcheck_reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
handled_tun_payload = False
listener.settimeout(20)

def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed early")
        data += chunk
    return data

while True:
    conn, _ = listener.accept()
    conn.settimeout(5)

    try:
        greeting = recv_exact(conn, 3)
        if greeting != b"\x05\x01\x00":
            raise RuntimeError(f"unexpected socks5 greeting: {greeting!r}")
        conn.sendall(b"\x05\x00")

        head = recv_exact(conn, 4)
        if head[:3] != b"\x05\x01\x00":
            raise RuntimeError(f"unexpected socks5 request head: {head!r}")
        atyp = head[3]
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
        elif (host, port) == ("edge.example.com", 443):
            payload = recv_exact(conn, len(b"ping-through-realistic-fakeip"))
            if payload != b"ping-through-realistic-fakeip":
                raise RuntimeError(f"unexpected tun payload: {payload!r}")
            conn.sendall(b"pong-through-realistic-fakeip")
            handled_tun_payload = True
        else:
            raise RuntimeError(f"unexpected connect target: {(host, port)!r}")
    except EOFError:
        conn.close()
        continue
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
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
allow-lan: true
external-controller: 127.0.0.1:${CONTROLLER_PORT}
secret: "${SECRET}"
redir-port: ${REDIR_PORT}
tproxy-port: ${TPROXY_PORT}
tun:
  enable: true
  stack: ${STACK}
  device: ${DEVICE_NAME}
  auto-route: true
  auto-redirect: true
  dns-hijack:
    - 0.0.0.0:53
  mtu: 1400
  inet4-address:
    - 198.19.0.1/30
dns:
  enable: true
  listen: 0.0.0.0:${DNS_PORT}
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - system://
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
    health-check:
      enable: true
      url: http://127.0.0.1:${HEALTH_PORT}/delay
      expected-status: 204
proxy-groups:
  - name: auto
    type: select
    use:
      - provider1
rules:
  - DOMAIN-SUFFIX,example.com,auto
  - MATCH,DIRECT
EOF

python3 "$WORKDIR/provider-socks5.py" &
PROXY_PID="$!"
echo "provider_proxy_started=ok"

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
iptables -t nat -I PREROUTING -i "${HOST_VETH}" -p udp --dport 53 -j REDIRECT --to-ports "${DNS_PORT}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

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
  if ip link show dev "$DEVICE_NAME" >/dev/null 2>&1 && \
     curl -fsS -H "Authorization: Bearer ${SECRET}" "http://127.0.0.1:${CONTROLLER_PORT}/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS -H "Authorization: Bearer ${SECRET}" \
  "http://127.0.0.1:${CONTROLLER_PORT}/providers/proxies/provider1/healthcheck?url=http%3A%2F%2F127.0.0.1%3A18080%2Fdelay&timeout=5000&expected=204" >/dev/null
echo "provider_healthcheck_triggered=ok"

python3 - <<'PY'
import json
import time
import urllib.request

req = urllib.request.Request(
    "http://127.0.0.1:19092/providers/proxies/provider1",
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

query_fake_ip() {
  port="$1"
  nsenter -t "${CLIENT_PID}" -n env DNS_PORT="$port" python3 - <<'PY'
import socket
import struct
import os

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
sock.sendto(build_query("edge.example.com"), ("192.0.2.1", int(os.environ["DNS_PORT"])))
data, _ = sock.recvfrom(2048)
print(parse_a_answer(data))
sock.close()
PY
}

DIRECT_DNS_IP="$(query_fake_ip "${DNS_PORT}")"
case "$DIRECT_DNS_IP" in
  198.18.*)
    echo "lan_dns_direct_1053=ok fake_ip=${DIRECT_DNS_IP}"
    ;;
  *)
    echo "unexpected direct lan dns fake ip: $DIRECT_DNS_IP" >&2
    ss -lun || true
    iptables -t nat -vnL PREROUTING || true
    tail -n 80 "$WORKDIR/core.log" || true
    exit 1
    ;;
esac

FAKE_IP="$(query_fake_ip 53)"

case "$FAKE_IP" in
  198.18.*) ;;
  *)
    echo "unexpected fake ip: $FAKE_IP" >&2
    exit 1
    ;;
esac
echo "fake_ip_allocated=${FAKE_IP}"

nsenter -t "${CLIENT_PID}" -n env FAKE_IP="${FAKE_IP}" python3 - <<'PY'
import os
import socket

sock = socket.create_connection((os.environ["FAKE_IP"], 443), timeout=5)
sock.settimeout(5)
sock.sendall(b"ping-through-realistic-fakeip")
reply = sock.recv(4096)
if reply != b"pong-through-realistic-fakeip":
    raise RuntimeError(f"unexpected reply: {reply!r}")
sock.close()
PY
echo "lan_fakeip_roundtrip=ok"

wait "$PROXY_PID"
echo "docker_openwrt_like_provider_fakeip_lan_smoke=ok"
