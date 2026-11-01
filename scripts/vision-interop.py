#!/usr/bin/env python3
"""Offline integration test: native mihomo SOCKS -> official Xray -> local fixtures.
Run inside Docker with the two binaries supplied by docker-vision-interop.sh.
"""
import argparse
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time

USER = "b831381d-6324-4d53-ad4f-8cda48b30811"
PAYLOAD = bytes(range(256)) * 2048  # 512 KiB in each direction.


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError(f"expected {size} bytes; received {len(data)}")
        data.extend(part)
    return bytes(data)


def socks_reply(sock):
    header = exact(sock, 4)
    assert header[:2] == b"\x05\x00", header
    size = {1: 4, 4: 16}.get(header[3])
    if header[3] == 3:
        size = exact(sock, 1)[0]
    addr = exact(sock, size)
    port = struct.unpack("!H", exact(sock, 2))[0]
    return socket.inet_ntoa(addr) if header[3] == 1 else "127.0.0.1", port


def socks(port, destination, command=1):
    sock = socket.create_connection(("127.0.0.1", port), timeout=15)
    sock.sendall(b"\x05\x01\x00")
    assert exact(sock, 2) == b"\x05\x00"
    sock.sendall(b"\x05" + bytes([command]) + b"\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", destination))
    relay = socks_reply(sock)
    return sock, relay


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.send_header("X-Upload-SHA256", hashlib.sha256(body).hexdigest())
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(PAYLOAD)
        self.close_connection = True

    def log_message(self, *_):
        pass


class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        self.request.sendall(b"vision-ready\n")
        assert exact(self.request, 4) == b"ack\n"
        self.request.sendall(b"done\n")


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def http_fixture(cert, key, version=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    if version:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["h2", "http/1.1"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@contextlib.contextmanager
def process(args, log_path, env=None):
    with open(log_path, "w") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def wait_port(port, proc, log_path):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited: {Path(log_path).read_text()[-5000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not become ready")


def transfer(socks_port, target_port, version):
    sock, _ = socks(socks_port, target_port)
    with sock:
        if version:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = context.maximum_version = version
            sock = context.wrap_socket(sock, server_hostname="localhost")
        with sock:
            sock.sendall((f"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(PAYLOAD)}\r\nConnection: close\r\n\r\n").encode())
            sock.sendall(PAYLOAD)
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read()
            assert response.status == 200, response.status
            assert response.getheader("X-Upload-SHA256") == hashlib.sha256(PAYLOAD).hexdigest()
            assert body == PAYLOAD, (len(body), len(PAYLOAD))


def udp_transfer(socks_port, echo_port):
    control, relay = socks(socks_port, 0, command=3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(15)
        for size in [1, 256, 1500, 4096, 8190]:
            data = PAYLOAD[:size]
            packet = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", echo_port) + data
            udp.sendto(packet, relay)
            reply, _ = udp.recvfrom(65536)
            assert reply[:4] == b"\x00\x00\x00\x01", reply[:20]
            assert reply[10:] == data, (len(reply), size)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", default="/target/debug/mihomo")
    parser.add_argument("--xray", default="/tmp/xray")
    parser.add_argument("--sing-box", default="/tmp/sing-box")
    parser.add_argument("--server", choices=["xray", "sing-box"], default="xray")
    parser.add_argument("--camouflage-alpn", default="h2,http/1.1")
    parser.add_argument("--client-alpn", default=None)
    parser.add_argument("--mlkem", choices=["on", "off"], default="on")
    parser.add_argument("--output", default=None)
    parser.add_argument("--security", choices=["all", "tls", "reality"], default="all")
    args = parser.parse_args()
    work = Path(args.output or tempfile.mkdtemp(prefix="vision-interop-"))
    work.mkdir(parents=True, exist_ok=True)
    cert, key = work / "fixture.crt", work / "fixture.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
    http = http_fixture(cert, key)
    tls12 = http_fixture(cert, key, ssl.TLSVersion.TLSv1_2)
    tls13 = http_fixture(cert, key, ssl.TLSVersion.TLSv1_3)
    banner = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
    banner.daemon_threads = True
    threading.Thread(target=banner.serve_forever, daemon=True).start()
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    keypair = subprocess.check_output([args.xray, "x25519"], text=True)
    fields = dict(line.split(": ", 1) for line in keypair.strip().splitlines() if ": " in line)
    private_key = fields["PrivateKey"]
    public_key = fields.get("Password (PublicKey)", fields.get("Password", fields.get("PublicKey")))
    assert public_key
    tls_port, reality_port, camouflage_port = free_port(), free_port(), free_port()
    tls_settings = {"minVersion": "1.3", "maxVersion": "1.3", "alpn": args.camouflage_alpn.split(","), "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}
    inbounds = [
        {"listen": "127.0.0.1", "port": tls_port, "protocol": "vless", "settings": {"clients": [{"id": USER, "flow": "xtls-rprx-vision"}], "decryption": "none"}, "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls_settings}},
        # REALITY borrows this Xray TLS server's recorded flight. Using an
        # independent Xray target avoids a Python/OpenSSL record-size quirk.
        {"listen": "127.0.0.1", "port": camouflage_port, "protocol": "vless", "settings": {"clients": [{"id": USER}], "decryption": "none"}, "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls_settings}},
    ]
    inbounds.append({"listen": "127.0.0.1", "port": reality_port, "protocol": "vless", "settings": {"clients": [{"id": USER, "flow": "xtls-rprx-vision"}], "decryption": "none"}, "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {"target": f"127.0.0.1:{camouflage_port}", "serverNames": ["localhost"], "privateKey": private_key, "shortIds": ["abcd"], "show": True}}})
    server_config = work / "xray.json"
    server_config.write_text(json.dumps({"log": {"loglevel": "debug"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]}))
    singbox_config = work / "sing-box.json"
    if args.server == "sing-box":
        sing_tls_port, sing_reality_port = free_port(), free_port()
        sing_tls = {"enabled": True, "server_name": "localhost", "min_version": "1.3", "max_version": "1.3", "alpn": args.camouflage_alpn.split(","), "certificate_path": str(cert), "key_path": str(key)}
        sing_reality = {"enabled": True, "server_name": "localhost", "reality": {"enabled": True, "handshake": {"server": "127.0.0.1", "server_port": camouflage_port}, "private_key": private_key, "short_id": ["abcd"]}}
        singbox_config.write_text(json.dumps({"log": {"level": "debug", "timestamp": True}, "inbounds": [
            {"type": "vless", "tag": "tls", "listen": "127.0.0.1", "listen_port": sing_tls_port, "users": [{"uuid": USER, "flow": "xtls-rprx-vision"}], "tls": sing_tls},
            {"type": "vless", "tag": "reality", "listen": "127.0.0.1", "listen_port": sing_reality_port, "users": [{"uuid": USER, "flow": "xtls-rprx-vision"}], "tls": sing_reality},
        ], "outbounds": [{"type": "direct", "tag": "direct"}]}))
        tls_port, reality_port = sing_tls_port, sing_reality_port
    env = {**os.environ, "MIHOMO_FORCE_NATIVE_RUNTIME": "1"}
    results = []
    xray_log = work / "xray.log"
    try:
        with contextlib.ExitStack() as stack:
            xray = stack.enter_context(process([args.xray, "run", "-c", str(server_config)], xray_log))
            wait_port(camouflage_port, xray, xray_log)
            if args.server == "sing-box":
                singbox_log = work / "sing-box.log"
                singbox = stack.enter_context(process([args.sing_box, "run", "-c", str(singbox_config)], singbox_log))
                wait_port(tls_port, singbox, singbox_log)
            for security, port in [("tls", tls_port), ("reality", reality_port)]:
                if args.security != "all" and args.security != security:
                    continue
                for xudp in [False, True]:
                    label = f"{security}-{'xudp' if xudp else 'udp'}"
                    socks_port = free_port()
                    proxy = {"name": "vision", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": USER, "tls": True, "servername": "localhost", "skip-cert-verify": True, "flow": "xtls-rprx-vision", "network": "tcp", "udp": True, "xudp": xudp, "client-fingerprint": "chrome"}
                    if security == "reality":
                        proxy["reality-opts"] = {"public-key": public_key, "short-id": "abcd", "support-x25519mlkem768": args.mlkem == "on"}
                    if args.client_alpn is not None:
                        proxy["alpn"] = args.client_alpn.split(",")
                    config = work / f"mihomo-{label}.json"
                    config.write_text(json.dumps({"listeners": [{"name": "vision-test", "type": "mixed", "listen": "127.0.0.1", "port": socks_port, "udp": True}], "mode": "rule", "log-level": "debug", "ipv6": False, "dns": {"enable": False}, "proxies": [proxy], "rules": ["MATCH,vision"]}))
                    log = work / f"mihomo-{label}.log"
                    state_dir = work / f"state-{label}"
                    state_dir.mkdir(exist_ok=True)
                    with process([args.mihomo, "-d", str(state_dir), "-f", str(config)], log, env) as mihomo:
                        wait_port(socks_port, mihomo, log)
                        if not xudp:
                            for version, target in [(None, http), (ssl.TLSVersion.TLSv1_2, tls12), (ssl.TLSVersion.TLSv1_3, tls13)]:
                                name = f"{label}/{version.name if version else 'plain-http'}"
                                transfer(socks_port, target.server_port, version)
                                results.append(name)
                                print(f"PASS {name}: 512 KiB upload + 512 KiB download", flush=True)
                        if not xudp:
                            banner_sock, _ = socks(socks_port, banner.server_address[1])
                            with banner_sock:
                                assert exact(banner_sock, 13) == b"vision-ready\n"
                                banner_sock.sendall(b"ack\n")
                                assert exact(banner_sock, 5) == b"done\n"
                            results.append(f"{label}/server-first")
                            print(f"PASS {label}: server speaks first", flush=True)
                        udp_transfer(socks_port, echo.server_address[1])
                        results.append(f"{label}/datagrams")
                        print(f"PASS {label}: UDP echo sizes 1, 256, 1500, 4096, 8190", flush=True)
        text = xray_log.read_text()
        # Require direct-copy evidence from the independent server, in addition
        # to checking every byte of the application transfers.
        direct_reads = [line for line in text.splitlines() if "Xtls Unpadding" in line and "command 2" in line]
        direct_writes = [line for line in text.splitlines() if "XtlsPadding" in line and line.endswith(" 2")]
        expected = 2 if args.security == "all" else 1
        if args.server == "xray":
            assert len(direct_reads) >= expected and len(direct_writes) >= expected, "Xray did not confirm both directions of TLS/REALITY Vision direct copy"
        direct_lines = direct_reads + direct_writes
        report = {"server": args.server, "server_version": subprocess.check_output([args.xray if args.server == "xray" else args.sing_box, "version"], text=True).splitlines()[0], "mlkem": args.mlkem, "camouflage_alpn": args.camouflage_alpn, "client_alpn": args.client_alpn, "passed": results, "direct_evidence": direct_lines}
        (work / "results.json").write_text(json.dumps(report, indent=2))
        print(f"PASS all {len(results)} scenarios with {args.server}. Evidence: {work}", flush=True)
    except Exception:
        print(f"FAIL; evidence retained at {work}", flush=True)
        for log in work.glob("*.log"):
            print(f"--- {log.name} ---\n{log.read_text()[-5000:]}", flush=True)
        raise
    finally:
        for server in [http, tls12, tls13, banner, echo]:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
