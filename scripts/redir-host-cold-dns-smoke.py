#!/usr/bin/env python3
"""Exercise real UDP/TCP DNS listeners with deterministic cold upstream replies.

Run in a Linux container. All DNS, controller and HTTP traffic stays on loopback.
"""

import argparse
import collections
import contextlib
import hashlib
import http.client
import json
import pathlib
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


def query(host, kind, request_id=0x1234):
    question = b"".join(bytes([len(label)]) + label.encode() for label in host.split("."))
    return struct.pack("!6H", request_id, 0x0100, 1, 0, 0, 0) + question + b"\0" + struct.pack("!HH", kind, 1)


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError("DNS TCP response ended early")
        data += part
    return data


class DnsServer(socketserver.ThreadingUDPServer):
    daemon_threads = True

    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0), DnsHandler)
        self.mode = mode
        self.hits = collections.Counter()
        self.lock = threading.Lock()


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        end, labels = 12, []
        while packet[end]:
            size = packet[end]
            labels.append(packet[end + 1:end + 1 + size].decode())
            end += size + 1
        kind = struct.unpack_from("!H", packet, end + 1)[0]
        end += 5
        key = (".".join(labels), kind)
        with self.server.lock:
            self.server.hits[key] += 1
            count = self.server.hits[key]
        mode = self.server.mode
        cold = mode in ("cold-empty", "cold-nxdomain") and count == 1
        rcode = 3 if mode == "nxdomain" or (mode == "cold-nxdomain" and cold) else 0
        answer = b""
        if kind in (1, 28) and mode not in ("empty", "nxdomain") and not cold:
            ip = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                  "127.0.0.10" if kind == 1 else "2001:db8::10")
            answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 37, len(ip)) + ip
        response = packet[:2] + struct.pack("!5H", 0x8180 | rcode, 1, bool(answer), 0, 0) + packet[12:end] + answer
        sock.sendto(response, self.client_address)


class HttpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


@contextlib.contextmanager
def serving(server):
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exchange(port, packet, protocol):
    if protocol == "tcp":
        with socket.create_connection(("127.0.0.1", port), 4) as sock:
            sock.settimeout(4)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            return read_exact(sock, struct.unpack("!H", read_exact(sock, 2))[0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.sendto(packet, ("127.0.0.1", port))
        return sock.recv(65535)


def http_after_resolution(packet, port):
    if packet[3] & 15 or struct.unpack_from("!H", packet, 6)[0] != 1:
        return False
    address = socket.inet_ntoa(packet[-4:])
    with socket.create_connection((address, port), 2) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: cold.test\r\nConnection: close\r\n\r\n")
        return b"200 OK" in sock.recv(4096)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    core = str(pathlib.Path(args.core).resolve())
    checks, cases = [], []

    def check(name, passed, **details):
        checks.append(dict(name=name, passed=bool(passed), **details))
        if not passed:
            print("FAIL", name, details, flush=True)

    scenarios = [
        ("empty-first", "cold-empty", True, None, 1, True, 0),
        ("nxdomain-first", "cold-nxdomain", True, None, 1, True, 0),
        ("ipv6-empty-first", "cold-empty", True, None, 28, True, 0),
        ("no-fallback-empty", "empty", False, None, 1, False, 0),
        ("no-fallback-nxdomain", "nxdomain", False, None, 1, False, 3),
        ("healthy-primary", "ok", True, None, 1, True, 0),
        ("https-empty", "empty", True, None, 65, False, 0),
        ("private-policy", "empty", True, "private", 1, False, 0),
        ("rcode-success", "ok", True, "rcode://success", 1, False, 0),
        ("rcode-nxdomain", "ok", True, "rcode://name_error", 1, False, 3),
    ]
    with tempfile.TemporaryDirectory(prefix="redir-host-cold-") as temporary:
        root = pathlib.Path(temporary)
        for name, mode, fallback, policy, kind, has_answer, rcode in scenarios:
            process = None
            home = root / name
            home.mkdir()
            with contextlib.ExitStack() as stack:
                primary = stack.enter_context(serving(DnsServer(mode)))
                backup = stack.enter_context(serving(DnsServer("ok")))
                http_server = stack.enter_context(serving(HttpServer(("127.0.0.10", 0), HttpHandler)))
                dns_port, controller = free_port(), free_port()
                primary_url = "udp://127.0.0.1:" + str(primary.server_address[1])
                config = {
                    "external-controller": "127.0.0.1:" + str(controller),
                    "mode": "rule", "rules": ["MATCH,DIRECT"],
                    "dns": {"enable": True, "listen": "127.0.0.1:" + str(dns_port),
                            "ipv6": kind == 28, "enhanced-mode": "redir-host",
                            "nameserver": [primary_url]},
                }
                if fallback:
                    config["dns"]["fallback"] = ["udp://127.0.0.1:" + str(backup.server_address[1])]
                if policy:
                    config["dns"]["nameserver-policy"] = {"+.cold.test": [primary_url if policy == "private" else policy]}
                    # A matching private policy must also beat the fallback domain filter.
                    config["dns"]["fallback-filter"] = {"domain": ["+.cold.test"]} if policy == "private" else {}
                config_file = home / "config.json"
                config_file.write_text(json.dumps(config))
                with (home / "core.log").open("w") as log:
                    try:
                        process = subprocess.Popen([core, "-d", str(home), "-f", str(config_file)], stdout=log, stderr=log)
                        deadline = time.monotonic() + 8
                        while True:
                            if process.poll() is not None:
                                raise RuntimeError((home / "core.log").read_text())
                            try:
                                connection = http.client.HTTPConnection("127.0.0.1", controller, timeout=.2)
                                connection.request("GET", "/version")
                                connection.getresponse().read()
                                connection.close()
                                break
                            except OSError:
                                if time.monotonic() >= deadline:
                                    raise TimeoutError("core controller startup")
                                time.sleep(.025)
                        for protocol in ("udp", "tcp"):
                            host = protocol + ".cold.test"
                            packet = query(host, kind)
                            started = time.monotonic()
                            first = exchange(dns_port, packet, protocol)
                            elapsed = time.monotonic() - started
                            count = struct.unpack_from("!H", first, 6)[0]
                            check(name + "/" + protocol + " first lookup", first[:2] == packet[:2] and (first[3] & 15) == rcode and bool(count) == has_answer,
                                  rcode=first[3] & 15, answers=count, elapsed_seconds=elapsed)
                            if kind == 1 and has_answer:
                                check(name + "/" + protocol + " first HTTP access", http_after_resolution(first, http_server.server_address[1]))
                            second = exchange(dns_port, packet, protocol)
                            if mode.startswith("cold-"):
                                check(name + "/" + protocol + " refresh succeeds", bool(struct.unpack_from("!H", second, 6)[0]))
                        backup_hits = sum(backup.hits.values())
                        expect_fallback = mode.startswith("cold-") and fallback and policy is None
                        check(name + " fallback routing", (backup_hits > 0) == expect_fallback, fallback_queries=backup_hits)
                        cases.append(dict(case=name, primary_hits={str(k): v for k, v in primary.hits.items()}, fallback_hits=backup_hits))
                    except Exception as error:
                        check(name + " fixture", False, error=repr(error))
                    finally:
                        if process is not None and process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()
    result = dict(passed=all(item["passed"] for item in checks),
                  core_sha256=hashlib.sha256(pathlib.Path(core).read_bytes()).hexdigest(),
                  checks=checks, cases=cases)
    pathlib.Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "checks": len(checks),
                      "failed": sum(not item["passed"] for item in checks)}), flush=True)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
