#!/usr/bin/env python3
"""Local echo, DNS and SOCKS fixtures; run only in the target network namespace."""
import json
import os
import pathlib
import socket
import socketserver
import struct
import threading
import time

ROOT = pathlib.Path('/results')
LOCK = threading.Lock()
COUNTS = {}


def exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = 65535


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


class Peer(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(json.dumps(self.client_address).encode() + b'\n')


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        try:
            end = 12
            labels = []
            while query[end]:
                length = query[end]
                labels.append(query[end + 1:end + 1 + length].decode())
                end += length + 1
            name = '.'.join(labels)
            kind = struct.unpack('!H', query[end + 1:end + 3])[0]
            end += 5
            with LOCK:
                COUNTS[name] = COUNTS.get(name, 0) + 1
                (ROOT / 'dns-counts.tmp').write_text(json.dumps(COUNTS))
                os.replace(ROOT / 'dns-counts.tmp', ROOT / 'dns-counts.json')
            # A deliberate delay makes overlapping requests observable.
            time.sleep(.08)
            address = (ROOT / 'dns-answer.txt').read_text().strip()
            answer = b''
            if kind == 1:
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton(address)
            response = query[:2] + struct.pack('!5H', 0x8180, 1, int(bool(answer)), 0, 0)
            sock.sendto(response + query[12:end] + answer, self.client_address)
        except (OSError, ValueError, IndexError):
            pass


def splice_direction(source, destination):
    read_fd, write_fd = os.pipe()
    try:
        while True:
            count = os.splice(source.fileno(), write_fd, 65536)
            if not count:
                break
            while count:
                count -= os.splice(read_fd, destination.fileno(), count)
    except OSError:
        pass
    finally:
        os.close(read_fd)
        os.close(write_fd)
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            client = self.request
            head = exact(client, 2)
            if head[0] != 5:
                return
            exact(client, head[1])
            client.sendall(b'\x05\x00')
            head = exact(client, 4)
            if head[:3] != b'\x05\x01\x00':
                return
            if head[3] == 1:
                host = socket.inet_ntop(socket.AF_INET, exact(client, 4))
            elif head[3] == 4:
                host = socket.inet_ntop(socket.AF_INET6, exact(client, 16))
            else:
                host = exact(client, exact(client, 1)[0]).decode()
            port = struct.unpack('!H', exact(client, 2))[0]
            with socket.create_connection((host, port), timeout=8) as upstream:
                upstream.settimeout(None)
                client.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                other = threading.Thread(target=splice_direction, args=(upstream, client), daemon=True)
                other.start()
                splice_direction(client, upstream)
                other.join(8)
        except (OSError, EOFError, ValueError):
            pass


for cls, port, handler in ((TCP, 18080, Echo), (TCP, 18081, Peer),
                           (UDP, 18082, UdpEcho), (UDP, 53, DNS), (TCP, 1080, Socks)):
    server = cls(('203.0.113.30', port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
print('ready', flush=True)
threading.Event().wait()
