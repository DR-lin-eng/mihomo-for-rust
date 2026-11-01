#!/usr/bin/env python3
"""Real TLS and large HTTP bodies over TUN; isolated Linux Docker only."""
import argparse
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--core', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--inbound', choices=['tun', 'mixed'], default='tun')
parser.add_argument('--outbound', choices=['socks5', 'ss'], default='socks5')
parser.add_argument('--drop-first-reply', action='store_true')
args = parser.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix='tun-https-'))
checks, hits, failures = [], [], []
core = None
servers = []
drop_rule = None
mark, table, priority = 0x163, 21623, 1889
body = bytes(range(256)) * 16384
body_hash = hashlib.sha256(body).hexdigest()


def check(name, passed, detail=None):
    checks.append(dict(name=name, passed=bool(passed), detail=detail))
    if not passed:
        print('FAIL', name, detail, flush=True)


def run(*command, required=True):
    return subprocess.run(command, capture_output=True, text=True, check=required, timeout=15)


def free():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def exact(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def send_body(self, payload):
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def do_GET(self):
        self.send_body(body if self.path == '/large' else b'tls-keepalive-ok')

    def do_POST(self):
        remaining = int(self.headers['Content-Length'])
        digest = hashlib.sha256()
        while remaining:
            part = self.rfile.read(min(remaining, 65536))
            if not part:
                return
            digest.update(part)
            remaining -= len(part)
        self.send_body(digest.hexdigest().encode())


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(8)
            version, count = exact(self.request, 2)
            assert version == 5
            exact(self.request, count)
            self.request.sendall(b'\x05\x00')
            version, command, reserved, kind = exact(self.request, 4)
            if kind == 1:
                host = socket.inet_ntoa(exact(self.request, 4))
            elif kind == 3:
                host = exact(self.request, exact(self.request, 1)[0]).decode()
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, exact(self.request, 16))
            else:
                raise ValueError(kind)
            port = struct.unpack('!H', exact(self.request, 2))[0]
            assert command == 1 and port == origin.server_port
            hits.append((host, port))
            with socket.create_connection(('127.0.0.1', port), timeout=8) as remote:
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                endpoints = [self.request, remote]
                while endpoints:
                    readable, _, _ = select.select(endpoints, [], [], 8)
                    if not readable:
                        return
                    for source in readable:
                        destination = remote if source is self.request else self.request
                        data = source.recv(65536)
                        if data:
                            destination.sendall(data)
                        else:
                            endpoints.remove(source)
                            destination.shutdown(socket.SHUT_WR)
        except (OSError, EOFError, AssertionError, ValueError) as error:
            failures.append(repr(error))


def api(path):
    connection = http.client.HTTPConnection('127.0.0.1', controller, timeout=3)
    connection.request('GET', path, headers={'Connection': 'close'})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    assert response.status == 200
    return json.loads(data)


def connection():
    raw = socket.socket()
    raw.settimeout(6)
    if args.inbound == 'tun':
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        raw.connect(('198.51.100.44', origin.server_port))
    else:
        raw.connect(('127.0.0.1', mixed))
        raw.sendall(f'CONNECT tun.test:{origin.server_port} HTTP/1.1\r\nHost: tun.test\r\n\r\n'.encode())
        header = b''
        while not header.endswith(b'\r\n\r\n'):
            header += exact(raw, 1)
        assert b'200' in header
    context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
    stream = context.wrap_socket(raw, server_hostname='tun.test')
    return stream


def request(stream, method, path, payload=b'', slow=False):
    stream.sendall(f'{method} {path} HTTP/1.1\r\nHost: tun.test\r\nContent-Length: {len(payload)}\r\nConnection: keep-alive\r\n\r\n'.encode() + payload)
    if slow:
        time.sleep(.3)
    response = http.client.HTTPResponse(stream)
    response.begin()
    received = response.read()
    assert response.status == 200
    return received


def client(index):
    results = {}
    try:
        with connection() as stream:
            results['TLS handshake'] = stream.version()
            small = request(stream, 'GET', '/small')
            assert small == b'tls-keepalive-ok'
            results['small HTTPS response'] = len(small)
            large = request(stream, 'GET', '/large', slow=True)
            assert hashlib.sha256(large).hexdigest() == body_hash
            results['4 MiB slow-reader download'] = len(large)
            uploaded = request(stream, 'POST', '/upload', body)
            assert uploaded.decode() == body_hash
            results['4 MiB upload'] = len(body)
            time.sleep(.1)
            assert request(stream, 'GET', '/small') == b'tls-keepalive-ok'
            results['HTTPS keepalive after bulk transfer'] = True
    except Exception as error:
        results['error'] = repr(error)
    return index, results


try:
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'), '-days', '1', '-subj', '/CN=tun.test', '-addext', 'subjectAltName=DNS:tun.test')
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root / 'cert.pem', root / 'key.pem')
    origin.socket = tls.wrap_socket(origin.socket, server_side=True)
    servers.append(origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    proxy = TCP(('127.0.0.1', 0), Socks)
    servers.append(proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    controller, mixed, ss_port = free(), free(), free()
    proxy_config = f'{{name: fixture, type: socks5, server: 127.0.0.1, port: {proxy.server_address[1]}}}'
    if args.outbound == 'ss':
        proxy_config = f'{{name: fixture, type: ss, server: 127.0.0.1, port: {ss_port}, cipher: aes-128-gcm, password: tls-fixture-only}}'
    config = f'''mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
log-level: debug
hosts: {{tun.test: 127.0.0.1}}
dns:
  enable: true
  use-hosts: true
  nameserver: [rcode://success]
sniffer:
  enable: true
  parse-pure-ip: true
  force-dns-mapping: true
  override-destination: true
  sniff:
    TLS: {{ports: [{origin.server_port}]}}
tun:
  enable: true
  stack: system
  device: https-tun
  auto-route: false
  auto-detect-interface: false
  auto-redirect: false
  mtu: 1500
proxies:
  - {proxy_config}
rules: ['DOMAIN,tun.test,fixture','MATCH,REJECT']
'''
    if args.outbound == 'ss':
        config += f'''listeners:
  - name: ss-fixture
    type: shadowsocks
    listen: 127.0.0.1
    port: "{ss_port}"
    cipher: aes-128-gcm
    password: tls-fixture-only
    proxy: DIRECT
'''
    (root / 'config.yaml').write_text(config)
    log = (root / 'core.log').open('w')
    core = subprocess.Popen([args.core, '-d', str(root), '-f', str(root / 'config.yaml')], stdout=log, stderr=log, env=dict(os.environ, MIHOMO_TUN_TCP_TRACE='1'))
    for _ in range(300):
        if core.poll() is not None:
            raise RuntimeError((root / 'core.log').read_text())
        try:
            api('/version')
            break
        except OSError:
            time.sleep(.03)
    else:
        raise TimeoutError('controller not ready')
    if args.inbound == 'tun':
        run('ip', 'route', 'add', 'default', 'dev', 'https-tun', 'table', str(table))
        run('ip', 'rule', 'add', 'fwmark', hex(mark), 'table', str(table), 'priority', str(priority))
        if args.drop_first_reply:
            drop_rule = ['-i', 'https-tun', '-p', 'tcp', '--sport', str(origin.server_port), '-m', 'length', '--length', '100:65535', '-m', 'statistic', '--mode', 'nth', '--every', '1000000', '--packet', '0', '-j', 'DROP']
            run('iptables', '-A', 'INPUT', *drop_rule)
    index, single = client(0)
    for stage in ['TLS handshake', 'small HTTPS response', '4 MiB slow-reader download', '4 MiB upload', 'HTTPS keepalive after bulk transfer']:
        check('single ' + stage, stage in single, single)
    if 'error' not in single:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for index, result in pool.map(client, range(1, 5)):
                check('concurrent HTTPS transfer ' + str(index), 'error' not in result, result)
    check('controller survives HTTPS transfers', bool(api('/version')))
    if drop_rule is not None:
        counters = run('iptables', '-L', 'INPUT', '-n', '-v', '-x').stdout
        count = next((int(line.split()[0]) for line in counters.splitlines() if 'DROP' in line), 0)
        check('TLS survives an actually dropped TUN reply', count == 1 and 'error' not in single, dict(dropped=count, single=single))
except Exception as error:
    check('fixture execution', False, repr(error))
finally:
    if drop_rule is not None:
        run('iptables', '-D', 'INPUT', *drop_rule, required=False)
    run('ip', 'rule', 'del', 'fwmark', hex(mark), 'table', str(table), 'priority', str(priority), required=False)
    run('ip', 'route', 'flush', 'table', str(table), required=False)
    if core is not None and core.poll() is None:
        core.terminate()
        try:
            core.wait(10)
        except subprocess.TimeoutExpired:
            core.kill()
            core.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    if 'log' in globals():
        log.close()
    result = dict(passed=all(c['passed'] for c in checks), checks=checks, inbound=args.inbound, outbound=args.outbound, drop_first_reply=args.drop_first_reply, work=str(root), proxy_hits=hits, proxy_errors=failures, core_log=(root / 'core.log').read_text() if (root / 'core.log').exists() else '', sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    pathlib.Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], checks=len(checks), work=str(root))), flush=True)
raise SystemExit(0 if result['passed'] else 1)
