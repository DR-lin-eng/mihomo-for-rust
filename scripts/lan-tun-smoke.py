#!/usr/bin/env python3
"""Independent LAN clients using mixed + auto-route TUN and hijacked DNS.

Run only in an isolated privileged Linux Docker network namespace.
"""
import argparse
import contextlib
import ctypes
import hashlib
import http.client
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
parser.add_argument('--oem-policy-routing', action='store_true')
args = parser.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix='lan-tun-'))
checks, hits, servers, namespaces, links = [], [], [], [], []
core = None
original_default_routes = []
https_body = bytes(range(256)) * 16384
https_hash = hashlib.sha256(https_body).hexdigest()
lan, wan = 'wifi-ap', 'rmnet_data0'
client_ns, proxy_ns = 'wifi-client', 'wan-proxy'


def check(name, passed, detail=None):
    checks.append(dict(name=name, passed=bool(passed), detail=detail))
    if not passed:
        print('FAIL', name, detail, flush=True)


def run(*command, required=True):
    return subprocess.run(command, capture_output=True, text=True, check=required, timeout=12)


def free():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def netns(name):
    original = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    target = os.open('/run/netns/' + name, os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if libc.setns(target, 0x40000000) != 0:
            raise OSError(ctypes.get_errno(), 'setns')
        yield
    finally:
        libc.setns(original, 0x40000000)
        os.close(original)
        os.close(target)


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(4)
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
                return
            port = struct.unpack('!H', exact(self.request, 2))[0]
            hits.append(dict(command=command, host=host, port=port))
            if command == 1:
                self.request.sendall(b'\x05\x00\x00\x01\xcb\x00\x71\x02\x00\x00')
                if self.request.recv(1, socket.MSG_PEEK) == b'\x16':
                    with origin_tls.wrap_socket(self.request, server_side=True) as stream:
                        header = b''
                        while not header.endswith(b'\r\n\r\n'):
                            header += exact(stream, 1)
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(https_body)).encode() + b'\r\nConnection: close\r\n\r\n' + https_body)
                    return
                payload = self.request.recv(8192)
                self.request.sendall(b'proxy-tcp:' + payload)
                self.request.shutdown(socket.SHUT_WR)
            elif command == 3:
                with netns(proxy_ns):
                    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    relay.bind(('203.0.113.2', 0))
                with relay:
                    relay.settimeout(4)
                    self.request.sendall(b'\x05\x00\x00\x01\xcb\x00\x71\x02' + struct.pack('!H', relay.getsockname()[1]))
                    while True:
                        ready, _, _ = select.select([relay, self.request], [], [], 4)
                        if not ready or self.request in ready and not self.request.recv(1024):
                            return
                        if relay in ready:
                            packet, peer = relay.recvfrom(65535)
                            assert packet[:4] == b'\x00\x00\x00\x01'
                            hits.append(dict(command='udp', host=socket.inet_ntoa(packet[4:8]), port=struct.unpack('!H', packet[8:10])[0]))
                            relay.sendto(packet[:10] + b'proxy-udp:' + packet[10:], peer)
        except (OSError, EOFError, AssertionError):
            return


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        end = 12
        while query[end]:
            end += query[end] + 1
        end += 5
        record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('198.51.100.44')
        response = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + query[12:end] + record
        sock.sendto(response, self.client_address)


def serve(server):
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def api(path):
    connection = http.client.HTTPConnection('127.0.0.1', controller, timeout=3)
    connection.request('GET', path, headers={'Connection': 'close'})
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    assert response.status == 200
    return json.loads(payload)


def dns_query(tcp, peer='192.168.0.212'):
    query = b'\x19\x91\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x04test\x00\x00\x01\x00\x01'
    with netns(client_ns):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        sock.bind((peer, 0))
    with sock:
        sock.settimeout(3)
        sock.connect(('8.8.8.8', 53))
        sock.sendall(struct.pack('!H', len(query)) + query if tcp else query)
        response = exact(sock, struct.unpack('!H', exact(sock, 2))[0]) if tcp else sock.recv(65535)
        assert response[:2] == query[:2] and response[3] & 15 == 0
        return socket.inet_ntoa(response[-4:])


def tcp_flow(target, peer, manual=False):
    with netns(client_ns):
        sock = socket.socket()
        sock.bind((peer, 0))
    with sock:
        sock.settimeout(4)
        sock.connect(('192.168.0.1', mixed) if manual else (target, 443))
        if manual:
            sock.sendall(b'CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test\r\n\r\n')
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                header += exact(sock, 1)
            assert b'200' in header
        payload = b'lan-client-' + peer.encode()
        sock.sendall(payload)
        result = exact(sock, len(b'proxy-tcp:') + len(payload))
        assert result == b'proxy-tcp:' + payload
        return sock.getsockname()[0]


def udp_flow(peer):
    with netns(client_ns):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((peer, 45321))
    with sock:
        sock.settimeout(4)
        sock.connect(('198.51.100.44', 9999))
        payload = b'lan-udp-' + peer.encode()
        sock.send(payload)
        assert sock.recv(65535) == b'proxy-udp:' + payload
        return sock.getsockname()[0]


def https_flow(target, peer):
    with netns(client_ns):
        raw = socket.socket()
        raw.bind((peer, 0))
    raw.settimeout(6)
    raw.connect((target, 443))
    context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
    with context.wrap_socket(raw, server_hostname='fixture.test') as stream:
        stream.sendall(b'GET /large HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n')
        time.sleep(.2)
        response = http.client.HTTPResponse(stream)
        response.begin()
        received = response.read()
        assert response.status == 200 and hashlib.sha256(received).hexdigest() == https_hash
        return dict(source=stream.getsockname()[0], bytes=len(received), tls=stream.version(), sha256=https_hash)


try:
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'), '-days', '1', '-subj', '/CN=fixture.test', '-addext', 'subjectAltName=DNS:fixture.test')
    origin_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    origin_tls.load_cert_chain(root / 'cert.pem', root / 'key.pem')
    for name in (client_ns, proxy_ns):
        run('ip', 'netns', 'add', name)
        namespaces.append(name)
        run('ip', 'netns', 'exec', name, 'ip', 'link', 'set', 'lo', 'up')
    for interface, peer, ns, local, remote in (
        (lan, 'wifi-peer', client_ns, '192.168.0.1/24', '192.168.0.212/24'),
        (wan, 'wan-peer', proxy_ns, '203.0.113.1/24', '203.0.113.2/24'),
    ):
        run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', peer)
        links.append(interface)
        run('ip', 'link', 'set', peer, 'netns', ns)
        run('ip', 'addr', 'add', local, 'dev', interface)
        run('ip', 'link', 'set', interface, 'up')
        run('ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', remote, 'dev', peer)
        run('ip', 'netns', 'exec', ns, 'ip', 'link', 'set', peer, 'up')
    proxy_host = '203.0.113.2'
    if args.oem_policy_routing:
        proxy_host = '198.51.100.2'
        run('ip', 'netns', 'exec', proxy_ns, 'ip', 'addr', 'add', proxy_host + '/32', 'dev', 'lo')
    run('ip', 'netns', 'exec', client_ns, 'ip', 'addr', 'add', '192.168.0.213/24', 'dev', 'wifi-peer')
    run('ip', 'netns', 'exec', client_ns, 'ip', 'route', 'add', 'default', 'via', '192.168.0.1')
    if args.oem_policy_routing:
        original_default_routes = [line.split() for line in run('ip', 'route', 'show', 'default').stdout.splitlines() if line]
        for route in original_default_routes:
            run('ip', 'route', 'del', *route)
        run('ip', 'route', 'add', 'default', 'via', '203.0.113.2', 'dev', wan, 'table', '1002')
        run('ip', 'rule', 'add', 'priority', '10000', 'lookup', '1002')
    else:
        run('ip', 'route', 'add', 'default', 'via', '203.0.113.2', 'dev', wan, 'metric', '1')
    pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    with netns(proxy_ns):
        proxy = TCP((proxy_host, 0), Proxy)
    proxy_port = serve(proxy)
    dns_port = serve(UDP(('127.0.0.1', 0), DNS))
    controller, mixed = free(), free()
    config = f'''mixed-port: {mixed}
mode: Rule
allow-lan: true
ipv6: true
external-controller: 127.0.0.1:{controller}
log-level: debug
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP: {{ports: [80, 8080-8880]}}
    TLS: {{ports: [443, 5228, 8443]}}
    QUIC: {{ports: [443, 8443]}}
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver: [udp://127.0.0.1:{dns_port}]
tun:
  enable: true
  device: Meta
  stack: mixed
  dns-hijack: [any:53, 'tcp://any:53']
  udp-timeout: 300
  auto-route: true
  strict-route: true
  auto-redirect: false
  auto-detect-interface: true
  exclude-package: [com.samsung.android.messaging]
proxies:
  - {{name: fixture, type: socks5, server: {proxy_host}, port: {proxy_port}, udp: true}}
rules: ['DOMAIN,fixture.test,fixture', 'IP-CIDR,198.51.100.44/32,fixture,no-resolve', 'MATCH,REJECT']
'''
    (root / 'config.yaml').write_text(config)
    log = (root / 'core.log').open('w')
    core = subprocess.Popen([args.core, '-d', str(root), '-f', str(root / 'config.yaml')], stdout=log, stderr=log, env=dict(os.environ, MIHOMO_TUN_TCP_TRACE='1'))
    for _ in range(250):
        if core.poll() is not None:
            raise RuntimeError((root / 'core.log').read_text())
        try:
            api('/version')
            break
        except OSError:
            time.sleep(.03)
    else:
        raise TimeoutError('core startup')
    for _ in range(150):
        try:
            with socket.create_connection(('127.0.0.1', mixed), timeout=.1):
                break
        except OSError:
            time.sleep(.03)
    else:
        raise TimeoutError('mixed listener startup')
    # Go opens its controller/listeners before publishing Running to the tunnel.
    time.sleep(.4)
    routing = dict(rules=run('ip', 'rule', 'show').stdout, routes=run('ip', 'route', 'show', 'table', 'all').stdout)
    for peer in ('192.168.0.212', '192.168.0.213'):
        for manual in (True, False):
            try:
                source = tcp_flow('198.51.100.44', peer, manual)
                check(('LAN mixed ' if manual else 'LAN auto-route TUN ') + peer, source == peer, dict(source=source))
            except Exception as error:
                check(('LAN mixed ' if manual else 'LAN auto-route TUN ') + peer, False, repr(error))
        try:
            check('LAN auto-route UDP same source port ' + peer, udp_flow(peer) == peer)
        except Exception as error:
            check('LAN auto-route UDP same source port ' + peer, False, repr(error))
    resolved_fake_ip = None
    for tcp in (False, True):
        name = 'LAN TCP DNS hijack' if tcp else 'LAN UDP DNS hijack'
        try:
            fake_ip = dns_query(tcp)
            check(name + ' uses core fake-IP DNS', fake_ip.startswith('198.18.'), fake_ip)
            if fake_ip.startswith('198.18.'):
                resolved_fake_ip = fake_ip
                check(name + ' mapping routes later LAN TCP', tcp_flow(fake_ip, '192.168.0.213') == '192.168.0.213')
        except Exception as error:
            check(name, False, repr(error))
    if resolved_fake_ip is not None:
        for peer in ('192.168.0.212', '192.168.0.213'):
            try:
                response = https_flow(resolved_fake_ip, peer)
                check('LAN TLS and 4 MiB download ' + peer, response['source'] == peer, response)
            except Exception as error:
                check('LAN TLS and 4 MiB download ' + peer, False, repr(error))
    check('remote proxy sees original public destination', any(hit['host'] == '198.51.100.44' and hit['port'] == 443 for hit in hits), hits)
except Exception as error:
    check('fixture execution', False, repr(error))
finally:
    if core is not None and core.poll() is None:
        core.terminate()
        try:
            core.wait(12)
        except subprocess.TimeoutExpired:
            core.kill()
            core.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    if args.oem_policy_routing:
        run('ip', 'rule', 'del', 'priority', '10000', 'lookup', '1002', required=False)
        run('ip', 'route', 'flush', 'table', '1002', required=False)
        for route in original_default_routes:
            run('ip', 'route', 'add', *route, required=False)
    else:
        run('ip', 'route', 'del', 'default', 'via', '203.0.113.2', 'dev', wan, 'metric', '1', required=False)
    for interface in links:
        run('ip', 'link', 'del', interface, required=False)
    for name in namespaces:
        run('ip', 'netns', 'del', name, required=False)
    if 'log' in globals():
        log.close()
    result = dict(passed=all(c['passed'] for c in checks), checks=checks, work=str(root), oem_policy_routing=args.oem_policy_routing, hits=hits, config=locals().get('config'), routing=locals().get('routing'), core_log=(root / 'core.log').read_text() if (root / 'core.log').exists() else '', sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    pathlib.Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], checks=len(checks), work=str(root))), flush=True)
raise SystemExit(0 if result['passed'] else 1)
