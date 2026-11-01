#!/usr/bin/env python3
"""Real LAN fake-IP UDP: echo, burst login, delayed replies and server push.

Run in an isolated privileged Linux container; no external game or DNS needed.
"""
import argparse, contextlib, ctypes, hashlib, http.client, ipaddress, json, os
import pathlib, select, socket, socketserver, struct, subprocess, tempfile, threading, time

p = argparse.ArgumentParser()
p.add_argument('--core', required=True)
p.add_argument('--output', required=True)
p.add_argument('--outbound', choices=['socks5', 'direct', 'ss', 'vless', 'hy2'], default='socks5')
p.add_argument('--reference-core', help='Go Mihomo used only as the SS/VLESS/Hysteria2 server')
p.add_argument('--endpoint-independent-nat', action='store_true')
p.add_argument('--push-delay', type=float, default=1.3)
p.add_argument('--switch-route', action='store_true', help='Game B uses DIRECT on the shared source session')
p.add_argument('--interleave', action='store_true', help='Send to game B while awaiting game A server push')
args = p.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix='fakeip-game-'))
checks, hits, servers = [], [], []
connection_samples = []
core = None
reference = None
ns = 'game-client-' + str(os.getpid())
link, peer = 'game-ap', 'game-peer'
stop = threading.Event()
game_ips = {'game-a.test': '127.0.0.10', 'game-b.test': '127.0.0.11'}

def run(*command, required=True):
    return subprocess.run(command, capture_output=True, text=True, check=required, timeout=12)

def check(name, ok, detail=None):
    checks.append(dict(name=name, passed=bool(ok), detail=detail))
    if not ok: print('FAIL', name, detail, flush=True)

@contextlib.contextmanager
def client_network():
    original = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    target = os.open('/run/netns/' + ns, os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if libc.setns(target, 0x40000000): raise OSError(ctypes.get_errno(), 'setns')
        yield
    finally:
        libc.setns(original, 0x40000000); os.close(target); os.close(original)

def exact(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part: raise EOFError()
        data += part
    return data

class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

def start(server):
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        end, labels = 12, []
        while query[end]:
            length = query[end]; end += 1
            labels.append(query[end:end+length].decode()); end += length
        kind = struct.unpack('!H', query[end+1:end+3])[0]; end += 5
        host = '.'.join(labels)
        answer = b''
        if kind == 1 and host in game_ips:
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(game_ips[host])
        sock.sendto(query[:2] + struct.pack('!5H', 0x8180, 1, int(bool(answer)), 0, 0) + query[12:end] + answer, self.client_address)

class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(4)
            version, count = exact(self.request, 2); assert version == 5
            exact(self.request, count); self.request.sendall(b'\x05\x00')
            request = exact(self.request, 10); assert request[:4] == b'\x05\x03\x00\x01'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                relay.bind(('127.0.0.1', 0))
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', relay.getsockname()[1]))
                queues = {}
                while not stop.is_set():
                    ready, _, _ = select.select([relay, self.request], [], [], .2)
                    if self.request in ready and not self.request.recv(1): return
                    if relay not in ready: continue
                    frame, source = relay.recvfrom(65535)
                    assert frame[:4] == b'\x00\x00\x00\x01'
                    host, port, payload = socket.inet_ntoa(frame[4:8]), struct.unpack('!H', frame[8:10])[0], frame[10:]
                    hits.append(dict(host=host, port=port, relay_source=source, payload=payload.hex()))
                    if port == echo_port:
                        relay.sendto(frame[:10] + payload, source)
                    elif port == game_port:
                        key = (source, host, port)
                        queue = queues.setdefault(key, [])
                        queue.append(payload)
                        if len(queue) == 3:
                            reply_prefix = frame[:10]
                            def replies(destination=source, header=reply_prefix, chunks=list(queue)):
                                try:
                                    for chunk in chunks: relay.sendto(header + chunk, destination)
                                    stop.wait(args.push_delay)
                                    if not stop.is_set(): relay.sendto(header + b'server-push', destination)
                                except OSError: pass
                            threading.Thread(target=replies, daemon=True).start()
        except (OSError, EOFError, AssertionError): pass

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        hits.append(dict(host=self.server.server_address[0], port=self.server.server_address[1], relay_source=self.client_address, payload=data.hex()))
        sock.sendto(data, self.client_address)

class Game(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        hits.append(dict(host=self.server.server_address[0], port=self.server.server_address[1], relay_source=self.client_address, payload=data.hex()))
        with self.server.lock:
            chunks = self.server.queues.setdefault(self.client_address, [])
            chunks.append(data)
            if len(chunks) != 3: return
            chunks = list(chunks)
        for chunk in chunks: sock.sendto(chunk, self.client_address)
        stop.wait(args.push_delay)
        if not stop.is_set(): sock.sendto(b'server-push', self.client_address)

def free():
    with socket.socket() as s: s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def api(path, method='GET'):
    c = http.client.HTTPConnection('127.0.0.1', controller, timeout=3)
    c.request(method, path, headers={'Connection':'close'})
    r = c.getresponse(); data = r.read(); c.close(); assert r.status == (200 if method=='GET' else 204)
    return json.loads(data) if data else None

def dns(host):
    q = b'\x43\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    q += b''.join(bytes([len(v)]) + v.encode() for v in host.split('.')) + b'\0\x00\x01\x00\x01'
    with client_network(): s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with s:
        s.settimeout(4); s.sendto(q, ('8.8.8.8',53)); reply = s.recv(4096)
    assert reply[:2] == q[:2] and reply[3] & 15 == 0 and reply[6:8] == b'\x00\x01'
    return socket.inet_ntoa(reply[-4:])

try:
    run('ip','netns','add',ns)
    run('ip','link','add',link,'type','veth','peer','name',peer)
    run('ip','link','set',peer,'netns',ns)
    run('ip','addr','add','192.0.2.1/24','dev',link); run('ip','link','set',link,'up')
    run('ip','-n',ns,'link','set','lo','up')
    run('ip','-n',ns,'addr','add','192.0.2.44/24','dev',peer)
    run('ip','-n',ns,'link','set',peer,'up')
    run('ip','-n',ns,'route','add','default','via','192.0.2.1')
    pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    upstream = start(UDP(('127.0.0.1',0),DNS))
    controller, echo_port, game_port = free(), free(), free()
    if args.outbound in ('direct', 'ss', 'vless', 'hy2') or args.switch_route:
        for host in game_ips.values():
            start(UDP((host,echo_port),Echo))
            server = UDP((host,game_port),Game); server.lock = threading.Lock(); server.queues = {}; start(server)
    if args.outbound in ('direct', 'ss', 'vless', 'hy2'):
        proxy_config = ''; route = 'DIRECT'
        if args.outbound in ('ss', 'vless', 'hy2'):
            assert args.reference_core, '--reference-core is required for SS/VLESS/Hysteria2'
            route = 'game-node'; port = free()
            uuid = 'b831381d-6324-4d53-ad4f-8cda48b30811'
            if args.outbound == 'ss':
                inbound = f'{{type: shadowsocks, name: udp-server, listen: 127.0.0.1, port: {port}, cipher: aes-128-gcm, password: fixture-only, udp: true}}'
                outbound = f'{{type: ss, name: game-node, server: 127.0.0.1, port: {port}, cipher: aes-128-gcm, password: fixture-only, udp: true}}'
            else:
                run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=udp-fixture.test','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'))
                if args.outbound == 'vless':
                    inbound = f'{{type: vless, name: udp-server, certificate: {root}/cert.pem, private-key: {root}/key.pem, listen: 127.0.0.1, port: {port}, users: [{{uuid: {uuid}}}]}}'
                    outbound = f'{{type: vless, name: game-node, server: 127.0.0.1, port: {port}, uuid: {uuid}, udp: true, tls: true, servername: udp-fixture.test, skip-cert-verify: true}}'
                else:
                    inbound = f'{{type: hysteria2, name: udp-server, certificate: {root}/cert.pem, private-key: {root}/key.pem, listen: 127.0.0.1, port: {port}, users: {{game: fixture-only}}}}'
                    outbound = f'{{type: hysteria2, name: game-node, server: 127.0.0.1, port: {port}, password: fixture-only, sni: udp-fixture.test, skip-cert-verify: true}}'
            server_config = root/'server.yaml'
            server_config.write_text(f"log-level: debug\nlisteners:\n  - {inbound}\nrules: ['MATCH,DIRECT']\n")
            server_log = (root/'server.log').open('w')
            reference = subprocess.Popen([args.reference_core,'-d',str(root),'-f',str(server_config)],stdout=server_log,stderr=server_log)
            time.sleep(.5)
            if reference.poll() is not None: raise RuntimeError((root/'server.log').read_text())
            proxy_config = f'proxies:\n  - {outbound}\n'
    else:
        port = start(TCP(('127.0.0.1',0),Socks)); route = 'game-socks'
        proxy_config = f'proxies:\n  - {{name: game-socks, type: socks5, server: 127.0.0.1, port: {port}, udp: true}}\n'
    config = f'''mode: Rule
external-controller: 127.0.0.1:{controller}
log-level: debug
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver: [udp://127.0.0.1:{upstream}]
tun:
  enable: true
  stack: mixed
  device: game-tun
  auto-route: true
  strict-route: true
  auto-redirect: false
  dns-hijack: [any:53, 'tcp://any:53']
  udp-timeout: 300
  endpoint-independent-nat: {str(args.endpoint_independent_nat or args.switch_route).lower()}
rules: {"['DOMAIN,game-b.test,DIRECT', 'DOMAIN-SUFFIX,test," + route + "', 'MATCH,REJECT']" if args.switch_route else "['DOMAIN-SUFFIX,test," + route + "', 'MATCH,REJECT']"}
{proxy_config}'''
    (root/'config.yaml').write_text(config)
    log = (root/'core.log').open('w')
    core = subprocess.Popen([args.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
    for _ in range(200):
        if core.poll() is not None: raise RuntimeError((root/'core.log').read_text())
        try:
            api('/version'); break
        except OSError: time.sleep(.03)
    else: raise TimeoutError('core startup')
    time.sleep(.3)
    fake_a, fake_b = dns('game-a.test'), dns('game-b.test')
    check('separate DNS fake IPs', fake_a!=fake_b and all(ipaddress.ip_address(v) in ipaddress.ip_network('198.18.0.0/16') for v in (fake_a,fake_b)), [fake_a,fake_b])
    def sample_connections():
        while not stop.wait(.1):
            try: connection_samples.append(api('/connections'))
            except OSError: pass
    threading.Thread(target=sample_connections,daemon=True).start()
    with client_network(): s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('192.0.2.44',49152))
    with s:
        s.settimeout(5)
        for fake_ip in (fake_a,fake_b,fake_a):
            payload = b'echo-' + fake_ip.encode(); s.sendto(payload,(fake_ip,echo_port))
            try:
                answer, source = s.recvfrom(8192)
                check('echo payload and fake source '+fake_ip,answer==payload and source==(fake_ip,echo_port),dict(source=source,payload=answer.hex()))
            except OSError as error: check('echo payload and fake source '+fake_ip,False,repr(error))
        chunks = [struct.pack('!I',i)+bytes(range(128)) for i in range(3)]
        started = time.monotonic()
        for chunk in chunks: s.sendto(chunk,(fake_a,game_port))
        received = []; sources = []; deadline = time.monotonic()+max(5,args.push_delay+4); login_elapsed = None
        interleaved_sent = False; interleaved_reply = None
        while len(received)<4 and time.monotonic()<deadline:
            try:
                s.settimeout(max(.01,deadline-time.monotonic())); answer, source = s.recvfrom(8192)
                if args.interleave and answer == b'interleaved-game-b':
                    interleaved_reply = source
                    continue
                received.append(answer); sources.append(source)
                if login_elapsed is None and all(c in received for c in chunks): login_elapsed = time.monotonic()-started
                if args.interleave and login_elapsed is not None and not interleaved_sent:
                    s.sendto(b'interleaved-game-b',(fake_b,echo_port)); interleaved_sent = True
            except socket.timeout: break
        check('three-packet login burst arrives promptly',login_elapsed is not None and login_elapsed < 1,dict(received=[v.hex() for v in received],login_elapsed=login_elapsed))
        check('delayed server push without client sending',b'server-push' in received)
        check('all login and push replies preserve fake source',len(sources)==4 and all(v==(fake_a,game_port) for v in sources),sources)
        if args.interleave:
            check('other destination reply preserves fake source during game session',interleaved_reply==(fake_b,echo_port),interleaved_reply)
        if b'server-push' in received and args.push_delay < 5:
            rows = api('/connections')['connections']
            row = next(row for row in rows if row['metadata']['network']=='udp' and str(row['metadata']['sourcePort'])=='49152' and str(row['metadata']['destinationPort'])==str(game_port))
            api('/connections/'+row['id'],'DELETE')
            check('controller closes UDP flow',True)
            new_chunks = [b'reconnect-'+struct.pack('!I',i) for i in range(3)]
            for chunk in new_chunks: s.sendto(chunk,(fake_a,game_port))
            s.settimeout(4); restarted = []
            for _ in range(4):
                packet, source = s.recvfrom(8192)
                if source==(fake_a,game_port): restarted.append(packet)
            check('UDP login recovers after controller closes old flow',all(c in restarted for c in new_chunks) and b'server-push' in restarted,[v.hex() for v in restarted])
    check('upstream sees real IPs, never fake addresses',bool(hits) and all(v['host'] in game_ips.values() for v in hits),hits)
except Exception as error: check('fixture execution',False,repr(error))
finally:
    stop.set()
    if core is not None and core.poll() is None:
        core.terminate()
        try: core.wait(10)
        except subprocess.TimeoutExpired: core.kill(); core.wait(); check('bounded shutdown',False)
    for server in servers: server.shutdown(); server.server_close()
    if reference is not None and reference.poll() is None:
        reference.terminate()
        try: reference.wait(5)
        except subprocess.TimeoutExpired: reference.kill(); reference.wait()
    if 'server_log' in globals(): server_log.close()
    run('ip','link','del',link,required=False); run('ip','netns','del',ns,required=False)
    if 'log' in globals(): log.close()
    result = dict(passed=all(c['passed'] for c in checks),checks=checks,work=str(root),outbound=args.outbound,endpoint_independent_nat=args.endpoint_independent_nat or args.switch_route,switch_route=args.switch_route,interleave=args.interleave,push_delay=args.push_delay,connection_samples=connection_samples,hits=hits,core_log=(root/'core.log').read_text() if (root/'core.log').exists() else '',server_log=(root/'server.log').read_text() if (root/'server.log').exists() else '',sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    pathlib.Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=result['passed'],checks=len(checks),work=str(root))),flush=True)
raise SystemExit(0 if result['passed'] else 1)
