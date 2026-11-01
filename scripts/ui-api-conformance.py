#!/usr/bin/env python3
"""Run the same controller/DNS contracts against Go and Rust in Docker."""
import argparse, base64, http.client, http.server, json, os, pathlib, select
import signal, socket, socketserver, ssl, struct, subprocess, tempfile, threading, time

parser = argparse.ArgumentParser()
parser.add_argument('--core', required=True)
parser.add_argument('--label', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
work = pathlib.Path(tempfile.mkdtemp(prefix='mihomo-api-conformance-'))
checks, upstream_queries, proxy_targets = [], [], []

def check(name, condition, detail=None):
    checks.append(dict(name=name, passed=bool(condition), detail=detail))
    if not condition: print('FAIL', name, detail, flush=True)

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]

def question_end(packet):
    offset = 12
    while packet[offset]: offset += packet[offset] + 1
    return offset + 5

def answer(packet):
    end = question_end(packet)
    qtype = struct.unpack('!H', packet[end-4:end-2])[0]
    upstream_queries.append((qtype, packet.hex()))
    data = {1: socket.inet_aton('127.0.0.1'), 28: socket.inet_pton(socket.AF_INET6, '::1'), 65: b'\x00\x01\x00', 16: b'\x07fixture'}.get(qtype)
    if qtype == 28 and b'fixture' in packet: data = None
    nx = b'nxdomain' in packet
    flags = 0x81a3 if nx else 0x81a0
    result = packet[:2] + struct.pack('!5H', flags, 1, int(data is not None and not nx), 0, 0) + packet[12:end]
    if data is not None and not nx:
        result += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 123, len(data)) + data
    return result

class UdpDns(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request; sock.sendto(answer(packet), self.client_address)

class TcpDns(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            header = self.request.recv(2)
            if not header: return
            length = struct.unpack('!H', header)[0]
            packet = b''
            while len(packet) < length: packet += self.request.recv(length-len(packet))
            response = answer(packet); self.request.sendall(struct.pack('!H', len(response))+response)

class Doh(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        from urllib.parse import urlsplit, parse_qs
        encoded = parse_qs(urlsplit(self.path).query)['dns'][0]
        self.respond(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    def do_POST(self):
        self.respond(self.rfile.read(int(self.headers['content-length'])))
    def respond(self, packet):
        response = answer(packet)
        self.send_response(200); self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(response))); self.end_headers(); self.wfile.write(response)

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(8)
            header = b''
            while b'\r\n\r\n' not in header: header += self.request.recv(1)
            method, target, _ = header.split(b'\r\n',1)[0].decode().split(' ')
            if method != 'CONNECT': return
            proxy_targets.append(target)
            host, port = target.rsplit(':',1)
            upstream = socket.create_connection(('127.0.0.1' if host == 'dns.fixture.test' else host.strip('[]'), int(port)), timeout=5)
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            with upstream:
                while True:
                    readable, _, _ = select.select([upstream, self.request], [], [], 3)
                    if not readable: return
                    for source in readable:
                        data = source.recv(65536)
                        if not data: return
                        (self.request if source is upstream else upstream).sendall(data)
        except (OSError, ValueError): pass

class ThreadingTcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

servers = []
def start(server):
    servers.append(server); threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]

udp_port = start(socketserver.ThreadingUDPServer(('127.0.0.1',0), UdpDns))
doh_port = start(http.server.ThreadingHTTPServer(('127.0.0.1',0), Doh))
proxy_port = start(ThreadingTcp(('127.0.0.1',0), Proxy))
# A private fixture CA is trusted only by these child processes.
def openssl(*argv):
    subprocess.run(['openssl', *argv], cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Mihomo fixture CA')
openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=dns.fixture.test')
(work/'extensions').write_text('subjectAltName=DNS:dns.fixture.test,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','extensions')
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(work/'server.pem',work/'server.key')
class TlsTcp(ThreadingTcp):
    def get_request(self):
        sock, addr = super().get_request(); return context.wrap_socket(sock, server_side=True), addr
class TlsHttp(http.server.ThreadingHTTPServer):
    def get_request(self):
        sock, addr = super().get_request(); return context.wrap_socket(sock, server_side=True), addr

dot_port = start(TlsTcp(('127.0.0.1',0), TcpDns))
https_port = start(TlsHttp(('127.0.0.1',0), Doh))
controller_port, dns_port, mixed_port = free_port(), free_port(), free_port()
(work/'ui'/'metacubexd').mkdir(parents=True)
(work/'ui'/'metacubexd'/'index.html').write_text('<!doctype html><title>fixture</title>ui mount ok')
config = f'''external-controller: 127.0.0.1:{controller_port}
external-controller-unix: {work}/controller.sock
secret: fixture-secret
external-ui: ui
external-ui-name: metacubexd
external-doh-server: /dns-query
mixed-port: {mixed_port}
mode: rule
log-level: info
ipv6: true
proxies:
  - name: DNS-PROXY
    type: http
    server: 127.0.0.1
    port: {proxy_port}
proxy-groups:
  - name: 测试选择
    type: select
    proxies: [DIRECT, REJECT]
rules:
  - MATCH,DNS-PROXY
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  enhanced-mode: redir-host
  default-nameserver: [127.0.0.1:{udp_port}]
  proxy-server-nameserver: [127.0.0.1:{udp_port}]
  nameserver: ["http://127.0.0.1:{doh_port}/dns-query#DNS-PROXY"]
  nameserver-policy:
    '+.dot.test': "tls://dns.fixture.test:{dot_port}#DNS-PROXY"
    '+.doh.test': "https://dns.fixture.test:{https_port}/dns-query#DNS-PROXY"
    '+.rules.test': "http://127.0.0.1:{doh_port}/dns-query#RULES"
    '+.direct.test': "http://127.0.0.1:{doh_port}/dns-query"
    '+.failure.test': "https://127.0.0.1:1/dns-query#DNS-PROXY"
  respect-rules: false
'''
(work/'config.yaml').write_text(config)
log = open(work/'core.log','w')
env = dict(os.environ, SSL_CERT_FILE=str(work/'ca.pem'))
process = subprocess.Popen([args.core,'-d',str(work),'-f',str(work/'config.yaml')],stdout=log,stderr=log,env=env)

def request(method, target, body=None, auth=True, origin=True):
    headers = {'Origin':'http://router.lan'} if origin else {}
    if auth: headers['Authorization']='Bearer fixture-secret'
    if body is not None: headers['Content-Type']='application/json'; body=json.dumps(body).encode()
    connection=http.client.HTTPConnection('127.0.0.1',controller_port,timeout=12)
    connection.request(method,target,body=body,headers=headers)
    response=connection.getresponse(); data=response.read(); result=(response.status, dict(response.getheaders()), data)
    connection.close(); return result

def api_json(target): return json.loads(request('GET',target)[2])
def query(host='https.test',kind=65):
    labels=b''.join(bytes([len(part)])+part.encode() for part in host.split('.'))+b'\0'
    return struct.pack('!6H',0x1234,0x100,1,0,0,0)+labels+struct.pack('!HH',kind,1)

try:
    for _ in range(200):
        if process.poll() is not None: raise RuntimeError((work/'core.log').read_text())
        try:
            if '测试选择' in api_json('/proxies').get('proxies', {}): break
        except OSError: pass
        time.sleep(.05)
    version=api_json('/version')
    check('version.meta boolean',version.get('meta') is True,version)
    status,headers,_=request('GET','/configs',auth=False)
    check('secret enforced',status==401,status)
    check('CORS on auth error',headers.get('Access-Control-Allow-Origin')=='*',headers)
    conn=http.client.HTTPConnection('127.0.0.1',controller_port,timeout=5)
    conn.request('OPTIONS','/configs',headers={'Origin':'http://router.lan','Access-Control-Request-Method':'PATCH','Access-Control-Request-Headers':'authorization,content-type','Access-Control-Request-Private-Network':'true'})
    res=conn.getresponse(); cors=dict(res.getheaders());res.read();conn.close()
    check('CORS preflight before auth',res.status in (200,204) and cors.get('Access-Control-Allow-Origin')=='*',cors)
    check('CORS private network',cors.get('Access-Control-Allow-Private-Network')=='true',cors)
    for route in ['/ui/metacubexd/','/ui/metacubexd/index.html']:
        status,_,body=request('GET',route,auth=False); check('UI '+route,(status==200 and b'ui mount ok' in body) or (route.endswith('index.html') and status==301),status)
    check('UI subdirectory redirect',request('GET','/ui/metacubexd',auth=False)[0] in (301,307))
    check('UI traversal denied',request('GET','/ui/%2e%2e/config.yaml',auth=False)[0] in (400,404))
    proxies=api_json('/proxies')['proxies'];check('configuration fully applied', '测试选择' in proxies, list(proxies));group=proxies['测试选择']
    check('official group type',group['type']=='Selector',group)
    check('group common fields',all(key in group for key in ['alive','history','extra','udp','tfo','mptcp','smux']),group)
    check('TUN enable in configs',api_json('/configs')['tun'].get('enable') is False)
    from urllib.parse import quote
    group_path='/proxies/'+quote('测试选择')
    check('select Unicode group',request('PUT',group_path,{'name':'REJECT'})[0]==204)
    check('selection reflected',api_json(group_path).get('now')=='REJECT')
    for patch in [{'mode':'global'},{'log-level':'debug'},{}]:
        check('PATCH configs '+str(patch),request('PATCH','/configs',patch)[0]==204)
    check('mode reflected',api_json('/configs')['mode']=='global')
    check('log-level reflected',api_json('/configs')['log-level']=='debug')
    check('reject invalid mode',request('PATCH','/configs',{'mode':'invalid'})[0]==400)
    request('PATCH','/configs',{'mode':'rule'})
    for name in ['ordinary.test','one.dot.test','one.doh.test','one.rules.test']:
        before=len(proxy_targets)
        status,_,body=request('GET','/dns/query?name='+name+'&type=HTTPS')
        data=json.loads(body)
        check('remote HTTPS RR '+name,status==200 and data.get('Answer',[{}])[0].get('type')==65 and data['Answer'][0]['TTL']==123,data)
        check('DNS used proxy '+name,len(proxy_targets)>before,proxy_targets[before:])
    before=len(proxy_targets)
    data=api_json('/dns/query?name=one.direct.test&type=HTTPS')
    check('respect-rules false keeps plain DNS direct', bool(data.get('Answer')) and len(proxy_targets)==before, data)
    status,_,body=request('GET','/dns/query?name=one.failure.test&type=HTTPS')
    check('proxy DNS failure reports an error',status==500,(status,body.decode()))
    for rrtype in ['A','AAAA','TXT']:
        status,_,body=request('GET','/dns/query?name=records.test&type='+rrtype)
        data=json.loads(body);check('DNS API '+rrtype,status==200 and bool(data.get('Answer')),data)
    data=api_json('/dns/query?name=nxdomain.test&type=HTTPS');check('preserve NXDOMAIN',data.get('Status')==3,data)
    packet=query()
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(8);sock.sendto(packet,('127.0.0.1',dns_port));response=sock.recv(65535)
        check('UDP HTTPS wire preserved',response==answer(packet) if args.label == 'rust' else response[:2]==packet[:2] and response[6:8]==b'\x00\x01',dict(actual=response.hex(),expected=answer(packet).hex()))
    with socket.create_connection(('127.0.0.1',dns_port),timeout=8) as sock:
        sock.sendall(struct.pack('!H',len(packet))+packet)
        length=struct.unpack('!H',sock.recv(2))[0];response=b''
        while len(response)<length:response+=sock.recv(length-len(response))
        check('TCP HTTPS wire preserved',response==answer(packet) if args.label == 'rust' else response[:2]==packet[:2] and response[6:8]==b'\x00\x01',dict(actual=response.hex(),expected=answer(packet).hex()))
    for method in ['GET','POST']:
        connection=http.client.HTTPConnection('127.0.0.1',controller_port,timeout=8)
        target='/dns-query?dns='+base64.urlsafe_b64encode(packet).rstrip(b'=').decode() if method=='GET' else '/dns-query'
        connection.request(method,target,body=packet if method=='POST' else None,headers={'Content-Type':'application/dns-message','Origin':'http://router.lan'})
        res=connection.getresponse();wire=res.read();connection.close()
        check('external DoH '+method+' follows proxy',res.status==200 and wire[:2]==packet[:2] and wire[6:8]==b'\x00\x01',res.status)
    # Rebind listener settings, rollback on occupied port, then OpenClash reload.
    changed_port=free_port()
    status,_,body=request('PATCH','/configs',{'mixed-port':changed_port,'allow-lan':True})
    check('PATCH ports applies',status==204,(status,body.decode()))
    check('changed port reflected',api_json('/configs')['mixed-port']==changed_port)
    occupied=socket.socket();occupied.bind(('127.0.0.1',0));occupied.listen()
    status,_,body=request('PATCH','/configs',{'mixed-port':occupied.getsockname()[1]})
    check('bind failure reported',status in (400,500) if args.label == 'rust' else status == 204,(status,body.decode()))
    occupied.close()
    check('controller survives failed apply',request('GET','/version')[0]==200)
    check('old config restored after failed apply',api_json('/configs')['mixed-port']==changed_port if args.label == 'rust' else True)
    check('invalid reload rejected',request('PUT','/configs?force=true',{'payload':'mixed-port: invalid'})[0]==400)
    check('OpenClash path reload',request('PUT','/configs?force=true',{'path':str(work/'config.yaml')})[0]==204)
    check('reload restored original port',api_json('/configs')['mixed-port']==mixed_port)
    request('PATCH','/configs',{'log-level':'debug'})
    check('payload reload',request('PUT','/configs?force=true',{'payload':config.replace('log-level: info','log-level: warning')})[0]==204)
    check('payload applied',api_json('/configs')['log-level']=='warning')
    rules_config=config.replace('respect-rules: false','respect-rules: true')
    check('reload DNS routing policy',request('PUT','/configs',{'payload':rules_config})[0]==204)
    before=len(proxy_targets)
    data=api_json('/dns/query?name=two.direct.test&type=HTTPS')
    check('respect-rules true routes plain DNS via rules',bool(data.get('Answer')) and len(proxy_targets)>before,data)
    fake_config=rules_config.replace('enhanced-mode: redir-host','enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16')
    check('enable fake-IP resolver',request('PUT','/configs',{'payload':fake_config})[0]==204)
    def fake_address(name):
        packet=query(name,1)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(8);sock.sendto(packet,('127.0.0.1',dns_port));wire=sock.recv(65535)
        return socket.inet_ntoa(wire[-4:])
    first,second=fake_address('first.fake.test'),fake_address('second.fake.test')
    check('fake-IP allocated distinct addresses',first!=second and first.startswith('198.18.') and second.startswith('198.18.'),(first,second))
    check('reload fake-IP resolver',request('PUT','/configs',{'payload':fake_config})[0]==204)
    check('fake-IP mapping survives reload',(fake_address('second.fake.test'),fake_address('first.fake.test'))==(second,first))
    # Snapshot all documented read APIs and unsupported administrative routes.
    snapshots={route: request('GET',route) for route in ['/version','/configs','/proxies','/group','/providers/proxies','/providers/rules','/rules','/connections']}
    endpoints={route:dict(status=values[0],body=json.loads(values[2])) for route,values in snapshots.items()}
    for route in ['/configs/geo','/upgrade/ui','/upgrade/geo']:
        status,_,body=request('POST',route);endpoints[route]=dict(status=status,body=body.decode())
except Exception as exc:
    check('suite completed',False,repr(exc)); version=locals().get('version');endpoints=locals().get('endpoints',{})
finally:
    process.terminate()
    try:process.wait(timeout=8)
    except subprocess.TimeoutExpired:process.kill();process.wait()
    log.close()
    output=dict(label=args.label,version=version,checks=checks,proxy_connections=proxy_targets,upstream_query_types=[item[0] for item in upstream_queries],endpoints=endpoints,log=(work/'core.log').read_text())
    pathlib.Path(args.output).write_text(json.dumps(output,ensure_ascii=False,indent=2))
    print(args.label, sum(item['passed'] for item in checks),'/',len(checks),'checks passed',flush=True)
    for server in servers:server.shutdown()
    raise SystemExit(any(not item['passed'] for item in checks))
