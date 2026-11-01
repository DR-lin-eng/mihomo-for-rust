#!/usr/bin/env python3
"""OpenClash TUN readiness and real marked TCP/UDP forwarding in Docker.

Requires an isolated privileged Linux network namespace, /dev/net/tun, iproute2,
and Python. No public DNS/server or user authentication data is used.
"""
import argparse
import base64
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
import select

p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--output',required=True);args=p.parse_args()
root=pathlib.Path(tempfile.mkdtemp(prefix='openclash-tun-smoke-'));checks=[];hits=[];core=None;server=None
mark=0x162;table=21622;priority=1888
def check(name,passed,detail=None):
    checks.append(dict(name=name,passed=bool(passed),detail=detail))
    if not passed:print('FAIL',name,detail,flush=True)
def command(*parts,required=True):return subprocess.run(parts,text=True,capture_output=True,check=required,timeout=10)
def free():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait_for(test,timeout=8):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        value=test()
        if value:return value
        time.sleep(.025)
    raise AssertionError('fixture condition timed out')
def exact(sock,n):
    out=b''
    while len(out)<n:
        data=sock.recv(n-len(out))
        if not data:raise EOFError()
        out+=data
    return out
def address(sock):
    kind=exact(sock,1)[0]
    if kind==1:host=socket.inet_ntop(socket.AF_INET,exact(sock,4))
    elif kind==4:host=socket.inet_ntop(socket.AF_INET6,exact(sock,16))
    elif kind==3:host=exact(sock,exact(sock,1)[0]).decode()
    else:raise ValueError(kind)
    return host,struct.unpack('!H',exact(sock,2))[0]
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(8)
            version,methods=exact(self.request,2);assert version==5
            exact(self.request,methods);self.request.sendall(b'\x05\x00')
            version,cmd,reserved=exact(self.request,3);host,port=address(self.request);hits.append((cmd,host,port))
            if host=='198.51.100.99':
                self.request.sendall(b'\x05\x00');return
            if cmd==1:
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                data=self.request.recv(4096)
                if data:self.request.sendall(b'reply:'+data)
                self.request.shutdown(socket.SHUT_WR)
            elif cmd==3:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1',0));relay=udp.getsockname()[1]
                    self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',relay))
                    while True:
                        ready,_,_=select.select([udp,self.request],[],[],5)
                        if not ready:return
                        if self.request in ready:
                            if not self.request.recv(1024):return
                        if udp in ready:
                            data,peer=udp.recvfrom(65535)
                            assert data[:4]==b'\x00\x00\x00\x01'
                            hits.append(('udp',socket.inet_ntoa(data[4:8]),struct.unpack('!H',data[8:10])[0]))
                            udp.sendto(data[:10]+b'reply:'+data[10:],peer)
        except (OSError,EOFError,AssertionError,ValueError):pass
def api(path):
    c=http.client.HTTPConnection('127.0.0.1',ctl,timeout=3);c.request('GET',path);r=c.getresponse();data=r.read();c.close();assert r.status==200;return json.loads(data)
def log_text():return (root/'core.log').read_text()
def http_connect(target):
    sock=socket.create_connection(('127.0.0.1',mixed),timeout=5);sock.settimeout(5)
    auth=base64.b64encode(b'fixture:fixture').decode()
    sock.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n'.encode())
    head=b''
    while not head.endswith(b'\r\n\r\n'):
        data=sock.recv(1)
        if not data:break
        head+=data
    return sock,head
def start(config):
    global core,log
    (root/'config.yaml').write_text(config);log=(root/'core.log').open('w')
    core=subprocess.Popen([args.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
    def ready():
        if core.poll() is not None:raise RuntimeError(log_text())
        try:return api('/version')
        except OSError:return False
    wait_for(ready)
def stop():
    if core is not None and core.poll() is None:
        core.terminate()
        try:core.wait(10)
        except subprocess.TimeoutExpired:core.kill();core.wait();check('bounded shutdown',False)
    if 'log' in globals():log.close()

try:
    assert command('ip','link','show','dev','utun',required=False).returncode!=0,'fixture requires unused utun'
    server=Server(('127.0.0.1',0),Proxy);threading.Thread(target=server.serve_forever,daemon=True).start();proxy=server.server_address[1]
    mixed,socks,ctl=free(),free(),free()
    config=f'''mixed-port: {mixed}
socks-port: {socks}
external-controller: 127.0.0.1:{ctl}
log-level: debug
authentication: ['fixture:fixture']
dns:
  enable: true
  enhanced-mode: redir-host
  nameserver: [rcode://success]
tun:
  enable: true
  stack: system
  device: utun
  dns-hijack: [127.0.0.1:53]
  endpoint-independent-nat: true
  auto-route: false
  auto-detect-interface: false
  auto-redirect: false
  strict-route: false
proxies:
  - {{name: fixture, type: socks5, server: 127.0.0.1, port: {proxy}, udp: true}}
rules: ['MATCH,fixture']
'''
    original_rules=command('ip','-4','rule','show').stdout
    start(config)
    link=command('ip','link','show','dev','utun').stdout
    check('utun exists and is up','UP' in link,link)
    addresses=command('ip','-4','addr','show','dev','utun').stdout
    check('Go-compatible default interface address','198.18.0.1/30' in addresses,addresses)
    routes=command('ip','route','list').stdout
    check('OpenClash exact main-table readiness condition','utun' in routes,routes)
    check('connected subnet is /30','198.18.0.0/30 dev utun' in routes,routes)
    check('frontend still owns policy routing',command('ip','-4','rule','show').stdout==original_rules)
    check('TUN startup log identifies address','[TUN] interface utun started' in log_text() and '198.18.0.1/30' in log_text())
    for _ in range(5):
        for dest,data in [(socks,b''),(mixed,b'\x05'),(mixed,b'G')]:
            with socket.create_connection(('127.0.0.1',dest),timeout=3) as sock:
                if data:sock.sendall(data)
    time.sleep(.25)
    check('closed probes do not become error spam','listener dispatch error' not in log_text(),log_text())
    with socket.create_connection(('127.0.0.1',mixed),timeout=3) as sock:
        sock.sendall(b'INVALID\r\n\r\n');sock.recv(1024)
    wait_for(lambda:'invalid http proxy request' in log_text())
    check('malformed requests remain visible','protocol=mixed' in log_text() and 'peer=Some(' in log_text(),log_text())
    sock,head=http_connect('198.51.100.99:443');sock.close()
    wait_for(lambda:'failed to fill whole buffer' in log_text())
    check('real truncated upstream responses remain errors','listener dispatch error protocol=mixed' in log_text() and b'502' in head,head.decode(errors='replace'))
    sock,head=http_connect('198.51.100.10:443')
    with sock:
        check('authenticated mixed HTTP CONNECT still works',b'200' in head,head.decode(errors='replace'))
        sock.sendall(b'plain-proxy');check('ordinary proxy forwarding after probes',sock.recv(4096)==b'reply:plain-proxy')
    command('ip','route','add','default','dev','utun','table',str(table))
    command('ip','rule','add','fwmark',hex(mark),'table',str(table),'priority',str(priority))
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark);sock.settimeout(6);sock.connect(('198.51.100.20',443));sock.sendall(b'tun-tcp')
        check('marked TCP goes through real TUN and proxy',sock.recv(4096)==b'reply:tun-tcp')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark);sock.settimeout(6);sock.connect(('198.51.100.21',9999));sock.send(b'tun-udp')
        check('marked UDP goes through real TUN and SOCKS relay',sock.recv(4096)==b'reply:tun-udp')
    check('TCP proxy sees original TUN destination',(1,'198.51.100.20',443) in hits,hits)
    check('UDP proxy sees original TUN destination',('udp','198.51.100.21',9999) in hits,hits)
    command('ip','rule','del','fwmark',hex(mark),'table',str(table),'priority',str(priority))
    command('ip','route','flush','table',str(table))
    stop();check('TUN disappears on normal core shutdown',command('ip','link','show','dev','utun',required=False).returncode!=0)
    check('frontend rules preserved on shutdown',command('ip','-4','rule','show').stdout==original_rules)
    sniff_config=config.replace("rules: ['MATCH,fixture']", "rules: ['DOMAIN,tun.example,fixture','MATCH,REJECT']")+'''sniffer:
  enable: true
  parse-pure-ip: true
  force-dns-mapping: true
  override-destination: true
  sniff:
    TLS: {ports: [443]}
'''
    start(sniff_config)
    command('ip','route','add','default','dev','utun','table',str(table))
    command('ip','rule','add','fwmark',hex(mark),'table',str(table),'priority',str(priority))
    host=b'tun.example';sni=struct.pack('!H',len(host)+3)+b'\x00'+struct.pack('!H',len(host))+host
    extensions=b'\x00\x00'+struct.pack('!H',len(sni))+sni
    body=b'\x03\x03'+bytes(32)+b'\x00\x00\x02\x00\x2f\x01\x00'+struct.pack('!H',len(extensions))+extensions
    handshake=b'\x01'+len(body).to_bytes(3,'big')+body;hello=b'\x16\x03\x03'+struct.pack('!H',len(handshake))+handshake
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark);sock.settimeout(6);sock.connect(('198.51.100.22',443));sock.sendall(hello[:8]);time.sleep(.025);sock.sendall(hello[8:])
        check('TUN fragmented TLS SNI selects domain rule',sock.recv(4096)==b'reply:'+hello)
    check('TUN proxy sees sniffed hostname',(1,'tun.example',443) in hits,hits)
    command('ip','rule','del','fwmark',hex(mark),'table',str(table),'priority',str(priority));command('ip','route','flush','table',str(table));stop()
    # A custom fake-IP range must seed the interface's own /30 too.
    config=config.replace('enhanced-mode: redir-host','enhanced-mode: redir-host\n  fake-ip-range: 198.19.12.1/16')
    start(config)
    check('custom fake-IP seed derives correct /30','198.19.12.1/30' in command('ip','-4','addr','show','dev','utun').stdout)
    check('custom range also passes OpenClash readiness','198.19.12.0/30 dev utun' in command('ip','route','list').stdout)
    stop()
except Exception as error:
    check('fixture execution',False,repr(error))
    if (root/'core.log').exists():print(log_text()[-4000:],flush=True)
finally:
    command('ip','rule','del','fwmark',hex(mark),'table',str(table),'priority',str(priority),required=False)
    command('ip','route','flush','table',str(table),required=False)
    stop()
    if server is not None:server.shutdown();server.server_close()
    result=dict(passed=all(c['passed'] for c in checks),checks=checks,work=str(root),core=args.core,sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest(),proxy_hits=hits)
    pathlib.Path(args.output).write_text(json.dumps(result,indent=2));print(json.dumps(dict(passed=result['passed'],checks=len(checks),work=str(root))),flush=True)
raise SystemExit(0 if result['passed'] else 1)
