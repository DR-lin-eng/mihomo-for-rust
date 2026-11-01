#!/usr/bin/env python3
"""Real REDIRECT/TPROXY domain routing with DNS, TLS SNI, HTTP Host and QUIC.
Run only in an isolated privileged Docker network namespace. No public server,
subscription, user account or real node configuration is used.
"""
import argparse,base64,hashlib,http.client,json,os,pathlib,select,socket,socketserver,ssl,struct,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--output',required=True);args=p.parse_args()
root=pathlib.Path(tempfile.mkdtemp(prefix='domain-routing-'));checks=[];hits=[];dns_hits=[];servers=[];core=None;clients=[]
ns='domain-'+str(os.getpid());veth='dr'+str(os.getpid());peer='dp'+str(os.getpid());router='10.93.0.1';client_ip='10.93.0.2';mark=0x793;table=21793
def check(name,ok,detail=None):
    checks.append(dict(name=name,passed=bool(ok),detail=detail))
    if not ok:print('FAIL',name,detail,flush=True)
def run(*cmd,ok=True):return subprocess.run(cmd,text=True,capture_output=True,check=ok,timeout=15)
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait_for(fn,timeout=10):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=fn()
        if value:return value
        time.sleep(.03)
    raise AssertionError('fixture condition timed out')
def exact(sock,n):
    out=b''
    while len(out)<n:
        b=sock.recv(n-len(out))
        if not b:raise EOFError()
        out+=b
    return out
def read_head(sock):
    out=b''
    while not out.endswith(b'\r\n\r\n'):
        out+=exact(sock,1)
        if len(out)>65536:raise ValueError('fixture header limit')
    return out
def decode_addr(sock):
    kind=exact(sock,1)[0]
    if kind==1:host=socket.inet_ntoa(exact(sock,4))
    elif kind==4:host=socket.inet_ntop(socket.AF_INET6,exact(sock,16))
    elif kind==3:host=exact(sock,exact(sock,1)[0]).decode()
    else:raise ValueError(kind)
    return host,struct.unpack('!H',exact(sock,2))[0]
class TCP(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class UDP(socketserver.ThreadingUDPServer):allow_reuse_address=True;daemon_threads=True
def start(server):servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start();return server.server_address[1]
def wire_name(name):return b''.join(bytes([len(v)])+v.encode() for v in name.split('.'))+b'\x00'
def question(packet):
    pos=12;parts=[]
    while packet[pos]:n=packet[pos];pos+=1;parts.append(packet[pos:pos+n].decode());pos+=n
    pos+=1;return '.'.join(parts),struct.unpack('!H',packet[pos:pos+2])[0],pos+4
def rr(owner,kind,ttl,data):return owner+struct.pack('!HHIH',kind,1,ttl,len(data))+data
ip_for={name:'203.0.113.'+str(i+10) for i,name in enumerate(['mapping.test','dns-tcp.test','alias.test','hints.test','hosts.test','unmatched.test','ttl.test','provider.test','udp-mapping.test'])}
def dns_reply(packet):
    host,kind,end=question(packet);dns_hits.append((host,kind));ip=ip_for.get(host,'203.0.113.202');ttl=1 if host=='ttl.test' else 60;answers=[]
    if kind==1:
        if host=='alias.test':answers.append(rr(b'\xc0\x0c',5,ttl,wire_name('edge.test')));owner=wire_name('edge.test')
        else:owner=b'\xc0\x0c'
        answers.append(rr(owner,1,ttl,socket.inet_aton(ip)))
    elif kind==65:answers.append(rr(b'\xc0\x0c',65,ttl,b'\x00\x01\x00'+struct.pack('!HH',4,4)+socket.inet_aton(ip)))
    return packet[:2]+struct.pack('!HHHHH',0x8180,1,len(answers),0,0)+packet[12:end]+b''.join(answers)
class DnsUDP(socketserver.BaseRequestHandler):
    def handle(self):data,sock=self.request;sock.sendto(dns_reply(data),self.client_address)
class DnsTCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:data=exact(self.request,struct.unpack('!H',exact(self.request,2))[0]);answer=dns_reply(data);self.request.sendall(struct.pack('!H',len(answer))+answer)
        except (OSError,EOFError):pass
class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(12);v,n=exact(self.request,2);assert v==5;exact(self.request,n);self.request.sendall(b'\x05\x00');v,cmd,_=exact(self.request,3);host,target_port=decode_addr(self.request)
            hits.append(dict(node=self.server.node,kind='connect',host=host,port=target_port))
            if host=='eof.test':self.request.sendall(b'\x05\x00');return
            if cmd==3:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1',0));self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',udp.getsockname()[1]))
                    while True:
                        ready,_,_=select.select([udp,self.request],[],[],8)
                        if not ready:return
                        if self.request in ready and not self.request.recv(1024):return
                        if udp in ready:
                            data,addr=udp.recvfrom(65535);assert data[:4]==b'\x00\x00\x00\x01';body=data[10:]
                            hit=dict(node=self.server.node,kind='udp',host=socket.inet_ntoa(data[4:8]),port=struct.unpack('!H',data[8:10])[0],sha256=hashlib.sha256(body).hexdigest());hits.append(hit)
                            response=json.dumps(dict(node=self.server.node,host=hit['host'],sha256=hit['sha256'])).encode();udp.sendto(data[:10]+response,addr)
            elif cmd==1:
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                stream=server_tls.wrap_socket(self.request,server_side=True) if target_port in (443,8443,9443) else self.request
                with stream:
                    head=read_head(stream);length=0
                    for line in head.split(b'\r\n'):
                        if line.lower().startswith(b'content-length:'):length=int(line.split(b':',1)[1])
                    body=exact(stream,length) if length else b'';result=dict(node=self.server.node,target=host+':'+str(target_port),sha256=hashlib.sha256(head+body).hexdigest())
                    reply=json.dumps(result).encode();stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(reply)).encode()+b'\r\nConnection: keep-alive\r\n\r\n'+reply)
                    try:stream.recv(1)
                    except OSError:pass
        except (OSError,EOFError,ValueError,AssertionError):pass

client_code=r'''
import sys,socket,ssl,struct,json,time,http.client,hashlib
job=json.loads(sys.argv[1])
if job['mode']=='dns':
 q=job['host'];packet=b'\x19\x93\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b''.join(bytes([len(v)])+v.encode() for v in q.split('.'))+b'\x00'+struct.pack('!HH',job.get('kind',1),1)
 if job.get('tcp'):
  s=socket.create_connection((job['router'],job['port']),timeout=5);s.sendall(struct.pack('!H',len(packet))+packet);n=struct.unpack('!H',s.recv(2))[0];data=b''
  while len(data)<n:data+=s.recv(n-len(data))
 else:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);s.sendto(packet,(job['router'],job['port']));data=s.recv(65535)
 print(json.dumps(dict(bytes=len(data),rcode=data[3]&15,hex=data.hex())),flush=True);s.close()
elif job['mode']=='udp':
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);s.connect((job['ip'],job['port']))
 for part in job['packets']:s.send(bytes.fromhex(part));time.sleep(.025)
 data=s.recv(65535);print(data.decode(),flush=True);s.close()
else:
 s=socket.create_connection((job['ip'],job['port']),timeout=6);s.settimeout(6)
 if job.get('tls'):s=ssl._create_unverified_context().wrap_socket(s,server_hostname=job['host'])
 raw=bytes.fromhex(job['request']);cut=job.get('cut',0)
 if cut:s.sendall(raw[:cut]);time.sleep(.025);s.sendall(raw[cut:])
 else:s.sendall(raw)
 response=http.client.HTTPResponse(s);response.begin();data=json.loads(response.read());data['client_port']=s.getsockname()[1];data['request_sha256']=hashlib.sha256(raw).hexdigest();print(json.dumps(data),flush=True);sys.stdin.readline();s.close()
'''
def client(job,hold=False):
    process=subprocess.Popen(['ip','netns','exec',ns,'python3','-u','-c',client_code,json.dumps(job)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);clients.append(process)
    ready,_,_=select.select([process.stdout],[],[],10)
    if not ready:raise AssertionError('namespace client timed out')
    text=process.stdout.readline()
    if not text:raise AssertionError(process.stderr.read())
    result=json.loads(text)
    if not hold:process.stdin.close();process.wait(8)
    return result,process
def release(process):
    if process.poll() is None:process.stdin.write('\n');process.stdin.flush();process.wait(8)
def api(path):
    c=http.client.HTTPConnection('127.0.0.1',controller,timeout=5);c.request('GET',path);response=c.getresponse();data=response.read();c.close();assert response.status==200;return json.loads(data)
def dns(host,kind=1,tcp=False):return client(dict(mode='dns',host=host,kind=kind,tcp=tcp,router=router,port=dns_port))[0]
def flow(host,ip,expected,port=443,tls=True,rule=None,body=b'',cut=0):
    raw=(f'POST /fixture HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\nX-Bytes: preserve\r\n\r\n'.encode()+body)
    result,process=client(dict(mode='tcp',ip=ip,port=port,host=host,tls=tls,request=raw.hex(),cut=cut),True)
    try:
        check('actual route '+host+' '+str(port),result['node']==expected,result)
        check('payload unchanged '+host,result['sha256']==result['request_sha256'],result)
        row=wait_for(lambda:next((c for c in api('/connections')['connections'] if str(c['metadata'].get('sourcePort'))==str(result['client_port'])),None))
        if rule:check('API matched rule '+host,rule.lower().replace('-','') in row['rule'].lower().replace('-',''),row)
        return result,row
    finally:release(process)
def launch(sniffer,override=True):
    global core,log
    lines='''sniffer:
  enable: %s
  override-destination: %s
  parse-pure-ip: true
  force-dns-mapping: true
  skip-domain: ['+.apple.com']
  force-domain: ['+.netflix.com']
  sniff:
    TLS: {ports: [443,8443]}
    HTTP: {ports: [80,8080-8880]}
    QUIC: {ports: [443]}
'''%('true' if sniffer else 'false','true' if override else 'false')
    names=['mapping.test','dns-tcp.test','alias.test','hints.test','hosts.test','ttl.test','udp-mapping.test','sni.test','override.test','eof.test','www.google.com','cloudflare-dns.com','quic.nginx.org','chat.openai.com','fonts.gstatic.com','ogads-pa.clients6.google.com']
    config=f'''allow-lan: true
bind-address: '*'
redir-port: {redir_port}
tproxy-port: {tproxy_port}
external-controller: 127.0.0.1:{controller}
log-level: debug
dns:
  enable: true
  enhanced-mode: redir-host
  use-hosts: true
  listen: 0.0.0.0:{dns_port}
  nameserver: [udp://127.0.0.1:{upstream}]
hosts:
  hosts.test: {ip_for['hosts.test']}
proxies:
  - {{name: domain, type: socks5, server: 127.0.0.1, port: {domain_proxy}, udp: true}}
  - {{name: fallback, type: socks5, server: 127.0.0.1, port: {fallback_proxy}, udp: true}}
rule-providers:
  media:
    type: inline
    behavior: classical
    payload: ['DOMAIN-SUFFIX,provider.test']
rules:
'''+''.join('  - DOMAIN,'+name+',domain\n' for name in names)+'''  - DOMAIN-SUFFIX,example.test,domain
  - RULE-SET,media,domain
  - MATCH,fallback
'''+lines
    (root/'config.yaml').write_text(config);log=(root/('core-'+str(sniffer)+'.log')).open('w');core=subprocess.Popen([args.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
    def ready():
        if core.poll() is not None:raise RuntimeError(log.name+': '+pathlib.Path(log.name).read_text())
        try:return api('/version')
        except OSError:return False
    wait_for(ready)
def stop():
    if core is not None and core.poll() is None:
        core.terminate()
        try:core.wait(12)
        except subprocess.TimeoutExpired:core.kill();core.wait();check('bounded shutdown',False)
    if 'log' in globals():log.close()

try:
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=domain-routing-fixture','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'))
    server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_tls.load_cert_chain(root/'cert.pem',root/'key.pem')
    upstream=start(UDP(('127.0.0.1',0),DnsUDP));start(TCP(('127.0.0.1',upstream),DnsTCP))
    a=TCP(('127.0.0.1',0),Proxy);a.node='domain';domain_proxy=start(a);b=TCP(('127.0.0.1',0),Proxy);b.node='fallback';fallback_proxy=start(b)
    redir_port,tproxy_port,dns_port,controller=port(),port(),port(),port()
    run('ip','netns','add',ns);run('ip','link','add',veth,'type','veth','peer','name',peer);run('ip','link','set',peer,'netns',ns)
    run('ip','addr','add',router+'/24','dev',veth);run('ip','link','set',veth,'up');run('ip','-n',ns,'link','set','lo','up');run('ip','-n',ns,'addr','add',client_ip+'/24','dev',peer);run('ip','-n',ns,'link','set',peer,'up');run('ip','-n',ns,'route','add','default','via',router)
    tcp_rule=['-s',client_ip,'-d','203.0.113.0/24','-p','tcp','-j','REDIRECT','--to-ports',str(redir_port)]
    udp_rule=['-s',client_ip,'-d','203.0.113.0/24','-p','udp','-j','TPROXY','--on-port',str(tproxy_port),'--tproxy-mark',hex(mark)]
    run('iptables','-t','nat','-A','PREROUTING',*tcp_rule);run('iptables','-t','mangle','-A','PREROUTING',*udp_rule);run('ip','rule','add','fwmark',hex(mark),'lookup',str(table),'priority','1889');run('ip','route','add','local','0.0.0.0/0','dev','lo','table',str(table))
    launch(False)
    for name in ['mapping.test','dns-tcp.test','alias.test','hints.test','hosts.test','provider.test']:
        result=dns(name,65 if name=='hints.test' else 1,name=='dns-tcp.test');check('DNS answer '+name,result['rcode']==0,result)
        _,row=flow(name,ip_for[name],'domain',rule='RuleSet' if name=='provider.test' else 'Domain')
        check('API domain restored '+name,row['metadata']['host']==name,row)
        check('real destination IP retained '+name,row['metadata']['destinationIP']==ip_for[name],row)
    dns('unmatched.test');flow('unmatched.test',ip_for['unmatched.test'],'fallback',rule='Match')
    dns('ttl.test');time.sleep(1.1);_,row=flow('ttl.test',ip_for['ttl.test'],'fallback',rule='Match');check('expired DNS name not reused',not row['metadata'].get('host'),row)
    dns('ttl.test');flow('ttl.test',ip_for['ttl.test'],'domain',rule='Domain')
    dns('udp-mapping.test');result,_=client(dict(mode='udp',ip=ip_for['udp-mapping.test'],port=9999,packets=[b'plain-udp'.hex()]));check('TPROXY UDP uses redir-host mapping',result['node']=='domain',result)
    stop();launch(True)
    _,row=flow('sni.test','203.0.113.201','domain',rule='Domain');check('TLS SNI visible in API',row['metadata']['host']=='sni.test' and row['metadata'].get('sniffHost')=='sni.test',row)
    dns('mapping.test');_,row=flow('override.test',ip_for['mapping.test'],'domain',rule='Domain');check('force-dns-mapping replaces stale DNS hostname',row['metadata'].get('sniffHost')=='override.test' and row['metadata']['host']=='override.test',row)
    flow('sni.test','203.0.113.201','domain',port=8443,rule='Domain')
    flow('web.example.test','203.0.113.203','domain',port=80,tls=False,rule='DomainSuffix',body=b'preserved'*3000,cut=35)
    flow('provider.test','203.0.113.204','domain',port=8080,tls=False,rule='RuleSet')
    _,row=flow('push.apple.com','203.0.113.205','fallback',rule='Match');check('skip-domain respected',not row['metadata'].get('sniffHost'),row)
    _,row=flow('sni.test','203.0.113.206','fallback',port=9443,rule='Match');check('sniff port filter respected',not row['metadata'].get('host'),row)
    fixture=json.loads(pathlib.Path('/repo/rust/crates/mihomo-runtime/src/sniffer-quic-fixtures.json').read_text())
    for index,case in enumerate(fixture):
        before=len([hit for hit in hits if hit['kind']=='udp']);result,_=client(dict(mode='udp',ip='203.0.113.'+str(207+index),port=443,packets=case['packets']));check('QUIC actual route '+case['domain'],result['node']=='domain',result)
        wait_for(lambda:len([hit for hit in hits if hit['kind']=='udp'])>=before+len(case['packets']))
        sent=[hit for hit in hits if hit['kind']=='udp'][before:];expected=[hashlib.sha256(bytes.fromhex(packet)).hexdigest() for packet in case['packets']]
        check('QUIC exact datagrams '+case['domain'],[hit['sha256'] for hit in sent]==expected,sent)
    check('wire HTTPS query still forwarded',('hints.test',65) in dns_hits,dns_hits)
    try:
        client(dict(mode='tcp',ip='203.0.113.214',port=443,host='eof.test',tls=True,request=b'GET / HTTP/1.1\r\nHost: eof.test\r\n\r\n'.hex()))
        check('upstream EOF returns failure',False)
    except AssertionError:check('upstream EOF returns failure',True)
    text=pathlib.Path(log.name).read_text()
    check('redir EOF identifies actual proxy and target','protocol=redir' in text and 'proxy=domain' in text and 'target=eof.test:443' in text,text)
    stop();launch(True,False)
    _,row=flow('sni.test','203.0.113.215','domain',rule='Domain');check('override false retains original IP but matches SNI',row['metadata']['destinationIP']=='203.0.113.215' and row['metadata'].get('sniffHost')=='sni.test',row)
except Exception as error:
    check('fixture execution',False,repr(error))
    for path in root.glob('core-*.log'):print(path.read_text()[-3500:],flush=True)
finally:
    for process in clients:
        if process.poll() is None:process.kill();process.wait()
    stop()
    if 'tcp_rule' in globals():run('iptables','-t','nat','-D','PREROUTING',*tcp_rule,ok=False)
    if 'udp_rule' in globals():run('iptables','-t','mangle','-D','PREROUTING',*udp_rule,ok=False)
    run('ip','rule','del','fwmark',hex(mark),'lookup',str(table),'priority','1889',ok=False);run('ip','route','flush','table',str(table),ok=False);run('ip','link','del',veth,ok=False);run('ip','netns','del',ns,ok=False)
    for server in servers:server.shutdown();server.server_close()
    result=dict(passed=all(c['passed'] for c in checks),checks=checks,work=str(root),sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest(),proxy_hits=hits,dns_queries=dns_hits)
    pathlib.Path(args.output).write_text(json.dumps(result,indent=2));print(json.dumps(dict(passed=result['passed'],checks=len(checks),work=str(root))),flush=True)
raise SystemExit(0 if result['passed'] else 1)
