#!/usr/bin/env python3
"""Real CONNECT/TLS fixtures for Smart races, probes, exits, and lifecycle.

No public endpoint or subscription credentials are needed. Run inside Docker;
the generated CA is trusted only by this child core and the fixture client.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import http.client
import json
import os
import pathlib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

parser=argparse.ArgumentParser()
parser.add_argument('--core',required=True)
parser.add_argument('--output',required=True)
args=parser.parse_args()
work=pathlib.Path(tempfile.mkdtemp(prefix='mihomo-smart-advanced-'))
checks=[]
events=[]
lock=threading.Lock()
hold_started=threading.Event()
hold_release=threading.Event()

def check(name,passed,detail=None):
    checks.append(dict(name=name,passed=bool(passed),detail=detail))
    if not passed: print('FAIL',name,detail,flush=True)

def wait_for(predicate,timeout=12):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        result=predicate()
        if result:return result
        time.sleep(.05)
    raise AssertionError('fixture condition timed out')

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]

def openssl(*arguments):
    subprocess.run(['openssl',*arguments],cwd=work,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)

openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Smart Fixture CA','-keyout','ca.key','-out','ca.crt','-addext','basicConstraints=critical,CA:TRUE')
openssl('req','-newkey','rsa:2048','-nodes','-subj','/CN=*.test','-keyout','server.key','-out','server.csr')
names=['race.test','manual.test','health.test','region.test','shared.test','challenge.test','rate.test','body-region.test','redirect.test','regional-redirect.test','large.test','held.test','slow-body.test','target-exit.test','www.cloudflare.com','api.ip.sb','ipwho.is']
(work/'extensions').write_text('subjectAltName='+','.join('DNS:'+name for name in names)+'\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
openssl('x509','-req','-days','2','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out','server.crt','-extfile','extensions')
server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_tls.load_cert_chain(work/'server.crt',work/'server.key')
client_tls=ssl.create_default_context(cafile=work/'ca.crt')

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

def read_head(sock):
    data=b''
    while not data.endswith(b'\r\n\r\n'):
        byte=sock.recv(1)
        if not byte:raise EOFError()
        data+=byte
        if len(data)>32768:raise ValueError('fixture header overflow')
    return data

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        label=self.server.label
        active=False
        try:
            self.request.settimeout(12)
            head=read_head(self.request)
            method,authority,_=head.split(b'\r\n',1)[0].decode().split(' ')
            if method!='CONNECT':return
            host=authority.rsplit(':',1)[0]
            with lock:events.append(dict(node=label,host=host,event='dial',time=time.monotonic()))
            if label.startswith('reject'):
                self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                return
            with lock:self.server.active+=1
            active=True
            # A race winner must wait for the CONNECT reply, not just TCP accept.
            if self.server.delay:time.sleep(self.server.delay)
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            with server_tls.wrap_socket(self.request,server_side=True) as tls:
                try:request=read_head(tls)
                except (OSError,EOFError):return
                path=request.split(b' ',2)[1].decode()
                with lock:events.append(dict(node=label,host=host,event='request',path=path,time=time.monotonic()))
                status=200
                headers={}
                body=b'application body'
                if path=='/cdn-cgi/trace' or host=='api.ip.sb':
                    region,ip,asn=self.server.exit
                    if host=='target-exit.test':region='DE';ip='203.0.113.99'
                    if host=='www.cloudflare.com' and label=='b':
                        status=403;body=b'not a trace'
                    elif host=='api.ip.sb':
                        body=json.dumps(dict(ip=ip,country_code=region,asn=asn)).encode()
                    else:body=f'ip={ip}\nloc={region}\n'.encode()
                elif path=='/robots.txt':
                    if host in ('region.test','shared.test') and label in ('a','b','alias'):
                        status=403;body=b'access forbidden'
                    elif host=='challenge.test':
                        status=403;headers['Cf-Mitigated']='challenge';body=b'challenge'
                    elif host=='rate.test':
                        status=429;headers['Retry-After']='123';body=b'rate limited'
                    elif host=='body-region.test':body=b'This service is not available in your country'
                    elif host=='redirect.test':
                        status=302;headers['Location']='https://login.test/';body=b'moved'
                    elif host=='regional-redirect.test':
                        status=302;headers['Location']='/welcome/unavailable';body=b'moved'
                    elif host=='large.test':body=b'A'*4096+b'not available in your country'+b'B'*200000
                    elif host=='held.test':
                        hold_started.set();hold_release.wait(10)
                    elif host=='slow-body.test':
                        body=b'later'
                phrase={200:'OK',302:'Found',403:'Forbidden',429:'Too Many Requests'}.get(status,'OK')
                headers['Content-Length']=str(len(body));headers['Connection']='close'
                response=f'HTTP/1.1 {status} {phrase}\r\n'+''.join(f'{key}: {value}\r\n' for key,value in headers.items())+'\r\n'
                tls.sendall(response.encode())
                if host=='slow-body.test' and path=='/robots.txt':time.sleep(2.5)
                tls.sendall(body)
        except (OSError,EOFError,ValueError):pass
        finally:
            if active:
                with lock:self.server.active-=1;events.append(dict(node=label,event='closed',time=time.monotonic()))

servers=[]
def start(label,delay=0,exit=('US','203.0.113.1',111)):
    server=Server(('127.0.0.1',0),Proxy)
    server.label=label;server.delay=delay;server.exit=exit;server.active=0
    threading.Thread(target=server.serve_forever,daemon=True).start()
    servers.append(server)
    return server.server_address[1]

ports={name:start(name,delay,exit) for name,delay,exit in [
    ('reject1',0,('US','203.0.113.10',111)),('reject2',0,('US','203.0.113.11',111)),('reject3',0,('US','203.0.113.12',111)),
    ('slow',.9,('US','203.0.113.13',111)),('fast',.03,('JP','203.0.113.14',222)),('late',1.5,('JP','203.0.113.15',222)),
    ('a',0,('US','203.0.113.1',111)),('b',0,('US','203.0.113.2',111)),('alias',0,('US','203.0.113.1',111)),('c',0,('JP','203.0.113.3',222)),
]}
ports.update({f'cap{n}':ports['reject1'] for n in range(1,13)})
controller=port();mixed=port()
config=f'''mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
secret: advanced-fixture
mode: rule
log-level: debug
profile:
  store-selected: true
proxies:
'''+''.join(f'  - {{name: {name}, type: http, server: 127.0.0.1, port: {value}}}\n' for name,value in ports.items())+'''
proxy-groups:
  - name: Race
    type: smart
    proxies: [reject1, reject2, reject3, slow, fast, late]
    policy-priority: 'reject1:20;reject2:19;reject3:18;slow:3;fast:2;late:1'
    url: https://health.test/ping
    interval: 86400
    lazy: true
  - name: Probe
    type: smart
    proxies: [a, b, alias, c]
    prefer-asn: true
    url: https://health.test/ping
    interval: 86400
    lazy: true
  - name: Cap
    type: smart
    proxies: [cap1, cap2, cap3, cap4, cap5, cap6, cap7, cap8, cap9, cap10, cap11, cap12]
    url: https://health.test/ping
    interval: 86400
    lazy: true
rules:
  - DOMAIN,race.test,Race
  - DOMAIN,manual.test,Race
  - DOMAIN,cap.test,Cap
  - MATCH,Probe
'''
(work/'config.yaml').write_text(config)
log=open(work/'core.log','w')
process=None

def request(method,path,body=None,auth=True):
    connection=http.client.HTTPConnection('127.0.0.1',controller,timeout=15)
    headers={'Authorization':'Bearer advanced-fixture'} if auth else {}
    if body is not None:body=json.dumps(body).encode();headers['Content-Type']='application/json'
    connection.request(method,path,body,headers)
    response=connection.getresponse();data=response.read();status=response.status;connection.close()
    return status,json.loads(data) if data else None

def api(path):return request('GET',path)[1]
def state(group='Probe'):return api(f'/group/{group}/smart')['advanced']
def drained(group='Probe'):
    value=api(f'/group/{group}/smart')
    return value['pending']==0 and value['active']==0
def pin(node,group='Probe'):check('manual pin '+group+' '+node,request('PUT','/proxies/'+group,dict(name=node))[0]==204)
def clear(group='Probe'):check('clear pin '+group,request('DELETE','/proxies/'+group)[0]==204)
def flow(host,verify=True):
    sock=socket.create_connection(('127.0.0.1',mixed),timeout=15);sock.settimeout(15)
    sock.sendall(f'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n'.encode())
    head=read_head(sock)
    if not head.startswith(b'HTTP/1.1 200'):sock.close();raise AssertionError(head)
    context=client_tls if verify else ssl._create_unverified_context()
    with context.wrap_socket(sock,server_hostname=host) as tls:
        tls.sendall(f'GET /data HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
        response=http.client.HTTPResponse(tls);response.begin();data=response.read();assert response.status==200
        return data
def seen(host,path,node=None):
    with lock:return [event for event in events if event.get('host')==host and event.get('path')==path and (node is None or event['node']==node)]
def node_for(host):
    return seen(host,'/data')[-1]['node']
def probe_record(host,node):return state()['probes'].get(host+'\x1f'+node)
def launch():
    global process
    environment=os.environ.copy();environment['SSL_CERT_FILE']=str(work/'ca.crt')
    process=subprocess.Popen([args.core,'-d',str(work),'-f',str(work/'config.yaml')],stdout=log,stderr=log,env=environment)
    def ready():
        if process.poll() is not None:raise RuntimeError((work/'core.log').read_text())
        try:return request('GET','/version')[0]==200
        except OSError:return False
    wait_for(ready)
def stop():
    if process is None or process.poll() is not None:return
    process.terminate()
    try:process.wait(15)
    except subprocess.TimeoutExpired:process.kill();process.wait();check('bounded shutdown',False)

try:
    launch()
    check('diagnostics requires authentication',request('GET','/group/Race/smart',auth=False)[0]==401)
    started=time.monotonic();check('race forwards actual TLS traffic',flow('race.test')==b'application body')
    elapsed=time.monotonic()-started
    check('race chooses fast protocol handshake',node_for('race.test')=='fast',node_for('race.test'))
    check('race finishes before slow CONNECT reply',elapsed<.8,elapsed)
    check('race schedule recorded',state('Race')['races']>=1)
    check('race cancels pending losers',state('Race')['cancelled']>=1)
    wait_for(lambda:all(server.active==0 for server in servers if server.label in ('slow','late')),4)
    check('race loser sockets close',True)
    race_before=len(seen('race.test','/data'))
    flow('race.test');check('winning route reused',node_for('race.test')=='fast')
    check('no application payload reaches slow losers',not seen('race.test','/data','slow') and not seen('race.test','/data','late'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        burst=list(pool.map(lambda _:flow('race.test'),range(24)))
    check('worker budget preserves concurrent normal connections',all(body==b'application body' for body in burst))
    wait_for(lambda:drained('Race'))
    pin('reject1','Race')
    try:flow('manual.test');check('failed manual node stays fixed',False)
    except (OSError,EOFError,AssertionError):check('failed manual node stays fixed',not seen('manual.test','/data'))
    check('manual selection visible',api('/proxies/Race')['now']=='reject1')
    clear('Race')
    try:flow('cap.test');check('all failed candidates return failure',False)
    except (OSError,EOFError,AssertionError):check('all failed candidates return failure',True)
    attempted=[event for event in events if event.get('event')=='dial' and event.get('host')=='cap.test']
    check('dial candidates capped at ten',len(attempted)==10,len(attempted))

    for node in ['a','b','c']:
        pin(node);flow('region.test')
        wait_for(lambda node=node:probe_record('region.test',node) is not None)
        wait_for(drained)
    evidence=state()
    check('two independent refusals and cross-region control confirm region',evidence['suspects'].get('region.test\x1fregion:US',0)>time.time(),evidence['suspects'])
    check('target traces collected',all('region.test\x1f'+node in evidence['target_exits'] for node in ('a','b','c')))
    check('global trace fallback parses JSON ASN',evidence['exits']['b']['asn']=='111',evidence['exits'].get('b'))
    check('exit identity hashed',all(len(item['key'])==12 for item in evidence['exits'].values()))
    check('raw exit IP not exposed',not any(ip in json.dumps(evidence) for ip in ('203.0.113.1','203.0.113.2','203.0.113.3')))
    clear();flow('region.test');check('automatic route skips known suspected exits',node_for('region.test') in ('c','alias'),node_for('region.test'))
    wait_for(drained)
    flow('region.test');check('newly discovered exit is classified before next selection',node_for('region.test')=='c',node_for('region.test'))
    pin('a');flow('region.test');check('manual selection overrides regional exclusion',node_for('region.test')=='a');clear()

    for node in ['a','alias','c']:
        pin(node);flow('shared.test');wait_for(lambda node=node:probe_record('shared.test',node) is not None);wait_for(drained)
    check('same exit IP cannot count as independent regional evidence','shared.test\x1fregion:US' not in state()['suspects'])

    for host,reason in [('challenge.test','challenge'),('rate.test','rate limited'),('body-region.test','region unavailable'),('regional-redirect.test','region unavailable')]:
        pin('a');flow(host);record=wait_for(lambda host=host:probe_record(host,'a'));check('actual HTTPS classification '+host,record['verdict']['reason']==reason,record)
        if host=='rate.test':check('actual Retry-After TTL',record['verdict']['ttl']==123)
        wait_for(drained)
    pin('a');flow('redirect.test');wait_for(lambda:len(seen('redirect.test','/robots.txt'))>0);wait_for(drained)
    check('ordinary redirect does not block or clear',probe_record('redirect.test','a') is None)
    check('probe never follows redirects',not any(event.get('host')=='login.test' for event in events))
    pin('a');flow('wrong.invalid',verify=False);record=wait_for(lambda:probe_record('wrong.invalid','a'));check('TLS hostname verification affects probe',record['verdict']['reason']=='certificate hostname mismatch',record)
    wait_for(drained)
    pin('a');flow('large.test');record=wait_for(lambda:probe_record('large.test','a'));check('probe body limited to 4096 bytes',record['verdict']['action']=='reachable',record);wait_for(drained)
    pin('a');flow('slow-body.test');started=time.monotonic();record=wait_for(lambda:probe_record('slow-body.test','a'));check('body wait preserves valid response',record['verdict']['control_success'] and time.monotonic()-started<2.5,record);wait_for(drained)
    pin('a');flow('target-exit.test');wait_for(drained)
    check('target-specific trace overrides global trace',state()['target_exits']['target-exit.test\x1fa']['region']=='DE')

    stop()
    saved=json.loads(next((work/'storage').glob('smart-*.json')).read_text())
    learned=saved['groups']['Race']['nodes']
    check('cancelled race losers do not become node failures',all(learned.get(node,{}).get('input',{}).get('failure',0)==0 for node in ('slow','late')))
    launch()
    check('advanced evidence survives restart','region.test\x1fregion:US' in state()['suspects'])
    check('advanced exits survive restart',state()['exits']['b']['asn']=='111')
    pin('a');flow('held.test');assert hold_started.wait(8)
    check('flush during in-flight HTTPS probe',request('POST','/cache/smart/flush')[0]==204)
    hold_release.set();wait_for(drained);time.sleep(.15)
    after=state()
    check('in-flight result cannot repopulate flushed state',not after['probes'] and not after['exits'] and not after['suspects'],after)
    check('flush keeps manual selection',api('/proxies/Probe')['now']=='a')
    started=time.monotonic();stop();check('shutdown completes without waiting for stale probe',time.monotonic()-started<3)
except Exception as error:
    check('fixture execution',False,repr(error))
    print((work/'core.log').read_text()[-5000:],flush=True)
finally:
    hold_release.set();stop();log.close()
    for server in servers:server.shutdown();server.server_close()
    result=dict(passed=all(item['passed'] for item in checks),checks=len(checks),results=checks,work=str(work),events=events,core=str(pathlib.Path(args.core).resolve()),sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    pathlib.Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print(json.dumps({key:result[key] for key in ('passed','checks','work')},ensure_ascii=False),flush=True)
raise SystemExit(0 if result['passed'] else 1)
