#!/usr/bin/env python3
"""Measure /traffic in bytes/s while real TCP connections remain open.

Uses deterministic paced traffic and independent TCP/UDP fixture byte counts.
Tests polling, HTTP chunked streaming, and simultaneous WebSocket subscribers.
"""
import argparse,base64,datetime,hashlib,http.client,json,pathlib,queue,select,socket,socketserver,struct,subprocess,tempfile,threading,time,statistics
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--output',required=True);p.add_argument('--inbound',choices=['mixed','redir'],default='mixed');p.add_argument('--outbound',choices=['direct','socks5'],default='direct');args=p.parse_args()
root=pathlib.Path(tempfile.mkdtemp(prefix='traffic-speed-'));checks=[];samples={};phases=[];stop_event=threading.Event();pairs=[];servers=[];core=None;redir_rules=[]
def check(name,ok,detail=None):
    checks.append(dict(name=name,passed=bool(ok),detail=json.loads(json.dumps(detail)) if detail is not None else None))
    if not ok:print('FAIL',name,detail,flush=True)
def free():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait_for(test,timeout=5):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=test()
        if value:return value
        time.sleep(.01)
    raise AssertionError('fixture condition timed out')
def exact(sock,n):
    out=b''
    while len(out)<n:
        data=sock.recv(n-len(out))
        if not data:raise EOFError()
        out+=data
    return out
def head(sock):
    out=b''
    while not out.endswith(b'\r\n\r\n'):out+=exact(sock,1)
    return out
class TCP(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class UDP(socketserver.ThreadingUDPServer):allow_reuse_address=True;daemon_threads=True
accepted=queue.Queue()
delayed_udp=queue.Queue();release_udp=threading.Event()
class Target(socketserver.BaseRequestHandler):
    def handle(self):
        state=dict(socket=self.request,upload=0,download=0);accepted.put(state);self.request.settimeout(.3)
        while not stop_event.is_set():
            try:
                data=self.request.recv(65536)
                if not data:return
                state['upload']+=len(data)
            except socket.timeout:continue
            except OSError:return
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        if data==b'close-udp-request':delayed_udp.put(True);release_udp.wait(3)
        sock.sendto(data+data,self.client_address)
def address(sock):
    kind=exact(sock,1)[0]
    if kind==1:host=socket.inet_ntoa(exact(sock,4))
    elif kind==4:host=socket.inet_ntop(socket.AF_INET6,exact(sock,16))
    elif kind==3:host=exact(sock,exact(sock,1)[0]).decode()
    else:raise ValueError(kind)
    return host,struct.unpack('!H',exact(sock,2))[0]
class SocksProxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            version,count=exact(self.request,2);assert version==5
            exact(self.request,count);self.request.sendall(b'\x05\x00')
            version,command,reserved=exact(self.request,3);host,port=address(self.request)
            if command==1:
                with socket.create_connection((host,port),timeout=5) as remote:
                    self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                    self.request.settimeout(.3);remote.settimeout(.3)
                    def copy(source,destination):
                        try:
                            while not stop_event.is_set():
                                try:data=source.recv(65536)
                                except socket.timeout:continue
                                if not data:return
                                destination.sendall(data)
                        except OSError:pass
                        finally:
                            try:destination.shutdown(socket.SHUT_WR)
                            except OSError:pass
                    worker=threading.Thread(target=copy,args=(remote,self.request),daemon=True);worker.start()
                    copy(self.request,remote);worker.join(5)
            elif command==3:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as relay:
                    relay.bind(('127.0.0.1',0));relay.settimeout(3)
                    self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',relay.getsockname()[1]))
                    while not stop_event.is_set():
                        ready,_,_=select.select([relay,self.request],[],[],1)
                        if self.request in ready and not self.request.recv(1024):return
                        if relay in ready:
                            frame,peer=relay.recvfrom(65535);assert frame[:4]==b'\x00\x00\x00\x01'
                            target_host=socket.inet_ntoa(frame[4:8]);target_port=struct.unpack('!H',frame[8:10])[0]
                            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as target_sock:
                                target_sock.settimeout(3);target_sock.sendto(frame[10:],(target_host,target_port));reply=target_sock.recv(65535)
                            relay.sendto(frame[:10]+reply,peer)
        except (OSError,EOFError,AssertionError,ValueError):return
def start(server):servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start();return server.server_address[1]
target=start(TCP(('127.0.0.1',0),Target));udp_target=start(UDP(('127.0.0.1',0),Echo));controller,mixed,udp_listener,redir=free(),free(),free(),free()
proxy_port=start(TCP(('127.0.0.1',0),SocksProxy));route='DIRECT' if args.outbound=='direct' else 'SpeedRoute'
expected_chains=['DIRECT'] if args.outbound=='direct' else ['speed-socks','SpeedRoute'];expected_providers=[''] if args.outbound=='direct' else ['speed-provider','']
config=f'''mixed-port: {mixed}
redir-port: {redir}
external-controller: 127.0.0.1:{controller}
secret: speed-fixture
mode: rule
log-level: warning
hosts:
  udp.traffic.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
  nameserver: [127.0.0.1]
listeners:
  - name: speed-udp
    type: tunnel
    listen: 127.0.0.1
    port: "{udp_listener}"
    network: [udp]
    target: udp.traffic.test:{udp_target}
rules: ['DOMAIN,udp.traffic.test,{route}', 'MATCH,{route}']
'''
if args.outbound=='socks5':config+=f'''proxy-providers:
  speed-provider:
    type: inline
    payload:
      - name: speed-socks
        type: socks5
        server: 127.0.0.1
        port: {proxy_port}
        udp: true
proxy-groups:
  - name: SpeedRoute
    type: select
    use: [speed-provider]
'''
(root/'config.yaml').write_text(config)
def api(path):
    c=http.client.HTTPConnection('127.0.0.1',controller,timeout=5);c.request('GET',path,headers={'Authorization':'Bearer speed-fixture','Connection':'close'});r=c.getresponse();data=r.read();c.close();assert r.status==200;return json.loads(data)
class Subscription:
    def __init__(self,name,kind,interval,path='/traffic'):
        self.name=name;self.kind=kind;self.interval=interval;self.path=path;self.error=None;self.sock=None;self.frames=[];samples[name]=self.frames
        self.worker=threading.Thread(target=self.run,daemon=True);self.worker.start()
    def run(self):
        try:
            if self.kind=='websocket':
                self.sock=socket.create_connection(('127.0.0.1',controller),timeout=5);self.sock.settimeout(5)
                key=base64.b64encode(b'traffic-fixture1').decode()
                self.sock.sendall(f'GET {self.path}?interval={self.interval} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer speed-fixture\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode());assert b'101' in head(self.sock)
                while not stop_event.is_set():
                    first,second=exact(self.sock,2);n=second&127
                    if n==126:n=struct.unpack('!H',exact(self.sock,2))[0]
                    elif n==127:n=struct.unpack('!Q',exact(self.sock,8))[0]
                    data=exact(self.sock,n)
                    if first&15==1:self.frames.append(dict(t=time.monotonic(),**json.loads(data)))
            else:
                self.conn=http.client.HTTPConnection('127.0.0.1',controller,timeout=5);self.conn.request('GET',f'{self.path}?interval={self.interval}',headers={'Authorization':'Bearer speed-fixture','Connection':'keep-alive'});r=self.conn.getresponse();assert r.status==200
                while not stop_event.is_set():
                    line=r.readline()
                    if not line:break
                    self.frames.append(dict(t=time.monotonic(),**json.loads(line)))
        except Exception as error:
            if not stop_event.is_set():self.error=repr(error)
    def close(self):
        if self.sock is not None:
            try:self.sock.shutdown(socket.SHUT_RDWR);self.sock.close()
            except OSError:pass
        self.worker.join(2)
class Pair:
    def __init__(self):
        if args.inbound=='redir':
            self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.sock.settimeout(5)
            rule=['-p','tcp','-s','127.0.0.1','-d','127.0.0.1','--sport',str(self.sock.getsockname()[1]),'--dport',str(target),'-j','REDIRECT','--to-ports',str(redir)]
            subprocess.run(['iptables','-t','nat','-A','OUTPUT',*rule],capture_output=True,check=True);redir_rules.append(rule);self.sock.connect(('127.0.0.1',target))
        else:
            self.sock=socket.create_connection(('127.0.0.1',mixed),timeout=5);self.sock.settimeout(5)
            self.sock.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n'.encode());assert b'200' in head(self.sock)
        self.port=self.sock.getsockname()[1];self.target=accepted.get(timeout=5);self.download=0;self.error=None;self.closed=False
        self.sock.settimeout(.3)
        self.reader=threading.Thread(target=self.read,daemon=True);self.reader.start();pairs.append(self)
    def read(self):
        try:
            while not self.closed:
                try:data=self.sock.recv(65536)
                except socket.timeout:continue
                if not data:return
                self.download+=len(data)
        except OSError as error:
            if not self.closed:self.error=repr(error)
    def close(self):
        self.closed=True
        try:self.sock.shutdown(socket.SHUT_RDWR);self.sock.close()
        except OSError:pass
        self.reader.join(2)
def paced(pair,direction,rate,duration,errors):
    size=16384 if direction=='up' else 8192;count=round(rate*duration/size);payload=b'U'*size if direction=='up' else b'D'*size;start_time=time.monotonic()
    try:
        for index in range(count):
            delay=start_time+index*size/rate-time.monotonic()
            if delay>0:time.sleep(delay)
            (pair.sock if direction=='up' else pair.target['socket']).sendall(payload)
            if direction=='down':pair.target['download']+=size
    except Exception as error:errors.append(repr(error))
def totals():return dict(upTotal=sum(p.target['upload'] for p in pairs),downTotal=sum(p.download for p in pairs))
def same_totals(expected):
    actual=api('/traffic');return actual if all(actual[k]==v for k,v in expected.items()) else None
def check_live(name):
    time.sleep(.08)
    expected=totals();actual=wait_for(lambda:same_totals(expected));check(name+' live global totals match fixture',all(actual[k]==v for k,v in expected.items()),dict(expected=expected,actual=actual))
    connections=api('/connections');check(name+' global connections totals remain live',connections['uploadTotal']==expected['upTotal'] and connections['downloadTotal']==expected['downTotal'],connections)
    for pair in pairs:
        row=next((row for row in connections['connections'] if str(row['metadata']['sourcePort'])==str(pair.port)),None)
        check(name+' active per-connection counters '+str(pair.port),row is not None and row['upload']==pair.target['upload'] and row['download']==pair.download,row)
        if row is not None:check_row_metadata(name+' TCP '+str(pair.port),row,'tcp')
def check_row_metadata(name,row,network):
    check(name+' actual outbound and provider chains',row['chains']==expected_chains and row['providerChains']==expected_providers,row)
    stamp=row.get('start');valid_time=False
    if isinstance(stamp,str):
        age=(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))).total_seconds();valid_time=0<=age<120
    check(name+' RFC3339 start and network metadata',valid_time and row['metadata']['network']==network,dict(start=stamp,metadata=row['metadata']))
def measured_phase(name,work,up_rate,down_rate,duration=3.5):
    start_time=time.monotonic();errors=[];threads=[threading.Thread(target=paced,args=(pair,direction,rate,duration,errors)) for pair,direction,rate in work]
    for worker in threads:worker.start()
    for worker in threads:worker.join()
    end=start_time+duration;time.sleep(max(0,end-time.monotonic()));wait_for(lambda:all(pair.error is None for pair in pairs))
    phase=dict(name=name,start=start_time,end=time.monotonic(),expected_up=up_rate,expected_down=down_rate);phases.append(phase)
    check(name+' transfer completes',not errors,errors);check_live(name)
    for source in connection_samplers:
        snapshots=[frame for frame in source.frames if start_time<=frame['t']<phase['end']]
        consistent=bool(snapshots) and all(sum(row['upload'] for row in frame['connections'])==frame['uploadTotal'] and sum(row['download'] for row in frame['connections'])==frame['downloadTotal'] for frame in snapshots)
        check(name+' '+source.name+' totals agree within each live snapshot',consistent,dict(samples=len(snapshots)))
    for source in [*subscriptions,poller]:
        readings=[frame for frame in source.frames if start_time+2<=frame['t']<phase['end']]
        for field,expected in [('up',up_rate),('down',down_rate)]:
            value=statistics.median([r[field] for r in readings]) if readings else None
            good=value is not None and (value==0 if expected==0 else abs(value-expected)<=expected*.15)
            check(name+' '+source.name+' '+field+' bytes/s',good,dict(expected=expected,median=value,samples=len(readings)))
def idle(name):
    expected=totals();time.sleep(2.2);actual=api('/traffic');check(name+' returns to zero',actual['up']==0 and actual['down']==0,actual);check(name+' cumulative totals stay fixed',all(actual[k]==v for k,v in expected.items()),dict(expected=expected,actual=actual))
class Poller:
    def __init__(self,name='poll-100ms',path='/traffic',interval=.1):self.name=name;self.path=path;self.interval=interval;self.frames=[];self.error=None;samples[self.name]=self.frames;self.worker=threading.Thread(target=self.run,daemon=True);self.worker.start()
    def run(self):
        while not stop_event.is_set():
            try:self.frames.append(dict(t=time.monotonic(),**api(self.path)))
            except Exception as error:
                if not stop_event.is_set():self.error=repr(error)
            stop_event.wait(self.interval)
def udp_phase(label,socks,expected):
    control=None
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.bind(('127.0.0.1',0));udp.settimeout(3);peer_port=udp.getsockname()[1]
        destination=('127.0.0.1',udp_listener);prefix=b''
        if socks:
            control=socket.create_connection(('127.0.0.1',mixed),timeout=5)
            control.sendall(b'\x05\x01\x00');assert exact(control,2)==b'\x05\x00'
            control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',peer_port));assert exact(control,3)==b'\x05\x00\x00'
            host,port=address(control);destination=('127.0.0.1' if host=='0.0.0.0' else host,port)
            domain=b'udp.traffic.test';prefix=b'\x00\x00\x00\x03'+bytes([len(domain)])+domain+struct.pack('!H',udp_target)
        sent=0;received=0;start_time=time.monotonic();payload=b'x'*1024
        def verify(stage):
            expected_all=dict(upTotal=expected['upTotal']+sent,downTotal=expected['downTotal']+received)
            actual=wait_for(lambda:same_totals(expected_all));connections=api('/connections')
            row=next((row for row in connections['connections'] if row['metadata']['network']=='udp' and str(row['metadata']['sourcePort'])==str(peer_port)),None)
            check(label+' '+stage+' payload counters and global totals',row is not None and row['upload']==sent and row['download']==received and connections['uploadTotal']==expected_all['upTotal'] and connections['downloadTotal']==expected_all['downTotal'],dict(expected=expected_all,traffic=actual,connections=connections))
            if row is not None:
                check_row_metadata(label+' '+stage,row,'udp')
                check(label+' '+stage+' routed domain and rule',row['metadata']['host']=='udp.traffic.test' and row['metadata']['destinationIP']=='127.0.0.1' and row['rule']=='Domain' and row['rulePayload']=='udp.traffic.test',row)
        try:
            for index in range(56):
                delay=start_time+index/16-time.monotonic()
                if delay>0:time.sleep(delay)
                udp.sendto(prefix+payload,destination);sent+=len(payload);reply=udp.recv(65535)
                if socks:
                    assert reply[:4]==b'\x00\x00\x00\x01';reply=reply[10:]
                received+=len(reply);assert reply==payload+payload
                if index==27:verify('during transfer')
            end=time.monotonic();phases.append(dict(name=label,start=start_time,end=end,expected_up=16384,expected_down=32768))
            verify('after transfer')
        finally:
            if control is not None:control.close()
    expected['upTotal']+=sent;expected['downTotal']+=received
    for source in [*subscriptions,poller]:
        frames=[f for f in source.frames if start_time+2<=f['t']<end]
        for field,rate in [('up',16384),('down',32768)]:
            value=statistics.median(f[field] for f in frames) if frames else None;check(label+' '+source.name+' '+field+' bytes/s',value is not None and abs(value-rate)<=rate*.15,dict(expected=rate,median=value))
    time.sleep(2.2);final=api('/traffic');check(label+' pause returns speed to zero',final['up']==0 and final['down']==0,final)
    check(label+' idle cumulative totals stay fixed',final['upTotal']==expected['upTotal'] and final['downTotal']==expected['downTotal'],dict(expected=expected,actual=final))
def close_udp(expected):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.bind(('127.0.0.1',0));udp.settimeout(.6);peer_port=udp.getsockname()[1]
        payload=b'close-udp-request';udp.sendto(payload,('127.0.0.1',udp_listener));delayed_udp.get(timeout=3)
        def row():return next((row for row in api('/connections')['connections'] if row['metadata']['network']=='udp' and str(row['metadata']['sourcePort'])==str(peer_port) and row['upload']==len(payload)),None)
        old=wait_for(row);conn=http.client.HTTPConnection('127.0.0.1',controller,timeout=5)
        conn.request('DELETE','/connections/'+old['id'],headers={'Authorization':'Bearer speed-fixture'});response=conn.getresponse();response.read();status=response.status;conn.close();release_udp.set()
        dropped=False
        try:udp.recv(65535)
        except socket.timeout:dropped=True
        expected['upTotal']+=len(payload);actual=api('/traffic');connections=api('/connections')
        check('DELETE UDP flow cancels outstanding reply and preserves bytes already sent',status==204 and dropped and all(actual[k]==v for k,v in expected.items()) and not any(item['id']==old['id'] for item in connections['connections']),dict(status=status,dropped=dropped,traffic=actual))
        following=b'after-udp-close';udp.settimeout(3);udp.sendto(following,('127.0.0.1',udp_listener));reply=udp.recv(65535);assert reply==following+following
        expected['upTotal']+=len(following);expected['downTotal']+=len(reply);wait_for(lambda:same_totals(expected))
        new=next(item for item in api('/connections')['connections'] if item['metadata']['network']=='udp' and str(item['metadata']['sourcePort'])==str(peer_port))
        check('UDP traffic after DELETE creates a fresh flow',new['id']!=old['id'] and new['upload']==len(following) and new['download']==len(reply),new)
subscriptions=[];connection_samplers=[];poller=None
try:
    log=(root/'core.log').open('w');core=subprocess.Popen([args.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
    def ready():
        if core.poll() is not None:raise RuntimeError((root/'core.log').read_text())
        try:return api('/version')
        except OSError:return False
    wait_for(ready)
    subscriptions=[Subscription('ws-100ms','websocket',100),Subscription('ws-700ms','websocket',700),Subscription('http-250ms','http',250)];poller=Poller()
    connection_samplers=[Subscription('connections-ws-50ms','websocket',50,'/connections'),Poller('connections-poll-30ms','/connections',.03)]
    wait_for(lambda:all(s.frames for s in subscriptions));baseline=api('/traffic');check('new core starts at zero',all(baseline[k]==0 for k in ['up','down','upTotal','downTotal']),baseline)
    first=Pair();measured_phase('upload only',[(first,'up',512*1024)],512*1024,0);idle('upload paused while connection open')
    measured_phase('download only',[(first,'down',256*1024)],0,256*1024);idle('download paused while connection open')
    second=Pair();measured_phase('two full-duplex connections',[(first,'up',128*1024),(first,'down',256*1024),(second,'up',256*1024),(second,'down',512*1024)],384*1024,768*1024)
    idle('full duplex paused')
    expected=totals()
    for pair in pairs:pair.close()
    wait_for(lambda:not api('/connections')['connections']);time.sleep(.15);after=api('/traffic');check('closing TCP does not count traffic twice',all(after[k]==v for k,v in expected.items()),dict(expected=expected,actual=after))
    udp_phase('tunnel UDP payload',False,expected)
    udp_phase('SOCKS5 inbound UDP payload',True,expected)
    close_udp(expected)
    wait_for(lambda:not api('/connections')['connections'],timeout=32)
    final=api('/connections');check('idle UDP rows expire without losing cumulative totals',final['uploadTotal']==expected['upTotal'] and final['downloadTotal']==expected['downTotal'],dict(expected=expected,actual=final))
    for source in [*subscriptions,poller]:
        check(source.name+' stream stays healthy',source.error is None,source.error)
        check(source.name+' totals never decrease',all(a['upTotal']<=b['upTotal'] and a['downTotal']<=b['downTotal'] for a,b in zip(source.frames,source.frames[1:])))
    for source in connection_samplers:
        check(source.name+' stream stays healthy',source.error is None,source.error)
        check(source.name+' global totals never decrease',all(a['uploadTotal']<=b['uploadTotal'] and a['downloadTotal']<=b['downloadTotal'] for a,b in zip(source.frames,source.frames[1:])))
except Exception as error:
    check('fixture execution',False,repr(error));print((root/'core.log').read_text()[-3000:] if (root/'core.log').exists() else '',flush=True)
finally:
    stop_event.set();release_udp.set()
    for pair in pairs:pair.close()
    for subscription in subscriptions+[s for s in connection_samplers if isinstance(s,Subscription)]:subscription.close()
    if core is not None and core.poll() is None:
        core.terminate()
        try:core.wait(12)
        except subprocess.TimeoutExpired:core.kill();core.wait();check('bounded shutdown',False)
    for server in servers:server.shutdown();server.server_close()
    for rule in redir_rules:subprocess.run(['iptables','-t','nat','-D','OUTPUT',*rule],capture_output=True)
    if 'log' in globals():log.close()
    result=dict(passed=all(c['passed'] for c in checks),checks=checks,phases=phases,samples=samples,work=str(root),inbound=args.inbound,outbound=args.outbound,sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    pathlib.Path(args.output).write_text(json.dumps(result,indent=2));print(json.dumps(dict(passed=result['passed'],checks=len(checks),work=str(root))),flush=True)
raise SystemExit(0 if result['passed'] else 1)
