#!/usr/bin/env python3
"""TUN/mixed parallel transfer benchmark in an isolated Linux container.

Collect core thread CPU time, throughput, payload integrity and API responsiveness.
"""
import argparse, concurrent.futures, hashlib, http.client, json, os, pathlib
import select, socket, socketserver, struct, subprocess, sys, tempfile, threading, time

p=argparse.ArgumentParser()
p.add_argument('--core',required=True);p.add_argument('--output',required=True)
p.add_argument('--inbound',choices=['tun','mixed'],default='tun')
p.add_argument('--clients',type=int,default=16);p.add_argument('--seconds',type=float,default=6)
p.add_argument('--direction',choices=['download','upload'],default='download')
a=p.parse_args();root=pathlib.Path(tempfile.mkdtemp(prefix='multicore-'))
block=bytes(range(256))*256
checks=[];samples=[];errors=[];stop=threading.Event();core=None
mark,table,priority=0x174,21634,1874

def check(name,ok,detail=None):
    checks.append(dict(name=name,passed=bool(ok),detail=detail))
    if not ok: print('FAIL',name,detail,flush=True)

def run(*args,required=True): return subprocess.run(args,check=required,capture_output=True,text=True,timeout=10)
def free():
    with socket.socket() as s: s.bind(('127.0.0.1',0));return s.getsockname()[1]
def exact(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part: raise EOFError()
        data+=part
    return data

class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            s=self.request;s.settimeout(20)
            head=exact(s,2);assert head[0]==5;exact(s,head[1]);s.sendall(b'\x05\x00')
            head=exact(s,4);assert head[:3]==b'\x05\x01\x00'
            exact(s,4 if head[3]==1 else 16 if head[3]==4 else exact(s,1)[0]);exact(s,2)
            s.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            command=exact(s,1)
            if command==b'D':
                while not stop.is_set(): s.sendall(block)
            else:
                received=0
                while not stop.is_set():
                    data=s.recv(65536)
                    if not data: break
                    offset=received%256
                    if data!=(block[offset:]+block[:offset])[:len(data)]:
                        raise ValueError('upload content mismatch')
                    received+=len(data)
                s.sendall(struct.pack('!Q',received))
        except (OSError,EOFError,AssertionError,ValueError): pass

def api(path):
    c=http.client.HTTPConnection('127.0.0.1',controller,timeout=3);start=time.monotonic()
    c.request('GET',path,headers={'Connection':'close'});r=c.getresponse();data=r.read();c.close()
    assert r.status==200
    return json.loads(data),time.monotonic()-start

def proc_threads():
    result={}
    for item in pathlib.Path('/proc/'+str(core.pid)+'/task').iterdir():
        try:
            raw=(item/'stat').read_text(); tail=raw[raw.rfind(')')+2:].split()
            result[item.name]=dict(name=(item/'comm').read_text().strip(),ticks=int(tail[11])+int(tail[12]),cpu=int(tail[36]))
        except (FileNotFoundError,ProcessLookupError): pass
    return result

def client(index,barrier,deadline):
    data=bytearray(65536);received=0;valid=True; started=None
    with socket.socket() as s:
        s.settimeout(15)
        if a.inbound=='tun':
            s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark);s.connect(('198.51.100.44',443))
        else:
            s.connect(('127.0.0.1',mixed));s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
            s.sendall(b'\x05\x01\x00\x01\xc6\x33\x64\x2c\x01\xbb');assert exact(s,10)[1]==0
        barrier.wait(15);started=time.monotonic();s.sendall(b'D' if a.direction=='download' else b'U')
        if a.direction=='download':
            while time.monotonic()<deadline[0]:
                n=s.recv_into(data)
                if not n: break
                # Validate every byte without introducing a per-byte Python loop.
                view=memoryview(data)[:n];offset=received%256
                expected=(block[offset:]+block[:offset])[:n]
                if view!=expected: valid=False
                received+=n
        else:
            while time.monotonic()<deadline[0]: s.sendall(block);received+=len(block)
            s.shutdown(socket.SHUT_WR);ack=struct.unpack('!Q',exact(s,8))[0];valid=ack==received
    return dict(client=index,bytes=received,valid=valid,seconds=time.monotonic()-started)

try:
    proxy=TCP(('127.0.0.1',0),Proxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    controller,mixed=free(),free()
    config=f'''mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
log-level: error
mode: rule
tun:
  enable: {str(a.inbound=='tun').lower()}
  stack: mixed
  device: perf-tun
  mtu: 1500
  auto-route: false
  auto-redirect: false
  auto-detect-interface: false
proxies:
  - {{name: bench, type: socks5, server: 127.0.0.1, port: {proxy.server_address[1]}, udp: true}}
rules: ['MATCH,bench']
'''
    (root/'config.yaml').write_text(config);log=(root/'core.log').open('w')
    core=subprocess.Popen([a.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
    for _ in range(200):
        if core.poll() is not None: raise RuntimeError((root/'core.log').read_text())
        try: api('/version');break
        except OSError: time.sleep(.02)
    if a.inbound=='tun':
        run('ip','rule','add','fwmark',str(mark),'table',str(table),'priority',str(priority))
        run('ip','route','add','table',str(table),'default','dev','perf-tun')
    initial=proc_threads();started=time.monotonic()
    deadline=[0]
    barrier=threading.Barrier(a.clients+1,action=lambda:deadline.__setitem__(0,time.monotonic()+a.seconds))
    monitor_output=root/'samples.json';monitor_stop=root/'stop-monitor'
    monitor=subprocess.Popen([sys.executable,str(pathlib.Path(__file__).with_name('multicore-monitor.py')),
        '--pid',str(core.pid),'--controller',str(controller),'--output',str(monitor_output),'--stop',str(monitor_stop)])
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.clients) as pool:
        futures=[pool.submit(client,index,barrier,deadline) for index in range(a.clients)]
        barrier.wait(15)
        transfers=[f.result(60) for f in futures]
    elapsed=time.monotonic()-started
    monitor_stop.touch();monitor.wait(5)
    monitored=json.loads(monitor_output.read_text());samples=monitored['samples'];errors=monitored['errors']
    stop.set()
    final=proc_threads();hz=os.sysconf('SC_CLK_TCK')
    all_rows={}
    for snap in samples+[dict(threads=final)]:
        for tid,row in snap['threads'].items():
            previous=all_rows.get(tid)
            if previous is None or previous['ticks']<row['ticks']:all_rows[tid]=row
    threads=[dict(tid=tid,name=row['name'],cpu_seconds=(row['ticks']-initial.get(tid,dict(ticks=0))['ticks'])/hz,last_cpu=row['cpu']) for tid,row in all_rows.items()]
    threads.sort(key=lambda row:row['cpu_seconds'],reverse=True)
    transferred=sum(row['bytes'] for row in transfers)
    check('all clients transferred and payload is correct',all(row['valid'] and row['bytes']>0 for row in transfers),transfers)
    check('controller remained responsive',not errors and bool(samples) and max(s['api_seconds'] for s in samples)<1,dict(errors=errors,max_api_seconds=max((s['api_seconds'] for s in samples),default=0)))
    check('every client has an independent tracked connection',any(s['connections']>=a.clients for s in samples))
    result=dict(passed=all(c['passed'] for c in checks),checks=checks,core_sha256=hashlib.sha256(pathlib.Path(a.core).read_bytes()).hexdigest(),inbound=a.inbound,direction=a.direction,clients=a.clients,test_seconds=a.seconds,elapsed=elapsed,bytes=transferred,mbps=transferred*8/a.seconds/1e6,cpu_seconds=sum(row['cpu_seconds'] for row in threads),threads=threads,samples=samples)
except Exception as e:
    check('benchmark execution',False,repr(e));result=dict(passed=False,checks=checks)
finally:
    stop.set()
    if 'monitor' in locals() and monitor.poll() is None:
        monitor_stop.touch()
        try:monitor.wait(5)
        except subprocess.TimeoutExpired:monitor.kill();monitor.wait()
    if core is not None and core.poll() is None:
        core.terminate()
        try:core.wait(5)
        except subprocess.TimeoutExpired: core.kill();core.wait()
    if a.inbound=='tun':
        run('ip','rule','del','fwmark',str(mark),'table',str(table),'priority',str(priority),required=False)
        run('ip','route','flush','table',str(table),required=False)
    if 'proxy' in locals():proxy.shutdown();proxy.server_close()
    if 'log' in locals():log.close()
    result['cpu_affinity']=sorted(os.sched_getaffinity(0))
    result['cpu_quota']=pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().strip()
    result['core_log']=(root/'core.log').read_text() if (root/'core.log').exists() else ''
    pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('samples','core_log','threads','checks')}),flush=True)
raise SystemExit(not result['passed'])
