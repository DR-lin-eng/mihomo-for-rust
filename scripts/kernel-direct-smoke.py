#!/usr/bin/env python3
"""Real independent LAN and WAN namespaces; no external network services."""
import argparse,contextlib,ctypes,hashlib,http.client,json,os,pathlib,socket,socketserver,struct,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--output',required=True);p.add_argument('--offload',choices=['on','off'],default='on');p.add_argument('--perf-seconds',type=float,default=0);p.add_argument('--auto-route',action='store_true');p.add_argument('--lifecycle',action='store_true');p.add_argument('--masquerade',action='store_true');a=p.parse_args()
root=pathlib.Path(tempfile.mkdtemp(prefix='kernel-direct-'));checks=[];core=None;servers=[];target=None
lan,wan,tun='kd-lan','kd-wan','kd-tun';client_ns,target_ns='kd-client','kd-target'
def run(*args,required=True):return subprocess.run(args,check=required,capture_output=True,text=True,timeout=12)
def check(name,ok,detail=None):
 checks.append(dict(name=name,passed=bool(ok),detail=detail))
 if not ok:print('FAIL',name,detail,flush=True)
def free():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
@contextlib.contextmanager
def network(name):
 old=os.open('/proc/thread-self/ns/net',os.O_RDONLY);new=os.open('/run/netns/'+name,os.O_RDONLY);lib=ctypes.CDLL(None,use_errno=True)
 try:
  if lib.setns(new,0x40000000):raise OSError(ctypes.get_errno(),'setns')
  yield
 finally:lib.setns(old,0x40000000);os.close(old);os.close(new)
class UDP(socketserver.ThreadingUDPServer):allow_reuse_address=True;daemon_threads=True;max_packet_size=65535
class DNS(socketserver.BaseRequestHandler):
 def handle(self):
  q,s=self.request;end=12
  while q[end]:end+=q[end]+1
  kind=struct.unpack('!H',q[end+1:end+3])[0];end+=5
  address=socket.inet_aton('203.0.113.30') if kind==1 else socket.inet_pton(socket.AF_INET6,'2001:db8:3::30')
  answer=b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(address))+address if kind in (1,28) else b''
  s.sendto(q[:2]+struct.pack('!5H',0x8180,1,int(bool(answer)),0,0)+q[12:end]+answer,self.client_address)
def api(path,method='GET',body=None):
 c=http.client.HTTPConnection('127.0.0.1',controller,timeout=4)
 c.request(method,path,None if body is None else json.dumps(body),{'Content-Type':'application/json'});r=c.getresponse();data=r.read();c.close()
 assert r.status in (200,204),(path,r.status,data)
 return json.loads(data) if data else None
def fake(host,ipv6=False):
 q=b'\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b''.join(bytes([len(v)])+v.encode() for v in host.split('.'))+b'\0'+struct.pack('!HH',28 if ipv6 else 1,1)
 with network(client_ns):s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 with s:s.settimeout(4);s.sendto(q,('192.0.2.1',dns_port));reply=s.recv(4096)
 assert reply[3]&15==0 and reply[6:8]==b'\0\x01',reply.hex()
 return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET,reply[-16:] if ipv6 else reply[-4:])
def connect(host,udp=False,port=None):
 with network(client_ns):s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
 s.settimeout(4);s.connect((host,port or (udp_port if udp else tcp_port)));return s
def request(s,payload):
 s.sendall(payload);return s.recv(65536)
def row_for(s):
 port=str(s.getsockname()[1]);return next((r for r in api('/connections')['connections'] if r['metadata']['sourcePort']==port),None)
def blocked(s,payload):
 try:s.settimeout(.35);s.sendall(payload);return s.recv(4096)!=payload
 except OSError:return True
try:
 pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1');pathlib.Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
 for namespace,link,local,remote,v6local,v6remote in [(client_ns,lan,'192.0.2.1','192.0.2.2','2001:db8:1::1','2001:db8:1::2'),(target_ns,wan,'203.0.113.1','203.0.113.30','2001:db8:3::1','2001:db8:3::30')]:
  run('ip','netns','add',namespace);run('ip','link','add',link,'type','veth','peer','name',link+'-peer');run('ip','link','set',link+'-peer','netns',namespace)
  run('ip','addr','add',local+'/24','dev',link);run('ip','-6','addr','add',v6local+'/64','dev',link,'nodad');run('ip','link','set',link,'up')
  run('ip','-n',namespace,'link','set','lo','up');run('ip','-n',namespace,'addr','add',remote+'/24','dev',link+'-peer');run('ip','-n',namespace,'-6','addr','add',v6remote+'/64','dev',link+'-peer','nodad');run('ip','-n',namespace,'link','set',link+'-peer','up')
  run('ip','-n',namespace,'route','add','default','via',local);run('ip','-n',namespace,'-6','route','add','default','via',v6local)
 if a.masquerade:run('iptables','-t','nat','-A','POSTROUTING','-o',wan,'-j','MASQUERADE')
 tcp_port,udp_port,controller,dns_port=free(),free(),free(),free()
 target_script=root/'target.py';target_script.write_text('''import socketserver,socket,threading,json,sys
class TCP(socketserver.BaseRequestHandler):
 def handle(self):
  first=True
  while True:
   b=self.request.recv(65536)
   if not b:return
   if first and b==b'bulk-download':
    data=bytes(range(256))*256
    try:
     while True:self.request.sendall(data)
    except OSError:return
   first=False
   self.request.sendall(b)
class UDP(socketserver.BaseRequestHandler):
 def handle(self):b,s=self.request;s.sendto(b,self.client_address)
class T(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class U(socketserver.ThreadingUDPServer):allow_reuse_address=True;daemon_threads=True;max_packet_size=65535
class T6(T):address_family=socket.AF_INET6
class U6(U):address_family=socket.AF_INET6
for cls,host,port,handler in [(T,'203.0.113.30',int(sys.argv[1]),TCP),(U,'203.0.113.30',int(sys.argv[2]),UDP),(T6,'2001:db8:3::30',int(sys.argv[1]),TCP),(U6,'2001:db8:3::30',int(sys.argv[2]),UDP)]:
 server=cls((host,port),handler);threading.Thread(target=server.serve_forever,daemon=True).start()
print('ready',flush=True);threading.Event().wait()
''')
 target=subprocess.Popen(['ip','netns','exec',target_ns,'python3',str(target_script),str(tcp_port),str(udp_port)],stdout=(root/'target.log').open('w'),stderr=subprocess.STDOUT)
 upstream=UDP(('127.0.0.1',0),DNS);servers.append(upstream);threading.Thread(target=upstream.serve_forever,daemon=True).start()
 cfg=f'''allow-lan: true
ipv6: true
mode: rule
log-level: debug
external-controller: 127.0.0.1:{controller}
dns:
  enable: true
  listen: 0.0.0.0:{dns_port}
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range6: fdfe:dcba::1/64
  nameserver: [udp://127.0.0.1:{upstream.server_address[1]}]
tun:
  enable: true
  stack: mixed
  device: {tun}
  auto-route: {str(a.auto_route).lower()}
  auto-redirect: false
  mtu: 1500
  udp-timeout: 2
  inet6-address: [fdfe:dcba::1/126]
{('ebpf:' + chr(10) + '  direct-offload: ['+lan+']') if a.offload=='on' else ''}
rules: ['DOMAIN,reject.test,REJECT', 'MATCH,DIRECT']
'''
 (root/'config.yaml').write_text(cfg);log=(root/'core.log').open('w');core=subprocess.Popen([a.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
 for _ in range(200):
  if core.poll() is not None:raise RuntimeError((root/'core.log').read_text())
  try:
   state=api('/ebpf')
   if state.get('direct_offload',{}).get('running',False)==(a.offload=='on'):break
  except (OSError,KeyError):pass
  time.sleep(.03)
 else:raise TimeoutError('kernel direct startup')
 check('DIRECT enabled only when configured',state.get('direct_offload',{}).get('running',False)==(a.offload=='on'),state)
 if a.offload=='off':
  # Give the ordinary userspace TUN path the same LAN traffic for comparison.
  run('ip','rule','add','iif',lan,'table','21576','priority','8576');run('ip','route','add','table','21576','default','dev',tun)
  run('ip','-6','rule','add','iif',lan,'table','21576','priority','8576');run('ip','-6','route','add','table','21576','default','dev',tun)
 hosts=[('203.0.113.30',False),(fake('direct.test'),False)]
 if a.offload=='on':hosts.extend([('2001:db8:3::30',True),(fake('direct6.test',True),True)])
 for host,ipv6 in hosts:
  with connect(host) as s:
   payload=b'tcp-'+host.encode();check('TCP echo '+host,request(s,payload)==payload)
   time.sleep(.15);rows=api('/connections')['connections'];row=next((r for r in rows if r.get('kernelOffload') and r['metadata']['sourcePort']==str(s.getsockname()[1])),None)
   check('TCP is tracked as configured DIRECT path '+host,(row is not None)==(a.offload=='on'),row)
   if a.offload=='on':check('TCP payload counters '+host,row is not None and row['upload']==len(payload) and row['download']==len(payload),row)
   large=bytes(range(256))*1024;s.sendall(large);received=b''
   while len(received)<len(large):received+=s.recv(len(large)-len(received))
   check('large TCP bytes '+host,received==large)
   if a.offload=='on':
    time.sleep(.1);row=row_for(s);check('large TCP counters '+host,row is not None and row['upload']==len(payload)+len(large) and row['download']==len(payload)+len(large),row)
    api('/connections/'+row['id'],'DELETE');check('DELETE stops existing kernel TCP '+host,blocked(s,b'deleted'))
  with connect(host,True) as s:
   payload=b'udp-'+host.encode();check('UDP echo '+host,request(s,payload)==payload)
   time.sleep(.1);rows=api('/connections')['connections'];row=next((r for r in rows if r.get('kernelOffload') and r['metadata']['sourcePort']==str(s.getsockname()[1])),None)
   if a.offload=='on':check('UDP kernel counters '+host,row is not None and row['upload']==len(payload) and row['download']==len(payload),row)
   large=bytes(range(256))*(64 if a.offload=='on' else 4);check(('fragmented UDP ' if a.offload=='on' else 'userspace UDP ')+host,request(s,large)==large)
   if a.offload=='on':
    time.sleep(.1);row=row_for(s);check('fragmented UDP counted once '+host,row is not None and row['upload']==len(payload)+len(large) and row['download']==len(payload)+len(large),row)
 if a.offload=='on':
  host=fake('direct.test')
  with connect(host,True) as s:
   payload=bytes(range(256))*64;check('first datagram can be fragmented',request(s,payload)==payload)
  with connect(host,True) as s:
   check('UDP session before idle expiry',request(s,b'before-idle')==b'before-idle');time.sleep(.1);first=row_for(s)['id'];time.sleep(2.2)
   check('UDP session after idle expiry',request(s,b'after-idle')==b'after-idle');time.sleep(.1);row=row_for(s);check('expired UDP creates new tracked flow',row is not None and row['id']!=first,row)
  with connect(host,True) as s:
   check('UDP policy before mode switch',request(s,b'before-mode')==b'before-mode');time.sleep(.1);first=row_for(s)['id']
   payload=(root/'config.yaml').read_text();api('/configs?force=true','PUT',{'payload':payload.replace('mode: rule','mode: global')});
   check('mode change invalidates UDP offload',request(s,b'after-mode')==b'after-mode');time.sleep(.1);mode_row=row_for(s);check('mode changed flow is userspace',mode_row is not None and not mode_row.get('kernelOffload',False),mode_row);
   api('/configs?force=true','PUT',{'payload':payload})
  with connect(host,True) as s:check('UDP after rule mode restored',request(s,b'restored')==b'restored')
  ip_config=cfg.replace("rules: ['DOMAIN,reject.test,REJECT', 'MATCH,DIRECT']","rules: ['IP-CIDR,203.0.113.30/32,DIRECT', 'IP-CIDR6,2001:db8:3::30/128,DIRECT', 'MATCH,REJECT']")
  api('/configs?force=true','PUT',{'payload':ip_config})
  with connect(fake('ip-rule.test')) as s:
   check('IP-CIDR resolves fake-IP before final action',request(s,b'ip-rule')==b'ip-rule');time.sleep(.1);check('IP-CIDR decision is kernel offloaded',row_for(s).get('kernelOffload',False),row_for(s))
  sniff_config=cfg+f'\nsniffer:\n  enable: true\n  force-domain: [direct.test]\n  sniff:\n    HTTP: {{ports: [{tcp_port}]}}\n'
  api('/configs?force=true','PUT',{'payload':sniff_config})
  with connect(fake('direct.test')) as s:
   payload=b'GET / HTTP/1.1\r\nHost: direct.test\r\n\r\n';check('sniff-required flow still forwards',request(s,payload)==payload);time.sleep(.1);check('sniff-required flow stays userspace',not row_for(s).get('kernelOffload',False),row_for(s))
  select_config=cfg.replace("'MATCH,DIRECT'","'MATCH,choose-direct'")+"\nproxy-groups:\n  - name: choose-direct\n    type: select\n    proxies: [DIRECT, REJECT]\n"
  api('/configs?force=true','PUT',{'payload':select_config})
  api('/proxies/choose-direct','PUT',{'name':'DIRECT'})
  host=fake('direct.test')
  with connect(host,True) as s:
   check('explicit selector DIRECT forwards',request(s,b'select-direct')==b'select-direct');time.sleep(.1);check('explicit selector DIRECT uses kernel',row_for(s).get('kernelOffload',False),row_for(s))
   api('/proxies/choose-direct','PUT',{'name':'REJECT'});check('selector change invalidates offloaded UDP',blocked(s,b'now-reject'))
  api('/configs?force=true','PUT',{'payload':cfg})
 if a.perf_seconds:
  from concurrent.futures import ThreadPoolExecutor
  barrier=threading.Barrier(9);deadline=[0];start_ticks=pathlib.Path('/proc/'+str(core.pid)+'/stat').read_text().split();start_cpu=int(start_ticks[13])+int(start_ticks[14]);start=time.monotonic()
  def bulk(index):
   with connect('203.0.113.30') as s:
    barrier.wait();s.sendall(b'bulk-download');n=0;buf=bytearray(65536)
    pattern=bytes(range(256))*256
    while time.monotonic()<deadline[0]:
     received=s.recv_into(buf)
     if not received:raise EOFError('bulk source closed')
     offset=n%256
     if memoryview(buf)[:received]!=(pattern[offset:]+pattern[:offset])[:received]:raise AssertionError('bulk payload mismatch')
     n+=received
    return n
  with ThreadPoolExecutor(max_workers=8) as pool:
   futures=[pool.submit(bulk,i) for i in range(8)];deadline[0]=time.monotonic()+a.perf_seconds;barrier.wait();total=sum(f.result() for f in futures)
  end_ticks=pathlib.Path('/proc/'+str(core.pid)+'/stat').read_text().split();cpu=(int(end_ticks[13])+int(end_ticks[14])-start_cpu)/os.sysconf('SC_CLK_TCK')
  performance=dict(bytes=total,seconds=a.perf_seconds,mbps=total*8/a.perf_seconds/1e6,core_cpu_seconds=cpu);check('bulk kernel transfer completed',total>0,performance)
 rejected=fake('reject.test')
 try:
  with connect(rejected) as s:request(s,b'blocked')
  blocked=False
 except (OSError,EOFError):blocked=True
 check('REJECT domain never becomes a kernel DIRECT flow',blocked)
 if a.offload=='on':
  with connect('203.0.113.30',True) as s:check('final counter probe forwards',request(s,b'counter-probe')==b'counter-probe')
 status=api('/ebpf').get('direct_offload',{})
 if a.offload=='on':check('kernel counters advance',status['upload']>0 and status['download']>0,status)
 if a.lifecycle and a.offload=='on':
  # A failed new configuration must restore both the capture and routing.
  c=http.client.HTTPConnection('127.0.0.1',controller,timeout=10);c.request('PUT','/configs?force=true',json.dumps({'payload':cfg.replace('direct-offload: [kd-lan]','direct-offload: [missing-kd0]')}),{'Content-Type':'application/json'});r=c.getresponse();r.read();c.close();check('failed interface reload is rejected',r.status==400,r.status)
  with connect(fake('direct.test')) as s:check('failed reload restores old DIRECT path',request(s,b'rollback')==b'rollback')
  api('/configs?force=true','PUT',{'payload':cfg})
  with connect(fake('direct.test')) as s:check('normal reload restores DIRECT path',request(s,b'reload')==b'reload')
  # Terminating an already-owned interface must leave an unrelated clsact/filter.
  run('tc','filter','add','dev',lan,'ingress','pref','100','matchall','action','continue')
  core.terminate();core.wait(8)
  filters=json.loads(run('tc','-j','filter','show','dev',lan,'ingress').stdout or '[]');check('foreign TC filter survives shutdown',any(f.get('pref')==100 for f in filters),filters)
  check('normal shutdown removes DIRECT programs',not any(p.get('name','').startswith('mihomo_kd') for p in json.loads(run('bpftool','-j','prog','show').stdout)))
  check('normal shutdown removes owned routing mark rule','0x636c746d' not in run('ip','rule','show').stdout)
  # A process lock prevents a second core from deleting live TC programs.
  core=subprocess.Popen([a.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
  for _ in range(200):
   try:
    if api('/ebpf')['direct_offload']['running']:break
   except OSError:pass
   time.sleep(.03)
  crash_ids=api('/ebpf')['direct_offload']['program_ids'];core.kill();core.wait(5)
  core=subprocess.Popen([a.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
  for _ in range(200):
   if core.poll() is not None:raise RuntimeError((root/'core.log').read_text())
   try:
    if api('/ebpf')['direct_offload']['running']:break
   except OSError:pass
   time.sleep(.03)
  check('SIGKILL recovery replaces stale BPF programs',not set(crash_ids)&set(api('/ebpf')['direct_offload']['program_ids']))
  with connect(fake('direct.test')) as s:check('DIRECT works after SIGKILL recovery',request(s,b'crash-recovery')==b'crash-recovery')
except Exception as e:check('fixture execution',False,repr(e))
finally:
 if core is not None and core.poll() is None:
  core.terminate()
  try:core.wait(8)
  except subprocess.TimeoutExpired:core.kill();core.wait();check('bounded shutdown',False)
 if a.lifecycle:
  check('final shutdown removes direct programs',not any(p.get('name','').startswith('mihomo_kd') for p in json.loads(run('bpftool','-j','prog','show').stdout)))
  check('crash-recovered routing ownership cleaned','0x636c746d' not in run('ip','rule','show').stdout)
 if target is not None:target.terminate();target.wait(5)
 for server in servers:server.shutdown();server.server_close()
 if a.masquerade:run('iptables','-t','nat','-D','POSTROUTING','-o',wan,'-j','MASQUERADE',required=False)
 if a.offload=='off':
  run('ip','rule','del','iif',lan,'table','21576','priority','8576',required=False);run('ip','route','flush','table','21576',required=False)
  run('ip','-6','rule','del','iif',lan,'table','21576','priority','8576',required=False);run('ip','-6','route','flush','table','21576',required=False)
 for link in [lan,wan]:run('ip','link','del',link,required=False)
 for ns in [client_ns,target_ns]:run('ip','netns','del',ns,required=False)
 if 'log' in locals():log.close()
 result=dict(passed=all(c['passed'] for c in checks),checks=checks,work=str(root),offload=a.offload,auto_route=a.auto_route,lifecycle=a.lifecycle,masquerade=a.masquerade,performance=locals().get('performance'),sha256=hashlib.sha256(pathlib.Path(a.core).read_bytes()).hexdigest(),core_log=(root/'core.log').read_text() if (root/'core.log').exists() else '')
 pathlib.Path(a.output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(dict(passed=result['passed'],checks=len(checks),work=str(root))),flush=True)
raise SystemExit(not result['passed'])
