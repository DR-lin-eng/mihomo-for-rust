#!/usr/bin/env python3
"""Real TC eBPF tests; run only inside an isolated privileged Linux container."""
import argparse,http.client,json,os,pathlib,socket,socketserver,struct,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--output',required=True);args=p.parse_args()
work=pathlib.Path(tempfile.mkdtemp(prefix='mihomo-ebpf-smoke-'));checks=[];destinations=[];process=None;servers=[];links=[];namespaces=[];logs=[];target_process=None
def check(name,result,detail=None):
 checks.append(dict(name=name,passed=bool(result),detail=detail))
 if not result:print('FAIL',name,detail,flush=True)
def run(*argv,ok=True):return subprocess.run(argv,text=True,capture_output=True,check=ok,timeout=15)
def port():
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def exact(sock,size):
 data=b''
 while len(data)<size:
  chunk=sock.recv(size-len(data))
  if not chunk:raise EOFError()
  data+=chunk
 return data
class ThreadTcp(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class Socks(socketserver.BaseRequestHandler):
 def handle(self):
  try:
   self.request.settimeout(10);version,count=exact(self.request,2);exact(self.request,count);self.request.sendall(b'\x05\x00')
   version,command,reserved,kind=exact(self.request,4)
   if kind==1:host=socket.inet_ntoa(exact(self.request,4))
   elif kind==4:host=socket.inet_ntop(socket.AF_INET6,exact(self.request,16))
   elif kind==3:host=exact(self.request,exact(self.request,1)[0]).decode()
   else:return
   remote_port=struct.unpack('!H',exact(self.request,2))[0];destinations.append((host,remote_port))
   if command==3:
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(8)
    self.request.sendall(b'\x05\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',udp.getsockname()[1]))
    packet,peer=udp.recvfrom(65535);kind=packet[3];offset=10 if kind==1 else 22
    target=socket.inet_ntop(socket.AF_INET if kind==1 else socket.AF_INET6,packet[4:8] if kind==1 else packet[4:20]);target_port=struct.unpack('!H',packet[offset-2:offset])[0]
    destinations.append((target,target_port));udp.sendto(packet[:offset]+b'pong:'+packet[offset:],peer);udp.close();return
   self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
   data=self.request.recv(4096);self.request.sendall(b'pong:'+data);self.request.shutdown(socket.SHUT_WR)
  except (OSError,EOFError):pass
socks=ThreadTcp(('127.0.0.1',0),Socks);servers.append(socks);threading.Thread(target=socks.serve_forever,daemon=True).start();proxy_port=socks.server_address[1]
controller_port=port();redir_port=port()
def request(method,target,body=None,auth=True):
 conn=http.client.HTTPConnection('127.0.0.1',controller_port,timeout=15);headers={}
 if auth:headers['Authorization']='Bearer ebpf-fixture'
 if body is not None:body=json.dumps(body).encode();headers['Content-Type']='application/json'
 conn.request(method,target,body,headers);response=conn.getresponse();data=response.read();status=response.status;conn.close();return status,data
def api(path='/ebpf'):return json.loads(request('GET',path)[1])
def launch(config,label):
 global process
 path=work/(label+'.yaml');path.write_text(config);log_path=work/(label+'.log');logs.append(log_path);log=log_path.open('w')
 process=subprocess.Popen([args.core,'-d',str(work),'-f',str(path)],stdout=log,stderr=log,env=dict(os.environ,MIHOMO_FORCE_NATIVE_RUNTIME='1'));log.close()
 for _ in range(300):
  if process.poll() is not None:raise RuntimeError(log_path.read_text())
  try:
   status=api()
   if status['running']:return
  except OSError:pass
  time.sleep(.05)
 raise RuntimeError('eBPF did not become ready: '+log_path.read_text())
def stop():
 global process
 if not process:return
 process.terminate()
 try:process.wait(timeout=12)
 except subprocess.TimeoutExpired:process.kill();process.wait();check('core stopped gracefully',False)
 process=None

def config(ebpf,tun=''):
 return f'''external-controller: 127.0.0.1:{controller_port}
secret: ebpf-fixture
mode: rule
log-level: debug
allow-lan: true
ipv6: true
redir-port: {redir_port}
{tun}
ebpf:
{ebpf}
proxies:
  - name: echo-proxy
    type: socks5
    server: 127.0.0.1
    port: {proxy_port}
    udp: true
rules:
  - MATCH,echo-proxy
'''

def filters(name,direction):
 result=run('tc','-j','filter','show','dev',name,direction);return json.loads(result.stdout or '[]')
def client(namespace,host,remote_port,payload,udp=False):
 script='''import socket,sys
host,port,payload=sys.argv[1],int(sys.argv[2]),sys.argv[3].encode()
s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_DGRAM if sys.argv[4]=='udp' else socket.SOCK_STREAM);s.settimeout(8)
s.connect((host,port));s.sendall(payload);print(s.recv(4096).decode());s.close()
'''
 command=['python3','-c',script,host,str(remote_port),payload,'udp' if udp else 'tcp']
 if namespace:command=['ip','netns','exec',namespace]+command
 return run(*command).stdout.strip()
def bpf_ids():return {p['id'] for p in json.loads(run('bpftool','-j','prog','show').stdout) if p.get('name','').startswith('mihomo_')}
try:
 initial_ids=bpf_ids()
 # Simulated LAN, completely inside the container's network namespace.
 ns='ebpf-client';run('ip','netns','add',ns);namespaces.append(ns)
 run('ip','link','add','ebpf-lan','type','veth','peer','name','ebpf-peer');links.append('ebpf-lan')
 run('ip','link','set','ebpf-peer','netns',ns)
 run('ip','addr','add','192.0.2.1/24','dev','ebpf-lan');run('ip','-6','addr','add','2001:db8:1::1/64','dev','ebpf-lan','nodad');run('ip','link','set','ebpf-lan','up')
 run('ip','netns','exec',ns,'ip','link','set','lo','up');run('ip','netns','exec',ns,'ip','addr','add','192.0.2.2/24','dev','ebpf-peer');run('ip','netns','exec',ns,'ip','-6','addr','add','2001:db8:1::2/64','dev','ebpf-peer','nodad');run('ip','netns','exec',ns,'ip','link','set','ebpf-peer','up')
 run('ip','netns','exec',ns,'ip','route','add','default','via','192.0.2.1');run('ip','netns','exec',ns,'ip','-6','route','add','default','via','2001:db8:1::1')
 auto=config('  auto-redir: [ebpf-lan]')
 launch(auto,'auto-redir')
 state=api();ids=set(state['interfaces'][0]['program_ids']);check('auto-redir real programs loaded',len(ids)==2 and ids.issubset(bpf_ids()),state)
 check('eBPF status requires bearer',request('GET','/ebpf',auth=False)[0]==401)
 check('API exposes configured ebpf',api('/configs')['ebpf']['auto-redir']==['ebpf-lan'])
 check('TC ingress and egress attached',bool(filters('ebpf-lan','ingress')) and bool(filters('ebpf-lan','egress')))
 check('IPv4 LAN TCP transparent proxy',client(ns,'203.0.113.10',443,'ebpf-v4')=='pong:ebpf-v4')
 check('IPv4 original destination preserved',('203.0.113.10',443) in destinations,destinations)
 check('IPv6 LAN TCP transparent proxy',client(ns,'2001:db8:abcd::10',443,'ebpf-v6')=='pong:ebpf-v6')
 check('IPv6 original destination preserved',('2001:db8:abcd::10',443) in destinations,destinations)
 counters=api()['interfaces'][0]['counters'];check('kernel packet counters advance',counters['redirected']>=4,counters)
 old_ids=ids
 check('config reload with BPF attached',request('PUT','/configs?force=true',{'payload':auto})[0]==204)
 check('reload detaches old programs',not(old_ids&bpf_ids()),list(bpf_ids()))
 check('traffic still works after reload',client(ns,'203.0.113.11',8443,'reload')=='pong:reload')
 invalid_reload=auto.replace('[ebpf-lan]','[ebpf-lan, missing-ebpf0]')
 check('failed eBPF reconfiguration returns error',request('PUT','/configs',{'payload':invalid_reload})[0]==400)
 check('failed eBPF reconfiguration restores previous capture',client(ns,'203.0.113.14',443,'rollback')=='pong:rollback')

 stop();check('normal exit detaches filters',not filters('ebpf-lan','ingress') and not filters('ebpf-lan','egress'))
 check('normal exit frees programs',not(bpf_ids()-initial_ids),list(bpf_ids()-initial_ids))
 check('owned empty clsact removed',not any(q['kind']=='clsact' for q in json.loads(run('tc','-j','qdisc','show','dev','ebpf-lan').stdout)))
 # A foreign clsact/filter must remain intact through core start, reload and exit.
 run('tc','qdisc','add','dev','ebpf-lan','clsact')
 run('tc','filter','add','dev','ebpf-lan','ingress','pref','10','matchall','action','continue')
 launch(auto,'foreign-filter');client(ns,'203.0.113.12',443,'foreign');stop()
 check('foreign TC filter preserved',any(f.get('pref')==10 for f in filters('ebpf-lan','ingress')),filters('ebpf-lan','ingress'))
 check('foreign clsact preserved',any(q['kind']=='clsact' for q in json.loads(run('tc','-j','qdisc','show','dev','ebpf-lan').stdout)))
 run('tc','filter','del','dev','ebpf-lan','ingress','pref','10')
 launch(auto,'foreign-empty-qdisc');stop()
 check('preexisting empty clsact preserved',any(q['kind']=='clsact' for q in json.loads(run('tc','-j','qdisc','show','dev','ebpf-lan').stdout)))
 run('tc','qdisc','del','dev','ebpf-lan','clsact')
 # redirect-to-tun follows legacy Go's TC egress semantics.
 run('ip','link','add','ebpf-wan','type','dummy');links.append('ebpf-wan');run('ip','addr','add','198.51.100.1/24','dev','ebpf-wan');run('ip','link','set','ebpf-wan','up')
 run('ip','route','add','203.0.113.20/32','dev','ebpf-wan');run('ip','-6','route','add','2001:db8:abcd::20/128','dev','ebpf-wan')
 tun='''tun:
  enable: true
  stack: system
  device: ebpf-tun
  auto-route: false
  mtu: 1500
  inet4-address: [198.19.0.1/30]
  inet6-address: [fdfe:dcba::1/126]'''
 redirect=config('  redirect-to-tun: [ebpf-wan]',tun)
 launch(redirect,'redirect-to-tun');state=api();check('TUN redirect program attached',state['interfaces'][0]['mode']=='redirect-to-tun' and len(state['interfaces'][0]['program_ids'])==1,state)
 check('TC egress redirects IPv4 TCP into core TUN',client(None,'203.0.113.20',443,'tun-v4')=='pong:tun-v4')
 check('TC egress redirects IPv4 UDP into core TUN',client(None,'203.0.113.20',5354,'tun-udp',True)=='pong:tun-udp')
 check('TC egress redirects IPv6 TCP into core TUN',client(None,'2001:db8:abcd::20',443,'tun-v6')=='pong:tun-v6')
 counters=api()['interfaces'][0]['counters'];check('TUN kernel counters advance',counters['redirected']>0,counters)
 stop();check('TUN mode exit removes BPF filters',not filters('ebpf-wan','egress'))
 check('TUN mode exit frees BPF programs',not(bpf_ids()-initial_ids),list(bpf_ids()-initial_ids))

 # A live instance owns an interface exclusively. After SIGKILL the next start
 # must remove stale owned filters, not stack another copy on top.
 launch(auto,'before-crash');old_ids=set(api()['interfaces'][0]['program_ids'])
 other_port=port();other_config=auto.replace(str(controller_port),str(other_port)).replace(str(redir_port),str(port()))
 collision=work/'collision.yaml';collision.write_text(other_config)
 other=subprocess.run([args.core,'-d',str(work),'-f',str(collision)],capture_output=True,text=True,timeout=10)
 check('live eBPF ownership is exclusive',other.returncode!=0 and 'already owned' in other.stderr,other.stderr[-800:])
 check('rejected second core leaves first attached',old_ids.issubset(bpf_ids()))
 process.kill();process.wait();process=None
 launch(auto,'after-crash');check('crash recovery removes stale programs',not(old_ids&bpf_ids()),list(bpf_ids()))
 check('TCP works after crash recovery',client(ns,'203.0.113.13',443,'recovery')=='pong:recovery');stop()
 # Direct sockets created by the core must not be captured for a second time.
 target_ns='ebpf-target';run('ip','netns','add',target_ns);namespaces.append(target_ns)
 run('ip','link','add','ebpf-direct','type','veth','peer','name','ebpf-target');links.append('ebpf-direct')
 run('ip','link','set','ebpf-target','netns',target_ns);run('ip','addr','add','203.0.113.1/24','dev','ebpf-direct');run('ip','link','set','ebpf-direct','up')
 run('ip','netns','exec',target_ns,'ip','link','set','lo','up');run('ip','netns','exec',target_ns,'ip','addr','add','203.0.113.30/24','dev','ebpf-target');run('ip','netns','exec',target_ns,'ip','link','set','ebpf-target','up')
 target_script=work/'direct-target.py';target_script.write_text("""import socketserver,threading,struct
class TCP(socketserver.BaseRequestHandler):
 def handle(self):self.request.sendall(b'pong:'+self.request.recv(4096))
class UDP(socketserver.BaseRequestHandler):
 def handle(self):data,sock=self.request;sock.sendto(b'pong:'+data,self.client_address)
class DNS(socketserver.BaseRequestHandler):
 def handle(self):
  query,sock=self.request;end=12
  while query[end]:end+=query[end]+1
  end+=5;data=b'\\x07fixture';reply=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+b'\\xc0\\x0c'+struct.pack('!HHIH',16,1,123,len(data))+data;sock.sendto(reply,self.client_address)
for cls,port in [(socketserver.ThreadingTCPServer,8080),(socketserver.ThreadingUDPServer,8080),(socketserver.ThreadingUDPServer,5353)]:
 handler=DNS if port==5353 else UDP if cls==socketserver.ThreadingUDPServer else TCP
 server=cls(('203.0.113.30',port),handler);threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
""")
 target_process=subprocess.Popen(['ip','netns','exec',target_ns,'python3',str(target_script)]);time.sleep(.2)
 direct=config('  redirect-to-tun: [ebpf-direct]',tun).replace('MATCH,echo-proxy','MATCH,DIRECT')+'\ndns:\n  enable: true\n  nameserver: [203.0.113.30:5353]\n'
 launch(direct,'core-socket-bypass')
 check('core TCP sockets bypass eBPF capture',client(None,'203.0.113.30',8080,'direct-tcp')=='pong:direct-tcp')
 check('core UDP sockets bypass eBPF capture',client(None,'203.0.113.30',8080,'direct-udp',True)=='pong:direct-udp')
 status,data=request('GET','/dns/query?name=bypass.test&type=TXT');answer=json.loads(data)
 check('core DNS UDP sockets bypass capture',status==200 and bool(answer.get('Answer')),answer)
 state=api();check('bypass mark observed by kernel',state['interfaces'][0]['counters']['bypassed']>0,state)
 stop()

 missing=work/'missing.yaml';missing.write_text(auto.replace('[ebpf-lan]','[missing-ebpf0]'))
 failed=subprocess.run([args.core,'-d',str(work),'-f',str(missing)],capture_output=True,text=True,timeout=10)
 check('missing capture interface fails startup',failed.returncode!=0,failed.stderr[-600:])
 check('failed startup leaves no BPF programs',not(bpf_ids()-initial_ids),list(bpf_ids()-initial_ids))
 no_caps=work/'no-caps.yaml';no_caps.write_text(auto)
 failed=subprocess.run(['setpriv','--bounding-set=-bpf,-sys_admin,-net_admin',args.core,'-d',str(work),'-f',str(no_caps)],capture_output=True,text=True,timeout=10)
 check('insufficient capabilities fail explicitly',failed.returncode!=0,failed.stderr[-600:])
 check('capability failure leaves no BPF programs',not(bpf_ids()-initial_ids),list(bpf_ids()-initial_ids))

except Exception as error:check('suite completed',False,repr(error))
finally:
 stop()
 if target_process is not None:target_process.terminate();target_process.wait(timeout=5)
 for name in reversed(links):run('ip','link','del',name,ok=False)
 for name in namespaces:run('ip','netns','del',name,ok=False)
 for server in servers:server.shutdown()
 record=dict(core=args.core,checks=checks,destinations=destinations,logs={path.name:path.read_text() for path in logs},workspace=str(work))
 pathlib.Path(args.output).write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n');print(sum(c['passed'] for c in checks),'/',len(checks),'eBPF checks passed',flush=True)
 raise SystemExit(any(not c['passed'] for c in checks))
