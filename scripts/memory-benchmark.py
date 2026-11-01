#!/usr/bin/env python3
"""Compare static cores with fixed inputs and /proc RSS, PSS and high water marks."""
import argparse,hashlib,http.client,json,os,pathlib,shutil,socket,subprocess,tempfile,threading,time
parser=argparse.ArgumentParser();parser.add_argument('--core',required=True);parser.add_argument('--model',required=True);parser.add_argument('--output',required=True);parser.add_argument('--runs',type=int,default=3);parser.add_argument('--scenarios',nargs='+',default=['idle','rules-40000','geosite-120000','smart-18-groups']);args=parser.parse_args()
root=pathlib.Path(tempfile.mkdtemp(prefix='mihomo-memory-'));records=[]
def port():
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def varint(value):
 out=bytearray()
 while value>=128:out.append((value&127)|128);value>>=7
 out.append(value);return bytes(out)
def field(number,value):return varint(number*8+2)+varint(len(value))+value
def geosite():
 entries=[]
 for category in range(24):
  domains=[]
  for i in range(5000):
   domain=b'\x08\x02'+field(2,f'site-{i:05d}.category-{category:02d}.example'.encode());domains.append(field(2,domain))
  entries.append(field(1,field(1,('cn' if category==0 else f'category-{category}').encode())+b''.join(domains)))
 return b''.join(entries)
geodata=geosite();(root/'GeoSite.dat').write_bytes(geodata)
def status(pid):
 values={}
 try:
  for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
   if ':' in line:
    key,value=line.split(':',1)
    if key in ['VmRSS','VmHWM','VmSize','Threads']:values[key]=int(value.strip().split()[0])
  for line in pathlib.Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
   if ':' in line:
    key,value=line.split(':',1)
    if key in ['Pss','Private_Dirty','Anonymous']:values[key]=int(value.strip().split()[0])
 except (OSError,ValueError):pass
 return values
def request(controller,path):
 conn=http.client.HTTPConnection('127.0.0.1',controller,timeout=20);conn.request('GET',path,headers={'Authorization':'Bearer memory-fixture'});res=conn.getresponse();data=res.read();code=res.status;conn.close();return code,data
def kernel_maps(pid):
 maps={}
 for file in pathlib.Path(f'/proc/{pid}/fdinfo').glob('*'):
  try:
   values=dict(line.split(':',1) for line in file.read_text().splitlines() if ':' in line)
   if 'map_id' in values and 'memlock' in values:maps[values['map_id'].strip()]=int(values['memlock'].strip())
  except (OSError,ValueError):pass
 return sum(maps.values())
for repeat in range(args.runs):
 for scenario in args.scenarios:
  work=root/f'{scenario}-{repeat}';work.mkdir();controller=port();mixed=port()
  groups=[]
  for i in range(18):groups.extend([f'  - name: group-{i}',f'    type: {"smart" if scenario=="smart-18-groups" else "select"}','    proxies: [DIRECT, REJECT]']+(['    uselightgbm: true','    lazy: true'] if scenario=='smart-18-groups' else []))
  proxies='\n'.join(f'  - {{name: proxy-{i}, type: socks5, server: 127.0.0.1, port: 9000, udp: true}}' for i in range(67))
  rules=('\n'.join(f'  - DOMAIN-SUFFIX,rule-{i:05d}.example,DIRECT' for i in range(40000))+'\n' if scenario=='rules-40000' else '  - GEOSITE,cn,DIRECT\n' if scenario=='geosite-120000' else '')+'  - MATCH,DIRECT\n'
  config=f'''external-controller: 127.0.0.1:{controller}
secret: memory-fixture
mixed-port: {mixed}
mode: rule
log-level: warning
proxies:
{proxies}
proxy-groups:
'''+ '\n'.join(groups)+'\nrules:\n'+rules+'dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-filter: ["geosite:cn"]\n  nameserver: [rcode://success]\n' if scenario=='geosite-120000' else f'''external-controller: 127.0.0.1:{controller}
secret: memory-fixture
mixed-port: {mixed}
mode: rule
log-level: warning
proxies:
{proxies}
proxy-groups:
'''+ '\n'.join(groups)+'\nrules:\n'+rules+'dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [rcode://success]\n'
  capture='memory-bpf0'
  if scenario=='ebpf-auto-redir':
   subprocess.run(['ip','link','add',capture,'type','dummy'],check=True)
   subprocess.run(['ip','addr','add','192.0.2.1/24','dev',capture],check=True)
   subprocess.run(['ip','link','set',capture,'up'],check=True)
   config+='allow-lan: true\nredir-port: '+str(port())+'\nebpf:\n  auto-redir: ['+capture+']\n'
  (work/'config.yaml').write_text(config)
  if scenario.startswith('smart'):shutil.copyfile(args.model,work/'Model.bin')
  if scenario.startswith('geosite'):shutil.copyfile(root/'GeoSite.dat',work/'GeoSite.dat')
  log=open(work/'core.log','w');process=subprocess.Popen([args.core,'-d',str(work),'-f',str(work/'config.yaml')],stdout=log,stderr=log,env=dict(os.environ,MIHOMO_FORCE_NATIVE_RUNTIME='1'))
  peak=[0];samples=[];done=threading.Event()
  def monitor():
   while not done.is_set():
    data=status(process.pid)
    if data:peak[0]=max(peak[0],data.get('VmHWM',0),data.get('VmRSS',0));samples.append(data)
    done.wait(.01)
  watcher=threading.Thread(target=monitor,daemon=True);watcher.start();started=time.monotonic()
  try:
   for _ in range(1200):
    if process.poll() is not None:raise RuntimeError((work/'core.log').read_text())
    try:
     if request(controller,'/version')[0]==200:break
    except OSError:pass
    time.sleep(.025)
   else:raise RuntimeError('core startup timed out')
   startup_seconds=time.monotonic()-started;time.sleep(.3);idle=status(process.pid);map_bytes=kernel_maps(process.pid)
   if scenario=='ebpf-auto-redir' and not json.loads(request(controller,'/ebpf')[1])['running']:raise RuntimeError('eBPF did not load')
   for _ in range(8):
    for route in ['/version','/proxies','/configs','/rules']:
     code,data=request(controller,route)
     if code!=200:raise RuntimeError((route,code))
   time.sleep(.3);after=status(process.pid)
   record=dict(scenario=scenario,repeat=repeat,startup_seconds=round(startup_seconds,4),idle=idle,after_api_poll=after,peak_rss_kib=max(peak[0],after.get('VmHWM',0)),requests=32,kernel_map_memlock_bytes=map_bytes,passed=True)
  except Exception as error:record=dict(scenario=scenario,repeat=repeat,passed=False,error=repr(error),log=(work/'core.log').read_text())
  finally:
   process.terminate()
   try:process.wait(timeout=12)
   except subprocess.TimeoutExpired:process.kill();process.wait()
   done.set();watcher.join();log.close()
   if scenario=='ebpf-auto-redir':subprocess.run(['ip','link','del',capture],check=True)
  records.append(record);print(json.dumps(record),flush=True)
result=dict(core=args.core,sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest(),model_sha256=hashlib.sha256(pathlib.Path(args.model).read_bytes()).hexdigest(),geosite_sha256=hashlib.sha256(geodata).hexdigest(),geosite_bytes=len(geodata),records=records)
pathlib.Path(args.output).write_text(json.dumps(result,indent=2)+'\n');raise SystemExit(any(not record['passed'] for record in records))
