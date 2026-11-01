#!/usr/bin/env python3
"""Rule-provider timestamps, refresh/rollback, and a local yacd browser fixture."""
import argparse,datetime,hashlib,http.client,http.server,json,pathlib,signal,socket,subprocess,tempfile,threading,time,urllib.parse
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--output');p.add_argument('--home');p.add_argument('--controller',type=int);p.add_argument('--ui');p.add_argument('--serve',action='store_true');args=p.parse_args()
root=pathlib.Path(args.home or tempfile.mkdtemp(prefix='yacd-rules-'));root.mkdir(parents=True,exist_ok=True);checks=[];payload={'mode':'valid','body':b'payload:\n  - DOMAIN-SUFFIX,remote.test\n  - DOMAIN,second.remote.test\n'};shutdown=threading.Event();core=None
def check(name,ok,detail=None):
 checks.append(dict(name=name,passed=bool(ok),detail=detail))
 if not ok:print('FAIL',name,detail,flush=True)
def free():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
class Source(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path=='/probe':data=b'ok';status=200
  else:data=payload['body'] if payload['mode']=='valid' else b'payload:\n  - INVALID-RULE\n';status=503 if payload['mode']=='offline' else 200
  self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Source);threading.Thread(target=server.serve_forever,daemon=True).start();port=args.controller or free();mixed=free()
file=root/'file.yaml';cached=root/'cached.yaml';file.write_text('payload:\n  - DOMAIN-SUFFIX,file.test\n');cached.write_text('payload:\n  - DOMAIN-SUFFIX,cached.test\n')
import os
os.utime(file,(946684800,946684800));os.utime(cached,(978307200,978307200))
config=f'''external-controller: 0.0.0.0:{port}
secret: yacd-fixture
mixed-port: {mixed}
mode: rule
rule-providers:
  Inline Rules:
    type: inline
    behavior: classical
    payload: ['DOMAIN-SUFFIX,inline.test']
  File Rules:
    type: file
    behavior: classical
    path: file.yaml
  HTTP Rules:
    type: http
    behavior: classical
    path: cached.yaml
    url: http://127.0.0.1:{server.server_port}/rules.yaml
    interval: 86400
rules:
  - RULE-SET,Inline Rules,DIRECT
  - RULE-SET,File Rules,DIRECT
  - RULE-SET,HTTP Rules,DIRECT
  - MATCH,DIRECT
'''
if args.ui:config+='external-ui: '+json.dumps(args.ui)+'\n'
(root/'config.yaml').write_text(config)
def request(method,path,body=None):
 c=http.client.HTTPConnection('127.0.0.1',port,timeout=8);headers={'Authorization':'Bearer yacd-fixture','Connection':'close'}
 if body is not None:body=json.dumps(body);headers['Content-Type']='application/json'
 c.request(method,path,body,headers);r=c.getresponse();data=r.read();status=r.status;c.close();return status,json.loads(data) if data else None
def providers():status,data=request('GET','/providers/rules');assert status==200;return data['providers']
def stamp(raw):return datetime.datetime.fromisoformat(raw.replace('Z','+00:00'))
def refresh(name):return request('PUT','/providers/rules/'+urllib.parse.quote(name))[0]
def snapshot_all():
 items=providers()
 for name,item in items.items():
  check(name+' has RFC3339 updatedAt',isinstance(item.get('updatedAt'),str) and stamp(item['updatedAt']).tzinfo is not None,item)
  status,detail=request('GET','/providers/rules/'+urllib.parse.quote(name));check(name+' list and detail dates agree',status==200 and detail['updatedAt']==item['updatedAt'])
 return items
def terminate():
 if core is not None and core.poll() is None:
  core.terminate()
  try:core.wait(12)
  except subprocess.TimeoutExpired:core.kill();core.wait()
def probe_rules():
 s=socket.create_connection(('127.0.0.1',mixed),timeout=5);s.settimeout(5);s.sendall(f'CONNECT 127.0.0.1:{server.server_port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode());head=b''
 while not head.endswith(b'\r\n\r\n'):
  b=s.recv(1)
  if not b:raise EOFError()
  head+=b
 assert b'200' in head;s.sendall(b'GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');r=http.client.HTTPResponse(s);r.begin();assert r.read()==b'ok';s.close()
try:
 log=(root/'core.log').open('w');core=subprocess.Popen([args.core,'-d',str(root),'-f',str(root/'config.yaml')],stdout=log,stderr=log)
 for _ in range(160):
  if core.poll() is not None:raise RuntimeError((root/'core.log').read_text())
  try:
   if request('GET','/version')[0]==200:break
  except OSError:pass
  time.sleep(.05)
 else:raise AssertionError('controller did not start')
 if args.serve:
  signal.signal(signal.SIGTERM,lambda *_:shutdown.set());signal.signal(signal.SIGINT,lambda *_:shutdown.set());print(json.dumps(dict(ready=True,port=port,home=str(root))),flush=True)
  while not shutdown.wait(.2):
   if core.poll() is not None:raise RuntimeError('fixture core exited')
 else:
  before=snapshot_all();cache_stat=cached.stat();first_file=file.stat()
  check('file provider exposes original mtime',stamp(before['File Rules']['updatedAt']).timestamp()==946684800)
  check('cached HTTP provider exposes original mtime',stamp(before['HTTP Rules']['updatedAt']).timestamp()==978307200)
  first=before['Inline Rules']['updatedAt'];time.sleep(.025);again=providers();check('GET keeps inline update time stable',again['Inline Rules']['updatedAt']==first)
  check('GET keeps cached HTTP mtime stable',cached.stat().st_mtime_ns==cache_stat.st_mtime_ns)
  check('GET keeps file mtime stable',file.stat().st_mtime_ns==first_file.st_mtime_ns)
  check('inline refresh succeeds',refresh('Inline Rules')==204);after=providers();check('inline refresh advances timestamp',stamp(after['Inline Rules']['updatedAt'])>stamp(first))
  file.write_text('payload:\n  - DOMAIN-SUFFIX,file.test\n  - DOMAIN,new.file.test\n');check('file refresh succeeds',refresh('File Rules')==204);after=providers();check('file refresh updates date and count',after['File Rules']['ruleCount']==2 and stamp(after['File Rules']['updatedAt']).timestamp()>946684800)
  check('HTTP refresh succeeds',refresh('HTTP Rules')==204);after=providers();updated=after['HTTP Rules']['updatedAt'];check('HTTP refresh updates date and count',after['HTTP Rules']['ruleCount']==2 and stamp(updated).timestamp()>978307200)
  cache_stat=cached.stat();payload['mode']='invalid';check('invalid remote payload is rejected',refresh('HTTP Rules')==503);after=providers();check('invalid refresh preserves previous date',after['HTTP Rules']['updatedAt']==updated);check('invalid refresh preserves previous count',after['HTTP Rules']['ruleCount']==2);check('invalid refresh preserves cache mtime',cached.stat().st_mtime_ns==cache_stat.st_mtime_ns)
  payload['mode']='offline';check('offline refresh can use cached rules',refresh('HTTP Rules')==204);after=providers();check('offline cache fallback preserves date',after['HTTP Rules']['updatedAt']==updated);check('offline cache fallback preserves mtime',cached.stat().st_mtime_ns==cache_stat.st_mtime_ns)
  payload['mode']='valid';rules=request('GET','/rules')[1]['rules'];check('cold rule timestamps parse',all(stamp(rule['extra']['hitAt']) and stamp(rule['extra']['missAt']) for rule in rules))
  probe_rules();rules=request('GET','/rules')[1]['rules'];check('rule hit and miss times remain parseable',all(stamp(rule['extra']['hitAt']) and stamp(rule['extra']['missAt']) for rule in rules));check('actual match has a real hit timestamp',rules[-1]['extra']['hitCount']>0 and rules[-1]['extra']['hitAt']!='0001-01-01T00:00:00Z');check('tested rule has a real miss timestamp',rules[0]['extra']['missCount']>0 and rules[0]['extra']['missAt']!='0001-01-01T00:00:00Z')
  check('rule disabling works',request('PATCH','/rules/disable',{'0':True})[0]==204);check('disabled flag remains visible',request('GET','/rules')[1]['rules'][0]['extra']['disabled'])
except Exception as error:
 check('fixture execution',False,repr(error));print((root/'core.log').read_text()[-3000:] if (root/'core.log').exists() else '',flush=True)
finally:
 terminate();server.shutdown();server.server_close()
 if 'log' in globals():log.close()
 result=dict(passed=all(c['passed'] for c in checks),checks=checks,home=str(root),sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
 if args.output:pathlib.Path(args.output).write_text(json.dumps(result,indent=2))
 if not args.serve:print(json.dumps(dict(passed=result['passed'],checks=len(checks),home=str(root))),flush=True)
raise SystemExit(0 if result['passed'] else 1)
