#!/usr/bin/env python3
"""Smart runtime smoke: real proxy traffic, model, API, sampling and persistence."""
import argparse,base64,csv,http.client,http.server,json,pathlib,select,socket,socketserver,struct,subprocess,tempfile,threading,time,urllib.parse
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--model',required=True);p.add_argument('--output',required=True);args=p.parse_args()
work=pathlib.Path(tempfile.mkdtemp(prefix='mihomo-smart-smoke-'));(work/'Model.bin').write_bytes(pathlib.Path(args.model).read_bytes())
checks=[];proxy_hits=[];fixture_model=(work/'Model.bin').read_bytes()
def check(name,passed,detail=None):
 checks.append(dict(name=name,passed=bool(passed),detail=detail))
 if not passed:print('FAIL',name,detail,flush=True)
def free_port():
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class Target(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path=='/model':data=fixture_model
  elif self.path=='/bad-model':data=b'invalid model'
  elif self.path=='/redirect':self.send_response(302);self.send_header('Location','/model');self.end_headers();return
  else:data=b'smart target response'*400
  self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
class Proxy(socketserver.BaseRequestHandler):
 def handle(self):
  header=b'';self.request.settimeout(10)
  try:
   while b'\r\n\r\n' not in header:header+=self.request.recv(1)
   method,target,_=header.split(b'\r\n',1)[0].decode().split(' ');proxy_hits.append((self.server.label,target))
   if method!='CONNECT':return
   host,port=target.rsplit(':',1)
   upstream=socket.create_connection(('127.0.0.1',int(port)),timeout=5)
   if self.server.delay:time.sleep(self.server.delay)
   self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
   with upstream:
    while True:
     ready,_,_=select.select([upstream,self.request],[],[],4)
     if not ready:return
     for source in ready:
      data=source.recv(65535)
      if not data:return
      (self.request if source is upstream else upstream).sendall(data)
  except OSError:pass
servers=[]
def start(server):servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start();return server.server_address[1]
target_port=start(http.server.ThreadingHTTPServer(('127.0.0.1',0),Target))
class UdpEcho(socketserver.BaseRequestHandler):
 def handle(self):
  packet,sock=self.request;sock.sendto(b'udp:'+packet,self.client_address)
udp_echo=start(socketserver.ThreadingUDPServer(('127.0.0.1',0),UdpEcho));udp_listener=free_port()

a=Server(('127.0.0.1',0),Proxy);a.label='fast';a.delay=0;fast_port=start(a)
b=Server(('127.0.0.1',0),Proxy);b.label='slow';b.delay=.08;slow_port=start(b)
dead_port=free_port();controller_port=free_port();mixed_port=free_port()
config=f'''external-controller: 127.0.0.1:{controller_port}
secret: smart-fixture
mixed-port: {mixed_port}
mode: rule
log-level: debug
lgbm-url: http://127.0.0.1:{target_port}/redirect
profile:
  smart-collector-size: 0.05
proxies:
  - {{name: dead, type: http, server: 127.0.0.1, port: {dead_port}}}
  - {{name: fast, type: http, server: 127.0.0.1, port: {fast_port}}}
  - {{name: slow, type: http, server: 127.0.0.1, port: {slow_port}}}
proxy-groups:
  - name: 智能选择
    type: smart
    proxies: [dead, fast, slow]
    uselightgbm: true
    collectdata: true
    sample-rate: 1.0
    policy-priority: 'dead:3;fast:2;slow:1'
    prefer-asn: true
    tolerance: 20
    url: http://127.0.0.1:{target_port}/health
    lazy: true
    interval: 300
  - name: UDP智能
    type: smart
    proxies: [DIRECT]
    uselightgbm: true
    collectdata: true
listeners:
  - name: smart-udp
    type: tunnel
    listen: 127.0.0.1
    port: "{udp_listener}"
    network: [udp]
    proxy: UDP智能
    target: 127.0.0.1:{udp_echo}
rules:
  - MATCH,智能选择
''';(work/'config.yaml').write_text(config)
log=open(work/'core.log','w');process=None

def request(method,target,body=None,auth=True):
 conn=http.client.HTTPConnection('127.0.0.1',controller_port,timeout=20);headers={}
 if auth:headers['Authorization']='Bearer smart-fixture'
 if body is not None:body=json.dumps(body).encode();headers['Content-Type']='application/json'
 conn.request(method,target,body,headers);res=conn.getresponse();data=res.read();status=res.status;conn.close();return status,data
def api(target):return json.loads(request('GET',target)[1])
group='/proxies/'+urllib.parse.quote('智能选择');weights='/group/'+urllib.parse.quote('智能选择')+'/weights'
def launch():
 global process
 process=subprocess.Popen([args.core,'-d',str(work),'-f',str(work/'config.yaml')],stdout=log,stderr=log)
 for _ in range(200):
  if process.poll() is not None:raise RuntimeError((work/'core.log').read_text())
  try:
   if request('GET','/version')[0]==200:return
  except OSError:pass
  time.sleep(.05)
 raise RuntimeError('controller did not start')
def stop():
 process.terminate()
 try:process.wait(timeout=20)
 except subprocess.TimeoutExpired:process.kill();process.wait()
def traffic(host='one.fixture.test'):
 with socket.create_connection(('127.0.0.1',mixed_port),timeout=10) as stream:
  stream.sendall(f'CONNECT {host}:{target_port} HTTP/1.1\r\nHost: {host}:{target_port}\r\n\r\n'.encode());head=b''
  while b'\r\n\r\n' not in head:head+=stream.recv(1)
  if b'200' not in head:raise RuntimeError(head)
  stream.sendall(f'GET /data HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode());response=b''
  while True:
   chunk=stream.recv(65535)
   if not chunk:break
   response+=chunk
  if b'smart target response' not in response:raise RuntimeError('missing target response')
 time.sleep(.12)
def records():
 files=list((work/'storage').glob('smart-*.json'));return json.loads(files[0].read_text()) if files else None
try:
 launch()
 version=subprocess.check_output([args.core,'-v'],text=True);check('OpenClash identifies smart core','smart' in version,version.strip())
 current=api(group);check('API exposes Smart type',current['type']=='Smart',current)
 check('Smart options serialized',current.get('useLightGBM') is True and current.get('collectData') is True and current.get('sampleRate')==1 and current.get('preferASN') is True,current)
 check('auto selection marker',current['now']=='Smart - Select' and current.get('fixed')=='',current)
 check('ranking requires auth',request('GET',weights,auth=False)[0]==401)
 check('cold ranking empty',api(weights)['weights']==[])
 # First choice is dead by priority. A single actual request must recover to another node.
 traffic();check('dead proxy fails over during one connection',any(name=='fast' for name,target in proxy_hits),proxy_hits)
 for _ in range(3):traffic()
 ranking=api(weights)['weights'];check('learned weights exposed',bool(ranking) and all(set(['Name','Rank','Weight']).issubset(item) for item in ranking),ranking)
 check('all groups weight API', '智能选择' in api('/group/weights')['weights'])
 check('manual pin accepted',request('PUT',group,{'name':'slow'})[0]==204)
 before=len(proxy_hits);traffic('two.fixture.test');check('manual pin routes to requested node',any(name=='slow' for name,target in proxy_hits[before:]),proxy_hits[before:])
 check('manual pin reflected',api(group)['fixed']=='slow')
 check('clear pin accepted',request('DELETE',group)[0]==204)
 check('clear pin returns auto marker',api(group)['now']=='Smart - Select')
 csv_path=work/'smart_weight_data.csv';rows=list(csv.DictReader(csv_path.open()))
 check('local collector contains traffic samples',len(rows)>=4 and all('weight_source' in row for row in rows),len(rows))
 check('real model used for trained observations',any(row['weight_source']=='lightgbm' for row in rows),[row['weight_source'] for row in rows])
 check('collector size bound',csv_path.stat().st_size<=.05*1024*1024,csv_path.stat().st_size)
 check('model file loaded in actual core','Model file loaded successfully' in (work/'core.log').read_text())
 for index in range(2):
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
   sock.settimeout(5);payload=('packet'+str(index)).encode();sock.sendto(payload,('127.0.0.1',udp_listener));reply=sock.recv(2048)
   check('Smart UDP actual forwarding '+str(index),reply==b'udp:'+payload,reply.decode())
 check('reload through OpenClash API',request('PUT','/configs?force=true',{'path':str(work/'config.yaml')})[0]==204)
 udp_weights='/group/'+urllib.parse.quote('UDP智能')+'/weights'
 check('UDP feedback survives reload',bool(api(udp_weights)['weights']),api(udp_weights))
 check('statistics survive reload',bool(api(weights)['weights']))
 before_model=(work/'Model.bin').read_bytes();check('model upgrade follows redirect',request('POST','/upgrade/lgbm')[0]==204)
 check('downloaded model matches published bytes',(work/'Model.bin').read_bytes()==before_model)
 bad=config.replace('/redirect','/bad-model')
 check('reload bad-model URL setting',request('PUT','/configs',{'payload':bad})[0]==204)
 check('invalid model update returns error',request('POST','/upgrade/lgbm')[0]==500)
 check('invalid model update preserves existing model',(work/'Model.bin').read_bytes()==before_model)
 stop();data=records();check('graceful shutdown persists statistics',data and data['groups']['智能选择']['observations']>=5,data['groups']['智能选择']['observations'] if data else None)
 launch();check('statistics survive process restart',bool(api(weights)['weights']))
 check('scoped flush other config succeeds',request('POST','/cache/smart/flush/other')[0]==204)
 check('other config flush preserves active data',bool(api(weights)['weights']))
 check('scoped active config flush',request('POST','/cache/smart/flush/config')[0]==204)
 check('flush clears weights',api(weights)['weights']==[])
 traffic();traffic();check('fresh observations after flush',bool(api(weights)['weights']))
 check('global flush succeeds',request('POST','/cache/smart/flush')[0]==204)
 check('global flush empties weights',api(weights)['weights']==[])
 stop();(work/'Model.bin').write_bytes(b'corrupt model')
 # Disable learning to prove collectdata=false creates no additional rows.
 no_collect=config.replace('collectdata: true','collectdata: false').replace('/redirect','/bad-model')
 (work/'config.yaml').write_text(no_collect);size=csv_path.stat().st_size;launch();traffic();traffic()
 check('invalid model keeps adaptive routing usable',request('GET','/version')[0]==200)
 check('disabled collector does not append samples',csv_path.stat().st_size==size,(size,csv_path.stat().st_size))
except Exception as error:check('suite completed',False,repr(error))
finally:
 if process and process.poll() is None:stop()
 log.close();record=dict(checks=checks,core=args.core,model_sha256=__import__('hashlib').sha256(fixture_model).hexdigest(),proxy_connections=proxy_hits,log=(work/'core.log').read_text(),workspace=str(work))
 pathlib.Path(args.output).write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n');print(sum(c['passed'] for c in checks),'/',len(checks),'Smart checks passed',flush=True)
 for server in servers:server.shutdown()
 raise SystemExit(any(not c['passed'] for c in checks))
