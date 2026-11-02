#!/usr/bin/env python3
"""Deterministic cold fake-IP access, DNS failures and concurrent allocation."""
import argparse, contextlib, hashlib, http.client, http.server, json, os, pathlib, socket, ssl
import socketserver, struct, subprocess, tempfile, threading, time

p = argparse.ArgumentParser()
p.add_argument('--core', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix='fakeip-first-'))
checks, cases = [], []

def exact(s, n):
    result = b''
    while len(result) < n:
        data = s.recv(n-len(result))
        if not data: raise EOFError()
        result += data
    return result

def free():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def query(host, kind=1):
    return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b''.join(bytes([len(v)])+v.encode() for v in host.split('.')) + b'\0' + struct.pack('!HH',kind,1)

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, s = self.request
        end = 12; labels=[]
        while data[end]:
            size=data[end]; end+=1; labels.append(data[end:end+size].decode()); end+=size
        kind=struct.unpack('!H',data[end+1:end+3])[0]; end+=5
        host='.'.join(labels)
        self.server.hits.append((host,kind))
        if self.server.mode=='silent' or (kind==28 and self.server.mode=='drop-aaaa'): return
        if host=='inflight.test':
            self.server.started.set(); time.sleep(.4)
        if host=='slow-https.test':
            self.server.started.set(); time.sleep(.55)
        rcode=2 if self.server.mode=='servfail' else 0
        answer=b''
        if kind==1 and not rcode:
            answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('127.0.0.10')
        s.sendto(data[:2]+struct.pack('!5H',0x8180|rcode,1,int(bool(answer)),0,0)+data[12:end]+answer,self.client_address)

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data,s=self.request; s.sendto(data,self.client_address)

class HTTP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')

class DoH(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        packet=self.rfile.read(int(self.headers['Content-Length']))
        class Reply:
            def sendto(self, response, peer): self.response=response
        reply=Reply()
        handler=object.__new__(DNS);handler.request=(packet,reply);handler.server=self.server;handler.client_address=None;handler.handle()
        self.send_response(200);self.send_header('Content-Type','application/dns-message');self.send_header('Content-Length',str(len(reply.response)));self.end_headers();self.wfile.write(reply.response)
    def log_message(self,*args): pass

def start(server):
    threading.Thread(target=server.serve_forever,daemon=True).start(); return server

def check(name, ok, detail=None):
    checks.append(dict(name=name,passed=bool(ok),detail=detail))
    if not ok: print('FAIL',name,detail,flush=True)

for case,modes in [('ipv4-only',['drop-aaaa']),('slow-first',['silent','ok']),('servfail-first',['servfail','ok']),('doh-slow-first',['silent','doh']),('concurrency',['ok'])]:
    servers=[]; core=None; data=dict(case=case)
    try:
        for mode in modes:
            if mode=='doh':
                cert=root/'cert.pem';key=root/'key.pem'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
                s=http.server.ThreadingHTTPServer(('127.0.0.1',0),DoH)
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);s.socket=ctx.wrap_socket(s.socket,server_side=True)
            else: s=UDP(('127.0.0.1',0),DNS)
            s.mode=mode;s.hits=[];s.started=threading.Event();servers.append(start(s))
        dns_servers=list(servers)
        http_server=start(TCP(('127.0.0.10',0),HTTP));servers.append(http_server)
        echo=start(UDP(('127.0.0.10',0),Echo));servers.append(echo)
        mixed,dns_port,controller=free(),free(),free()
        config=f'''mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
mode: Rule
dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:{dns_port}
  enhanced-mode: fake-ip
  nameserver: {json.dumps([('https://' if s.mode=='doh' else 'udp://')+'127.0.0.1:'+str(s.server_address[1])+('/dns-query' if s.mode=='doh' else '') for s in dns_servers])}
rules: ['MATCH,DIRECT']
'''
        home=root/case;home.mkdir();(home/'config.yaml').write_text(config)
        log=(home/'core.log').open('w')
        env=os.environ.copy()
        if case=='doh-slow-first': env['SSL_CERT_FILE']=str(root/'cert.pem')
        core=subprocess.Popen([a.core,'-d',str(home),'-f',str(home/'config.yaml')],stdout=log,stderr=log,env=env)
        for _ in range(120):
            if core.poll() is not None: raise RuntimeError((home/'core.log').read_text())
            try:
                c=http.client.HTTPConnection('127.0.0.1',controller,timeout=.1);c.request('GET','/version');c.getresponse().read();c.close();break
            except OSError: time.sleep(.025)
        def dns(host,kind=1):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                s.settimeout(4);s.sendto(query(host,kind),('127.0.0.1',dns_port));return s.recv(4096)
        def fake(host):
            response=dns(host);assert response[3]&15==0 and response[6:8]==b'\0\x01';return socket.inet_ntoa(response[-4:])
        def socks(host,port,command=1):
            s=socket.create_connection(('127.0.0.1',mixed),4);s.settimeout(4)
            s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
            s.sendall(bytes([5,command,0,1])+socket.inet_aton(host)+struct.pack('!H',port))
            head=exact(s,4); addr=exact(s,4 if head[3]==1 else 16); bound_port=struct.unpack('!H',exact(s,2))[0]
            if head[1]: s.close();raise RuntimeError('SOCKS reply '+str(head[1]))
            return s,(socket.inet_ntoa(addr) if len(addr)==4 else '::1',bound_port)
        def connect(host):
            with socks(host,http_server.server_address[1])[0] as s:
                s.sendall(b'GET / HTTP/1.1\r\nHost: cold.test\r\nConnection: close\r\n\r\n');return b'200 OK' in s.recv(4096)
        if case!='concurrency':
            ip=fake('cold.test');started=time.monotonic()
            try: ok=connect(ip);error=None
            except Exception as e: ok=False;error=repr(e)
            elapsed=time.monotonic()-started
            check(case+' first fake-IP TCP succeeds',ok,dict(elapsed=elapsed,error=error))
            check(case+' first access under 350ms',ok and elapsed<.35,elapsed)
            data['elapsed']=elapsed
            if case=='ipv4-only': check('IPv6 disabled avoids AAAA upstream requests',not any(k==28 for s in dns_servers for _,k in s.hits),[s.hits for s in dns_servers])
            started=time.monotonic();response=dns('record.test',65);elapsed=time.monotonic()-started
            check(case+' HTTPS query returns healthy response',response[3]&15==0,response[3]&15)
            check(case+' HTTPS query under 350ms',elapsed<.35,elapsed)
        else:
            slow=[]
            thread=threading.Thread(target=lambda:slow.append(dns('slow-https.test',65)),daemon=True);thread.start()
            assert dns_servers[0].started.wait(2)
            started=time.monotonic();fake('unrelated.test');elapsed=time.monotonic()-started
            check('slow HTTPS record does not block local fake-IP answer',elapsed<.2,elapsed);thread.join(4)
            dns_servers[0].started.clear()
            inflight=fake('inflight.test')
            control,relay=socks('0.0.0.0',0,3)
            with control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(4)
                client.sendto(b'\0\0\0\1'+socket.inet_aton(inflight)+struct.pack('!H',echo.server_address[1])+b'inflight',relay)
                assert dns_servers[0].started.wait(2)
                late=fake('late.test');answer=client.recv(4096)
                check('inflight fake-IP UDP resolves successfully',answer.endswith(b'inflight'))
                try: ok=connect(late);error=None
                except Exception as e: ok=False;error=repr(e)
                check('new fake-IP mapping survives older UDP resolution',ok,error)
        data['dns_hits']=[s.hits for s in dns_servers]
    except Exception as error: check(case+' fixture',False,repr(error))
    finally:
        if core is not None and core.poll() is None:
            core.terminate()
            try: core.wait(5)
            except subprocess.TimeoutExpired: core.kill();core.wait()
        if 'home' in locals() and (home/'core.log').exists(): data['log']=(home/'core.log').read_text()
        if 'log' in locals(): log.close()
        for s in servers: s.shutdown();s.server_close()
        cases.append(data)
result=dict(passed=all(c['passed'] for c in checks),sha256=hashlib.sha256(pathlib.Path(a.core).read_bytes()).hexdigest(),checks=checks,cases=cases)
pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(passed=result['passed'],checks=len(checks))),flush=True)
raise SystemExit(not result['passed'])
