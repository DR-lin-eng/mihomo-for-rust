#!/usr/bin/env python3
"""Run DIRECT TC programs in the kernel against controlled packet/state pairs."""
import argparse,ctypes,ipaddress,json,pathlib,struct,subprocess,tempfile,time,shutil
p=argparse.ArgumentParser();p.add_argument('--object',required=True);p.add_argument('--output',required=True);a=p.parse_args()
root=pathlib.Path(tempfile.mkdtemp(prefix='kd-packets-'));pin=pathlib.Path('/sys/fs/bpf')/root.name;checks=[]
def cmd(*args):return subprocess.check_output(args,text=True)
def check(name,ok,detail=None):
 checks.append(dict(name=name,passed=bool(ok),detail=detail))
 if not ok:print('FAIL',name,detail,flush=True)
def checksum(data):
 data+=b'\0'*(len(data)%2);s=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
 while s>>16:s=(s&65535)+(s>>16)
 return ~s&65535
def address(s):return ipaddress.ip_address(s).packed
def key(src,dst,sp=32000,dp=443,udp=False):
 x,y=address(src),address(dst);return x.ljust(16,b'\0')+y.ljust(16,b'\0')+struct.pack('!HH',sp,dp)+struct.pack('=II',4 if len(x)==4 else 6,17 if udp else 6)
def packet(src,dst,sp=32000,dp=443,udp=False,seq=100,ack=0,flags=2,data=b'',icmp=False):
 x,y=address(src),address(dst);v6=len(x)==16;proto=58 if icmp and v6 else 1 if icmp else 17 if udp else 6
 l4=data if icmp else struct.pack('!HHHH',sp,dp,8+len(data),0)+data if udp else struct.pack('!HHIIBBHHH',sp,dp,seq,ack,0x50,flags,65535,0,0)+data
 if icmp and not v6:cs=checksum(l4);l4=l4[:2]+struct.pack('!H',cs)+l4[4:]
 else:
  pseudo=x+y+(struct.pack('!I3xB',len(l4),proto) if v6 else struct.pack('!BBH',0,proto,len(l4)))
  offset=2 if icmp else 6 if udp else 16;l4=l4[:offset]+struct.pack('!H',checksum(pseudo+l4))+l4[offset+2:]
 if v6:ip=struct.pack('!IHBB',6<<28,len(l4),proto,64)+x+y
 else:
  ip=struct.pack('!BBHHHBBH',0x45,0,20+len(l4),234,0,64,proto,0)+x+y;ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('020000000001020000000002')+struct.pack('!H',0x86dd if v6 else 0x800)+ip+l4
def valid(data):
 ip=data[14:];v6=ip[0]>>4==6;off=40 if v6 else (ip[0]&15)*4;proto=ip[6] if v6 else ip[9];l4=ip[off:]
 if not v6 and checksum(ip[:off])!=0:return False
 if proto==1:return checksum(l4)==0
 pseudo=ip[8:40]+struct.pack('!I3xB',len(l4),proto) if v6 else ip[12:20]+struct.pack('!BBH',0,proto,len(l4))
 return checksum(pseudo+l4)==0
def update(name,k,v):cmd('bpftool','map','update','pinned',str(pin/'maps'/name),'key','hex',*[f'{x:02x}' for x in k],'value','hex',*[f'{x:02x}' for x in v])
def lookup(name,k):
 d=json.loads(cmd('bpftool','-j','map','lookup','pinned',str(pin/'maps'/name),'key','hex',*[f'{x:02x}' for x in k]));v=d['value'];return bytes(int(x,16) if isinstance(x,str) else x for x in v)
def execute(name,data):
 (root/'in').write_bytes(data);r=json.loads(cmd('bpftool','-j','prog','run','pinned',str(pin/name),'data_in',str(root/'in'),'data_out',str(root/'out'),'repeat','1'));return r['retval'],(root/'out').read_bytes()
next_id=10
def flow(src,fake,real,udp=False,sp=32000,dp=443):
 global next_id
 next_id+=1;k=key(src,fake,sp,dp,udp);real_key=key(src,real,sp,dp,udp)
 value=struct.pack('=IIQ',0,0,next_id)+address(real).ljust(16,b'\0')+struct.pack('!H',dp)+struct.pack('=HIQQQQIIIIII',0,0,120_000_000_000,time.monotonic_ns(),0,0,0,0,0,0,0,0)
 assert len(value)==96
 update('direct_flows',k,value);update('direct_actions',k,struct.pack('=QII',next_id,1,0));update('direct_replies',real_key,k)
 return k
try:
 pin.mkdir();(pin/'maps').mkdir();cmd('bpftool','prog','loadall',a.object,str(pin),'type','classifier','pinmaps',str(pin/'maps'))
 update('direct_config',b'\0'*4,struct.pack('=4I',0x636c746d,1,1,0))
 for src,fake,real in [('192.0.2.2','198.18.0.4','203.0.113.30'),('2001:db8:1::2','fdfe:dcba::4','2001:db8:3::30')]:
  v6=':' in src
  for udp in (False,True):
   k=flow(src,fake,real,udp);name=('IPv6' if v6 else 'IPv4')+(' UDP' if udp else ' TCP')
   outgoing=packet(src,fake,udp=udp,seq=101,flags=16,data=b'hello')
   code,converted=execute('mihomo_kd_tun',outgoing[14:])
   eth=outgoing[:14]+converted
   check(name+' forward rewrite',code==0 and (address(real) in converted),dict(code=code))
   check(name+' forward checksum',valid(eth))
   reply=packet(real,src,sp=443,dp=32000,udp=udp,seq=201,ack=106,flags=16,data=b'world')
   code,converted=execute('mihomo_kd_out',reply)
   check(name+' reverse fake source',code==0 and address(fake) in converted)
   check(name+' reverse checksum',valid(converted))
   if udp:
    value=lookup('direct_flows',k);check(name+' payload counters',struct.unpack_from('=QQ',value,56)==(5,5))
   else:
    # Establish initial sequence state; ACKs only count distinct delivered
    # payload, independent of duplicate data and retransmitted ACK packets.
    k=flow(src,fake,real)
    execute('mihomo_kd_tun',packet(src,fake,seq=100,flags=2)[14:]);execute('mihomo_kd_out',packet(real,src,sp=443,dp=32000,seq=200,ack=101,flags=18))
    data=packet(src,fake,seq=101,ack=201,flags=16,data=b'payload')
    execute('mihomo_kd_tun',data[14:]);execute('mihomo_kd_tun',data[14:])
    ack=packet(real,src,sp=443,dp=32000,seq=201,ack=108,flags=16)
    execute('mihomo_kd_out',ack);execute('mihomo_kd_out',ack)
    value=lookup('direct_flows',k);check(name+' retransmissions counted once',struct.unpack_from('=Q',value,56)[0]==7)
    execute('mihomo_kd_out',packet(real,src,sp=443,dp=32000,seq=201,ack=100000,flags=16));value=lookup('direct_flows',k)
    check(name+' impossible ACK cannot inflate counters',struct.unpack_from('=Q',value,56)[0]==7)
   # Closing a flow must fail closed for the data packet in both directions.
   id=struct.unpack_from('=Q',lookup('direct_flows',k),8)[0];update('direct_actions',k,struct.pack('=QII',id,0,0))
   code,_=execute('mihomo_kd_tun',packet(src,fake,udp=udp,seq=110,flags=16,data=b'closed')[14:]);check(name+' controller close drops outgoing',code==2)
   code,_=execute('mihomo_kd_out',reply);check(name+' controller close drops reply',code==2)
  # ICMP errors quote a packet whose target has been rewritten to a real IP.
  k=flow(src,fake,real,True,sp=32001)
  quoted=packet(src,real,sp=32001,udp=True,data=b'icmp-data')[14:]
  outer=packet(real,src,icmp=True,data=(b'\x01\x04' if v6 else b'\x03\x03')+b'\0'*6+quoted)
  code,converted=execute('mihomo_kd_out',outer)
  check(('IPv6' if v6 else 'IPv4')+' ICMP quoted fake destination restored',code==0 and address(fake) in converted)
  check(('IPv6' if v6 else 'IPv4')+' ICMP checksum preserved',valid(converted))
 # No action entry must never authorize forwarding an arbitrary fake address.
 code,_=execute('mihomo_kd_in',packet('192.0.2.99','203.0.113.99'));check('unclassified LAN TCP is sent to TUN',code==7)
except Exception as e:check('packet fixture',False,repr(e))
finally:
 shutil.rmtree(pin,ignore_errors=True)
 result=dict(passed=all(c['passed'] for c in checks),checks=checks,object_sha256=__import__('hashlib').sha256(pathlib.Path(a.object).read_bytes()).hexdigest())
 pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(passed=result['passed'],checks=len(checks))))
raise SystemExit(not result['passed'])
