#!/usr/bin/env python3
"""Execute embedded TC programs with real BPF_PROG_TEST_RUN on crafted packets."""
import argparse,ipaddress,json,pathlib,struct,subprocess,tempfile,shutil
p=argparse.ArgumentParser();p.add_argument('--object',required=True);p.add_argument('--output',required=True);args=p.parse_args()
work=pathlib.Path(tempfile.mkdtemp(prefix='mihomo-bpf-packets-'));pin=pathlib.Path('/sys/fs/bpf')/work.name;pin.mkdir();maps=pin/'maps';maps.mkdir();checks=[]
def command(*argv):return subprocess.check_output(argv,text=True)
def check(name,ok,detail=None):
 checks.append(dict(name=name,passed=bool(ok),detail=detail))
 if not ok:print('FAIL',name,detail)
def checksum(data):
 if len(data)%2:data+=b'\0'
 value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
 while value>>16:value=(value&65535)+(value>>16)
 return (~value)&65535
def packet(src,dst,sport=12345,dport=443,udp=False,icmp=False,vlan=False,options=False,extension=False,fragment=False,flags=2):
 source=ipaddress.ip_address(src).packed;dest=ipaddress.ip_address(dst).packed;v6=len(source)==16
 protocol=58 if icmp and v6 else 1 if icmp else 17 if udp else 6
 payload=bytes([8,0,0,0,0,0,0,0]) if icmp else struct.pack('!HHHH',sport,dport,8,0) if udp else struct.pack('!HHIIBBHHH',sport,dport,100,0,0x50,flags,65535,0,0)
 if not icmp:
  pseudo=source+dest+(struct.pack('!I3xB',len(payload),protocol) if v6 else struct.pack('!BBH',0,protocol,len(payload)))
  cs=checksum(pseudo+payload);offset=6 if udp else 16;payload=payload[:offset]+struct.pack('!H',cs)+payload[offset+2:]
 if v6:
  ext=bytes([protocol,0])+b'\0'*6 if extension else b''
  header=struct.pack('!IHBB',6<<28,len(payload)+len(ext),0 if extension else protocol,64)+source+dest+ext
 else:
  opts=b'\x01\x01\x01\x01' if options else b'';ihl=20+len(opts)
  header=struct.pack('!BBHHHBBH',0x40+ihl//4,0,ihl+len(payload),1,0x2000 if fragment else 0,64,protocol,0)+source+dest+opts
  header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
 ether=b'\x02\0\0\0\0\x01\x02\0\0\0\0\x02'+struct.pack('!H',0x8100 if vlan else 0x86dd if v6 else 0x800)
 if vlan:ether+=struct.pack('!HH',100,0x86dd if v6 else 0x800)
 return ether+header+payload
def execute(program,data):
 inp=work/'in';out=work/'out';inp.write_bytes(data)
 result=json.loads(command('bpftool','-j','prog','run','pinned',str(pin/program),'data_in',str(inp),'data_out',str(out),'repeat','1'))
 return result['retval'],out.read_bytes()
def tcp_checksums_valid(data):
 l2=18 if data[12:14]==b'\x81\x00' else 14;v6=data[l2]>>4==6
 if v6:
  protocol=data[l2+6];off=l2+40
  if protocol==0:protocol=data[off];off+=8
  pseudo=data[l2+8:l2+40]+struct.pack('!I3xB',len(data)-off,protocol)
 else:
  off=l2+(data[l2]&15)*4;protocol=data[l2+9];pseudo=data[l2+12:l2+20]+struct.pack('!BBH',0,protocol,len(data)-off)
  if checksum(data[l2:off])!=0:return False
 return checksum(pseudo+data[off:])==0
try:
 command('bpftool','prog','loadall',args.object,str(pin),'type','classifier','pinmaps',str(maps))
 config=struct.pack('=II',0x636c746d,1)+ipaddress.ip_address('192.0.2.1').packed+ipaddress.ip_address('2001:db8:1::1').packed+struct.pack('!H',17891)+b'\0\0'
 command('bpftool','map','update','pinned',str(maps/'config'),'key','hex','00','00','00','00','value','hex',*[f'{byte:02x}' for byte in config])
 cases=[('TCP IPv4 redirect',packet('192.0.2.2','203.0.113.10'),7),('UDP IPv4 redirect',packet('192.0.2.2','203.0.113.10',udp=True),7),('TCP IPv6 redirect',packet('2001:db8:1::2','2001:db8:2::10'),7),('VLAN redirect',packet('192.0.2.2','203.0.113.10',vlan=True),7),('IPv4 options redirect',packet('192.0.2.2','203.0.113.10',options=True),7),('IPv6 extension redirect',packet('2001:db8:1::2','2001:db8:2::10',extension=True),7),('private IPv4 bypass',packet('192.0.2.2','192.168.1.1'),0),('link-local IPv6 bypass',packet('2001:db8:1::2','fe80::1'),0),('private IPv6 bypass',packet('2001:db8:1::2','fd00::1'),0),('multicast IPv6 bypass',packet('2001:db8:1::2','ff02::1'),0),('ICMP bypass',packet('192.0.2.2','203.0.113.10',icmp=True),0),('IPv4 fragments bypass',packet('192.0.2.2','203.0.113.10',fragment=True),0),('ARP bypass',b'\xff'*12+b'\x08\x06'+b'\0'*28,0),('truncated IP packet bypass',b'\0'*12+b'\x08\x00'+b'\0'*10,0)]
 for name,data,expected in cases:
  result,rewritten=execute('mihomo_rs_tun',data);check(name,result==expected,result)
 for index,(data,expected_ip,l2,ip_len) in enumerate([(packet('192.0.2.2','203.0.113.10'),ipaddress.ip_address('192.0.2.1').packed,14,20),(packet('192.0.2.2','203.0.113.11',sport=12346,options=True),ipaddress.ip_address('192.0.2.1').packed,14,24),(packet('192.0.2.2','203.0.113.12',sport=12347,vlan=True),ipaddress.ip_address('192.0.2.1').packed,18,20),(packet('2001:db8:1::2','2001:db8:2::10'),ipaddress.ip_address('2001:db8:1::1').packed,14,40),(packet('2001:db8:1::2','2001:db8:2::11',sport=12346,extension=True),ipaddress.ip_address('2001:db8:1::1').packed,14,48)]):
  result,rewritten=execute('mihomo_rs_in',data);address_offset=l2+(16 if len(expected_ip)==4 else 24)
  check('auto-redir destination rewrite '+str(index),result==0 and rewritten[address_offset:address_offset+len(expected_ip)]==expected_ip and rewritten[l2+ip_len+2:l2+ip_len+4]==struct.pack('!H',17891),rewritten.hex())
  check('auto-redir IP/TCP checksum '+str(index),tcp_checksums_valid(rewritten))
 for family,source,client,original in [(4,'192.0.2.1','192.0.2.2','203.0.113.10'),(6,'2001:db8:1::1','2001:db8:1::2','2001:db8:2::10')]:
  response=packet(source,client,sport=17891,dport=12345,flags=18)
  result,rewritten=execute('mihomo_rs_out',response);offset=14+(12 if family==4 else 8);expected=ipaddress.ip_address(original).packed
  check('reply original source address restored IPv'+str(family),result==0 and rewritten[offset:offset+len(expected)]==expected and rewritten[(34 if family==4 else 54):(36 if family==4 else 56)]==struct.pack('!H',443),rewritten.hex())
  check('reply checksum IPv'+str(family),tcp_checksums_valid(rewritten))
 collision=packet('192.0.2.2','203.0.113.99')
 result,_=execute('mihomo_rs_in',collision);check('simultaneous tuple collision is rejected',result==2,result)
 result,rewritten=execute('mihomo_rs_out',packet('192.0.2.1','192.0.2.2',sport=17891,dport=12345,flags=18))
 check('tuple collision cannot corrupt established destination',rewritten[26:30]==ipaddress.ip_address('203.0.113.10').packed)
 for name,data in [('UDP',packet('192.0.2.2','203.0.113.10',udp=True)),('TCP DNS',packet('192.0.2.2','203.0.113.10',dport=53)),('private TCP',packet('192.0.2.2','10.1.1.1'))]:
  result,rewritten=execute('mihomo_rs_in',data);check('auto-redir bypass '+name,result==0 and rewritten==data)
except Exception as error:check('suite completed',False,repr(error))
finally:
 shutil.rmtree(pin,ignore_errors=True)
 pathlib.Path(args.output).write_text(json.dumps(dict(checks=checks),indent=2)+'\n');print(sum(c['passed'] for c in checks),'/',len(checks),'kernel packet checks passed')
 raise SystemExit(any(not c['passed'] for c in checks))
