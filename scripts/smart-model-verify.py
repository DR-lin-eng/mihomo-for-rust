#!/usr/bin/env python3
"""Compare the Rust Smart model reader against LightGBM's native predictor."""
import argparse,hashlib,json,math,pathlib,random,subprocess
import lightgbm as lgb
import numpy as np

parser=argparse.ArgumentParser()
parser.add_argument('--model',required=True)
parser.add_argument('--rust',required=True)
parser.add_argument('--output',required=True)
args=parser.parse_args()
model_path=pathlib.Path(args.model);text=model_path.read_text()
now=1793472000
rng=random.Random(0x534d415254)
inputs=[]
base=dict(success=2,failure=0,connect_time=20,latency=80,upload_mb=.02,history_upload_mb=2,max_upload_kb=32,history_max_upload_kb=100,
 download_mb=.1,history_download_mb=10,max_download_kb=300,history_max_download_kb=1024,duration_minutes=.01,history_duration_minutes=.1,last_used=now-60,
 is_udp=False,loss_rate=0,cumul_loss_rate=0,asn='AS15169 Google',host='www.google.com',ip='8.8.8.8',port=443,geoip=['US'],exit_region='',exit_asn='')
for index in range(160):
 item=base.copy()
 for key in ['upload_mb','history_upload_mb','max_upload_kb','history_max_upload_kb','download_mb','history_download_mb','max_download_kb','history_max_download_kb','duration_minutes','history_duration_minutes']:
  item[key]=rng.random()*100 if index%3 else 0
 item.update(success=rng.randrange(2,2000),failure=rng.randrange(0,100),connect_time=rng.randrange(0,5000),latency=rng.randrange(0,10000),last_used=now-rng.randrange(0,604800),is_udp=bool(index%2),loss_rate=rng.random()*.1,cumul_loss_rate=rng.random()*.03)
 item['host']=['dns.google','api.cloudflare.com','netflix.com','steamcommunity.com','meet.google.com','www.example.org','8.8.8.8','news.test',''][index%9]
 item['asn']=['AS15169 Google','AS13335 Cloudflare','AS123456 Unknown','AS250000',''][index%5]
 item['geoip']=[['US'],['JP'],['CN'],['ZZ'],[]][index%5]
 item['port']=[53,853,443,80,8080,27017,22,5432,45678,0][index%10]
 item['ip']=['8.8.8.8','127.0.0.1','192.168.1.1','2001:db8::1','2606:4700::1111'][index%5]
 inputs.append(item)
fixture=pathlib.Path(args.output).with_suffix('.inputs.json');fixture.write_text(json.dumps(dict(now=now,inputs=inputs)))
result=json.loads(subprocess.check_output([args.rust,args.model,str(fixture)],text=True))
raw=np.asarray([item['features'] for item in result['results']],dtype=float)[:,:len(result['features'])]
scaled=raw.copy()
trailer=text.split('[transforms]',1)[1].split('[/transforms]',1)[0] if '[transforms]' in text else ''
definitions={};section=''
for line in trailer.splitlines():
 line=line.strip()
 if line.startswith('['):section=line.strip('[]');continue
 if section=='definitions' and '=' in line:
  key,value=line.split('=',1);name,param=key.split('_',1);definitions.setdefault(name,{})[param]=value
for transform in definitions.values():
 slots=[int(v) for v in transform['features'].split(',')]
 center=np.array([float(v) for v in transform['mean' if transform['type']=='StandardScaler' else 'center'].split(',')])
 scale=np.array([float(v) for v in transform['scale'].split(',')])
 scaled[:,slots]=(scaled[:,slots]-center)/scale
booster=lgb.Booster(model_file=args.model)
expected=booster.predict(scaled,num_threads=1)
actual=np.asarray([item['prediction'] for item in result['results']])
error=float(np.max(np.abs(expected-actual)))
np.testing.assert_allclose(actual,expected,rtol=1e-10,atol=1e-10)
record=dict(model_sha256=hashlib.sha256(model_path.read_bytes()).hexdigest(),model_bytes=model_path.stat().st_size,trees=result['trees'],feature_count=len(result['features']),cases=len(inputs),max_absolute_error=error,reference='LightGBM '+lgb.__version__,passed=True)
pathlib.Path(args.output).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
