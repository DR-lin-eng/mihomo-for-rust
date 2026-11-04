#!/usr/bin/env python3
"""Sample core CPU/API from a separate process, outside the load generator GIL."""
import argparse, http.client, json, pathlib, time

p=argparse.ArgumentParser();p.add_argument('--pid',type=int,required=True)
p.add_argument('--controller',type=int,required=True);p.add_argument('--output',required=True)
p.add_argument('--stop',required=True);a=p.parse_args()
samples=[];errors=[]
while not pathlib.Path(a.stop).exists():
    try:
        rows={}
        for item in pathlib.Path('/proc/'+str(a.pid)+'/task').iterdir():
            try:
                raw=(item/'stat').read_text();tail=raw[raw.rfind(')')+2:].split()
                rows[item.name]=dict(name=(item/'comm').read_text().strip(),ticks=int(tail[11])+int(tail[12]),cpu=int(tail[36]))
            except (FileNotFoundError,ProcessLookupError):pass
        c=http.client.HTTPConnection('127.0.0.1',a.controller,timeout=3);started=time.monotonic()
        c.request('GET','/connections',headers={'Connection':'close'});r=c.getresponse();body=r.read();c.close();assert r.status==200
        samples.append(dict(at=time.monotonic(),threads=rows,api_seconds=time.monotonic()-started,connections=len(json.loads(body)['connections'])))
    except Exception as e:errors.append(repr(e))
    time.sleep(.1)
pathlib.Path(a.output).write_text(json.dumps(dict(samples=samples,errors=errors)))
