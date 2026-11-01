#!/usr/bin/env python3
"""Extract unmodified classification functions from frozen Go source and fixtures."""
import argparse,hashlib,itertools,json,pathlib,re
p=argparse.ArgumentParser();p.add_argument('--reference',required=True);p.add_argument('--output',required=True);a=p.parse_args()
root=pathlib.Path(a.reference);output=pathlib.Path(a.output);output.mkdir(parents=True,exist_ok=True)
response=(root/'component/smart/response.go').read_text();exit=(root/'component/smart/exit.go').read_text()
def function(source,name):
    start=re.search(r'^func '+re.escape(name)+r'\(',source,re.M).start()
    end=re.search(r'^}',source[start:],re.M).end()+start
    return source[start:end]
names=['ClassifyResponse','parseRetryAfter','rateLimitTTL','isEdgeAnswer','isChallenge','isRateLimited','ignore','reachable','record']
code='''// Reference: vernesong/mihomo Alpha 77af4804d091d89b871c99b52d50915f4a600d81.
// Function bodies below are extracted verbatim, with standard net/http Header.
package main
import("bytes";"strings";"strconv";"time";"net/http";"encoding/json";"os")
type VerdictAction uint8
const(VerdictIgnore VerdictAction=iota;VerdictReachable;VerdictRecord)
type Verdict struct{Action VerdictAction;TTL time.Duration;Reason string;ControlSuccess bool;Unproven bool}
const(probeMaxBlockTTL=30*time.Minute;ReasonRegionUnavailable="region unavailable";ReasonForbidden="forbidden";ReasonOriginError="origin error";ReasonEdgeError="edge error")
var(probeDefaultBlockTTL=10*time.Minute;probeTransientBlockTTL=5*time.Minute;probeRegionalBlockTTL=30*time.Minute;probeMinBlockTTL=60*time.Second)
'''
code+='\n\n'.join(function(response,name) for name in names)+'\n'
code+='\n\n'.join(function(exit,name) for name in ['IsRegionUnavailableLocation','IsRegionUnavailableText'])+'\n'
code+='''
type Case struct{Status int;Headers map[string]string;Body string;Now int64}
func main(){data,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)};var cases []Case;if err=json.Unmarshal(data,&cases);err!=nil{panic(err)};results:=make([]map[string]any,0,len(cases));for _,c:=range cases{h:=make(http.Header);for k,v:=range c.Headers{h.Set(k,v)};v:=ClassifyResponse(c.Status,h,[]byte(c.Body),time.Unix(c.Now,0));action:=[]string{"ignore","reachable","record"}[v.Action];results=append(results,map[string]any{"action":action,"ttl":int64(v.TTL/time.Second),"reason":v.Reason,"control_success":v.ControlSuccess,"unproven":v.Unproven})};if err=json.NewEncoder(os.Stdout).Encode(results);err!=nil{panic(err)}}
'''
(output/'reference.go').write_text(code)
now=1800000000
statuses=[100,199,200,204,299,301,302,307,399,400,401,403,404,405,421,429,451,500,501,502,503,599]
headers=[{}, {'cf-mitigated':'challenge'},{'x-amzn-waf-action':' CAPTCHA '},{'x-ratelimit-remaining':'0'},{'retry-after':'123'},{'retry-after':'1'},{'retry-after':'0'},{'retry-after':'-20'},{'retry-after':'9999'},{'retry-after':'18446744073709551615'},{'x-ratelimit-reset':str(now+180)},{'retry-after':'Fri, 15 Jan 2027 08:05:00 GMT'},{'location':'https://login.test/'},{'location':'/welcome/unavailable'},{'location':'/geo-restrict/denied'}]
bodies=['', 'hello world', 'This service is not available in your country','cf-error-details','cf-error-overview','cf.errors.css']
cases=[dict(status=s,headers=h,body=b,now=now) for s,h,b in itertools.product(statuses,headers,bodies)]
(output/'fixtures.json').write_text(json.dumps(cases))
(output/'reference-source.json').write_text(json.dumps(dict(commit='77af4804d091d89b871c99b52d50915f4a600d81',functions=names+['IsRegionUnavailableLocation','IsRegionUnavailableText'],files={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['component/smart/response.go','component/smart/exit.go']},cases=len(cases)),indent=2))
print(json.dumps(dict(cases=len(cases),output=str(output))))
