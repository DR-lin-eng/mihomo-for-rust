// Reference: vernesong/mihomo Alpha 77af4804d091d89b871c99b52d50915f4a600d81.
// Function bodies below are extracted verbatim, with standard net/http Header.
package main
import("bytes";"strings";"strconv";"time";"net/http";"encoding/json";"os")
type VerdictAction uint8
const(VerdictIgnore VerdictAction=iota;VerdictReachable;VerdictRecord)
type Verdict struct{Action VerdictAction;TTL time.Duration;Reason string;ControlSuccess bool;Unproven bool}
const(probeMaxBlockTTL=30*time.Minute;ReasonRegionUnavailable="region unavailable";ReasonForbidden="forbidden";ReasonOriginError="origin error";ReasonEdgeError="edge error")
var(probeDefaultBlockTTL=10*time.Minute;probeTransientBlockTTL=5*time.Minute;probeRegionalBlockTTL=30*time.Minute;probeMinBlockTTL=60*time.Second)
func ClassifyResponse(status int, header http.Header, body []byte, now time.Time) Verdict {
	switch {
	case isChallenge(header):
		return record(probeDefaultBlockTTL, "challenge")
	case status == http.StatusTooManyRequests:
		return record(rateLimitTTL(header, now), "rate limited")
	case status == http.StatusForbidden && isRateLimited(header, now):
		return record(rateLimitTTL(header, now), "rate limited")
	case status == http.StatusOK && strings.TrimSpace(header.Get("X-Ratelimit-Remaining")) == "0":
		return record(rateLimitTTL(header, now), "quota exhausted")
	case IsRegionUnavailableText(body):
		return record(probeRegionalBlockTTL, ReasonRegionUnavailable)
	case status == http.StatusForbidden:
		return record(probeDefaultBlockTTL, ReasonForbidden)
	case status == http.StatusUnavailableForLegalReasons:
		return record(probeRegionalBlockTTL, "unavailable for legal reasons")
	case status == http.StatusMisdirectedRequest:
		return ignore("misdirected request")
	case status >= 300 && status < 400:
		if IsRegionUnavailableLocation(header.Get("Location")) {
			return record(probeRegionalBlockTTL, ReasonRegionUnavailable)
		}
		return ignore("redirect")
	case status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		return ignore("method not allowed")
	case status >= 500:
		if _, ok := parseRetryAfter(header.Get("Retry-After"), now); ok {
			return record(rateLimitTTL(header, now), "overloaded")
		}
		if isEdgeAnswer(body) {
			return record(probeTransientBlockTTL, ReasonEdgeError)
		}
		return record(probeTransientBlockTTL, ReasonOriginError)
	case status >= 200:
		return reachable("answered", status >= 200 && status < 300)
	default:
		return ignore("unknown status")
	}
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0, false
		}
		if seconds > int64(probeMaxBlockTTL/time.Second) {
			return probeMaxBlockTTL, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil && t.After(now) {
		return t.Sub(now), true
	}
	return 0, false
}

func rateLimitTTL(header http.Header, now time.Time) time.Duration {
	if d, ok := parseRetryAfter(header.Get("Retry-After"), now); ok {
		return d
	}
	if epoch, err := strconv.ParseInt(strings.TrimSpace(header.Get("X-Ratelimit-Reset")), 10, 64); err == nil && epoch > now.Unix() {
		seconds := epoch - now.Unix()
		if seconds > int64(probeMaxBlockTTL/time.Second) {
			return probeMaxBlockTTL
		}
		return time.Duration(seconds) * time.Second
	}
	return probeDefaultBlockTTL
}

func isEdgeAnswer(body []byte) bool {
	return bytes.Contains(body, []byte("cf-error-details")) ||
		bytes.Contains(body, []byte("cf-error-overview")) ||
		bytes.Contains(body, []byte("cf.errors.css"))
}

func isChallenge(header http.Header) bool {
	if strings.EqualFold(strings.TrimSpace(header.Get("Cf-Mitigated")), "challenge") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(header.Get("X-Amzn-Waf-Action"))) {
	case "challenge", "captcha":
		return true
	}
	return false
}

func isRateLimited(header http.Header, now time.Time) bool {
	if strings.TrimSpace(header.Get("X-Ratelimit-Remaining")) == "0" {
		return true
	}
	_, ok := parseRetryAfter(header.Get("Retry-After"), now)
	return ok
}

func ignore(reason string) Verdict {
	return Verdict{Action: VerdictIgnore, Reason: reason}
}

func reachable(reason string, controlSuccess bool) Verdict {
	return Verdict{Action: VerdictReachable, Reason: reason, ControlSuccess: controlSuccess}
}

func record(ttl time.Duration, reason string) Verdict {
	if ttl < probeMinBlockTTL {
		ttl = probeMinBlockTTL
	}
	if ttl > probeMaxBlockTTL {
		ttl = probeMaxBlockTTL
	}
	return Verdict{Action: VerdictRecord, TTL: ttl, Reason: reason}
}
func IsRegionUnavailableLocation(location string) bool {
	if location == "" {
		return false
	}
	location = strings.ToLower(location)
	for _, pattern := range []string{
		"app-unavailable-in-region",
		"/welcome/unavailable",
		"unavailable-in-region",
		"region-unavailable",
		"not-available-in-your-region",
		"unsupported-region",
	} {
		if strings.Contains(location, pattern) {
			return true
		}
	}
	region := false
	for _, word := range []string{"region", "country", "location", "geo-block", "geoblock", "geo-restrict", "georestrict"} {
		if strings.Contains(location, word) {
			region = true
			break
		}
	}
	if !region {
		return false
	}
	for _, word := range []string{"unavailable", "not-available", "notavailable", "unsupported", "blocked", "restricted", "denied"} {
		if strings.Contains(location, word) {
			return true
		}
	}
	return false
}

func IsRegionUnavailableText(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	text := strings.ReplaceAll(strings.ToLower(string(body)), "_", " ")
	for _, phrase := range []string{
		"not available in your region",
		"not available in your country",
		"not available in your area",
		"not available in your location",
		"not available in your territory",
		"unavailable in your region",
		"unavailable in your country",
		"not available in this region",
		"not available in this country",
		"not available in the region",
		"unsupported country",
		"unsupported region",
		"region is not supported",
		"country is not supported",
		"not supported in your country",
		"not supported in your region",
		"blocked in your region",
		"blocked in your country",
		"geo-blocked",
		"geoblocked",
		"geo-restricted",
		"georestricted",
		"地区不可用",
		"所在地区不可用",
		"不支持您所在的",
		"您所在的地区",
		"お住まいの地域",
		"お住まいの国",
		"地域ではご利用",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

type Case struct{Status int;Headers map[string]string;Body string;Now int64}
func main(){data,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)};var cases []Case;if err=json.Unmarshal(data,&cases);err!=nil{panic(err)};results:=make([]map[string]any,0,len(cases));for _,c:=range cases{h:=make(http.Header);for k,v:=range c.Headers{h.Set(k,v)};v:=ClassifyResponse(c.Status,h,[]byte(c.Body),time.Unix(c.Now,0));action:=[]string{"ignore","reachable","record"}[v.Action];results=append(results,map[string]any{"action":action,"ttl":int64(v.TTL/time.Second),"reason":v.Reason,"control_success":v.ControlSuccess,"unproven":v.Unproven})};if err=json.NewEncoder(os.Stdout).Encode(results);err!=nil{panic(err)}}
