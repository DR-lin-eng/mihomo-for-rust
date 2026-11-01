//! Response classification follows Smart Alpha 77af4804. Never follow redirects
//! when classifying a node: an answer from a different host is not its evidence.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub type Headers = BTreeMap<String, String>;
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Ignore,
    Reachable,
    Record,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub ttl: u64,
    pub reason: String,
    pub control_success: bool,
    pub unproven: bool,
}
fn ignore(reason: &str) -> Verdict {
    Verdict {
        reason: reason.into(),
        ..Default::default()
    }
}
fn record(ttl: u64, reason: &str) -> Verdict {
    Verdict {
        action: Action::Record,
        ttl: ttl.clamp(60, 1800),
        reason: reason.into(),
        ..Default::default()
    }
}
fn value<'a>(headers: &'a Headers, key: &str) -> &'a str {
    headers.get(key).map(String::as_str).unwrap_or("").trim()
}
fn retry_after(raw: &str, now: u64) -> Option<u64> {
    if let Ok(seconds) = raw.trim().parse::<i64>() {
        return (seconds > 0).then_some(seconds.clamp(0, 1800) as u64);
    }
    httpdate::parse_http_date(raw)
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|time| time.as_secs())
        .filter(|epoch| *epoch > now)
        .map(|epoch| epoch - now)
}
fn rate_ttl(headers: &Headers, now: u64) -> u64 {
    retry_after(value(headers, "retry-after"), now)
        .or_else(|| {
            value(headers, "x-ratelimit-reset")
                .parse::<i64>()
                .ok()
                .filter(|epoch| *epoch > 0 && *epoch as u64 > now)
                .map(|epoch| (epoch as u64 - now).min(1800))
        })
        .unwrap_or(600)
}
pub fn regional_reason(reason: &str) -> bool {
    matches!(reason, "region unavailable" | "forbidden" | "origin error")
}
pub fn classify(status: u16, headers: &Headers, body: &[u8], now: u64) -> Verdict {
    let quota = value(headers, "x-ratelimit-remaining") == "0";
    if value(headers, "cf-mitigated").eq_ignore_ascii_case("challenge")
        || ["challenge", "captcha"].contains(
            &value(headers, "x-amzn-waf-action")
                .to_ascii_lowercase()
                .as_str(),
        )
    {
        return record(600, "challenge");
    }
    if status == 429
        || (status == 403 && (quota || retry_after(value(headers, "retry-after"), now).is_some()))
    {
        return record(rate_ttl(headers, now), "rate limited");
    }
    if status == 200 && quota {
        return record(rate_ttl(headers, now), "quota exhausted");
    }
    if region_text(body) {
        return record(1800, "region unavailable");
    }
    match status {
        403 => record(600, "forbidden"),
        451 => record(1800, "unavailable for legal reasons"),
        421 => ignore("misdirected request"),
        300..=399 => {
            if region_location(value(headers, "location")) {
                record(1800, "region unavailable")
            } else {
                ignore("redirect")
            }
        }
        405 | 501 => ignore("method not allowed"),
        500..=599 => {
            if retry_after(value(headers, "retry-after"), now).is_some() {
                record(rate_ttl(headers, now), "overloaded")
            } else if ["cf-error-details", "cf-error-overview", "cf.errors.css"]
                .iter()
                .any(|text| String::from_utf8_lossy(body).contains(text))
            {
                record(300, "edge error")
            } else {
                record(300, "origin error")
            }
        }
        200.. => Verdict {
            action: Action::Reachable,
            reason: "answered".into(),
            control_success: (200..300).contains(&status),
            ..Default::default()
        },
        _ => ignore("unknown status"),
    }
}
pub fn classify_error(error: &str, timeout: bool) -> Verdict {
    let lower = error.to_ascii_lowercase();
    if lower.contains("notvalidforname")
        || lower.contains("hostname mismatch")
        || lower.contains("not valid for name")
    {
        record(600, "certificate hostname mismatch")
    } else if lower.contains("unknownissuer")
        || lower.contains("unknown issuer")
        || lower.contains("unknown certificate authority")
    {
        record(600, "unknown certificate authority")
    } else if timeout {
        record(300, "probe timed out")
    } else {
        Verdict {
            unproven: true,
            ..ignore("probe failed")
        }
    }
}
pub fn region_location(raw: &str) -> bool {
    let raw = raw.to_lowercase();
    if [
        "app-unavailable-in-region",
        "/welcome/unavailable",
        "unavailable-in-region",
        "region-unavailable",
        "not-available-in-your-region",
        "unsupported-region",
    ]
    .iter()
    .any(|word| raw.contains(word))
    {
        return true;
    }
    [
        "region",
        "country",
        "location",
        "geo-block",
        "geoblock",
        "geo-restrict",
        "georestrict",
    ]
    .iter()
    .any(|word| raw.contains(word))
        && [
            "unavailable",
            "not-available",
            "notavailable",
            "unsupported",
            "blocked",
            "restricted",
            "denied",
        ]
        .iter()
        .any(|word| raw.contains(word))
}
pub fn region_text(body: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(body)
        .to_lowercase()
        .replace('_', " ");
    include_str!("region-phrases.txt")
        .lines()
        .filter(|phrase| !phrase.is_empty())
        .any(|phrase| raw.contains(phrase))
}
