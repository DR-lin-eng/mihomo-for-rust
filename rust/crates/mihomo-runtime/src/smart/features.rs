//! Feature encoding from vernesong/mihomo Alpha 77af4804, kept in training order.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::OnceLock;

pub const FEATURE_NAMES: [&str; 32] = [
    "success",
    "failure",
    "connect_time",
    "latency",
    "upload_mb",
    "history_upload_mb",
    "maxuploadrate_kb",
    "history_maxuploadrate_kb",
    "download_mb",
    "history_download_mb",
    "maxdownloadrate_kb",
    "history_maxdownloadrate_kb",
    "duration_minutes",
    "history_duration_minutes",
    "last_used_seconds",
    "is_udp",
    "is_tcp",
    "loss_rate",
    "cumul_loss_rate",
    "asn_feature",
    "country_feature",
    "address_feature",
    "port_feature",
    "traffic_ratio",
    "traffic_density",
    "connection_type_feature",
    "asn_hash",
    "host_hash",
    "ip_hash",
    "geoip_hash",
    "exit_region",
    "exit_asn_hash",
];

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelInput {
    pub success: u64,
    pub failure: u64,
    pub connect_time: f64,
    pub latency: f64,
    pub upload_mb: f64,
    pub history_upload_mb: f64,
    pub max_upload_kb: f64,
    pub history_max_upload_kb: f64,
    pub download_mb: f64,
    pub history_download_mb: f64,
    pub max_download_kb: f64,
    pub history_max_download_kb: f64,
    pub duration_minutes: f64,
    pub history_duration_minutes: f64,
    pub last_used: u64,
    pub is_udp: bool,
    pub loss_rate: f64,
    pub cumul_loss_rate: f64,
    pub ema_loss_rate: f64,
    pub connection_failed: bool,
    pub asn: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub geoip: Vec<String>,
    pub exit_region: String,
    pub exit_asn: String,
}
fn tables() -> &'static Value {
    static TABLES: OnceLock<Value> = OnceLock::new();
    TABLES.get_or_init(|| {
        serde_json::from_str(include_str!("feature-tables.json"))
            .expect("embedded Smart feature tables")
    })
}
fn entries(name: &str) -> &'static [Value] {
    tables()[name].as_array().expect("embedded feature list")
}
fn has_port(name: &str, port: u16) -> bool {
    entries(name)
        .iter()
        .any(|v| v.as_u64() == Some(port as u64))
}
pub fn shared_asn(asn: &str) -> bool {
    entries("sharedASNs")
        .iter()
        .any(|v| v.as_str() == Some(asn))
}

pub fn fnv_hash(value: &str, buckets: u32) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let hash = value.bytes().fold(2166136261u32, |hash, b| {
        (hash ^ b as u32).wrapping_mul(16777619)
    });
    (hash % buckets + 1) as f64
}
fn asn_feature(value: &str) -> f64 {
    let value = value.to_lowercase();
    if value.is_empty() {
        return 0.0;
    }
    for pair in entries("asn") {
        if value.contains(pair[0].as_str().unwrap()) {
            return pair[1].as_f64().unwrap();
        }
    }
    let numeric = value
        .strip_prefix("as")
        .unwrap_or(&value)
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    match numeric.parse::<u64>() {
        Ok(v) if v < 1000 => 1.0,
        Ok(v) if v < 10000 => 2.0,
        Ok(v) if v < 50000 => 3.0,
        Ok(v) if v < 150000 => 4.0,
        Ok(_) => 5.0,
        Err(_) => 0.0,
    }
}
fn geo_feature(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    if let Some(code) = tables()["geo"][value].as_f64() {
        return code;
    }
    (1 + value
        .chars()
        .fold(0u64, |h, c| h.wrapping_mul(31).wrapping_add(c as u64))
        % 20) as f64
}
fn domain_feature(host: &str) -> f64 {
    let host = host.to_lowercase();
    if host.is_empty() {
        return 0.0;
    }
    if host.contains('[') || host.parse::<IpAddr>().is_ok() {
        return 1.0;
    }
    for (list, code) in [
        ("dnsServiceKeywords", 104.0),
        ("apiServiceKeywords", 103.0),
        ("gameKeywords", 101.0),
        ("communicationKeywords", 102.0),
        ("streamingKeywords", 100.0),
    ] {
        if entries(list)
            .iter()
            .any(|v| host.contains(v.as_str().unwrap()))
        {
            return code;
        }
    }
    for (suffix, code) in [
        (".gov", 114.0),
        (".edu", 115.0),
        (".cn", 110.0),
        (".com", 111.0),
        (".net", 112.0),
        (".org", 113.0),
    ] {
        if host.ends_with(suffix) {
            return code;
        }
    }
    if host.contains('.')
        && host
            .rsplit('.')
            .next()
            .is_some_and(|label| !label.is_empty())
    {
        if host.matches('.').count() >= 2 {
            2.0
        } else {
            3.0
        }
    } else {
        0.0
    }
}
fn ip_feature(raw: &str) -> f64 {
    let Ok(ip) = raw.parse::<IpAddr>() else {
        return 0.0;
    };
    for pair in entries("privateIPNetworks") {
        let (network, prefix) = pair[0].as_str().unwrap().split_once('/').unwrap();
        let network = network.parse::<IpAddr>().unwrap();
        let prefix = prefix.parse::<u32>().unwrap();
        let matches = match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                u32::from(ip) & mask == u32::from(net) & mask
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                u128::from(ip) & mask == u128::from(net) & mask
            }
            _ => false,
        };
        if matches {
            return pair[1].as_f64().unwrap();
        }
    }
    if ip.is_ipv4() {
        14.0
    } else {
        15.0
    }
}
fn port_feature(port: u16) -> f64 {
    for (list, code) in [
        ("dnsServicePorts", 7.0),
        ("apiServicePorts", 6.0),
        ("gameSpecificPorts", 1.0),
        ("communicationPorts", 2.0),
    ] {
        if has_port(list, port) {
            return code;
        }
    }
    if let Some(code) = tables()["wellKnownPorts"][port.to_string()].as_f64() {
        return code;
    }
    for range in entries("gameCommRanges") {
        if (range[0].as_u64().unwrap()..=range[1].as_u64().unwrap()).contains(&(port as u64)) {
            return range[2].as_f64().unwrap() + 2.0;
        }
    }
    for range in entries("portRanges") {
        if (range[0].as_u64().unwrap()..=range[1].as_u64().unwrap()).contains(&(port as u64)) {
            return range[2].as_f64().unwrap();
        }
    }
    0.0
}
fn connection_type(port: u16, address: f64, service: f64) -> f64 {
    if address == 104.0 || service == 7.0 || has_port("dnsServicePorts", port) {
        return 7.0;
    }
    if address == 103.0 || service == 6.0 || has_port("apiServicePorts", port) {
        return 6.0;
    }
    if address == 101.0
        || address == 102.0
        || has_port("gameSpecificPorts", port)
        || has_port("communicationPorts", port)
    {
        return 3.0;
    }
    if address == 100.0 {
        return 2.0;
    }
    if port == 80 || port == 443 || service == 103.0 || service == 106.0 {
        return 1.0;
    }
    if [112.0, 113.0, 114.0, 115.0].contains(&service) {
        return 4.0;
    }
    if [20, 21, 22, 989, 990].contains(&port) {
        return 5.0;
    }
    if entries("gameCommRanges").iter().any(|range| {
        (range[0].as_u64().unwrap()..=range[1].as_u64().unwrap()).contains(&(port as u64))
    }) || (port > 10000 && port < 65000)
    {
        return 3.0;
    }
    0.0
}
impl ModelInput {
    pub fn features(&self, now: u64) -> [f64; 32] {
        let mut f = [0.0; 32];
        f[0] = self.success as f64;
        f[1] = self.failure as f64;
        for (slot, value) in [
            (2, self.connect_time),
            (3, self.latency),
            (4, self.upload_mb),
            (5, self.history_upload_mb),
            (6, self.max_upload_kb),
            (7, self.history_max_upload_kb),
            (8, self.download_mb),
            (9, self.history_download_mb),
            (10, self.max_download_kb),
            (11, self.history_max_download_kb),
            (12, self.duration_minutes),
            (13, self.history_duration_minutes),
        ] {
            f[slot] = value.max(0.0).ln_1p();
        }
        f[14] = if self.last_used > 0 {
            (now.saturating_sub(self.last_used) as f64).ln_1p()
        } else {
            0.0
        };
        f[15] = if self.is_udp { 1.0 } else { 0.0 };
        f[16] = 1.0 - f[15];
        f[17] = self.loss_rate;
        f[18] = self.cumul_loss_rate;
        f[19] = asn_feature(&self.asn);
        f[20] = geo_feature(self.geoip.first().map(String::as_str).unwrap_or(""));
        f[21] = if self.host.is_empty() {
            ip_feature(&self.ip)
        } else {
            domain_feature(&self.host)
        };
        f[22] = port_feature(self.port);
        if self.upload_mb > 0.0 && self.download_mb > 0.0 {
            f[23] = if self.upload_mb > self.download_mb {
                self.download_mb / self.upload_mb
            } else {
                -self.upload_mb / self.download_mb
            };
        }
        if self.duration_minutes > 0.0 {
            f[24] = ((self.upload_mb + self.download_mb) / self.duration_minutes).ln_1p();
        }
        f[25] = connection_type(self.port, f[21], f[22]);
        f[26] = fnv_hash(&self.asn, 500);
        f[27] = fnv_hash(&self.host, 1000);
        f[28] = fnv_hash(&self.ip, 10000);
        f[29] = fnv_hash(self.geoip.first().map(String::as_str).unwrap_or(""), 200);
        f[30] = geo_feature(&self.exit_region.to_uppercase());
        f[31] = fnv_hash(&self.exit_asn, 500);
        f
    }
}
