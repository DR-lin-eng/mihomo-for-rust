use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;

fn deserialize_port_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null => Ok(String::new()),
        Value::String(text) => Ok(text),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(flag) => Ok(flag.to_string()),
        other => Err(serde::de::Error::custom(format!(
            "invalid inbound port type: expected string or integer, got {other:?}"
        ))),
    }
}

fn default_true() -> bool {
    true
}

fn default_dns_hijack() -> Vec<String> {
    vec!["0.0.0.0:53".to_owned()]
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BaseInboundConfig {
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "listen")]
    pub listen: String,
    #[serde(default, rename = "port", deserialize_with = "deserialize_port_string")]
    pub port: String,
    #[serde(default, rename = "rule")]
    pub special_rules: String,
    #[serde(default, rename = "proxy")]
    pub special_proxy: String,
}

impl BaseInboundConfig {
    pub fn effective_listen(&self) -> &str {
        if self.listen.is_empty() {
            "0.0.0.0"
        } else {
            &self.listen
        }
    }

    pub fn ports(&self) -> Vec<u16> {
        if self.port.is_empty() {
            return vec![0];
        }

        let mut ports = Vec::new();
        for raw_segment in self.port.split(',') {
            let segment = raw_segment.trim();
            if segment.is_empty() {
                continue;
            }
            if let Some((start, end)) = segment.split_once('-') {
                let start = start.trim().parse::<u16>().unwrap_or(0);
                let end = end.trim().parse::<u16>().unwrap_or(0);
                if start <= end {
                    ports.extend(start..=end);
                }
            } else if let Ok(port) = segment.parse::<u16>() {
                ports.push(port);
            }
        }
        if ports.is_empty() {
            vec![0]
        } else {
            ports
        }
    }

    pub fn raw_addresses(&self) -> Vec<String> {
        self.ports()
            .into_iter()
            .map(|port| format!("{}:{port}", self.effective_listen()))
            .collect()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthUser {
    #[serde(default, rename = "username")]
    pub username: String,
    #[serde(default, rename = "password")]
    pub password: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealityLimitFallback {
    #[serde(default, rename = "after-bytes")]
    pub after_bytes: u64,
    #[serde(default, rename = "bytes-per-sec")]
    pub bytes_per_sec: u64,
    #[serde(default, rename = "burst-bytes-per-sec")]
    pub burst_bytes_per_sec: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealityConfig {
    #[serde(default, rename = "dest")]
    pub dest: String,
    #[serde(default, rename = "private-key")]
    pub private_key: String,
    #[serde(default, rename = "short-id")]
    pub short_id: Vec<String>,
    #[serde(default, rename = "server-names")]
    pub server_names: Vec<String>,
    #[serde(default, rename = "max-time-difference")]
    pub max_time_difference: i32,
    #[serde(default, rename = "proxy")]
    pub proxy: String,
    #[serde(default, rename = "limit-fallback-upload")]
    pub limit_fallback_upload: RealityLimitFallback,
    #[serde(default, rename = "limit-fallback-download")]
    pub limit_fallback_download: RealityLimitFallback,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(default, rename = "users")]
    pub users: Vec<AuthUser>,
    #[serde(default = "default_true", rename = "udp")]
    pub udp: bool,
    #[serde(default, rename = "certificate")]
    pub certificate: String,
    #[serde(default, rename = "private-key")]
    pub private_key: String,
    #[serde(default, rename = "client-auth-type")]
    pub client_auth_type: String,
    #[serde(default, rename = "client-auth-cert")]
    pub client_auth_cert: String,
    #[serde(default, rename = "ech-key")]
    pub ech_key: String,
    #[serde(default, rename = "reality-config")]
    pub reality_config: RealityConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HttpInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(default, rename = "users")]
    pub users: Vec<AuthUser>,
    #[serde(default, rename = "certificate")]
    pub certificate: String,
    #[serde(default, rename = "private-key")]
    pub private_key: String,
    #[serde(default, rename = "client-auth-type")]
    pub client_auth_type: String,
    #[serde(default, rename = "client-auth-cert")]
    pub client_auth_cert: String,
    #[serde(default, rename = "ech-key")]
    pub ech_key: String,
    #[serde(default, rename = "reality-config")]
    pub reality_config: RealityConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TProxyInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(default = "default_true", rename = "udp")]
    pub udp: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedirInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TunnelInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(default, rename = "network")]
    pub network: Vec<String>,
    #[serde(default, rename = "target")]
    pub target: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SimpleObfsConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(default, rename = "mode")]
    pub mode: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShadowSocksInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(default, rename = "password")]
    pub password: String,
    #[serde(default, rename = "cipher")]
    pub cipher: String,
    // Go's shadowsocks listener defaults UDP off (`Udp bool` zero value).
    #[serde(default, rename = "udp")]
    pub udp: bool,
    #[serde(default, rename = "mux-option")]
    pub mux_option: BTreeMap<String, Value>,
    #[serde(default, rename = "shadow-tls")]
    pub shadow_tls: BTreeMap<String, Value>,
    #[serde(default, rename = "kcp-tun")]
    pub kcp_tun: BTreeMap<String, Value>,
    #[serde(default, rename = "simple-obfs")]
    pub simple_obfs: SimpleObfsConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunStack {
    Gvisor,
    System,
    Mixed,
    Unknown(String),
}

impl Default for TunStack {
    fn default() -> Self {
        Self::Gvisor
    }
}

impl<'de> Deserialize<'de> for TunStack {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "gvisor" => Self::Gvisor,
            "system" => Self::System,
            "mixed" => Self::Mixed,
            _ => Self::Unknown(raw),
        })
    }
}

impl Serialize for TunStack {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Gvisor => serializer.serialize_str("gvisor"),
            Self::System => serializer.serialize_str("system"),
            Self::Mixed => serializer.serialize_str("mixed"),
            Self::Unknown(raw) => serializer.serialize_str(raw),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TunInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(default, rename = "device")]
    pub device: String,
    #[serde(default, rename = "stack")]
    pub stack: TunStack,
    #[serde(default = "default_dns_hijack", rename = "dns-hijack")]
    pub dns_hijack: Vec<String>,
    #[serde(default, rename = "auto-route")]
    pub auto_route: bool,
    #[serde(default, rename = "auto-detect-interface")]
    pub auto_detect_interface: bool,
    #[serde(default, rename = "mtu")]
    pub mtu: u32,
    #[serde(default, rename = "gso")]
    pub gso: bool,
    #[serde(default, rename = "gso-max-size")]
    pub gso_max_size: u32,
    #[serde(default, rename = "inet4-address")]
    pub inet4_address: Vec<String>,
    #[serde(default, rename = "inet6-address")]
    pub inet6_address: Vec<String>,
    #[serde(default, rename = "iproute2-table-index")]
    pub iproute2_table_index: i32,
    #[serde(default, rename = "iproute2-rule-index")]
    pub iproute2_rule_index: i32,
    #[serde(default, rename = "auto-redirect")]
    pub auto_redirect: bool,
    #[serde(default, rename = "auto-redirect-input-mark")]
    pub auto_redirect_input_mark: u32,
    #[serde(default, rename = "auto-redirect-output-mark")]
    pub auto_redirect_output_mark: u32,
    #[serde(
        default,
        rename = "auto-redirect-iproute2-fallback-rule-index"
    )]
    pub auto_redirect_iproute2_fallback_rule_index: i32,
    #[serde(default, rename = "loopback-address")]
    pub loopback_address: Vec<String>,
    #[serde(default, rename = "strict-route")]
    pub strict_route: bool,
    #[serde(default, rename = "route-address")]
    pub route_address: Vec<String>,
    #[serde(default, rename = "route-address-set")]
    pub route_address_set: Vec<String>,
    #[serde(default, rename = "route-exclude-address")]
    pub route_exclude_address: Vec<String>,
    #[serde(default, rename = "route-exclude-address-set")]
    pub route_exclude_address_set: Vec<String>,
    #[serde(default, rename = "include-interface")]
    pub include_interface: Vec<String>,
    #[serde(default, rename = "exclude-interface")]
    pub exclude_interface: Vec<String>,
    #[serde(default, rename = "include-uid")]
    pub include_uid: Vec<u32>,
    #[serde(default, rename = "include-uid-range")]
    pub include_uid_range: Vec<String>,
    #[serde(default, rename = "exclude-uid")]
    pub exclude_uid: Vec<u32>,
    #[serde(default, rename = "exclude-uid-range")]
    pub exclude_uid_range: Vec<String>,
    #[serde(default, rename = "exclude-src-port")]
    pub exclude_src_port: Vec<u16>,
    #[serde(default, rename = "exclude-src-port-range")]
    pub exclude_src_port_range: Vec<String>,
    #[serde(default, rename = "exclude-dst-port")]
    pub exclude_dst_port: Vec<u16>,
    #[serde(default, rename = "exclude-dst-port-range")]
    pub exclude_dst_port_range: Vec<String>,
    #[serde(default, rename = "include-android-user")]
    pub include_android_user: Vec<i32>,
    #[serde(default, rename = "include-package")]
    pub include_package: Vec<String>,
    #[serde(default, rename = "exclude-package")]
    pub exclude_package: Vec<String>,
    #[serde(default, rename = "include-mac-address")]
    pub include_mac_address: Vec<String>,
    #[serde(default, rename = "exclude-mac-address")]
    pub exclude_mac_address: Vec<String>,
    #[serde(default, rename = "endpoint-independent-nat")]
    pub endpoint_independent_nat: bool,
    #[serde(default, rename = "udp-timeout")]
    pub udp_timeout: i64,
    #[serde(default, rename = "disable-icmp-forwarding")]
    pub disable_icmp_forwarding: bool,
    #[serde(default, rename = "file-descriptor")]
    pub file_descriptor: i32,
    #[serde(default, rename = "inet4-route-address")]
    pub inet4_route_address: Vec<String>,
    #[serde(default, rename = "inet6-route-address")]
    pub inet6_route_address: Vec<String>,
    #[serde(default, rename = "inet4-route-exclude-address")]
    pub inet4_route_exclude_address: Vec<String>,
    #[serde(default, rename = "inet6-route-exclude-address")]
    pub inet6_route_exclude_address: Vec<String>,
    #[serde(default, rename = "recvmsgx")]
    pub recvmsgx: bool,
    #[serde(default, rename = "sendmsgx")]
    pub sendmsgx: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenericInboundConfig {
    #[serde(flatten)]
    pub base: BaseInboundConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
