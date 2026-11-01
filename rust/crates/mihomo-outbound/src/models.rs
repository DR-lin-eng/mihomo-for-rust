use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::{OutboundDefinition, OutboundGroupKind, ProxyProviderVehicleType};

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmuxConfig {
    #[serde(default, rename = "enabled")]
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupDefinition {
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "type")]
    pub group_type: String,
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<String>,
    #[serde(default, rename = "use")]
    pub use_providers: Vec<String>,
    #[serde(default, rename = "url")]
    pub url: String,
    #[serde(default, rename = "interval")]
    pub interval: i32,
    #[serde(default, rename = "timeout")]
    pub timeout: i32,
    #[serde(default, rename = "max-failed-times")]
    pub max_failed_times: i32,
    #[serde(default = "default_true", rename = "lazy")]
    pub lazy: bool,
    #[serde(default, rename = "disable-udp")]
    pub disable_udp: bool,
    #[serde(default, rename = "filter")]
    pub filter: String,
    #[serde(default, rename = "exclude-filter")]
    pub exclude_filter: String,
    #[serde(default, rename = "exclude-type")]
    pub exclude_type: String,
    #[serde(
        default,
        rename = "expected-status",
        deserialize_with = "crate::serde_support::deserialize_string_like"
    )]
    pub expected_status: String,
    #[serde(default, rename = "include-all")]
    pub include_all: bool,
    #[serde(default, rename = "include-all-proxies")]
    pub include_all_proxies: bool,
    #[serde(default, rename = "include-all-providers")]
    pub include_all_providers: bool,
    #[serde(default, rename = "hidden")]
    pub hidden: bool,
    #[serde(default, rename = "icon")]
    pub icon: String,
    #[serde(default, rename = "strategy")]
    pub strategy: String,
    #[serde(default, rename = "tolerance")]
    pub tolerance: i32,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl GroupDefinition {
    pub fn kind(&self) -> Option<OutboundGroupKind> {
        match self.group_type.as_str() {
            "select" => Some(OutboundGroupKind::Selector),
            "url-test" => Some(OutboundGroupKind::UrlTest),
            "fallback" => Some(OutboundGroupKind::Fallback),
            "load-balance" => Some(OutboundGroupKind::LoadBalance),
            "smart" => Some(OutboundGroupKind::Smart),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderHealthCheckConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(default, rename = "url")]
    pub url: String,
    #[serde(default, rename = "interval")]
    pub interval: i32,
    #[serde(default, rename = "timeout")]
    pub timeout: i32,
    #[serde(default = "default_true", rename = "lazy")]
    pub lazy: bool,
    #[serde(
        default,
        rename = "expected-status",
        deserialize_with = "crate::serde_support::deserialize_string_like"
    )]
    pub expected_status: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyProviderOverride {
    #[serde(default, rename = "skip-cert-verify")]
    pub skip_cert_verify: bool,
    #[serde(default, rename = "udp")]
    pub udp: bool,
    #[serde(default, rename = "down")]
    pub down: String,
    #[serde(default, rename = "up")]
    pub up: String,
    #[serde(default, rename = "dialer-proxy")]
    pub dialer_proxy: String,
    #[serde(default, rename = "interface-name")]
    pub interface_name: String,
    #[serde(default, rename = "routing-mark")]
    pub routing_mark: i32,
    #[serde(default, rename = "ip-version")]
    pub ip_version: String,
    #[serde(default, rename = "additional-prefix")]
    pub additional_prefix: String,
    #[serde(default, rename = "additional-suffix")]
    pub additional_suffix: String,
    #[serde(default, rename = "proxy-name")]
    pub proxy_name: Vec<BTreeMap<String, Value>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyProviderDefinition {
    #[serde(default, rename = "type")]
    pub provider_type: String,
    #[serde(default, rename = "path")]
    pub path: String,
    #[serde(default, rename = "url")]
    pub url: String,
    #[serde(default, rename = "proxy")]
    pub proxy: String,
    #[serde(default, rename = "interval")]
    pub interval: i32,
    #[serde(default, rename = "filter")]
    pub filter: String,
    #[serde(default, rename = "exclude-filter")]
    pub exclude_filter: String,
    #[serde(default, rename = "exclude-type")]
    pub exclude_type: String,
    #[serde(default, rename = "dialer-proxy")]
    pub dialer_proxy: String,
    #[serde(default, rename = "size-limit")]
    pub size_limit: i64,
    #[serde(default, rename = "payload")]
    pub payload: Vec<OutboundDefinition>,
    #[serde(default, rename = "health-check")]
    pub health_check: ProviderHealthCheckConfig,
    #[serde(default, rename = "override")]
    pub override_config: ProxyProviderOverride,
    #[serde(default, rename = "header")]
    pub header: BTreeMap<String, Vec<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ProxyProviderDefinition {
    pub fn vehicle_type(&self) -> Option<ProxyProviderVehicleType> {
        match self.provider_type.as_str() {
            "file" => Some(ProxyProviderVehicleType::File),
            "http" => Some(ProxyProviderVehicleType::Http),
            "inline" => Some(ProxyProviderVehicleType::Inline),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyBaseConfig {
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "tfo")]
    pub tfo: bool,
    #[serde(default, rename = "mptcp")]
    pub mptcp: bool,
    #[serde(default, rename = "interface-name")]
    pub interface_name: String,
    #[serde(default, rename = "routing-mark")]
    pub routing_mark: i32,
    #[serde(default, rename = "ip-version")]
    pub ip_version: String,
    #[serde(default, rename = "dialer-proxy")]
    pub dialer_proxy: String,
    #[serde(default, rename = "smux")]
    pub smux: SmuxConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamedOutboundConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerPortOutboundConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    #[serde(default, rename = "server")]
    pub server: String,
    #[serde(default, rename = "port")]
    pub port: u16,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShadowSocksOutboundConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    #[serde(default, rename = "server")]
    pub server: String,
    #[serde(default, rename = "port")]
    pub port: u16,
    #[serde(default, rename = "cipher")]
    pub cipher: String,
    #[serde(default, rename = "password")]
    pub password: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WireGuardOutboundConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    #[serde(default, rename = "server")]
    pub server: String,
    #[serde(default, rename = "port")]
    pub port: u16,
    #[serde(default, rename = "private-key")]
    pub private_key: String,
    #[serde(default, rename = "ip")]
    pub ip: String,
    #[serde(default, rename = "ipv6")]
    pub ipv6: String,
    #[serde(default, rename = "public-key")]
    pub public_key: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
