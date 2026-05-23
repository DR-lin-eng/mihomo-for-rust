use std::collections::BTreeMap;

use mihomo_core::{RewriteStage, SubsystemManifest};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundKind {
    Direct,
    Reject,
    Dns,
    Http,
    Socks5,
    ShadowSocks,
    ShadowSocksR,
    Snell,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Hysteria2,
    WireGuard,
    Tuic,
    GostRelay,
    Ssh,
    Mieru,
    AnyTls,
    Sudoku,
    Masque,
    TrustTunnel,
    OpenVpn,
    Tailscale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundGroupKind {
    Selector,
    UrlTest,
    Fallback,
    LoadBalance,
}

pub const SUPPORTED_OUTBOUNDS: &[OutboundKind] = &[
    OutboundKind::Direct,
    OutboundKind::Reject,
    OutboundKind::Dns,
    OutboundKind::Http,
    OutboundKind::Socks5,
    OutboundKind::ShadowSocks,
    OutboundKind::ShadowSocksR,
    OutboundKind::Snell,
    OutboundKind::Vmess,
    OutboundKind::Vless,
    OutboundKind::Trojan,
    OutboundKind::Hysteria,
    OutboundKind::Hysteria2,
    OutboundKind::WireGuard,
    OutboundKind::Tuic,
    OutboundKind::GostRelay,
    OutboundKind::Ssh,
    OutboundKind::Mieru,
    OutboundKind::AnyTls,
    OutboundKind::Sudoku,
    OutboundKind::Masque,
    OutboundKind::TrustTunnel,
    OutboundKind::OpenVpn,
    OutboundKind::Tailscale,
];

pub const SUPPORTED_OUTBOUND_GROUPS: &[OutboundGroupKind] = &[
    OutboundGroupKind::Selector,
    OutboundGroupKind::UrlTest,
    OutboundGroupKind::Fallback,
    OutboundGroupKind::LoadBalance,
];

impl OutboundKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reject => "reject",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::ShadowSocks => "ss",
            Self::ShadowSocksR => "ssr",
            Self::Snell => "snell",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria => "hysteria",
            Self::Hysteria2 => "hysteria2",
            Self::WireGuard => "wireguard",
            Self::Tuic => "tuic",
            Self::GostRelay => "gost-relay",
            Self::Ssh => "ssh",
            Self::Mieru => "mieru",
            Self::AnyTls => "anytls",
            Self::Sudoku => "sudoku",
            Self::Masque => "masque",
            Self::TrustTunnel => "trusttunnel",
            Self::OpenVpn => "openvpn",
            Self::Tailscale => "tailscale",
        }
    }
}

impl OutboundGroupKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Selector => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProviderVehicleType {
    File,
    Http,
    Inline,
}

impl ProxyProviderVehicleType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Http => "http",
            Self::Inline => "inline",
        }
    }
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
    #[serde(default, rename = "expected-status")]
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
    #[serde(default, rename = "expected-status")]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum OutboundDefinition {
    #[serde(rename = "direct")]
    Direct(NamedOutboundConfig),
    #[serde(rename = "dns")]
    Dns(NamedOutboundConfig),
    #[serde(rename = "reject")]
    Reject(NamedOutboundConfig),
    #[serde(rename = "http")]
    Http(ServerPortOutboundConfig),
    #[serde(rename = "socks5")]
    Socks5(ServerPortOutboundConfig),
    #[serde(rename = "ss")]
    ShadowSocks(ShadowSocksOutboundConfig),
    #[serde(rename = "ssr")]
    ShadowSocksR(ServerPortOutboundConfig),
    #[serde(rename = "snell")]
    Snell(ServerPortOutboundConfig),
    #[serde(rename = "vmess")]
    Vmess(ServerPortOutboundConfig),
    #[serde(rename = "vless")]
    Vless(ServerPortOutboundConfig),
    #[serde(rename = "trojan")]
    Trojan(ServerPortOutboundConfig),
    #[serde(rename = "hysteria")]
    Hysteria(ServerPortOutboundConfig),
    #[serde(rename = "hysteria2")]
    Hysteria2(ServerPortOutboundConfig),
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardOutboundConfig),
    #[serde(rename = "tuic")]
    Tuic(ServerPortOutboundConfig),
    #[serde(rename = "gost-relay")]
    GostRelay(ServerPortOutboundConfig),
    #[serde(rename = "ssh")]
    Ssh(ServerPortOutboundConfig),
    #[serde(rename = "mieru")]
    Mieru(ServerPortOutboundConfig),
    #[serde(rename = "anytls")]
    AnyTls(ServerPortOutboundConfig),
    #[serde(rename = "sudoku")]
    Sudoku(ServerPortOutboundConfig),
    #[serde(rename = "masque")]
    Masque(ServerPortOutboundConfig),
    #[serde(rename = "trusttunnel")]
    TrustTunnel(ServerPortOutboundConfig),
    #[serde(rename = "openvpn")]
    OpenVpn(ServerPortOutboundConfig),
    #[serde(rename = "tailscale")]
    Tailscale(NamedOutboundConfig),
}

impl OutboundDefinition {
    pub fn kind(&self) -> OutboundKind {
        match self {
            Self::Direct(_) => OutboundKind::Direct,
            Self::Dns(_) => OutboundKind::Dns,
            Self::Reject(_) => OutboundKind::Reject,
            Self::Http(_) => OutboundKind::Http,
            Self::Socks5(_) => OutboundKind::Socks5,
            Self::ShadowSocks(_) => OutboundKind::ShadowSocks,
            Self::ShadowSocksR(_) => OutboundKind::ShadowSocksR,
            Self::Snell(_) => OutboundKind::Snell,
            Self::Vmess(_) => OutboundKind::Vmess,
            Self::Vless(_) => OutboundKind::Vless,
            Self::Trojan(_) => OutboundKind::Trojan,
            Self::Hysteria(_) => OutboundKind::Hysteria,
            Self::Hysteria2(_) => OutboundKind::Hysteria2,
            Self::WireGuard(_) => OutboundKind::WireGuard,
            Self::Tuic(_) => OutboundKind::Tuic,
            Self::GostRelay(_) => OutboundKind::GostRelay,
            Self::Ssh(_) => OutboundKind::Ssh,
            Self::Mieru(_) => OutboundKind::Mieru,
            Self::AnyTls(_) => OutboundKind::AnyTls,
            Self::Sudoku(_) => OutboundKind::Sudoku,
            Self::Masque(_) => OutboundKind::Masque,
            Self::TrustTunnel(_) => OutboundKind::TrustTunnel,
            Self::OpenVpn(_) => OutboundKind::OpenVpn,
            Self::Tailscale(_) => OutboundKind::Tailscale,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Direct(config) => &config.base.name,
            Self::Dns(config) => &config.base.name,
            Self::Reject(config) => &config.base.name,
            Self::Http(config) => &config.base.name,
            Self::Socks5(config) => &config.base.name,
            Self::ShadowSocks(config) => &config.base.name,
            Self::ShadowSocksR(config) => &config.base.name,
            Self::Snell(config) => &config.base.name,
            Self::Vmess(config) => &config.base.name,
            Self::Vless(config) => &config.base.name,
            Self::Trojan(config) => &config.base.name,
            Self::Hysteria(config) => &config.base.name,
            Self::Hysteria2(config) => &config.base.name,
            Self::WireGuard(config) => &config.base.name,
            Self::Tuic(config) => &config.base.name,
            Self::GostRelay(config) => &config.base.name,
            Self::Ssh(config) => &config.base.name,
            Self::Mieru(config) => &config.base.name,
            Self::AnyTls(config) => &config.base.name,
            Self::Sudoku(config) => &config.base.name,
            Self::Masque(config) => &config.base.name,
            Self::TrustTunnel(config) => &config.base.name,
            Self::OpenVpn(config) => &config.base.name,
            Self::Tailscale(config) => &config.base.name,
        }
    }

    pub fn dialer_proxy(&self) -> &str {
        match self {
            Self::Direct(config) => &config.base.dialer_proxy,
            Self::Dns(config) => &config.base.dialer_proxy,
            Self::Reject(config) => &config.base.dialer_proxy,
            Self::Http(config) => &config.base.dialer_proxy,
            Self::Socks5(config) => &config.base.dialer_proxy,
            Self::ShadowSocks(config) => &config.base.dialer_proxy,
            Self::ShadowSocksR(config) => &config.base.dialer_proxy,
            Self::Snell(config) => &config.base.dialer_proxy,
            Self::Vmess(config) => &config.base.dialer_proxy,
            Self::Vless(config) => &config.base.dialer_proxy,
            Self::Trojan(config) => &config.base.dialer_proxy,
            Self::Hysteria(config) => &config.base.dialer_proxy,
            Self::Hysteria2(config) => &config.base.dialer_proxy,
            Self::WireGuard(config) => &config.base.dialer_proxy,
            Self::Tuic(config) => &config.base.dialer_proxy,
            Self::GostRelay(config) => &config.base.dialer_proxy,
            Self::Ssh(config) => &config.base.dialer_proxy,
            Self::Mieru(config) => &config.base.dialer_proxy,
            Self::AnyTls(config) => &config.base.dialer_proxy,
            Self::Sudoku(config) => &config.base.dialer_proxy,
            Self::Masque(config) => &config.base.dialer_proxy,
            Self::TrustTunnel(config) => &config.base.dialer_proxy,
            Self::OpenVpn(config) => &config.base.dialer_proxy,
            Self::Tailscale(config) => &config.base.dialer_proxy,
        }
    }

    pub fn base(&self) -> &ProxyBaseConfig {
        match self {
            Self::Direct(config) => &config.base,
            Self::Dns(config) => &config.base,
            Self::Reject(config) => &config.base,
            Self::Http(config) => &config.base,
            Self::Socks5(config) => &config.base,
            Self::ShadowSocks(config) => &config.base,
            Self::ShadowSocksR(config) => &config.base,
            Self::Snell(config) => &config.base,
            Self::Vmess(config) => &config.base,
            Self::Vless(config) => &config.base,
            Self::Trojan(config) => &config.base,
            Self::Hysteria(config) => &config.base,
            Self::Hysteria2(config) => &config.base,
            Self::WireGuard(config) => &config.base,
            Self::Tuic(config) => &config.base,
            Self::GostRelay(config) => &config.base,
            Self::Ssh(config) => &config.base,
            Self::Mieru(config) => &config.base,
            Self::AnyTls(config) => &config.base,
            Self::Sudoku(config) => &config.base,
            Self::Masque(config) => &config.base,
            Self::TrustTunnel(config) => &config.base,
            Self::OpenVpn(config) => &config.base,
            Self::Tailscale(config) => &config.base,
        }
    }

    pub fn base_mut(&mut self) -> &mut ProxyBaseConfig {
        match self {
            Self::Direct(config) => &mut config.base,
            Self::Dns(config) => &mut config.base,
            Self::Reject(config) => &mut config.base,
            Self::Http(config) => &mut config.base,
            Self::Socks5(config) => &mut config.base,
            Self::ShadowSocks(config) => &mut config.base,
            Self::ShadowSocksR(config) => &mut config.base,
            Self::Snell(config) => &mut config.base,
            Self::Vmess(config) => &mut config.base,
            Self::Vless(config) => &mut config.base,
            Self::Trojan(config) => &mut config.base,
            Self::Hysteria(config) => &mut config.base,
            Self::Hysteria2(config) => &mut config.base,
            Self::WireGuard(config) => &mut config.base,
            Self::Tuic(config) => &mut config.base,
            Self::GostRelay(config) => &mut config.base,
            Self::Ssh(config) => &mut config.base,
            Self::Mieru(config) => &mut config.base,
            Self::AnyTls(config) => &mut config.base,
            Self::Sudoku(config) => &mut config.base,
            Self::Masque(config) => &mut config.base,
            Self::TrustTunnel(config) => &mut config.base,
            Self::OpenVpn(config) => &mut config.base,
            Self::Tailscale(config) => &mut config.base,
        }
    }

    pub fn remote_endpoint(&self) -> Option<(&str, u16)> {
        match self {
            Self::Http(config) => Some((&config.server, config.port)),
            Self::Socks5(config) => Some((&config.server, config.port)),
            Self::ShadowSocks(config) => Some((&config.server, config.port)),
            Self::ShadowSocksR(config) => Some((&config.server, config.port)),
            Self::Snell(config) => Some((&config.server, config.port)),
            Self::Vmess(config) => Some((&config.server, config.port)),
            Self::Vless(config) => Some((&config.server, config.port)),
            Self::Trojan(config) => Some((&config.server, config.port)),
            Self::Hysteria(config) => Some((&config.server, config.port)),
            Self::Hysteria2(config) => Some((&config.server, config.port)),
            Self::WireGuard(config) => Some((&config.server, config.port)),
            Self::Tuic(config) => Some((&config.server, config.port)),
            Self::GostRelay(config) => Some((&config.server, config.port)),
            Self::Ssh(config) => Some((&config.server, config.port)),
            Self::Mieru(config) => Some((&config.server, config.port)),
            Self::AnyTls(config) => Some((&config.server, config.port)),
            Self::Sudoku(config) => Some((&config.server, config.port)),
            Self::Masque(config) => Some((&config.server, config.port)),
            Self::TrustTunnel(config) => Some((&config.server, config.port)),
            Self::OpenVpn(config) => Some((&config.server, config.port)),
            Self::Direct(_) | Self::Dns(_) | Self::Reject(_) | Self::Tailscale(_) => None,
        }
    }

    pub fn set_name(&mut self, name: String) {
        self.base_mut().name = name;
    }
}

pub fn parse_outbound_yaml(input: &str) -> Result<OutboundDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

pub fn parse_group_yaml(input: &str) -> Result<GroupDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

pub fn parse_provider_yaml(input: &str) -> Result<ProxyProviderDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPayloadDocument {
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<OutboundDefinition>,
}

pub fn parse_provider_payload_document(
    input: &str,
) -> Result<ProviderPayloadDocument, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

fn default_true() -> bool {
    true
}

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-outbound",
    go_areas: &["adapter/outbound", "adapter/outboundgroup", "adapter/provider"],
    contracts: &["proxy adapters", "proxy groups", "provider compatibility"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        parse_group_yaml, parse_outbound_yaml, parse_provider_yaml, GroupDefinition,
        OutboundDefinition, OutboundGroupKind, OutboundKind, ProviderHealthCheckConfig,
        ProxyProviderVehicleType, ShadowSocksOutboundConfig, SUPPORTED_OUTBOUND_GROUPS,
        SUPPORTED_OUTBOUNDS, WireGuardOutboundConfig,
    };

    #[test]
    fn inventory_tracks_adapter_surface() {
        assert!(SUPPORTED_OUTBOUNDS.len() >= 20);
        assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::WireGuard));
        assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::Tailscale));
        assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::Sudoku));
        assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::TrustTunnel));
    }

    #[test]
    fn inventory_tracks_group_surface() {
        assert_eq!(SUPPORTED_OUTBOUND_GROUPS.len(), 4);
        assert!(SUPPORTED_OUTBOUND_GROUPS.contains(&OutboundGroupKind::UrlTest));
    }

    #[test]
    fn shadowsocks_proxy_parses_basic_and_smux_fields() {
        let parsed = parse_outbound_yaml(
            r#"
type: ss
name: edge-ss
server: 1.2.3.4
port: 8388
cipher: chacha20-ietf-poly1305
password: secret
tfo: true
smux:
  enabled: true
"#,
        )
        .unwrap();
        let OutboundDefinition::ShadowSocks(ShadowSocksOutboundConfig {
            server,
            port,
            cipher,
            password,
            base,
            ..
        }) = parsed
        else {
            panic!("expected shadowsocks proxy");
        };
        assert_eq!(server, "1.2.3.4");
        assert_eq!(port, 8388);
        assert_eq!(cipher, "chacha20-ietf-poly1305");
        assert_eq!(password, "secret");
        assert!(base.tfo);
        assert!(base.smux.enabled);
    }

    #[test]
    fn direct_proxy_parses_without_server_fields() {
        let parsed = parse_outbound_yaml(
            r#"
type: direct
name: local
interface-name: en0
routing-mark: 10
"#,
        )
        .unwrap();
        let OutboundDefinition::Direct(config) = parsed else {
            panic!("expected direct proxy");
        };
        assert_eq!(config.base.name, "local");
        assert_eq!(config.base.interface_name, "en0");
        assert_eq!(config.base.routing_mark, 10);
    }

    #[test]
    fn wireguard_proxy_keeps_modeled_keys() {
        let parsed = parse_outbound_yaml(
            r#"
type: wireguard
name: wg
server: edge.example.com
port: 51820
private-key: abc
ip: 10.0.0.2/32
ipv6: fd00::2/128
public-key: pub
"#,
        )
        .unwrap();
        let OutboundDefinition::WireGuard(WireGuardOutboundConfig {
            server,
            port,
            private_key,
            ip,
            ipv6,
            public_key,
            ..
        }) = parsed
        else {
            panic!("expected wireguard proxy");
        };
        assert_eq!(server, "edge.example.com");
        assert_eq!(port, 51820);
        assert_eq!(private_key, "abc");
        assert_eq!(ip, "10.0.0.2/32");
        assert_eq!(ipv6, "fd00::2/128");
        assert_eq!(public_key, "pub");
    }

    #[test]
    fn proxy_group_parses_group_common_fields_and_defaults() {
        let parsed = parse_group_yaml(
            r#"
name: auto
type: url-test
proxies: [ss1, ss2, vmess1]
url: https://cp.cloudflare.com/generate_204
interval: 300
"#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            GroupDefinition {
                name: "auto".into(),
                group_type: "url-test".into(),
                proxies: vec!["ss1".into(), "ss2".into(), "vmess1".into()],
                use_providers: vec![],
                url: "https://cp.cloudflare.com/generate_204".into(),
                interval: 300,
                timeout: 0,
                max_failed_times: 0,
                lazy: true,
                disable_udp: false,
                filter: String::new(),
                exclude_filter: String::new(),
                exclude_type: String::new(),
                expected_status: String::new(),
                include_all: false,
                include_all_proxies: false,
                include_all_providers: false,
                hidden: false,
                icon: String::new(),
                strategy: String::new(),
                tolerance: 0,
                extra: BTreeMap::new(),
            }
        );
        assert_eq!(parsed.kind(), Some(OutboundGroupKind::UrlTest));
    }

    #[test]
    fn provider_parses_http_vehicle_health_check_and_override() {
        let parsed = parse_provider_yaml(
            r#"
type: http
url: https://example.com/provider.yaml
interval: 3600
path: ./provider1.yaml
proxy: DIRECT
header:
  User-Agent:
    - Clash/v1.18.0
health-check:
  enable: true
  interval: 600
  url: https://cp.cloudflare.com/generate_204
override:
  udp: true
  interface-name: tailscale0
"#,
        )
        .unwrap();
        assert_eq!(parsed.vehicle_type(), Some(ProxyProviderVehicleType::Http));
        assert_eq!(
            parsed.health_check,
            ProviderHealthCheckConfig {
                enable: true,
                url: "https://cp.cloudflare.com/generate_204".into(),
                interval: 600,
                timeout: 0,
                lazy: true,
                expected_status: String::new(),
            }
        );
        assert!(parsed.override_config.udp);
        assert_eq!(parsed.override_config.interface_name, "tailscale0");
        assert_eq!(
            parsed.header.get("User-Agent"),
            Some(&vec!["Clash/v1.18.0".into()])
        );
    }

    #[test]
    fn provider_parses_inline_payload_as_nested_proxies() {
        let parsed = parse_provider_yaml(
            r#"
type: inline
payload:
  - name: ss1
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
"#,
        )
        .unwrap();
        assert_eq!(parsed.vehicle_type(), Some(ProxyProviderVehicleType::Inline));
        assert_eq!(parsed.payload.len(), 1);
        match &parsed.payload[0] {
            OutboundDefinition::ShadowSocks(config) => {
                assert_eq!(config.base.name, "ss1");
                assert_eq!(config.server, "server");
                assert_eq!(config.port, 443);
            }
            _ => panic!("expected nested shadowsocks proxy"),
        }
    }
}
