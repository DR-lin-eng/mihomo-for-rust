use std::collections::BTreeMap;

use mihomo_core::SubsystemManifest;
use mihomo_core::RewriteStage;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundKind {
    Socks,
    Http,
    TProxy,
    Redir,
    Mixed,
    Tunnel,
    Tun,
    ShadowSocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Hysteria2Realm,
    Tuic,
    AnyTls,
    Mieru,
    Sudoku,
    TrustTunnel,
}

pub const SUPPORTED_INBOUNDS: &[InboundKind] = &[
    InboundKind::Socks,
    InboundKind::Http,
    InboundKind::TProxy,
    InboundKind::Redir,
    InboundKind::Mixed,
    InboundKind::Tunnel,
    InboundKind::Tun,
    InboundKind::ShadowSocks,
    InboundKind::Vmess,
    InboundKind::Vless,
    InboundKind::Trojan,
    InboundKind::Hysteria2,
    InboundKind::Hysteria2Realm,
    InboundKind::Tuic,
    InboundKind::AnyTls,
    InboundKind::Mieru,
    InboundKind::Sudoku,
    InboundKind::TrustTunnel,
];

impl InboundKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Socks => "socks",
            Self::Http => "http",
            Self::TProxy => "tproxy",
            Self::Redir => "redir",
            Self::Mixed => "mixed",
            Self::Tunnel => "tunnel",
            Self::Tun => "tun",
            Self::ShadowSocks => "shadowsocks",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria2 => "hysteria2",
            Self::Hysteria2Realm => "hysteria2-realm",
            Self::Tuic => "tuic",
            Self::AnyTls => "anytls",
            Self::Mieru => "mieru",
            Self::Sudoku => "sudoku",
            Self::TrustTunnel => "trusttunnel",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BaseInboundConfig {
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "listen")]
    pub listen: String,
    #[serde(default, rename = "port")]
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
    #[serde(default = "default_true", rename = "udp")]
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
    #[serde(default, rename = "include-package")]
    pub include_package: Vec<String>,
    #[serde(default, rename = "exclude-package")]
    pub exclude_package: Vec<String>,
    #[serde(default, rename = "udp-timeout")]
    pub udp_timeout: i64,
    #[serde(default, rename = "file-descriptor")]
    pub file_descriptor: i32,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum InboundDefinition {
    #[serde(rename = "socks")]
    Socks(TlsInboundConfig),
    #[serde(rename = "http")]
    Http(HttpInboundConfig),
    #[serde(rename = "tproxy")]
    TProxy(TProxyInboundConfig),
    #[serde(rename = "redir")]
    Redir(RedirInboundConfig),
    #[serde(rename = "mixed")]
    Mixed(TlsInboundConfig),
    #[serde(rename = "tunnel")]
    Tunnel(TunnelInboundConfig),
    #[serde(rename = "tun")]
    Tun(TunInboundConfig),
    #[serde(rename = "shadowsocks")]
    ShadowSocks(ShadowSocksInboundConfig),
    #[serde(rename = "vmess")]
    Vmess(GenericInboundConfig),
    #[serde(rename = "vless")]
    Vless(GenericInboundConfig),
    #[serde(rename = "trojan")]
    Trojan(GenericInboundConfig),
    #[serde(rename = "hysteria2")]
    Hysteria2(GenericInboundConfig),
    #[serde(rename = "hysteria2-realm")]
    Hysteria2Realm(GenericInboundConfig),
    #[serde(rename = "tuic")]
    Tuic(GenericInboundConfig),
    #[serde(rename = "anytls")]
    AnyTls(GenericInboundConfig),
    #[serde(rename = "mieru")]
    Mieru(GenericInboundConfig),
    #[serde(rename = "sudoku")]
    Sudoku(GenericInboundConfig),
    #[serde(rename = "trusttunnel")]
    TrustTunnel(GenericInboundConfig),
}

impl InboundDefinition {
    pub fn kind(&self) -> InboundKind {
        match self {
            Self::Socks(_) => InboundKind::Socks,
            Self::Http(_) => InboundKind::Http,
            Self::TProxy(_) => InboundKind::TProxy,
            Self::Redir(_) => InboundKind::Redir,
            Self::Mixed(_) => InboundKind::Mixed,
            Self::Tunnel(_) => InboundKind::Tunnel,
            Self::Tun(_) => InboundKind::Tun,
            Self::ShadowSocks(_) => InboundKind::ShadowSocks,
            Self::Vmess(_) => InboundKind::Vmess,
            Self::Vless(_) => InboundKind::Vless,
            Self::Trojan(_) => InboundKind::Trojan,
            Self::Hysteria2(_) => InboundKind::Hysteria2,
            Self::Hysteria2Realm(_) => InboundKind::Hysteria2Realm,
            Self::Tuic(_) => InboundKind::Tuic,
            Self::AnyTls(_) => InboundKind::AnyTls,
            Self::Mieru(_) => InboundKind::Mieru,
            Self::Sudoku(_) => InboundKind::Sudoku,
            Self::TrustTunnel(_) => InboundKind::TrustTunnel,
        }
    }

    pub fn base(&self) -> &BaseInboundConfig {
        match self {
            Self::Socks(config) => &config.base,
            Self::Http(config) => &config.base,
            Self::TProxy(config) => &config.base,
            Self::Redir(config) => &config.base,
            Self::Mixed(config) => &config.base,
            Self::Tunnel(config) => &config.base,
            Self::Tun(config) => &config.base,
            Self::ShadowSocks(config) => &config.base,
            Self::Vmess(config) => &config.base,
            Self::Vless(config) => &config.base,
            Self::Trojan(config) => &config.base,
            Self::Hysteria2(config) => &config.base,
            Self::Hysteria2Realm(config) => &config.base,
            Self::Tuic(config) => &config.base,
            Self::AnyTls(config) => &config.base,
            Self::Mieru(config) => &config.base,
            Self::Sudoku(config) => &config.base,
            Self::TrustTunnel(config) => &config.base,
        }
    }

    pub fn raw_addresses(&self) -> Vec<String> {
        self.base().raw_addresses()
    }
}

pub fn parse_inbound_yaml(input: &str) -> Result<InboundDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-inbound",
    go_areas: &["listener", "adapter/inbound"],
    contracts: &["listener families", "metadata extraction", "packet ingestion"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

fn default_true() -> bool {
    true
}

fn default_dns_hijack() -> Vec<String> {
    vec!["0.0.0.0:53".to_owned()]
}

#[cfg(test)]
mod tests {
    use super::{
        parse_inbound_yaml, InboundDefinition, InboundKind, ShadowSocksInboundConfig,
        SUPPORTED_INBOUNDS, TunStack, TProxyInboundConfig, TlsInboundConfig,
    };

    #[test]
    fn inventory_tracks_listener_parse_surface() {
        assert!(SUPPORTED_INBOUNDS.len() >= 18);
        assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::Tun));
        assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::TProxy));
        assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::ShadowSocks));
        assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::Tuic));
    }

    #[test]
    fn socks_defaults_udp_true_like_listener_parse_go() {
        let parsed = parse_inbound_yaml(
            r#"
type: socks
name: edge
listen: 127.0.0.1
port: "1080"
"#,
        )
        .unwrap();
        let InboundDefinition::Socks(TlsInboundConfig { udp, base, .. }) = parsed else {
            panic!("expected socks config");
        };
        assert!(udp);
        assert_eq!(base.raw_addresses(), vec!["127.0.0.1:1080"]);
    }

    #[test]
    fn tproxy_defaults_udp_true_like_listener_parse_go() {
        let parsed = parse_inbound_yaml(
            r#"
type: tproxy
name: edge
listen: 0.0.0.0
port: "7893"
"#,
        )
        .unwrap();
        let InboundDefinition::TProxy(TProxyInboundConfig { udp, .. }) = parsed else {
            panic!("expected tproxy config");
        };
        assert!(udp);
    }

    #[test]
    fn tun_defaults_match_listener_parse_go() {
        let parsed = parse_inbound_yaml(
            r#"
type: tun
name: edge
"#,
        )
        .unwrap();
        let InboundDefinition::Tun(config) = parsed else {
            panic!("expected tun config");
        };
        assert_eq!(config.stack, TunStack::Gvisor);
        assert_eq!(config.dns_hijack, vec!["0.0.0.0:53"]);
        assert_eq!(config.base.raw_addresses(), vec!["0.0.0.0:0"]);
    }

    #[test]
    fn shadowsocks_defaults_udp_true_and_keeps_modeled_fields() {
        let parsed = parse_inbound_yaml(
            r#"
type: shadowsocks
name: edge
listen: 0.0.0.0
port: "8388"
password: secret
cipher: chacha20-ietf-poly1305
simple-obfs:
  enable: true
  mode: http
"#,
        )
        .unwrap();
        let InboundDefinition::ShadowSocks(ShadowSocksInboundConfig {
            udp,
            password,
            cipher,
            simple_obfs,
            ..
        }) = parsed
        else {
            panic!("expected shadowsocks config");
        };
        assert!(udp);
        assert_eq!(password, "secret");
        assert_eq!(cipher, "chacha20-ietf-poly1305");
        assert!(simple_obfs.enable);
        assert_eq!(simple_obfs.mode, "http");
    }

    #[test]
    fn tunnel_variant_keeps_network_and_target() {
        let parsed = parse_inbound_yaml(
            r#"
type: tunnel
name: edge
listen: 127.0.0.1
port: "9000-9001"
network: [tcp, udp]
target: example.com:443
"#,
        )
        .unwrap();
        let InboundDefinition::Tunnel(config) = parsed else {
            panic!("expected tunnel config");
        };
        assert_eq!(config.network, vec!["tcp", "udp"]);
        assert_eq!(config.target, "example.com:443");
        assert_eq!(
            config.base.raw_addresses(),
            vec!["127.0.0.1:9000", "127.0.0.1:9001"]
        );
    }
}
