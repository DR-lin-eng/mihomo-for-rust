use std::collections::BTreeMap;

use mihomo_config::{GeoXUrlConfig, TuicServerConfig};
use mihomo_inbound::TunInboundConfig;
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiVersion {
    pub meta: bool,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiSnapshot {
    pub version: ApiVersion,
    pub general: ApiGeneralSnapshot,
    pub listeners: Vec<ApiListenerSnapshot>,
    pub proxies: Vec<ApiProxySnapshot>,
    pub groups: Vec<ApiGroupSnapshot>,
    pub proxy_providers: Vec<ApiProxyProviderSnapshot>,
    pub rule_providers: Vec<ApiRuleProviderSnapshot>,
    pub rules: Vec<ApiRuleSnapshot>,
    pub dns: ApiDnsSnapshot,
    pub tun: ApiTunSnapshot,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApiGeneralSnapshot {
    pub port: u16,
    #[serde(rename = "socks-port")]
    pub socks_port: u16,
    #[serde(rename = "redir-port")]
    pub redir_port: u16,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: u16,
    #[serde(rename = "mixed-port")]
    pub mixed_port: u16,
    #[serde(rename = "ss-config")]
    pub shadow_socks_config: String,
    #[serde(rename = "vmess-config")]
    pub vmess_config: String,
    pub authentication: Vec<String>,
    #[serde(rename = "skip-auth-prefixes")]
    pub skip_auth_prefixes: Vec<String>,
    #[serde(rename = "lan-allowed-ips")]
    pub lan_allowed_ips: Vec<String>,
    #[serde(rename = "lan-disallowed-ips")]
    pub lan_disallowed_ips: Vec<String>,
    pub mode: String,
    #[serde(rename = "unified-delay")]
    pub unified_delay: bool,
    #[serde(rename = "log-level")]
    pub log_level: String,
    #[serde(rename = "allow-lan")]
    pub allow_lan: bool,
    #[serde(rename = "bind-address")]
    pub bind_address: String,
    #[serde(rename = "inbound-tfo")]
    pub inbound_tfo: bool,
    #[serde(rename = "inbound-mptcp")]
    pub inbound_mptcp: bool,
    pub ipv6: bool,
    #[serde(rename = "interface-name")]
    pub interface_name: String,
    #[serde(rename = "routing-mark")]
    pub routing_mark: i32,
    #[serde(rename = "geox-url")]
    pub geox_url: GeoXUrlConfig,
    #[serde(rename = "geo-auto-update")]
    pub geo_auto_update: bool,
    #[serde(rename = "geo-update-interval")]
    pub geo_update_interval: i32,
    #[serde(rename = "geodata-mode")]
    pub geodata_mode: bool,
    #[serde(rename = "geodata-loader")]
    pub geodata_loader: String,
    #[serde(rename = "geosite-matcher")]
    pub geosite_matcher: String,
    #[serde(rename = "tcp-concurrent")]
    pub tcp_concurrent: bool,
    #[serde(rename = "find-process-mode")]
    pub find_process_mode: String,
    pub sniffing: bool,
    #[serde(rename = "global-client-fingerprint")]
    pub global_client_fingerprint: String,
    #[serde(rename = "global-ua")]
    pub global_ua: String,
    #[serde(rename = "etag-support")]
    pub etag_support: bool,
    #[serde(rename = "keep-alive-idle")]
    pub keep_alive_idle: i32,
    #[serde(rename = "keep-alive-interval")]
    pub keep_alive_interval: i32,
    #[serde(rename = "disable-keep-alive")]
    pub disable_keep_alive: bool,
    #[serde(rename = "external-controller")]
    pub external_controller: String,
    #[serde(rename = "external-controller-tls")]
    pub external_controller_tls: String,
    #[serde(rename = "external-controller-unix")]
    pub external_controller_unix: String,
    #[serde(rename = "external-controller-pipe")]
    pub external_controller_pipe: String,
    #[serde(rename = "external-ui")]
    pub external_ui: String,
    #[serde(rename = "external-ui-url")]
    pub external_ui_url: String,
    #[serde(rename = "external-ui-name")]
    pub external_ui_name: String,
    #[serde(rename = "tuic-server")]
    pub tuic_server: TuicServerConfig,
    pub tun: ApiGeneralTunSnapshot,
    pub listener_count: usize,
    pub proxy_count: usize,
    pub group_count: usize,
    pub provider_count: usize,
    pub ebpf: mihomo_config::EbpfConfig,
    #[serde(rename="lgbm-auto-update")]
    pub lgbm_auto_update: bool,
    #[serde(rename="lgbm-update-interval")]
    pub lgbm_update_interval: u64,
    #[serde(rename="lgbm-url")]
    pub lgbm_url: String,
    #[serde(rename="smart-collector-size")]
    pub smart_collector_size: f64,
}

impl Eq for ApiGeneralSnapshot {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiGeneralTunSnapshot {
    pub enable: bool,
    #[serde(flatten)]
    pub config: TunInboundConfig,
}
impl std::ops::Deref for ApiGeneralTunSnapshot {
    type Target = TunInboundConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiListenerSnapshot {
    pub name: String,
    pub kind: String,
    pub addresses: Vec<String>,
    pub origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiProxySnapshot {
    pub name: String,
    #[serde(rename = "type")]
    #[serde(serialize_with = "serialize_adapter_type")]
    pub proxy_type: String,
    pub alive: bool,
    pub history: Vec<ApiDelayHistorySnapshot>,
    pub extra: BTreeMap<String, ApiProxyStateSnapshot>,
    pub udp: bool,
    pub uot: bool,
    pub xudp: bool,
    pub tfo: bool,
    pub mptcp: bool,
    pub smux: bool,
    #[serde(rename = "interface")]
    pub interface_name: String,
    #[serde(rename = "routing-mark")]
    pub routing_mark: i32,
    #[serde(rename = "provider-name")]
    pub provider_name: String,
    #[serde(rename = "dialer-proxy")]
    pub dialer_proxy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiDelayHistorySnapshot {
    pub time: String,
    pub delay: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiProxyStateSnapshot {
    pub alive: bool,
    pub history: Vec<ApiDelayHistorySnapshot>,
    #[serde(rename = "lastError")]
    pub last_error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiGroupSnapshot {
    pub common: ApiProxySnapshot,
    pub smart: Option<mihomo_runtime::smart::SmartOptions>,
    pub name: String,
    pub group_type: String,
    pub candidates: Vec<String>,
    pub selected: Option<String>,
    pub test_url: String,
    pub expected_status: String,
    pub fixed: Option<String>,
    pub hidden: bool,
    pub icon: String,
}

impl Serialize for ApiGroupSnapshot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("type", adapter_type_name(&self.group_type))?;
        map.serialize_entry("all", &self.candidates)?;
        map.serialize_entry("now", &self.selected)?;
        map.serialize_entry("testUrl", &self.test_url)?;
        if self.group_type != "select" {
            map.serialize_entry("expectedStatus", &self.expected_status)?;
        }
        if matches!(self.group_type.as_str(), "url-test" | "fallback" | "smart") {
            map.serialize_entry("fixed", &self.fixed)?;
        }
        if let Some(options) = &self.smart {
            map.serialize_entry("policy-priority", &options.policy_priority)?;
            map.serialize_entry("useLightGBM", &options.use_lightgbm)?;
            map.serialize_entry("collectData", &options.collect_data)?;
            map.serialize_entry("sampleRate", &options.sample_rate())?;
            map.serialize_entry("preferASN", &options.prefer_asn)?;
            map.serialize_entry("tolerance", &options.tolerance_ms)?;
        }
        map.serialize_entry("emptyFallback", "COMPATIBLE")?;
        map.serialize_entry("hidden", &self.hidden)?;
        map.serialize_entry("icon", &self.icon)?;
        map.serialize_entry("alive", &self.common.alive)?;
        map.serialize_entry("history", &self.common.history)?;
        map.serialize_entry("extra", &self.common.extra)?;
        map.serialize_entry("udp", &self.common.udp)?;
        map.serialize_entry("xudp", &self.common.xudp)?;
        map.serialize_entry("uot", &self.common.uot)?;
        map.serialize_entry("interface", &self.common.interface_name)?;
        map.serialize_entry("routing-mark", &self.common.routing_mark)?;
        map.serialize_entry("provider-name", &self.common.provider_name)?;
        map.serialize_entry("dialer-proxy", &self.common.dialer_proxy)?;
        map.serialize_entry("tfo", &self.common.tfo)?;
        map.serialize_entry("mptcp", &self.common.mptcp)?;
        map.serialize_entry("smux", &self.common.smux)?;
        map.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiProxyProviderSnapshot {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(rename = "vehicleType")]
    pub vehicle_type: String,
    pub proxies: Vec<ApiProxySnapshot>,
    #[serde(rename = "testUrl")]
    pub test_url: String,
    #[serde(rename = "expectedStatus")]
    pub expected_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiRuleProviderSnapshot {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(rename = "vehicleType")]
    pub vehicle_type: String,
    pub behavior: String,
    pub format: String,
    #[serde(rename = "ruleCount")]
    pub rule_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiRuleSnapshot {
    pub index: usize,
    #[serde(rename = "type")]
    #[serde(serialize_with = "serialize_rule_type")]
    pub rule_type: String,
    pub payload: String,
    #[serde(rename = "proxy")]
    pub target: String,
    pub size: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<ApiRuleExtraSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiRuleExtraSnapshot {
    pub disabled: bool,
    #[serde(rename = "hitCount")]
    pub hit_count: u64,
    #[serde(rename = "hitAt")]
    pub hit_at: String,
    #[serde(rename = "missCount")]
    pub miss_count: u64,
    #[serde(rename = "missAt")]
    pub miss_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiDnsSnapshot {
    pub enabled: bool,
    pub listen: String,
    pub enhanced_mode: String,
    pub use_hosts: bool,
    pub nameserver_count: usize,
    pub default_nameserver_count: usize,
    pub fallback_count: usize,
    pub cache_algorithm: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiTunSnapshot {
    pub enabled: bool,
    pub spec_count: usize,
    pub stacks: Vec<String>,
    pub dns_hijack_entries: usize,
    pub auto_route: bool,
    pub auto_redirect: bool,
}

// Configuration spellings are lowercase; the Clash controller uses the Go
// AdapterType.String() names. Dashboards use these names to identify groups.
fn serialize_adapter_type<S: serde::Serializer>(
    value: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(adapter_type_name(value))
}

fn adapter_type_name(value: &str) -> &str {
    match value {
        "direct" => "Direct",
        "reject" => "Reject",
        "reject-drop" => "RejectDrop",
        "compatible" => "Compatible",
        "pass" => "Pass",
        "dns" => "Dns",
        "ss" => "Shadowsocks",
        "ssr" => "ShadowsocksR",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "socks5" => "Socks5",
        "http" => "Http",
        "trojan" => "Trojan",
        "snell" => "Snell",
        "hysteria" => "Hysteria",
        "hysteria2" | "hy2" => "Hysteria2",
        "wireguard" => "WireGuard",
        "tuic" => "Tuic",
        "ssh" => "Ssh",
        "mieru" => "Mieru",
        "anytls" => "AnyTLS",
        "sudoku" => "Sudoku",
        "masque" => "Masque",
        "trusttunnel" => "TrustTunnel",
        "openvpn" => "OpenVPN",
        "tailscale" => "Tailscale",
        "gost-relay" => "GostRelay",
        "select" => "Selector",
        "url-test" => "URLTest",
        "fallback" => "Fallback",
        "load-balance" => "LoadBalance",
        "smart" => "Smart",
        "relay" => "Relay",
        name => name,
    }
}

fn serialize_rule_type<S: serde::Serializer>(
    value: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(controller_rule_type_name(value))
}

pub(crate) fn controller_rule_type_name(value: &str) -> &str {
    match value {
        "DOMAIN" => "Domain",
        "DOMAIN-SUFFIX" => "DomainSuffix",
        "DOMAIN-KEYWORD" => "DomainKeyword",
        "DOMAIN-REGEX" => "DomainRegex",
        "DOMAIN-WILDCARD" => "DomainWildcard",
        "GEOSITE" => "GeoSite",
        "GEOIP" => "GeoIP",
        "SRC-GEOIP" => "SrcGeoIP",
        "IP-ASN" => "IPASN",
        "SRC-IP-ASN" => "SrcIPASN",
        "IP-CIDR" | "IP-CIDR6" => "IPCIDR",
        "SRC-IP-CIDR" => "SrcIPCIDR",
        "IP-SUFFIX" => "IPSuffix",
        "SRC-IP-SUFFIX" => "SrcIPSuffix",
        "SRC-PORT" => "SrcPort",
        "DST-PORT" => "DstPort",
        "IN-PORT" => "InPort",
        "IN-USER" => "InUser",
        "IN-NAME" => "InName",
        "IN-TYPE" => "InType",
        "PROCESS-NAME" => "ProcessName",
        "PROCESS-PATH" => "ProcessPath",
        "PROCESS-NAME-REGEX" => "ProcessNameRegex",
        "PROCESS-PATH-REGEX" => "ProcessPathRegex",
        "PROCESS-NAME-WILDCARD" => "ProcessNameWildcard",
        "PROCESS-PATH-WILDCARD" => "ProcessPathWildcard",
        "MATCH" => "Match",
        "RULE-SET" => "RuleSet",
        "NETWORK" => "Network",
        "UID" => "Uid",
        "SUB-RULE" => "SubRules",
        name => name,
    }
}
