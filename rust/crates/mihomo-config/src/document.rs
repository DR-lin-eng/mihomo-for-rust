use std::collections::BTreeMap;

use mihomo_inbound::{InboundDefinition, TunInboundConfig};
use mihomo_outbound::{GroupDefinition, OutboundDefinition, ProxyProviderDefinition};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

fn default_mode() -> String {
    "rule".to_owned()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleProviderBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl RuleProviderBehavior {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::IpCidr => "ipcidr",
            Self::Classical => "classical",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleProviderVehicleType {
    File,
    Http,
    Inline,
}

impl RuleProviderVehicleType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Http => "http",
            Self::Inline => "inline",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleProviderFormat {
    Yaml,
    Text,
    Mrs,
}

impl RuleProviderFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Text => "text",
            Self::Mrs => "mrs",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeoXUrlConfig {
    #[serde(default, rename = "geoip")]
    pub geoip: String,
    #[serde(default, rename = "mmdb")]
    pub mmdb: String,
    #[serde(default, rename = "asn")]
    pub asn: String,
    #[serde(default, rename = "geosite")]
    pub geosite: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TuicServerConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(default, rename = "listen")]
    pub listen: String,
    #[serde(default, rename = "token")]
    pub token: Vec<String>,
    #[serde(default, rename = "users")]
    pub users: BTreeMap<String, String>,
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
    #[serde(default, rename = "congestion-controller")]
    pub congestion_controller: String,
    #[serde(default, rename = "max-idle-time")]
    pub max_idle_time: i32,
    #[serde(default, rename = "authentication-timeout")]
    pub authentication_timeout: i32,
    #[serde(default, rename = "alpn")]
    pub alpn: Vec<String>,
    #[serde(default, rename = "max-udp-relay-packet-size")]
    pub max_udp_relay_packet_size: i32,
    #[serde(default, rename = "max-datagram-frame-size")]
    pub max_datagram_frame_size: i32,
    #[serde(default, rename = "cwnd")]
    pub cwnd: i32,
    #[serde(default, rename = "bbr-profile")]
    pub bbr_profile: String,
    #[serde(default, rename = "mux-option")]
    pub mux_option: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TopLevelProfileConfig {
    #[serde(default, rename = "store-selected")]
    pub store_selected: bool,
    #[serde(default, rename = "store-fake-ip")]
    pub store_fake_ip: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnifferProtocolConfig {
    #[serde(default, rename = "ports", deserialize_with = "deserialize_string_list")]
    pub ports: Vec<String>,
    #[serde(default, rename = "override-destination")]
    pub override_destination: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TopLevelSnifferConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(default, rename = "override-destination")]
    pub override_destination: bool,
    #[serde(default, rename = "force-dns-mapping")]
    pub force_dns_mapping: bool,
    #[serde(default, rename = "parse-pure-ip")]
    pub parse_pure_ip: bool,
    #[serde(default, rename = "sniffing")]
    pub sniffing: Vec<String>,
    #[serde(default, rename = "force-domain")]
    pub force_domain: Vec<String>,
    #[serde(default, rename = "skip-src-address")]
    pub skip_src_address: Vec<String>,
    #[serde(default, rename = "skip-dst-address")]
    pub skip_dst_address: Vec<String>,
    #[serde(default, rename = "skip-domain")]
    pub skip_domain: Vec<String>,
    #[serde(default, rename = "port-whitelist")]
    pub port_whitelist: Vec<String>,
    #[serde(default, rename = "sniff")]
    pub sniff: BTreeMap<String, SnifferProtocolConfig>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Legacy Clash TC eBPF configuration. Programs are attached only when lists are nonempty.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EbpfConfig {
    #[serde(default, rename="redirect-to-tun")]
    pub redirect_to_tun: Vec<String>,
    #[serde(default, rename="auto-redir")]
    pub auto_redir: Vec<String>,
    #[serde(default, rename="bypass-mark")]
    pub bypass_mark: u32,
}
impl EbpfConfig {
    pub fn enabled(&self)->bool { !self.redirect_to_tun.is_empty() || !self.auto_redir.is_empty() }
    pub fn effective_bypass_mark(&self)->u32 { if self.bypass_mark==0 { 0x636c746d } else { self.bypass_mark } }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RuntimeConfigDocument {
    #[serde(default, rename = "port")]
    pub port: u16,
    #[serde(default, rename = "socks-port")]
    pub socks_port: u16,
    #[serde(default, rename = "redir-port")]
    pub redir_port: u16,
    #[serde(default, rename = "tproxy-port")]
    pub tproxy_port: u16,
    #[serde(default, rename = "mixed-port")]
    pub mixed_port: u16,
    #[serde(default, rename = "ss-config")]
    pub shadow_socks_config: String,
    #[serde(default, rename = "vmess-config")]
    pub vmess_config: String,
    #[serde(default, rename = "allow-lan")]
    pub allow_lan: bool,
    #[serde(default, rename = "bind-address")]
    pub bind_address: String,
    #[serde(default, rename = "authentication")]
    pub authentication: Vec<String>,
    #[serde(default, rename = "skip-auth-prefixes")]
    pub skip_auth_prefixes: Vec<String>,
    #[serde(default, rename = "lan-allowed-ips")]
    pub lan_allowed_ips: Vec<String>,
    #[serde(default, rename = "lan-disallowed-ips")]
    pub lan_disallowed_ips: Vec<String>,
    #[serde(default, rename = "inbound-tfo")]
    pub inbound_tfo: bool,
    #[serde(default, rename = "inbound-mptcp")]
    pub inbound_mptcp: bool,
    #[serde(default = "default_mode", rename = "mode")]
    pub mode: String,
    #[serde(default, rename = "unified-delay")]
    pub unified_delay: bool,
    #[serde(default, rename = "log-level")]
    pub log_level: String,
    #[serde(default, rename = "ipv6")]
    pub ipv6: bool,
    #[serde(default, rename = "interface-name")]
    pub interface_name: String,
    #[serde(default, rename = "routing-mark")]
    pub routing_mark: i32,
    #[serde(default, rename = "geox-url")]
    pub geox_url: GeoXUrlConfig,
    #[serde(default, rename = "geo-auto-update")]
    pub geo_auto_update: bool,
    #[serde(default, rename = "geo-update-interval")]
    pub geo_update_interval: i32,
    #[serde(default, rename = "geodata-mode")]
    pub geodata_mode: bool,
    #[serde(default, rename = "geodata-loader")]
    pub geodata_loader: String,
    #[serde(default, rename = "geosite-matcher")]
    pub geosite_matcher: String,
    #[serde(default, rename = "tcp-concurrent")]
    pub tcp_concurrent: bool,
    #[serde(default, rename = "find-process-mode")]
    pub find_process_mode: String,
    #[serde(default, rename = "global-client-fingerprint")]
    pub global_client_fingerprint: String,
    #[serde(default, rename = "global-ua")]
    pub global_ua: String,
    #[serde(default, rename = "etag-support")]
    pub etag_support: bool,
    #[serde(default, rename = "keep-alive-idle")]
    pub keep_alive_idle: i32,
    #[serde(default, rename = "keep-alive-interval")]
    pub keep_alive_interval: i32,
    #[serde(default, rename = "disable-keep-alive")]
    pub disable_keep_alive: bool,
    #[serde(default, rename = "external-controller")]
    pub external_controller: String,
    #[serde(default, rename = "external-controller-tls")]
    pub external_controller_tls: String,
    #[serde(default, rename = "external-controller-unix")]
    pub external_controller_unix: String,
    #[serde(default, rename = "external-controller-pipe")]
    pub external_controller_pipe: String,
    #[serde(default, rename = "external-ui")]
    pub external_ui: String,
    #[serde(default, rename = "external-ui-url")]
    pub external_ui_url: String,
    #[serde(default, rename = "external-ui-name")]
    pub external_ui_name: String,
    #[serde(default, rename = "external-doh-server")]
    pub external_doh_server: String,
    #[serde(default, rename = "secret")]
    pub secret: String,
    #[serde(default, rename = "profile")]
    pub profile: TopLevelProfileConfig,
    #[serde(default, rename = "tuic-server")]
    pub tuic_server: TuicServerConfig,
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<OutboundDefinition>,
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<GroupDefinition>,
    #[serde(default, rename = "proxy-providers")]
    pub proxy_providers: BTreeMap<String, ProxyProviderDefinition>,
    #[serde(default, rename = "rule-providers")]
    pub rule_providers: BTreeMap<String, RuleProviderDefinition>,
    #[serde(default, rename = "listeners")]
    pub listeners: Vec<InboundDefinition>,
    #[serde(default, rename = "rules")]
    pub rules: Vec<String>,
    #[serde(default, rename = "sub-rules")]
    pub sub_rules: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "tun")]
    pub tun: TopLevelTunConfig,
    #[serde(default, rename="ebpf")]
    pub ebpf: EbpfConfig,
    #[serde(default, rename = "hosts")]
    pub hosts: BTreeMap<String, HostMappingValue>,
    #[serde(default, rename = "dns")]
    pub dns: TopLevelDnsConfig,
    #[serde(default, rename = "sniffer")]
    pub sniffer: TopLevelSnifferConfig,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TopLevelTunConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(flatten)]
    pub config: TunInboundConfig,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct HostMappingValue {
    pub values: Vec<String>,
}

impl<'de> Deserialize<'de> for HostMappingValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(text) => Ok(Self { values: vec![text] }),
            Value::Sequence(sequence) => {
                let values = sequence
                    .into_iter()
                    .map(|item| match item {
                        Value::String(text) => Ok(text),
                        other => Err(serde::de::Error::custom(format!(
                            "hosts sequence entry must be string, got {other:?}"
                        ))),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self { values })
            }
            other => Err(serde::de::Error::custom(format!(
                "hosts entry must be string or sequence, got {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StringOrList {
    pub values: Vec<String>,
}

impl<'de> Deserialize<'de> for StringOrList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(text) => Ok(Self { values: vec![text] }),
            Value::Sequence(sequence) => {
                let values = sequence
                    .into_iter()
                    .map(|item| match item {
                        Value::String(text) => Ok(text),
                        other => Err(serde::de::Error::custom(format!(
                            "sequence entry must be string, got {other:?}"
                        ))),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self { values })
            }
            other => Err(serde::de::Error::custom(format!(
                "value must be string or sequence, got {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DnsFallbackFilterConfig {
    #[serde(default, rename = "geoip")]
    pub geoip: bool,
    #[serde(default, rename = "geoip-code")]
    pub geoip_code: String,
    #[serde(default, rename = "ipcidr")]
    pub ipcidr: Vec<String>,
    #[serde(default, rename = "domain")]
    pub domain: Vec<String>,
    #[serde(default, rename = "geosite")]
    pub geosite: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TopLevelDnsConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(default, rename = "listen")]
    pub listen: String,
    #[serde(default, rename = "use-system-hosts")]
    pub use_system_hosts: bool,
    #[serde(default, rename = "enhanced-mode")]
    pub enhanced_mode: String,
    #[serde(default, rename = "fake-ip-range")]
    pub fake_ip_range: String,
    #[serde(default, rename = "fake-ip-range6")]
    pub fake_ip_range6: String,
    #[serde(default, rename = "fake-ip-filter")]
    pub fake_ip_filter: Vec<String>,
    #[serde(default, rename = "fake-ip-filter-mode")]
    pub fake_ip_filter_mode: String,
    #[serde(default, rename = "fake-ip-ttl")]
    pub fake_ip_ttl: i32,
    #[serde(default, rename = "use-hosts")]
    pub use_hosts: bool,
    #[serde(default, rename = "respect-rules")]
    pub respect_rules: bool,
    #[serde(default, rename = "cache-algorithm")]
    pub cache_algorithm: String,
    #[serde(default, rename = "default-nameserver")]
    pub default_nameserver: Vec<String>,
    #[serde(default, rename = "nameserver")]
    pub nameserver: Vec<String>,
    #[serde(default, rename = "fallback")]
    pub fallback: Vec<String>,
    #[serde(default, rename = "fallback-filter")]
    pub fallback_filter: DnsFallbackFilterConfig,
    #[serde(default, rename = "nameserver-policy")]
    pub nameserver_policy: BTreeMap<String, StringOrList>,
    #[serde(default, rename = "proxy-server-nameserver")]
    pub proxy_server_nameserver: Vec<String>,
    #[serde(default, rename = "proxy-server-nameserver-policy")]
    pub proxy_server_nameserver_policy: BTreeMap<String, StringOrList>,
    #[serde(default, rename = "direct-nameserver")]
    pub direct_nameserver: Vec<String>,
    #[serde(default, rename = "direct-nameserver-follow-policy")]
    pub direct_nameserver_follow_policy: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleProviderDefinition {
    #[serde(default, rename = "type")]
    pub provider_type: String,
    #[serde(default, rename = "behavior")]
    pub behavior: String,
    #[serde(default, rename = "format")]
    pub format: String,
    #[serde(default, rename = "path")]
    pub path: String,
    #[serde(default, rename = "url")]
    pub url: String,
    #[serde(default, rename = "proxy")]
    pub proxy: String,
    #[serde(default, rename = "interval")]
    pub interval: i32,
    #[serde(default, rename = "size-limit")]
    pub size_limit: i64,
    #[serde(default, rename = "payload")]
    pub payload: Vec<String>,
    #[serde(default, rename = "header")]
    pub header: BTreeMap<String, Vec<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl RuleProviderDefinition {
    pub fn vehicle_type(&self) -> Option<RuleProviderVehicleType> {
        match self.provider_type.as_str() {
            "file" => Some(RuleProviderVehicleType::File),
            "http" => Some(RuleProviderVehicleType::Http),
            "inline" => Some(RuleProviderVehicleType::Inline),
            _ => None,
        }
    }

    pub fn behavior_kind(&self) -> Option<RuleProviderBehavior> {
        match self.behavior.as_str() {
            "domain" => Some(RuleProviderBehavior::Domain),
            "ipcidr" => Some(RuleProviderBehavior::IpCidr),
            "classical" => Some(RuleProviderBehavior::Classical),
            _ => None,
        }
    }

    pub fn format_kind(&self) -> Option<RuleProviderFormat> {
        match self.format.as_str() {
            "" | "yaml" => Some(RuleProviderFormat::Yaml),
            "text" => Some(RuleProviderFormat::Text),
            "mrs" => Some(RuleProviderFormat::Mrs),
            _ => None,
        }
    }
}

pub fn parse_runtime_config_document(
    input: &str,
) -> Result<RuntimeConfigDocument, serde_yaml::Error> {
    let mut value = serde_yaml::from_str::<Value>(input)?;
    expand_yaml_merge_keys(&mut value);
    let mut document:RuntimeConfigDocument=serde_yaml::from_value(value)?;
    if !document.ebpf.auto_redir.is_empty() && document.redir_port==0 { document.redir_port=29810; }
    Ok(document)
}

fn expand_yaml_merge_keys(value: &mut Value) {
    match value {
        Value::Mapping(mapping) => expand_yaml_mapping_merge_keys(mapping),
        Value::Sequence(sequence) => {
            for item in sequence {
                expand_yaml_merge_keys(item);
            }
        }
        _ => {}
    }
}

fn expand_yaml_mapping_merge_keys(mapping: &mut serde_yaml::Mapping) {
    for value in mapping.values_mut() {
        expand_yaml_merge_keys(value);
    }

    let merge_key = Value::String("<<".to_owned());
    let Some(mut merge_value) = mapping.remove(&merge_key) else {
        return;
    };
    expand_yaml_merge_keys(&mut merge_value);

    let mut merged_entries = Vec::new();
    collect_merged_mapping_entries(&merge_value, &mut merged_entries);
    for (key, value) in merged_entries {
        mapping.entry(key).or_insert(value);
    }
}

fn collect_merged_mapping_entries(value: &Value, entries: &mut Vec<(Value, Value)>) {
    match value {
        Value::Mapping(mapping) => {
            for (key, value) in mapping {
                entries.push((key.clone(), value.clone()));
            }
        }
        Value::Sequence(sequence) => {
            for item in sequence {
                collect_merged_mapping_entries(item, entries);
            }
        }
        _ => {}
    }
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<Value>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| match value {
            Value::String(value) => Ok(value),
            Value::Number(value) => Ok(value.to_string()),
            Value::Bool(value) => Ok(value.to_string()),
            other => Err(serde::de::Error::custom(format!(
                "invalid string list item: {other:?}"
            ))),
        })
        .collect()
}
