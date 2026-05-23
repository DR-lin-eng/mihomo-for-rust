use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::collections::BTreeSet;

use mihomo_inbound::{InboundDefinition, TunInboundConfig};
use mihomo_outbound::{GroupDefinition, OutboundDefinition, ProxyProviderDefinition};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Run,
    ConvertRuleset(Vec<String>),
    Generate(Vec<String>),
}

impl Default for Command {
    fn default() -> Self {
        Self::Run
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootOptions {
    pub home_dir: Option<String>,
    pub config_file: Option<String>,
    pub config_base64: Option<String>,
    pub external_ui: Option<String>,
    pub external_controller: Option<String>,
    pub external_controller_unix: Option<String>,
    pub external_controller_pipe: Option<String>,
    pub secret: Option<String>,
    pub post_up: Option<String>,
    pub post_down: Option<String>,
    pub geodata_mode: bool,
    pub show_version: bool,
    pub test_config: bool,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    MissingValue(&'static str),
    UnexpectedPositional(String),
    UnknownFlag(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue(flag) => write!(f, "missing value for flag {flag}"),
            Self::UnexpectedPositional(value) => write!(f, "unexpected positional argument: {value}"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigSource {
    File(PathBuf),
    Stdin,
    Base64(String),
}

impl ConfigSource {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Stdin => "stdin",
            Self::Base64(_) => "base64",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedBoot {
    pub home_dir: PathBuf,
    pub config_source: ConfigSource,
    pub command: Command,
    pub geodata_mode: bool,
    pub show_version: bool,
    pub test_config: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootEnvironment {
    pub user_home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
}

impl BootEnvironment {
    pub fn from_process() -> Self {
        Self {
            user_home: std::env::var_os("HOME").map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
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
pub struct SnifferProtocolConfig {
    #[serde(default, rename = "ports")]
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
    #[serde(default, rename = "mode")]
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
    #[serde(default, rename = "tuic-server")]
    pub tuic_server: TuicServerConfig,
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<OutboundDefinition>,
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<GroupDefinition>,
    #[serde(default, rename = "proxy-providers")]
    pub proxy_providers: std::collections::BTreeMap<String, ProxyProviderDefinition>,
    #[serde(default, rename = "rule-providers")]
    pub rule_providers: std::collections::BTreeMap<String, RuleProviderDefinition>,
    #[serde(default, rename = "listeners")]
    pub listeners: Vec<InboundDefinition>,
    #[serde(default, rename = "rules")]
    pub rules: Vec<String>,
    #[serde(default, rename = "sub-rules")]
    pub sub_rules: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "tun")]
    pub tun: TopLevelTunConfig,
    #[serde(default, rename = "hosts")]
    pub hosts: BTreeMap<String, HostMappingValue>,
    #[serde(default, rename = "dns")]
    pub dns: TopLevelDnsConfig,
    #[serde(default, rename = "sniffer")]
    pub sniffer: TopLevelSnifferConfig,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TopLevelTunConfig {
    #[serde(default, rename = "enable")]
    pub enable: bool,
    #[serde(flatten)]
    pub config: TunInboundConfig,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigValidationError {
    DuplicateProxyName(String),
    DuplicateProxyGroupName(String),
    DuplicateListenerName(String),
    ReservedProviderName(String),
    ProxyGroupMissingName(usize),
    UnsupportedProxyGroupType(String),
    ProxyGroupReferenceNotFound { group: String, reference: String },
    ProviderVehicleUnsupported { provider: String, vehicle_type: String },
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProxyName(name) => write!(f, "proxy {name} is the duplicate name"),
            Self::DuplicateProxyGroupName(name) => {
                write!(f, "proxy group {name}: the duplicate name")
            }
            Self::DuplicateListenerName(name) => write!(f, "listener {name} is the duplicate name"),
            Self::ReservedProviderName(name) => {
                write!(f, "can not defined a provider called `{name}`")
            }
            Self::ProxyGroupMissingName(index) => write!(f, "proxy group {index}: missing name"),
            Self::UnsupportedProxyGroupType(name) => write!(
                f,
                "unsupported proxy group type or removed group behavior: {name}"
            ),
            Self::ProxyGroupReferenceNotFound { group, reference } => {
                write!(f, "proxy group {group}: '{reference}' not found")
            }
            Self::ProviderVehicleUnsupported { provider, vehicle_type } => write!(
                f,
                "parse proxy provider {provider} error: unsupport vehicle type: {vehicle_type}"
            ),
        }
    }
}

impl std::error::Error for ConfigValidationError {}

pub fn parse_args<I, S>(args: I) -> Result<BootOptions, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();

    let mut options = BootOptions::default();
    let mut pending = iter.next();

    if let Some(command) = pending.clone() {
        match command.as_str() {
            "convert-ruleset" => {
                options.command = Command::ConvertRuleset(iter.collect());
                return Ok(options);
            }
            "generate" => {
                options.command = Command::Generate(iter.collect());
                return Ok(options);
            }
            _ => {}
        }
    }

    while let Some(arg) = pending.take().or_else(|| iter.next()) {
        match arg.as_str() {
            "-d" => options.home_dir = Some(next_value("-d", &mut iter)?),
            "-f" => options.config_file = Some(next_value("-f", &mut iter)?),
            "-config" => options.config_base64 = Some(next_value("-config", &mut iter)?),
            "-ext-ui" => options.external_ui = Some(next_value("-ext-ui", &mut iter)?),
            "-ext-ctl" => {
                options.external_controller = Some(next_value("-ext-ctl", &mut iter)?)
            }
            "-ext-ctl-unix" => {
                options.external_controller_unix = Some(next_value("-ext-ctl-unix", &mut iter)?)
            }
            "-ext-ctl-pipe" => {
                options.external_controller_pipe = Some(next_value("-ext-ctl-pipe", &mut iter)?)
            }
            "-secret" => options.secret = Some(next_value("-secret", &mut iter)?),
            "-post-up" => options.post_up = Some(next_value("-post-up", &mut iter)?),
            "-post-down" => options.post_down = Some(next_value("-post-down", &mut iter)?),
            "-m" => options.geodata_mode = true,
            "-v" => options.show_version = true,
            "-t" => options.test_config = true,
            value if value.starts_with('-') => return Err(ParseError::UnknownFlag(value.to_owned())),
            value => return Err(ParseError::UnexpectedPositional(value.to_owned())),
        }
    }

    Ok(options)
}

pub fn parse_runtime_config_document(input: &str) -> Result<RuntimeConfigDocument, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::ConvertRuleset(_) => "convert-ruleset",
            Self::Generate(_) => "generate",
        }
    }
}

impl ResolvedBoot {
    pub fn config_display_path(&self) -> PathBuf {
        match &self.config_source {
            ConfigSource::File(path) => path.clone(),
            ConfigSource::Base64(_) | ConfigSource::Stdin => self.home_dir.join("config.yaml"),
        }
    }
}

impl BootOptions {
    pub fn resolve(&self, cwd: &Path, env: &BootEnvironment) -> ResolvedBoot {
        let home_dir = resolve_home_dir(self.home_dir.as_deref(), cwd, env);
        let config_source = resolve_config_source(self, cwd, &home_dir);
        ResolvedBoot {
            home_dir,
            config_source,
            command: self.command.clone(),
            geodata_mode: self.geodata_mode,
            show_version: self.show_version,
            test_config: self.test_config,
        }
    }
}

impl RuntimeConfigDocument {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        let mut seen_proxy_names = BTreeSet::new();
        for proxy in &self.proxies {
            let name = proxy.name().to_owned();
            if !seen_proxy_names.insert(name.clone()) {
                return Err(ConfigValidationError::DuplicateProxyName(name));
            }
        }

        let mut available_proxy_refs: BTreeSet<String> = [
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "COMPATIBLE",
            "PASS",
            "GLOBAL",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        available_proxy_refs.extend(seen_proxy_names.iter().cloned());

        for (name, provider) in &self.proxy_providers {
            if name == "default" {
                return Err(ConfigValidationError::ReservedProviderName(name.clone()));
            }
            if provider.vehicle_type().is_none() {
                return Err(ConfigValidationError::ProviderVehicleUnsupported {
                    provider: name.clone(),
                    vehicle_type: provider.provider_type.clone(),
                });
            }
        }

        let all_group_names = self
            .proxy_groups
            .iter()
            .map(|group| group.name.clone())
            .collect::<Vec<_>>();
        let all_group_name_set = all_group_names.iter().cloned().collect::<BTreeSet<_>>();

        let mut seen_group_names = BTreeSet::new();
        for (index, group) in self.proxy_groups.iter().enumerate() {
            if group.name.is_empty() {
                return Err(ConfigValidationError::ProxyGroupMissingName(index));
            }
            if group.group_type == "relay" || group.kind().is_none() {
                return Err(ConfigValidationError::UnsupportedProxyGroupType(
                    group.group_type.clone(),
                ));
            }
            if !seen_group_names.insert(group.name.clone()) || available_proxy_refs.contains(&group.name)
            {
                return Err(ConfigValidationError::DuplicateProxyGroupName(group.name.clone()));
            }
            for reference in &group.proxies {
                if !available_proxy_refs.contains(reference) && !all_group_name_set.contains(reference) {
                    return Err(ConfigValidationError::ProxyGroupReferenceNotFound {
                        group: group.name.clone(),
                        reference: reference.clone(),
                    });
                }
            }
            for provider_name in &group.use_providers {
                if !self.proxy_providers.contains_key(provider_name) {
                    return Err(ConfigValidationError::ProxyGroupReferenceNotFound {
                        group: group.name.clone(),
                        reference: provider_name.clone(),
                    });
                }
            }
        }

        let mut seen_listener_names = BTreeSet::new();
        for listener in &self.listeners {
            let name = listener.base().name.clone();
            if !seen_listener_names.insert(name.clone()) {
                return Err(ConfigValidationError::DuplicateListenerName(name));
            }
        }

        Ok(())
    }
}

fn next_value<I>(flag: &'static str, iter: &mut I) -> Result<String, ParseError>
where
    I: Iterator<Item = String>,
{
    iter.next().ok_or(ParseError::MissingValue(flag))
}

fn resolve_home_dir(home_dir: Option<&str>, cwd: &Path, env: &BootEnvironment) -> PathBuf {
    match home_dir {
        Some(path) => resolve_cwd_relative(cwd, path),
        None => default_home_dir(cwd, env),
    }
}

fn resolve_config_source(options: &BootOptions, cwd: &Path, home_dir: &Path) -> ConfigSource {
    if let Some(config_base64) = &options.config_base64 {
        return ConfigSource::Base64(config_base64.clone());
    }

    match options.config_file.as_deref() {
        Some("-") => ConfigSource::Stdin,
        Some(path) => ConfigSource::File(resolve_cwd_relative(cwd, path)),
        None => ConfigSource::File(home_dir.join("config.yaml")),
    }
}

fn resolve_cwd_relative(cwd: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(candidate)
    }
}

fn default_home_dir(cwd: &Path, env: &BootEnvironment) -> PathBuf {
    let home_base = env.user_home.clone().unwrap_or_else(|| cwd.to_path_buf());
    let standard = home_base.join(".config").join("mihomo");
    if standard.exists() {
        return standard;
    }

    if let Some(xdg) = &env.xdg_config_home {
        return xdg.join("mihomo");
    }

    standard
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use mihomo_inbound::InboundDefinition;
    use mihomo_outbound::{OutboundDefinition, OutboundGroupKind, ProxyProviderVehicleType};

    use super::{
        parse_args, parse_runtime_config_document, BootEnvironment, BootOptions, Command,
        ConfigSource, ConfigValidationError, ParseError, RuleProviderBehavior,
        RuleProviderFormat, RuleProviderVehicleType,
    };

    #[test]
    fn parses_main_run_flags() {
        let args = [
            "mihomo",
            "-d",
            "/tmp/home",
            "-f",
            "config.yaml",
            "-ext-ctl",
            "127.0.0.1:9090",
            "-m",
            "-t",
        ];
        let options = parse_args(args).unwrap();
        assert_eq!(
            options,
            BootOptions {
                home_dir: Some("/tmp/home".into()),
                config_file: Some("config.yaml".into()),
                config_base64: None,
                external_ui: None,
                external_controller: Some("127.0.0.1:9090".into()),
                external_controller_unix: None,
                external_controller_pipe: None,
                secret: None,
                post_up: None,
                post_down: None,
                geodata_mode: true,
                show_version: false,
                test_config: true,
                command: Command::Run,
            }
        );
    }

    #[test]
    fn parses_builtin_subcommands() {
        let convert = parse_args(["mihomo", "convert-ruleset", "rules.yaml"]).unwrap();
        let generate = parse_args(["mihomo", "generate", "template"]).unwrap();
        assert_eq!(convert.command, Command::ConvertRuleset(vec!["rules.yaml".into()]));
        assert_eq!(generate.command, Command::Generate(vec!["template".into()]));
    }

    #[test]
    fn rejects_unknown_flags() {
        let err = parse_args(["mihomo", "--unknown"]).unwrap_err();
        assert_eq!(err, ParseError::UnknownFlag("--unknown".into()));
    }

    #[test]
    fn resolves_relative_paths_like_main_go() {
        let options = BootOptions {
            home_dir: Some("state".into()),
            config_file: Some("override.yaml".into()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let cwd = PathBuf::from("/tmp/mihomo-rs");
        let resolved = options.resolve(&cwd, &BootEnvironment::default());
        assert_eq!(resolved.home_dir, cwd.join("state"));
        assert_eq!(
            resolved.config_source,
            ConfigSource::File(cwd.join("override.yaml"))
        );
    }

    #[test]
    fn defaults_config_file_under_resolved_home_dir() {
        let cwd = unique_temp_dir();
        fs::create_dir_all(cwd.join("home").join(".config").join("mihomo")).unwrap();
        let env = BootEnvironment {
            user_home: Some(cwd.join("home")),
            xdg_config_home: None,
        };
        let resolved = BootOptions::default().resolve(&cwd, &env);
        assert_eq!(
            resolved.config_source,
            ConfigSource::File(cwd.join("home").join(".config").join("mihomo").join("config.yaml"))
        );
    }

    #[test]
    fn config_base64_has_priority_over_file_source() {
        let options = BootOptions {
            home_dir: None,
            config_file: Some("-".into()),
            config_base64: Some("YmFzZTY0".into()),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let resolved = options.resolve(Path::new("/tmp"), &BootEnvironment::default());
        assert_eq!(resolved.config_source, ConfigSource::Base64("YmFzZTY0".into()));
    }

    #[test]
    fn xdg_home_is_used_when_default_home_is_missing() {
        let cwd = unique_temp_dir();
        let env = BootEnvironment {
            user_home: Some(cwd.join("home")),
            xdg_config_home: Some(cwd.join("xdg")),
        };
        let resolved = BootOptions::default().resolve(&cwd, &env);
        assert_eq!(resolved.home_dir, cwd.join("xdg").join("mihomo"));
    }

    #[test]
    fn runtime_config_document_parses_listeners_key() {
        let document = parse_runtime_config_document(
            r#"
mode: rule
log-level: debug
mixed-port: 7890
allow-lan: true
bind-address: "*"
external-controller: 0.0.0.0:9093
external-ui: ./ui
proxies:
  - type: direct
    name: direct-a
proxy-groups:
  - name: auto
    type: url-test
    proxies: [direct-a]
    url: https://cp.cloudflare.com/generate_204
    interval: 300
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: direct
        name: provider-direct
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - '.example.org'
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "1080"
  - type: tun
    name: edge-tun
rules:
  - DOMAIN-SUFFIX,example.com,direct-a
  - MATCH,auto
sub-rules:
  edge:
    - DOMAIN,edge.example.com,direct-a
tun:
  enable: true
  stack: system
  dns-hijack:
    - 0.0.0.0:53
hosts:
  example.com:
    - 1.1.1.1
    - 1.0.0.1
  alias.local: target.local
dns:
  enable: true
  use-hosts: true
  use-system-hosts: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-range6: fdfe:dcba:9876::1/64
  fake-ip-filter:
    - '*.lan'
  fallback-filter:
    domain:
      - '+.fallback.test'
    ipcidr:
      - 240.0.0.0/4
  nameserver:
    - 8.8.8.8
  proxy-server-nameserver:
    - 9.9.9.9
  proxy-server-nameserver-policy:
    "+.proxy.test":
      - 4.4.4.4
  direct-nameserver:
    - 1.1.1.1
  direct-nameserver-follow-policy: true
  default-nameserver:
    - 1.1.1.1
"#,
        )
        .unwrap();

        assert_eq!(document.proxies.len(), 1);
        assert_eq!(document.proxy_groups.len(), 1);
        assert_eq!(document.proxy_providers.len(), 1);
        assert_eq!(document.rule_providers.len(), 1);
        assert_eq!(document.listeners.len(), 2);
        assert_eq!(document.rules.len(), 2);
        assert_eq!(document.sub_rules.len(), 1);
        assert!(document.tun.enable);
        assert!(document.dns.enable);
        assert_eq!(document.hosts.len(), 2);
        assert_eq!(document.mode, "rule");
        assert_eq!(document.log_level, "debug");
        assert_eq!(document.mixed_port, 7890);
        assert!(document.allow_lan);
        assert_eq!(document.bind_address, "*");
        assert_eq!(document.external_controller, "0.0.0.0:9093");
        assert_eq!(document.external_ui, "./ui");
        match &document.proxies[0] {
            OutboundDefinition::Direct(config) => {
                assert_eq!(config.base.name, "direct-a");
            }
            _ => panic!("expected direct proxy"),
        }
        assert_eq!(document.proxy_groups[0].kind(), Some(OutboundGroupKind::UrlTest));
        assert_eq!(
            document.proxy_providers["provider1"].vehicle_type(),
            Some(ProxyProviderVehicleType::Inline)
        );
        assert_eq!(
            document.rule_providers["rule1"].vehicle_type(),
            Some(RuleProviderVehicleType::Inline)
        );
        assert_eq!(
            document.rule_providers["rule1"].behavior_kind(),
            Some(RuleProviderBehavior::Domain)
        );
        assert_eq!(
            document.rule_providers["rule1"].format_kind(),
            Some(RuleProviderFormat::Yaml)
        );
        match &document.listeners[0] {
            InboundDefinition::Socks(config) => {
                assert_eq!(config.base.name, "edge-socks");
            }
            _ => panic!("expected socks listener"),
        }
        match &document.listeners[1] {
            InboundDefinition::Tun(config) => {
                assert_eq!(config.base.name, "edge-tun");
            }
            _ => panic!("expected tun listener"),
        }
        assert_eq!(document.rules[0], "DOMAIN-SUFFIX,example.com,direct-a");
        assert_eq!(document.rules[1], "MATCH,auto");
        assert_eq!(document.sub_rules["edge"][0], "DOMAIN,edge.example.com,direct-a");
        assert_eq!(document.tun.config.dns_hijack, vec!["0.0.0.0:53"]);
        assert_eq!(document.hosts["example.com"].values, vec!["1.1.1.1", "1.0.0.1"]);
        assert_eq!(document.hosts["alias.local"].values, vec!["target.local"]);
        assert_eq!(document.dns.enhanced_mode, "fake-ip");
        assert_eq!(document.dns.fake_ip_range, "198.18.0.1/16");
        assert_eq!(document.dns.fake_ip_range6, "fdfe:dcba:9876::1/64");
        assert_eq!(document.dns.fake_ip_filter, vec!["*.lan"]);
        assert!(document.dns.use_system_hosts);
        assert_eq!(document.dns.fallback_filter.domain, vec!["+.fallback.test"]);
        assert_eq!(document.dns.fallback_filter.ipcidr, vec!["240.0.0.0/4"]);
        assert_eq!(document.dns.nameserver, vec!["8.8.8.8"]);
        assert_eq!(document.dns.proxy_server_nameserver, vec!["9.9.9.9"]);
        assert_eq!(
            document.dns.proxy_server_nameserver_policy["+.proxy.test"].values,
            vec!["4.4.4.4"]
        );
        assert_eq!(document.dns.direct_nameserver, vec!["1.1.1.1"]);
        assert!(document.dns.direct_nameserver_follow_policy);
        assert_eq!(document.dns.default_nameserver, vec!["1.1.1.1"]);
        assert!(document.extra.is_empty());
        document.validate().unwrap();
    }

    #[test]
    fn validation_rejects_duplicate_proxy_names() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: same
  - type: reject
    name: same
"#,
        )
        .unwrap();
        assert_eq!(
            document.validate().unwrap_err(),
            ConfigValidationError::DuplicateProxyName("same".into())
        );
    }

    #[test]
    fn validation_rejects_reserved_provider_name() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  default:
    type: inline
    payload:
      - type: direct
        name: direct-a
"#,
        )
        .unwrap();
        assert_eq!(
            document.validate().unwrap_err(),
            ConfigValidationError::ReservedProviderName("default".into())
        );
    }

    #[test]
    fn validation_rejects_missing_group_reference() {
        let document = parse_runtime_config_document(
            r#"
proxy-groups:
  - name: auto
    type: select
    proxies: [missing-proxy]
"#,
        )
        .unwrap();
        assert_eq!(
            document.validate().unwrap_err(),
            ConfigValidationError::ProxyGroupReferenceNotFound {
                group: "auto".into(),
                reference: "missing-proxy".into()
            }
        );
    }

    #[test]
    fn validation_rejects_removed_relay_group_type() {
        let document = parse_runtime_config_document(
            r#"
proxy-groups:
  - name: relay
    type: relay
    proxies: [DIRECT]
"#,
        )
        .unwrap();
        assert_eq!(
            document.validate().unwrap_err(),
            ConfigValidationError::UnsupportedProxyGroupType("relay".into())
        );
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mihomo-config-test-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
