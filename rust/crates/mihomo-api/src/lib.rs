mod server;
mod storage;

use mihomo_config::{GeoXUrlConfig, RuntimeConfigDocument, TuicServerConfig};
use mihomo_config::{RuleProviderBehavior, RuleProviderFormat, RuleProviderVehicleType};
use mihomo_core::{RewriteStage, SubsystemManifest};
use mihomo_inbound::TunInboundConfig;
use mihomo_outbound::{OutboundDefinition, OutboundKind, ProxyProviderVehicleType};
use mihomo_rules::{load_rule_provider_payload_from_sources, parse_rule, RuleError};
use mihomo_runtime::ProviderHealthCheckRuntime;
use mihomo_runtime::{
    build_effective_listeners, build_runtime_registry, build_tun_runtime_specs, BootstrapState,
    ListenerOrigin, ProviderContentSources, ProxySource, RegistryError, RuntimeRegistry,
};
use serde::Serialize;
use serde_yaml::Value;

pub use server::{
    ApiControlCommand, ApiController, ApiHttpRequest, ApiHttpResponse, ControllerError,
    RunningApiController,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApiVersion {
    pub meta: String,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    pub tun: TunInboundConfig,
    pub listener_count: usize,
    pub proxy_count: usize,
    pub group_count: usize,
    pub provider_count: usize,
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
    pub proxy_type: String,
    pub udp: bool,
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
pub struct ApiGroupSnapshot {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    #[serde(rename = "all")]
    pub candidates: Vec<String>,
    #[serde(rename = "now")]
    pub selected: Option<String>,
    #[serde(rename = "testUrl")]
    pub test_url: String,
    #[serde(rename = "expectedStatus")]
    pub expected_status: String,
    #[serde(rename = "fixed")]
    pub fixed: Option<String>,
    pub hidden: bool,
    pub icon: String,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiError {
    Registry(RegistryError),
    Rule(RuleError),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(err) => write!(f, "{err}"),
            Self::Rule(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<RegistryError> for ApiError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

impl From<RuleError> for ApiError {
    fn from(value: RuleError) -> Self {
        Self::Rule(value)
    }
}

pub fn build_api_snapshot(document: &RuntimeConfigDocument) -> Result<ApiSnapshot, ApiError> {
    let registry = build_runtime_registry(document)?;
    build_api_snapshot_with_registry(document, &ProviderContentSources::default(), &registry)
}

pub fn build_api_snapshot_from_bootstrap(state: &BootstrapState) -> Result<ApiSnapshot, ApiError> {
    build_api_snapshot_with_registry(&state.document, &state.provider_sources, &state.registry)
}

fn build_api_snapshot_with_registry(
    document: &RuntimeConfigDocument,
    provider_sources: &ProviderContentSources,
    registry: &RuntimeRegistry,
) -> Result<ApiSnapshot, ApiError> {
    let listeners = build_effective_listeners(document)
        .into_iter()
        .map(|listener| ApiListenerSnapshot {
            name: listener.synthetic_name,
            kind: listener.kind.as_str().to_owned(),
            addresses: listener.addresses,
            origin: match listener.origin {
                ListenerOrigin::TopLevel => "top-level".to_owned(),
                ListenerOrigin::Custom => "custom".to_owned(),
            },
        })
        .collect::<Vec<_>>();

    let proxies = registry
        .proxies
        .values()
        .map(|proxy| match &proxy.source {
            ProxySource::Builtin => build_builtin_api_proxy_snapshot(&proxy.name),
            ProxySource::UserConfig => registry
                .proxy_definitions
                .get(&proxy.name)
                .map(|definition| build_api_proxy_snapshot(definition, ""))
                .unwrap_or_else(|| {
                    build_minimal_api_proxy_snapshot(
                        &proxy.name,
                        proxy.kind.map(OutboundKind::as_str).unwrap_or("unknown"),
                        "",
                        proxy.dialer_proxy.as_deref().unwrap_or_default(),
                    )
                }),
            ProxySource::GroupSynthetic => build_minimal_api_proxy_snapshot(
                &proxy.name,
                registry
                    .groups
                    .get(&proxy.name)
                    .map(|view| view.runtime.group.group_type.as_str())
                    .unwrap_or("group"),
                "",
                "",
            ),
            ProxySource::ProviderInline { provider } => registry
                .proxy_definitions
                .get(&proxy.name)
                .map(|definition| build_api_proxy_snapshot(definition, provider))
                .unwrap_or_else(|| {
                    build_minimal_api_proxy_snapshot(
                        &proxy.name,
                        proxy.kind.map(OutboundKind::as_str).unwrap_or("unknown"),
                        provider,
                        proxy.dialer_proxy.as_deref().unwrap_or_default(),
                    )
                }),
        })
        .collect::<Vec<_>>();

    let groups = registry
        .groups
        .iter()
        .map(|(name, view)| ApiGroupSnapshot {
            name: name.clone(),
            group_type: view.runtime.group.group_type.clone(),
            candidates: view.candidate_names.clone(),
            selected: None,
            test_url: view.runtime.test_url.clone(),
            expected_status: view.runtime.expected_status.clone(),
            fixed: view.runtime.selected().map(ToOwned::to_owned),
            hidden: document
                .proxy_groups
                .iter()
                .find(|group| group.name == *name)
                .map(|group| group.hidden)
                .unwrap_or(false),
            icon: document
                .proxy_groups
                .iter()
                .find(|group| group.name == *name)
                .map(|group| group.icon.clone())
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    let proxy_providers = document
        .proxy_providers
        .iter()
        .map(|(name, _definition)| {
            let runtime = registry
                .providers
                .get(name)
                .expect("provider runtime should exist for validated document");
            ApiProxyProviderSnapshot {
                name: name.clone(),
                provider_type: "Proxy".into(),
                vehicle_type: provider_vehicle_type_name(runtime.vehicle_type),
                proxies: runtime
                    .members
                    .iter()
                    .map(|member| build_api_proxy_snapshot(&member.definition, name))
                    .collect(),
                test_url: runtime.health_check.url.clone(),
                expected_status: expected_status_text(&runtime.health_check),
            }
        })
        .collect::<Vec<_>>();

    let rule_providers = build_rule_provider_snapshots(document, provider_sources)?;

    let rules = document
        .rules
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            let parsed = parse_rule(raw)?;
            Ok(ApiRuleSnapshot {
                index,
                rule_type: parsed.rule_type.as_str().to_owned(),
                payload: parsed.payload,
                target: parsed.target,
                size: -1,
                extra: None,
            })
        })
        .collect::<Result<Vec<_>, RuleError>>()?;

    let tun_specs = build_tun_runtime_specs(document);
    Ok(ApiSnapshot {
        version: ApiVersion {
            meta: "mihomo-rust".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        general: ApiGeneralSnapshot {
            port: document.port,
            socks_port: document.socks_port,
            redir_port: document.redir_port,
            tproxy_port: document.tproxy_port,
            mixed_port: document.mixed_port,
            shadow_socks_config: document.shadow_socks_config.clone(),
            vmess_config: document.vmess_config.clone(),
            authentication: document.authentication.clone(),
            skip_auth_prefixes: document.skip_auth_prefixes.clone(),
            lan_allowed_ips: document.lan_allowed_ips.clone(),
            lan_disallowed_ips: document.lan_disallowed_ips.clone(),
            mode: document.mode.clone(),
            unified_delay: document.unified_delay,
            log_level: document.log_level.clone(),
            allow_lan: document.allow_lan,
            bind_address: document.bind_address.clone(),
            inbound_tfo: document.inbound_tfo,
            inbound_mptcp: document.inbound_mptcp,
            ipv6: document.ipv6,
            interface_name: document.interface_name.clone(),
            routing_mark: document.routing_mark,
            geox_url: document.geox_url.clone(),
            geo_auto_update: document.geo_auto_update,
            geo_update_interval: document.geo_update_interval,
            geodata_mode: document.geodata_mode,
            geodata_loader: document.geodata_loader.clone(),
            geosite_matcher: document.geosite_matcher.clone(),
            tcp_concurrent: document.tcp_concurrent,
            find_process_mode: document.find_process_mode.clone(),
            sniffing: document.sniffer.enable,
            global_client_fingerprint: document.global_client_fingerprint.clone(),
            global_ua: document.global_ua.clone(),
            etag_support: document.etag_support,
            keep_alive_idle: document.keep_alive_idle,
            keep_alive_interval: document.keep_alive_interval,
            disable_keep_alive: document.disable_keep_alive,
            external_controller: document.external_controller.clone(),
            external_controller_tls: document.external_controller_tls.clone(),
            external_controller_unix: document.external_controller_unix.clone(),
            external_controller_pipe: document.external_controller_pipe.clone(),
            external_ui: document.external_ui.clone(),
            external_ui_url: document.external_ui_url.clone(),
            external_ui_name: document.external_ui_name.clone(),
            tuic_server: document.tuic_server.clone(),
            tun: document.tun.config.clone(),
            listener_count: listeners.len(),
            proxy_count: proxies.len(),
            group_count: groups.len(),
            provider_count: registry.providers.len(),
        },
        listeners,
        proxies,
        groups,
        proxy_providers,
        rule_providers,
        rules,
        dns: ApiDnsSnapshot {
            enabled: document.dns.enable,
            listen: document.dns.listen.clone(),
            enhanced_mode: document.dns.enhanced_mode.clone(),
            use_hosts: document.dns.use_hosts,
            nameserver_count: document.dns.nameserver.len(),
            default_nameserver_count: document.dns.default_nameserver.len(),
            fallback_count: document.dns.fallback.len(),
            cache_algorithm: document.dns.cache_algorithm.clone(),
        },
        tun: ApiTunSnapshot {
            enabled: document.tun.enable || !tun_specs.is_empty(),
            spec_count: tun_specs.len(),
            stacks: tun_specs
                .iter()
                .map(|spec| format!("{:?}", spec.stack()).to_ascii_lowercase())
                .collect(),
            dns_hijack_entries: tun_specs
                .iter()
                .map(|spec| spec.config.dns_hijack.len())
                .sum(),
            auto_route: tun_specs.iter().any(|spec| spec.config.auto_route),
            auto_redirect: tun_specs.iter().any(|spec| spec.config.auto_redirect),
        },
    })
}

fn provider_vehicle_type_name(vehicle_type: ProxyProviderVehicleType) -> String {
    match vehicle_type {
        ProxyProviderVehicleType::File => "File".to_owned(),
        ProxyProviderVehicleType::Http => "HTTP".to_owned(),
        ProxyProviderVehicleType::Inline => "Inline".to_owned(),
    }
}

fn rule_provider_vehicle_type_name(definition: &mihomo_config::RuleProviderDefinition) -> String {
    match definition.vehicle_type() {
        Some(RuleProviderVehicleType::File) => "File".to_owned(),
        Some(RuleProviderVehicleType::Http) => "HTTP".to_owned(),
        Some(RuleProviderVehicleType::Inline) => "Inline".to_owned(),
        None => "Unknown".to_owned(),
    }
}

fn expected_status_text(health_check: &ProviderHealthCheckRuntime) -> String {
    if health_check.expected_status.trim().is_empty() {
        "200".to_owned()
    } else {
        health_check.expected_status.clone()
    }
}

fn build_api_proxy_snapshot(
    definition: &OutboundDefinition,
    provider_name: &str,
) -> ApiProxySnapshot {
    let base = definition.base();
    ApiProxySnapshot {
        name: definition.name().to_owned(),
        proxy_type: definition.kind().as_str().to_owned(),
        udp: outbound_udp_enabled(definition),
        tfo: base.tfo,
        mptcp: base.mptcp,
        smux: base.smux.enabled,
        interface_name: base.interface_name.clone(),
        routing_mark: base.routing_mark,
        provider_name: provider_name.to_owned(),
        dialer_proxy: base.dialer_proxy.clone(),
    }
}

fn build_builtin_api_proxy_snapshot(name: &str) -> ApiProxySnapshot {
    ApiProxySnapshot {
        name: name.to_owned(),
        proxy_type: builtin_proxy_type_name(name).to_owned(),
        udp: builtin_proxy_supports_udp(name),
        tfo: false,
        mptcp: false,
        smux: false,
        interface_name: String::new(),
        routing_mark: 0,
        provider_name: String::new(),
        dialer_proxy: String::new(),
    }
}

fn build_minimal_api_proxy_snapshot(
    name: &str,
    proxy_type: &str,
    provider_name: &str,
    dialer_proxy: &str,
) -> ApiProxySnapshot {
    ApiProxySnapshot {
        name: name.to_owned(),
        proxy_type: proxy_type.to_owned(),
        udp: false,
        tfo: false,
        mptcp: false,
        smux: false,
        interface_name: String::new(),
        routing_mark: 0,
        provider_name: provider_name.to_owned(),
        dialer_proxy: dialer_proxy.to_owned(),
    }
}

fn outbound_udp_enabled(definition: &OutboundDefinition) -> bool {
    match definition.kind() {
        OutboundKind::Direct
        | OutboundKind::Dns
        | OutboundKind::Reject
        | OutboundKind::Hysteria
        | OutboundKind::Hysteria2
        | OutboundKind::WireGuard
        | OutboundKind::Tuic
        | OutboundKind::Tailscale => true,
        _ => outbound_extra(definition)
            .get("udp")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn outbound_extra(definition: &OutboundDefinition) -> &std::collections::BTreeMap<String, Value> {
    match definition {
        OutboundDefinition::Direct(config) => &config.extra,
        OutboundDefinition::Dns(config) => &config.extra,
        OutboundDefinition::Reject(config) => &config.extra,
        OutboundDefinition::Http(config) => &config.extra,
        OutboundDefinition::Socks5(config) => &config.extra,
        OutboundDefinition::ShadowSocks(config) => &config.extra,
        OutboundDefinition::ShadowSocksR(config) => &config.extra,
        OutboundDefinition::Snell(config) => &config.extra,
        OutboundDefinition::Vmess(config) => &config.extra,
        OutboundDefinition::Vless(config) => &config.extra,
        OutboundDefinition::Trojan(config) => &config.extra,
        OutboundDefinition::Hysteria(config) => &config.extra,
        OutboundDefinition::Hysteria2(config) => &config.extra,
        OutboundDefinition::WireGuard(config) => &config.extra,
        OutboundDefinition::Tuic(config) => &config.extra,
        OutboundDefinition::GostRelay(config) => &config.extra,
        OutboundDefinition::Ssh(config) => &config.extra,
        OutboundDefinition::Mieru(config) => &config.extra,
        OutboundDefinition::AnyTls(config) => &config.extra,
        OutboundDefinition::Sudoku(config) => &config.extra,
        OutboundDefinition::Masque(config) => &config.extra,
        OutboundDefinition::TrustTunnel(config) => &config.extra,
        OutboundDefinition::OpenVpn(config) => &config.extra,
        OutboundDefinition::Tailscale(config) => &config.extra,
    }
}

fn builtin_proxy_type_name(name: &str) -> &'static str {
    match name {
        "DIRECT" => "direct",
        "REJECT" => "reject",
        "REJECT-DROP" => "reject-drop",
        "COMPATIBLE" => "compatible",
        "PASS" => "pass",
        _ => "builtin",
    }
}

fn builtin_proxy_supports_udp(name: &str) -> bool {
    matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS"
    )
}

fn rule_provider_behavior_name(behavior: RuleProviderBehavior) -> String {
    match behavior {
        RuleProviderBehavior::Domain => "Domain".to_owned(),
        RuleProviderBehavior::IpCidr => "IPCIDR".to_owned(),
        RuleProviderBehavior::Classical => "Classical".to_owned(),
    }
}

fn rule_provider_format_name(format: RuleProviderFormat) -> String {
    match format {
        RuleProviderFormat::Yaml => "YamlRule".to_owned(),
        RuleProviderFormat::Text => "TextRule".to_owned(),
        RuleProviderFormat::Mrs => "MrsRule".to_owned(),
    }
}

fn build_rule_provider_snapshots(
    document: &RuntimeConfigDocument,
    provider_sources: &ProviderContentSources,
) -> Result<Vec<ApiRuleProviderSnapshot>, ApiError> {
    document
        .rule_providers
        .iter()
        .map(|(name, definition)| {
            let payload = load_rule_provider_payload_from_sources(
                definition,
                &provider_sources.file_blobs,
                &provider_sources.http_blobs,
            )?;
            Ok(ApiRuleProviderSnapshot {
                name: name.clone(),
                provider_type: "Rule".into(),
                vehicle_type: rule_provider_vehicle_type_name(definition),
                behavior: definition
                    .behavior_kind()
                    .map(rule_provider_behavior_name)
                    .unwrap_or_else(|| "Unknown".to_owned()),
                format: definition
                    .format_kind()
                    .map(rule_provider_format_name)
                    .unwrap_or_else(|| "Unknown".to_owned()),
                rule_count: payload.len(),
            })
        })
        .collect()
}

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-api",
    go_areas: &["hub/route"],
    contracts: &["external controller compatibility", "external UI exposure"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mihomo_config::parse_runtime_config_document;
    use mihomo_runtime::bootstrap_from_yaml;

    use super::{build_api_snapshot, build_api_snapshot_from_bootstrap};

    #[test]
    fn api_snapshot_summarizes_runtime_surface() {
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
rules:
  - DOMAIN-SUFFIX,example.com,direct-a
  - MATCH,auto
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "1080"
tun:
  enable: true
  stack: system
  dns-hijack:
    - 0.0.0.0:53
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
  default-nameserver:
    - 1.1.1.1
"#,
        )
        .unwrap();
        let snapshot = build_api_snapshot(&document).unwrap();
        assert_eq!(snapshot.general.mode, "rule");
        assert!(snapshot.general.tun.stack == mihomo_inbound::TunStack::System);
        assert_eq!(snapshot.general.listener_count, 2);
        assert!(snapshot.proxies.iter().any(|proxy| proxy.name == "direct-a"));
        assert!(snapshot.groups.iter().any(|group| group.name == "auto"));
        assert_eq!(snapshot.rules.len(), 2);
        assert!(snapshot.tun.enabled);
        assert_eq!(snapshot.dns.nameserver_count, 1);
    }

    #[test]
    fn api_snapshot_can_be_built_from_bootstrap_state() {
        let (document, _, _) = bootstrap_from_yaml(
            r#"
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry: mihomo_runtime::build_runtime_registry(&parse_runtime_config_document(
                "proxies:\n  - type: direct\n    name: direct-a\n",
            )
            .unwrap())
            .unwrap(),
        };
        let snapshot = build_api_snapshot_from_bootstrap(&state).unwrap();
        assert!(snapshot.proxies.iter().any(|proxy| proxy.name == "direct-a"));
    }

    #[test]
    fn bootstrap_snapshot_uses_loaded_rule_provider_payloads() {
        let temp = unique_temp_dir("mihomo-api-bootstrap-rule-provider");
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("rule-provider.yaml"),
            "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,example.org\n",
        )
        .unwrap();

        let (document, provider_sources, registry) = bootstrap_from_yaml(
            r#"
rule-providers:
  rule1:
    type: file
    behavior: classical
    format: yaml
    path: rule-provider.yaml
proxies:
  - type: direct
    name: direct-a
"#,
            &temp,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources,
            registry,
        };

        let snapshot = build_api_snapshot_from_bootstrap(&state).unwrap();
        assert_eq!(snapshot.rule_providers.len(), 1);
        assert_eq!(snapshot.rule_providers[0].name, "rule1");
        assert_eq!(snapshot.rule_providers[0].rule_count, 2);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
