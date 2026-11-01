use std::collections::BTreeMap;
use std::io::Cursor;

use mihomo_config::{RuleProviderBehavior, RuleProviderFormat, RuleProviderVehicleType, RuntimeConfigDocument};
use mihomo_outbound::{OutboundDefinition, OutboundKind, ProxyProviderVehicleType};
use mihomo_rules::{parse_rule, RuleError};
use mihomo_runtime::ProviderHealthCheckRuntime;
use mihomo_runtime::{
    build_effective_listeners, build_runtime_registry, build_tun_runtime_specs, BootstrapState,
    ListenerOrigin, ProviderContentSources, ProxySource, RegistryError, RuntimeRegistry,
};
use serde_yaml::Value;
use chrono::{TimeZone, Utc};

use crate::snapshot_types::{
    ApiDnsSnapshot, ApiGeneralSnapshot, ApiGroupSnapshot, ApiListenerSnapshot, ApiProxyProviderSnapshot,
    ApiProxySnapshot, ApiProxyStateSnapshot, ApiRuleProviderSnapshot, ApiRuleSnapshot, ApiSnapshot,
    ApiTunSnapshot, ApiVersion, ApiDelayHistorySnapshot,
};

#[derive(Clone, Debug, Default, serde::Deserialize, Eq, PartialEq)]
struct RuleProviderPayloadDocument {
    #[serde(default, rename = "payload")]
    payload: Vec<String>,
    #[serde(default, rename = "rules")]
    rules: Vec<String>,
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
    build_api_snapshot_with_registry(document, &ProviderContentSources::default(), &registry, true)
}

pub fn build_api_snapshot_from_bootstrap(state: &BootstrapState) -> Result<ApiSnapshot, ApiError> {
    let sources = state
        .provider_sources_for_snapshot()
        .unwrap_or_else(|_| state.provider_sources.clone());
    build_api_snapshot_with_registry(&state.document, &sources, &state.registry, true)
}

pub(crate) fn build_controller_snapshot(state:&BootstrapState)->Result<ApiSnapshot,ApiError>{
    let sources=state.provider_sources_for_snapshot().unwrap_or_else(|_|state.provider_sources.clone());
    build_api_snapshot_with_registry(&state.document,&sources,&state.registry,false)
}

fn build_api_snapshot_with_registry(
    document: &RuntimeConfigDocument,
    provider_sources: &ProviderContentSources,
    registry: &RuntimeRegistry,
    include_rules: bool,
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
            smart: view.runtime.smart.as_ref().map(|smart| { let mut options=smart.options.clone();options.policy_priority=smart.normalized_priority(); options }),
            common: {
                let mut common=proxies.iter().find(|entry| entry.name == *name).unwrap().clone();
                if view.runtime.smart.is_some(){common.udp=!view.runtime.disable_udp&&view.candidate_names.iter().any(|candidate|proxies.iter().find(|proxy|proxy.name==*candidate).is_some_and(|proxy|proxy.udp));}
                common
            },
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

    let rules = if include_rules { document
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
        .collect::<Result<Vec<_>, RuleError>>()? } else { Vec::new() };

    let tun_specs = build_tun_runtime_specs(document);
    Ok(ApiSnapshot {
        version: ApiVersion {
            meta: true,
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
            tun: crate::snapshot_types::ApiGeneralTunSnapshot { enable: document.tun.enable, config: document.tun.config.clone() },
            listener_count: listeners.len(),
            proxy_count: proxies.len(),
            group_count: groups.len(),
            provider_count: registry.providers.len(),
            ebpf: document.ebpf.clone(),
            lgbm_auto_update: document.extra.get("lgbm-auto-update").and_then(Value::as_bool).unwrap_or(false),
            lgbm_update_interval: document.extra.get("lgbm-update-interval").and_then(Value::as_u64).unwrap_or(72),
            lgbm_url: document.extra.get("lgbm-url").and_then(Value::as_str).unwrap_or(mihomo_runtime::smart::DEFAULT_MODEL_URL).to_owned(),
            smart_collector_size: document.profile.extra.get("smart-collector-size").and_then(Value::as_f64).filter(|value|value.is_finite()&&*value>0.0).unwrap_or(100.0),
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
            dns_hijack_entries: tun_specs.iter().map(|spec| spec.config.dns_hijack.len()).sum(),
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

fn build_api_proxy_snapshot(definition: &OutboundDefinition, provider_name: &str) -> ApiProxySnapshot {
    let base = definition.base();
    ApiProxySnapshot {
        name: definition.name().to_owned(),
        proxy_type: definition.kind().as_str().to_owned(),
        alive: true,
        history: Vec::new(),
        extra: BTreeMap::new(),
        udp: outbound_udp_enabled(definition),
        uot: outbound_extra(definition).get("udp-over-tcp").and_then(Value::as_bool).unwrap_or(false),
        xudp: outbound_extra(definition).get("packet-encoding").and_then(Value::as_str) == Some("xudp"),
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
        alive: true,
        history: Vec::new(),
        extra: BTreeMap::new(),
        udp: builtin_proxy_supports_udp(name),
        uot: false,
        xudp: false,
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
        alive: true,
        history: Vec::new(),
        extra: BTreeMap::new(),
        udp: false,
        uot: false,
        xudp: false,
        tfo: false,
        mptcp: false,
        smux: false,
        interface_name: String::new(),
        routing_mark: 0,
        provider_name: provider_name.to_owned(),
        dialer_proxy: dialer_proxy.to_owned(),
    }
}

pub(crate) fn apply_runtime_proxy_health(
    proxy: &mut ApiProxySnapshot,
    runtime_tunnel: &mihomo_runtime::RuntimeTunnel,
) {
    let Some(health) = runtime_tunnel.proxy_health_snapshot(&proxy.name) else {
        return;
    };
    proxy.alive = health.alive;
    proxy.history = health
        .history
        .into_iter()
        .map(|entry| ApiDelayHistorySnapshot {
            time: Utc
                .timestamp_millis_opt(entry.time_unix_ms as i64)
                .single()
                .unwrap_or_else(Utc::now)
                .to_rfc3339(),
            delay: entry.delay_ms,
        })
        .collect();
    proxy.extra = health
        .extra
        .into_iter()
        .map(|(url, state)| {
            (
                url,
                ApiProxyStateSnapshot {
                    alive: state.alive,
                    history: state
                        .history
                        .into_iter()
                        .map(|entry| ApiDelayHistorySnapshot {
                            time: Utc
                                .timestamp_millis_opt(entry.time_unix_ms as i64)
                                .single()
                                .unwrap_or_else(Utc::now)
                                .to_rfc3339(),
                            delay: entry.delay_ms,
                        })
                        .collect(),
                    last_error: state.last_error,
                },
            )
        })
        .collect();
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
    matches!(name, "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS")
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
            let rule_count = estimate_rule_provider_count(
                definition,
                &provider_sources.file_contents,
                &provider_sources.http_contents,
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
                rule_count,
            })
        })
        .collect()
}

fn estimate_rule_provider_count<S: AsRef<[u8]>>(
    definition: &mihomo_config::RuleProviderDefinition,
    file_contents: &BTreeMap<String, String>,
    http_contents: &BTreeMap<String, String>,
    file_blobs: &BTreeMap<String, S>,
    http_blobs: &BTreeMap<String, S>,
) -> Result<usize, ApiError> {
    let behavior = definition
        .behavior_kind()
        .ok_or_else(|| ApiError::Rule(RuleError::UnsupportedRuleProviderBehavior(definition.behavior.clone())))?;
    let format = definition
        .format_kind()
        .ok_or_else(|| ApiError::Rule(RuleError::UnsupportedRuleProviderFormat(definition.format.clone())))?;

    let text_source = || match definition.vehicle_type() {
        Some(mihomo_config::RuleProviderVehicleType::Inline) => None,
        Some(mihomo_config::RuleProviderVehicleType::File) => file_contents
            .get(&definition.path)
            .map(|value| value.as_str())
            .or_else(|| {
                file_blobs
                    .get(&definition.path)
                    .and_then(|value| std::str::from_utf8(value.as_ref()).ok())
            }),
        Some(mihomo_config::RuleProviderVehicleType::Http) => http_contents
            .get(&definition.url)
            .map(|value| value.as_str())
            .or_else(|| file_contents.get(&definition.path).map(|value| value.as_str()))
            .or_else(|| {
                http_blobs
                    .get(&definition.url)
                    .and_then(|value| std::str::from_utf8(value.as_ref()).ok())
            })
            .or_else(|| {
                file_blobs
                    .get(&definition.path)
                    .and_then(|value| std::str::from_utf8(value.as_ref()).ok())
            }),
        None => None,
    };

    match format {
        RuleProviderFormat::Yaml => {
            let content = match definition.vehicle_type() {
                Some(mihomo_config::RuleProviderVehicleType::Inline) => {
                    return Ok(definition.payload.len())
                }
                Some(mihomo_config::RuleProviderVehicleType::File)
                | Some(mihomo_config::RuleProviderVehicleType::Http) => match text_source() {
                    Some(content) => content,
                    None => return Ok(0),
                },
                None => return Ok(0),
            };
            let document = serde_yaml::from_str::<RuleProviderPayloadDocument>(content)
                .map_err(|err| ApiError::Rule(RuleError::InvalidRuleProviderContent(err.to_string())))?;
            Ok(if !document.rules.is_empty() {
                document.rules.len()
            } else {
                document.payload.len()
            })
        }
        RuleProviderFormat::Text => {
            let content = match definition.vehicle_type() {
                Some(mihomo_config::RuleProviderVehicleType::Inline) => {
                    return Ok(definition.payload.len())
                }
                Some(mihomo_config::RuleProviderVehicleType::File)
                | Some(mihomo_config::RuleProviderVehicleType::Http) => match text_source() {
                    Some(content) => content,
                    None => return Ok(0),
                },
                None => return Ok(0),
            };
            Ok(content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with('#') && !line.starts_with("//"))
            .count())
        }
        RuleProviderFormat::Mrs => {
            let bytes = match definition.vehicle_type() {
                Some(mihomo_config::RuleProviderVehicleType::Inline) => {
                    return Ok(definition.payload.len())
                }
                Some(mihomo_config::RuleProviderVehicleType::File) => match file_blobs.get(&definition.path) {
                    Some(content) => content.as_ref(),
                    None => return Ok(0),
                },
                Some(mihomo_config::RuleProviderVehicleType::Http) => match http_blobs
                    .get(&definition.url)
                    .or_else(|| file_blobs.get(&definition.path))
                {
                    Some(content) => content.as_ref(),
                    None => return Ok(0),
                },
                None => return Ok(0),
            };
            estimate_mrs_rule_count(bytes, behavior)
        }
    }
}

fn estimate_mrs_rule_count(
    content: &[u8],
    behavior: RuleProviderBehavior,
) -> Result<usize, ApiError> {
    if behavior == RuleProviderBehavior::Classical {
        return Err(ApiError::Rule(RuleError::UnsupportedRuleProviderFormat("mrs".into())));
    }
    let decoded = zstd::decode_all(Cursor::new(content))
        .map_err(|err| ApiError::Rule(RuleError::InvalidRuleProviderContent(err.to_string())))?;
    if decoded.len() < 21 {
        return Err(ApiError::Rule(RuleError::InvalidRuleProviderContent(
            "mrs header is truncated".into(),
        )));
    }
    if decoded[..4] != [b'M', b'R', b'S', 1] {
        return Err(ApiError::Rule(RuleError::InvalidRuleProviderContent(
            "invalid mrs magic".into(),
        )));
    }
    let encoded_behavior = decoded[4];
    let expected_behavior = match behavior {
        RuleProviderBehavior::Domain => 0,
        RuleProviderBehavior::IpCidr => 1,
        RuleProviderBehavior::Classical => unreachable!(),
    };
    if encoded_behavior != expected_behavior {
        return Err(ApiError::Rule(RuleError::InvalidRuleProviderContent(
            "mrs behavior does not match provider definition".into(),
        )));
    }
    let rule_count = i64::from_be_bytes(decoded[5..13].try_into().unwrap());
    if rule_count < 0 {
        return Err(ApiError::Rule(RuleError::InvalidRuleProviderContent(
            "mrs length is invalid".into(),
        )));
    }
    Ok(rule_count as usize)
}
