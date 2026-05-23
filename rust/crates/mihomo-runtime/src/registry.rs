use std::collections::BTreeMap;

use mihomo_config::RuntimeConfigDocument;
use mihomo_outbound::{
    parse_provider_payload_document, GroupDefinition, OutboundDefinition, OutboundKind,
    ProxyProviderOverride, ProxyProviderVehicleType,
};
use regex::Regex;

use crate::{
    assemble_proxy_topology, build_runtime_groups, AssembledProxyTopology, RuntimeGroup,
    TopologyError, ResolvedGroup,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxySource {
    Builtin,
    UserConfig,
    GroupSynthetic,
    ProviderInline { provider: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRegistration {
    pub name: String,
    pub kind: Option<OutboundKind>,
    pub source: ProxySource,
    pub dialer_proxy: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHealthCheckRuntime {
    pub enabled: bool,
    pub url: String,
    pub interval_secs: i32,
    pub timeout_ms: i32,
    pub lazy: bool,
    pub expected_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMember {
    pub name: String,
    pub definition: OutboundDefinition,
}

impl ProviderMember {
    pub fn kind(&self) -> OutboundKind {
        self.definition.kind()
    }

    pub fn dialer_proxy(&self) -> Option<String> {
        non_empty(self.definition.dialer_proxy())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRuntime {
    pub name: String,
    pub vehicle_type: ProxyProviderVehicleType,
    pub members: Vec<ProviderMember>,
    pub health_check: ProviderHealthCheckRuntime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeGroupView {
    pub runtime: RuntimeGroup,
    pub candidate_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRegistry {
    pub topology: AssembledProxyTopology,
    pub proxies: BTreeMap<String, ProxyRegistration>,
    pub proxy_definitions: BTreeMap<String, OutboundDefinition>,
    pub providers: BTreeMap<String, ProviderRuntime>,
    pub groups: BTreeMap<String, RuntimeGroupView>,
    pub default_provider_members: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderContentSources {
    pub file_contents: BTreeMap<String, String>,
    pub http_contents: BTreeMap<String, String>,
    pub file_blobs: BTreeMap<String, Vec<u8>>,
    pub http_blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    Topology(TopologyError),
    Regex(String),
    DuplicateProviderMemberName { provider: String, name: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Topology(err) => write!(f, "{err}"),
            Self::Regex(err) => write!(f, "{err}"),
            Self::DuplicateProviderMemberName { provider, name } => write!(
                f,
                "provider {provider} contains proxy name collision: {name}"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

impl From<TopologyError> for RegistryError {
    fn from(value: TopologyError) -> Self {
        Self::Topology(value)
    }
}

pub fn build_runtime_registry(document: &RuntimeConfigDocument) -> Result<RuntimeRegistry, RegistryError> {
    build_runtime_registry_with_sources(document, &ProviderContentSources::default())
}

pub fn build_runtime_registry_with_sources(
    document: &RuntimeConfigDocument,
    sources: &ProviderContentSources,
) -> Result<RuntimeRegistry, RegistryError> {
    document.validate().map_err(|err| RegistryError::Regex(err.to_string()))?;
    let topology = assemble_proxy_topology(document)?;
    let runtime_groups = build_runtime_groups(
        &topology.resolved_groups_in_dependency_order,
        &document.proxy_groups,
        &document.proxy_providers,
    );

    let mut proxies = BTreeMap::new();
    let mut proxy_definitions = BTreeMap::new();
    for builtin in &topology.builtin_proxy_names {
        proxies.insert(
            builtin.clone(),
            ProxyRegistration {
                name: builtin.clone(),
                kind: None,
                source: ProxySource::Builtin,
                dialer_proxy: None,
            },
        );
    }
    for proxy in &document.proxies {
        proxy_definitions.insert(proxy.name().to_owned(), proxy.clone());
        proxies.insert(
            proxy.name().to_owned(),
            ProxyRegistration {
                name: proxy.name().to_owned(),
                kind: Some(proxy.kind()),
                source: ProxySource::UserConfig,
                dialer_proxy: non_empty(proxy.dialer_proxy()),
            },
        );
    }
    for group in &topology.group_names_in_dependency_order {
        proxies.insert(
            group.clone(),
            ProxyRegistration {
                name: group.clone(),
                kind: None,
                source: ProxySource::GroupSynthetic,
                dialer_proxy: None,
            },
        );
    }
    if topology.injected_global {
        proxies.insert(
            "GLOBAL".into(),
            ProxyRegistration {
                name: "GLOBAL".into(),
                kind: None,
                source: ProxySource::GroupSynthetic,
                dialer_proxy: None,
            },
        );
    }

    let providers = build_provider_runtimes(document, sources)?;
    for (provider_name, provider) in &providers {
        for member in &provider.members {
            if proxies.contains_key(&member.name) {
                return Err(RegistryError::DuplicateProviderMemberName {
                    provider: provider_name.clone(),
                    name: member.name.clone(),
                });
            }
            proxies.insert(
                member.name.clone(),
                ProxyRegistration {
                    name: member.name.clone(),
                    kind: Some(member.kind()),
                    source: ProxySource::ProviderInline {
                        provider: provider_name.clone(),
                    },
                    dialer_proxy: member.dialer_proxy(),
                },
            );
            proxy_definitions.insert(member.name.clone(), member.definition.clone());
        }
    }
    let mut groups = BTreeMap::new();
    for runtime in runtime_groups {
        let definition = document
            .proxy_groups
            .iter()
            .find(|group| group.name == runtime.group.name)
            .expect("runtime group definition should exist");
        let candidates = expand_group_candidates(definition, &runtime, &providers)?;
        groups.insert(
            runtime.group.name.clone(),
            RuntimeGroupView {
                runtime,
                candidate_names: candidates,
            },
        );
    }

    let default_provider_members = topology.synthetic_default_provider_members.clone();
    if topology.injected_global {
        groups.insert(
            "GLOBAL".into(),
            RuntimeGroupView {
                runtime: RuntimeGroup::new(ResolvedGroup {
                    name: "GLOBAL".into(),
                    group_type: "select".into(),
                    proxies: default_provider_members.clone(),
                    use_providers: vec![],
                }),
                candidate_names: default_provider_members.clone(),
            },
        );
    }

    Ok(RuntimeRegistry {
        topology,
        proxies,
        proxy_definitions,
        providers,
        groups,
        default_provider_members,
    })
}

fn build_provider_runtimes(
    document: &RuntimeConfigDocument,
    sources: &ProviderContentSources,
) -> Result<BTreeMap<String, ProviderRuntime>, RegistryError> {
    document
        .proxy_providers
        .iter()
        .map(|(name, provider)| {
            let vehicle_type = provider
                .vehicle_type()
                .ok_or_else(|| RegistryError::Regex(format!("unsupport vehicle type: {}", provider.provider_type)))?;
            let mut payload = provider.payload.clone();
            if payload.is_empty() {
                payload = load_provider_payload(provider, sources)?;
            }
            let members = materialize_provider_members(name, provider, payload)?;
            let interval_secs = if provider.health_check.enable && provider.health_check.interval == 0 {
                300
            } else {
                provider.health_check.interval
            };
            Ok((
                name.clone(),
                ProviderRuntime {
                    name: name.clone(),
                    vehicle_type,
                    members,
                    health_check: ProviderHealthCheckRuntime {
                        enabled: provider.health_check.enable,
                        url: provider.health_check.url.clone(),
                        interval_secs,
                        timeout_ms: provider.health_check.timeout,
                        lazy: provider.health_check.lazy,
                        expected_status: provider.health_check.expected_status.clone(),
                    },
                },
            ))
        })
        .collect()
}

fn expand_group_candidates(
    definition: &GroupDefinition,
    runtime: &RuntimeGroup,
    providers: &BTreeMap<String, ProviderRuntime>,
) -> Result<Vec<String>, RegistryError> {
    let mut candidates = runtime.group.proxies.clone();
    let filtered_provider_members = collect_group_provider_members(definition, providers)?;
    candidates.extend(filtered_provider_members);
    if candidates.is_empty() {
        candidates.push("COMPATIBLE".into());
    }
    Ok(candidates)
}

fn collect_group_provider_members(
    definition: &GroupDefinition,
    providers: &BTreeMap<String, ProviderRuntime>,
) -> Result<Vec<String>, RegistryError> {
    let filters = compile_patterns(&definition.filter)?;
    let exclude_filters = compile_patterns(&definition.exclude_filter)?;
    let exclude_types = parse_exclude_types(&definition.exclude_type);
    let provider_names = &definition.use_providers;

    let mut proxies = Vec::new();
    if filters.is_empty() {
        for provider_name in provider_names {
            if let Some(provider) = providers.get(provider_name) {
                proxies.extend(provider.members.clone());
            }
        }
    } else {
        for provider_name in provider_names {
            if let Some(provider) = providers.get(provider_name) {
                if provider.vehicle_type == ProxyProviderVehicleType::File
                    || provider.vehicle_type == ProxyProviderVehicleType::Http
                {
                    proxies.extend(provider.members.clone());
                    continue;
                }
                let mut new_members = Vec::new();
                let mut seen = BTreeMap::<String, ()>::new();
                for filter in &filters {
                    for member in &provider.members {
                        if filter.is_match(&member.name) && !seen.contains_key(&member.name) {
                            seen.insert(member.name.clone(), ());
                            new_members.push(member.clone());
                        }
                    }
                }
                proxies.extend(new_members);
            }
        }
    }

    if provider_names.len() > 1 && filters.len() > 1 {
        let mut reordered = Vec::new();
        let mut seen = BTreeMap::<String, ()>::new();
        for filter in &filters {
            for member in &proxies {
                if filter.is_match(&member.name) && !seen.contains_key(&member.name) {
                    seen.insert(member.name.clone(), ());
                    reordered.push(member.clone());
                }
            }
        }
        for member in &proxies {
            if !seen.contains_key(&member.name) {
                seen.insert(member.name.clone(), ());
                reordered.push(member.clone());
            }
        }
        proxies = reordered;
    }

    if !exclude_filters.is_empty() {
        proxies.retain(|member| !exclude_filters.iter().any(|regex| regex.is_match(&member.name)));
    }
    if !exclude_types.is_empty() {
        proxies.retain(|member| {
            let kind = Some(member.kind().as_str().to_ascii_lowercase());
            !kind.as_ref().is_some_and(|kind| exclude_types.iter().any(|value| value == kind))
        });
    }

    Ok(proxies.into_iter().map(|member| member.name).collect())
}

fn compile_patterns(input: &str) -> Result<Vec<Regex>, RegistryError> {
    input
        .split('`')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| Regex::new(pattern).map_err(|err| RegistryError::Regex(err.to_string())))
        .collect()
}

fn parse_exclude_types(input: &str) -> Vec<String> {
    input
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn load_provider_payload(
    provider: &mihomo_outbound::ProxyProviderDefinition,
    sources: &ProviderContentSources,
) -> Result<Vec<OutboundDefinition>, RegistryError> {
    match provider.vehicle_type() {
        Some(ProxyProviderVehicleType::Inline) | None => Ok(provider.payload.clone()),
        Some(ProxyProviderVehicleType::File) => {
            let Some(content) = sources.file_contents.get(&provider.path) else {
                return Ok(Vec::new());
            };
            Ok(parse_provider_payload_document(content)
                .map_err(|err| RegistryError::Regex(err.to_string()))?
                .proxies)
        }
        Some(ProxyProviderVehicleType::Http) => {
            let content = sources
                .http_contents
                .get(&provider.url)
                .or_else(|| sources.file_contents.get(&provider.path));
            let Some(content) = content else {
                return Ok(Vec::new());
            };
            Ok(parse_provider_payload_document(content)
                .map_err(|err| RegistryError::Regex(err.to_string()))?
                .proxies)
        }
    }
}

fn materialize_provider_members(
    provider_name: &str,
    provider: &mihomo_outbound::ProxyProviderDefinition,
    payload: Vec<OutboundDefinition>,
) -> Result<Vec<ProviderMember>, RegistryError> {
    let filters = compile_patterns(&provider.filter)?;
    let exclude_filters = compile_patterns(&provider.exclude_filter)?;
    let exclude_types = parse_exclude_types(&provider.exclude_type);

    let mut seen = BTreeMap::<String, ()>::new();
    let mut members = Vec::new();

    let mut materialized = payload
        .into_iter()
        .map(|proxy| apply_provider_override(proxy, provider_name, provider))
        .collect::<Result<Vec<_>, _>>()?;

    if !filters.is_empty() {
        let mut filtered = Vec::new();
        for filter in &filters {
            for proxy in &materialized {
                if filter.is_match(proxy.name()) && !seen.contains_key(proxy.name()) {
                    seen.insert(proxy.name().to_owned(), ());
                    filtered.push(proxy.clone());
                }
            }
        }
        materialized = filtered;
        seen.clear();
    }

    for proxy in materialized {
        if !exclude_filters.is_empty() && exclude_filters.iter().any(|regex| regex.is_match(proxy.name())) {
            continue;
        }
        if !exclude_types.is_empty()
            && exclude_types
                .iter()
                .any(|value| value == &proxy.kind().as_str().to_ascii_lowercase())
        {
            continue;
        }
        if !seen.contains_key(proxy.name()) {
            seen.insert(proxy.name().to_owned(), ());
            members.push(ProviderMember {
                name: proxy.name().to_owned(),
                definition: proxy,
            });
        }
    }

    Ok(members)
}

fn apply_provider_override(
    mut proxy: OutboundDefinition,
    _provider_name: &str,
    provider: &mihomo_outbound::ProxyProviderDefinition,
) -> Result<OutboundDefinition, RegistryError> {
    if !provider.dialer_proxy.is_empty() {
        proxy.base_mut().dialer_proxy = provider.dialer_proxy.clone();
    }

    apply_override_to_proxy(&mut proxy, &provider.override_config)?;
    Ok(proxy)
}

fn apply_override_to_proxy(
    proxy: &mut OutboundDefinition,
    override_config: &ProxyProviderOverride,
) -> Result<(), RegistryError> {
    if !override_config.dialer_proxy.is_empty() {
        proxy.base_mut().dialer_proxy = override_config.dialer_proxy.clone();
    }
    if !override_config.interface_name.is_empty() {
        proxy.base_mut().interface_name = override_config.interface_name.clone();
    }
    if override_config.routing_mark != 0 {
        proxy.base_mut().routing_mark = override_config.routing_mark;
    }
    if !override_config.ip_version.is_empty() {
        proxy.base_mut().ip_version = override_config.ip_version.clone();
    }

    let mut name = proxy.name().to_owned();
    for rename in &override_config.proxy_name {
        let pattern = rename
            .get("pattern")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let target = rename
            .get("target")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if pattern.is_empty() {
            continue;
        }
        let regex = Regex::new(pattern).map_err(|err| RegistryError::Regex(err.to_string()))?;
        name = regex.replace_all(&name, target).into_owned();
    }
    if !override_config.additional_prefix.is_empty() {
        name = format!("{}{}", override_config.additional_prefix, name);
    }
    if !override_config.additional_suffix.is_empty() {
        name = format!("{}{}", name, override_config.additional_suffix);
    }
    proxy.set_name(name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mihomo_config::parse_runtime_config_document;

    use super::{
        build_runtime_registry, build_runtime_registry_with_sources, ProviderContentSources,
        ProxySource, RegistryError,
    };

    #[test]
    fn registry_collects_builtin_user_group_and_provider_nodes() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: direct-a
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: ss
        name: provider-ss
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: password
proxy-groups:
  - name: auto
    type: select
    proxies: [direct-a]
    use: [provider1]
"#,
        )
        .unwrap();

        let registry = build_runtime_registry(&document).unwrap();
        assert_eq!(registry.providers["provider1"].members.len(), 1);
        assert_eq!(registry.providers["provider1"].members[0].name, "provider-ss");
        assert_eq!(registry.groups["auto"].candidate_names, vec!["direct-a", "provider-ss"]);
        assert_eq!(registry.proxies["DIRECT"].source, ProxySource::Builtin);
        assert_eq!(registry.proxies["direct-a"].source, ProxySource::UserConfig);
        assert_eq!(registry.proxies["auto"].source, ProxySource::GroupSynthetic);
    }

    #[test]
    fn group_filter_applies_only_to_provider_members() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: direct-a
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: ss
        name: HK-1
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: password
      - type: ss
        name: US-1
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: password
proxy-groups:
  - name: auto
    type: select
    proxies: [direct-a]
    use: [provider1]
    filter: "HK"
"#,
        )
        .unwrap();

        let registry = build_runtime_registry(&document).unwrap();
        assert_eq!(registry.groups["auto"].candidate_names, vec!["direct-a", "HK-1"]);
    }

    #[test]
    fn group_exclude_type_and_empty_provider_result_falls_back_to_compatible() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: ss
        name: HK-1
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: password
proxy-groups:
  - name: auto
    type: select
    use: [provider1]
    exclude-type: ss
"#,
        )
        .unwrap();

        let registry = build_runtime_registry(&document).unwrap();
        assert_eq!(registry.groups["auto"].candidate_names, vec!["COMPATIBLE"]);
    }

    #[test]
    fn invalid_group_filter_regex_returns_error() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: direct
        name: a
proxy-groups:
  - name: auto
    type: select
    use: [provider1]
    filter: "("
"#,
        )
        .unwrap();

        match build_runtime_registry(&document).unwrap_err() {
            RegistryError::Regex(_) => {}
            other => panic!("expected regex error, got {other:?}"),
        }
    }

    #[test]
    fn file_provider_content_is_loaded_and_overridden() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: file
    path: ./provider.yaml
    dialer-proxy: upstream
    override:
      additional-prefix: "[provider1] "
      interface-name: tailscale0
"#,
        )
        .unwrap();
        let sources = ProviderContentSources {
            file_contents: BTreeMap::from([(
                "./provider.yaml".into(),
                r#"
proxies:
  - type: direct
    name: direct-a
"#
                .into(),
            )]),
            http_contents: BTreeMap::new(),
            file_blobs: BTreeMap::new(),
            http_blobs: BTreeMap::new(),
        };

        let registry = build_runtime_registry_with_sources(&document, &sources).unwrap();
        assert_eq!(registry.providers["provider1"].members[0].name, "[provider1] direct-a");
        assert_eq!(registry.providers["provider1"].health_check.interval_secs, 0);
    }

    #[test]
    fn http_provider_content_uses_url_key_and_healthcheck_defaults() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: http
    url: https://example.com/provider.yaml
    health-check:
      enable: true
"#,
        )
        .unwrap();
        let sources = ProviderContentSources {
            file_contents: BTreeMap::new(),
            http_contents: BTreeMap::from([(
                "https://example.com/provider.yaml".into(),
                r#"
proxies:
  - type: direct
    name: direct-a
"#
                .into(),
            )]),
            file_blobs: BTreeMap::new(),
            http_blobs: BTreeMap::new(),
        };

        let registry = build_runtime_registry_with_sources(&document, &sources).unwrap();
        assert_eq!(registry.providers["provider1"].members[0].name, "direct-a");
        assert_eq!(registry.providers["provider1"].health_check.interval_secs, 300);
    }

    #[test]
    fn provider_filter_and_exclude_type_apply_before_group_use() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: inline
    filter: "HK"
    exclude-type: ss
    payload:
      - type: ss
        name: HK-1
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: password
      - type: direct
        name: HK-DIRECT
      - type: direct
        name: US-DIRECT
"#,
        )
        .unwrap();

        let registry = build_runtime_registry(&document).unwrap();
        assert_eq!(registry.providers["provider1"].members.len(), 1);
        assert_eq!(registry.providers["provider1"].members[0].name, "HK-DIRECT");
    }
}
