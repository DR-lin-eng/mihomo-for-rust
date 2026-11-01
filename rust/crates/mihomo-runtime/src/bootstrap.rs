use base64::Engine;
use mihomo_config::{
    parse_runtime_config_document, BootEnvironment, BootOptions, ConfigSource, ResolvedBoot,
    RuntimeConfigDocument,
};
use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata};
use mihomo_dns::DnsError;
use mihomo_inbound::InboundDefinition;
use mihomo_rules::{geoip_provider_from_bytes, geosite_provider_from_bytes, parse_rule, RuleError};
use mihomo_transport::{TransportPlan, TransportTarget};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use url::Url;

use crate::{
    build_runtime_registry_with_sources, detect_native_support_gaps,
    resolve_proxy_path_preferring_selected, CandidateState, ExecutionError, ExecutionPlan,
    ProviderContentSources, RegistryError, RuntimeRegistry, RuntimeTunnel, TcpForwardError,
    TcpRelayStats, TcpRelayStrategy,
};

fn startup_trace(stage: &str) {
    if std::env::var_os("MIHOMO_STARTUP_TRACE").is_some() {
        eprintln!("[startup-trace] {stage}");
    }
}

#[derive(Clone, Debug)]
pub struct BootstrapState {
    pub resolved_boot: ResolvedBoot,
    pub document: RuntimeConfigDocument,
    pub provider_sources: ProviderContentSources,
    pub registry: RuntimeRegistry,
}

impl BootstrapState {
    fn provider_sources_with_rule_provider_bytes(
        &self,
    ) -> Result<ProviderContentSources, std::io::Error> {
        if self.document.rule_providers.is_empty() {
            return Ok(self.provider_sources.clone());
        }
        let mut sources = self.provider_sources.clone();
        load_rule_provider_content_sources_from_home_into(
            &self.document,
            &self.resolved_boot.home_dir,
            &mut sources,
        )?;
        Ok(sources)
    }

    pub fn provider_sources_for_snapshot(&self) -> Result<ProviderContentSources, std::io::Error> {
        self.provider_sources_with_rule_provider_bytes()
    }

    fn build_dns_runtime_from_sources(
        &self,
        sources: &ProviderContentSources,
    ) -> Result<mihomo_dns::DnsRuntime, DnsError> {
        mihomo_dns::DnsRuntime::from_document_with_rule_providers_and_home_bytes(
            &self.document,
            &sources.file_blobs,
            &sources.http_blobs,
            &self.resolved_boot.home_dir,
        )
    }

    pub fn build_dns_runtime(&self) -> Result<mihomo_dns::DnsRuntime, DnsError> {
        let sources = self
            .provider_sources_with_rule_provider_bytes()
            .map_err(|err| DnsError::Io(err.to_string()))?;
        self.build_dns_runtime_from_sources(&sources)
    }

    pub fn build_runtime_tunnel(&self) -> Result<RuntimeTunnel, RuleError> {
        let sources = self
            .provider_sources_with_rule_provider_bytes()
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        let rules = mihomo_rules::compile_rule_table_with_providers(
            &self.document.rules,
            &self.document.sub_rules,
            &self.document.rule_providers,
            &sources.file_blobs,
            &sources.http_blobs,
        )?;
        let mut tunnel = RuntimeTunnel::new(self.document.mode.clone(), self.registry.clone())
            .with_rule_set(rules).with_sniffer(self.document.sniffer.clone());
        let dns_runtime = self.build_dns_runtime_from_sources(&sources)
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        tunnel = tunnel.with_dns_runtime(dns_runtime);
        let name = self.resolved_boot.config_display_path().file_stem().map(|name|name.to_string_lossy().into_owned()).unwrap_or_else(||"config".into());
        let collector_size = self.document.profile.extra.get("smart-collector-size").and_then(serde_yaml::Value::as_f64).filter(|value|value.is_finite()&&*value>0.0).unwrap_or(100.0);
        tunnel.configure_smart(&self.resolved_boot.home_dir, &name, collector_size);
        Ok(tunnel)
    }

    pub fn build_runtime_tunnel_without_dns_runtime(&self) -> Result<RuntimeTunnel, RuleError> {
        let sources = self
            .provider_sources_with_rule_provider_bytes()
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        let rules = mihomo_rules::compile_rule_table_with_providers(
            &self.document.rules,
            &self.document.sub_rules,
            &self.document.rule_providers,
            &sources.file_blobs,
            &sources.http_blobs,
        )?;
        Ok(
            RuntimeTunnel::new(self.document.mode.clone(), self.registry.clone())
                .with_rule_set(rules).with_sniffer(self.document.sniffer.clone()),
        )
    }

    pub fn collect_default_path_proxy_names(&self) -> Result<BTreeSet<String>, RuleError> {
        let tunnel = self.build_runtime_tunnel()?;
        let metadata = Metadata {
            host: Some("www.gstatic.com".to_owned()),
            dst_port: Some(80),
            ..Metadata::default()
        };
        let mut names = BTreeSet::new();
        let (target, _) = tunnel
            .selected_target_for_metadata(&metadata)
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        let mut registry = self.registry.clone();
        let resolved = resolve_proxy_path_preferring_selected(
            &mut registry,
            &target,
            Some(&metadata),
            &BTreeMap::<String, CandidateState>::new(),
        )
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        names.extend(resolved.selected_path);
        names.extend(resolved.dialer_path);

        let mut registry = self.registry.clone();
        for group_name in self
            .registry
            .groups
            .iter()
            .filter_map(|(name, view)| view.runtime.selected().map(|_| name.clone()))
        {
            let resolved = resolve_proxy_path_preferring_selected(
                &mut registry,
                &group_name,
                None,
                &BTreeMap::<String, CandidateState>::new(),
            )
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            names.extend(resolved.selected_path);
            names.extend(resolved.dialer_path);
        }

        for target in explicit_rule_targets(&self.document)? {
            let resolved = resolve_proxy_path_preferring_selected(
                &mut registry,
                &target,
                None,
                &BTreeMap::<String, CandidateState>::new(),
            )
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            names.extend(resolved.selected_path);
            names.extend(resolved.dialer_path);
        }

        for target in explicit_listener_targets(&self.document) {
            let resolved = resolve_proxy_path_preferring_selected(
                &mut registry,
                &target,
                None,
                &BTreeMap::<String, CandidateState>::new(),
            )
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            names.extend(resolved.selected_path);
            names.extend(resolved.dialer_path);
        }

        for target in explicit_provider_proxy_targets(&self.document) {
            let resolved = resolve_proxy_path_preferring_selected(
                &mut registry,
                &target,
                None,
                &BTreeMap::<String, CandidateState>::new(),
            )
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            names.extend(resolved.selected_path);
            names.extend(resolved.dialer_path);
        }

        Ok(names)
    }

    pub fn detect_default_path_native_support_gaps(
        &self,
    ) -> Result<Vec<crate::NativeSupportGap>, RuleError> {
        let names = self.collect_default_path_proxy_names()?;
        let mut gaps = Vec::new();
        let all_gaps = detect_native_support_gaps(&self.registry);
        for name in names {
            gaps.extend(
                all_gaps
                    .iter()
                    .filter(|gap| gap.proxy_name == name)
                    .cloned(),
            );
        }
        gaps.dedup_by(|left, right| {
            left.proxy_name == right.proxy_name
                && left.kind == right.kind
                && left.provider_name == right.provider_name
                && left.reason == right.reason
        });
        Ok(gaps)
    }

    pub fn into_runtime_tunnel(self) -> Result<RuntimeTunnel, RuleError> {
        let sources = self
            .provider_sources_with_rule_provider_bytes()
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        let rules = mihomo_rules::compile_rule_table_with_providers(
            &self.document.rules,
            &self.document.sub_rules,
            &self.document.rule_providers,
            &sources.file_blobs,
            &sources.http_blobs,
        )?;
        let dns_runtime = self.build_dns_runtime_from_sources(&sources).ok();
        let mut tunnel = RuntimeTunnel::new(self.document.mode, self.registry).with_rule_set(rules).with_sniffer(self.document.sniffer.clone());
        if let Some(dns_runtime) = dns_runtime {
            tunnel = tunnel.with_dns_runtime(dns_runtime);
        }
        Ok(tunnel)
    }

    pub fn build_execution_plan(
        &mut self,
        target: &str,
        metadata: Option<&Metadata>,
        states: &BTreeMap<String, CandidateState>,
    ) -> Result<ExecutionPlan, ExecutionError> {
        crate::build_execution_plan(&mut self.registry, target, metadata, states)
    }

    pub fn build_transport_plan(
        &mut self,
        target: &str,
        metadata: &Metadata,
        states: &BTreeMap<String, CandidateState>,
    ) -> Result<TransportPlan, ExecutionError> {
        crate::build_transport_plan(&mut self.registry, target, metadata, states)
    }

    pub fn connect_target<R>(
        &mut self,
        target: &str,
        metadata: &Metadata,
        states: &BTreeMap<String, CandidateState>,
        runner: &mut R,
    ) -> Result<BoxedTcpStream, ExecutionError>
    where
        R: mihomo_transport::TransportPlanRunner<Output = BoxedTcpStream>,
    {
        crate::connect_target(&mut self.registry, target, metadata, states, runner)
    }

    pub fn forward_tcp_context_with_system_dialer(
        &mut self,
        target: &str,
        context: &mut ConnectionContext,
        states: &BTreeMap<String, CandidateState>,
        strategy: TcpRelayStrategy,
    ) -> Result<TcpRelayStats, TcpForwardError> {
        crate::forward_tcp_context_with_system_dialer(
            &mut self.registry,
            target,
            context,
            states,
            strategy,
        )
    }

    pub fn apply_selected_proxy_mapping(&mut self, mapping: &BTreeMap<String, String>) {
        for (group_name, selected) in mapping {
            if let Some(view) = self.registry.groups.get_mut(group_name) {
                if selected.trim().is_empty() {
                    view.runtime.clear_selected();
                } else if view
                    .candidate_names
                    .iter()
                    .any(|candidate| candidate == selected)
                {
                    view.runtime.set_selected(selected.clone());
                } else {
                    view.runtime.clear_selected();
                }
            }
        }
    }

    pub fn refresh_rule_provider_sources(
        &mut self,
        provider_name: &str,
        tunnel: &RuntimeTunnel,
    ) -> Result<(), BootstrapError> {
        let Some(provider) = self.document.rule_providers.get(provider_name) else {
            return Err(BootstrapError::MissingRuleProvider(
                provider_name.to_owned(),
            ));
        };
        let updated_at=match provider.vehicle_type() {
            Some(mihomo_config::RuleProviderVehicleType::Inline) => Some(provider_now_ms()),
            Some(mihomo_config::RuleProviderVehicleType::File) => {
                if provider.path.is_empty() {
                    return Ok(());
                }
                let path = resolve_home_relative(&self.resolved_boot.home_dir, &provider.path);
                let content = fs::read(&path)?;
                self.provider_sources
                    .file_blobs
                    .insert(provider.path.clone(), content);
                Some(provider_file_ms(&path))
            }
            Some(mihomo_config::RuleProviderVehicleType::Http) => {
                let fresh=refresh_http_rule_provider_source(
                    &mut self.provider_sources,
                    &self.resolved_boot.home_dir,
                    provider,
                    tunnel,
                )?;
                fresh.then(provider_now_ms)
            }
            None => None,
        };
        if let Some(updated_at)=updated_at {
            self.provider_sources.rule_provider_updated_at.insert(provider_name.into(),updated_at);
        }
        Ok(())
    }

    pub fn refresh_proxy_provider_sources(
        &mut self,
        provider_name: &str,
        tunnel: &RuntimeTunnel,
    ) -> Result<(), BootstrapError> {
        let Some(provider) = self.document.proxy_providers.get(provider_name) else {
            return Err(BootstrapError::MissingProxyProvider(
                provider_name.to_owned(),
            ));
        };
        match provider.vehicle_type() {
            Some(mihomo_outbound::ProxyProviderVehicleType::Inline) => Ok(()),
            Some(mihomo_outbound::ProxyProviderVehicleType::File) => {
                if provider.path.is_empty() {
                    return Ok(());
                }
                let path = resolve_home_relative(&self.resolved_boot.home_dir, &provider.path);
                let content = fs::read(&path)?;
                if let Ok(text) = String::from_utf8(content) {
                    self.provider_sources
                        .file_contents
                        .insert(provider.path.clone(), text);
                }
                Ok(())
            }
            Some(mihomo_outbound::ProxyProviderVehicleType::Http) => {
                refresh_http_proxy_provider_source(
                    &mut self.provider_sources,
                    &self.resolved_boot.home_dir,
                    provider,
                    tunnel,
                )
            }
            None => Ok(()),
        }
    }
}

fn explicit_rule_targets(document: &RuntimeConfigDocument) -> Result<Vec<String>, RuleError> {
    let mut targets = BTreeSet::new();
    collect_rule_targets(&mut targets, &document.rules)?;
    for rules in document.sub_rules.values() {
        collect_rule_targets(&mut targets, rules)?;
    }
    Ok(targets.into_iter().collect())
}

fn collect_rule_targets(targets: &mut BTreeSet<String>, rules: &[String]) -> Result<(), RuleError> {
    for raw in rules {
        let definition = parse_rule(raw)?;
        let target = definition.target.trim();
        if target.is_empty() {
            continue;
        }
        if matches!(
            target,
            "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "GLOBAL" | "COMPATIBLE" | "dns"
        ) {
            continue;
        }
        targets.insert(target.to_owned());
    }
    Ok(())
}

fn explicit_listener_targets(document: &RuntimeConfigDocument) -> Vec<String> {
    let mut targets = Vec::new();
    if document.tun.enable {
        targets.push(document.tun.config.base.special_proxy.clone());
    }
    for listener in &document.listeners {
        let target = match listener {
            InboundDefinition::Socks(config) => &config.base.special_proxy,
            InboundDefinition::Http(config) => &config.base.special_proxy,
            InboundDefinition::Mixed(config) => &config.base.special_proxy,
            InboundDefinition::Redir(config) => &config.base.special_proxy,
            InboundDefinition::TProxy(config) => &config.base.special_proxy,
            InboundDefinition::Tunnel(config) => &config.base.special_proxy,
            InboundDefinition::Tun(config) => &config.base.special_proxy,
            _ => continue,
        };
        targets.push(target.clone());
    }
    targets
        .into_iter()
        .map(|target| target.trim().to_owned())
        .filter(|target| !target.is_empty())
        .filter(|target| {
            !matches!(
                target.as_str(),
                "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "GLOBAL" | "COMPATIBLE" | "dns"
            )
        })
        .collect()
}

fn explicit_provider_proxy_targets(document: &RuntimeConfigDocument) -> Vec<String> {
    document
        .proxy_providers
        .values()
        .map(|provider| provider.proxy.as_str())
        .chain(
            document
                .rule_providers
                .values()
                .map(|provider| provider.proxy.as_str()),
        )
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .filter(|target| {
            !matches!(
                *target,
                "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "GLOBAL" | "COMPATIBLE" | "dns"
            )
        })
        .map(ToOwned::to_owned)
        .collect()
}

#[derive(Debug)]
pub enum BootstrapError {
    Io(std::io::Error),
    Base64(base64::DecodeError),
    Utf8(std::string::FromUtf8Error),
    ParseConfig(serde_yaml::Error),
    Registry(RegistryError),
    MissingHttpProviderCache,
    MissingProxyProvider(String),
    MissingRuleProvider(String),
    GeoData(String),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Base64(err) => write!(f, "{err}"),
            Self::Utf8(err) => write!(f, "{err}"),
            Self::ParseConfig(err) => write!(f, "{err}"),
            Self::Registry(err) => write!(f, "{err}"),
            Self::MissingHttpProviderCache => write!(f, "http provider cache file is missing"),
            Self::MissingProxyProvider(name) => write!(f, "proxy provider not found: {name}"),
            Self::MissingRuleProvider(name) => write!(f, "rule provider not found: {name}"),
            Self::GeoData(message) => write!(f, "geodata error: {message}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<std::io::Error> for BootstrapError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<base64::DecodeError> for BootstrapError {
    fn from(value: base64::DecodeError) -> Self {
        Self::Base64(value)
    }
}

impl From<std::string::FromUtf8Error> for BootstrapError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::Utf8(value)
    }
}

impl From<serde_yaml::Error> for BootstrapError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::ParseConfig(value)
    }
}

impl From<RegistryError> for BootstrapError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

pub fn bootstrap_from_boot_options(
    options: &BootOptions,
    cwd: &Path,
    env: &BootEnvironment,
) -> Result<BootstrapState, BootstrapError> {
    bootstrap_from_boot_options_with_stdin(options, cwd, env, &mut std::io::empty())
}

pub fn bootstrap_from_boot_options_with_stdin(
    options: &BootOptions,
    cwd: &Path,
    env: &BootEnvironment,
    stdin: &mut dyn Read,
) -> Result<BootstrapState, BootstrapError> {
    startup_trace("bootstrap:resolve");
    let resolved_boot = options.resolve(cwd, env);
    startup_trace("bootstrap:load-config-text:start");
    let config_text = load_config_text(&resolved_boot, stdin)?;
    startup_trace("bootstrap:load-config-text:done");
    startup_trace("bootstrap:parse-config:start");
    let mut document = apply_boot_overrides(parse_runtime_config_document(&config_text)?, options);
    inject_builtin_geodata(&mut document, &resolved_boot.home_dir)?;
    startup_trace("bootstrap:parse-config:done");
    startup_trace("bootstrap:load-provider-sources:start");
    let provider_sources =
        load_provider_content_sources_from_home(&document, &resolved_boot.home_dir)?;
    startup_trace("bootstrap:load-provider-sources:done");
    startup_trace("bootstrap:build-registry:start");
    let registry = build_runtime_registry_with_sources(&document, &provider_sources)?;
    startup_trace("bootstrap:build-registry:done");
    Ok(BootstrapState {
        resolved_boot,
        document,
        provider_sources,
        registry,
    })
}

pub fn bootstrap_from_yaml(
    yaml: &str,
    home_dir: &Path,
) -> Result<
    (
        RuntimeConfigDocument,
        ProviderContentSources,
        RuntimeRegistry,
    ),
    BootstrapError,
> {
    let mut document = parse_runtime_config_document(yaml)?;
    inject_builtin_geodata(&mut document, home_dir)?;
    let provider_sources = load_provider_content_sources_from_home(&document, home_dir)?;
    let registry = build_runtime_registry_with_sources(&document, &provider_sources)?;
    Ok((document, provider_sources, registry))
}

pub fn load_provider_content_sources_from_home(
    document: &RuntimeConfigDocument,
    home_dir: &Path,
) -> Result<ProviderContentSources, std::io::Error> {
    let mut sources = ProviderContentSources::default();
    for provider in document.proxy_providers.values() {
        match provider.vehicle_type() {
            Some(mihomo_outbound::ProxyProviderVehicleType::File) => {
                if provider.url.is_empty() && provider.path.is_empty() {
                    continue;
                }
                if !provider.url.is_empty() {
                    if load_cached_http_proxy_provider_source(&mut sources, home_dir, provider)? {
                        continue;
                    }
                    let tunnel = build_provider_fetch_tunnel(document, &sources, home_dir);
                    let _ = refresh_http_proxy_provider_source(
                        &mut sources,
                        home_dir,
                        provider,
                        &tunnel,
                    );
                    continue;
                }
                if provider.path.is_empty() {
                    continue;
                }
                let path = resolve_home_relative(home_dir, &provider.path);
                let content = match fs::read(&path) {
                    Ok(content) => content,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                };
                sources
                    .file_blobs
                    .insert(provider.path.clone(), content.clone());
                if let Ok(text) = String::from_utf8(content) {
                    sources.file_contents.insert(provider.path.clone(), text);
                }
            }
            Some(mihomo_outbound::ProxyProviderVehicleType::Http) => {
                if load_cached_http_proxy_provider_source(&mut sources, home_dir, provider)? {
                    continue;
                }
                let tunnel = build_provider_fetch_tunnel(document, &sources, home_dir);
                let _ =
                    refresh_http_proxy_provider_source(&mut sources, home_dir, provider, &tunnel);
            }
            _ => {}
        }
    }
    load_rule_provider_content_sources_from_home_into(document, home_dir, &mut sources)?;
    Ok(sources)
}

fn load_rule_provider_content_sources_from_home_into(
    document: &RuntimeConfigDocument,
    home_dir: &Path,
    sources: &mut ProviderContentSources,
) -> Result<(), std::io::Error> {
    for (name,provider) in &document.rule_providers {
        match provider.vehicle_type() {
            Some(mihomo_config::RuleProviderVehicleType::File) => {
                if provider.url.is_empty() && provider.path.is_empty() {
                    continue;
                }
                if !provider.url.is_empty() {
                    if load_cached_http_rule_provider_source(sources, home_dir, provider)? {
                        sources.rule_provider_updated_at.entry(name.clone()).or_insert_with(||provider_file_ms(&resolve_home_relative(home_dir,&provider.path)));
                        continue;
                    }
                    let tunnel = build_provider_fetch_tunnel(document, &sources, home_dir);
                    if matches!(refresh_http_rule_provider_source(sources, home_dir, provider, &tunnel),Ok(true)) {
                        sources.rule_provider_updated_at.insert(name.clone(),provider_now_ms());
                    }
                    continue;
                }
                if provider.path.is_empty() {
                    continue;
                }
                let path = resolve_home_relative(home_dir, &provider.path);
                let content = match fs::read(&path) {
                    Ok(content) => content,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                };
                sources
                    .file_blobs
                    .insert(provider.path.clone(), content.clone());
                sources.rule_provider_updated_at.insert(name.clone(),provider_file_ms(&path));
                if let Ok(text) = String::from_utf8(content) {
                    sources.file_contents.insert(provider.path.clone(), text);
                }
            }
            Some(mihomo_config::RuleProviderVehicleType::Http) => {
                if load_cached_http_rule_provider_source(sources, home_dir, provider)? {
                    sources.rule_provider_updated_at.entry(name.clone()).or_insert_with(||provider_file_ms(&resolve_home_relative(home_dir,&provider.path)));
                    continue;
                }
                let tunnel = build_provider_fetch_tunnel(document, &sources, home_dir);
                if matches!(refresh_http_rule_provider_source(sources, home_dir, provider, &tunnel),Ok(true)) {
                    sources.rule_provider_updated_at.insert(name.clone(),provider_now_ms());
                }
            }
            Some(mihomo_config::RuleProviderVehicleType::Inline)=>{
                sources.rule_provider_updated_at.entry(name.clone()).or_insert_with(provider_now_ms);
            }
            _ => {}
        }
    }
    Ok(())
}

fn load_cached_http_rule_provider_source(
    sources: &mut ProviderContentSources,
    home_dir: &Path,
    provider: &mihomo_config::RuleProviderDefinition,
) -> Result<bool, std::io::Error> {
    let content = match read_http_provider_cache(home_dir, &provider.path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    validate_http_rule_provider_content(provider, &content)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    cache_rule_provider_content(sources, &provider.path, &provider.url, &content);
    Ok(true)
}

fn provider_now_ms()->u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis().min(u128::from(u64::MAX)) as u64
}
fn provider_file_ms(path:&Path)->u64 {
    fs::metadata(path).and_then(|metadata|metadata.modified()).ok()
        .and_then(|time|time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|time|time.as_millis().min(u128::from(u64::MAX)) as u64).unwrap_or(0)
}

fn load_cached_http_proxy_provider_source(
    sources: &mut ProviderContentSources,
    home_dir: &Path,
    provider: &mihomo_outbound::ProxyProviderDefinition,
) -> Result<bool, std::io::Error> {
    let content = match read_http_provider_cache(home_dir, &provider.path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    store_http_proxy_provider_content(home_dir, sources, &provider.path, &provider.url, &content)?;
    Ok(true)
}

fn build_provider_fetch_tunnel(
    document: &RuntimeConfigDocument,
    sources: &ProviderContentSources,
    home_dir: &Path,
) -> RuntimeTunnel {
    let registry = build_runtime_registry_with_sources(document, sources).unwrap_or_else(|err| {
        let topology = crate::AssembledProxyTopology {
            builtin_proxy_names: vec![
                "DIRECT".into(),
                "REJECT".into(),
                "REJECT-DROP".into(),
                "COMPATIBLE".into(),
                "PASS".into(),
            ],
            user_proxy_names_in_order: Vec::new(),
            all_proxy_names_sorted: Vec::new(),
            all_provider_names_sorted: Vec::new(),
            group_names_in_original_order: Vec::new(),
            group_names_in_dependency_order: Vec::new(),
            resolved_groups_in_dependency_order: Vec::new(),
            proxy_list_order: vec!["DIRECT".into(), "REJECT".into()],
            synthetic_default_provider_members: vec!["DIRECT".into(), "REJECT".into()],
            final_proxy_names: ["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            injected_global: false,
        };
        let mut proxies = BTreeMap::new();
        for name in ["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS"] {
            proxies.insert(
                name.to_owned(),
                crate::ProxyRegistration {
                    name: name.to_owned(),
                    kind: None,
                    source: crate::ProxySource::Builtin,
                    dialer_proxy: None,
                },
            );
        }
        let _ = err;
        RuntimeRegistry {
            topology,
            proxies,
            proxy_definitions: BTreeMap::new(),
            providers: BTreeMap::new(),
            groups: BTreeMap::new(),
            default_provider_members: Vec::new(),
        }
    });
    let mut tunnel = RuntimeTunnel::new("direct", registry);
    // Provider bootstrap frequently reconstructs this tunnel while sources grow.
    // Loading every fetched rule-provider payload into the DNS runtime on each pass
    // can balloon memory usage before startup completes, especially with large MRS sets.
    // For bootstrap fetches we only need lightweight DNS features such as hosts/nameserver
    // handling; rule-provider-backed DNS rules are not required to download provider content.
    let empty_sources = BTreeMap::<String, Vec<u8>>::new();
    if let Ok(dns_runtime) =
        mihomo_dns::DnsRuntime::from_document_with_rule_providers_and_home_bytes(
            document,
            &empty_sources,
            &empty_sources,
            home_dir,
        )
    {
        tunnel = tunnel.with_dns_runtime(dns_runtime);
    }
    tunnel
}

fn load_config_text(
    resolved_boot: &ResolvedBoot,
    stdin: &mut dyn Read,
) -> Result<String, BootstrapError> {
    match &resolved_boot.config_source {
        ConfigSource::Base64(encoded) => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
            Ok(String::from_utf8(bytes)?)
        }
        ConfigSource::File(path) => Ok(fs::read_to_string(path)?),
        ConfigSource::Stdin => {
            let mut bytes = Vec::new();
            stdin.read_to_end(&mut bytes)?;
            Ok(String::from_utf8(bytes)?)
        }
    }
}

fn resolve_home_relative(home_dir: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        home_dir.join(candidate)
    }
}

fn inject_builtin_geodata(
    document: &mut RuntimeConfigDocument,
    home_dir: &Path,
) -> Result<(), BootstrapError> {
    let geosite_names = collect_geosite_names(document);
    let geoip_names = collect_geoip_names(document);
    if geosite_names.is_empty() && geoip_names.is_empty() {
        return Ok(());
    }

    if !geosite_names.is_empty() {
        if let Some((path, bytes)) =
            read_geodata_asset(home_dir, &["GeoSite.dat", "geosite.dat", "geosite.site"])
        {
            for name in geosite_names {
                if document.rule_providers.contains_key(&name) {
                    continue;
                }
                let provider = geosite_provider_from_bytes(&bytes, &name)
                    .map_err(|err| BootstrapError::GeoData(format!("{}: {err}", path.display())))?;
                document.rule_providers.insert(name, provider);
            }
        }
    }
    if !geoip_names.is_empty() {
        if let Some((path, bytes)) = read_geodata_asset(home_dir, &["GeoIP.dat", "geoip.dat"]) {
            for name in geoip_names {
                let provider_name = format!("{}_IP", name.to_ascii_uppercase());
                if document.rule_providers.contains_key(&provider_name) {
                    continue;
                }
                let provider = geoip_provider_from_bytes(&bytes, &name)
                    .map_err(|err| BootstrapError::GeoData(format!("{}: {err}", path.display())))?;
                document.rule_providers.insert(provider_name, provider);
            }
        }
    }
    Ok(())
}

fn read_geodata_asset(home_dir: &Path, names: &[&str]) -> Option<(PathBuf, Vec<u8>)> {
    let roots = [
        home_dir.to_path_buf(),
        home_dir.join("geo"),
        home_dir.join("resources"),
    ];
    for root in roots {
        for name in names {
            let path = root.join(name);
            if let Ok(bytes) = fs::read(&path) {
                return Some((path, bytes));
            }
        }
    }
    None
}

fn collect_geosite_names(document: &RuntimeConfigDocument) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for raw in document
        .rules
        .iter()
        .chain(document.sub_rules.values().flatten())
    {
        collect_rule_geodata_name(raw, "GEOSITE", &mut names);
    }
    for raw in &document.dns.fake_ip_filter {
        collect_short_geodata_name(raw, "geosite:", &mut names);
    }
    for raw in &document.dns.fallback_filter.domain {
        collect_short_geodata_name(raw, "geosite:", &mut names);
    }
    for raw in &document.dns.fallback_filter.geosite {
        collect_short_geodata_name(raw, "", &mut names);
    }
    for key in document
        .dns
        .nameserver_policy
        .keys()
        .chain(document.dns.proxy_server_nameserver_policy.keys())
    {
        collect_short_geodata_name(key, "geosite:", &mut names);
    }
    names
}

fn collect_geoip_names(document: &RuntimeConfigDocument) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for raw in document
        .rules
        .iter()
        .chain(document.sub_rules.values().flatten())
    {
        collect_rule_geodata_name(raw, "GEOIP", &mut names);
    }
    for raw in &document.dns.fallback_filter.ipcidr {
        collect_short_geodata_name(raw, "geoip:", &mut names);
    }
    names
}

fn collect_rule_geodata_name(raw: &str, kind: &str, names: &mut BTreeSet<String>) {
    let mut parts = raw.split(',');
    if parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(kind))
    {
        if let Some(name) = parts.next().map(str::trim).filter(|name| !name.is_empty()) {
            names.insert(name.to_owned());
        }
    }
}

fn collect_short_geodata_name(raw: &str, prefix: &str, names: &mut BTreeSet<String>) {
    let value = raw.trim();
    let name = if prefix.is_empty() {
        value
    } else {
        value.strip_prefix(prefix).unwrap_or_default()
    };
    let name = name.trim();
    if !name.is_empty() {
        names.insert(name.to_owned());
    }
}

fn apply_boot_overrides(
    mut document: RuntimeConfigDocument,
    options: &BootOptions,
) -> RuntimeConfigDocument {
    if let Some(external_ui) = &options.external_ui {
        document.external_ui = external_ui.clone();
    }
    if let Some(external_controller) = &options.external_controller {
        document.external_controller = external_controller.clone();
    }
    if let Some(external_controller_unix) = &options.external_controller_unix {
        document.external_controller_unix = external_controller_unix.clone();
    }
    if let Some(external_controller_pipe) = &options.external_controller_pipe {
        document.external_controller_pipe = external_controller_pipe.clone();
    }
    if let Some(secret) = &options.secret {
        document.secret = secret.clone();
    }
    if options.geodata_mode {
        document.geodata_mode = true;
    }
    document
}

fn refresh_http_rule_provider_source(
    sources: &mut ProviderContentSources,
    home_dir: &Path,
    provider: &mihomo_config::RuleProviderDefinition,
    tunnel: &RuntimeTunnel,
) -> Result<bool, BootstrapError> {
    let fetched = fetch_http_provider_bytes(
        &provider.url,
        &provider.header,
        provider.size_limit,
        &provider.proxy,
        tunnel,
    )
    .or_else(|_| {
        if provider.proxy.trim().is_empty() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "direct fetch already attempted",
            ))
        } else {
            fetch_http_provider_bytes(
                &provider.url,
                &provider.header,
                provider.size_limit,
                "",
                tunnel,
            )
        }
    });
    let (content,fresh)=match fetched {
        Ok(content)=>(content,true),
        Err(_)=>match read_http_provider_cache(home_dir,&provider.path) {
            Ok(content)=>(content,false),
            Err(err) if err.kind()==io::ErrorKind::NotFound=>return Ok(false),
            Err(err)=>return Err(err.into()),
        },
    };
    validate_http_rule_provider_content(provider, &content)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    if fresh && provider.behavior_kind()==Some(mihomo_config::RuleProviderBehavior::Classical) {
        // A well-formed YAML payload can still contain invalid rule syntax.
        // Compile fresh classical rules before replacing a working cache.
        let providers=BTreeMap::from([("_validate".to_owned(),provider.clone())]);
        let files=BTreeMap::from([(provider.path.clone(),content.as_slice())]);
        let remote=BTreeMap::from([(provider.url.clone(),content.as_slice())]);
        mihomo_rules::compile_rule_table_with_providers(&["RULE-SET,_validate,DIRECT".into()],&BTreeMap::new(),&providers,&files,&remote)
            .map_err(|err|io::Error::new(io::ErrorKind::InvalidData,err.to_string()))?;
    }
    if fresh {store_http_rule_provider_content(home_dir, sources, &provider.path, &provider.url, &content)?;}
    else {cache_rule_provider_content(sources,&provider.path,&provider.url,&content);}
    Ok(fresh)
}

fn validate_http_rule_provider_content(
    provider: &mihomo_config::RuleProviderDefinition,
    content: &[u8],
) -> Result<(), mihomo_rules::RuleError> {
    let behavior = provider.behavior_kind().ok_or_else(|| {
        mihomo_rules::RuleError::UnsupportedRuleProviderBehavior(provider.behavior.clone())
    })?;
    let format = provider.format_kind().ok_or_else(|| {
        mihomo_rules::RuleError::UnsupportedRuleProviderFormat(provider.format.clone())
    })?;
    mihomo_rules::validate_rule_provider_content(content, behavior, format)
}

fn refresh_http_proxy_provider_source(
    sources: &mut ProviderContentSources,
    home_dir: &Path,
    provider: &mihomo_outbound::ProxyProviderDefinition,
    tunnel: &RuntimeTunnel,
) -> Result<(), BootstrapError> {
    let content = match fetch_http_provider_bytes(
        &provider.url,
        &provider.header,
        provider.size_limit,
        &provider.proxy,
        tunnel,
    )
    .or_else(|_| {
        if provider.proxy.trim().is_empty() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "direct fetch already attempted",
            ))
        } else {
            fetch_http_provider_bytes(
                &provider.url,
                &provider.header,
                provider.size_limit,
                "",
                tunnel,
            )
        }
    })
    .or_else(|_| read_http_provider_cache(home_dir, &provider.path))
    {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    store_http_proxy_provider_content(home_dir, sources, &provider.path, &provider.url, &content)?;
    Ok(())
}

fn fetch_http_provider_bytes(
    url: &str,
    header: &BTreeMap<String, Vec<String>>,
    size_limit: i64,
    proxy: &str,
    tunnel: &RuntimeTunnel,
) -> std::io::Result<Vec<u8>> {
    if !proxy.trim().is_empty() {
        return fetch_http_provider_bytes_via_proxy(tunnel, url, header, size_limit, proxy);
    }
    fetch_http_provider_bytes_direct(tunnel, url, header, size_limit)
}

fn fetch_http_provider_bytes_via_proxy(
    tunnel: &RuntimeTunnel,
    url: &str,
    header: &BTreeMap<String, Vec<String>>,
    size_limit: i64,
    proxy_name: &str,
) -> std::io::Result<Vec<u8>> {
    let parsed = Url::parse(url)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing url host"))?;
    let scheme = parsed.scheme();
    let port =
        parsed
            .port_or_known_default()
            .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    let path = {
        let mut path = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        if path.is_empty() {
            "/".to_owned()
        } else {
            path
        }
    };
    fetch_http_provider_bytes_over_stream(
        tunnel,
        url,
        host,
        scheme,
        port,
        &path,
        header,
        size_limit,
        Some(proxy_name),
    )
}

fn fetch_http_provider_bytes_direct(
    tunnel: &RuntimeTunnel,
    url: &str,
    header: &BTreeMap<String, Vec<String>>,
    size_limit: i64,
) -> std::io::Result<Vec<u8>> {
    let parsed = Url::parse(url)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing url host"))?;
    let scheme = parsed.scheme();
    let port =
        parsed
            .port_or_known_default()
            .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    let path = {
        let mut path = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        if path.is_empty() {
            "/".to_owned()
        } else {
            path
        }
    };
    fetch_http_provider_bytes_over_stream(
        tunnel, url, host, scheme, port, &path, header, size_limit, None,
    )
}

fn fetch_http_provider_bytes_over_stream(
    tunnel: &RuntimeTunnel,
    url: &str,
    host: &str,
    scheme: &str,
    port: u16,
    path: &str,
    header: &BTreeMap<String, Vec<String>>,
    size_limit: i64,
    proxy_name: Option<&str>,
) -> std::io::Result<Vec<u8>> {
    let metadata = Metadata {
        host: Some(host.to_owned()),
        dst_port: Some(port),
        special_proxy: proxy_name.unwrap_or_default().to_owned(),
        ..Metadata::default()
    };
    let (mut upstream, _) = tunnel
        .connect_tcp_with_system_dialer(&metadata)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                if let Some(proxy_name) = proxy_name {
                    format!(
                        "failed to connect provider url {} via proxy {}: {}",
                        url, proxy_name, err
                    )
                } else {
                    format!("failed to connect provider url {url}: {err}")
                },
            )
        })?;
    if scheme == "https" {
        let tls = mihomo_transport::TlsOptions {
            enabled: true,
            sni: host.to_owned(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let target = TransportTarget::new(host.to_owned(), port);
        upstream = mihomo_transport::wrap_tls_proxy_stream(upstream, target, &tls, &[]).map_err(
            |err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to establish tls for provider url {url}: {err}"),
                )
            },
        )?;
    }
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in provider_request_headers(header) {
        request.push_str(&name);
        request.push_str(": ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    upstream.write_all(request.as_bytes())?;
    upstream.flush()?;

    let (headers, mut body) = read_http_response_head(&mut *upstream)?;
    let headers = String::from_utf8_lossy(&headers);
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected http status",
        ));
    }
    let expected_len = expected_http_content_length(&headers)?;
    let mut content = if response_is_chunked(&headers) {
        read_chunked_http_body(&mut *upstream, &mut body)?
    } else {
        if let Some(expected_len) = expected_len {
            if body.len() < expected_len {
                let mut remaining = vec![0_u8; expected_len - body.len()];
                upstream.read_exact(&mut remaining)?;
                body.extend_from_slice(&remaining);
            }
            body.truncate(expected_len);
        } else {
            upstream.read_to_end(&mut body)?;
        }
        body
    };
    if let Some(expected_len) = expected_len {
        if content.len() != expected_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "http response body truncated: expected {expected_len} bytes, got {}",
                    content.len()
                ),
            ));
        }
    }
    if size_limit > 0 && content.len() > size_limit as usize {
        content.truncate(size_limit as usize);
    }
    Ok(content)
}

fn read_http_response_head(stream: &mut dyn Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http response ended before headers were complete",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
        if let Some(split) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = split + 4;
            return Ok((
                response[..header_end].to_vec(),
                response[header_end..].to_vec(),
            ));
        }
        if response.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http response headers exceeded 64KiB",
            ));
        }
    }
}

fn response_is_chunked(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("Transfer-Encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    })
}

fn decode_chunked_http_body(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let size_line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "chunked response ended before chunk size line completed",
                )
            })?;
        let size_line = std::str::from_utf8(&body[..size_line_end])
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        body = &body[size_line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if body.len() < size + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunked response ended mid-chunk",
            ));
        }
        decoded.extend_from_slice(&body[..size]);
        if &body[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunked response terminator",
            ));
        }
        body = &body[size + 2..];
    }
}

fn read_chunked_http_body(stream: &mut dyn Read, initial: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    loop {
        match decode_chunked_http_body(initial) {
            Ok(decoded) => return Ok(decoded),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    return Err(err);
                }
                initial.extend_from_slice(&chunk[..read]);
            }
            Err(err) => return Err(err),
        }
    }
}

fn expected_http_content_length(headers: &str) -> io::Result<Option<usize>> {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        let length = value
            .trim()
            .parse::<usize>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        return Ok(Some(length));
    }
    Ok(None)
}

fn read_http_provider_cache(home_dir: &Path, path: &str) -> std::io::Result<Vec<u8>> {
    if path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "http provider cache file is missing",
        ));
    }
    Ok(fs::read(resolve_home_relative(home_dir, path))?)
}

fn provider_request_headers(header: &BTreeMap<String, Vec<String>>) -> Vec<(String, String)> {
    header
        .iter()
        .filter_map(|(name, values)| {
            values
                .iter()
                .find(|value| !value.trim().is_empty())
                .cloned()
                .map(|value| (name.clone(), value))
        })
        .collect()
}

fn store_http_rule_provider_content(
    home_dir: &Path,
    sources: &mut ProviderContentSources,
    path: &str,
    url: &str,
    content: &[u8],
) -> std::io::Result<()> {
    if !path.is_empty() {
        let cache_path = resolve_home_relative(home_dir, path);
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&cache_path, content)?;
    }
    cache_rule_provider_content(sources,path,url,content);
    Ok(())
}

fn cache_rule_provider_content(sources:&mut ProviderContentSources,path:&str,url:&str,content:&[u8]) {
    if !path.is_empty() {
        sources.file_blobs.insert(path.to_owned(), content.to_vec());
        if let Ok(text) = String::from_utf8(content.to_vec()) {
            sources.file_contents.insert(path.to_owned(), text);
        }
    }
    if !url.is_empty() {
        sources.http_blobs.insert(url.to_owned(), content.to_vec());
        if let Ok(text) = String::from_utf8(content.to_vec()) {
            sources.http_contents.insert(url.to_owned(), text);
        }
    }
}

fn store_http_proxy_provider_content(
    home_dir: &Path,
    sources: &mut ProviderContentSources,
    path: &str,
    url: &str,
    content: &[u8],
) -> std::io::Result<()> {
    if !path.is_empty() {
        let cache_path = resolve_home_relative(home_dir, path);
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&cache_path, content)?;
        sources.file_blobs.insert(path.to_owned(), content.to_vec());
    }
    let Ok(text) = String::from_utf8(content.to_vec()) else {
        return Ok(());
    };
    if !path.is_empty() {
        sources.file_contents.insert(path.to_owned(), text.clone());
    }
    if !url.is_empty() {
        sources.http_contents.insert(url.to_owned(), text);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use super::{bootstrap_from_boot_options, bootstrap_from_yaml};
    use crate::RuntimeTunnel;
    use base64::Engine;
    use mihomo_config::{BootEnvironment, BootOptions, Command};
    use mihomo_core::Metadata;
    use mihomo_rules::convert_ruleset_content;

    #[test]
    fn bootstrap_loads_file_provider_from_home_dir() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("provider.yaml"),
            r#"
proxies:
  - type: direct
    name: file-direct
"#,
        )
        .unwrap();
        fs::write(
            temp.join("rule-provider.yaml"),
            r#"
payload:
  - .example.org
"#,
        )
        .unwrap();
        let (document, sources, registry) = bootstrap_from_yaml(
            r#"
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
rule-providers:
  rule1:
    type: file
    behavior: domain
    path: rule-provider.yaml
"#,
            &temp,
        )
        .unwrap();
        assert!(document.proxy_providers.contains_key("provider1"));
        assert!(document.rule_providers.contains_key("rule1"));
        assert!(sources.file_contents.contains_key("provider.yaml"));
        assert!(sources.file_contents.contains_key("rule-provider.yaml"));
        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "file-direct"
        );
    }

    #[test]
    fn bootstrap_reads_base64_config_source() {
        let temp = unique_temp_dir();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
proxies:
  - type: direct
    name: base64-direct
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        assert_eq!(
            state.registry.proxies["base64-direct"].name,
            "base64-direct"
        );
    }

    #[test]
    fn bootstrap_does_not_panic_when_http_provider_config_has_missing_group_reference() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
proxies:
  - type: direct
    name: direct-a
proxy-groups:
  - name: auto
    type: url-test
    proxies: [missing-proxy]
    url: https://cp.cloudflare.com/generate_204
    interval: 300
proxy-providers:
  provider1:
    type: http
    url: https://example.com/provider.yaml
    path: cache-provider.yaml
"#,
            )),
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
        let err = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing-proxy"), "{err}");
    }

    #[test]
    fn default_path_support_gap_ignores_unsupported_provider_members_when_selected_path_is_hy2() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("provider.yaml"),
            r#"
proxies:
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
  - type: hysteria2
    name: provider-hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
"#,
        )
        .unwrap();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
proxy-groups:
  - name: 香港
    type: select
    use: [provider1]
    filter: "Hy2"
rules:
  - MATCH,香港
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn default_path_support_gap_reports_selected_vless_vision_path() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("provider.yaml"),
            r#"
proxies:
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
"#,
        )
        .unwrap();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
proxy-groups:
  - name: 自动选择
    type: url-test
    use: [provider1]
    filter: "vision"
rules:
  - MATCH,自动选择
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_prefers_fixed_url_test_member_when_it_hits_native_gap() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("provider.yaml"),
            r#"
proxies:
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
  - type: hysteria2
    name: provider-hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
"#,
        )
        .unwrap();
        let mut state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
proxy-groups:
  - name: 自动选择
    type: url-test
    use: [provider1]
rules:
  - MATCH,自动选择
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        state.apply_selected_proxy_mapping(&BTreeMap::from([(
            "自动选择".to_owned(),
            "provider-vless-vision".to_owned(),
        )]));
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_includes_non_default_fixed_group_paths() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("provider.yaml"),
            r#"
proxies:
  - type: hysteria2
    name: provider-hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
"#,
        )
        .unwrap();
        let mut state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
proxy-groups:
  - name: auto
    type: url-test
    use: [provider1]
    filter: "hy2"
  - name: manual
    type: url-test
    use: [provider1]
rules:
  - MATCH,auto
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        state.apply_selected_proxy_mapping(&BTreeMap::from([(
            "manual".to_owned(),
            "provider-vless-vision".to_owned(),
        )]));
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_includes_explicit_rule_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
rules:
  - DOMAIN,manual.example.com,provider-vless-vision
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_ignores_builtin_rule_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
rules:
  - DOMAIN,manual.example.com,DIRECT
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn default_path_support_gap_includes_listener_proxy_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
listeners:
  - type: http
    name: edge
    listen: 127.0.0.1
    port: "8080"
    proxy: provider-vless-vision
rules:
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_ignores_builtin_listener_proxy_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
listeners:
  - type: http
    name: edge
    listen: 127.0.0.1
    port: "8080"
    proxy: DIRECT
rules:
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn default_path_support_gap_includes_provider_proxy_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
proxy-providers:
  provider1:
    type: http
    url: https://example.com/provider.yaml
    path: provider.yaml
    proxy: provider-vless-vision
rules:
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_ignores_builtin_provider_proxy_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
proxy-providers:
  provider1:
    type: http
    url: https://example.com/provider.yaml
    path: provider.yaml
    proxy: DIRECT
rules:
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn default_path_support_gap_includes_tun_proxy_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
  - type: vless
    name: provider-vless-vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
tun:
  enable: true
  proxy: provider-vless-vision
rules:
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    #[test]
    fn default_path_support_gap_ignores_builtin_tun_proxy_targets() {
        let temp = unique_temp_dir();
        let state = bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
mode: rule
proxies:
  - type: direct
    name: ok
tun:
  enable: true
  proxy: DIRECT
rules:
  - MATCH,ok
"#,
                )),
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
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        let gaps = state.detect_default_path_native_support_gaps().unwrap();
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn bootstrap_applies_geodata_mode_override_to_document() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                "proxies:\n  - type: direct\n    name: base64-direct\ngeodata-mode: false\n",
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: true,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(state.document.geodata_mode);
    }

    #[test]
    fn bootstrap_reads_http_provider_cache_file_when_present() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("cache-provider.yaml"),
            r#"
proxies:
  - type: direct
    name: cached-direct
"#,
        )
        .unwrap();
        let (_, sources, registry) = bootstrap_from_yaml(
            r#"
proxy-providers:
  provider1:
    type: http
    url: https://example.com/provider.yaml
    path: cache-provider.yaml
"#,
            &temp,
        )
        .unwrap();
        assert!(sources.file_contents.contains_key("cache-provider.yaml"));
        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "cached-direct"
        );
    }

    #[test]
    fn bootstrap_prefers_http_proxy_provider_cache_over_network_fetch_during_startup() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("cache-provider.yaml"),
            r#"
proxies:
  - type: direct
    name: cached-direct
"#,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = std::sync::Arc::new(AtomicBool::new(false));
        let worker_flag = std::sync::Arc::clone(&accepted);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + std::time::Duration::from_millis(500);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((_stream, _addr)) => {
                        worker_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => panic!("unexpected accept error: {err}"),
                }
            }
        });

        let (_, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
proxy-providers:
  provider1:
    type: http
    url: http://{addr}/provider.yaml
    path: cache-provider.yaml
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "cached-direct"
        );
        assert!(sources.file_contents.contains_key("cache-provider.yaml"));
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/provider.yaml")));
        assert!(!accepted.load(Ordering::SeqCst));
    }

    #[test]
    fn bootstrap_tolerates_missing_http_provider_cache() {
        let temp = unique_temp_dir();
        let (document, sources, registry) = bootstrap_from_yaml(
            r#"
proxy-providers:
  provider1:
    type: http
    url: https://example.com/provider.yaml
    path: cache-provider.yaml
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/rule-provider.mrs
    path: cache-rules.mrs
"#,
            &temp,
        )
        .unwrap();
        assert!(document.proxy_providers.contains_key("provider1"));
        assert!(document.rule_providers.contains_key("rule1"));
        assert!(!sources.file_contents.contains_key("cache-provider.yaml"));
        assert!(!sources.file_contents.contains_key("cache-rules.mrs"));
        assert!(registry.providers["provider1"].members.is_empty());
    }

    #[test]
    fn bootstrap_tolerates_missing_file_provider_content() {
        let temp = unique_temp_dir();
        let (document, sources, registry) = bootstrap_from_yaml(
            r#"
proxy-providers:
  provider1:
    type: file
    path: missing-provider.yaml
rule-providers:
  rule1:
    type: file
    behavior: classical
    path: missing-rules.list
"#,
            &temp,
        )
        .unwrap();
        assert!(document.proxy_providers.contains_key("provider1"));
        assert!(document.rule_providers.contains_key("rule1"));
        assert!(!sources.file_contents.contains_key("missing-provider.yaml"));
        assert!(!sources.file_contents.contains_key("missing-rules.list"));
        assert!(registry.providers["provider1"].members.is_empty());
    }

    #[test]
    fn bootstrap_fetches_http_proxy_provider_and_writes_cache() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"proxies:\n  - type: direct\n    name: fetched\n";
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("GET /provider.yaml HTTP/1.1\r\n"),
                "{request}"
            );
            assert!(request.contains("X-Test: provider-fetch\r\n"), "{request}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (document, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
proxy-providers:
  provider1:
    type: http
    url: http://{addr}/provider.yaml
    path: cache-provider.yaml
    header:
      X-Test:
        - provider-fetch
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(document.proxy_providers.contains_key("provider1"));
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/provider.yaml")));
        assert!(sources.file_contents.contains_key("cache-provider.yaml"));
        assert_eq!(registry.providers["provider1"].members[0].name, "fetched");
        assert!(fs::read_to_string(temp.join("cache-provider.yaml"))
            .unwrap()
            .contains("name: fetched"));
    }

    #[test]
    fn bootstrap_reads_http_proxy_provider_without_waiting_for_connection_close() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"proxies:\n  - type: direct\n    name: fetched-no-close\n";
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            stream.flush().unwrap();
            thread::sleep(std::time::Duration::from_secs(2));
        });

        let start = Instant::now();
        let (_, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
proxy-providers:
  provider1:
    type: http
    url: http://{addr}/provider.yaml
    path: cache-provider.yaml
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        let elapsed = start.elapsed();

        worker.join().unwrap();
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "fetched-no-close"
        );
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/provider.yaml")));
    }

    #[test]
    fn bootstrap_fetches_http_proxy_provider_with_dualstack_host_fallback() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"proxies:\n  - type: direct\n    name: fetched-dualstack\n";
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("GET /provider.yaml HTTP/1.1\r\n"),
                "{request}"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (_, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
hosts:
  dualstack.invalid:
    - "::1"
    - "127.0.0.1"
dns:
  enable: true
  use-hosts: true
  use-system-hosts: false
proxy-providers:
  provider1:
    type: http
    url: http://dualstack.invalid:{port}/provider.yaml
    path: cache-provider.yaml
"#,
                port = addr.port(),
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "fetched-dualstack"
        );
        assert!(sources.http_contents.contains_key(&format!(
            "http://dualstack.invalid:{}/provider.yaml",
            addr.port()
        )));
        assert!(fs::read_to_string(temp.join("cache-provider.yaml"))
            .unwrap()
            .contains("name: fetched-dualstack"));
    }

    #[test]
    fn bootstrap_fetches_http_proxy_provider_via_socks5_proxy() {
        let temp = unique_temp_dir();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_worker = thread::spawn(move || {
            let body = b"proxies:\n  - type: direct\n    name: fetched-via-proxy\n";
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("GET /provider.yaml HTTP/1.1\r\n"),
                "{request}"
            );
            assert!(request.contains("X-Test: provider-fetch\r\n"), "{request}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut client, _) = proxy.accept().unwrap();
            let mut greeting = [0_u8; 3];
            client.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            client.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            client.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
            assert_eq!(header[3], 0x03);
            let mut host_len = [0_u8; 1];
            client.read_exact(&mut host_len).unwrap();
            let mut host = vec![0_u8; host_len[0] as usize];
            client.read_exact(&mut host).unwrap();
            assert_eq!(String::from_utf8(host).unwrap(), "localhost");
            let mut port = [0_u8; 2];
            client.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), origin_addr.port());
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();

            let mut upstream = std::net::TcpStream::connect(origin_addr).unwrap();
            let _ = crate::relay_bidirectional(
                &mut client,
                &mut upstream,
                crate::TcpRelayStrategy::BufferedCopy,
            );
        });

        let (_, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
proxies:
  - type: socks5
    name: proxy-hop
    server: 127.0.0.1
    port: {proxy_port}
proxy-providers:
  provider1:
    type: http
    url: http://localhost:{origin_port}/provider.yaml
    path: cache-provider.yaml
    proxy: proxy-hop
    header:
      X-Test:
        - provider-fetch
"#,
                proxy_port = proxy_addr.port(),
                origin_port = origin_addr.port(),
            ),
            &temp,
        )
        .unwrap();

        proxy_worker.join().unwrap();
        origin_worker.join().unwrap();
        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "fetched-via-proxy"
        );
        assert!(sources.http_contents.contains_key(&format!(
            "http://localhost:{}/provider.yaml",
            origin_addr.port()
        )));
        assert!(fs::read_to_string(temp.join("cache-provider.yaml"))
            .unwrap()
            .contains("name: fetched-via-proxy"));
    }

    #[test]
    fn bootstrap_falls_back_to_direct_when_provider_proxy_is_missing() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"proxies:\n  - type: direct\n    name: fetched-direct-fallback\n";
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (_, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
proxy-providers:
  provider1:
    type: http
    url: http://{addr}/provider.yaml
    path: cache-provider.yaml
    proxy: missing-proxy
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();

        worker.join().unwrap();
        assert_eq!(
            registry.providers["provider1"].members[0].name,
            "fetched-direct-fallback"
        );
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/provider.yaml")));
    }

    #[test]
    fn bootstrap_fetches_http_rule_provider_and_writes_cache() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"payload:\n  - .fetched.example\n";
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("GET /rules.yaml HTTP/1.1\r\n"),
                "{request}"
            );
            assert!(
                request.contains("X-Rule-Test: provider-fetch\r\n"),
                "{request}"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (document, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
mode: rule
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: yaml
    url: http://{addr}/rules.yaml
    path: cache-rules.yaml
    header:
      X-Rule-Test:
        - provider-fetch
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,COMPATIBLE
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(document.rule_providers.contains_key("rule1"));
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/rules.yaml")));
        assert!(sources.file_contents.contains_key("cache-rules.yaml"));
        assert!(fs::read_to_string(temp.join("cache-rules.yaml"))
            .unwrap()
            .contains(".fetched.example"));
        assert!(registry.proxies.contains_key("direct-a"));
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry).with_rule_set(
            mihomo_rules::compile_rule_table_with_providers(
                &document.rules,
                &document.sub_rules,
                &document.rule_providers,
                &sources.file_blobs,
                &sources.http_blobs,
            )
            .unwrap(),
        );
        assert_eq!(
            tunnel.selected_target(&Metadata {
                host: Some("api.fetched.example".into()),
                ..Metadata::default()
            }),
            "direct-a"
        );
    }

    #[test]
    fn bootstrap_prefers_http_rule_provider_cache_over_network_fetch_during_startup() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("cache-rules.yaml"),
            r#"
payload:
  - .cached.example
"#,
        )
        .unwrap();
        let original_modified=fs::metadata(temp.join("cache-rules.yaml")).unwrap().modified().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = std::sync::Arc::new(AtomicBool::new(false));
        let worker_flag = std::sync::Arc::clone(&accepted);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + std::time::Duration::from_millis(500);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((_stream, _addr)) => {
                        worker_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => panic!("unexpected accept error: {err}"),
                }
            }
        });

        let (document, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
mode: rule
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: yaml
    url: http://{addr}/rules.yaml
    path: cache-rules.yaml
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,COMPATIBLE
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(document.rule_providers.contains_key("rule1"));
        assert_eq!(fs::metadata(temp.join("cache-rules.yaml")).unwrap().modified().unwrap(),original_modified,
            "loading a cache must not rewrite it or change its update time");
        assert_eq!(sources.rule_provider_updated_at["rule1"],original_modified.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64);
        let mut repeated=sources.clone();
        super::load_cached_http_rule_provider_source(&mut repeated,&temp,&document.rule_providers["rule1"]).unwrap();
        assert_eq!(fs::metadata(temp.join("cache-rules.yaml")).unwrap().modified().unwrap(),original_modified);
        assert!(sources.file_contents.contains_key("cache-rules.yaml"));
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/rules.yaml")));
        assert!(!accepted.load(Ordering::SeqCst));
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry).with_rule_set(
            mihomo_rules::compile_rule_table_with_providers(
                &document.rules,
                &document.sub_rules,
                &document.rule_providers,
                &sources.file_blobs,
                &sources.http_blobs,
            )
            .unwrap(),
        );
        assert_eq!(
            tunnel.selected_target(&Metadata {
                host: Some("api.cached.example".into()),
                ..Metadata::default()
            }),
            "direct-a"
        );
    }

    #[test]
    fn bootstrap_fetches_chunked_http_rule_provider_and_writes_cache() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"payload:\n  - .chunked.example\n";
            let chunk_prefix = format!("{:x}\r\n", body.len());
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("GET /rules.yaml HTTP/1.1\r\n"),
                "{request}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.write_all(chunk_prefix.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        });

        let (document, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
mode: rule
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: yaml
    url: http://{addr}/rules.yaml
    path: cache-rules.yaml
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,COMPATIBLE
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(document.rule_providers.contains_key("rule1"));
        assert!(sources
            .http_contents
            .contains_key(&format!("http://{addr}/rules.yaml")));
        assert!(sources.file_contents.contains_key("cache-rules.yaml"));
        assert!(fs::read_to_string(temp.join("cache-rules.yaml"))
            .unwrap()
            .contains(".chunked.example"));
        assert!(registry.proxies.contains_key("direct-a"));
    }

    #[test]
    fn bootstrap_rejects_truncated_http_rule_provider_body() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"payload:\n  - .truncated.example\n";
            let partial = &body[..body.len() / 2];
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(partial).unwrap();
        });

        let (document, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
mode: rule
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: yaml
    url: http://{addr}/rules.yaml
    path: cache-rules.yaml
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,COMPATIBLE
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(document.rule_providers.contains_key("rule1"));
        assert!(!sources
            .http_contents
            .contains_key(&format!("http://{addr}/rules.yaml")));
        assert!(!sources.file_contents.contains_key("cache-rules.yaml"));
        assert!(registry.proxies.contains_key("direct-a"));
        assert!(!temp.join("cache-rules.yaml").exists());
    }

    #[test]
    fn bootstrap_skips_invalid_http_mrs_rule_provider_cache_write() {
        let temp = unique_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let body = b"broken-zstd-frame";
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (document, sources, registry) = bootstrap_from_yaml(
            &format!(
                r#"
mode: rule
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: mrs
    url: http://{addr}/rules.mrs
    path: cache-rules.mrs
proxies:
  - type: direct
    name: direct-a
rules:
  - MATCH,COMPATIBLE
"#,
                addr = addr,
            ),
            &temp,
        )
        .unwrap();
        worker.join().unwrap();

        assert!(document.rule_providers.contains_key("rule1"));
        assert!(!sources
            .http_contents
            .contains_key(&format!("http://{addr}/rules.mrs")));
        assert!(!sources.file_contents.contains_key("cache-rules.mrs"));
        assert!(registry.proxies.contains_key("direct-a"));
        assert!(!temp.join("cache-rules.mrs").exists());
    }

    #[test]
    fn bootstrap_state_builds_transport_plan_from_loaded_registry() {
        let temp = unique_temp_dir();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
proxies:
  - type: http
    name: leaf
    server: leaf.example.com
    port: 8443
    dialer-proxy: outer
  - type: socks5
    name: outer
    server: outer.example.com
    port: 1080
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan = state
            .build_transport_plan("leaf", &metadata, &BTreeMap::new())
            .unwrap();
        assert_eq!(plan.hops.len(), 2);
        assert_eq!(plan.hops[0].name, "outer");
        assert_eq!(plan.hops[1].name, "leaf");
    }

    #[test]
    fn bootstrap_state_builds_rule_aware_runtime_tunnel() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("rule-provider.yaml"),
            r#"
payload:
  - .example.net
"#,
        )
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!(
            r#"
mode: rule
proxies:
  - type: direct
    name: direct-a
  - type: direct
    name: direct-b
rules:
  - SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),edge
  - RULE-SET,rule1,direct-a
  - DOMAIN-SUFFIX,example.com,direct-a
  - MATCH,COMPATIBLE
sub-rules:
  edge:
    - DOMAIN,branch.example.com,direct-b
rule-providers:
  rule1:
    type: file
    behavior: domain
    path: rule-provider.yaml
"#,
        ));
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let tunnel = state.build_runtime_tunnel().unwrap();
        let selected = tunnel.selected_target(&Metadata {
            host: Some("www.example.com".into()),
            ..Metadata::default()
        });
        assert_eq!(selected, "direct-a");

        let branch = tunnel.selected_target(&Metadata {
            host: Some("branch.example.com".into()),
            network: mihomo_core::NetworkKind::Tcp,
            ..Metadata::default()
        });
        assert_eq!(branch, "direct-b");

        let provider_selected = tunnel.selected_target(&Metadata {
            host: Some("www.example.net".into()),
            ..Metadata::default()
        });
        assert_eq!(provider_selected, "direct-a");
    }

    #[test]
    fn bootstrap_state_rule_aware_runtime_tunnel_respects_special_rules_entry() {
        let temp = unique_temp_dir();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
mode: rule
proxies:
  - type: direct
    name: direct-a
  - type: direct
    name: direct-b
rules:
  - DOMAIN,listener.example.com,direct-a
sub-rules:
  listener:
    - DOMAIN,listener.example.com,direct-b
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let tunnel = state.build_runtime_tunnel().unwrap();
        let selected = tunnel.selected_target(&Metadata {
            host: Some("listener.example.com".into()),
            special_rules: "listener".into(),
            ..Metadata::default()
        });
        assert_eq!(selected, "direct-b");
    }

    #[test]
    fn bootstrap_state_builds_dns_runtime() {
        let temp = unique_temp_dir();
        fs::write(
            temp.join("rule-provider.yaml"),
            r#"
payload:
  - .example.com
"#,
        )
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
rule-providers:
  rule1:
    type: file
    behavior: domain
    path: rule-provider.yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
    - MATCH,real-ip
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let mut dns = state.build_dns_runtime().unwrap();
        let mut metadata = Metadata {
            host: Some("example.com".into()),
            ..Metadata::default()
        };
        dns.resolve_metadata(&mut metadata).unwrap();
        assert_eq!(metadata.dns_mode, mihomo_core::DnsMode::FakeIp);
    }

    #[test]
    fn bootstrap_state_builds_runtime_tunnel_with_dns_tcp_outbound() {
        let temp = unique_temp_dir();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
hosts:
  example.test: 1.2.3.4
dns:
  enable: true
  use-hosts: true
proxies:
  - type: dns
    name: edge-dns
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let tunnel = state.build_runtime_tunnel().unwrap();
        let (mut stream, _) = tunnel
            .connect_tcp_with_system_dialer(&Metadata {
                host: Some("8.8.8.8".into()),
                dst_port: Some(53),
                special_proxy: "edge-dns".into(),
                ..Metadata::default()
            })
            .unwrap();

        let query = build_dns_query_packet("example.test", 1, 0x2468);
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&query).unwrap();
        stream.flush().unwrap();

        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).unwrap();
        let length = u16::from_be_bytes(header) as usize;
        let mut response = vec![0_u8; length];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(
            parse_first_a_answer(&response),
            Some("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn bootstrap_state_builds_rule_aware_runtime_tunnel_from_mrs_rule_provider() {
        let temp = unique_temp_dir();
        let mrs = convert_ruleset_content(
            b".example.com\n",
            mihomo_config::RuleProviderBehavior::Domain,
            mihomo_config::RuleProviderFormat::Text,
        )
        .unwrap();
        fs::write(temp.join("rule-provider.mrs"), mrs).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
mode: rule
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,COMPATIBLE
rule-providers:
  rule1:
    type: file
    behavior: domain
    format: mrs
    path: rule-provider.mrs
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let tunnel = state.build_runtime_tunnel().unwrap();
        let selected = tunnel.selected_target(&Metadata {
            host: Some("api.example.com".into()),
            ..Metadata::default()
        });
        assert_eq!(selected, "direct-a");
    }

    #[test]
    fn bootstrap_applies_external_controller_ui_and_secret_overrides() {
        let temp = unique_temp_dir();
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            r#"
external-controller: 127.0.0.1:9090
external-ui: ./ui
secret: from-config
proxies:
  - type: direct
    name: direct-a
"#,
        );
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(encoded),
            external_ui: Some("override-ui".into()),
            external_controller: Some("127.0.0.1:9999".into()),
            external_controller_unix: Some("/tmp/mihomo.sock".into()),
            external_controller_pipe: Some(r"\\.\pipe\mihomo".into()),
            secret: Some("from-flag".into()),
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        assert_eq!(state.document.external_ui, "override-ui");
        assert_eq!(state.document.external_controller, "127.0.0.1:9999");
        assert_eq!(state.document.external_controller_unix, "/tmp/mihomo.sock");
        assert_eq!(state.document.external_controller_pipe, r"\\.\pipe\mihomo");
        assert_eq!(state.document.secret, "from-flag");
    }

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("mihomo-bootstrap-test-{nanos}-{counter}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn build_dns_query_packet(host: &str, qtype: u16, request_id: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&request_id.to_be_bytes());
        payload.extend_from_slice(&0x0100_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        for label in host.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload
    }

    fn parse_first_a_answer(packet: &[u8]) -> Option<IpAddr> {
        if packet.len() < 12 {
            return None;
        }
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
        if answer_count == 0 {
            return None;
        }
        let mut offset = 12;
        while let Some(length) = packet.get(offset).copied() {
            offset += 1;
            if length == 0 {
                break;
            }
            offset += length as usize;
        }
        offset += 4;
        if offset + 16 > packet.len() {
            return None;
        }
        offset += 2;
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 2;
        offset += 2;
        offset += 4;
        let rd_length = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;
        if rr_type != 1 || rd_length != 4 || offset + 4 > packet.len() {
            return None;
        }
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[offset],
            packet[offset + 1],
            packet[offset + 2],
            packet[offset + 3],
        )))
    }
}
