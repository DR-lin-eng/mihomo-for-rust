use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use mihomo_config::{
    parse_runtime_config_document, BootEnvironment, BootOptions, ConfigSource, ResolvedBoot,
    RuntimeConfigDocument,
};
use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata};
use mihomo_dns::DnsError;
use mihomo_rules::RuleError;
use mihomo_transport::{TransportPlan, TransportTarget};
use url::Url;

use crate::{
    build_runtime_registry_with_sources, CandidateState, ExecutionError, ExecutionPlan,
    ProviderContentSources, RegistryError, RuntimeRegistry, RuntimeTunnel, TcpForwardError,
    TcpRelayStats, TcpRelayStrategy,
};

#[derive(Clone, Debug)]
pub struct BootstrapState {
    pub resolved_boot: ResolvedBoot,
    pub document: RuntimeConfigDocument,
    pub provider_sources: ProviderContentSources,
    pub registry: RuntimeRegistry,
}

impl BootstrapState {
    pub fn build_dns_runtime(&self) -> Result<mihomo_dns::DnsRuntime, DnsError> {
        mihomo_dns::DnsRuntime::from_document_with_rule_providers_bytes(
            &self.document,
            &self.provider_sources.file_blobs,
            &self.provider_sources.http_blobs,
        )
    }

    pub fn build_runtime_tunnel(&self) -> Result<RuntimeTunnel, RuleError> {
        let rules = mihomo_rules::compile_rule_table_with_providers(
            &self.document.rules,
            &self.document.sub_rules,
            &self.document.rule_providers,
            &self.provider_sources.file_blobs,
            &self.provider_sources.http_blobs,
        )?;
        let mut tunnel =
            RuntimeTunnel::new(self.document.mode.clone(), self.registry.clone()).with_rule_set(rules);
        if let Ok(dns_runtime) = self.build_dns_runtime() {
            tunnel = tunnel.with_dns_runtime(dns_runtime);
        }
        Ok(tunnel)
    }

    pub fn into_runtime_tunnel(self) -> Result<RuntimeTunnel, RuleError> {
        let rules = mihomo_rules::compile_rule_table_with_providers(
            &self.document.rules,
            &self.document.sub_rules,
            &self.document.rule_providers,
            &self.provider_sources.file_blobs,
            &self.provider_sources.http_blobs,
        )?;
        let dns_runtime = self.build_dns_runtime().ok();
        let mut tunnel = RuntimeTunnel::new(self.document.mode, self.registry).with_rule_set(rules);
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

    pub fn refresh_rule_provider_sources(
        &mut self,
        provider_name: &str,
        tunnel: &RuntimeTunnel,
    ) -> Result<(), BootstrapError> {
        let Some(provider) = self.document.rule_providers.get(provider_name) else {
            return Err(BootstrapError::MissingRuleProvider(provider_name.to_owned()));
        };
        match provider.vehicle_type() {
            Some(mihomo_config::RuleProviderVehicleType::Inline) => Ok(()),
            Some(mihomo_config::RuleProviderVehicleType::File) => {
                if provider.path.is_empty() {
                    return Ok(());
                }
                let path = resolve_home_relative(&self.resolved_boot.home_dir, &provider.path);
                let content = fs::read(&path)?;
                self.provider_sources
                    .file_blobs
                    .insert(provider.path.clone(), content.clone());
                if let Ok(text) = String::from_utf8(content) {
                    self.provider_sources
                        .file_contents
                        .insert(provider.path.clone(), text);
                }
                Ok(())
            }
            Some(mihomo_config::RuleProviderVehicleType::Http) => {
                refresh_http_rule_provider_source(
                    &mut self.provider_sources,
                    &self.resolved_boot.home_dir,
                    provider,
                    tunnel,
                )
            }
            None => Ok(()),
        }
    }

    pub fn refresh_proxy_provider_sources(
        &mut self,
        provider_name: &str,
        tunnel: &RuntimeTunnel,
    ) -> Result<(), BootstrapError> {
        let Some(provider) = self.document.proxy_providers.get(provider_name) else {
            return Err(BootstrapError::MissingProxyProvider(provider_name.to_owned()));
        };
        match provider.vehicle_type() {
            Some(mihomo_outbound::ProxyProviderVehicleType::Inline) => Ok(()),
            Some(mihomo_outbound::ProxyProviderVehicleType::File) => {
                if provider.path.is_empty() {
                    return Ok(());
                }
                let path = resolve_home_relative(&self.resolved_boot.home_dir, &provider.path);
                let content = fs::read(&path)?;
                self.provider_sources
                    .file_blobs
                    .insert(provider.path.clone(), content.clone());
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
    let resolved_boot = options.resolve(cwd, env);
    let config_text = load_config_text(&resolved_boot, stdin)?;
    let document = apply_boot_overrides(parse_runtime_config_document(&config_text)?, options);
    let provider_sources =
        load_provider_content_sources_from_home(&document, &resolved_boot.home_dir)?;
    let registry = build_runtime_registry_with_sources(&document, &provider_sources)?;
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
) -> Result<(RuntimeConfigDocument, ProviderContentSources, RuntimeRegistry), BootstrapError> {
    let document = parse_runtime_config_document(yaml)?;
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
                if provider.path.is_empty() {
                    continue;
                }
                let path = resolve_home_relative(home_dir, &provider.path);
                let content = fs::read(&path)?;
                sources.file_blobs.insert(provider.path.clone(), content.clone());
                if let Ok(text) = String::from_utf8(content) {
                    sources.file_contents.insert(provider.path.clone(), text);
                }
            }
            Some(mihomo_outbound::ProxyProviderVehicleType::Http) => {
                let tunnel = build_provider_fetch_tunnel(document, &sources);
                let _ = refresh_http_proxy_provider_source(
                    &mut sources,
                    home_dir,
                    provider,
                    &tunnel,
                );
            }
            _ => {}
        }
    }
    for provider in document.rule_providers.values() {
        match provider.vehicle_type() {
            Some(mihomo_config::RuleProviderVehicleType::File) => {
                if provider.path.is_empty() {
                    continue;
                }
                let path = resolve_home_relative(home_dir, &provider.path);
                let content = fs::read(&path)?;
                sources.file_blobs.insert(provider.path.clone(), content.clone());
                if let Ok(text) = String::from_utf8(content) {
                    sources.file_contents.insert(provider.path.clone(), text);
                }
            }
            Some(mihomo_config::RuleProviderVehicleType::Http) => {
                let tunnel = build_provider_fetch_tunnel(document, &sources);
                let _ = refresh_http_rule_provider_source(
                    &mut sources,
                    home_dir,
                    provider,
                    &tunnel,
                );
            }
            _ => {}
        }
    }
    Ok(sources)
}

fn build_provider_fetch_tunnel(
    document: &RuntimeConfigDocument,
    sources: &ProviderContentSources,
) -> RuntimeTunnel {
    let registry = build_runtime_registry_with_sources(document, sources).unwrap_or_else(|_| RuntimeRegistry {
        topology: crate::assemble_proxy_topology(document).unwrap(),
        proxies: BTreeMap::new(),
        proxy_definitions: BTreeMap::new(),
        providers: BTreeMap::new(),
        groups: BTreeMap::new(),
        default_provider_members: Vec::new(),
    });
    RuntimeTunnel::new("direct", registry)
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
) -> Result<(), BootstrapError> {
    let content = fetch_http_provider_bytes(
        &provider.url,
        &provider.header,
        provider.size_limit,
        &provider.proxy,
        tunnel,
    )
        .or_else(|_| read_http_provider_cache(home_dir, &provider.path))?;
    store_http_provider_content(
        home_dir,
        sources,
        &provider.path,
        &provider.url,
        &content,
    )?;
    Ok(())
}

fn refresh_http_proxy_provider_source(
    sources: &mut ProviderContentSources,
    home_dir: &Path,
    provider: &mihomo_outbound::ProxyProviderDefinition,
    tunnel: &RuntimeTunnel,
) -> Result<(), BootstrapError> {
    let content = fetch_http_provider_bytes(
        &provider.url,
        &provider.header,
        provider.size_limit,
        &provider.proxy,
        tunnel,
    )
        .or_else(|_| read_http_provider_cache(home_dir, &provider.path))?;
    store_http_provider_content(
        home_dir,
        sources,
        &provider.path,
        &provider.url,
        &content,
    )?;
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
    let mut request = ureq::get(url).timeout(Duration::from_secs(30));
    for (name, values) in header {
        for value in values {
            request = request.set(name, value);
        }
    }
    let response = request
        .call()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    let mut reader = response.into_reader();
    let mut content = Vec::new();
    if size_limit > 0 {
        reader.take(size_limit as u64).read_to_end(&mut content)?;
    } else {
        reader.read_to_end(&mut content)?;
    }
    Ok(content)
}

fn fetch_http_provider_bytes_via_proxy(
    tunnel: &RuntimeTunnel,
    url: &str,
    header: &BTreeMap<String, Vec<String>>,
    size_limit: i64,
    proxy_name: &str,
) -> std::io::Result<Vec<u8>> {
    let parsed = Url::parse(url).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing url host"))?;
    let scheme = parsed.scheme();
    let port = parsed
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
    let metadata = Metadata {
        host: Some(host.to_owned()),
        dst_port: Some(port),
        special_proxy: proxy_name.to_owned(),
        ..Metadata::default()
    };
    let (mut upstream, _) = tunnel
        .connect_tcp_with_system_dialer(&metadata)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
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
        upstream = mihomo_transport::wrap_tls_proxy_stream(upstream, target, &tls, &[])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    }
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    );
    for (name, values) in header {
        for value in values {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
    }
    request.push_str("\r\n");
    upstream.write_all(request.as_bytes())?;
    upstream.flush()?;

    let mut response = Vec::new();
    upstream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid http response"))?;
    let (headers, body) = response.split_at(split + 4);
    let headers = String::from_utf8_lossy(headers);
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected http status"));
    }
    let mut content = body.to_vec();
    if size_limit > 0 && content.len() > size_limit as usize {
        content.truncate(size_limit as usize);
    }
    Ok(content)
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

fn store_http_provider_content(
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
    if !url.is_empty() {
        sources.http_blobs.insert(url.to_owned(), content.to_vec());
    }
    if let Ok(text) = String::from_utf8(content.to_vec()) {
        if !path.is_empty() {
            sources.file_contents.insert(path.to_owned(), text.clone());
        }
        if !url.is_empty() {
            sources.http_contents.insert(url.to_owned(), text);
        }
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
    use std::thread;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use mihomo_config::{BootEnvironment, BootOptions, Command};
    use mihomo_core::Metadata;
    use mihomo_rules::convert_ruleset_content;
    use super::{bootstrap_from_boot_options, bootstrap_from_yaml};
    use crate::RuntimeTunnel;

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
        assert_eq!(registry.providers["provider1"].members[0].name, "file-direct");
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
        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        assert_eq!(state.registry.proxies["base64-direct"].name, "base64-direct");
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
        assert_eq!(registry.providers["provider1"].members[0].name, "cached-direct");
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
            assert!(request.starts_with("GET /provider.yaml HTTP/1.1\r\n"), "{request}");
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
        assert!(sources.http_contents.contains_key(&format!("http://{addr}/provider.yaml")));
        assert!(sources.file_contents.contains_key("cache-provider.yaml"));
        assert_eq!(registry.providers["provider1"].members[0].name, "fetched");
        assert!(fs::read_to_string(temp.join("cache-provider.yaml"))
            .unwrap()
            .contains("name: fetched"));
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
            assert!(request.starts_with("GET /provider.yaml HTTP/1.1\r\n"), "{request}");
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
        assert_eq!(registry.providers["provider1"].members[0].name, "fetched-via-proxy");
        assert!(sources.http_contents.contains_key(&format!(
            "http://localhost:{}/provider.yaml",
            origin_addr.port()
        )));
        assert!(fs::read_to_string(temp.join("cache-provider.yaml"))
            .unwrap()
            .contains("name: fetched-via-proxy"));
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
            assert!(request.starts_with("GET /rules.yaml HTTP/1.1\r\n"), "{request}");
            assert!(request.contains("X-Rule-Test: provider-fetch\r\n"), "{request}");
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
        assert!(sources.http_contents.contains_key(&format!("http://{addr}/rules.yaml")));
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
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            format!(
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
            ),
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
        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
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
        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
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
        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
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
        assert_eq!(parse_first_a_answer(&response), Some("1.2.3.4".parse().unwrap()));
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
        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
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
