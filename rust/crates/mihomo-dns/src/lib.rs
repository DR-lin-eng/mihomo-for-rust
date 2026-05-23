use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

use mihomo_config::{
    HostMappingValue, RuleProviderBehavior, RuntimeConfigDocument, TopLevelDnsConfig,
};
use mihomo_core::{DnsMode, Metadata, NetworkKind, RewriteStage, SubsystemManifest};
use mihomo_rules::{compile_rule_table_with_providers, parse_rule, RuleError, RuleSet, RuleType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnhancedMode {
    Disabled,
    FakeIp,
    RedirHost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
    Rule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuntime {
    pub config: DnsRuntimeConfig,
    hosts: Vec<HostEntry>,
    fake_ip_matchers: Vec<FakeIpFilterMatcher>,
    fake_ip_rules: RuleSet,
    fake_ip_pool: FakeIpPool,
    fake_ip_pool6: Option<FakeIpPool6>,
    nameserver_policies: Vec<NameserverPolicy>,
    proxy_server_nameserver_policies: Vec<NameserverPolicy>,
    fallback_domain_matchers: Vec<NameserverPolicyMatcher>,
    fallback_ip_matchers: Vec<FallbackIpMatcher>,
    cache: HashMap<String, CachedAnswer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuntimeConfig {
    pub enabled: bool,
    pub listen: String,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub enhanced_mode: EnhancedMode,
    pub fake_ip_filter_mode: FakeIpFilterMode,
    pub fake_ip_ttl: u32,
    pub fake_ip_range6: String,
    pub nameserver: Vec<String>,
    pub default_nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub direct_nameserver: Vec<String>,
    pub direct_nameserver_follow_policy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedAnswer {
    pub ips: Vec<IpAddr>,
    pub servers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveSource {
    Hosts,
    FakeIp,
    Cache,
    Nameserver,
    Fallback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveAnswer {
    pub ips: Vec<IpAddr>,
    pub servers: Vec<String>,
    pub source: ResolveSource,
}

pub trait DnsUpstream {
    fn resolve(&mut self, servers: &[String], host: &str) -> Result<Vec<IpAddr>, DnsError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRecordType {
    A = 1,
    Aaaa = 28,
}

pub trait DnsPacketTransport {
    fn exchange(&mut self, server: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError>;
}

#[derive(Default)]
pub struct SystemDnsPacketTransport;

pub struct NetworkDnsUpstream<T> {
    transport: T,
    next_request_id: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsError {
    InvalidFakeIpRange(String),
    InvalidAliasLoop(String),
    Rule(RuleError),
    ResolveFailed(String),
    UnsupportedNameserver(String),
    DnsProtocol(String),
    Io(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFakeIpRange(raw) => write!(f, "invalid fake ip range: {raw}"),
            Self::InvalidAliasLoop(raw) => write!(f, "host alias loop: {raw}"),
            Self::Rule(err) => write!(f, "{err}"),
            Self::ResolveFailed(host) => write!(f, "failed to resolve host: {host}"),
            Self::UnsupportedNameserver(raw) => write!(f, "unsupported nameserver: {raw}"),
            Self::DnsProtocol(message) => write!(f, "dns protocol error: {message}"),
            Self::Io(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<RuleError> for DnsError {
    fn from(value: RuleError) -> Self {
        Self::Rule(value)
    }
}

impl From<io::Error> for DnsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl<T> NetworkDnsUpstream<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_request_id: 1,
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: DnsPacketTransport> DnsUpstream for NetworkDnsUpstream<T> {
    fn resolve(&mut self, servers: &[String], host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let mut resolved = Vec::new();
        for server in servers {
            match query_server(self, server, host) {
                Ok(ips) if !ips.is_empty() => {
                    for ip in ips {
                        if !resolved.contains(&ip) {
                            resolved.push(ip);
                        }
                    }
                    if !resolved.is_empty() {
                        return Ok(resolved);
                    }
                }
                Ok(_) => {}
                Err(DnsError::UnsupportedNameserver(_)) => continue,
                Err(_) => continue,
            }
        }
        Ok(resolved)
    }
}

impl DnsPacketTransport for SystemDnsPacketTransport {
    fn exchange(&mut self, server: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
        let endpoint = parse_udp_nameserver(server)?;
        let bind_addr = if endpoint.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        socket.set_write_timeout(Some(Duration::from_secs(1)))?;
        socket.send_to(payload, &endpoint)?;
        let mut buf = [0_u8; 1500];
        let (read, _) = socket.recv_from(&mut buf)?;
        Ok(buf[..read].to_vec())
    }
}

impl DnsRuntime {
    pub fn from_document(document: &RuntimeConfigDocument) -> Result<Self, DnsError> {
        let empty_sources = BTreeMap::<String, String>::new();
        Self::from_document_with_rule_providers(document, &empty_sources, &empty_sources)
    }

    pub fn from_document_with_rule_providers(
        document: &RuntimeConfigDocument,
        file_contents: &BTreeMap<String, String>,
        http_contents: &BTreeMap<String, String>,
    ) -> Result<Self, DnsError> {
        Self::from_document_with_rule_providers_bytes(document, file_contents, http_contents)
    }

    pub fn from_document_with_rule_providers_bytes<S>(
        document: &RuntimeConfigDocument,
        file_contents: &BTreeMap<String, S>,
        http_contents: &BTreeMap<String, S>,
    ) -> Result<Self, DnsError>
    where
        S: AsRef<[u8]>,
    {
        Self::from_document_with_rule_providers_and_system_hosts_bytes(
            document,
            file_contents,
            http_contents,
            None,
        )
    }

    #[cfg(test)]
    fn from_document_with_rule_providers_and_system_hosts(
        document: &RuntimeConfigDocument,
        file_contents: &BTreeMap<String, String>,
        http_contents: &BTreeMap<String, String>,
        system_hosts_override: Option<&str>,
    ) -> Result<Self, DnsError> {
        Self::from_document_with_rule_providers_and_system_hosts_bytes(
            document,
            file_contents,
            http_contents,
            system_hosts_override,
        )
    }

    fn from_document_with_rule_providers_and_system_hosts_bytes<S>(
        document: &RuntimeConfigDocument,
        file_contents: &BTreeMap<String, S>,
        http_contents: &BTreeMap<String, S>,
        system_hosts_override: Option<&str>,
    ) -> Result<Self, DnsError>
    where
        S: AsRef<[u8]>,
    {
        let config = DnsRuntimeConfig::from_top_level(&document.dns);
        let system_hosts_text = if config.use_system_hosts {
            system_hosts_override
                .map(ToOwned::to_owned)
                .or_else(read_system_hosts_text)
        } else {
            None
        };
        let hosts = compile_hosts(
            &document.hosts,
            system_hosts_text.as_deref(),
        );
        let fake_ip_matchers =
            compile_fake_ip_filter_matchers(document, file_contents, http_contents)?;
        let fake_ip_rules = if config.fake_ip_filter_mode == FakeIpFilterMode::Rule {
            validate_fake_ip_filter_rules(document)?;
            compile_rule_table_with_providers(
                &document.dns.fake_ip_filter,
                &BTreeMap::new(),
                &document.rule_providers,
                file_contents,
                http_contents,
            )?
        } else {
            RuleSet::default()
        };
        let fake_ip_pool = FakeIpPool::new(&document.dns.fake_ip_range)?;
        let fake_ip_pool6 = if document.dns.fake_ip_range6.trim().is_empty() {
            None
        } else {
            Some(FakeIpPool6::new(&document.dns.fake_ip_range6)?)
        };
        let nameserver_policies =
            compile_nameserver_policies(document, file_contents, http_contents)?;
        let proxy_server_nameserver_policies = compile_proxy_nameserver_policies(
            document,
            file_contents,
            http_contents,
        )?;
        let fallback_domain_matchers =
            compile_fallback_domain_matchers(document, file_contents, http_contents)?;
        let fallback_ip_matchers =
            compile_fallback_ip_matchers(document, file_contents, http_contents)?;
        Ok(Self {
            config,
            hosts,
            fake_ip_matchers,
            fake_ip_rules,
            fake_ip_pool,
            fake_ip_pool6,
            nameserver_policies,
            proxy_server_nameserver_policies,
            fallback_domain_matchers,
            fallback_ip_matchers,
            cache: HashMap::new(),
        })
    }

    pub fn resolve_host(&mut self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        if self.config.use_hosts || self.config.use_system_hosts {
            if let Some(ip) = self.resolve_host_from_hosts(host)? {
                return Ok(Some(ip));
            }
        }
        if self.config.enhanced_mode == EnhancedMode::FakeIp && self.should_use_fake_ip(host) {
            return self.fake_ip_pool.assign(host).map(Some);
        }
        let key = normalize(host);
        Ok(self
            .cache
            .get(&key)
            .and_then(|answer| answer.ips.first().copied()))
    }

    pub fn resolve_host_with_upstream(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<IpAddr>, DnsError> {
        let Some(answer) = self.lookup_answer(host, upstream)? else {
            return Ok(None);
        };
        Ok(answer.ips.first().copied())
    }

    pub fn resolve_host_via_system(&mut self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_host_with_upstream(host, &mut upstream)
    }

    pub fn resolve_proxy_server_host_with_upstream(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<IpAddr>, DnsError> {
        if self.config.proxy_server_nameserver.is_empty() {
            return self.resolve_host_with_upstream(host, upstream);
        }
        let servers = self.select_proxy_server_nameservers(host);
        if servers.is_empty() {
            return Ok(None);
        }
        let Some(answer) = self.lookup_answer_using_servers(host, upstream, &servers, false)? else {
            return Ok(None);
        };
        Ok(answer.ips.first().copied())
    }

    pub fn resolve_direct_server_host_with_upstream(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<IpAddr>, DnsError> {
        if self.config.direct_nameserver.is_empty() {
            return self.resolve_host_with_upstream(host, upstream);
        }
        let servers = self.select_direct_nameservers(host);
        if servers.is_empty() {
            return Ok(None);
        }
        let Some(answer) = self.lookup_answer_using_servers(host, upstream, &servers, false)? else {
            return Ok(None);
        };
        Ok(answer.ips.first().copied())
    }

    pub fn resolve_proxy_server_host_via_system(&mut self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_proxy_server_host_with_upstream(host, &mut upstream)
    }

    pub fn resolve_direct_server_host_via_system(&mut self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_direct_server_host_with_upstream(host, &mut upstream)
    }

    pub fn resolve_metadata(&mut self, metadata: &mut Metadata) -> Result<(), DnsError> {
        self.resolve_metadata_inner(metadata, None::<&mut NoopUpstream>)
    }

    pub fn resolve_metadata_with_upstream(
        &mut self,
        metadata: &mut Metadata,
        upstream: &mut impl DnsUpstream,
    ) -> Result<(), DnsError> {
        self.resolve_metadata_inner(metadata, Some(upstream))
    }

    pub fn resolve_metadata_via_system(&mut self, metadata: &mut Metadata) -> Result<(), DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_metadata_with_upstream(metadata, &mut upstream)
    }

    pub fn handle_query_packet(
        &mut self,
        packet: &[u8],
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<Vec<u8>>, DnsError> {
        self.handle_query_packet_inner(packet, upstream, true)
    }

    pub fn relay_query_packet(
        &mut self,
        packet: &[u8],
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<Vec<u8>>, DnsError> {
        self.handle_query_packet_inner(packet, upstream, false)
    }

    fn handle_query_packet_inner(
        &mut self,
        packet: &[u8],
        upstream: &mut impl DnsUpstream,
        require_enabled: bool,
    ) -> Result<Option<Vec<u8>>, DnsError> {
        if require_enabled && !self.config.enabled {
            return Ok(None);
        }
        let query = parse_dns_query_packet(packet)?;
        let ips = match query.query_type {
            DnsRecordType::A | DnsRecordType::Aaaa => match self.lookup_answer_for_query_type(
                &query.host,
                upstream,
                query.query_type,
            ) {
                Ok(Some(answer)) => answer
                    .ips
                    .into_iter()
                    .filter(|ip| matches_query_type(*ip, query.query_type))
                    .collect::<Vec<_>>(),
                Ok(None) | Err(DnsError::ResolveFailed(_)) => Vec::new(),
                Err(err) => return Err(err),
            },
        };

        Ok(Some(build_dns_response(
            &query,
            response_ttl_secs(self, !ips.is_empty()),
            &ips,
        )))
    }

    pub fn handle_query_packet_via_system(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.handle_query_packet(packet, &mut upstream)
    }

    pub fn relay_query_packet_via_system(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.relay_query_packet(packet, &mut upstream)
    }

    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<&str> {
        self.fake_ip_pool
            .reverse(ip)
            .or_else(|| self.fake_ip_pool6.as_ref().and_then(|pool| pool.reverse(ip)))
    }

    pub fn should_use_fake_ip(&self, host: &str) -> bool {
        if self.config.enhanced_mode != EnhancedMode::FakeIp {
            return false;
        }
        match self.config.fake_ip_filter_mode {
            FakeIpFilterMode::Blacklist => !self.host_matches_filter_patterns(host),
            FakeIpFilterMode::Whitelist => self.host_matches_filter_patterns(host),
            FakeIpFilterMode::Rule => {
                let metadata = Metadata {
                    host: Some(host.to_owned()),
                    network: NetworkKind::Invalid,
                    ..Metadata::default()
                };
                matches!(self.fake_ip_rules.target_for(&metadata), Some("fake-ip"))
            }
        }
    }

    pub fn select_nameservers(&self, host: &str) -> Vec<String> {
        let host = normalize(host);
        self.nameserver_policies
            .iter()
            .find(|policy| policy.matches(&host))
            .map(|policy| policy.servers.clone())
            .filter(|servers| !servers.is_empty())
            .unwrap_or_else(|| self.config.nameserver.clone())
    }

    pub fn select_proxy_server_nameservers(&self, host: &str) -> Vec<String> {
        if self.config.proxy_server_nameserver.is_empty() {
            return self.select_nameservers(host);
        }
        let host = normalize(host);
        self.proxy_server_nameserver_policies
            .iter()
            .find(|policy| policy.matches(&host))
            .map(|policy| policy.servers.clone())
            .filter(|servers| !servers.is_empty())
            .unwrap_or_else(|| self.config.proxy_server_nameserver.clone())
    }

    pub fn select_direct_nameservers(&self, host: &str) -> Vec<String> {
        if self.config.direct_nameserver.is_empty() {
            return self.select_nameservers(host);
        }
        if self.config.direct_nameserver_follow_policy {
            let selected = self.select_nameservers(host);
            if !selected.is_empty() {
                return selected;
            }
        }
        self.config.direct_nameserver.clone()
    }

    pub fn cached_answer(&self, host: &str) -> Option<&CachedAnswer> {
        self.cache.get(&normalize(host))
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    pub fn flush_fake_ip(&mut self) {
        self.fake_ip_pool.clear();
        if let Some(pool) = &mut self.fake_ip_pool6 {
            pool.clear();
        }
    }

    fn resolve_metadata_inner(
        &mut self,
        metadata: &mut Metadata,
        mut upstream: Option<&mut impl DnsUpstream>,
    ) -> Result<(), DnsError> {
        if metadata.host.is_none() && metadata.dst_ip.is_some() {
            if let Some(host) = metadata.dst_ip.and_then(|ip| self.reverse_lookup(ip)) {
                metadata.host = Some(host.to_owned());
                metadata.dns_mode = DnsMode::FakeIp;
            }
            return Ok(());
        }

        let Some(host) = metadata.host.clone() else {
            return Ok(());
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            metadata.dst_ip = Some(ip);
            return Ok(());
        }

        let answer = if let Some(upstream) = upstream.as_deref_mut() {
            self.lookup_answer(&host, upstream)?
        } else {
            self.lookup_local_answer(&host)?
        };

        let Some(answer) = answer else {
            return Err(DnsError::ResolveFailed(host));
        };
        let Some(ip) = answer.ips.first().copied() else {
            return Err(DnsError::ResolveFailed(host));
        };
        metadata.dst_ip = Some(ip);
        metadata.dns_mode = match answer.source {
            ResolveSource::FakeIp => DnsMode::FakeIp,
            ResolveSource::Hosts => DnsMode::Hosts,
            _ if self.fake_ip_pool.contains(ip)
                || self
                    .fake_ip_pool6
                    .as_ref()
                    .is_some_and(|pool| pool.contains(ip)) =>
            {
                DnsMode::FakeIp
            }
            _ => DnsMode::Normal,
        };
        Ok(())
    }

    fn lookup_answer(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        self.lookup_answer_for_query_type(host, upstream, DnsRecordType::A)
    }

    fn lookup_answer_for_query_type(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
        query_type: DnsRecordType,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if let Some(answer) = self.lookup_local_answer_for_query_type(host, Some(query_type))? {
            return Ok(Some(answer));
        }

        let key = normalize(host);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(Some(ResolveAnswer {
                ips: cached.ips.clone(),
                servers: cached.servers.clone(),
                source: ResolveSource::Cache,
            }));
        }

        if self.should_only_query_fallback(host) {
            if let Some(answer) = query_upstream(upstream, &self.config.fallback, host)? {
                self.cache.insert(
                    key,
                    CachedAnswer {
                        ips: answer.ips.clone(),
                        servers: answer.servers.clone(),
                    },
                );
                return Ok(Some(ResolveAnswer {
                    source: ResolveSource::Fallback,
                    ..answer
                }));
            }
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        let primary_servers = self.select_nameservers(host);
        self.lookup_answer_using_servers(host, upstream, &primary_servers, true)
    }

    fn lookup_answer_using_servers(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
        primary_servers: &[String],
        allow_fallback: bool,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        let key = normalize(host);
        if let Some(answer) = query_upstream(upstream, &primary_servers, host)? {
            let should_fallback = !self.config.fallback.is_empty()
                && allow_fallback
                && answer
                    .ips
                    .iter()
                    .any(|ip| self.should_ip_fallback(*ip));
            if !should_fallback {
                self.cache.insert(
                    key,
                    CachedAnswer {
                        ips: answer.ips.clone(),
                        servers: answer.servers.clone(),
                    },
                );
                return Ok(Some(answer));
            }
        }

        if self.config.fallback.is_empty() || !allow_fallback {
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        if let Some(answer) = query_upstream(upstream, &self.config.fallback, host)? {
            self.cache.insert(
                key,
                CachedAnswer {
                    ips: answer.ips.clone(),
                    servers: answer.servers.clone(),
                },
            );
            return Ok(Some(ResolveAnswer {
                source: ResolveSource::Fallback,
                ..answer
            }));
        }

        Err(DnsError::ResolveFailed(host.to_owned()))
    }

    fn lookup_local_answer(&mut self, host: &str) -> Result<Option<ResolveAnswer>, DnsError> {
        self.lookup_local_answer_for_query_type(host, None)
    }

    fn lookup_local_answer_for_query_type(
        &mut self,
        host: &str,
        query_type: Option<DnsRecordType>,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if self.config.use_hosts || self.config.use_system_hosts {
            if let Some(ip) = self.resolve_host_from_hosts(host)? {
                return Ok(Some(ResolveAnswer {
                    ips: vec![ip],
                    servers: Vec::new(),
                    source: ResolveSource::Hosts,
                }));
            }
        }
        if self.config.enhanced_mode == EnhancedMode::FakeIp && self.should_use_fake_ip(host) {
            let ips = match query_type {
                Some(DnsRecordType::Aaaa) => self
                    .fake_ip_pool6
                    .as_mut()
                    .map(|pool| pool.assign(host))
                    .transpose()?
                    .into_iter()
                    .collect::<Vec<_>>(),
                _ => vec![self.fake_ip_pool.assign(host)?],
            };
            if !ips.is_empty() {
                return Ok(Some(ResolveAnswer {
                    ips,
                    servers: Vec::new(),
                    source: ResolveSource::FakeIp,
                }));
            }
        }
        Ok(None)
    }

    fn resolve_host_from_hosts(&self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        self.resolve_host_with_depth(host, 0)
    }

    fn resolve_host_with_depth(&self, host: &str, depth: usize) -> Result<Option<IpAddr>, DnsError> {
        if depth > 8 {
            return Err(DnsError::InvalidAliasLoop(host.to_owned()));
        }
        let Some(entry) = self.matching_host_entry(host) else {
            return Ok(None);
        };
        let Some(first) = entry.values.first() else {
            return Ok(None);
        };
        if let Ok(ip) = first.parse::<IpAddr>() {
            return Ok(Some(ip));
        }
        self.resolve_host_with_depth(first, depth + 1)
    }

    fn matching_host_entry(&self, host: &str) -> Option<&HostEntry> {
        let host = normalize(host);
        self.hosts
            .iter()
            .filter(|entry| entry.pattern.matches(&host))
            .max_by_key(|entry| entry.pattern.priority())
    }

    fn host_matches_filter_patterns(&self, host: &str) -> bool {
        let host = normalize(host);
        self.fake_ip_matchers
            .iter()
            .any(|matcher| matcher.matches(&host))
    }

    fn should_only_query_fallback(&self, host: &str) -> bool {
        let normalized = normalize(host);
        let metadata = Metadata {
            host: Some(normalized.clone()),
            network: NetworkKind::Invalid,
            ..Metadata::default()
        };
        self.fallback_domain_matchers
            .iter()
            .any(|matcher| matcher.matches(&normalized, &metadata))
    }

    fn should_ip_fallback(&self, ip: IpAddr) -> bool {
        self.fallback_ip_matchers
            .iter()
            .any(|matcher| matcher.matches(ip))
    }
}

#[derive(Default)]
struct NoopUpstream;

impl DnsUpstream for NoopUpstream {
    fn resolve(&mut self, _servers: &[String], _host: &str) -> Result<Vec<IpAddr>, DnsError> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostEntry {
    pattern: HostPattern,
    values: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NameserverPolicy {
    matchers: Vec<NameserverPolicyMatcher>,
    servers: Vec<String>,
}

impl NameserverPolicy {
    fn matches(&self, host: &str) -> bool {
        let normalized = normalize(host);
        let metadata = Metadata {
            host: Some(normalized.clone()),
            network: NetworkKind::Invalid,
            ..Metadata::default()
        };
        self.matchers.iter().any(|matcher| matcher.matches(&normalized, &metadata))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NameserverPolicyMatcher {
    HostPattern(HostPattern),
    RuleSet(RuleSet),
}

impl NameserverPolicyMatcher {
    fn matches(&self, host: &str, metadata: &Metadata) -> bool {
        match self {
            Self::HostPattern(pattern) => pattern.matches(host),
            Self::RuleSet(rule_set) => rule_set.target_for(metadata).is_some(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FallbackIpMatcher {
    Cidr(IpCidrMatcher),
    RuleSet(RuleSet),
}

impl FallbackIpMatcher {
    fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Cidr(cidr) => cidr.contains(ip),
            Self::RuleSet(rule_set) => {
                let metadata = Metadata {
                    dst_ip: Some(ip),
                    network: NetworkKind::Invalid,
                    ..Metadata::default()
                };
                rule_set.target_for(&metadata).is_some()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IpCidrMatcher {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidrMatcher {
    fn parse(raw: &str) -> Result<Self, RuleError> {
        let Some((ip, prefix)) = raw.split_once('/') else {
            return Err(RuleError::InvalidCidr(raw.to_owned()));
        };
        let network = ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| RuleError::InvalidCidr(raw.to_owned()))?;
        let prefix_len = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| RuleError::InvalidCidr(raw.to_owned()))?;
        match network {
            IpAddr::V4(_) if prefix_len <= 32 => Ok(Self {
                network,
                prefix_len,
            }),
            IpAddr::V6(_) if prefix_len <= 128 => Ok(Self {
                network,
                prefix_len,
            }),
            _ => Err(RuleError::InvalidCidr(raw.to_owned())),
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(self.prefix_len);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(self.prefix_len);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FakeIpFilterMatcher {
    HostPattern(HostPattern),
    RuleSet(RuleSet),
}

impl FakeIpFilterMatcher {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::HostPattern(pattern) => pattern.matches(host),
            Self::RuleSet(rule_set) => {
                let metadata = Metadata {
                    host: Some(host.to_owned()),
                    network: NetworkKind::Invalid,
                    ..Metadata::default()
                };
                rule_set.target_for(&metadata).is_some()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostPattern {
    Exact(String),
    Suffix(String),
    WildcardSuffix(String),
}

impl HostPattern {
    fn parse(raw: &str) -> Self {
        let normalized = normalize(raw);
        if let Some(rest) = normalized.strip_prefix("*.") {
            Self::WildcardSuffix(rest.to_owned())
        } else if let Some(rest) = normalized.strip_prefix("+.") {
            Self::Suffix(rest.to_owned())
        } else if let Some(rest) = normalized.strip_prefix('.') {
            Self::Suffix(rest.to_owned())
        } else {
            Self::Exact(normalized)
        }
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Suffix(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            Self::WildcardSuffix(suffix) => host.ends_with(&format!(".{suffix}")),
        }
    }

    fn priority(&self) -> usize {
        match self {
            Self::Exact(value) => value.len() + 10_000,
            Self::Suffix(value) => value.len() + 1_000,
            Self::WildcardSuffix(value) => value.len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FakeIpPool {
    base: u32,
    size: u32,
    next_offset: u32,
    host_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_host: HashMap<Ipv4Addr, String>,
}

impl FakeIpPool {
    fn new(raw: &str) -> Result<Self, DnsError> {
        let raw = if raw.trim().is_empty() {
            "198.18.0.1/16"
        } else {
            raw
        };
        let Some((ip, prefix)) = raw.split_once('/') else {
            return Err(DnsError::InvalidFakeIpRange(raw.to_owned()));
        };
        let base_ip = ip
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| DnsError::InvalidFakeIpRange(raw.to_owned()))?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| DnsError::InvalidFakeIpRange(raw.to_owned()))?;
        if prefix > 32 {
            return Err(DnsError::InvalidFakeIpRange(raw.to_owned()));
        }
        let size = if prefix == 32 { 1 } else { 1_u32 << (32 - prefix) };
        Ok(Self {
            base: u32::from(base_ip),
            size,
            next_offset: 0,
            host_to_ip: HashMap::new(),
            ip_to_host: HashMap::new(),
        })
    }

    fn assign(&mut self, host: &str) -> Result<IpAddr, DnsError> {
        if let Some(ip) = self.host_to_ip.get(host) {
            return Ok(IpAddr::V4(*ip));
        }
        if self.next_offset >= self.size {
            self.next_offset = 0;
        }
        let ip = Ipv4Addr::from(self.base.wrapping_add(self.next_offset));
        self.next_offset = self.next_offset.saturating_add(1);
        self.host_to_ip.insert(host.to_owned(), ip);
        self.ip_to_host.insert(ip, host.to_owned());
        Ok(IpAddr::V4(ip))
    }

    fn reverse(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(ip) => self.ip_to_host.get(&ip).map(String::as_str),
            IpAddr::V6(_) => None,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                let end = self.base.wrapping_add(self.size.saturating_sub(1));
                self.base <= ip && ip <= end
            }
            IpAddr::V6(_) => false,
        }
    }

    fn clear(&mut self) {
        self.next_offset = 0;
        self.host_to_ip.clear();
        self.ip_to_host.clear();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FakeIpPool6 {
    base: u128,
    size: u128,
    next_offset: u128,
    host_to_ip: HashMap<String, Ipv6Addr>,
    ip_to_host: HashMap<Ipv6Addr, String>,
}

impl FakeIpPool6 {
    fn new(raw: &str) -> Result<Self, DnsError> {
        let Some((ip, prefix)) = raw.split_once('/') else {
            return Err(DnsError::InvalidFakeIpRange(raw.to_owned()));
        };
        let base_ip = ip
            .trim()
            .parse::<Ipv6Addr>()
            .map_err(|_| DnsError::InvalidFakeIpRange(raw.to_owned()))?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| DnsError::InvalidFakeIpRange(raw.to_owned()))?;
        if prefix > 128 {
            return Err(DnsError::InvalidFakeIpRange(raw.to_owned()));
        }
        let size = match prefix {
            128 => 1,
            0 => u128::MAX,
            _ => 1_u128
                .checked_shl((128 - prefix) as u32)
                .unwrap_or(u128::MAX),
        };
        Ok(Self {
            base: u128::from(base_ip),
            size,
            next_offset: 0,
            host_to_ip: HashMap::new(),
            ip_to_host: HashMap::new(),
        })
    }

    fn assign(&mut self, host: &str) -> Result<IpAddr, DnsError> {
        if let Some(ip) = self.host_to_ip.get(host) {
            return Ok(IpAddr::V6(*ip));
        }
        if self.next_offset >= self.size {
            self.next_offset = 0;
        }
        let ip = Ipv6Addr::from(self.base.wrapping_add(self.next_offset));
        self.next_offset = self.next_offset.saturating_add(1);
        self.host_to_ip.insert(host.to_owned(), ip);
        self.ip_to_host.insert(ip, host.to_owned());
        Ok(IpAddr::V6(ip))
    }

    fn reverse(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V6(ip) => self.ip_to_host.get(&ip).map(String::as_str),
            IpAddr::V4(_) => None,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                let end = self.base.wrapping_add(self.size.saturating_sub(1));
                self.base <= ip && ip <= end
            }
            IpAddr::V4(_) => false,
        }
    }

    fn clear(&mut self) {
        self.next_offset = 0;
        self.host_to_ip.clear();
        self.ip_to_host.clear();
    }
}

impl DnsRuntimeConfig {
    fn from_top_level(config: &TopLevelDnsConfig) -> Self {
        Self {
            enabled: config.enable,
            listen: config.listen.clone(),
            use_hosts: config.use_hosts,
            use_system_hosts: config.use_system_hosts,
            enhanced_mode: match config.enhanced_mode.to_ascii_lowercase().as_str() {
                "fake-ip" => EnhancedMode::FakeIp,
                "redir-host" => EnhancedMode::RedirHost,
                _ => EnhancedMode::Disabled,
            },
            fake_ip_filter_mode: match config.fake_ip_filter_mode.to_ascii_lowercase().as_str() {
                "whitelist" => FakeIpFilterMode::Whitelist,
                "rule" => FakeIpFilterMode::Rule,
                _ => FakeIpFilterMode::Blacklist,
            },
            fake_ip_ttl: config.fake_ip_ttl.max(0) as u32,
            fake_ip_range6: config.fake_ip_range6.clone(),
            nameserver: config.nameserver.clone(),
            default_nameserver: config.default_nameserver.clone(),
            fallback: config.fallback.clone(),
            proxy_server_nameserver: config.proxy_server_nameserver.clone(),
            direct_nameserver: config.direct_nameserver.clone(),
            direct_nameserver_follow_policy: config.direct_nameserver_follow_policy,
        }
    }
}

fn validate_fake_ip_filter_rules(document: &RuntimeConfigDocument) -> Result<(), DnsError> {
    for raw in &document.dns.fake_ip_filter {
        let definition = parse_rule(raw)?;
        if definition.rule_type == RuleType::RuleSet {
            let Some(provider) = document.rule_providers.get(&definition.payload) else {
                return Err(DnsError::Rule(RuleError::RuleProviderNotFound(
                    definition.payload,
                )));
            };
            if provider.behavior_kind() == Some(RuleProviderBehavior::IpCidr) {
                return Err(DnsError::Rule(RuleError::InvalidLogic(raw.clone())));
            }
            continue;
        }
        if !is_domain_rule_type(definition.rule_type) && definition.rule_type != RuleType::Match {
            return Err(DnsError::Rule(RuleError::InvalidLogic(raw.clone())));
        }
    }
    Ok(())
}

fn is_domain_rule_type(rule_type: RuleType) -> bool {
    matches!(
        rule_type,
        RuleType::Domain
            | RuleType::DomainSuffix
            | RuleType::DomainKeyword
            | RuleType::DomainRegex
            | RuleType::DomainWildcard
            | RuleType::RuleSet
    )
}

fn compile_fake_ip_filter_matchers<S>(
    document: &RuntimeConfigDocument,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<FakeIpFilterMatcher>, DnsError>
where
    S: AsRef<[u8]>,
{
    let mut matchers = Vec::new();
    for raw in &document.dns.fake_ip_filter {
        let normalized = raw.trim();
        if normalized.is_empty() || normalized.contains(',') {
            continue;
        }
        if let Some(name) = normalized.strip_prefix("rule-set:") {
            let name = name.trim();
            let Some(provider) = document.rule_providers.get(name) else {
                return Err(DnsError::Rule(RuleError::RuleProviderNotFound(
                    name.to_owned(),
                )));
            };
            if provider.behavior_kind() == Some(RuleProviderBehavior::IpCidr) {
                return Err(DnsError::Rule(RuleError::InvalidLogic(normalized.to_owned())));
            }
            let rule_set = compile_rule_table_with_providers(
                &[format!("RULE-SET,{name},fake-ip-filter")],
                &BTreeMap::new(),
                &document.rule_providers,
                file_contents,
                http_contents,
            )?;
            matchers.push(FakeIpFilterMatcher::RuleSet(rule_set));
            continue;
        }
        matchers.push(FakeIpFilterMatcher::HostPattern(HostPattern::parse(normalized)));
    }
    Ok(matchers)
}

fn compile_fallback_domain_matchers<S>(
    document: &RuntimeConfigDocument,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<NameserverPolicyMatcher>, DnsError>
where
    S: AsRef<[u8]>,
{
    let mut matchers = Vec::new();
    for raw in &document.dns.fallback_filter.domain {
        let normalized = raw.trim();
        if normalized.is_empty() {
            continue;
        }
        if let Some(name) = normalized.strip_prefix("rule-set:") {
            let name = name.trim();
            let Some(provider) = document.rule_providers.get(name) else {
                return Err(DnsError::Rule(RuleError::RuleProviderNotFound(
                    name.to_owned(),
                )));
            };
            if provider.behavior_kind() == Some(RuleProviderBehavior::IpCidr) {
                return Err(DnsError::Rule(RuleError::InvalidLogic(normalized.to_owned())));
            }
            let rule_set = compile_rule_table_with_providers(
                &[format!("RULE-SET,{name},dns.fallback-filter.domain")],
                &BTreeMap::new(),
                &document.rule_providers,
                file_contents,
                http_contents,
            )?;
            matchers.push(NameserverPolicyMatcher::RuleSet(rule_set));
            continue;
        }
        matchers.push(NameserverPolicyMatcher::HostPattern(HostPattern::parse(normalized)));
    }
    Ok(matchers)
}

fn compile_fallback_ip_matchers<S>(
    document: &RuntimeConfigDocument,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<FallbackIpMatcher>, DnsError>
where
    S: AsRef<[u8]>,
{
    let mut matchers = Vec::new();
    for raw in &document.dns.fallback_filter.ipcidr {
        let normalized = raw.trim();
        if normalized.is_empty() {
            continue;
        }
        if let Some(name) = normalized.strip_prefix("rule-set:") {
            let name = name.trim();
            let Some(provider) = document.rule_providers.get(name) else {
                return Err(DnsError::Rule(RuleError::RuleProviderNotFound(
                    name.to_owned(),
                )));
            };
            if provider.behavior_kind() == Some(RuleProviderBehavior::Domain) {
                return Err(DnsError::Rule(RuleError::InvalidLogic(normalized.to_owned())));
            }
            let rule_set = compile_rule_table_with_providers(
                &[format!("RULE-SET,{name},dns.fallback-filter.ipcidr")],
                &BTreeMap::new(),
                &document.rule_providers,
                file_contents,
                http_contents,
            )?;
            matchers.push(FallbackIpMatcher::RuleSet(rule_set));
            continue;
        }
        matchers.push(FallbackIpMatcher::Cidr(
            IpCidrMatcher::parse(normalized).map_err(DnsError::Rule)?,
        ));
    }
    Ok(matchers)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedDnsQuery {
    request_id: u16,
    flags: u16,
    query_type: DnsRecordType,
    host: String,
    question: Vec<u8>,
}

fn query_server<T: DnsPacketTransport>(
    upstream: &mut NetworkDnsUpstream<T>,
    server: &str,
    host: &str,
) -> Result<Vec<IpAddr>, DnsError> {
    let mut answers = Vec::new();
    for query_type in [DnsRecordType::A, DnsRecordType::Aaaa] {
        let request_id = upstream.next_request_id;
        upstream.next_request_id = upstream.next_request_id.wrapping_add(1);
        let payload = build_dns_query(host, query_type, request_id)?;
        let response = upstream.transport.exchange(server, &payload)?;
        let mut ips = parse_dns_response(&response, request_id, query_type)?;
        answers.append(&mut ips);
    }
    Ok(answers)
}

fn build_dns_query(host: &str, query_type: DnsRecordType, request_id: u16) -> Result<Vec<u8>, DnsError> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.extend_from_slice(&0x0100_u16.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());

    for label in host.trim_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > u8::MAX as usize {
            return Err(DnsError::DnsProtocol(format!("label too long: {label}")));
        }
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&(query_type as u16).to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    Ok(payload)
}

fn parse_dns_response(
    message: &[u8],
    request_id: u16,
    query_type: DnsRecordType,
) -> Result<Vec<IpAddr>, DnsError> {
    if message.len() < 12 {
        return Err(DnsError::DnsProtocol("response too short".to_owned()));
    }
    let response_id = u16::from_be_bytes([message[0], message[1]]);
    if response_id != request_id {
        return Err(DnsError::DnsProtocol("mismatched response id".to_owned()));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::DnsProtocol("response bit missing".to_owned()));
    }
    if flags & 0x000F != 0 {
        return Ok(Vec::new());
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;

    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_name(message, offset)?;
        offset = offset.checked_add(4).ok_or_else(|| {
            DnsError::DnsProtocol("question overflow".to_owned())
        })?;
        if offset > message.len() {
            return Err(DnsError::DnsProtocol("question exceeds buffer".to_owned()));
        }
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(DnsError::DnsProtocol("answer header exceeds buffer".to_owned()));
        }
        let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let _class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let rd_length =
            u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + rd_length > message.len() {
            return Err(DnsError::DnsProtocol("answer data exceeds buffer".to_owned()));
        }
        if rr_type == query_type as u16 {
            match query_type {
                DnsRecordType::A if rd_length == 4 => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        message[offset],
                        message[offset + 1],
                        message[offset + 2],
                        message[offset + 3],
                    )));
                }
                DnsRecordType::Aaaa if rd_length == 16 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&message[offset..offset + 16]);
                    ips.push(IpAddr::from(octets));
                }
                _ => {}
            }
        }
        offset += rd_length;
    }

    Ok(ips)
}

#[doc(hidden)]
pub fn build_dns_query_for_tests(
    host: &str,
    query_type: DnsRecordType,
    request_id: u16,
) -> Result<Vec<u8>, DnsError> {
    build_dns_query(host, query_type, request_id)
}

#[doc(hidden)]
pub fn parse_dns_response_for_tests(
    payload: &[u8],
    request_id: u16,
    query_type: DnsRecordType,
) -> Result<Vec<IpAddr>, DnsError> {
    parse_dns_response(payload, request_id, query_type)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    let mut jumps = 0;
    loop {
        let Some(&length) = message.get(offset) else {
            return Err(DnsError::DnsProtocol("name exceeds buffer".to_owned()));
        };
        if length & 0xC0 == 0xC0 {
            if offset + 1 >= message.len() {
                return Err(DnsError::DnsProtocol("compressed name truncated".to_owned()));
            }
            return Ok(offset + 2);
        }
        if length == 0 {
            return Ok(offset + 1);
        }
        offset = offset
            .checked_add(1 + length as usize)
            .ok_or_else(|| DnsError::DnsProtocol("name overflow".to_owned()))?;
        jumps += 1;
        if jumps > 128 {
            return Err(DnsError::DnsProtocol("name compression loop".to_owned()));
        }
    }
}

fn parse_udp_nameserver(raw: &str) -> Result<String, DnsError> {
    let endpoint = raw.split('#').next().unwrap_or(raw).trim();
    if endpoint.is_empty() {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    }
    let endpoint = endpoint
        .strip_prefix("udp://")
        .unwrap_or(endpoint);
    if endpoint.contains("://") {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    }
    if endpoint.starts_with('[') {
        if endpoint.contains("]:") {
            return Ok(endpoint.to_owned());
        }
        return Ok(format!("{endpoint}:53"));
    }
    if endpoint.rsplit_once(':').is_some() {
        Ok(endpoint.to_owned())
    } else {
        Ok(format!("{endpoint}:53"))
    }
}

fn parse_dns_query_packet(packet: &[u8]) -> Result<ParsedDnsQuery, DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::DnsProtocol("query too short".to_owned()));
    }
    let request_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if question_count != 1 {
        return Err(DnsError::DnsProtocol(format!(
            "unsupported question count: {question_count}"
        )));
    }

    let mut offset = 12;
    let host = read_name_string(packet, &mut offset)?;
    if offset + 4 > packet.len() {
        return Err(DnsError::DnsProtocol("query question truncated".to_owned()));
    }
    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    if qclass != 1 {
        return Err(DnsError::DnsProtocol(format!(
            "unsupported query class: {qclass}"
        )));
    }
    offset += 4;
    let query_type = match qtype {
        1 => DnsRecordType::A,
        28 => DnsRecordType::Aaaa,
        other => {
            return Err(DnsError::DnsProtocol(format!(
                "unsupported query type: {other}"
            )))
        }
    };
    Ok(ParsedDnsQuery {
        request_id,
        flags,
        query_type,
        host,
        question: packet[12..offset].to_vec(),
    })
}

fn read_name_string(packet: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut labels = Vec::new();
    loop {
        let Some(&length) = packet.get(*offset) else {
            return Err(DnsError::DnsProtocol("query name exceeds buffer".to_owned()));
        };
        *offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xC0 != 0 {
            return Err(DnsError::DnsProtocol(
                "compressed query names are not supported".to_owned(),
            ));
        }
        let end = offset.checked_add(length as usize).ok_or_else(|| {
            DnsError::DnsProtocol("query name overflow".to_owned())
        })?;
        if end > packet.len() {
            return Err(DnsError::DnsProtocol("query name exceeds buffer".to_owned()));
        }
        labels.push(String::from_utf8_lossy(&packet[*offset..end]).into_owned());
        *offset = end;
    }
    Ok(labels.join("."))
}

fn build_dns_response(query: &ParsedDnsQuery, ttl_secs: u32, ips: &[IpAddr]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&query.request_id.to_be_bytes());
    let response_flags = 0x8000_u16 | 0x0080_u16 | (query.flags & 0x0100);
    payload.extend_from_slice(&response_flags.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&(ips.len() as u16).to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&query.question);

    for ip in ips {
        payload.extend_from_slice(&0xC00C_u16.to_be_bytes());
        payload.extend_from_slice(&(query.query_type as u16).to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&ttl_secs.to_be_bytes());
        match ip {
            IpAddr::V4(ip) => {
                payload.extend_from_slice(&4_u16.to_be_bytes());
                payload.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                payload.extend_from_slice(&16_u16.to_be_bytes());
                payload.extend_from_slice(&ip.octets());
            }
        }
    }
    payload
}

fn matches_query_type(ip: IpAddr, query_type: DnsRecordType) -> bool {
    matches!(
        (ip, query_type),
        (IpAddr::V4(_), DnsRecordType::A) | (IpAddr::V6(_), DnsRecordType::Aaaa)
    )
}

fn response_ttl_secs(runtime: &DnsRuntime, has_answer: bool) -> u32 {
    if has_answer && runtime.config.enhanced_mode == EnhancedMode::FakeIp && runtime.config.fake_ip_ttl > 0
    {
        runtime.config.fake_ip_ttl
    } else {
        60
    }
}

fn query_upstream(
    upstream: &mut impl DnsUpstream,
    servers: &[String],
    host: &str,
) -> Result<Option<ResolveAnswer>, DnsError> {
    if servers.is_empty() {
        return Ok(None);
    }
    let ips = upstream.resolve(servers, host)?;
    if ips.is_empty() {
        return Ok(None);
    }
    Ok(Some(ResolveAnswer {
        ips,
        servers: servers.to_vec(),
        source: ResolveSource::Nameserver,
    }))
}

fn compile_hosts(
    raw_hosts: &BTreeMap<String, HostMappingValue>,
    system_hosts_text: Option<&str>,
) -> Vec<HostEntry> {
    let mut hosts = raw_hosts
        .iter()
        .map(|(host, value)| HostEntry {
            pattern: HostPattern::parse(host),
            values: value.values.iter().map(|value| value.trim().to_owned()).collect(),
        })
        .collect::<Vec<_>>();

    if let Some(text) = system_hosts_text {
        append_system_hosts(&mut hosts, text);
    }

    hosts
}

fn compile_nameserver_policies<S>(
    document: &RuntimeConfigDocument,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<NameserverPolicy>, DnsError>
where
    S: AsRef<[u8]>,
{
    let mut policies = Vec::new();
    for (pattern, servers) in &document.dns.nameserver_policy {
        let matchers =
            compile_nameserver_policy_matchers(document, pattern, file_contents, http_contents)?;
        if matchers.is_empty() {
            continue;
        }
        policies.push(NameserverPolicy {
            matchers,
            servers: servers.values.clone(),
        });
    }
    Ok(policies)
}

fn compile_proxy_nameserver_policies<S>(
    document: &RuntimeConfigDocument,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<NameserverPolicy>, DnsError>
where
    S: AsRef<[u8]>,
{
    let mut policies = Vec::new();
    for (pattern, servers) in &document.dns.proxy_server_nameserver_policy {
        let matchers =
            compile_nameserver_policy_matchers(document, pattern, file_contents, http_contents)?;
        if matchers.is_empty() {
            continue;
        }
        policies.push(NameserverPolicy {
            matchers,
            servers: servers.values.clone(),
        });
    }
    Ok(policies)
}

fn compile_nameserver_policy_matchers<S>(
    document: &RuntimeConfigDocument,
    pattern: &str,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<NameserverPolicyMatcher>, DnsError>
where
    S: AsRef<[u8]>,
{
    let normalized = pattern.trim();
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(rest) = normalized.strip_prefix("rule-set:") {
        return rest
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| {
                let Some(provider) = document.rule_providers.get(name) else {
                    return Err(DnsError::Rule(RuleError::RuleProviderNotFound(
                        name.to_owned(),
                    )));
                };
                if provider.behavior_kind() == Some(RuleProviderBehavior::IpCidr) {
                    return Err(DnsError::Rule(RuleError::InvalidLogic(format!(
                        "rule-set:{name}"
                    ))));
                }
                let rule_set = compile_rule_table_with_providers(
                    &[format!("RULE-SET,{name},dns.nameserver-policy")],
                    &BTreeMap::new(),
                    &document.rule_providers,
                    file_contents,
                    http_contents,
                )?;
                Ok(NameserverPolicyMatcher::RuleSet(rule_set))
            })
            .collect();
    }

    Ok(normalized
        .split(',')
        .map(str::trim)
        .filter(|entry| {
            (!entry.is_empty() && !entry.contains(':'))
                || entry.starts_with("+.")
                || entry.starts_with("*.")
                || entry.starts_with('.')
        })
        .map(|entry| NameserverPolicyMatcher::HostPattern(HostPattern::parse(entry)))
        .collect())
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn append_system_hosts(entries: &mut Vec<HostEntry>, raw: &str) {
    for line in raw.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0].trim();
        if ip.parse::<IpAddr>().is_err() {
            continue;
        }
        for host in &parts[1..] {
            let normalized = normalize(host);
            if normalized.is_empty() {
                continue;
            }
            if entries.iter().any(|entry| {
                matches!(&entry.pattern, HostPattern::Exact(existing) if existing == &normalized)
            }) {
                continue;
            }
            entries.push(HostEntry {
                pattern: HostPattern::Exact(normalized),
                values: vec![ip.to_owned()],
            });
        }
    }
}

fn read_system_hosts_text() -> Option<String> {
    let candidates = if cfg!(windows) {
        let mut paths = Vec::new();
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            paths.push(
                std::path::PathBuf::from(system_root)
                    .join("System32")
                    .join("drivers")
                    .join("etc")
                    .join("hosts"),
            );
        }
        paths
    } else {
        vec![std::path::PathBuf::from("/etc/hosts")]
    };
    for path in candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            return Some(content);
        }
    }
    None
}

fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-dns",
    go_areas: &["dns", "component/resolver", "component/fakeip"],
    contracts: &["resolver flow", "fake-ip", "hosts and system DNS compatibility"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::net::{IpAddr, Ipv4Addr};

    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{DnsMode, Metadata};

    use super::{
        build_dns_query, parse_dns_response, DnsPacketTransport, DnsRecordType, DnsRuntime,
        DnsUpstream, EnhancedMode, FakeIpFilterMode, NetworkDnsUpstream,
    };

    #[derive(Default)]
    struct StaticUpstream {
        answers: HashMap<(String, String), Vec<IpAddr>>,
        calls: Vec<(Vec<String>, String)>,
    }

    impl StaticUpstream {
        fn with_answer(
            mut self,
            server: &str,
            host: &str,
            answers: Vec<IpAddr>,
        ) -> Self {
            self.answers
                .insert((server.to_owned(), host.to_owned()), answers);
            self
        }
    }

    impl DnsUpstream for StaticUpstream {
        fn resolve(
            &mut self,
            servers: &[String],
            host: &str,
        ) -> Result<Vec<IpAddr>, super::DnsError> {
            self.calls.push((servers.to_vec(), host.to_owned()));
            for server in servers {
                if let Some(answer) = self.answers.get(&(server.clone(), host.to_owned())) {
                    return Ok(answer.clone());
                }
            }
            Ok(Vec::new())
        }
    }

    #[derive(Default)]
    struct FakePacketTransport {
        calls: Vec<String>,
        responses: HashMap<String, Vec<u8>>,
    }

    impl FakePacketTransport {
        fn with_response(mut self, server: &str, response: Vec<u8>) -> Self {
            self.responses.insert(server.to_owned(), response);
            self
        }
    }

    impl DnsPacketTransport for FakePacketTransport {
        fn exchange(&mut self, server: &str, _payload: &[u8]) -> Result<Vec<u8>, super::DnsError> {
            self.calls.push(server.to_owned());
            Ok(self.responses.get(server).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn hosts_exact_and_alias_resolution_work() {
        let document = parse_runtime_config_document(
            r#"
hosts:
  example.com: 1.1.1.1
  alias.local: example.com
dns:
  use-hosts: true
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        assert_eq!(
            runtime.resolve_host("example.com").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        assert_eq!(
            runtime.resolve_host("alias.local").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[test]
    fn system_hosts_entries_are_loaded_when_enabled() {
        let document = parse_runtime_config_document(
            r#"
dns:
  use-system-hosts: true
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document_with_rule_providers_and_system_hosts(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Some(
                r#"
127.0.0.1 localhost custom.local
10.0.0.2 service.internal
"#,
            ),
        )
        .unwrap();
        assert_eq!(
            runtime.resolve_host("service.internal").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(
            runtime.resolve_host("custom.local").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn explicit_hosts_override_system_hosts_entries() {
        let document = parse_runtime_config_document(
            r#"
hosts:
  custom.local: 1.1.1.1
dns:
  use-system-hosts: true
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document_with_rule_providers_and_system_hosts(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Some("127.0.0.1 custom.local"),
        )
        .unwrap();
        assert_eq!(
            runtime.resolve_host("custom.local").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[test]
    fn fake_ip_assignment_and_reverse_lookup_work() {
        let document = parse_runtime_config_document(
            r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let fake_ip = runtime.resolve_host("example.com").unwrap().unwrap();
        assert!(runtime.reverse_lookup(fake_ip).is_some());
        let mut metadata = Metadata {
            dst_ip: Some(fake_ip),
            ..Metadata::default()
        };
        runtime.resolve_metadata(&mut metadata).unwrap();
        assert_eq!(metadata.host.as_deref(), Some("example.com"));
        assert_eq!(metadata.dns_mode, DnsMode::FakeIp);
    }

    #[test]
    fn fake_ip_range6_answers_aaaa_queries_and_reverse_lookup_work() {
        let document = parse_runtime_config_document(
            r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range6: fdfe:dcba:9876::1/64
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let query = build_dns_query("example.com", DnsRecordType::Aaaa, 0x4321).unwrap();
        let response = runtime
            .handle_query_packet(&query, &mut StaticUpstream::default())
            .unwrap()
            .unwrap();
        let ips = parse_dns_response(&response, 0x4321, DnsRecordType::Aaaa).unwrap();
        assert_eq!(ips.len(), 1);
        assert!(matches!(ips[0], IpAddr::V6(_)));
        assert_eq!(runtime.reverse_lookup(ips[0]), Some("example.com"));
    }

    #[test]
    fn resolve_metadata_recovers_host_from_ipv6_fake_ip() {
        let document = parse_runtime_config_document(
            r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range6: fdfe:dcba:9876::1/64
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let query = build_dns_query("example.com", DnsRecordType::Aaaa, 0x4321).unwrap();
        let response = runtime
            .handle_query_packet(&query, &mut StaticUpstream::default())
            .unwrap()
            .unwrap();
        let fake_ip = parse_dns_response(&response, 0x4321, DnsRecordType::Aaaa).unwrap()[0];
        let mut metadata = Metadata {
            dst_ip: Some(fake_ip),
            ..Metadata::default()
        };
        runtime.resolve_metadata(&mut metadata).unwrap();
        assert_eq!(metadata.host.as_deref(), Some("example.com"));
        assert_eq!(metadata.dns_mode, DnsMode::FakeIp);
    }

    #[test]
    fn fake_ip_filter_blacklist_and_whitelist_modes_apply() {
        let blacklist = parse_runtime_config_document(
            r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - '*.lan'
"#,
        )
        .unwrap();
        let runtime = DnsRuntime::from_document(&blacklist).unwrap();
        assert_eq!(runtime.config.enhanced_mode, EnhancedMode::FakeIp);
        assert_eq!(runtime.config.fake_ip_filter_mode, FakeIpFilterMode::Blacklist);
        assert!(!runtime.should_use_fake_ip("router.lan"));

        let whitelist = parse_runtime_config_document(
            r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
  fake-ip-filter:
    - '*.allowed'
"#,
        )
        .unwrap();
        let runtime = DnsRuntime::from_document(&whitelist).unwrap();
        assert!(runtime.should_use_fake_ip("app.allowed"));
        assert!(!runtime.should_use_fake_ip("blocked.example"));
    }

    #[test]
    fn fake_ip_filter_rule_mode_uses_rule_targets() {
        let document = parse_runtime_config_document(
            r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - DOMAIN-SUFFIX,example.com,fake-ip
    - MATCH,real-ip
"#,
        )
        .unwrap();
        let runtime = DnsRuntime::from_document(&document).unwrap();
        assert!(runtime.should_use_fake_ip("www.example.com"));
        assert!(!runtime.should_use_fake_ip("other.test"));
    }

    #[test]
    fn fake_ip_filter_rule_mode_supports_rule_set_provider() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .example.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
    - MATCH,real-ip
"#,
        )
        .unwrap();
        let runtime = DnsRuntime::from_document_with_rule_providers(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(runtime.should_use_fake_ip("api.example.net"));
        assert!(!runtime.should_use_fake_ip("other.test"));
    }

    #[test]
    fn fake_ip_filter_rule_mode_rejects_ipcidr_rule_set_provider() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: ipcidr
    payload:
      - 1.1.1.0/24
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
"#,
        )
        .unwrap();
        assert!(DnsRuntime::from_document_with_rule_providers(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[test]
    fn fake_ip_filter_blacklist_and_whitelist_support_rule_set_provider() {
        let blacklist = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .blocked.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - rule-set:rule1
"#,
        )
        .unwrap();
        let blacklist_runtime = DnsRuntime::from_document_with_rule_providers(
            &blacklist,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(!blacklist_runtime.should_use_fake_ip("api.blocked.net"));
        assert!(blacklist_runtime.should_use_fake_ip("other.test"));

        let whitelist = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .allowed.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
  fake-ip-filter:
    - rule-set:rule1
"#,
        )
        .unwrap();
        let whitelist_runtime = DnsRuntime::from_document_with_rule_providers(
            &whitelist,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(whitelist_runtime.should_use_fake_ip("api.allowed.net"));
        assert!(!whitelist_runtime.should_use_fake_ip("other.test"));
    }

    #[test]
    fn fake_ip_filter_blacklist_and_whitelist_reject_ipcidr_rule_set_provider() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: ipcidr
    payload:
      - 1.1.1.0/24
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - rule-set:rule1
"#,
        )
        .unwrap();
        assert!(DnsRuntime::from_document_with_rule_providers(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[test]
    fn resolve_metadata_prefers_hosts_before_fake_ip() {
        let document = parse_runtime_config_document(
            r#"
hosts:
  service.local: 10.0.0.10
dns:
  use-hosts: true
  enhanced-mode: fake-ip
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let mut metadata = Metadata {
            host: Some("service.local".into()),
            ..Metadata::default()
        };
        runtime.resolve_metadata(&mut metadata).unwrap();
        assert_eq!(metadata.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10))));
        assert_eq!(metadata.dns_mode, DnsMode::Hosts);
    }

    #[test]
    fn nameserver_policy_and_fallback_with_cache_work() {
        let document = parse_runtime_config_document(
            r#"
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  nameserver-policy:
    "+.cn":
      - 223.5.5.5
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        assert_eq!(runtime.select_nameservers("www.test.cn"), vec!["223.5.5.5"]);

        let mut upstream = StaticUpstream::default()
            .with_answer("1.1.1.1", "fallback.test", vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))])
            .with_answer("223.5.5.5", "www.test.cn", vec![IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))]);

        assert_eq!(
            runtime.resolve_host_with_upstream("www.test.cn", &mut upstream).unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)))
        );
        assert_eq!(
            runtime.resolve_host_with_upstream("fallback.test", &mut upstream).unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
        let calls_before_cache = upstream.calls.len();
        assert_eq!(
            runtime.resolve_host_with_upstream("fallback.test", &mut upstream).unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
        assert_eq!(upstream.calls.len(), calls_before_cache);
        assert_eq!(
            runtime.cached_answer("fallback.test").unwrap().ips,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
        );
    }

    #[test]
    fn fallback_filter_domain_forces_fallback_nameserver() {
        let document = parse_runtime_config_document(
            r#"
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    domain:
      - '+.blocked.test'
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let mut upstream = StaticUpstream::default()
            .with_answer("8.8.8.8", "api.blocked.test", vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .with_answer("1.1.1.1", "api.blocked.test", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

        assert_eq!(
            runtime
                .resolve_host_with_upstream("api.blocked.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[test]
    fn fallback_filter_ipcidr_switches_to_fallback_nameserver() {
        let document = parse_runtime_config_document(
            r#"
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    ipcidr:
      - 240.0.0.0/4
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let mut upstream = StaticUpstream::default()
            .with_answer("8.8.8.8", "fallback.test", vec![IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))])
            .with_answer("1.1.1.1", "fallback.test", vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);

        assert_eq!(
            runtime
                .resolve_host_with_upstream("fallback.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
    }

    #[test]
    fn fallback_filter_supports_rule_set_providers() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  domain-rule:
    type: inline
    behavior: domain
    payload:
      - .domain.test
  ip-rule:
    type: inline
    behavior: ipcidr
    payload:
      - 240.0.0.0/4
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    domain:
      - rule-set:domain-rule
    ipcidr:
      - rule-set:ip-rule
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document_with_rule_providers(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let mut upstream = StaticUpstream::default()
            .with_answer("8.8.8.8", "api.domain.test", vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .with_answer("1.1.1.1", "api.domain.test", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))])
            .with_answer("8.8.8.8", "fallback.test", vec![IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))])
            .with_answer("1.1.1.1", "fallback.test", vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);

        assert_eq!(
            runtime
                .resolve_host_with_upstream("api.domain.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        assert_eq!(
            runtime
                .resolve_host_with_upstream("fallback.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
    }

    #[test]
    fn nameserver_policy_supports_rule_set_provider() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .example.net
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "rule-set:rule1":
      - 9.9.9.9
"#,
        )
        .unwrap();
        let runtime = DnsRuntime::from_document_with_rule_providers(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(runtime.select_nameservers("api.example.net"), vec!["9.9.9.9"]);
        assert_eq!(runtime.select_nameservers("other.test"), vec!["8.8.8.8"]);
    }

    #[test]
    fn proxy_server_nameserver_policy_is_used() {
        let document = parse_runtime_config_document(
            r#"
dns:
  nameserver:
    - 8.8.8.8
  proxy-server-nameserver:
    - 9.9.9.9
  proxy-server-nameserver-policy:
    "+.proxy.test":
      - 4.4.4.4
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        assert_eq!(
            runtime.select_proxy_server_nameservers("api.proxy.test"),
            vec!["4.4.4.4"]
        );
        assert_eq!(
            runtime.select_proxy_server_nameservers("other.test"),
            vec!["9.9.9.9"]
        );

        let mut upstream = StaticUpstream::default()
            .with_answer("4.4.4.4", "api.proxy.test", vec![IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4))])
            .with_answer("9.9.9.9", "other.test", vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))])
            .with_answer("8.8.8.8", "api.proxy.test", vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);

        assert_eq!(
            runtime
                .resolve_proxy_server_host_with_upstream("api.proxy.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)))
        );
        assert_eq!(
            runtime
                .resolve_proxy_server_host_with_upstream("other.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
        assert_eq!(
            upstream.calls,
            vec![
                (vec!["4.4.4.4".into()], "api.proxy.test".into()),
                (vec!["9.9.9.9".into()], "other.test".into())
            ]
        );
    }

    #[test]
    fn direct_nameserver_follow_policy_controls_selection() {
        let document = parse_runtime_config_document(
            r#"
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "+.cn":
      - 223.5.5.5
  direct-nameserver:
    - 1.1.1.1
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        assert_eq!(
            runtime.select_direct_nameservers("www.test.cn"),
            vec!["1.1.1.1"]
        );
        let mut upstream = StaticUpstream::default()
            .with_answer("1.1.1.1", "www.test.cn", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        assert_eq!(
            runtime
                .resolve_direct_server_host_with_upstream("www.test.cn", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        assert_eq!(
            upstream.calls,
            vec![(vec!["1.1.1.1".into()], "www.test.cn".into())]
        );

        let document = parse_runtime_config_document(
            r#"
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "+.cn":
      - 223.5.5.5
  direct-nameserver:
    - 1.1.1.1
  direct-nameserver-follow-policy: true
"#,
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        assert_eq!(
            runtime.select_direct_nameservers("www.test.cn"),
            vec!["223.5.5.5"]
        );
        assert_eq!(
            runtime.select_direct_nameservers("other.test"),
            vec!["8.8.8.8"]
        );
        let mut upstream = StaticUpstream::default()
            .with_answer("223.5.5.5", "www.test.cn", vec![IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))])
            .with_answer("8.8.8.8", "other.test", vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
        assert_eq!(
            runtime
                .resolve_direct_server_host_with_upstream("www.test.cn", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)))
        );
        assert_eq!(
            runtime
                .resolve_direct_server_host_with_upstream("other.test", &mut upstream)
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(
            upstream.calls,
            vec![
                (vec!["223.5.5.5".into()], "www.test.cn".into()),
                (vec!["8.8.8.8".into()], "other.test".into())
            ]
        );
    }

    #[test]
    fn nameserver_policy_rejects_ipcidr_rule_set_provider() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  rule1:
    type: inline
    behavior: ipcidr
    payload:
      - 1.1.1.0/24
dns:
  nameserver-policy:
    "rule-set:rule1":
      - 9.9.9.9
"#,
        )
        .unwrap();
        assert!(DnsRuntime::from_document_with_rule_providers(
            &document,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .is_err());
    }

    #[test]
    fn dns_query_codec_round_trips_a_record_answers() {
        let query = build_dns_query("example.com", DnsRecordType::A, 0x1234).unwrap();
        assert!(query.ends_with(&[0, 0x00, 0x01, 0x00, 0x01]));

        let response = [
            vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            query[12..].to_vec(),
            vec![0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 1, 1, 1],
        ]
        .concat();
        let ips = parse_dns_response(&response, 0x1234, DnsRecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
    }

    #[test]
    fn network_dns_upstream_queries_plain_udp_servers() {
        let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
        let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
        let response_a = [
            vec![0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            query_a[12..].to_vec(),
            vec![0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 8, 8, 8, 8],
        ]
        .concat();
        let response_aaaa = [
            vec![0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            query_aaaa[12..].to_vec(),
        ]
        .concat();
        let transport = FakePacketTransport::default()
            .with_response("8.8.8.8", response_a)
            .with_response("8.8.8.8#aaaa", response_aaaa);
        let mut upstream = NetworkDnsUpstream::new(SequencedTransport::new(transport));
        let result = upstream.resolve(&["8.8.8.8".into()], "example.com").unwrap();
        assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
    }

    #[test]
    fn invalid_fake_ip_range_is_reported() {
        let document = parse_runtime_config_document(
            r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/99
"#,
        )
        .unwrap();
        assert!(DnsRuntime::from_document(&document).is_err());
    }

    struct SequencedTransport {
        transport: FakePacketTransport,
        counts: HashMap<String, usize>,
    }

    impl SequencedTransport {
        fn new(transport: FakePacketTransport) -> Self {
            Self {
                transport,
                counts: HashMap::new(),
            }
        }
    }

    impl DnsPacketTransport for SequencedTransport {
        fn exchange(&mut self, server: &str, _payload: &[u8]) -> Result<Vec<u8>, super::DnsError> {
            let count = self.counts.entry(server.to_owned()).or_insert(0);
            *count += 1;
            let key = if *count == 1 {
                server.to_owned()
            } else {
                format!("{server}#aaaa")
            };
            self.transport.exchange(&key, &[])
        }
    }
}
