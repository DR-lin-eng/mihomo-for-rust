use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use mihomo_config::{RuntimeConfigDocument, TopLevelDnsConfig};
use mihomo_core::{DnsMode, Metadata, NetworkKind};
use mihomo_rules::{compile_rule_table_with_providers, RuleSet};
use serde::{Deserialize, Serialize};

use crate::matchers::{HostEntry, PersistedFakeIpPoolState};
use crate::support::{
    cache_answer, compile_fake_ip_filter_matchers, compile_fallback_domain_matchers,
    compile_fallback_ip_matchers, compile_hosts, compile_nameserver_policies,
    compile_proxy_nameserver_policies, matches_query_type, normalize, query_upstream,
    read_system_hosts_text, response_ttl_secs, validate_fake_ip_filter_rules, NoopUpstream,
};
use crate::{
    CachedAnswer, DnsError, DnsRecordType, DnsRuntime, DnsRuntimeConfig, DnsUpstream, EnhancedMode,
    FakeIpFilterMode, NetworkDnsUpstream, ResolveAnswer, ResolveSource, SystemDnsPacketTransport,
};

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
            None,
        )
    }

    pub fn from_document_with_rule_providers_and_home_bytes<S>(
        document: &RuntimeConfigDocument,
        file_contents: &BTreeMap<String, S>,
        http_contents: &BTreeMap<String, S>,
        home_dir: &Path,
    ) -> Result<Self, DnsError>
    where
        S: AsRef<[u8]>,
    {
        Self::from_document_with_rule_providers_and_system_hosts_bytes(
            document,
            file_contents,
            http_contents,
            None,
            Some(home_dir),
        )
    }

    #[cfg(test)]
    pub(crate) fn from_document_with_rule_providers_and_system_hosts(
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
            None,
        )
    }

    fn from_document_with_rule_providers_and_system_hosts_bytes<S>(
        document: &RuntimeConfigDocument,
        file_contents: &BTreeMap<String, S>,
        http_contents: &BTreeMap<String, S>,
        system_hosts_override: Option<&str>,
        home_dir: Option<&Path>,
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
        let hosts = compile_hosts(&document.hosts, system_hosts_text.as_deref());
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
        let fake_ip_pool = crate::matchers::FakeIpPool::new(&document.dns.fake_ip_range)?;
        let fake_ip_pool6 = if document.dns.fake_ip_range6.trim().is_empty() {
            None
        } else {
            Some(crate::matchers::FakeIpPool6::new(
                &document.dns.fake_ip_range6,
            )?)
        };
        let nameserver_policies =
            compile_nameserver_policies(document, file_contents, http_contents)?;
        let proxy_server_nameserver_policies =
            compile_proxy_nameserver_policies(document, file_contents, http_contents)?;
        let fallback_domain_matchers =
            compile_fallback_domain_matchers(document, file_contents, http_contents)?;
        let fallback_ip_matchers =
            compile_fallback_ip_matchers(document, file_contents, http_contents)?;
        let fake_ip_state_path = if document.profile.store_fake_ip {
            home_dir.map(|home_dir| home_dir.join("storage").join("fakeip.json"))
        } else {
            None
        };
        let mut runtime = Self {
            config,
            hosts: Arc::new(hosts),
            fake_ip_matchers: Arc::new(fake_ip_matchers),
            fake_ip_rules,
            fake_ip_pool,
            fake_ip_pool6,
            nameserver_policies: Arc::new(nameserver_policies),
            proxy_server_nameserver_policies: Arc::new(proxy_server_nameserver_policies),
            fallback_domain_matchers: Arc::new(fallback_domain_matchers),
            fallback_ip_matchers: Arc::new(fallback_ip_matchers),
            cache: Arc::new(std::collections::HashMap::new()),
            cache_order: Arc::new(std::collections::VecDeque::new()),
            domain_mappings: crate::mapping::DomainMappings::default(),
            fake_ip_state_path,
        };
        runtime.restore_fake_ip_state();
        Ok(runtime)
    }

    pub fn resolve_host(&mut self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        if self.config.use_hosts || self.config.use_system_hosts {
            if let Some(ip) = self.resolve_host_from_hosts(host)? {
                return Ok(Some(ip));
            }
        }
        if self.config.enhanced_mode == EnhancedMode::FakeIp && self.should_use_fake_ip(host) {
            let assigned = self.fake_ip_pool.assign(host)?;
            self.persist_fake_ip_state();
            return Ok(Some(assigned));
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
        let Some(answer) = self.lookup_real_answer(host, upstream)? else {
            return Ok(None);
        };
        Ok(answer.ips.first().copied())
    }

    pub fn resolve_host_addrs_with_upstream(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let Some(answer) = self.lookup_real_answer_all(host, upstream)? else {
            return Ok(Vec::new());
        };
        Ok(answer.ips)
    }

    pub fn resolve_host_via_system(&mut self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_host_with_upstream(host, &mut upstream)
    }

    pub fn resolve_host_addrs_via_system(&mut self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_host_addrs_with_upstream(host, &mut upstream)
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
        let Some(answer) = self.lookup_answer_using_servers(host, upstream, &servers, false, self.address_query_type())?
        else {
            return Ok(None);
        };
        Ok(answer.ips.first().copied())
    }

    pub fn resolve_proxy_server_host_addrs_with_upstream(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Vec<IpAddr>, DnsError> {
        if self.config.proxy_server_nameserver.is_empty() {
            return self.resolve_host_addrs_with_upstream(host, upstream);
        }
        let servers = self.select_proxy_server_nameservers(host);
        if servers.is_empty() {
            return Ok(Vec::new());
        }
        let Some(answer) = self.lookup_answer_using_servers(host, upstream, &servers, false, self.address_query_type())?
        else {
            return Ok(Vec::new());
        };
        Ok(answer.ips)
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
        let Some(answer) = self.lookup_answer_using_servers(host, upstream, &servers, false, self.address_query_type())?
        else {
            return Ok(None);
        };
        Ok(answer.ips.first().copied())
    }

    pub fn resolve_direct_server_host_addrs_with_upstream(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Vec<IpAddr>, DnsError> {
        if self.config.direct_nameserver.is_empty() {
            return self.resolve_host_addrs_with_upstream(host, upstream);
        }
        let servers = self.select_direct_nameservers(host);
        if servers.is_empty() {
            return Ok(Vec::new());
        }
        let Some(answer) = self.lookup_answer_using_servers(host, upstream, &servers, false, self.address_query_type())?
        else {
            return Ok(Vec::new());
        };
        Ok(answer.ips)
    }

    pub fn resolve_proxy_server_host_via_system(
        &mut self,
        host: &str,
    ) -> Result<Option<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_proxy_server_host_with_upstream(host, &mut upstream)
    }

    pub fn resolve_proxy_server_host_addrs_via_system(
        &mut self,
        host: &str,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_proxy_server_host_addrs_with_upstream(host, &mut upstream)
    }

    pub fn resolve_direct_server_host_via_system(
        &mut self,
        host: &str,
    ) -> Result<Option<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_direct_server_host_with_upstream(host, &mut upstream)
    }

    pub fn resolve_direct_server_host_addrs_via_system(
        &mut self,
        host: &str,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.resolve_direct_server_host_addrs_with_upstream(host, &mut upstream)
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

    /// Preserve remote records, TTLs, flags and DNS errors for listener/API queries.
    pub fn exchange_query_packet(
        &mut self,
        packet: &[u8],
        upstream: &mut impl DnsUpstream,
    ) -> Result<Vec<u8>, DnsError> {
        let query = crate::packet::parse_dns_query_packet(packet)?;
        let fallback_only = self.should_only_query_fallback(&query.host);
        let servers = if fallback_only {
            self.config.fallback.clone()
        } else {
            self.select_query_relay_nameservers(&query.host)
        };
        let response = upstream.exchange(&servers, packet);
        let fallback = !self.config.fallback.is_empty() && !fallback_only;
        let response = match response {
            Ok(response) => {
                let ips = crate::packet::parse_dns_response(
                    &response,
                    query.request_id,
                    query.query_type,
                )?;
                if fallback && ips.iter().any(|ip| self.should_ip_fallback(*ip)) {
                    upstream.exchange(&self.config.fallback, packet)?
                } else {
                    response
                }
            }
            Err(_) if fallback => upstream.exchange(&self.config.fallback, packet)?,
            Err(err) => return Err(err),
        };
        crate::packet::validate_dns_reply(packet, &response)?;
        let _ = self.observe_dns_response(packet, &response);
        Ok(response)
    }

    /// Answer hosts/fake-IP queries while holding the shared resolver lock.
    /// Network I/O is deliberately left to the caller after releasing it.
    pub fn local_query_packet(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
        let query = crate::packet::parse_dns_query_packet(packet)?;
        if query.query_type == DnsRecordType::Aaaa && !self.config.ipv6 {
            return Ok(Some(crate::packet::build_dns_response(&query, 60, &[])));
        }
        if !matches!(query.query_type, DnsRecordType::A | DnsRecordType::Aaaa) {
            return Ok(None);
        }
        let Some(answer) =
            self.lookup_local_answer_for_query_type(&query.host, Some(query.query_type))?
        else {
            return Ok(None);
        };
        let ips = answer
            .ips
            .into_iter()
            .filter(|ip| matches_query_type(*ip, query.query_type))
            .collect::<Vec<_>>();
        let response = crate::packet::build_dns_response(
            &query,
            response_ttl_secs(self, !ips.is_empty()),
            &ips,
        );
        let _ = self.observe_dns_response(packet, &response);
        Ok(Some(response))
    }

    pub fn merge_cache_from(&mut self, other: &Self) {
        if Arc::ptr_eq(&self.cache, &other.cache) {
            return;
        }
        for key in other.cache_order.iter() {
            if let Some(answer) = other.cache.get(key) {
                self.store_cached_answer(key.clone(), answer.clone());
            }
        }
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
        let query = crate::packet::parse_dns_query_packet(packet)?;
        let ips = match query.query_type {
            DnsRecordType::A | DnsRecordType::Aaaa => {
                match self.lookup_query_answer_for_query_type(
                    &query.host,
                    upstream,
                    query.query_type,
                    require_enabled,
                ) {
                    Ok(Some(answer)) => answer
                        .ips
                        .into_iter()
                        .filter(|ip| matches_query_type(*ip, query.query_type))
                        .collect::<Vec<_>>(),
                    Ok(None) | Err(DnsError::ResolveFailed(_)) => Vec::new(),
                    Err(err) => return Err(err),
                }
            }
            DnsRecordType::Other(_) => {
                // Preserve unknown/modern record types (HTTPS=65, SVCB=64,
                // TXT, PTR, …) as wire queries. Browsers and OpenClash send
                // HTTPS queries routinely; treating them as a protocol error
                // breaks the DNS listener even when A/AAAA resolution works.
                let servers = if self.should_only_query_fallback(&query.host) {
                    self.config.fallback.clone()
                } else {
                    self.select_query_relay_nameservers(&query.host)
                };
                let response = upstream.exchange(&servers, packet).or_else(|err| {
                    if self.config.fallback.is_empty() || servers == self.config.fallback {
                        Err(err)
                    } else {
                        upstream.exchange(&self.config.fallback, packet)
                    }
                })?;
                let _ = self.observe_dns_response(packet, &response);
                return Ok(Some(response));
            }
        };

        let response = crate::packet::build_dns_response(
            &query,
            response_ttl_secs(self, !ips.is_empty()),
            &ips,
        );
        let _ = self.observe_dns_response(packet, &response);
        Ok(Some(response))
    }

    fn lookup_query_answer_for_query_type(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
        query_type: DnsRecordType,
        require_enabled: bool,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if let Some(answer) = self.lookup_local_answer_for_query_type(host, Some(query_type))? {
            return Ok(Some(answer));
        }

        let key = normalize(host);
        if let Some(cached) = self.cache.get(&key) {
            let ips: Vec<_> = cached.ips.iter().copied()
                .filter(|ip| matches_query_type(*ip, query_type)).collect();
            if !ips.is_empty() {
                return Ok(Some(ResolveAnswer {
                    ips, servers: cached.servers.clone(), source: ResolveSource::Cache,
                }));
            }
        }

        if self.should_only_query_fallback(host) {
            if let Some(answer) = query_upstream(upstream, &self.config.fallback, host, Some(query_type))? {
                cache_answer(self, key, &answer);
                return Ok(Some(ResolveAnswer {
                    source: ResolveSource::Fallback,
                    ..answer
                }));
            }
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        let primary_servers = if require_enabled {
            self.select_query_relay_nameservers(host)
        } else {
            self.select_query_relay_nameservers(host)
        };
        self.lookup_answer_using_servers(host, upstream, &primary_servers, true, Some(query_type))
    }

    pub fn handle_query_packet_via_system(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.handle_query_packet(packet, &mut upstream)
    }

    pub fn relay_query_packet_via_system(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>, DnsError> {
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        self.relay_query_packet(packet, &mut upstream)
    }

    pub fn resolve_nameserver_host(&mut self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Some(answer) = self.lookup_local_real_answer(host)? {
            return Ok(answer.ips);
        }
        let servers = if self.config.default_nameserver.is_empty() {
            vec!["system://".to_owned()]
        } else {
            self.config.default_nameserver.clone()
        };
        let mut upstream = NetworkDnsUpstream::new(SystemDnsPacketTransport);
        let ips = match self.address_query_type() {
            Some(kind) => upstream.resolve_for_type(&servers, host, kind)?,
            None => upstream.resolve(&servers, host)?,
        };
        if ips.is_empty() {
            return Err(DnsError::ResolveFailed(host.into()));
        }
        Ok(ips)
    }

    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<&str> {
        self.fake_ip_pool.reverse(ip).or_else(|| {
            self.fake_ip_pool6
                .as_ref()
                .and_then(|pool| pool.reverse(ip))
        })
    }

    pub fn is_fake_ip_addr(&self, ip: IpAddr) -> bool {
        self.config.enhanced_mode == EnhancedMode::FakeIp && (self.fake_ip_pool.contains(ip)
            || self
                .fake_ip_pool6
                .as_ref()
                .is_some_and(|pool| pool.contains(ip)))
    }

    pub fn clone_fake_ip_state_from(&mut self, other: &Self) {
        self.domain_mappings = other.domain_mappings.clone();
        self.fake_ip_pool.clone_state_from(&other.fake_ip_pool);
        match (&mut self.fake_ip_pool6, &other.fake_ip_pool6) {
            (Some(current), Some(previous)) => current.clone_state_from(previous),
            _ => {}
        }
        self.persist_fake_ip_state();
    }

    pub fn without_fake_ip_persistence(mut self) -> Self {
        self.fake_ip_state_path = None;
        self
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
            .unwrap_or_else(|| {
                if self.config.nameserver.is_empty() {
                    vec!["system://".to_owned()]
                } else {
                    self.config.nameserver.clone()
                }
            })
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

    fn select_query_relay_nameservers(&self, host: &str) -> Vec<String> {
        if !self.config.proxy_server_nameserver.is_empty() && self.config.nameserver.is_empty() {
            return self.select_proxy_server_nameservers(host);
        }
        self.select_nameservers(host)
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

    pub(crate) fn store_cached_answer(&mut self, key: String, answer: CachedAnswer) {
        if self.cache.contains_key(&key) {
            Arc::make_mut(&mut self.cache).insert(key, answer);
            return;
        }
        while self.cache.len() >= self.config.cache_size {
            let Some(oldest) = Arc::make_mut(&mut self.cache_order).pop_front() else {
                break;
            };
            Arc::make_mut(&mut self.cache).remove(&oldest);
        }
        Arc::make_mut(&mut self.cache_order).push_back(key.clone());
        Arc::make_mut(&mut self.cache).insert(key, answer);
    }

    pub fn cached_answer(&self, host: &str) -> Option<&CachedAnswer> {
        self.cache.get(&normalize(host))
    }

    pub fn clear_cache(&mut self) {
        self.domain_mappings.clear();
        self.cache = Arc::new(std::collections::HashMap::new());
        self.cache_order = Arc::new(std::collections::VecDeque::new());
    }

    pub fn flush_fake_ip(&mut self) {
        self.fake_ip_pool.clear();
        if let Some(pool) = &mut self.fake_ip_pool6 {
            pool.clear();
        }
        self.persist_fake_ip_state();
    }

    fn resolve_metadata_inner(
        &mut self,
        metadata: &mut Metadata,
        mut upstream: Option<&mut impl DnsUpstream>,
    ) -> Result<(), DnsError> {
        if metadata.host.is_none() && metadata.dst_ip.is_some() {
            if let Some(host) = metadata.dst_ip.and_then(|ip| self.domain_for_ip(ip)) {
                metadata.host = Some(host);
                metadata.dns_mode = if metadata.dst_ip.is_some_and(|ip|self.is_fake_ip_addr(ip)){DnsMode::FakeIp}else{DnsMode::Mapping};
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

        // Fake-ip mode with rule-based filtering allocates locally, so the
        // answer must be produced even when no upstream is available (the
        // bootstrap path resolves through a freshly built runtime).
        if self.config.enhanced_mode == EnhancedMode::FakeIp
            && self.should_use_fake_ip(&host)
            && upstream.is_none()
        {
            if let Ok(Some(answer)) = self.lookup_local_answer_for_query_type(&host, None) {
                if let Some(ip) = answer.ips.first().copied() {
                    metadata.dst_ip = Some(ip);
                    metadata.dns_mode = match answer.source {
                        ResolveSource::FakeIp => DnsMode::FakeIp,
                        ResolveSource::Hosts => DnsMode::Hosts,
                        _ => DnsMode::Normal,
                    };
                    return Ok(());
                }
            }
        }

        let answer = if let Some(upstream) = upstream.as_deref_mut() {
            self.lookup_real_answer(&host, upstream)?
        } else {
            self.lookup_local_real_answer(&host)?
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
            _ if self.is_fake_ip_addr(ip) => DnsMode::FakeIp,
            _ => DnsMode::Normal,
        };
        Ok(())
    }

    fn address_query_type(&self) -> Option<DnsRecordType> {
        (!self.config.ipv6).then_some(DnsRecordType::A)
    }

    fn lookup_real_answer(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        self.lookup_real_answer_for_query_type(host, upstream, DnsRecordType::A)
    }

    fn lookup_real_answer_all(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if let Some(answer) = self.lookup_local_real_answer(host)? {
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
            if let Some(answer) = query_upstream(upstream, &self.config.fallback, host, self.address_query_type())? {
                cache_answer(self, key, &answer);
                return Ok(Some(ResolveAnswer {
                    source: ResolveSource::Fallback,
                    ..answer
                }));
            }
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        let primary_servers = self.select_nameservers(host);
        self.lookup_answer_using_servers(host, upstream, &primary_servers, true, self.address_query_type())
    }

    fn lookup_real_answer_for_query_type(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
        query_type: DnsRecordType,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if let Some(answer) =
            self.lookup_local_real_answer_for_query_type(host, Some(query_type))?
        {
            return Ok(Some(answer));
        }

        let key = normalize(host);
        if let Some(cached) = self.cache.get(&key) {
            let ips: Vec<_> = cached.ips.iter().copied()
                .filter(|ip| matches_query_type(*ip, query_type)).collect();
            if !ips.is_empty() {
                return Ok(Some(ResolveAnswer {
                    ips, servers: cached.servers.clone(), source: ResolveSource::Cache,
                }));
            }
        }

        if self.should_only_query_fallback(host) {
            if let Some(answer) = query_upstream(upstream, &self.config.fallback, host, Some(query_type))? {
                cache_answer(self, key, &answer);
                return Ok(Some(ResolveAnswer {
                    source: ResolveSource::Fallback,
                    ..answer
                }));
            }
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        let primary_servers = self.select_nameservers(host);
        self.lookup_answer_using_servers(host, upstream, &primary_servers, true, Some(query_type))
    }

    fn lookup_answer(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        self.lookup_answer_for_query_type(host, upstream, DnsRecordType::A)
    }

    fn lookup_answer_all(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if let Some(answer) = self.lookup_local_answer(host)? {
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
            if let Some(answer) = query_upstream(upstream, &self.config.fallback, host, self.address_query_type())? {
                cache_answer(self, key, &answer);
                return Ok(Some(ResolveAnswer {
                    source: ResolveSource::Fallback,
                    ..answer
                }));
            }
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        let primary_servers = self.select_nameservers(host);
        self.lookup_answer_using_servers(host, upstream, &primary_servers, true, self.address_query_type())
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
            let ips: Vec<_> = cached.ips.iter().copied()
                .filter(|ip| matches_query_type(*ip, query_type)).collect();
            if !ips.is_empty() {
                return Ok(Some(ResolveAnswer {
                    ips, servers: cached.servers.clone(), source: ResolveSource::Cache,
                }));
            }
        }

        if self.should_only_query_fallback(host) {
            if let Some(answer) = query_upstream(upstream, &self.config.fallback, host, Some(query_type))? {
                cache_answer(self, key, &answer);
                return Ok(Some(ResolveAnswer {
                    source: ResolveSource::Fallback,
                    ..answer
                }));
            }
            return Err(DnsError::ResolveFailed(host.to_owned()));
        }

        let primary_servers = self.select_nameservers(host);
        self.lookup_answer_using_servers(host, upstream, &primary_servers, true, Some(query_type))
    }

    fn lookup_answer_using_servers(
        &mut self,
        host: &str,
        upstream: &mut impl DnsUpstream,
        primary_servers: &[String],
        allow_fallback: bool,
        query_type: Option<DnsRecordType>,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        let key = normalize(host);
        let primary = query_upstream(upstream, &primary_servers, host, query_type);
        if let Ok(Some(answer)) = &primary {
            let should_fallback = !self.config.fallback.is_empty()
                && allow_fallback
                && answer.ips.iter().any(|ip| self.should_ip_fallback(*ip));
            if !should_fallback {
                cache_answer(self, key, answer);
                return Ok(Some(answer.clone()));
            }
        }

        if self.config.fallback.is_empty() || !allow_fallback {
            return primary.and_then(|_| Err(DnsError::ResolveFailed(host.to_owned())));
        }

        if let Some(answer) = query_upstream(upstream, &self.config.fallback, host, query_type)? {
            cache_answer(self, key, &answer);
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

    fn lookup_local_real_answer(&self, host: &str) -> Result<Option<ResolveAnswer>, DnsError> {
        self.lookup_local_real_answer_for_query_type(host, None)
    }

    fn lookup_local_answer_for_query_type(
        &mut self,
        host: &str,
        query_type: Option<DnsRecordType>,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if self.config.use_hosts || self.config.use_system_hosts {
            let ips = self.resolve_host_addrs_from_hosts(host)?;
            let ips = match query_type {
                Some(query_type) => ips
                    .into_iter()
                    .filter(|ip| matches_query_type(*ip, query_type))
                    .collect::<Vec<_>>(),
                None => ips,
            };
            if !ips.is_empty() {
                return Ok(Some(ResolveAnswer {
                    ips,
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
                self.persist_fake_ip_state();
                return Ok(Some(ResolveAnswer {
                    ips,
                    servers: Vec::new(),
                    source: ResolveSource::FakeIp,
                }));
            }
        }
        Ok(None)
    }

    fn lookup_local_real_answer_for_query_type(
        &self,
        host: &str,
        query_type: Option<DnsRecordType>,
    ) -> Result<Option<ResolveAnswer>, DnsError> {
        if self.config.use_hosts || self.config.use_system_hosts {
            let ips = self.resolve_host_addrs_from_hosts(host)?;
            let ips = match query_type {
                Some(query_type) => ips
                    .into_iter()
                    .filter(|ip| matches_query_type(*ip, query_type))
                    .collect::<Vec<_>>(),
                None => ips,
            };
            if !ips.is_empty() {
                return Ok(Some(ResolveAnswer {
                    ips,
                    servers: Vec::new(),
                    source: ResolveSource::Hosts,
                }));
            }
        }
        Ok(None)
    }

    fn resolve_host_from_hosts(&self, host: &str) -> Result<Option<IpAddr>, DnsError> {
        Ok(self.resolve_host_addrs_from_hosts(host)?.into_iter().next())
    }

    fn resolve_host_addrs_from_hosts(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.resolve_host_addrs_with_depth(host, 0)
    }

    fn resolve_host_addrs_with_depth(
        &self,
        host: &str,
        depth: usize,
    ) -> Result<Vec<IpAddr>, DnsError> {
        if depth > 8 {
            return Err(DnsError::InvalidAliasLoop(host.to_owned()));
        }
        let Some(entry) = self.matching_host_entry(host) else {
            return Ok(Vec::new());
        };

        let mut ips = entry
            .values
            .iter()
            .filter_map(|value| value.parse::<IpAddr>().ok())
            .collect::<Vec<_>>();
        if !ips.is_empty() {
            ips.dedup();
            return Ok(ips);
        }

        let Some(first_alias) = entry.values.first() else {
            return Ok(Vec::new());
        };
        self.resolve_host_addrs_with_depth(first_alias, depth + 1)
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

    fn restore_fake_ip_state(&mut self) {
        let Some(path) = self.fake_ip_state_path.as_ref() else {
            return;
        };
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let Ok(state) = serde_json::from_slice::<PersistedFakeIpState>(&bytes) else {
            return;
        };
        self.fake_ip_pool.restore_state(&state.ipv4);
        if let (Some(pool), Some(ipv6)) = (&mut self.fake_ip_pool6, state.ipv6.as_ref()) {
            pool.restore_state(ipv6);
        }
    }

    fn persist_fake_ip_state(&self) {
        let Some(path) = self.fake_ip_state_path.as_ref() else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        let _ = fs::create_dir_all(parent);
        let state = PersistedFakeIpState {
            ipv4: self.fake_ip_pool.export_state(),
            ipv6: self.fake_ip_pool6.as_ref().map(|pool| pool.export_state()),
        };
        let Ok(bytes) = serde_json::to_vec(&state) else {
            return;
        };
        let temp_path = path.with_extension("tmp");
        if fs::write(&temp_path, bytes).is_ok() {
            let _ = fs::rename(&temp_path, path);
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct PersistedFakeIpState {
    ipv4: PersistedFakeIpPoolState,
    ipv6: Option<PersistedFakeIpPoolState>,
}

impl DnsRuntimeConfig {
    pub(crate) fn from_top_level(config: &TopLevelDnsConfig) -> Self {
        Self {
            enabled: config.enable,
            ipv6: config.extra.get("ipv6").and_then(|value| value.as_bool()).unwrap_or(false),
            cache_size: config
                .extra
                .get("cache-size")
                .and_then(|value| value.as_u64())
                .unwrap_or(4096)
                .clamp(1, 1048576) as usize,
            listen: config.listen.clone(),
            use_hosts: config.use_hosts,
            use_system_hosts: config.use_system_hosts,
            respect_rules: config.respect_rules,
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
