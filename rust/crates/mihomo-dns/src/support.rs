use std::collections::BTreeMap;
use std::net::IpAddr;

use mihomo_config::{HostMappingValue, RuleProviderBehavior, RuntimeConfigDocument};
use mihomo_rules::{compile_rule_table_with_providers, parse_rule, RuleError, RuleType};

use crate::matchers::{
    FakeIpFilterMatcher, FallbackIpMatcher, HostEntry, HostPattern, IpCidrMatcher,
    NameserverPolicy, NameserverPolicyMatcher,
};
use crate::{
    CachedAnswer, DnsError, DnsRecordType, DnsRuntime, ResolveAnswer, ResolveSource,
};

pub(crate) fn validate_fake_ip_filter_rules(
    document: &RuntimeConfigDocument,
) -> Result<(), DnsError> {
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

pub(crate) fn is_domain_rule_type(rule_type: RuleType) -> bool {
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

pub(crate) fn compile_fake_ip_filter_matchers<S>(
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
        if let Some(name) = normalized.strip_prefix("geosite:") {
            let name = name.trim();
            let rule_set = compile_domain_rule_set_provider(
                document,
                name,
                "fake-ip-filter",
                file_contents,
                http_contents,
            )?;
            matchers.push(FakeIpFilterMatcher::RuleSet(rule_set));
            continue;
        }
        if let Some(name) = normalized.strip_prefix("rule-set:") {
            let name = name.trim();
            let rule_set = compile_domain_rule_set_provider(
                document,
                name,
                "fake-ip-filter",
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

pub(crate) fn compile_fallback_domain_matchers<S>(
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
        if let Some(name) = normalized.strip_prefix("geosite:") {
            let name = name.trim();
            let rule_set = compile_domain_rule_set_provider(
                document,
                name,
                "dns.fallback-filter.domain",
                file_contents,
                http_contents,
            )?;
            matchers.push(NameserverPolicyMatcher::RuleSet(rule_set));
            continue;
        }
        if let Some(name) = normalized.strip_prefix("rule-set:") {
            let name = name.trim();
            let rule_set = compile_domain_rule_set_provider(
                document,
                name,
                "dns.fallback-filter.domain",
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

pub(crate) fn compile_fallback_ip_matchers<S>(
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
        if let Some(code) = normalized.strip_prefix("geoip:") {
            let provider_name = geoip_rule_set_name(code);
            let rule_set = compile_ip_rule_set_provider(
                document,
                &provider_name,
                normalized,
                "dns.fallback-filter.ipcidr",
                file_contents,
                http_contents,
            )?;
            matchers.push(FallbackIpMatcher::RuleSet(rule_set));
            continue;
        }
        if let Some(name) = normalized.strip_prefix("rule-set:") {
            let name = name.trim();
            let rule_set = compile_ip_rule_set_provider(
                document,
                name,
                normalized,
                "dns.fallback-filter.ipcidr",
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

pub(crate) fn compile_hosts(
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

pub(crate) fn compile_nameserver_policies<S>(
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

pub(crate) fn compile_proxy_nameserver_policies<S>(
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

pub(crate) fn compile_nameserver_policy_matchers<S>(
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
    if let Some(rest) = normalized.strip_prefix("geosite:") {
        return rest
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| {
                let rule_set = compile_domain_rule_set_provider(
                    document,
                    name,
                    "dns.nameserver-policy",
                    file_contents,
                    http_contents,
                )?;
                Ok(NameserverPolicyMatcher::RuleSet(rule_set))
            })
            .collect();
    }
    if let Some(rest) = normalized.strip_prefix("rule-set:") {
        return rest
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| {
                let rule_set = compile_domain_rule_set_provider(
                    document,
                    name,
                    "dns.nameserver-policy",
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

pub(crate) fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn geoip_rule_set_name(code: &str) -> String {
    format!("{}_IP", code.trim().to_ascii_uppercase())
}

fn compile_domain_rule_set_provider<S>(
    document: &RuntimeConfigDocument,
    name: &str,
    target: &str,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<mihomo_rules::RuleSet, DnsError>
where
    S: AsRef<[u8]>,
{
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
    compile_rule_table_with_providers(
        &[format!("RULE-SET,{name},{target}")],
        &BTreeMap::new(),
        &document.rule_providers,
        file_contents,
        http_contents,
    )
    .map_err(DnsError::Rule)
}

fn compile_ip_rule_set_provider<S>(
    document: &RuntimeConfigDocument,
    name: &str,
    raw: &str,
    target: &str,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<mihomo_rules::RuleSet, DnsError>
where
    S: AsRef<[u8]>,
{
    let Some(provider) = document.rule_providers.get(name) else {
        return Err(DnsError::Rule(RuleError::RuleProviderNotFound(
            name.to_owned(),
        )));
    };
    if provider.behavior_kind() == Some(RuleProviderBehavior::Domain) {
        return Err(DnsError::Rule(RuleError::InvalidLogic(raw.to_owned())));
    }
    compile_rule_table_with_providers(
        &[format!("RULE-SET,{name},{target}")],
        &BTreeMap::new(),
        &document.rule_providers,
        file_contents,
        http_contents,
    )
    .map_err(DnsError::Rule)
}

pub(crate) fn append_system_hosts(entries: &mut Vec<HostEntry>, raw: &str) {
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

pub(crate) fn read_system_hosts_text() -> Option<String> {
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

pub(crate) fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

pub(crate) fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

pub(crate) fn matches_query_type(ip: IpAddr, query_type: DnsRecordType) -> bool {
    matches!(
        (ip, query_type),
        (IpAddr::V4(_), DnsRecordType::A) | (IpAddr::V6(_), DnsRecordType::Aaaa)
    )
}

pub(crate) fn response_ttl_secs(runtime: &DnsRuntime, has_answer: bool) -> u32 {
    if has_answer
        && runtime.config.enhanced_mode == crate::EnhancedMode::FakeIp
        && runtime.config.fake_ip_ttl > 0
    {
        runtime.config.fake_ip_ttl
    } else {
        60
    }
}

pub(crate) fn query_upstream(
    upstream: &mut impl crate::DnsUpstream,
    servers: &[String],
    host: &str,
    query_type: Option<DnsRecordType>,
) -> Result<Option<ResolveAnswer>, DnsError> {
    if servers.is_empty() {
        return Ok(None);
    }
    let ips = match query_type {
        Some(kind) => upstream.resolve_for_type(servers, host, kind)?,
        None => upstream.resolve(servers, host)?,
    };
    if ips.is_empty() {
        return Ok(None);
    }
    Ok(Some(ResolveAnswer {
        ips,
        servers: servers.to_vec(),
        source: ResolveSource::Nameserver,
    }))
}

#[derive(Default)]
pub(crate) struct NoopUpstream;

impl crate::DnsUpstream for NoopUpstream {
    fn resolve(&mut self, _servers: &[String], _host: &str) -> Result<Vec<IpAddr>, DnsError> {
        Ok(Vec::new())
    }
}

pub(crate) fn cache_answer(
    runtime: &mut DnsRuntime,
    key: String,
    answer: &ResolveAnswer,
) {
    runtime.store_cached_answer(
        key,
        CachedAnswer {
            ips: answer.ips.clone(),
            servers: answer.servers.clone(),
        },
    );
}
