use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use mihomo_rules::RuleError;

use crate::matchers::{
    FakeIpFilterMatcher, FakeIpPool, FakeIpPool6, FallbackIpMatcher, HostEntry, NameserverPolicy,
    NameserverPolicyMatcher,
};

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
    pub(crate) hosts: Arc<Vec<HostEntry>>,
    pub(crate) fake_ip_matchers: Arc<Vec<FakeIpFilterMatcher>>,
    pub(crate) fake_ip_rules: mihomo_rules::RuleSet,
    pub(crate) fake_ip_pool: FakeIpPool,
    pub(crate) fake_ip_pool6: Option<FakeIpPool6>,
    pub(crate) nameserver_policies: Arc<Vec<NameserverPolicy>>,
    pub(crate) proxy_server_nameserver_policies: Arc<Vec<NameserverPolicy>>,
    pub(crate) fallback_domain_matchers: Arc<Vec<NameserverPolicyMatcher>>,
    pub(crate) fallback_ip_matchers: Arc<Vec<FallbackIpMatcher>>,
    pub(crate) cache: Arc<HashMap<String, CachedAnswer>>,
    pub(crate) cache_order: Arc<VecDeque<String>>,
    pub(crate) domain_mappings: crate::mapping::DomainMappings,
    pub(crate) fake_ip_state_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuntimeConfig {
    pub enabled: bool,
    pub cache_size: usize,
    pub listen: String,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub respect_rules: bool,
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

    /// For record types the address cache cannot materialize (HTTPS/SVCB,
    /// TXT, PTR, etc.), forward the original DNS wire query unchanged.
    fn exchange(&mut self, _servers: &[String], _packet: &[u8]) -> Result<Vec<u8>, DnsError> {
        Err(DnsError::DnsProtocol(
            "raw DNS query forwarding is unavailable".to_owned(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Other(u16),
}

impl DnsRecordType {
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Other(code) => code,
        }
    }
}

pub trait DnsPacketTransport {
    fn exchange(&mut self, server: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError>;
}

#[derive(Default)]
pub struct SystemDnsPacketTransport;

pub struct NetworkDnsUpstream<T> {
    pub(crate) transport: T,
    pub(crate) next_request_id: u16,
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
