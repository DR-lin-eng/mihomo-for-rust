use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use mihomo_core::{Metadata, NetworkKind};
use mihomo_rules::{RuleError, RuleSet};
use serde::{Deserialize, Serialize};

use crate::support::{normalize, prefix_mask_u128, prefix_mask_u32};
use crate::DnsError;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PersistedFakeIpEntry {
    pub(crate) host: String,
    pub(crate) ip: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PersistedFakeIpPoolState {
    pub(crate) offset_ip: Option<String>,
    pub(crate) cycle: bool,
    pub(crate) entries: Vec<PersistedFakeIpEntry>,
    pub(crate) lru: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostEntry {
    pub(crate) pattern: HostPattern,
    pub(crate) values: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NameserverPolicy {
    pub(crate) matchers: Vec<NameserverPolicyMatcher>,
    pub(crate) servers: Vec<String>,
}

impl NameserverPolicy {
    pub(crate) fn matches(&self, host: &str) -> bool {
        let normalized = normalize(host);
        let metadata = Metadata {
            host: Some(normalized.clone()),
            network: NetworkKind::Invalid,
            ..Metadata::default()
        };
        self.matchers
            .iter()
            .any(|matcher| matcher.matches(&normalized, &metadata))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NameserverPolicyMatcher {
    HostPattern(HostPattern),
    RuleSet(RuleSet),
}

impl NameserverPolicyMatcher {
    pub(crate) fn matches(&self, host: &str, metadata: &Metadata) -> bool {
        match self {
            Self::HostPattern(pattern) => pattern.matches(host),
            Self::RuleSet(rule_set) => rule_set.target_for(metadata).is_some(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FallbackIpMatcher {
    Cidr(IpCidrMatcher),
    RuleSet(RuleSet),
}

impl FallbackIpMatcher {
    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
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
pub(crate) struct IpCidrMatcher {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidrMatcher {
    pub(crate) fn parse(raw: &str) -> Result<Self, RuleError> {
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

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
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
pub(crate) enum FakeIpFilterMatcher {
    HostPattern(HostPattern),
    RuleSet(RuleSet),
}

impl FakeIpFilterMatcher {
    pub(crate) fn matches(&self, host: &str) -> bool {
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
pub(crate) enum HostPattern {
    Exact(String),
    Suffix(String),
    WildcardSuffix(String),
}

impl HostPattern {
    pub(crate) fn parse(raw: &str) -> Self {
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

    pub(crate) fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Suffix(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            Self::WildcardSuffix(suffix) => host.ends_with(&format!(".{suffix}")),
        }
    }

    pub(crate) fn priority(&self) -> usize {
        match self {
            Self::Exact(value) => value.len() + 10_000,
            Self::Suffix(value) => value.len() + 1_000,
            Self::WildcardSuffix(value) => value.len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FakeIpPool {
    network: u32,
    prefix_len: u8,
    gateway: u32,
    first: u32,
    last: u32,
    offset: u32,
    cycle: bool,
    capacity: usize,
    host_to_ip: Arc<HashMap<String, Ipv4Addr>>,
    ip_to_host: Arc<HashMap<Ipv4Addr, String>>,
    lru: Arc<VecDeque<String>>,
}

impl FakeIpPool {
    pub(crate) fn new(raw: &str) -> Result<Self, DnsError> {
        Self::with_capacity(raw, 1000)
    }

    pub(crate) fn with_capacity(raw: &str, capacity: usize) -> Result<Self, DnsError> {
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
        let mask = prefix_mask_u32(prefix);
        let network = u32::from(base_ip) & mask;
        let gateway = network.saturating_add(1);
        let first = network.saturating_add(4);
        let last = network | !mask;
        if first >= last {
            return Err(DnsError::InvalidFakeIpRange(raw.to_owned()));
        }
        Ok(Self {
            network,
            prefix_len: prefix,
            gateway,
            first,
            last,
            offset: first.saturating_sub(1),
            cycle: false,
            capacity: capacity.max(1),
            host_to_ip: Arc::new(HashMap::new()),
            ip_to_host: Arc::new(HashMap::new()),
            lru: Arc::new(VecDeque::new()),
        })
    }

    pub(crate) fn assign(&mut self, host: &str) -> Result<IpAddr, DnsError> {
        let host = normalize(host);
        if let Some(ip) = self.host_to_ip.get(&host).copied() {
            self.touch(&host);
            return Ok(IpAddr::V4(ip));
        }
        let next = self.offset.saturating_add(1);
        let ip_raw = if next >= self.last {
            self.cycle = true;
            self.first
        } else {
            next
        };
        self.offset = ip_raw;
        let ip = Ipv4Addr::from(ip_raw);
        if self.cycle || self.ip_to_host.contains_key(&ip) {
            self.remove_by_ip(ip);
        }
        Arc::make_mut(&mut self.host_to_ip).insert(host.clone(), ip);
        Arc::make_mut(&mut self.ip_to_host).insert(ip, host.clone());
        self.touch(&host);
        self.evict_if_needed();
        Ok(IpAddr::V4(ip))
    }

    pub(crate) fn reverse(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(ip) => self.ip_to_host.get(&ip).map(String::as_str),
            IpAddr::V6(_) => None,
        }
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.contains_ipv4(ip),
            IpAddr::V6(_) => false,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.offset = self.first.saturating_sub(1);
        self.cycle = false;
        self.host_to_ip = Arc::new(HashMap::new());
        self.ip_to_host = Arc::new(HashMap::new());
        self.lru = Arc::new(VecDeque::new());
    }

    pub(crate) fn clone_state_from(&mut self, other: &Self) {
        if self.network != other.network || self.prefix_len != other.prefix_len {
            return;
        }
        self.offset = other.offset;
        self.cycle = other.cycle;
        self.host_to_ip = other.host_to_ip.clone();
        self.ip_to_host = other.ip_to_host.clone();
        self.lru = other.lru.clone();
    }

    pub(crate) fn export_state(&self) -> PersistedFakeIpPoolState {
        let mut entries = self
            .host_to_ip
            .iter()
            .map(|(host, ip)| PersistedFakeIpEntry {
                host: host.clone(),
                ip: ip.to_string(),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.host.cmp(&right.host));
        PersistedFakeIpPoolState {
            offset_ip: Some(Ipv4Addr::from(self.offset).to_string()),
            cycle: self.cycle,
            entries,
            lru: self.lru.iter().cloned().collect(),
        }
    }

    pub(crate) fn restore_state(&mut self, state: &PersistedFakeIpPoolState) {
        self.clear();
        self.cycle = state.cycle;
        if let Some(offset) = state
            .offset_ip
            .as_deref()
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
            .filter(|value| self.contains_ipv4(*value))
        {
            self.offset = u32::from(offset);
        }
        for entry in &state.entries {
            let host = normalize(&entry.host);
            let Some(ip) = entry.ip.parse::<Ipv4Addr>().ok() else {
                continue;
            };
            if !self.contains_ipv4(ip) {
                continue;
            }
            Arc::make_mut(&mut self.host_to_ip).insert(host.clone(), ip);
            Arc::make_mut(&mut self.ip_to_host).insert(ip, host);
        }
        self.lru = Arc::new(
            state
                .lru
                .iter()
                .map(|host| normalize(host))
                .filter(|host| self.host_to_ip.contains_key(host))
                .fold(VecDeque::new(), |mut acc, host| {
                    if !acc.iter().any(|value| value == &host) {
                        acc.push_back(host);
                    }
                    acc
                }),
        );
        for host in self.host_to_ip.keys() {
            if !self.lru.iter().any(|value| value == host) {
                Arc::make_mut(&mut self.lru).push_back(host.clone());
            }
        }
    }

    fn contains_ipv4(&self, ip: Ipv4Addr) -> bool {
        let raw = u32::from(ip);
        let mask = prefix_mask_u32(self.prefix_len);
        (raw & mask) == self.network && raw != self.gateway && raw != self.last
    }

    fn remove_by_ip(&mut self, ip: Ipv4Addr) {
        if let Some(host) = Arc::make_mut(&mut self.ip_to_host).remove(&ip) {
            Arc::make_mut(&mut self.host_to_ip).remove(&host);
            self.remove_from_lru(&host);
        }
    }

    fn remove_from_lru(&mut self, host: &str) {
        if let Some(index) = self.lru.iter().position(|value| value == host) {
            Arc::make_mut(&mut self.lru).remove(index);
        }
    }

    fn touch(&mut self, host: &str) {
        self.remove_from_lru(host);
        Arc::make_mut(&mut self.lru).push_back(host.to_owned());
    }

    fn evict_if_needed(&mut self) {
        while self.host_to_ip.len() > self.capacity {
            let Some(host) = Arc::make_mut(&mut self.lru).pop_front() else {
                break;
            };
            if let Some(ip) = Arc::make_mut(&mut self.host_to_ip).remove(&host) {
                Arc::make_mut(&mut self.ip_to_host).remove(&ip);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FakeIpPool6 {
    network: u128,
    prefix_len: u8,
    gateway: u128,
    first: u128,
    last: u128,
    offset: u128,
    cycle: bool,
    capacity: usize,
    host_to_ip: Arc<HashMap<String, Ipv6Addr>>,
    ip_to_host: Arc<HashMap<Ipv6Addr, String>>,
    lru: Arc<VecDeque<String>>,
}

impl FakeIpPool6 {
    pub(crate) fn new(raw: &str) -> Result<Self, DnsError> {
        Self::with_capacity(raw, 1000)
    }

    pub(crate) fn with_capacity(raw: &str, capacity: usize) -> Result<Self, DnsError> {
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
        let mask = prefix_mask_u128(prefix);
        let network = u128::from(base_ip) & mask;
        let gateway = network.saturating_add(1);
        let first = network.saturating_add(4);
        let last = network | !mask;
        if first >= last {
            return Err(DnsError::InvalidFakeIpRange(raw.to_owned()));
        }
        Ok(Self {
            network,
            prefix_len: prefix,
            gateway,
            first,
            last,
            offset: first.saturating_sub(1),
            cycle: false,
            capacity: capacity.max(1),
            host_to_ip: Arc::new(HashMap::new()),
            ip_to_host: Arc::new(HashMap::new()),
            lru: Arc::new(VecDeque::new()),
        })
    }

    pub(crate) fn assign(&mut self, host: &str) -> Result<IpAddr, DnsError> {
        let host = normalize(host);
        if let Some(ip) = self.host_to_ip.get(&host).copied() {
            self.touch(&host);
            return Ok(IpAddr::V6(ip));
        }
        let next = self.offset.saturating_add(1);
        let ip_raw = if next >= self.last {
            self.cycle = true;
            self.first
        } else {
            next
        };
        self.offset = ip_raw;
        let ip = Ipv6Addr::from(ip_raw);
        if self.cycle || self.ip_to_host.contains_key(&ip) {
            self.remove_by_ip(ip);
        }
        Arc::make_mut(&mut self.host_to_ip).insert(host.clone(), ip);
        Arc::make_mut(&mut self.ip_to_host).insert(ip, host.clone());
        self.touch(&host);
        self.evict_if_needed();
        Ok(IpAddr::V6(ip))
    }

    pub(crate) fn reverse(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V6(ip) => self.ip_to_host.get(&ip).map(String::as_str),
            IpAddr::V4(_) => None,
        }
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V6(ip) => self.contains_ipv6(ip),
            IpAddr::V4(_) => false,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.offset = self.first.saturating_sub(1);
        self.cycle = false;
        self.host_to_ip = Arc::new(HashMap::new());
        self.ip_to_host = Arc::new(HashMap::new());
        self.lru = Arc::new(VecDeque::new());
    }

    pub(crate) fn clone_state_from(&mut self, other: &Self) {
        if self.network != other.network || self.prefix_len != other.prefix_len {
            return;
        }
        self.offset = other.offset;
        self.cycle = other.cycle;
        self.host_to_ip = other.host_to_ip.clone();
        self.ip_to_host = other.ip_to_host.clone();
        self.lru = other.lru.clone();
    }

    pub(crate) fn export_state(&self) -> PersistedFakeIpPoolState {
        let mut entries = self
            .host_to_ip
            .iter()
            .map(|(host, ip)| PersistedFakeIpEntry {
                host: host.clone(),
                ip: ip.to_string(),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.host.cmp(&right.host));
        PersistedFakeIpPoolState {
            offset_ip: Some(Ipv6Addr::from(self.offset).to_string()),
            cycle: self.cycle,
            entries,
            lru: self.lru.iter().cloned().collect(),
        }
    }

    pub(crate) fn restore_state(&mut self, state: &PersistedFakeIpPoolState) {
        self.clear();
        self.cycle = state.cycle;
        if let Some(offset) = state
            .offset_ip
            .as_deref()
            .and_then(|value| value.parse::<Ipv6Addr>().ok())
            .filter(|value| self.contains_ipv6(*value))
        {
            self.offset = u128::from(offset);
        }
        for entry in &state.entries {
            let host = normalize(&entry.host);
            let Some(ip) = entry.ip.parse::<Ipv6Addr>().ok() else {
                continue;
            };
            if !self.contains_ipv6(ip) {
                continue;
            }
            Arc::make_mut(&mut self.host_to_ip).insert(host.clone(), ip);
            Arc::make_mut(&mut self.ip_to_host).insert(ip, host);
        }
        self.lru = Arc::new(
            state
                .lru
                .iter()
                .map(|host| normalize(host))
                .filter(|host| self.host_to_ip.contains_key(host))
                .fold(VecDeque::new(), |mut acc, host| {
                    if !acc.iter().any(|value| value == &host) {
                        acc.push_back(host);
                    }
                    acc
                }),
        );
        for host in self.host_to_ip.keys() {
            if !self.lru.iter().any(|value| value == host) {
                Arc::make_mut(&mut self.lru).push_back(host.clone());
            }
        }
    }

    fn contains_ipv6(&self, ip: Ipv6Addr) -> bool {
        let raw = u128::from(ip);
        let mask = prefix_mask_u128(self.prefix_len);
        (raw & mask) == self.network && raw != self.gateway && raw != self.last
    }

    fn remove_by_ip(&mut self, ip: Ipv6Addr) {
        if let Some(host) = Arc::make_mut(&mut self.ip_to_host).remove(&ip) {
            Arc::make_mut(&mut self.host_to_ip).remove(&host);
            self.remove_from_lru(&host);
        }
    }

    fn remove_from_lru(&mut self, host: &str) {
        if let Some(index) = self.lru.iter().position(|value| value == host) {
            Arc::make_mut(&mut self.lru).remove(index);
        }
    }

    fn touch(&mut self, host: &str) {
        self.remove_from_lru(host);
        Arc::make_mut(&mut self.lru).push_back(host.to_owned());
    }

    fn evict_if_needed(&mut self) {
        while self.host_to_ip.len() > self.capacity {
            let Some(host) = Arc::make_mut(&mut self.lru).pop_front() else {
                break;
            };
            if let Some(ip) = Arc::make_mut(&mut self.host_to_ip).remove(&host) {
                Arc::make_mut(&mut self.ip_to_host).remove(&ip);
            }
        }
    }
}
