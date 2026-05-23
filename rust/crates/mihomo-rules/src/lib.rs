use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_config::{
    RuleProviderBehavior, RuleProviderDefinition, RuleProviderFormat, RuleProviderVehicleType,
};
use mihomo_core::{Metadata, NetworkKind, RewriteStage, SessionKind, SubsystemManifest};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    DomainWildcard,
    IpCidr,
    SrcIpCidr,
    SrcPort,
    DstPort,
    InPort,
    Dscp,
    ProcessName,
    ProcessPath,
    ProcessNameRegex,
    ProcessPathRegex,
    ProcessNameWildcard,
    ProcessPathWildcard,
    Uid,
    InType,
    InUser,
    InName,
    Network,
    RuleSet,
    SubRule,
    And,
    Or,
    Not,
    Match,
}

impl RuleType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "DOMAIN",
            Self::DomainSuffix => "DOMAIN-SUFFIX",
            Self::DomainKeyword => "DOMAIN-KEYWORD",
            Self::DomainRegex => "DOMAIN-REGEX",
            Self::DomainWildcard => "DOMAIN-WILDCARD",
            Self::IpCidr => "IP-CIDR",
            Self::SrcIpCidr => "SRC-IP-CIDR",
            Self::SrcPort => "SRC-PORT",
            Self::DstPort => "DST-PORT",
            Self::InPort => "IN-PORT",
            Self::Dscp => "DSCP",
            Self::ProcessName => "PROCESS-NAME",
            Self::ProcessPath => "PROCESS-PATH",
            Self::ProcessNameRegex => "PROCESS-NAME-REGEX",
            Self::ProcessPathRegex => "PROCESS-PATH-REGEX",
            Self::ProcessNameWildcard => "PROCESS-NAME-WILDCARD",
            Self::ProcessPathWildcard => "PROCESS-PATH-WILDCARD",
            Self::Uid => "UID",
            Self::InType => "IN-TYPE",
            Self::InUser => "IN-USER",
            Self::InName => "IN-NAME",
            Self::Network => "NETWORK",
            Self::RuleSet => "RULE-SET",
            Self::SubRule => "SUB-RULE",
            Self::And => "AND",
            Self::Or => "OR",
            Self::Not => "NOT",
            Self::Match => "MATCH",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleDefinition {
    pub rule_type: RuleType,
    pub payload: String,
    pub target: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuleRuntimeExtraSnapshot {
    pub disabled: bool,
    pub hit_count: u64,
    pub hit_at_unix_ms: u64,
    pub miss_count: u64,
    pub miss_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRuleSnapshot {
    pub index: usize,
    pub definition: RuleDefinition,
    pub extra: RuleRuntimeExtraSnapshot,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    sub_rules: BTreeMap<String, Vec<CompiledRule>>,
}

impl RuleSet {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.sub_rules.values().all(Vec::is_empty)
    }

    pub fn len(&self) -> usize {
        self.rules.len() + self.sub_rules.values().map(Vec::len).sum::<usize>()
    }

    pub fn target_for<'a>(&'a self, metadata: &Metadata) -> Option<&'a str> {
        let selected = self
            .sub_rules
            .get(metadata.special_rules.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&self.rules);
        self.matching_rule_in(selected, metadata, false)
            .map(|matched| matched.target)
    }

    pub fn matched_rule_definition(&self, metadata: &Metadata) -> Option<RuleDefinition> {
        let selected = self
            .sub_rules
            .get(metadata.special_rules.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&self.rules);
        self.matching_rule_in(selected, metadata, false)
            .map(|matched| matched.to_definition())
    }

    pub fn matched_rule_definition_and_record(&self, metadata: &Metadata) -> Option<RuleDefinition> {
        let selected = self
            .sub_rules
            .get(metadata.special_rules.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&self.rules);
        self.matching_rule_in(selected, metadata, true)
            .map(|matched| matched.to_definition())
    }

    pub fn runtime_snapshots(&self) -> Vec<RuntimeRuleSnapshot> {
        self.rules
            .iter()
            .enumerate()
            .map(|(index, rule)| RuntimeRuleSnapshot {
                index,
                definition: rule.definition(),
                extra: rule.runtime.snapshot(),
            })
            .collect()
    }

    pub fn set_rule_disabled(&self, index: usize, disabled: bool) -> bool {
        let Some(rule) = self.rules.get(index) else {
            return false;
        };
        rule.runtime.disabled.store(disabled, Ordering::Relaxed);
        true
    }

    pub fn runtime_rule_count(&self) -> usize {
        self.rules.len()
    }

    fn matching_rule_in<'a>(
        &'a self,
        rules: &'a [CompiledRule],
        metadata: &Metadata,
        record: bool,
    ) -> Option<RuleMatchRef<'a>> {
        for rule in rules {
            let Some(matched) = self.matching_rule(rule, metadata, record) else {
                continue;
            };
            match matched {
                RuleMatch::Target(target) => return Some(target),
                RuleMatch::SubRule(name) => {
                    if let Some(nested) = self.sub_rules.get(name) {
                        if let Some(matched) = self.matching_rule_in(nested, metadata, record) {
                            return Some(matched);
                        }
                    }
                }
            }
        }
        None
    }

    fn matching_rule<'a>(
        &'a self,
        rule: &'a CompiledRule,
        metadata: &Metadata,
        record: bool,
    ) -> Option<RuleMatch<'a>> {
        if rule.runtime.disabled.load(Ordering::Relaxed) {
            return None;
        }
        let matched = rule.matcher.matches(metadata);
        let outcome = if matched {
            match &rule.action {
                RuleAction::Target(target) => Some(RuleMatch::Target(RuleMatchRef {
                    rule_type: rule.rule_type,
                    payload: &rule.payload,
                    target,
                })),
                RuleAction::SubRule(name) => Some(RuleMatch::SubRule(name)),
            }
        } else {
            None
        };
        if record {
            if outcome.is_some() {
                rule.runtime.record_hit();
            } else {
                rule.runtime.record_miss();
            }
        }
        outcome
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleError {
    MissingType(String),
    MissingPayload(String),
    MissingTarget(String),
    UnsupportedRuleType(String),
    InvalidCidr(String),
    InvalidPort(String),
    InvalidDscp(String),
    InvalidUid(String),
    InvalidInType(String),
    InvalidInUser(String),
    InvalidInName(String),
    InvalidNetwork(String),
    InvalidRegex(String),
    InvalidLogic(String),
    RuleProviderNotFound(String),
    UnsupportedRuleProviderVehicle(String),
    UnsupportedRuleProviderBehavior(String),
    UnsupportedRuleProviderFormat(String),
    InvalidRuleProviderContent(String),
    EmptySubRuleName,
    SubRuleNotFound(String),
    CircularSubRule(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingType(raw) => write!(f, "missing rule type: {raw}"),
            Self::MissingPayload(raw) => write!(f, "missing rule payload: {raw}"),
            Self::MissingTarget(raw) => write!(f, "missing rule target: {raw}"),
            Self::UnsupportedRuleType(raw) => write!(f, "unsupported rule type: {raw}"),
            Self::InvalidCidr(raw) => write!(f, "invalid cidr: {raw}"),
            Self::InvalidPort(raw) => write!(f, "invalid port rule payload: {raw}"),
            Self::InvalidDscp(raw) => write!(f, "invalid dscp rule payload: {raw}"),
            Self::InvalidUid(raw) => write!(f, "invalid uid rule payload: {raw}"),
            Self::InvalidInType(raw) => write!(f, "invalid in-type rule payload: {raw}"),
            Self::InvalidInUser(raw) => write!(f, "invalid in-user rule payload: {raw}"),
            Self::InvalidInName(raw) => write!(f, "invalid in-name rule payload: {raw}"),
            Self::InvalidNetwork(raw) => write!(f, "invalid network: {raw}"),
            Self::InvalidRegex(raw) => write!(f, "invalid regex rule payload: {raw}"),
            Self::InvalidLogic(raw) => write!(f, "invalid logic rule payload: {raw}"),
            Self::RuleProviderNotFound(raw) => write!(f, "rule provider not found: {raw}"),
            Self::UnsupportedRuleProviderVehicle(raw) => {
                write!(f, "unsupported rule provider vehicle type: {raw}")
            }
            Self::UnsupportedRuleProviderBehavior(raw) => {
                write!(f, "unsupported rule provider behavior type: {raw}")
            }
            Self::UnsupportedRuleProviderFormat(raw) => {
                write!(f, "unsupported rule provider format type: {raw}")
            }
            Self::InvalidRuleProviderContent(raw) => {
                write!(f, "invalid rule provider content: {raw}")
            }
            Self::EmptySubRuleName => write!(f, "sub-rule name is empty"),
            Self::SubRuleNotFound(raw) => write!(f, "sub-rule not found: {raw}"),
            Self::CircularSubRule(raw) => write!(f, "circular sub-rule references: {raw}"),
        }
    }
}

impl std::error::Error for RuleError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledRule {
    rule_type: RuleType,
    payload: String,
    action: RuleAction,
    matcher: RuleMatcher,
    runtime: Arc<CompiledRuleRuntime>,
}

impl CompiledRule {
    fn definition(&self) -> RuleDefinition {
        RuleDefinition {
            rule_type: self.rule_type,
            payload: self.payload.clone(),
            target: match &self.action {
                RuleAction::Target(target) | RuleAction::SubRule(target) => target.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuleAction {
    Target(String),
    SubRule(String),
}

#[derive(Debug, Default)]
struct CompiledRuleRuntime {
    disabled: AtomicBool,
    hit_count: AtomicU64,
    hit_at_unix_ms: AtomicU64,
    miss_count: AtomicU64,
    miss_at_unix_ms: AtomicU64,
}

impl CompiledRuleRuntime {
    fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        self.hit_at_unix_ms.store(now_unix_ms(), Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.miss_count.fetch_add(1, Ordering::Relaxed);
        self.miss_at_unix_ms.store(now_unix_ms(), Ordering::Relaxed);
    }

    fn snapshot(&self) -> RuleRuntimeExtraSnapshot {
        RuleRuntimeExtraSnapshot {
            disabled: self.disabled.load(Ordering::Relaxed),
            hit_count: self.hit_count.load(Ordering::Relaxed),
            hit_at_unix_ms: self.hit_at_unix_ms.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            miss_at_unix_ms: self.miss_at_unix_ms.load(Ordering::Relaxed),
        }
    }
}

impl Clone for CompiledRuleRuntime {
    fn clone(&self) -> Self {
        let snapshot = self.snapshot();
        Self {
            disabled: AtomicBool::new(snapshot.disabled),
            hit_count: AtomicU64::new(snapshot.hit_count),
            hit_at_unix_ms: AtomicU64::new(snapshot.hit_at_unix_ms),
            miss_count: AtomicU64::new(snapshot.miss_count),
            miss_at_unix_ms: AtomicU64::new(snapshot.miss_at_unix_ms),
        }
    }
}

impl PartialEq for CompiledRuleRuntime {
    fn eq(&self, other: &Self) -> bool {
        self.snapshot() == other.snapshot()
    }
}

impl Eq for CompiledRuleRuntime {}

enum RuleMatch<'a> {
    Target(RuleMatchRef<'a>),
    SubRule(&'a str),
}

struct RuleMatchRef<'a> {
    rule_type: RuleType,
    payload: &'a str,
    target: &'a str,
}

impl RuleMatchRef<'_> {
    fn to_definition(&self) -> RuleDefinition {
        RuleDefinition {
            rule_type: self.rule_type,
            payload: self.payload.to_owned(),
            target: self.target.to_owned(),
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Debug)]
enum RuleMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    DomainWildcard(String),
    IpCidr(Cidr),
    SrcIpCidr(Cidr),
    SrcPort(NumericRanges),
    DstPort(NumericRanges),
    InPort(NumericRanges),
    Dscp(NumericRanges),
    ProcessName(String),
    ProcessPath(String),
    ProcessNameRegex(Regex),
    ProcessPathRegex(Regex),
    ProcessNameWildcard(String),
    ProcessPathWildcard(String),
    Uid(NumericRanges),
    InType(Vec<SessionKind>),
    InUser(Vec<String>),
    InName(Vec<String>),
    Network(NetworkKind),
    RuleSet(CompiledRuleProvider),
    And(Vec<RuleMatcher>),
    Or(Vec<RuleMatcher>),
    Not(Box<RuleMatcher>),
    Match,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CompiledRuleProvider {
    Domain(Vec<DomainProviderPattern>),
    IpCidr(Vec<Cidr>),
    Classical(Vec<RuleMatcher>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DomainProviderPattern {
    Exact(String),
    Suffix(String),
    Wildcard(String),
}

impl PartialEq for RuleMatcher {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Domain(left), Self::Domain(right))
            | (Self::DomainSuffix(left), Self::DomainSuffix(right))
            | (Self::DomainKeyword(left), Self::DomainKeyword(right))
            | (Self::DomainWildcard(left), Self::DomainWildcard(right))
            | (Self::ProcessName(left), Self::ProcessName(right))
            | (Self::ProcessPath(left), Self::ProcessPath(right))
            | (Self::ProcessNameWildcard(left), Self::ProcessNameWildcard(right))
            | (Self::ProcessPathWildcard(left), Self::ProcessPathWildcard(right)) => left == right,
            (Self::DomainRegex(left), Self::DomainRegex(right))
            | (Self::ProcessNameRegex(left), Self::ProcessNameRegex(right))
            | (Self::ProcessPathRegex(left), Self::ProcessPathRegex(right)) => {
                left.as_str() == right.as_str()
            }
            (Self::IpCidr(left), Self::IpCidr(right))
            | (Self::SrcIpCidr(left), Self::SrcIpCidr(right)) => left == right,
            (Self::SrcPort(left), Self::SrcPort(right))
            | (Self::DstPort(left), Self::DstPort(right))
            | (Self::InPort(left), Self::InPort(right))
            | (Self::Dscp(left), Self::Dscp(right))
            | (Self::Uid(left), Self::Uid(right)) => left == right,
            (Self::InType(left), Self::InType(right)) => left == right,
            (Self::InUser(left), Self::InUser(right))
            | (Self::InName(left), Self::InName(right)) => left == right,
            (Self::Network(left), Self::Network(right)) => left == right,
            (Self::RuleSet(left), Self::RuleSet(right)) => left == right,
            (Self::And(left), Self::And(right)) | (Self::Or(left), Self::Or(right)) => left == right,
            (Self::Not(left), Self::Not(right)) => left == right,
            (Self::Match, Self::Match) => true,
            _ => false,
        }
    }
}

impl Eq for RuleMatcher {}

impl RuleMatcher {
    fn matches(&self, metadata: &Metadata) -> bool {
        match self {
            Self::Domain(expected) => metadata
                .rule_host()
                .is_some_and(|host| normalize(host) == *expected),
            Self::DomainSuffix(suffix) => metadata.rule_host().is_some_and(|host| {
                let host = normalize(host);
                host == *suffix || host.ends_with(&format!(".{suffix}"))
            }),
            Self::DomainKeyword(keyword) => metadata
                .rule_host()
                .is_some_and(|host| normalize(host).contains(keyword)),
            Self::DomainRegex(regex) => metadata.rule_host().is_some_and(|host| regex.is_match(host)),
            Self::DomainWildcard(pattern) => metadata
                .rule_host()
                .is_some_and(|host| wildcard_matches(pattern, &normalize(host))),
            Self::IpCidr(cidr) => metadata.dst_ip.is_some_and(|ip| cidr.contains(ip)),
            Self::SrcIpCidr(cidr) => metadata.src_ip.is_some_and(|ip| cidr.contains(ip)),
            Self::SrcPort(ranges) => metadata
                .src_port
                .is_some_and(|port| ranges.contains(u64::from(port))),
            Self::DstPort(ranges) => metadata
                .dst_port
                .is_some_and(|port| ranges.contains(u64::from(port))),
            Self::InPort(ranges) => metadata
                .inbound_port
                .is_some_and(|port| ranges.contains(u64::from(port))),
            Self::Dscp(ranges) => metadata
                .dscp
                .is_some_and(|dscp| ranges.contains(u64::from(dscp))),
            Self::ProcessName(expected) => eq_ignore_ascii_case(&metadata.process, expected),
            Self::ProcessPath(expected) => eq_ignore_ascii_case(&metadata.process_path, expected),
            Self::ProcessNameRegex(regex) => regex.is_match(&metadata.process),
            Self::ProcessPathRegex(regex) => regex.is_match(&metadata.process_path),
            Self::ProcessNameWildcard(pattern) => {
                wildcard_matches(pattern, &normalize(&metadata.process))
            }
            Self::ProcessPathWildcard(pattern) => {
                wildcard_matches(pattern, &normalize(&metadata.process_path))
            }
            Self::Uid(ranges) => metadata.uid.is_some_and(|uid| ranges.contains(u64::from(uid))),
            Self::InType(expected) => expected.contains(&metadata.kind),
            Self::InUser(expected) => expected.iter().any(|user| metadata.inbound_user == *user),
            Self::InName(expected) => expected.iter().any(|name| metadata.inbound_name == *name),
            Self::Network(expected) => match expected {
                NetworkKind::All => {
                    matches!(
                        metadata.network,
                        NetworkKind::Tcp | NetworkKind::Udp | NetworkKind::All
                    )
                }
                _ => metadata.network == *expected,
            },
            Self::RuleSet(provider) => provider.matches(metadata),
            Self::And(children) => children.iter().all(|child| child.matches(metadata)),
            Self::Or(children) => children.iter().any(|child| child.matches(metadata)),
            Self::Not(child) => !child.matches(metadata),
            Self::Match => true,
        }
    }
}

impl CompiledRuleProvider {
    fn matches(&self, metadata: &Metadata) -> bool {
        match self {
            Self::Domain(patterns) => metadata.rule_host().is_some_and(|host| {
                let host = normalize(host);
                patterns.iter().any(|pattern| pattern.matches(&host))
            }),
            Self::IpCidr(cidrs) => metadata
                .dst_ip
                .is_some_and(|ip| cidrs.iter().any(|cidr| cidr.contains(ip))),
            Self::Classical(matchers) => matchers.iter().any(|matcher| matcher.matches(metadata)),
        }
    }
}

impl DomainProviderPattern {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Suffix(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            Self::Wildcard(pattern) => wildcard_matches(pattern, host),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NumericRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NumericRanges {
    ranges: Vec<NumericRange>,
}

impl NumericRanges {
    fn parse(
        raw: &str,
        max: u64,
        err: fn(String) -> RuleError,
        require_non_empty: bool,
    ) -> Result<Self, RuleError> {
        let normalized = raw.trim();
        if normalized.is_empty() {
            return Err(err(raw.to_owned()));
        }

        let mut ranges = Vec::new();
        for segment in normalized.replace(',', "/").split('/') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if segment == "*" {
                if require_non_empty && !ranges.is_empty() {
                    return Err(err(raw.to_owned()));
                }
                return Ok(Self {
                    ranges: vec![NumericRange { start: 0, end: max }],
                });
            }

            let (start_raw, end_raw) = segment
                .split_once('-')
                .map_or((segment, segment), |(start, end)| (start.trim(), end.trim()));
            let start = parse_u64(start_raw).ok_or_else(|| err(raw.to_owned()))?;
            let end = parse_u64(end_raw).ok_or_else(|| err(raw.to_owned()))?;
            if start > end || end > max {
                return Err(err(raw.to_owned()));
            }
            ranges.push(NumericRange { start, end });
        }

        if require_non_empty && ranges.is_empty() {
            return Err(err(raw.to_owned()));
        }

        Ok(Self { ranges })
    }

    fn contains(&self, value: u64) -> bool {
        self.ranges
            .iter()
            .any(|range| range.start <= value && value <= range.end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
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

pub fn parse_rule(raw: &str) -> Result<RuleDefinition, RuleError> {
    parse_rule_with_target(raw, true)
}

pub fn compile_rule_set(raw_rules: &[String]) -> Result<RuleSet, RuleError> {
    let empty_sources = BTreeMap::<String, String>::new();
    compile_rule_table_with_providers(
        raw_rules,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &empty_sources,
        &empty_sources,
    )
}

pub fn compile_rule_table(
    raw_rules: &[String],
    raw_sub_rules: &BTreeMap<String, Vec<String>>,
) -> Result<RuleSet, RuleError> {
    let empty_sources = BTreeMap::<String, String>::new();
    compile_rule_table_with_providers(
        raw_rules,
        raw_sub_rules,
        &BTreeMap::new(),
        &empty_sources,
        &empty_sources,
    )
}

pub const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1];

pub fn compile_rule_table_with_providers<S>(
    raw_rules: &[String],
    raw_sub_rules: &BTreeMap<String, Vec<String>>,
    raw_rule_providers: &BTreeMap<String, RuleProviderDefinition>,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<RuleSet, RuleError>
where
    S: AsRef<[u8]>,
{
    let mut compiler =
        RuleTableCompiler::new(raw_sub_rules, raw_rule_providers, file_contents, http_contents);
    let rules = compiler.compile_rule_lines(raw_rules)?;
    for name in raw_sub_rules.keys() {
        compiler.compile_sub_rule(name)?;
    }
    Ok(RuleSet {
        rules,
        sub_rules: compiler.compiled_sub_rules,
    })
}

fn parse_rule_with_target(raw: &str, need_target: bool) -> Result<RuleDefinition, RuleError> {
    let mut segments = raw.split(',').map(str::trim).collect::<Vec<_>>();
    let Some(rule_type_raw) = segments.first().copied() else {
        return Err(RuleError::MissingType(raw.to_owned()));
    };
    let rule_type = parse_rule_type(rule_type_raw)?;

    let mut payload = String::new();
    let mut target = String::new();

    if segments.len() > 1 {
        match rule_type {
            RuleType::Match => {
                target = segments.get(1).copied().unwrap_or_default().to_owned();
            }
            RuleType::And
            | RuleType::Or
            | RuleType::Not
            | RuleType::SubRule
            | RuleType::DomainRegex
            | RuleType::ProcessNameRegex
            | RuleType::ProcessPathRegex => {
                if need_target {
                    let Some(last) = segments.pop() else {
                        return Err(RuleError::MissingTarget(raw.to_owned()));
                    };
                    target = last.to_owned();
                }
                payload = segments[1..].join(",");
            }
            _ => {
                payload = segments.get(1).copied().unwrap_or_default().to_owned();
                if segments.len() > 2 && need_target {
                    target = segments[2].to_owned();
                }
            }
        }
    }

    match rule_type {
        RuleType::Match => {
            if target.is_empty() {
                return Err(RuleError::MissingTarget(raw.to_owned()));
            }
            Ok(RuleDefinition {
                rule_type,
                payload: String::new(),
                target,
            })
        }
        _ => {
            if payload.is_empty() {
                return Err(RuleError::MissingPayload(raw.to_owned()));
            }
            if need_target && target.is_empty() {
                return Err(RuleError::MissingTarget(raw.to_owned()));
            }
            Ok(RuleDefinition {
                rule_type,
                payload,
                target,
            })
        }
    }
}

fn parse_rule_type(raw: &str) -> Result<RuleType, RuleError> {
    Ok(match raw.to_ascii_uppercase().as_str() {
        "DOMAIN" => RuleType::Domain,
        "DOMAIN-SUFFIX" => RuleType::DomainSuffix,
        "DOMAIN-KEYWORD" => RuleType::DomainKeyword,
        "DOMAIN-REGEX" => RuleType::DomainRegex,
        "DOMAIN-WILDCARD" => RuleType::DomainWildcard,
        "IP-CIDR" | "IP-CIDR6" => RuleType::IpCidr,
        "SRC-IP-CIDR" => RuleType::SrcIpCidr,
        "SRC-PORT" => RuleType::SrcPort,
        "DST-PORT" => RuleType::DstPort,
        "IN-PORT" => RuleType::InPort,
        "DSCP" => RuleType::Dscp,
        "PROCESS-NAME" => RuleType::ProcessName,
        "PROCESS-PATH" => RuleType::ProcessPath,
        "PROCESS-NAME-REGEX" => RuleType::ProcessNameRegex,
        "PROCESS-PATH-REGEX" => RuleType::ProcessPathRegex,
        "PROCESS-NAME-WILDCARD" => RuleType::ProcessNameWildcard,
        "PROCESS-PATH-WILDCARD" => RuleType::ProcessPathWildcard,
        "UID" => RuleType::Uid,
        "IN-TYPE" => RuleType::InType,
        "IN-USER" => RuleType::InUser,
        "IN-NAME" => RuleType::InName,
        "NETWORK" => RuleType::Network,
        "RULE-SET" => RuleType::RuleSet,
        "SUB-RULE" => RuleType::SubRule,
        "AND" => RuleType::And,
        "OR" => RuleType::Or,
        "NOT" => RuleType::Not,
        "MATCH" => RuleType::Match,
        other => return Err(RuleError::UnsupportedRuleType(other.to_owned())),
    })
}

struct RuleTableCompiler<'a, S: AsRef<[u8]>> {
    raw_sub_rules: &'a BTreeMap<String, Vec<String>>,
    raw_rule_providers: &'a BTreeMap<String, RuleProviderDefinition>,
    file_contents: &'a BTreeMap<String, S>,
    http_contents: &'a BTreeMap<String, S>,
    compiled_sub_rules: BTreeMap<String, Vec<CompiledRule>>,
    compiled_rule_providers: BTreeMap<String, CompiledRuleProvider>,
    visiting: Vec<String>,
}

impl<'a, S: AsRef<[u8]>> RuleTableCompiler<'a, S> {
    fn new(
        raw_sub_rules: &'a BTreeMap<String, Vec<String>>,
        raw_rule_providers: &'a BTreeMap<String, RuleProviderDefinition>,
        file_contents: &'a BTreeMap<String, S>,
        http_contents: &'a BTreeMap<String, S>,
    ) -> Self {
        Self {
            raw_sub_rules,
            raw_rule_providers,
            file_contents,
            http_contents,
            compiled_sub_rules: BTreeMap::new(),
            compiled_rule_providers: BTreeMap::new(),
            visiting: Vec::new(),
        }
    }

    fn compile_rule_lines(&mut self, raw_rules: &[String]) -> Result<Vec<CompiledRule>, RuleError> {
        raw_rules
            .iter()
            .map(|raw| self.compile_rule_line(raw))
            .collect()
    }

    fn compile_rule_line(&mut self, raw: &str) -> Result<CompiledRule, RuleError> {
        let definition = parse_rule(raw)?;
        match definition.rule_type {
            RuleType::SubRule => {
                self.compile_sub_rule(&definition.target)?;
                let gate_payload = strip_outer_parens(&definition.payload)
                    .ok_or_else(|| RuleError::InvalidLogic(definition.payload.clone()))?;
                let gate = parse_rule_with_target(gate_payload, false)?;
                let matcher = self.compile_matcher(&gate, false)?;
                Ok(CompiledRule {
                    rule_type: definition.rule_type,
                    payload: definition.payload,
                    action: RuleAction::SubRule(definition.target),
                    matcher,
                    runtime: Arc::new(CompiledRuleRuntime::default()),
                })
            }
            RuleType::RuleSet => {
                let payload = definition.payload;
                let matcher = self.compile_rule_provider_matcher(&payload)?;
                Ok(CompiledRule {
                    rule_type: definition.rule_type,
                    payload,
                    action: RuleAction::Target(definition.target),
                    matcher,
                    runtime: Arc::new(CompiledRuleRuntime::default()),
                })
            }
            _ => {
                let matcher = self.compile_matcher(&definition, true)?;
                Ok(CompiledRule {
                    rule_type: definition.rule_type,
                    payload: definition.payload,
                    action: RuleAction::Target(definition.target),
                    matcher,
                    runtime: Arc::new(CompiledRuleRuntime::default()),
                })
            }
        }
    }

    fn compile_sub_rule(&mut self, name: &str) -> Result<(), RuleError> {
        if name.trim().is_empty() {
            return Err(RuleError::EmptySubRuleName);
        }
        if self.compiled_sub_rules.contains_key(name) {
            return Ok(());
        }
        let Some(raw_rules) = self.raw_sub_rules.get(name) else {
            return Err(RuleError::SubRuleNotFound(name.to_owned()));
        };
        if self.visiting.iter().any(|entry| entry == name) {
            let mut chain = self.visiting.clone();
            chain.push(name.to_owned());
            return Err(RuleError::CircularSubRule(chain.join("->")));
        }

        self.visiting.push(name.to_owned());
        let compiled = self.compile_rule_lines(raw_rules)?;
        self.visiting.pop();
        self.compiled_sub_rules.insert(name.to_owned(), compiled);
        Ok(())
    }

    fn compile_matcher(
        &mut self,
        definition: &RuleDefinition,
        top_level: bool,
    ) -> Result<RuleMatcher, RuleError> {
        Ok(match definition.rule_type {
            RuleType::Domain => RuleMatcher::Domain(normalize(&definition.payload)),
            RuleType::DomainSuffix => RuleMatcher::DomainSuffix(normalize(&definition.payload)),
            RuleType::DomainKeyword => RuleMatcher::DomainKeyword(normalize(&definition.payload)),
            RuleType::DomainRegex => RuleMatcher::DomainRegex(compile_regex(&definition.payload)?),
            RuleType::DomainWildcard => RuleMatcher::DomainWildcard(normalize(&definition.payload)),
            RuleType::IpCidr => RuleMatcher::IpCidr(Cidr::parse(&definition.payload)?),
            RuleType::SrcIpCidr => RuleMatcher::SrcIpCidr(Cidr::parse(&definition.payload)?),
            RuleType::SrcPort => RuleMatcher::SrcPort(NumericRanges::parse(
                &definition.payload,
                u64::from(u16::MAX),
                RuleError::InvalidPort,
                true,
            )?),
            RuleType::DstPort => RuleMatcher::DstPort(NumericRanges::parse(
                &definition.payload,
                u64::from(u16::MAX),
                RuleError::InvalidPort,
                true,
            )?),
            RuleType::InPort => RuleMatcher::InPort(NumericRanges::parse(
                &definition.payload,
                u64::from(u16::MAX),
                RuleError::InvalidPort,
                true,
            )?),
            RuleType::Dscp => RuleMatcher::Dscp(NumericRanges::parse(
                &definition.payload,
                63,
                RuleError::InvalidDscp,
                true,
            )?),
            RuleType::ProcessName => RuleMatcher::ProcessName(normalize(&definition.payload)),
            RuleType::ProcessPath => RuleMatcher::ProcessPath(normalize(&definition.payload)),
            RuleType::ProcessNameRegex => {
                RuleMatcher::ProcessNameRegex(compile_regex(&definition.payload)?)
            }
            RuleType::ProcessPathRegex => {
                RuleMatcher::ProcessPathRegex(compile_regex(&definition.payload)?)
            }
            RuleType::ProcessNameWildcard => {
                RuleMatcher::ProcessNameWildcard(normalize(&definition.payload))
            }
            RuleType::ProcessPathWildcard => {
                RuleMatcher::ProcessPathWildcard(normalize(&definition.payload))
            }
            RuleType::Uid => RuleMatcher::Uid(NumericRanges::parse(
                &definition.payload,
                u64::from(u32::MAX),
                RuleError::InvalidUid,
                true,
            )?),
            RuleType::InType => RuleMatcher::InType(parse_in_types(&definition.payload)?),
            RuleType::InUser => RuleMatcher::InUser(parse_name_list(
                &definition.payload,
                RuleError::InvalidInUser,
            )?),
            RuleType::InName => RuleMatcher::InName(parse_name_list(
                &definition.payload,
                RuleError::InvalidInName,
            )?),
            RuleType::Network => RuleMatcher::Network(parse_network(&definition.payload)?),
            RuleType::RuleSet => self.compile_rule_provider_matcher(&definition.payload)?,
            RuleType::SubRule => {
                return Err(RuleError::InvalidLogic(
                    "logic rule does not support SUB-RULE child".to_owned(),
                ))
            }
            RuleType::And => RuleMatcher::And(self.compile_logic_children(&definition.payload)?),
            RuleType::Or => RuleMatcher::Or(self.compile_logic_children(&definition.payload)?),
            RuleType::Not => RuleMatcher::Not(Box::new(self.compile_logic_not(&definition.payload)?)),
            RuleType::Match if top_level => RuleMatcher::Match,
            RuleType::Match => {
                return Err(RuleError::InvalidLogic(
                    "logic rule does not support MATCH child".to_owned(),
                ))
            }
        })
    }

    fn compile_logic_children(&mut self, payload: &str) -> Result<Vec<RuleMatcher>, RuleError> {
        parse_logic_children(payload)?
            .into_iter()
            .map(|raw| {
                let definition = parse_rule_with_target(&raw, false)?;
                self.compile_matcher(&definition, false)
            })
            .collect()
    }

    fn compile_logic_not(&mut self, payload: &str) -> Result<RuleMatcher, RuleError> {
        let children = self.compile_logic_children(payload)?;
        if children.len() != 1 {
            return Err(RuleError::InvalidLogic(payload.to_owned()));
        }
        Ok(children.into_iter().next().expect("one child"))
    }

    fn compile_rule_provider_matcher(&mut self, name: &str) -> Result<RuleMatcher, RuleError> {
        Ok(RuleMatcher::RuleSet(self.compile_rule_provider(name)?))
    }

    fn compile_rule_provider(&mut self, name: &str) -> Result<CompiledRuleProvider, RuleError> {
        if let Some(provider) = self.compiled_rule_providers.get(name) {
            return Ok(provider.clone());
        }

        let Some(provider) = self.raw_rule_providers.get(name) else {
            return Err(RuleError::RuleProviderNotFound(name.to_owned()));
        };
        let compiled = match provider
            .behavior_kind()
            .ok_or_else(|| RuleError::UnsupportedRuleProviderBehavior(provider.behavior.clone()))?
        {
            RuleProviderBehavior::Domain => {
                let payload = self.load_rule_provider_payload(provider)?;
                CompiledRuleProvider::Domain(
                    payload
                        .into_iter()
                        .map(|raw| parse_domain_provider_pattern(&raw))
                        .collect(),
                )
            }
            RuleProviderBehavior::IpCidr => {
                let payload = self.load_rule_provider_payload(provider)?;
                let cidrs = payload
                    .into_iter()
                    .map(|raw| Cidr::parse(&raw))
                    .collect::<Result<Vec<_>, _>>()?;
                CompiledRuleProvider::IpCidr(cidrs)
            }
            RuleProviderBehavior::Classical => {
                let payload = self.load_rule_provider_payload(provider)?;
                let mut matchers = Vec::new();
                for raw in payload {
                    let definition = parse_rule_with_target(&raw, false)?;
                    if matches!(
                        definition.rule_type,
                        RuleType::Match | RuleType::RuleSet | RuleType::SubRule
                    ) {
                        return Err(RuleError::InvalidLogic(raw));
                    }
                    matchers.push(self.compile_matcher(&definition, false)?);
                }
                CompiledRuleProvider::Classical(matchers)
            }
        };

        self.compiled_rule_providers
            .insert(name.to_owned(), compiled.clone());
        Ok(compiled)
    }

    fn load_rule_provider_payload(
        &self,
        provider: &RuleProviderDefinition,
    ) -> Result<Vec<String>, RuleError> {
        load_rule_provider_payload_from_sources(provider, self.file_contents, self.http_contents)
    }
}

fn parse_logic_children(payload: &str) -> Result<Vec<String>, RuleError> {
    let bytes = payload.as_bytes();
    if bytes.first() != Some(&b'(') || bytes.last() != Some(&b')') {
        return Err(RuleError::InvalidLogic(payload.to_owned()));
    }

    let mut depth = 0_u32;
    let mut child_start = None;
    let mut children = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' => {
                depth += 1;
                if depth == 2 {
                    child_start = Some(index + 1);
                }
            }
            b')' => {
                if depth == 0 {
                    return Err(RuleError::InvalidLogic(payload.to_owned()));
                }
                if depth == 2 {
                    let start = child_start
                        .take()
                        .ok_or_else(|| RuleError::InvalidLogic(payload.to_owned()))?;
                    children.push(payload[start..index].to_owned());
                }
                depth -= 1;
            }
            _ => {}
        }
    }

    if depth != 0 || children.is_empty() {
        return Err(RuleError::InvalidLogic(payload.to_owned()));
    }
    Ok(children)
}

fn strip_outer_parens(raw: &str) -> Option<&str> {
    raw.strip_prefix('(')?.strip_suffix(')')
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
struct RuleProviderPayloadDocument {
    #[serde(default, rename = "payload")]
    payload: Vec<String>,
    #[serde(default, rename = "rules")]
    rules: Vec<String>,
}

pub fn convert_ruleset_content(
    content: &[u8],
    behavior: RuleProviderBehavior,
    format: RuleProviderFormat,
) -> Result<Vec<u8>, RuleError> {
    let payload = parse_rule_provider_bytes(content, behavior, format)?;
    if payload.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
    }
    match format {
        RuleProviderFormat::Mrs => {
            let mut output = payload.join("\n");
            output.push('\n');
            Ok(output.into_bytes())
        }
        RuleProviderFormat::Yaml | RuleProviderFormat::Text => {
            encode_rule_provider_as_mrs(&payload, behavior)
        }
    }
}

pub fn load_rule_provider_payload_from_sources<S: AsRef<[u8]>>(
    provider: &RuleProviderDefinition,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<Vec<String>, RuleError> {
    let behavior = provider
        .behavior_kind()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderBehavior(provider.behavior.clone()))?;
    let format = provider
        .format_kind()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderFormat(provider.format.clone()))?;
    match provider
        .vehicle_type()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderVehicle(provider.provider_type.clone()))?
    {
        RuleProviderVehicleType::Inline => Ok(provider.payload.clone()),
        RuleProviderVehicleType::File => {
            let Some(content) = file_contents.get(&provider.path) else {
                return Ok(Vec::new());
            };
            parse_rule_provider_bytes(content.as_ref(), behavior, format)
        }
        RuleProviderVehicleType::Http => {
            let content = http_contents
                .get(&provider.url)
                .or_else(|| file_contents.get(&provider.path));
            let Some(content) = content else {
                return Ok(Vec::new());
            };
            parse_rule_provider_bytes(content.as_ref(), behavior, format)
        }
    }
}

fn parse_rule_provider_bytes(
    content: &[u8],
    behavior: RuleProviderBehavior,
    format: RuleProviderFormat,
) -> Result<Vec<String>, RuleError> {
    match format {
        RuleProviderFormat::Yaml => {
            let content = std::str::from_utf8(content)
                .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            let document = serde_yaml::from_str::<RuleProviderPayloadDocument>(content)
                .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            if !document.rules.is_empty() {
                Ok(document.rules)
            } else {
                Ok(document.payload)
            }
        }
        RuleProviderFormat::Text => Ok(std::str::from_utf8(content)
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with('#') && !line.starts_with("//"))
            .map(ToOwned::to_owned)
            .collect()),
        RuleProviderFormat::Mrs => decode_rule_provider_from_mrs(content, behavior),
    }
}

fn encode_rule_provider_as_mrs(
    payload: &[String],
    behavior: RuleProviderBehavior,
) -> Result<Vec<u8>, RuleError> {
    let mut encoder = zstd::Encoder::new(Vec::new(), 0)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    encoder
        .write_all(&MRS_MAGIC_BYTES)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    encoder
        .write_all(&[mrs_behavior_byte(behavior)])
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    encoder
        .write_all(&(payload.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    encoder
        .write_all(&0_i64.to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    match behavior {
        RuleProviderBehavior::Domain => write_domain_mrs_body(&mut encoder, payload)?,
        RuleProviderBehavior::IpCidr => write_ipcidr_mrs_body(&mut encoder, payload)?,
        RuleProviderBehavior::Classical => {
            return Err(RuleError::UnsupportedRuleProviderFormat("mrs".into()))
        }
    }
    encoder
        .finish()
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))
}

fn decode_rule_provider_from_mrs(
    content: &[u8],
    behavior: RuleProviderBehavior,
) -> Result<Vec<String>, RuleError> {
    match behavior {
        RuleProviderBehavior::Classical => {
            return Err(RuleError::UnsupportedRuleProviderFormat("mrs".into()))
        }
        RuleProviderBehavior::Domain | RuleProviderBehavior::IpCidr => {}
    }

    let decoded = zstd::stream::decode_all(Cursor::new(content))
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    let mut cursor = Cursor::new(decoded);
    let mut magic = [0_u8; 4];
    cursor
        .read_exact(&mut magic)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    if magic != MRS_MAGIC_BYTES {
        return Err(RuleError::InvalidRuleProviderContent(
            "invalid MrsMagic bytes".into(),
        ));
    }

    let mut encoded_behavior = [0_u8; 1];
    cursor
        .read_exact(&mut encoded_behavior)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    if encoded_behavior[0] != mrs_behavior_byte(behavior) {
        return Err(RuleError::InvalidRuleProviderContent(
            "invalid behavior".into(),
        ));
    }

    let _count = read_i64_be(&mut cursor)?;
    let extra_len = read_i64_be(&mut cursor)?;
    if extra_len < 0 {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    if extra_len > 0 {
        let mut extra = vec![0_u8; extra_len as usize];
        cursor
            .read_exact(&mut extra)
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    }

    match behavior {
        RuleProviderBehavior::Domain => read_domain_mrs_body(&mut cursor),
        RuleProviderBehavior::IpCidr => read_ipcidr_mrs_body(&mut cursor),
        RuleProviderBehavior::Classical => unreachable!(),
    }
}

fn write_domain_mrs_body(w: &mut impl Write, payload: &[String]) -> Result<(), RuleError> {
    let mut stored_rules = Vec::new();
    for raw in payload {
        stored_rules.extend(expand_domain_rule_for_mrs(raw));
    }
    if stored_rules.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
    }

    let mut reversed = stored_rules
        .into_iter()
        .map(|rule| reverse_ascii(&rule).into_bytes())
        .collect::<Vec<_>>();
    reversed.sort();
    reversed.dedup();

    let (leaves, label_bitmap, labels) = build_domain_set_binary(&reversed);
    w.write_all(&[1])
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    write_u64_vec(w, &leaves)?;
    write_u64_vec(w, &label_bitmap)?;
    w.write_all(&(labels.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    w.write_all(&labels)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    Ok(())
}

fn read_domain_mrs_body(r: &mut impl Read) -> Result<Vec<String>, RuleError> {
    let version = read_u8(r)?;
    if version != 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "version is invalid".into(),
        ));
    }
    let leaves = read_u64_vec(r)?;
    let label_bitmap = read_u64_vec(r)?;
    let labels_len = read_i64_be(r)?;
    if labels_len < 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    let mut labels = vec![0_u8; labels_len as usize];
    r.read_exact(&mut labels)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;

    let mut nodes = vec![DomainMrsNode::default()];
    let mut bit_index = 0_usize;
    let mut label_index = 0_usize;
    let mut current_node = 0_usize;
    while current_node < nodes.len() {
        if label_index == labels.len() {
            nodes[current_node].leaf = has_bit(&leaves, current_node);
            current_node += 1;
            continue;
        }
        let bit = get_bit(&label_bitmap, bit_index)
            .ok_or_else(|| RuleError::InvalidRuleProviderContent("length is invalid".into()))?;
        if bit == 0 {
            let label = *labels
                .get(label_index)
                .ok_or_else(|| RuleError::InvalidRuleProviderContent("length is invalid".into()))?;
            let child_index = nodes.len();
            nodes[current_node].children.push((label, child_index));
            nodes.push(DomainMrsNode::default());
            label_index += 1;
        } else {
            nodes[current_node].leaf = has_bit(&leaves, current_node);
            current_node += 1;
        }
        bit_index += 1;
    }
    if label_index != labels.len() {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }

    let mut keys = Vec::new();
    let mut current = Vec::new();
    collect_domain_keys(&nodes, 0, &mut current, &mut keys)?;
    keys.sort();
    let key_set = keys.iter().cloned().collect::<BTreeSet<_>>();
    Ok(keys
        .into_iter()
        .filter(|key| !key_set.contains(&format!("+.{key}")))
        .collect())
}

fn write_ipcidr_mrs_body(w: &mut impl Write, payload: &[String]) -> Result<(), RuleError> {
    let ranges = payload
        .iter()
        .map(|raw| Cidr::parse(raw))
        .collect::<Result<Vec<_>, _>>()?;
    if ranges.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
    }
    w.write_all(&[1])
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    w.write_all(&(ranges.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    for cidr in ranges {
        let (start, end) = cidr_bounds(&cidr);
        write_ip16(w, start)?;
        write_ip16(w, end)?;
    }
    Ok(())
}

fn read_ipcidr_mrs_body(r: &mut impl Read) -> Result<Vec<String>, RuleError> {
    let version = read_u8(r)?;
    if version != 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "version is invalid".into(),
        ));
    }
    let len = read_i64_be(r)?;
    if len < 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    let mut rules = Vec::new();
    for _ in 0..len {
        let start = read_ip16(r)?;
        let end = read_ip16(r)?;
        rules.extend(ip_range_to_cidrs(start, end));
    }
    Ok(rules)
}

fn mrs_behavior_byte(behavior: RuleProviderBehavior) -> u8 {
    match behavior {
        RuleProviderBehavior::Domain => 0,
        RuleProviderBehavior::IpCidr => 1,
        RuleProviderBehavior::Classical => 2,
    }
}

fn expand_domain_rule_for_mrs(raw: &str) -> Vec<String> {
    let normalized = normalize(raw);
    if normalized.is_empty() || normalized.ends_with('.') {
        return Vec::new();
    }
    if normalized.starts_with("+.") {
        let suffix = normalized.trim_start_matches("+.").to_owned();
        if suffix.is_empty() {
            return Vec::new();
        }
        return vec![suffix.clone(), format!("+.{suffix}")];
    }
    if normalized.starts_with('.') && normalized.len() > 1 {
        return vec![format!("+{}", normalized)];
    }
    vec![normalized]
}

fn reverse_ascii(value: &str) -> String {
    value.bytes().rev().map(char::from).collect()
}

fn build_domain_set_binary(keys: &[Vec<u8>]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    #[derive(Clone, Copy)]
    struct QueueElt {
        start: usize,
        end: usize,
        col: usize,
    }

    let mut leaves = Vec::new();
    let mut label_bitmap = Vec::new();
    let mut labels = Vec::new();
    let mut queue = vec![QueueElt {
        start: 0,
        end: keys.len(),
        col: 0,
    }];
    let mut bit_index = 0_usize;

    let mut node_index = 0_usize;
    while node_index < queue.len() {
        let mut elt = queue[node_index];
        if elt.col == keys[elt.start].len() {
            elt.start += 1;
            set_bit(&mut leaves, node_index, true);
        }

        let mut cursor = elt.start;
        while cursor < elt.end {
            let first = cursor;
            while cursor < elt.end && keys[cursor][elt.col] == keys[first][elt.col] {
                cursor += 1;
            }
            queue.push(QueueElt {
                start: first,
                end: cursor,
                col: elt.col + 1,
            });
            labels.push(keys[first][elt.col]);
            set_bit(&mut label_bitmap, bit_index, false);
            bit_index += 1;
        }
        set_bit(&mut label_bitmap, bit_index, true);
        bit_index += 1;
        node_index += 1;
    }

    (leaves, label_bitmap, labels)
}

fn collect_domain_keys(
    nodes: &[DomainMrsNode],
    node_index: usize,
    current: &mut Vec<u8>,
    out: &mut Vec<String>,
) -> Result<(), RuleError> {
    if nodes[node_index].leaf {
        let reversed = current.iter().rev().copied().collect::<Vec<_>>();
        out.push(
            String::from_utf8(reversed)
                .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?,
        );
    }
    for (label, child_index) in &nodes[node_index].children {
        current.push(*label);
        collect_domain_keys(nodes, *child_index, current, out)?;
        current.pop();
    }
    Ok(())
}

#[derive(Default)]
struct DomainMrsNode {
    leaf: bool,
    children: Vec<(u8, usize)>,
}

fn cidr_bounds(cidr: &Cidr) -> (IpAddr, IpAddr) {
    match cidr.network {
        IpAddr::V4(ip) => {
            let start = u32::from(ip) & prefix_mask_u32(cidr.prefix_len);
            let host_mask = if cidr.prefix_len == 32 {
                0
            } else {
                (1_u32 << (32 - cidr.prefix_len)) - 1
            };
            (
                IpAddr::V4(std::net::Ipv4Addr::from(start)),
                IpAddr::V4(std::net::Ipv4Addr::from(start | host_mask)),
            )
        }
        IpAddr::V6(ip) => {
            let start = u128::from(ip) & prefix_mask_u128(cidr.prefix_len);
            let host_mask = if cidr.prefix_len == 128 {
                0
            } else {
                (1_u128 << (128 - cidr.prefix_len)) - 1
            };
            (
                IpAddr::V6(std::net::Ipv6Addr::from(start)),
                IpAddr::V6(std::net::Ipv6Addr::from(start | host_mask)),
            )
        }
    }
}

fn write_u64_vec(w: &mut impl Write, values: &[u64]) -> Result<(), RuleError> {
    if values.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent("length is invalid".into()));
    }
    w.write_all(&(values.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    for value in values {
        w.write_all(&value.to_be_bytes())
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    }
    Ok(())
}

fn read_u64_vec(r: &mut impl Read) -> Result<Vec<u64>, RuleError> {
    let len = read_i64_be(r)?;
    if len < 1 {
        return Err(RuleError::InvalidRuleProviderContent("length is invalid".into()));
    }
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut buf = [0_u8; 8];
        r.read_exact(&mut buf)
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        values.push(u64::from_be_bytes(buf));
    }
    Ok(values)
}

fn read_u8(r: &mut impl Read) -> Result<u8, RuleError> {
    let mut buf = [0_u8; 1];
    r.read_exact(&mut buf)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    Ok(buf[0])
}

fn read_i64_be(r: &mut impl Read) -> Result<i64, RuleError> {
    let mut buf = [0_u8; 8];
    r.read_exact(&mut buf)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    Ok(i64::from_be_bytes(buf))
}

fn set_bit(bits: &mut Vec<u64>, index: usize, value: bool) {
    while index / 64 >= bits.len() {
        bits.push(0);
    }
    if value {
        bits[index / 64] |= 1_u64 << (index % 64);
    }
}

fn has_bit(bits: &[u64], index: usize) -> bool {
    get_bit(bits, index).unwrap_or(0) != 0
}

fn get_bit(bits: &[u64], index: usize) -> Option<u64> {
    let word = *bits.get(index / 64)?;
    Some((word >> (index % 64)) & 1)
}

fn write_ip16(w: &mut impl Write, ip: IpAddr) -> Result<(), RuleError> {
    let octets = match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    };
    w.write_all(&octets)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))
}

fn read_ip16(r: &mut impl Read) -> Result<IpAddr, RuleError> {
    let mut octets = [0_u8; 16];
    r.read_exact(&mut octets)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    if octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff {
        return Ok(IpAddr::V4(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        )));
    }
    Ok(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
}

fn ip_range_to_cidrs(start: IpAddr, end: IpAddr) -> Vec<String> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            range_to_cidrs_v4(u32::from(start), u32::from(end))
                .into_iter()
                .map(|(network, prefix)| format!("{}/{}", std::net::Ipv4Addr::from(network), prefix))
                .collect()
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            range_to_cidrs_v6(u128::from(start), u128::from(end))
                .into_iter()
                .map(|(network, prefix)| format!("{}/{}", std::net::Ipv6Addr::from(network), prefix))
                .collect()
        }
        _ => Vec::new(),
    }
}

fn range_to_cidrs_v4(mut start: u32, end: u32) -> Vec<(u32, u8)> {
    let mut result = Vec::new();
    while start <= end {
        let align_bits = if start == 0 { 32 } else { start.trailing_zeros() as u8 };
        let remaining_bits = if start == 0 && end == u32::MAX {
            32
        } else {
            ((end - start + 1).ilog2()) as u8
        };
        let block_bits = align_bits.min(remaining_bits);
        let prefix = 32 - block_bits;
        result.push((start, prefix));
        if block_bits == 32 {
            break;
        }
        start = start.wrapping_add(1_u32 << block_bits);
    }
    result
}

fn range_to_cidrs_v6(mut start: u128, end: u128) -> Vec<(u128, u8)> {
    let mut result = Vec::new();
    while start <= end {
        let align_bits = if start == 0 { 128 } else { start.trailing_zeros() as u8 };
        let remaining_bits = if start == 0 && end == u128::MAX {
            128
        } else {
            127 - (end - start + 1).leading_zeros() as u8
        };
        let block_bits = align_bits.min(remaining_bits);
        let prefix = 128 - block_bits;
        result.push((start, prefix));
        if block_bits == 128 {
            break;
        }
        start = start.wrapping_add(1_u128 << block_bits);
    }
    result
}

fn parse_domain_provider_pattern(raw: &str) -> DomainProviderPattern {
    let normalized = normalize(raw);
    if normalized.starts_with("+.") {
        DomainProviderPattern::Suffix(normalized.trim_start_matches("+.").to_owned())
    } else if normalized.starts_with('.') {
        DomainProviderPattern::Suffix(normalized.trim_start_matches('.').to_owned())
    } else if normalized.contains('*') || normalized.contains('?') {
        DomainProviderPattern::Wildcard(normalized)
    } else {
        DomainProviderPattern::Exact(normalized)
    }
}

fn parse_network(raw: &str) -> Result<NetworkKind, RuleError> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "TCP" => Ok(NetworkKind::Tcp),
        "UDP" => Ok(NetworkKind::Udp),
        "ALL" => Ok(NetworkKind::All),
        _ => Err(RuleError::InvalidNetwork(raw.to_owned())),
    }
}

fn compile_regex(pattern: &str) -> Result<Regex, RuleError> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|_| RuleError::InvalidRegex(pattern.to_owned()))
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    !left.is_empty() && normalize(left) == *right
}

fn parse_name_list(
    raw: &str,
    err: fn(String) -> RuleError,
) -> Result<Vec<String>, RuleError> {
    let values = raw
        .split('/')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(err(raw.to_owned()));
    }
    Ok(values)
}

fn parse_in_types(raw: &str) -> Result<Vec<SessionKind>, RuleError> {
    let values = raw
        .split('/')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(RuleError::InvalidInType(raw.to_owned()));
    }

    let mut kinds = Vec::new();
    for value in values {
        match value.to_ascii_uppercase().as_str() {
            "HTTP" => kinds.push(SessionKind::Http),
            "HTTPS" => kinds.push(SessionKind::Https),
            "SOCKS" => {
                kinds.push(SessionKind::Socks4);
                kinds.push(SessionKind::Socks5);
            }
            "SOCKS4" => kinds.push(SessionKind::Socks4),
            "SOCKS5" => kinds.push(SessionKind::Socks5),
            "SHADOWSOCKS" => kinds.push(SessionKind::ShadowSocks),
            "VMESS" => kinds.push(SessionKind::Vmess),
            "VLESS" => kinds.push(SessionKind::Vless),
            "REDIR" => kinds.push(SessionKind::Redir),
            "TPROXY" => kinds.push(SessionKind::TProxy),
            "TROJAN" => kinds.push(SessionKind::Trojan),
            "TUNNEL" => kinds.push(SessionKind::Tunnel),
            "TUN" => kinds.push(SessionKind::Tun),
            "TUIC" => kinds.push(SessionKind::Tuic),
            "HYSTERIA2" => kinds.push(SessionKind::Hysteria2),
            "ANYTLS" => kinds.push(SessionKind::AnyTls),
            "MIERU" => kinds.push(SessionKind::Mieru),
            "SUDOKU" => kinds.push(SessionKind::Sudoku),
            "TRUSTTUNNEL" => kinds.push(SessionKind::TrustTunnel),
            "INNER" => kinds.push(SessionKind::Inner),
            _ => return Err(RuleError::InvalidInType(raw.to_owned())),
        }
    }
    Ok(kinds)
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pi, mut vi) = (0_usize, 0_usize);
    let (mut star, mut backtrack) = (None, 0_usize);

    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            backtrack = vi;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            backtrack += 1;
            vi = backtrack;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

fn parse_u64(raw: &str) -> Option<u64> {
    raw.parse::<u64>().ok()
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
    crate_name: "mihomo-rules",
    go_areas: &["rules", "rules/provider"],
    contracts: &["rule matching", "policy selection", "provider updates"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use mihomo_config::RuleProviderDefinition;
    use mihomo_core::{Metadata, NetworkKind, SessionKind};

    use super::{
        compile_rule_set, compile_rule_table, compile_rule_table_with_providers,
        convert_ruleset_content, parse_rule, RuleDefinition, RuleError, RuleSet, RuleType,
    };

    #[test]
    fn parse_rule_supports_match_without_payload() {
        assert_eq!(
            parse_rule("MATCH,DIRECT").unwrap(),
            RuleDefinition {
                rule_type: RuleType::Match,
                payload: String::new(),
                target: "DIRECT".into(),
            }
        );
    }

    #[test]
    fn parse_rule_preserves_regex_payload_with_commas() {
        assert_eq!(
            parse_rule(r#"DOMAIN-REGEX,^api,(v1|v2)\.example\.com$,PROXY"#).unwrap(),
            RuleDefinition {
                rule_type: RuleType::DomainRegex,
                payload: r#"^api,(v1|v2)\.example\.com$"#.into(),
                target: "PROXY".into(),
            }
        );
    }

    #[test]
    fn parse_rule_rejects_unsupported_type() {
        assert_eq!(
            parse_rule("GEOIP,CN,DIRECT").unwrap_err(),
            RuleError::UnsupportedRuleType("GEOIP".into())
        );
    }

    #[test]
    fn rule_set_matches_domain_and_match_fallback_in_order() {
        let rules = compile_rule_set(&[
            "DOMAIN-SUFFIX,example.com,DIRECT".into(),
            "MATCH,REJECT".into(),
        ])
        .unwrap();

        let domain = Metadata {
            host: Some("www.example.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&domain), Some("DIRECT"));

        let other = Metadata {
            host: Some("openai.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&other), Some("REJECT"));
    }

    #[test]
    fn rule_set_matches_ip_and_network_variants() {
        let rules = compile_rule_set(&[
            "SRC-IP-CIDR,10.0.0.0/8,DIRECT".into(),
            "IP-CIDR,1.1.1.0/24,PROXY".into(),
            "NETWORK,UDP,UDP-OUT".into(),
            "MATCH,REJECT".into(),
        ])
        .unwrap();

        let src_match = Metadata {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&src_match), Some("DIRECT"));

        let dst_match = Metadata {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&dst_match), Some("PROXY"));

        let udp_match = Metadata {
            network: NetworkKind::Udp,
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&udp_match), Some("UDP-OUT"));
    }

    #[test]
    fn rule_set_matches_ports_uid_and_dscp_variants() {
        let rules = compile_rule_set(&[
            "SRC-PORT,10000-10010,LAN".into(),
            "DST-PORT,443/8443,TLS".into(),
            "IN-PORT,7890,MIXED".into(),
            "UID,1000-2000,UID-OUT".into(),
            "DSCP,46/48-50,QOS".into(),
            "MATCH,REJECT".into(),
        ])
        .unwrap();

        let src_port = Metadata {
            src_port: Some(10005),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&src_port), Some("LAN"));

        let dst_port = Metadata {
            dst_port: Some(8443),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&dst_port), Some("TLS"));

        let in_port = Metadata {
            inbound_port: Some(7890),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&in_port), Some("MIXED"));

        let uid = Metadata {
            uid: Some(1500),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&uid), Some("UID-OUT"));

        let dscp = Metadata {
            dscp: Some(48),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&dscp), Some("QOS"));
    }

    #[test]
    fn rule_set_matches_process_and_inbound_variants() {
        let rules = compile_rule_set(&[
            "IN-NAME,edge/tproxy-in,IN-NAME-OUT".into(),
            "IN-USER,alice/bob,IN-USER-OUT".into(),
            "IN-TYPE,SOCKS/TUNNEL,IN-TYPE-OUT".into(),
            "PROCESS-NAME,Firefox,PROC-NAME-OUT".into(),
            "PROCESS-PATH,/Applications/Firefox.app,PROC-PATH-OUT".into(),
            "MATCH,REJECT".into(),
        ])
        .unwrap();

        let in_name = Metadata {
            inbound_name: "tproxy-in".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&in_name), Some("IN-NAME-OUT"));

        let in_user = Metadata {
            inbound_user: "bob".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&in_user), Some("IN-USER-OUT"));

        let in_type = Metadata {
            kind: SessionKind::Socks5,
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&in_type), Some("IN-TYPE-OUT"));

        let process_name = Metadata {
            process: "firefox".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&process_name), Some("PROC-NAME-OUT"));

        let process_path = Metadata {
            process_path: "/applications/firefox.app".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&process_path), Some("PROC-PATH-OUT"));
    }

    #[test]
    fn rule_set_matches_regex_and_wildcard_variants() {
        let rules = compile_rule_set(&[
            r#"DOMAIN-REGEX,^api,(v1|v2)\.example\.com$,DOMAIN-REGEX-OUT"#.into(),
            "DOMAIN-WILDCARD,*.internal.example.com,DOMAIN-WILDCARD-OUT".into(),
            r#"PROCESS-NAME-REGEX,^fire.*x$,PROC-REGEX-OUT"#.into(),
            "PROCESS-PATH-WILDCARD,*/firefox.app/*,PROC-WILDCARD-OUT".into(),
            "MATCH,REJECT".into(),
        ])
        .unwrap();

        let domain_regex = Metadata {
            host: Some("api,v2.example.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&domain_regex), Some("DOMAIN-REGEX-OUT"));

        let domain_wildcard = Metadata {
            host: Some("foo.internal.example.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&domain_wildcard), Some("DOMAIN-WILDCARD-OUT"));

        let proc_regex = Metadata {
            process: "firefox".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&proc_regex), Some("PROC-REGEX-OUT"));

        let proc_wildcard = Metadata {
            process_path: "/applications/firefox.app/contents/macos/firefox".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&proc_wildcard), Some("PROC-WILDCARD-OUT"));
    }

    #[test]
    fn rule_set_matches_logic_variants() {
        let and_rules = compile_rule_set(&[
            "AND,((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535)),DIRECT".into(),
        ])
        .unwrap();
        let and_match = Metadata {
            host: Some("baidu.com".into()),
            network: NetworkKind::Tcp,
            dst_port: Some(20000),
            ..Metadata::default()
        };
        assert_eq!(and_rules.target_for(&and_match), Some("DIRECT"));

        let or_rules = compile_rule_set(&[
            "OR,((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535)),DIRECT".into(),
        ])
        .unwrap();
        let or_match = Metadata {
            network: NetworkKind::Tcp,
            ..Metadata::default()
        };
        assert_eq!(or_rules.target_for(&or_match), Some("DIRECT"));

        let not_rules = compile_rule_set(&["NOT,((DST-PORT,6000-6500)),REJECT".into()]).unwrap();
        let blocked = Metadata {
            dst_port: Some(6100),
            ..Metadata::default()
        };
        assert_eq!(not_rules.target_for(&blocked), None);

        let allowed = Metadata {
            dst_port: Some(7000),
            ..Metadata::default()
        };
        assert_eq!(not_rules.target_for(&allowed), Some("REJECT"));
    }

    #[test]
    fn rule_set_matches_nested_logic_variants() {
        let rules = compile_rule_set(&[
            "AND,((OR,((DOMAIN,example.com),(DOMAIN,example.org))),(NETWORK,TCP)),DIRECT".into(),
        ])
        .unwrap();
        let match_metadata = Metadata {
            host: Some("example.org".into()),
            network: NetworkKind::Tcp,
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&match_metadata), Some("DIRECT"));
    }

    #[test]
    fn rule_set_matches_sub_rule_variants() {
        let rules = compile_rule_table(
            &[
                "DOMAIN-SUFFIX,example.com,DIRECT".into(),
                "SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),branch-a".into(),
                "MATCH,REJECT".into(),
            ],
            &BTreeMap::from([(
                "branch-a".into(),
                vec![
                    "DOMAIN,google.com,PROXY".into(),
                    "DOMAIN,baidu.com,DIRECT".into(),
                ],
            )]),
        )
        .unwrap();

        let from_default = Metadata {
            host: Some("foo.example.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&from_default), Some("DIRECT"));

        let from_branch = Metadata {
            host: Some("google.com".into()),
            network: NetworkKind::Tcp,
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&from_branch), Some("PROXY"));
    }

    #[test]
    fn rule_set_uses_special_rules_when_present() {
        let rules = compile_rule_table(
            &["DOMAIN,default.com,DIRECT".into()],
            &BTreeMap::from([(
                "custom".into(),
                vec!["DOMAIN,branch.com,PROXY".into()],
            )]),
        )
        .unwrap();

        let mut metadata = Metadata {
            host: Some("branch.com".into()),
            ..Metadata::default()
        };
        metadata.special_rules = "custom".into();
        assert_eq!(rules.target_for(&metadata), Some("PROXY"));

        let missing = Metadata {
            host: Some("default.com".into()),
            special_rules: "missing".into(),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&missing), Some("DIRECT"));
    }

    #[test]
    fn rule_set_matches_rule_set_provider_variants() {
        let providers = BTreeMap::from([(
            "rule1".into(),
            RuleProviderDefinition {
                provider_type: "inline".into(),
                behavior: "domain".into(),
                payload: vec![".example.com".into()],
                ..RuleProviderDefinition::default()
            },
        )]);
        let empty_sources = BTreeMap::<String, String>::new();
        let rules = compile_rule_table_with_providers(
            &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
            &BTreeMap::new(),
            &providers,
            &empty_sources,
            &empty_sources,
        )
        .unwrap();

        let metadata = Metadata {
            host: Some("api.example.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&metadata), Some("PROXY"));
    }

    #[test]
    fn rule_set_matches_classical_rule_provider_variants() {
        let providers = BTreeMap::from([(
            "rule1".into(),
            RuleProviderDefinition {
                provider_type: "inline".into(),
                behavior: "classical".into(),
                payload: vec!["DOMAIN-KEYWORD,google".into(), "NETWORK,UDP".into()],
                ..RuleProviderDefinition::default()
            },
        )]);
        let empty_sources = BTreeMap::<String, String>::new();
        let rules = compile_rule_table_with_providers(
            &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
            &BTreeMap::new(),
            &providers,
            &empty_sources,
            &empty_sources,
        )
        .unwrap();

        let metadata = Metadata {
            host: Some("www.google.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&metadata), Some("PROXY"));
    }

    #[test]
    fn rule_set_loads_text_rule_provider_content() {
        let providers = BTreeMap::from([(
            "rule1".into(),
            RuleProviderDefinition {
                provider_type: "file".into(),
                behavior: "ipcidr".into(),
                format: "text".into(),
                path: "rule1.txt".into(),
                ..RuleProviderDefinition::default()
            },
        )]);
        let rules = compile_rule_table_with_providers(
            &["RULE-SET,rule1,PROXY".into()],
            &BTreeMap::new(),
            &providers,
            &BTreeMap::from([("rule1.txt".into(), "1.1.1.0/24\n".into())]),
            &BTreeMap::<String, String>::new(),
        )
        .unwrap();

        let metadata = Metadata {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&metadata), Some("PROXY"));
    }

    #[test]
    fn rule_set_loads_mrs_domain_rule_provider_content() {
        let mrs = convert_ruleset_content(
            b"example.com\n+.suffix.test\n",
            mihomo_config::RuleProviderBehavior::Domain,
            mihomo_config::RuleProviderFormat::Text,
        )
        .unwrap();
        let providers = BTreeMap::from([(
            "rule1".into(),
            RuleProviderDefinition {
                provider_type: "file".into(),
                behavior: "domain".into(),
                format: "mrs".into(),
                path: "rule1.mrs".into(),
                ..RuleProviderDefinition::default()
            },
        )]);
        let rules = compile_rule_table_with_providers(
            &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
            &BTreeMap::new(),
            &providers,
            &BTreeMap::from([("rule1.mrs".into(), mrs)]),
            &BTreeMap::<String, Vec<u8>>::new(),
        )
        .unwrap();

        let exact = Metadata {
            host: Some("example.com".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&exact), Some("PROXY"));

        let suffix = Metadata {
            host: Some("api.suffix.test".into()),
            ..Metadata::default()
        };
        assert_eq!(rules.target_for(&suffix), Some("PROXY"));
    }

    #[test]
    fn convert_ruleset_content_round_trips_mrs_formats() {
        let domain_mrs = convert_ruleset_content(
            b".example.com\nsub.test\n",
            mihomo_config::RuleProviderBehavior::Domain,
            mihomo_config::RuleProviderFormat::Text,
        )
        .unwrap();
        let domain_text = String::from_utf8(
            convert_ruleset_content(
                &domain_mrs,
                mihomo_config::RuleProviderBehavior::Domain,
                mihomo_config::RuleProviderFormat::Mrs,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(domain_text.contains("+.example.com"));
        assert!(domain_text.contains("sub.test"));

        let ip_mrs = convert_ruleset_content(
            b"1.1.1.0/24\n2001:db8::/126\n",
            mihomo_config::RuleProviderBehavior::IpCidr,
            mihomo_config::RuleProviderFormat::Text,
        )
        .unwrap();
        let ip_text = String::from_utf8(
            convert_ruleset_content(
                &ip_mrs,
                mihomo_config::RuleProviderBehavior::IpCidr,
                mihomo_config::RuleProviderFormat::Mrs,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(ip_text.contains("1.1.1.0/24"));
        assert!(ip_text.contains("2001:db8::/126"));
    }

    #[test]
    fn invalid_cidr_is_reported() {
        assert_eq!(
            compile_rule_set(&["IP-CIDR,1.1.1.1/99,DIRECT".into()]).unwrap_err(),
            RuleError::InvalidCidr("1.1.1.1/99".into())
        );
    }

    #[test]
    fn invalid_local_metadata_rules_are_reported() {
        assert_eq!(
            compile_rule_set(&["DST-PORT,70000,DIRECT".into()]).unwrap_err(),
            RuleError::InvalidPort("70000".into())
        );
        assert_eq!(
            compile_rule_set(&["DSCP,64,DIRECT".into()]).unwrap_err(),
            RuleError::InvalidDscp("64".into())
        );
        assert_eq!(
            compile_rule_set(&["IN-TYPE,SOCKS/UNKNOWN,DIRECT".into()]).unwrap_err(),
            RuleError::InvalidInType("SOCKS/UNKNOWN".into())
        );
        assert_eq!(
            compile_rule_set(&["IN-USER,/,DIRECT".into()]).unwrap_err(),
            RuleError::InvalidInUser("/".into())
        );
    }

    #[test]
    fn invalid_logic_rules_are_reported() {
        assert_eq!(
            compile_rule_set(&["NOT,(DST-PORT,5600-6666),DIRECT".into()]).unwrap_err(),
            RuleError::InvalidLogic("(DST-PORT,5600-6666)".into())
        );
        assert_eq!(
            compile_rule_set(&["NOT,((DST-PORT,5600-6666),(DOMAIN,baidu.com)),DIRECT".into()])
                .unwrap_err(),
            RuleError::InvalidLogic("((DST-PORT,5600-6666),(DOMAIN,baidu.com))".into())
        );
    }

    #[test]
    fn invalid_sub_rules_are_reported() {
        assert_eq!(
            compile_rule_table(
                &["SUB-RULE,(DOMAIN,google.com),branch-a".into()],
                &BTreeMap::new(),
            )
            .unwrap_err(),
            RuleError::SubRuleNotFound("branch-a".into())
        );

        assert_eq!(
            compile_rule_table(
                &["MATCH,DIRECT".into()],
                &BTreeMap::from([("".into(), vec!["MATCH,DIRECT".into()])]),
            )
            .unwrap_err(),
            RuleError::EmptySubRuleName
        );

        assert_eq!(
            compile_rule_table(
                &["MATCH,DIRECT".into()],
                &BTreeMap::from([
                    ("a".into(), vec!["SUB-RULE,(DOMAIN,foo.com),b".into()]),
                    ("b".into(), vec!["SUB-RULE,(DOMAIN,bar.com),a".into()]),
                ]),
            )
            .unwrap_err(),
            RuleError::CircularSubRule("a->b->a".into())
        );
    }

    #[test]
    fn empty_rule_set_is_supported() {
        let rules = RuleSet::default();
        assert!(rules.is_empty());
        assert_eq!(rules.len(), 0);
        assert_eq!(rules.target_for(&Metadata::default()), None);
    }
}
