use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_core::{Metadata, NetworkKind, SessionKind};
use regex::Regex;

use crate::matcher_support::{
    eq_ignore_ascii_case, normalize, wildcard_matches, Cidr, NumericRanges,
};
use crate::mrs::{DomainMrsSet, IpMrsSet};
use crate::types::{RuleDefinition, RuleRuntimeExtraSnapshot, RuleType, RuntimeRuleSnapshot};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuleSet {
    rules: Arc<Vec<CompiledRule>>,
    sub_rules: Arc<BTreeMap<String, Vec<CompiledRule>>>,
}

impl RuleSet {
    pub(crate) fn from_compiled_parts(
        rules: Vec<CompiledRule>,
        sub_rules: BTreeMap<String, Vec<CompiledRule>>,
    ) -> Self {
        Self { rules: Arc::new(rules), sub_rules: Arc::new(sub_rules) }
    }

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

    /// Whether a missing real destination could change the ordered decision.
    /// Stop at an already definitive earlier rule to avoid unnecessary DNS.
    pub fn needs_destination_ip(&self, metadata:&Metadata)->bool {
        if metadata.dst_ip.is_some(){return false;}
        let selected=self.sub_rules.get(metadata.special_rules.as_str()).map(Vec::as_slice).unwrap_or(&self.rules);
        for rule in selected {
            if rule.runtime.disabled.load(Ordering::Relaxed){continue;}
            if rule.matcher.needs_destination_ip() || matches!(rule.action,RuleAction::SubRule(_)){return true;}
            if self.matching_rule(rule,metadata,false).is_some(){return false;}
        }
        false
    }

    /// Identity of the actual matched rule and its collection size. This uses
    /// the compiled matcher, including sub-rules and disabled-rule state.
    pub fn smart_rule_identity(&self,metadata:&Metadata)->Option<(String,usize)> {
        let selected=self.sub_rules.get(metadata.special_rules.as_str()).map(Vec::as_slice).unwrap_or(&self.rules);
        self.matching_rule_in(selected,metadata,false).map(|matched| {
            let kind=match matched.smart_geodata {1=>"GeoSite",2=>"GeoIP",_=>match matched.rule_type {RuleType::RuleSet=>"RuleSet",RuleType::Match=>"Match",_=>matched.rule_type.as_str()}};
            let payload=if matched.smart_geodata==2{matched.payload.strip_suffix("_IP").unwrap_or(matched.payload)}else{matched.payload};
            (if payload.is_empty(){kind.into()}else{format!("{kind} [{payload}]")},matched.collection_size)
        })
    }

    pub fn matched_rule_definition_and_record(
        &self,
        metadata: &Metadata,
    ) -> Option<RuleDefinition> {
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
                    smart_geodata: rule.runtime.smart_geodata,
                    collection_size: match &rule.matcher {
                        RuleMatcher::RuleSet(provider)=>match provider {
                            CompiledRuleProvider::Domain(v)=>v.len(),CompiledRuleProvider::DomainMrs(v)=>v.entry_count(),
                            CompiledRuleProvider::IpCidr(v)=>v.len(),CompiledRuleProvider::IpMrs(v)=>v.entry_count(),CompiledRuleProvider::Classical(v)=>v.len(),
                        },
                        _=>0,
                    },
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
pub(crate) struct CompiledRule {
    pub(crate) rule_type: RuleType,
    pub(crate) payload: String,
    pub(crate) action: RuleAction,
    pub(crate) matcher: RuleMatcher,
    pub(crate) runtime: Arc<CompiledRuleRuntime>,
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
pub(crate) enum RuleAction {
    Target(String),
    SubRule(String),
}

#[derive(Debug, Default)]
pub(crate) struct CompiledRuleRuntime {
    pub(crate) disabled: AtomicBool,
    // Fits next to disabled in the existing counter alignment padding. Keeping
    // it here avoids growing every compiled matcher for geodata provenance.
    pub(crate) smart_geodata: u8,
    hit_count: AtomicU64,
    hit_at_unix_ms: AtomicU64,
    miss_count: AtomicU64,
    miss_at_unix_ms: AtomicU64,
}

impl CompiledRuleRuntime {
    pub(crate) fn with_geodata(kind: u8) -> Self {
        Self {smart_geodata: kind, ..Self::default()}
    }

    pub(crate) fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        self.hit_at_unix_ms.store(now_unix_ms(), Ordering::Relaxed);
    }

    pub(crate) fn record_miss(&self) {
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
            smart_geodata: self.smart_geodata,
            hit_count: AtomicU64::new(snapshot.hit_count),
            hit_at_unix_ms: AtomicU64::new(snapshot.hit_at_unix_ms),
            miss_count: AtomicU64::new(snapshot.miss_count),
            miss_at_unix_ms: AtomicU64::new(snapshot.miss_at_unix_ms),
        }
    }
}

impl PartialEq for CompiledRuleRuntime {
    fn eq(&self, other: &Self) -> bool {
        self.smart_geodata == other.smart_geodata && self.snapshot() == other.snapshot()
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
    collection_size: usize,
    smart_geodata: u8,
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
pub(crate) enum RuleMatcher {
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

impl RuleMatcher {
    fn needs_destination_ip(&self)->bool {
        match self {
            Self::IpCidr(_)=>true,
            Self::And(v)|Self::Or(v)=>v.iter().any(Self::needs_destination_ip),
            Self::Not(v)=>v.needs_destination_ip(),
            Self::RuleSet(CompiledRuleProvider::IpCidr(_)|CompiledRuleProvider::IpMrs(_))=>true,
            Self::RuleSet(CompiledRuleProvider::Classical(v))=>v.iter().any(Self::needs_destination_ip),
            _=>false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompiledRuleProvider {
    Domain(Vec<DomainProviderPattern>),
    // The trie is immutable and shared by provider references. Keeping its
    // header behind Arc also bounds the size of every RuleMatcher variant.
    DomainMrs(Arc<DomainMrsSet>),
    IpCidr(Vec<Cidr>),
    IpMrs(IpMrsSet),
    Classical(Vec<RuleMatcher>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DomainProviderPattern {
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
            (Self::And(left), Self::And(right)) | (Self::Or(left), Self::Or(right)) => {
                left == right
            }
            (Self::Not(left), Self::Not(right)) => left == right,
            (Self::Match, Self::Match) => true,
            _ => false,
        }
    }
}

impl Eq for RuleMatcher {}

impl RuleMatcher {
    pub(crate) fn matches(&self, metadata: &Metadata) -> bool {
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
            Self::DomainRegex(regex) => metadata
                .rule_host()
                .is_some_and(|host| regex.is_match(host)),
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
            Self::Uid(ranges) => metadata
                .uid
                .is_some_and(|uid| ranges.contains(u64::from(uid))),
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
            Self::DomainMrs(set) => metadata.rule_host().is_some_and(|host| set.matches(host)),
            Self::IpCidr(cidrs) => metadata
                .dst_ip
                .is_some_and(|ip| cidrs.iter().any(|cidr| cidr.contains(ip))),
            Self::IpMrs(set) => metadata.dst_ip.is_some_and(|ip| set.matches(ip)),
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
