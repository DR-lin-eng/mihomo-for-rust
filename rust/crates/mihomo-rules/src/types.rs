use mihomo_core::{RewriteStage, SubsystemManifest};

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

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-rules",
    go_areas: &["rules", "rules/provider"],
    contracts: &["rule matching", "policy selection", "provider updates"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}
