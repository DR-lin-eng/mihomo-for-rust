use std::collections::BTreeMap;
use std::sync::Arc;

use mihomo_config::{RuleProviderBehavior, RuleProviderDefinition};

use crate::engine::{
    CompiledRule, CompiledRuleProvider, CompiledRuleRuntime, RuleAction, RuleMatcher, RuleSet,
};
use crate::matcher_support::{
    compile_regex, normalize, parse_domain_provider_pattern, parse_in_types, parse_name_list,
    parse_network, Cidr, NumericRanges,
};
use crate::parser::{parse_rule, parse_rule_with_target};
use crate::provider_payload::{
    load_domain_rule_provider_source_from_sources, load_ip_rule_provider_source_from_sources,
    load_rule_provider_payload_from_sources, DomainRuleProviderSource, IpRuleProviderSource,
};
use crate::types::{RuleDefinition, RuleError, RuleType};

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
    let mut compiler = RuleTableCompiler::new(
        raw_sub_rules,
        raw_rule_providers,
        file_contents,
        http_contents,
    );
    let rules = compiler.compile_rule_lines(raw_rules)?;
    for name in raw_sub_rules.keys() {
        compiler.compile_sub_rule(name)?;
    }
    Ok(RuleSet::from_compiled_parts(
        rules,
        compiler.compiled_sub_rules,
    ))
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
        let smart_geodata = match raw.split(',').next().unwrap_or("").trim().to_ascii_uppercase().as_str() {
            "GEOSITE" => 1,
            "GEOIP" => 2,
            _ => 0,
        };
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
                    runtime: Arc::new(CompiledRuleRuntime::with_geodata(smart_geodata)),
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
                    runtime: Arc::new(CompiledRuleRuntime::with_geodata(smart_geodata)),
                })
            }
            _ => {
                let matcher = self.compile_matcher(&definition, true)?;
                Ok(CompiledRule {
                    rule_type: definition.rule_type,
                    payload: definition.payload,
                    action: RuleAction::Target(definition.target),
                    matcher,
                    runtime: Arc::new(CompiledRuleRuntime::with_geodata(smart_geodata)),
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
            RuleType::Not => {
                RuleMatcher::Not(Box::new(self.compile_logic_not(&definition.payload)?))
            }
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
                match self.load_domain_rule_provider_source(provider)? {
                    DomainRuleProviderSource::CompactMrs(set) => {
                        CompiledRuleProvider::DomainMrs(Arc::new(set))
                    }
                    DomainRuleProviderSource::Expanded(payload) => CompiledRuleProvider::Domain(
                        payload
                            .into_iter()
                            .map(|raw| parse_domain_provider_pattern(&raw))
                            .collect(),
                    ),
                }
            }
            RuleProviderBehavior::IpCidr => match self.load_ip_rule_provider_source(provider)? {
                IpRuleProviderSource::CompactMrs(set) => CompiledRuleProvider::IpMrs(set),
                IpRuleProviderSource::Expanded(payload) => {
                    let cidrs = payload
                        .into_iter()
                        .map(|raw| Cidr::parse(&raw))
                        .collect::<Result<Vec<_>, _>>()?;
                    CompiledRuleProvider::IpCidr(cidrs)
                }
            },
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

    fn load_domain_rule_provider_source(
        &self,
        provider: &RuleProviderDefinition,
    ) -> Result<DomainRuleProviderSource, RuleError> {
        load_domain_rule_provider_source_from_sources(
            provider,
            self.file_contents,
            self.http_contents,
        )
    }

    fn load_ip_rule_provider_source(
        &self,
        provider: &RuleProviderDefinition,
    ) -> Result<IpRuleProviderSource, RuleError> {
        load_ip_rule_provider_source_from_sources(provider, self.file_contents, self.http_contents)
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
