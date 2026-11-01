use crate::types::{RuleDefinition, RuleError, RuleType};

pub fn parse_rule(raw: &str) -> Result<RuleDefinition, RuleError> {
    parse_rule_with_target(raw, true)
}

pub(crate) fn parse_rule_with_target(
    raw: &str,
    need_target: bool,
) -> Result<RuleDefinition, RuleError> {
    let segments = raw.split(',').map(str::trim).collect::<Vec<_>>();
    let Some(rule_type_raw) = segments.first().copied() else {
        return Err(RuleError::MissingType(raw.to_owned()));
    };

    if rule_type_raw.eq_ignore_ascii_case("GEOIP") {
        return parse_geoip_rule(raw, segments, need_target);
    }
    if rule_type_raw.eq_ignore_ascii_case("GEOSITE") {
        return parse_geosite_rule(raw, segments, need_target);
    }

    let rule_type = parse_rule_type(rule_type_raw)?;

    let mut payload = String::new();
    let mut target = String::new();
    let mut segments = segments;

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

fn parse_geoip_rule(
    raw: &str,
    segments: Vec<&str>,
    need_target: bool,
) -> Result<RuleDefinition, RuleError> {
    if segments.len() < 2 {
        return Err(RuleError::MissingPayload(raw.to_owned()));
    }

    let payload = segments.get(1).copied().unwrap_or_default();
    if payload.is_empty() {
        return Err(RuleError::MissingPayload(raw.to_owned()));
    }

    let target = if need_target {
        segments.get(2).copied().unwrap_or_default().to_owned()
    } else {
        String::new()
    };

    if need_target && target.is_empty() {
        return Err(RuleError::MissingTarget(raw.to_owned()));
    }

    Ok(RuleDefinition {
        rule_type: RuleType::RuleSet,
        payload: format!("{}_IP", payload.to_ascii_uppercase()),
        target,
    })
}

fn parse_geosite_rule(
    raw: &str,
    segments: Vec<&str>,
    need_target: bool,
) -> Result<RuleDefinition, RuleError> {
    if segments.len() < 2 {
        return Err(RuleError::MissingPayload(raw.to_owned()));
    }

    let payload = segments.get(1).copied().unwrap_or_default().trim();
    if payload.is_empty() {
        return Err(RuleError::MissingPayload(raw.to_owned()));
    }

    let target = if need_target {
        segments.get(2).copied().unwrap_or_default().to_owned()
    } else {
        String::new()
    };

    if need_target && target.is_empty() {
        return Err(RuleError::MissingTarget(raw.to_owned()));
    }

    Ok(RuleDefinition {
        rule_type: RuleType::RuleSet,
        payload: payload.to_owned(),
        target,
    })
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
