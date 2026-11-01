use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use mihomo_config::{
    RuleProviderBehavior, RuleProviderDefinition, RuleProviderFormat, RuleProviderVehicleType,
};
use serde::Deserialize;

use crate::mrs::{
    mrs_behavior_byte, read_domain_mrs_body, read_domain_mrs_set, read_i64_be,
    read_ipcidr_mrs_body, read_ipcidr_mrs_set, read_u8, write_domain_mrs_body,
    write_ipcidr_mrs_body, DomainMrsSet, IpMrsSet,
};
use crate::types::RuleError;

const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1];

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

pub fn validate_rule_provider_content(
    content: &[u8],
    behavior: RuleProviderBehavior,
    format: RuleProviderFormat,
) -> Result<(), RuleError> {
    match format {
        RuleProviderFormat::Yaml => {
            let content = std::str::from_utf8(content)
                .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            let document = serde_yaml::from_str::<RuleProviderPayloadDocument>(content)
                .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
            let payload = if !document.rules.is_empty() {
                document.rules
            } else {
                document.payload
            };
            if payload.is_empty() {
                return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
            }
            Ok(())
        }
        RuleProviderFormat::Text => {
            let has_payload = std::str::from_utf8(content)
                .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?
                .lines()
                .map(str::trim)
                .any(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"));
            if !has_payload {
                return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
            }
            Ok(())
        }
        RuleProviderFormat::Mrs => validate_rule_provider_mrs(content, behavior),
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

pub(crate) enum DomainRuleProviderSource {
    CompactMrs(DomainMrsSet),
    Expanded(Vec<String>),
}

pub(crate) enum IpRuleProviderSource {
    CompactMrs(IpMrsSet),
    Expanded(Vec<String>),
}

pub(crate) fn load_domain_rule_provider_source_from_sources<S: AsRef<[u8]>>(
    provider: &RuleProviderDefinition,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<DomainRuleProviderSource, RuleError> {
    let format = provider
        .format_kind()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderFormat(provider.format.clone()))?;
    let content = match provider
        .vehicle_type()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderVehicle(provider.provider_type.clone()))?
    {
        RuleProviderVehicleType::Inline => {
            return Ok(DomainRuleProviderSource::Expanded(provider.payload.clone()))
        }
        RuleProviderVehicleType::File => file_contents.get(&provider.path).map(AsRef::as_ref),
        RuleProviderVehicleType::Http => http_contents
            .get(&provider.url)
            .map(AsRef::as_ref)
            .or_else(|| file_contents.get(&provider.path).map(AsRef::as_ref)),
    };
    let Some(content) = content else {
        return Ok(DomainRuleProviderSource::Expanded(Vec::new()));
    };

    match format {
        RuleProviderFormat::Mrs => {
            let set =
                decode_domain_rule_provider_set_from_mrs(content, RuleProviderBehavior::Domain)?;
            if set.contains_wildcards() {
                Ok(DomainRuleProviderSource::Expanded(set.to_rules()?))
            } else {
                Ok(DomainRuleProviderSource::CompactMrs(set))
            }
        }
        RuleProviderFormat::Yaml | RuleProviderFormat::Text => {
            Ok(DomainRuleProviderSource::Expanded(
                parse_rule_provider_bytes(content, RuleProviderBehavior::Domain, format)?,
            ))
        }
    }
}

pub(crate) fn load_ip_rule_provider_source_from_sources<S: AsRef<[u8]>>(
    provider: &RuleProviderDefinition,
    file_contents: &BTreeMap<String, S>,
    http_contents: &BTreeMap<String, S>,
) -> Result<IpRuleProviderSource, RuleError> {
    let format = provider
        .format_kind()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderFormat(provider.format.clone()))?;
    let content = match provider
        .vehicle_type()
        .ok_or_else(|| RuleError::UnsupportedRuleProviderVehicle(provider.provider_type.clone()))?
    {
        RuleProviderVehicleType::Inline => {
            return Ok(IpRuleProviderSource::Expanded(provider.payload.clone()))
        }
        RuleProviderVehicleType::File => file_contents.get(&provider.path).map(AsRef::as_ref),
        RuleProviderVehicleType::Http => http_contents
            .get(&provider.url)
            .map(AsRef::as_ref)
            .or_else(|| file_contents.get(&provider.path).map(AsRef::as_ref)),
    };
    let Some(content) = content else {
        return Ok(IpRuleProviderSource::Expanded(Vec::new()));
    };

    match format {
        RuleProviderFormat::Mrs => Ok(IpRuleProviderSource::CompactMrs(
            decode_ip_rule_provider_set_from_mrs(content, RuleProviderBehavior::IpCidr)?,
        )),
        RuleProviderFormat::Yaml | RuleProviderFormat::Text => Ok(IpRuleProviderSource::Expanded(
            parse_rule_provider_bytes(content, RuleProviderBehavior::IpCidr, format)?,
        )),
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
    let mut cursor = decode_rule_provider_mrs_cursor(content, behavior)?;
    match behavior {
        RuleProviderBehavior::Domain => read_domain_mrs_body(&mut cursor),
        RuleProviderBehavior::IpCidr => read_ipcidr_mrs_body(&mut cursor),
        RuleProviderBehavior::Classical => unreachable!(),
    }
}

fn decode_domain_rule_provider_set_from_mrs(
    content: &[u8],
    behavior: RuleProviderBehavior,
) -> Result<DomainMrsSet, RuleError> {
    let mut cursor = decode_rule_provider_mrs_cursor(content, behavior)?;
    read_domain_mrs_set(&mut cursor)
}

fn decode_ip_rule_provider_set_from_mrs(
    content: &[u8],
    behavior: RuleProviderBehavior,
) -> Result<IpMrsSet, RuleError> {
    let mut cursor = decode_rule_provider_mrs_cursor(content, behavior)?;
    read_ipcidr_mrs_set(&mut cursor)
}

fn validate_rule_provider_mrs(
    content: &[u8],
    behavior: RuleProviderBehavior,
) -> Result<(), RuleError> {
    let _cursor = decode_rule_provider_mrs_cursor(content, behavior)?;
    Ok(())
}

fn decode_rule_provider_mrs_cursor(
    content: &[u8],
    behavior: RuleProviderBehavior,
) -> Result<Cursor<Vec<u8>>, RuleError> {
    match behavior {
        RuleProviderBehavior::Classical => {
            return Err(RuleError::UnsupportedRuleProviderFormat("mrs".into()))
        }
        RuleProviderBehavior::Domain | RuleProviderBehavior::IpCidr => {}
    }

    let mut cursor = Cursor::new(
        zstd::decode_all(Cursor::new(content))
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?,
    );

    let mut magic = [0_u8; 4];
    cursor
        .read_exact(&mut magic)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    if magic != MRS_MAGIC_BYTES {
        return Err(RuleError::InvalidRuleProviderContent(
            "invalid mrs magic".into(),
        ));
    }

    let encoded_behavior = read_u8(&mut cursor)?;
    if encoded_behavior != mrs_behavior_byte(behavior) {
        return Err(RuleError::InvalidRuleProviderContent(
            "mrs behavior does not match provider definition".into(),
        ));
    }

    let length = read_i64_be(&mut cursor)?;
    let _unused = read_i64_be(&mut cursor)?;
    if length < 0 {
        return Err(RuleError::InvalidRuleProviderContent(
            "mrs length is invalid".into(),
        ));
    }
    Ok(cursor)
}
