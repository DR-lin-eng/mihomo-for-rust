//! Small protobuf reader for the standard geosite.dat/geoip.dat assets.
//!
//! Mihomo's Go runtime exposes these databases as virtual rule providers. The
//! Rust runtime uses the same rule compiler, so decoding them into inline
//! classical providers keeps GEOSITE/GEOIP rules compatible with OpenClash
//! layouts without adding a protobuf runtime dependency.
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mihomo_config::{RuleProviderDefinition, RuleProviderVehicleType};

use crate::types::RuleError;

#[derive(Clone, Debug)]
struct DomainRecord {
    kind: u64,
    value: String,
    attributes: BTreeSet<String>,
}

pub fn geosite_provider_from_bytes(
    data: &[u8],
    requested: &str,
) -> Result<RuleProviderDefinition, RuleError> {
    let (name, attrs) = split_name_attributes(requested);
    for entry in repeated_messages(data, 1)? {
        if !entry_code(entry)?.eq_ignore_ascii_case(name) {
            continue;
        }
        let (_, domains) = parse_geosite_entry(entry)?;
        let payload = domains
            .into_iter()
            .filter(|domain| attrs.iter().all(|attr| domain.attributes.contains(attr)))
            .map(domain_to_rule)
            .collect::<Vec<_>>();
        if payload.is_empty() {
            return Err(RuleError::InvalidRuleProviderContent(format!(
                "geosite list {requested} contains no matching domains"
            )));
        }
        return Ok(classical_provider(payload));
    }
    Err(RuleError::RuleProviderNotFound(requested.to_owned()))
}

pub fn geoip_provider_from_bytes(
    data: &[u8],
    requested: &str,
) -> Result<RuleProviderDefinition, RuleError> {
    let name = requested.trim();
    for entry in repeated_messages(data, 1)? {
        if !entry_code(entry)?.eq_ignore_ascii_case(name) {
            continue;
        }
        let (_, cidrs) = parse_geoip_entry(entry)?;
        if cidrs.is_empty() {
            return Err(RuleError::InvalidRuleProviderContent(format!(
                "geoip list {requested} contains no CIDRs"
            )));
        }
        let payload = cidrs
            .into_iter()
            .map(|(ip, prefix)| match ip {
                IpAddr::V4(ip) => format!("IP-CIDR,{ip}/{prefix}"),
                IpAddr::V6(ip) => format!("IP-CIDR6,{ip}/{prefix}"),
            })
            .collect();
        return Ok(classical_provider(payload));
    }
    Err(RuleError::RuleProviderNotFound(requested.to_owned()))
}

fn classical_provider(payload: Vec<String>) -> RuleProviderDefinition {
    RuleProviderDefinition {
        provider_type: RuleProviderVehicleType::Inline.as_str().to_owned(),
        behavior: "classical".to_owned(),
        format: "yaml".to_owned(),
        payload,
        ..RuleProviderDefinition::default()
    }
}

fn split_name_attributes(value: &str) -> (&str, Vec<String>) {
    let mut parts = value.split('@');
    let name = parts.next().unwrap_or_default().trim();
    let attrs = parts
        .map(|attr| attr.trim().to_ascii_lowercase())
        .filter(|attr| !attr.is_empty())
        .collect();
    (name, attrs)
}

fn domain_to_rule(domain: DomainRecord) -> String {
    match domain.kind {
        1 => format!("DOMAIN-REGEX,{}", domain.value),
        2 => format!("DOMAIN-SUFFIX,{}", domain.value),
        3 => format!("DOMAIN,{}", domain.value),
        _ => format!("DOMAIN-KEYWORD,{}", domain.value),
    }
}

fn entry_code(data: &[u8]) -> Result<&str, RuleError> {
    for (field, wire, value) in fields(data)? {
        if field == 1 && wire == 2 {
            return std::str::from_utf8(value).map_err(|error| invalid(&error.to_string()));
        }
    }
    Ok("")
}

fn parse_geosite_entry(data: &[u8]) -> Result<(String, Vec<DomainRecord>), RuleError> {
    let mut code = String::new();
    let mut domains = Vec::new();
    for (field, wire, value) in fields(data)? {
        match (field, wire) {
            (1, 2) => code = text(&value)?,
            (2, 2) => domains.push(parse_domain(&value)?),
            _ => {}
        }
    }
    Ok((code, domains))
}

fn parse_domain(data: &[u8]) -> Result<DomainRecord, RuleError> {
    let mut kind = 0;
    let mut value = String::new();
    let mut attributes = BTreeSet::new();
    for (field, wire, bytes) in fields(data)? {
        match (field, wire) {
            (1, 0) => kind = decode_varint(&bytes)?,
            (2, 2) => value = text(&bytes)?,
            (3, 2) => {
                for (attr_field, attr_wire, attr) in fields(&bytes)? {
                    if attr_field == 1 && attr_wire == 2 {
                        attributes.insert(text(&attr)?.to_ascii_lowercase());
                    }
                }
            }
            _ => {}
        }
    }
    if value.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent(
            "geosite domain value is empty".to_owned(),
        ));
    }
    Ok(DomainRecord {
        kind,
        value,
        attributes,
    })
}

fn parse_geoip_entry(data: &[u8]) -> Result<(String, Vec<(IpAddr, u8)>), RuleError> {
    let mut code = String::new();
    let mut cidrs = Vec::new();
    for (field, wire, value) in fields(data)? {
        match (field, wire) {
            (1, 2) => code = text(&value)?,
            (2, 2) => {
                let mut ip = None;
                let mut prefix = None;
                for (cidr_field, cidr_wire, cidr_value) in fields(&value)? {
                    match (cidr_field, cidr_wire) {
                        (1, 2) => ip = Some(cidr_value),
                        (2, 0) => prefix = Some(decode_varint(&cidr_value)? as u8),
                        _ => {}
                    }
                }
                let Some(ip) = ip else { continue };
                let ip = match ip.len() {
                    4 => IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                    16 => {
                        let mut octets = [0_u8; 16];
                        octets.copy_from_slice(&ip);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => {
                        return Err(RuleError::InvalidRuleProviderContent(
                            "geoip CIDR address has invalid length".to_owned(),
                        ))
                    }
                };
                if let Some(prefix) = prefix {
                    cidrs.push((ip, prefix));
                }
            }
            _ => {}
        }
    }
    Ok((code, cidrs))
}

fn text(value: &[u8]) -> Result<String, RuleError> {
    String::from_utf8(value.to_owned())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))
}

fn repeated_messages(data: &[u8], wanted_field: u32) -> Result<Vec<&[u8]>, RuleError> {
    Ok(fields(data)?
        .into_iter()
        .filter_map(|(field, wire, value)| (field == wanted_field && wire == 2).then_some(value))
        .collect())
}

fn fields(data: &[u8]) -> Result<Vec<(u32, u8, &[u8])>, RuleError> {
    let mut pos = 0;
    let mut result = Vec::new();
    while pos < data.len() {
        let key = decode_varint_from(data, &mut pos)?;
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        if field == 0 {
            return Err(invalid("protobuf field number is zero"));
        }
        let value = match wire {
            0 => {
                let start = pos;
                decode_varint_from(data, &mut pos)?;
                &data[start..pos]
            }
            1 => take(data, &mut pos, 8)?,
            2 => {
                let len = usize::try_from(decode_varint_from(data, &mut pos)?)
                    .map_err(|_| invalid("protobuf length overflow"))?;
                take(data, &mut pos, len)?
            }
            5 => take(data, &mut pos, 4)?,
            _ => return Err(invalid("unsupported protobuf wire type")),
        };
        result.push((field, wire, value));
    }
    Ok(result)
}

fn decode_varint(bytes: &[u8]) -> Result<u64, RuleError> {
    let mut pos = 0;
    decode_varint_from(bytes, &mut pos)
}

fn decode_varint_from(bytes: &[u8], pos: &mut usize) -> Result<u64, RuleError> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| invalid("truncated protobuf varint"))?;
        *pos += 1;
        if shift == 63 && byte > 1 {
            return Err(invalid("protobuf varint overflow"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("protobuf varint is too long"))
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], RuleError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| invalid("protobuf length overflow"))?;
    let value = bytes
        .get(*pos..end)
        .ok_or_else(|| invalid("truncated protobuf field"))?;
    *pos = end;
    Ok(value)
}

fn invalid(message: &str) -> RuleError {
    RuleError::InvalidRuleProviderContent(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }
    fn bytes(field: u32, data: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from(field << 3 | 2));
        out.extend_from_slice(&varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }
    fn number(field: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(field << 3));
        out.extend_from_slice(&varint(value));
        out
    }

    #[test]
    fn decodes_standard_geosite_types_and_attributes() {
        let attr = bytes(3, &bytes(1, b"ads"));
        let mut domain = number(1, 2);
        domain.extend(bytes(2, b"example.cn"));
        domain.extend(attr);
        let mut site = bytes(1, b"CN");
        site.extend(bytes(2, &domain));
        let data = bytes(1, &site);
        let provider = geosite_provider_from_bytes(&data, "cn@ads").unwrap();
        assert_eq!(provider.provider_type, "inline");
        assert!(provider
            .payload
            .iter()
            .any(|line| line == "DOMAIN-SUFFIX,example.cn"));
    }

    #[test]
    fn decodes_standard_geoip_cidrs() {
        let mut cidr = bytes(1, &[1, 2, 3, 0]);
        cidr.extend(number(2, 24));
        let mut entry = bytes(1, b"CN");
        entry.extend(bytes(2, &cidr));
        let provider = geoip_provider_from_bytes(&bytes(1, &entry), "cn").unwrap();
        assert_eq!(provider.payload, vec!["IP-CIDR,1.2.3.0/24"]);
    }
}

#[cfg(test)]
mod memory_regressions {
    use super::*;
    #[test]
    fn rejects_varint_overflow_without_wrapping_the_value() {
        assert!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]).is_err()
        );
    }
    #[test]
    fn unknown_categories_do_not_materialize_domain_records() {
        // An unrelated category contains a domain with invalid UTF-8. The
        // requested list must be decoded independently of that category.
        let data = [
            0x0a, 0x0b, 0x0a, 0x02, b'x', b'x', 0x12, 0x05, 0x08, 0x02, 0x12, 0x01, 0xff, 0x0a,
            0x13, 0x0a, 0x02, b'c', b'n', 0x12, 0x0d, 0x08, 0x02, 0x12, 0x09, b'a', b'.', b'e',
            b'x', b'a', b'm', b'p', b'l', b'e',
        ];
        let provider = geosite_provider_from_bytes(&data, "cn").unwrap();
        assert_eq!(provider.payload, ["DOMAIN-SUFFIX,a.example"]);
    }
}
