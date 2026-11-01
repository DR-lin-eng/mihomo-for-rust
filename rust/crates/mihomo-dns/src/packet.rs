use std::net::{IpAddr, Ipv4Addr};

use crate::{DnsError, DnsRecordType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedDnsQuery {
    pub(crate) request_id: u16,
    pub(crate) flags: u16,
    pub(crate) query_type: DnsRecordType,
    pub(crate) host: String,
    pub(crate) question: Vec<u8>,
}

pub(crate) fn build_dns_query(
    host: &str,
    query_type: DnsRecordType,
    request_id: u16,
) -> Result<Vec<u8>, DnsError> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.extend_from_slice(&0x0100_u16.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());

    for label in host.trim_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > u8::MAX as usize {
            return Err(DnsError::DnsProtocol(format!("label too long: {label}")));
        }
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&query_type.code().to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    Ok(payload)
}

pub(crate) fn parse_dns_response(
    message: &[u8],
    request_id: u16,
    query_type: DnsRecordType,
) -> Result<Vec<IpAddr>, DnsError> {
    if message.len() < 12 {
        return Err(DnsError::DnsProtocol("response too short".to_owned()));
    }
    let response_id = u16::from_be_bytes([message[0], message[1]]);
    if response_id != request_id {
        return Err(DnsError::DnsProtocol("mismatched response id".to_owned()));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::DnsProtocol("response bit missing".to_owned()));
    }
    if flags & 0x000F != 0 {
        return Ok(Vec::new());
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;

    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_name(message, offset)?;
        offset = offset
            .checked_add(4)
            .ok_or_else(|| DnsError::DnsProtocol("question overflow".to_owned()))?;
        if offset > message.len() {
            return Err(DnsError::DnsProtocol("question exceeds buffer".to_owned()));
        }
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(DnsError::DnsProtocol("answer header exceeds buffer".to_owned()));
        }
        let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let rd_length = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + rd_length > message.len() {
            return Err(DnsError::DnsProtocol("answer data exceeds buffer".to_owned()));
        }
        if rr_type == query_type.code() {
            match query_type {
                DnsRecordType::A if rd_length == 4 => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        message[offset],
                        message[offset + 1],
                        message[offset + 2],
                        message[offset + 3],
                    )));
                }
                DnsRecordType::Aaaa if rd_length == 16 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&message[offset..offset + 16]);
                    ips.push(IpAddr::from(octets));
                }
                _ => {}
            }
        }
        offset += rd_length;
    }

    Ok(ips)
}

pub(crate) fn parse_dns_query_packet(packet: &[u8]) -> Result<ParsedDnsQuery, DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::DnsProtocol("query too short".to_owned()));
    }
    let request_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if question_count != 1 {
        return Err(DnsError::DnsProtocol(format!(
            "unsupported question count: {question_count}"
        )));
    }

    let mut offset = 12;
    let host = read_name_string(packet, &mut offset)?;
    if offset + 4 > packet.len() {
        return Err(DnsError::DnsProtocol("query question truncated".to_owned()));
    }
    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    if qclass != 1 {
        return Err(DnsError::DnsProtocol(format!(
            "unsupported query class: {qclass}"
        )));
    }
    offset += 4;
    let query_type = match qtype {
        1 => DnsRecordType::A,
        28 => DnsRecordType::Aaaa,
        other => DnsRecordType::Other(other),
    };
    Ok(ParsedDnsQuery {
        request_id,
        flags,
        query_type,
        host,
        question: packet[12..offset].to_vec(),
    })
}

pub(crate) fn build_dns_response(
    query: &ParsedDnsQuery,
    ttl_secs: u32,
    ips: &[IpAddr],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&query.request_id.to_be_bytes());
    let response_flags = 0x8000_u16 | 0x0080_u16 | (query.flags & 0x0100);
    payload.extend_from_slice(&response_flags.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&(ips.len() as u16).to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&query.question);

    for ip in ips {
        payload.extend_from_slice(&0xC00C_u16.to_be_bytes());
        payload.extend_from_slice(&query.query_type.code().to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&ttl_secs.to_be_bytes());
        match ip {
            IpAddr::V4(ip) => {
                payload.extend_from_slice(&4_u16.to_be_bytes());
                payload.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                payload.extend_from_slice(&16_u16.to_be_bytes());
                payload.extend_from_slice(&ip.octets());
            }
        }
    }
    payload
}

pub(crate) fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    let mut jumps = 0;
    loop {
        let Some(&length) = message.get(offset) else {
            return Err(DnsError::DnsProtocol("name exceeds buffer".to_owned()));
        };
        if length & 0xC0 == 0xC0 {
            if offset + 1 >= message.len() {
                return Err(DnsError::DnsProtocol("compressed name truncated".to_owned()));
            }
            return Ok(offset + 2);
        }
        if length == 0 {
            return Ok(offset + 1);
        }
        offset = offset
            .checked_add(1 + length as usize)
            .ok_or_else(|| DnsError::DnsProtocol("name overflow".to_owned()))?;
        jumps += 1;
        if jumps > 128 {
            return Err(DnsError::DnsProtocol("name compression loop".to_owned()));
        }
    }
}

pub(crate) fn read_name_string(packet: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut labels = Vec::new();
    loop {
        let Some(&length) = packet.get(*offset) else {
            return Err(DnsError::DnsProtocol("query name exceeds buffer".to_owned()));
        };
        *offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xC0 != 0 {
            return Err(DnsError::DnsProtocol(
                "compressed query names are not supported".to_owned(),
            ));
        }
        let end = offset
            .checked_add(length as usize)
            .ok_or_else(|| DnsError::DnsProtocol("query name overflow".to_owned()))?;
        if end > packet.len() {
            return Err(DnsError::DnsProtocol("query name exceeds buffer".to_owned()));
        }
        labels.push(String::from_utf8_lossy(&packet[*offset..end]).into_owned());
        *offset = end;
    }
    Ok(labels.join("."))
}

/// Validate the response envelope without decoding or rewriting record data.
pub(crate) fn validate_dns_reply(query: &[u8], response: &[u8]) -> Result<(), DnsError> {
    let expected = parse_dns_query_packet(query)?;
    let actual = parse_dns_query_packet(response)?;
    if actual.flags & 0x8000 == 0 || actual.request_id != expected.request_id
        || actual.query_type != expected.query_type || !actual.host.eq_ignore_ascii_case(&expected.host)
    {
        return Err(DnsError::DnsProtocol("mismatched DNS response".into()));
    }
    Ok(())
}

pub fn build_servfail_response(packet: &[u8]) -> Result<Vec<u8>, DnsError> {
    let query = parse_dns_query_packet(packet)?;
    let mut response = build_dns_response(&query, 0, &[]);
    response[3] = (response[3] & 0xf0) | 2;
    Ok(response)
}
