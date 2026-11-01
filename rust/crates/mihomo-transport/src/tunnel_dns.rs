use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DNS_SOURCE_PORT: u16 = 53_000;
const DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

use crate::TransportError;

pub(crate) trait TunnelDnsDatagramIo {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<()>;
    fn recv_datagram_timeout(&mut self, timeout: Duration) -> io::Result<(SocketAddr, Vec<u8>)>;
}

pub(crate) fn resolve_ipv4_host_with_datagram_io(
    io: &mut dyn TunnelDnsDatagramIo,
    nameservers: &[String],
    host: &str,
    proxy_label: &str,
) -> Result<Ipv4Addr, TransportError> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy_label.to_owned(),
            feature: format!("ipv6 remote dns targets are not implemented: {host}"),
        });
    }
    if nameservers.is_empty() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy_label.to_owned(),
            feature: "remote-dns-resolve currently requires explicit dns servers".to_owned(),
        });
    }

    let mut last_err = None;
    for raw_server in nameservers {
        let nameserver = match parse_udp_nameserver(raw_server, proxy_label) {
            Ok(value) => value,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        let request_id = next_request_id();
        let query = build_dns_query(host, request_id, proxy_label)?;
        if let Err(err) = io.send_datagram(nameserver, &query) {
            last_err = Some(TransportError::from(err));
            continue;
        }
        match await_dns_response(io, nameserver, request_id, host, proxy_label) {
            Ok(Some(ip)) => return Ok(ip),
            Ok(None) => {
                last_err = Some(TransportError::Io {
                    kind: io::ErrorKind::NotFound,
                    message: format!("{proxy_label} remote dns returned no ipv4 answer for {host}"),
                });
            }
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| TransportError::Io {
        kind: io::ErrorKind::NotFound,
        message: format!("{proxy_label} remote dns failed to resolve host: {host}"),
    }))
}

pub(crate) fn parse_udp_nameserver(
    raw: &str,
    proxy_label: &str,
) -> Result<SocketAddr, TransportError> {
    let endpoint = raw.split('#').next().unwrap_or(raw).trim();
    if endpoint.is_empty() {
        return Err(TransportError::InvalidPlan(format!(
            "{proxy_label} dns nameserver is empty"
        )));
    }
    let endpoint = endpoint.strip_prefix("udp://").unwrap_or(endpoint).trim();
    if endpoint.contains("://") {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy_label.to_owned(),
            feature: format!("{proxy_label} remote dns nameserver is not implemented: {raw}"),
        });
    }
    let normalized = normalize_host_port(endpoint, 53);
    normalized
        .to_socket_addrs()
        .map_err(TransportError::from)?
        .find_map(|addr| match addr {
            SocketAddr::V4(_) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| TransportError::UnsupportedFeature {
            proxy: proxy_label.to_owned(),
            feature: format!(
                "{proxy_label} remote dns nameserver has no resolvable ipv4 address: {raw}"
            ),
        })
}

pub(crate) fn build_dns_query(
    host: &str,
    request_id: u16,
    proxy_label: &str,
) -> Result<Vec<u8>, TransportError> {
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
            return Err(TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns label too long: {label}"
            )));
        }
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    Ok(payload)
}

pub(crate) fn parse_dns_a_response(
    message: &[u8],
    request_id: u16,
    proxy_label: &str,
) -> Result<Option<Ipv4Addr>, TransportError> {
    if message.len() < 12 {
        return Err(TransportError::InvalidPlan(format!(
            "{proxy_label} remote dns response too short"
        )));
    }
    let response_id = u16::from_be_bytes([message[0], message[1]]);
    if response_id != request_id {
        return Err(TransportError::InvalidPlan(format!(
            "{proxy_label} remote dns response id mismatch"
        )));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err(TransportError::InvalidPlan(format!(
            "{proxy_label} remote dns response bit missing"
        )));
    }
    if flags & 0x000F != 0 {
        return Ok(None);
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_dns_name(message, offset, proxy_label)?;
        offset = offset.checked_add(4).ok_or_else(|| {
            TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns question overflow"
            ))
        })?;
        if offset > message.len() {
            return Err(TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns question exceeds buffer"
            )));
        }
    }
    for _ in 0..answer_count {
        offset = skip_dns_name(message, offset, proxy_label)?;
        if offset + 10 > message.len() {
            return Err(TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns answer header exceeds buffer"
            )));
        }
        let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let rd_length = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + rd_length > message.len() {
            return Err(TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns answer data exceeds buffer"
            )));
        }
        if rr_type == 1 && rd_length == 4 {
            return Ok(Some(Ipv4Addr::new(
                message[offset],
                message[offset + 1],
                message[offset + 2],
                message[offset + 3],
            )));
        }
        offset += rd_length;
    }
    Ok(None)
}

pub(crate) fn next_request_id() -> u16 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u16)
        .unwrap_or(1)
}

fn await_dns_response(
    io: &mut dyn TunnelDnsDatagramIo,
    nameserver: SocketAddr,
    request_id: u16,
    host: &str,
    proxy_label: &str,
) -> Result<Option<Ipv4Addr>, TransportError> {
    let started = std::time::Instant::now();
    while started.elapsed() < DNS_RESPONSE_TIMEOUT {
        let remaining = DNS_RESPONSE_TIMEOUT.saturating_sub(started.elapsed());
        let (source, payload) = match io.recv_datagram_timeout(remaining) {
            Ok(value) => value,
            Err(err)
                if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
            {
                continue;
            }
            Err(err) => return Err(TransportError::from(err)),
        };
        if source != nameserver {
            continue;
        }
        match parse_dns_a_response(&payload, request_id, proxy_label) {
            Ok(answer) => return Ok(answer),
            Err(_) => continue,
        }
    }
    Err(TransportError::Io {
        kind: io::ErrorKind::TimedOut,
        message: format!("{proxy_label} remote dns response timed out from {nameserver} for {host}"),
    })
}

fn normalize_host_port(endpoint: &str, default_port: u16) -> String {
    if endpoint.starts_with('[') {
        if endpoint.contains("]:") {
            endpoint.to_owned()
        } else {
            format!("{endpoint}:{default_port}")
        }
    } else if endpoint.rsplit_once(':').is_some() {
        endpoint.to_owned()
    } else {
        format!("{endpoint}:{default_port}")
    }
}

fn skip_dns_name(
    message: &[u8],
    mut offset: usize,
    proxy_label: &str,
) -> Result<usize, TransportError> {
    let mut jumps = 0;
    loop {
        let Some(&length) = message.get(offset) else {
            return Err(TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns name exceeds buffer"
            )));
        };
        if length & 0xC0 == 0xC0 {
            if offset + 1 >= message.len() {
                return Err(TransportError::InvalidPlan(format!(
                    "{proxy_label} remote dns compressed name truncated"
                )));
            }
            return Ok(offset + 2);
        }
        if length == 0 {
            return Ok(offset + 1);
        }
        offset = offset.checked_add(1 + length as usize).ok_or_else(|| {
            TransportError::InvalidPlan(format!("{proxy_label} remote dns name overflow"))
        })?;
        jumps += 1;
        if jumps > 128 {
            return Err(TransportError::InvalidPlan(format!(
                "{proxy_label} remote dns name compression loop"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_dns_query, parse_dns_a_response};

    #[test]
    fn dns_query_roundtrip_extracts_ipv4_answer() {
        let query = build_dns_query("example.com", 7, "<test>").unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&7_u16.to_be_bytes());
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&0xC00C_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[1, 1, 1, 1]);
        assert_eq!(
            parse_dns_a_response(&response, 7, "<test>").unwrap(),
            Some(std::net::Ipv4Addr::new(1, 1, 1, 1))
        );
    }
}
