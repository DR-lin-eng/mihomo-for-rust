use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use mihomo_buf::ByteWindow;
use mihomo_dns::DnsRuntime;

use super::listener_udp_outbound;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Socks5UdpFrame {
    pub(super) target: String,
    pub(super) payload: Vec<u8>,
    pub(super) fragment_index: u8,
    pub(super) final_fragment: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Socks5UdpReassembly {
    pub(super) target: String,
    pub(super) highest_seen: u8,
    pub(super) final_index: Option<u8>,
    pub(super) parts: BTreeMap<u8, Vec<u8>>,
    pub(super) updated_at: Instant,
}

pub(super) fn parse_socks5_udp_frame(payload: &[u8]) -> io::Result<Socks5UdpFrame> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp frame too short",
        ));
    }
    if payload[0] != 0 || payload[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp reserved bytes must be zero",
        ));
    }
    let frag = payload[2];
    let fragment_index = frag & 0x7f;
    let final_fragment = (frag & 0x80) != 0;
    if frag != 0 && fragment_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp fragment index must be non-zero",
        ));
    }
    let atyp = payload[3];
    let mut offset = 4;
    let host = match atyp {
        0x01 => {
            if offset + 4 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv4 target truncated"));
            }
            let addr = std::net::Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            );
            offset += 4;
            addr.to_string()
        }
        0x03 => {
            let length = *payload
                .get(offset)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "domain length missing"))?
                as usize;
            offset += 1;
            if offset + length > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain target truncated"));
            }
            let host = String::from_utf8_lossy(&payload[offset..offset + length]).into_owned();
            offset += length;
            host
        }
        0x04 => {
            if offset + 16 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv6 target truncated"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported socks5 udp address type",
            ))
        }
    };
    if offset + 2 > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target port truncated",
        ));
    }
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok(Socks5UdpFrame {
        target: listener_udp_outbound::format_target(host.as_str(), port),
        payload: payload[offset..].to_vec(),
        fragment_index,
        final_fragment,
    })
}

pub(super) fn reassemble_socks5_udp_frame(
    states: &mut HashMap<SocketAddr, Socks5UdpReassembly>,
    peer_addr: SocketAddr,
    frame: Socks5UdpFrame,
) -> io::Result<Option<(String, Vec<u8>)>> {
    let now = Instant::now();
    states.retain(|_, state| now.duration_since(state.updated_at) <= Duration::from_secs(5));

    if frame.fragment_index == 0 {
        states.remove(&peer_addr);
        return Ok(Some((frame.target, frame.payload)));
    }

    let state = states.entry(peer_addr).or_insert_with(|| Socks5UdpReassembly {
        target: frame.target.clone(),
        highest_seen: 0,
        final_index: None,
        parts: BTreeMap::new(),
        updated_at: now,
    });

    if state.target != frame.target || (frame.fragment_index == 1 && state.parts.contains_key(&1))
    {
        *state = Socks5UdpReassembly {
            target: frame.target.clone(),
            highest_seen: 0,
            final_index: None,
            parts: BTreeMap::new(),
            updated_at: now,
        };
    }

    state.updated_at = now;
    state.highest_seen = state.highest_seen.max(frame.fragment_index);
    if frame.final_fragment {
        state.final_index = Some(frame.fragment_index);
    }
    state.parts.insert(frame.fragment_index, frame.payload);

    let Some(final_index) = state.final_index else {
        return Ok(None);
    };
    for expected in 1..=final_index {
        if !state.parts.contains_key(&expected) {
            return Ok(None);
        }
    }

    let mut payload = Vec::new();
    for expected in 1..=final_index {
        if let Some(part) = state.parts.get(&expected) {
            payload.extend_from_slice(part);
        }
    }
    let target = state.target.clone();
    states.remove(&peer_addr);
    Ok(Some((target, payload)))
}

pub(super) fn parse_socks5_udp_source_frame(
    payload: &[u8],
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp frame too short",
        ));
    }
    if payload[0] != 0 || payload[1] != 0 || payload[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socks5 udp frame header",
        ));
    }
    let atyp = payload[3];
    let mut offset = 4;
    let addr = match atyp {
        0x01 => {
            if offset + 4 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv4 source truncated"));
            }
            let addr = std::net::Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            );
            offset += 4;
            std::net::IpAddr::V4(addr)
        }
        0x04 => {
            if offset + 16 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv6 source truncated"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        0x03 => {
            let length = *payload
                .get(offset)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "domain length missing"))?
                as usize;
            offset += 1;
            if offset + length > payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain source truncated",
                ));
            }
            let host = String::from_utf8_lossy(&payload[offset..offset + length]).into_owned();
            offset += length;
            listener_udp_outbound::resolve_host_to_ipaddr(host.as_str(), dns_runtime.as_deref_mut())?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported socks5 udp source address type",
            ))
        }
    };
    if offset + 2 > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp source port truncated",
        ));
    }
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok((SocketAddr::new(addr, port), payload[offset..].to_vec()))
}

pub(crate) fn build_socks5_udp_frame(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut framed = vec![0x00, 0x00, 0x00];
    match source {
        SocketAddr::V4(addr) => {
            framed.push(0x01);
            framed.extend_from_slice(&addr.ip().octets());
            framed.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            framed.push(0x04);
            framed.extend_from_slice(&addr.ip().octets());
            framed.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    framed.extend_from_slice(payload);
    framed
}

pub(crate) fn build_socks5_udp_packet(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    source: SocketAddr,
    payload: ByteWindow,
) -> io::Result<usize> {
    let framed = build_socks5_udp_frame(source, payload.as_slice());
    socket.send_to(&framed, peer_addr)
}
