use std::io::Write;
use std::net::ToSocketAddrs;

use mihomo_core::BoxedTcpStream;
use sha2::{Digest, Sha224};

use crate::{TransportError, TransportTarget};

pub(crate) const DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x03;
const CRLF: &[u8] = b"\r\n";

pub(crate) fn wrap_stream(
    mut stream: BoxedTcpStream,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    write_header(&mut *stream, password, COMMAND_TCP, target)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(stream)
}

pub(crate) fn open_udp_stream(
    mut stream: BoxedTcpStream,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    write_header(&mut *stream, password, COMMAND_UDP, target)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(stream)
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> std::io::Result<usize> {
    let target = TransportTarget::new(target.ip().to_string(), target.port());
    let mut packet = super::encode_socks5_target(&target)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))?;
    packet.extend_from_slice(&target.port.to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(CRLF);
    packet.extend_from_slice(payload);
    stream.write_all(&packet)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn std::io::Read,
) -> std::io::Result<(std::net::SocketAddr, Vec<u8>)> {
    let target = read_udp_target(stream)?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let total = u16::from_be_bytes(length) as usize;
    let mut crlf = [0_u8; 2];
    stream.read_exact(&mut crlf)?;
    if crlf != *CRLF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid trojan udp packet delimiter",
        ));
    }
    let mut payload = vec![0_u8; total];
    stream.read_exact(&mut payload)?;
    Ok((target, payload))
}

fn write_header(
    stream: &mut dyn Write,
    password: &str,
    command: u8,
    target: &TransportTarget,
) -> Result<(), TransportError> {
    let key = encode_password(password);
    let mut request = Vec::with_capacity(key.len() + 2 + 1 + target.host.len() + 8);
    request.extend_from_slice(key.as_bytes());
    request.extend_from_slice(CRLF);
    request.push(command);
    request.extend_from_slice(&super::encode_socks5_target(target)?);
    request.extend_from_slice(&target.port.to_be_bytes());
    request.extend_from_slice(CRLF);
    stream.write_all(&request).map_err(TransportError::from)
}

fn encode_password(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(nibble_to_hex((byte >> 4) & 0x0f));
        encoded.push(nibble_to_hex(byte & 0x0f));
    }
    encoded
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("hex nibble must fit within 4 bits"),
    }
}

fn read_udp_target(stream: &mut dyn std::io::Read) -> std::io::Result<std::net::SocketAddr> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let host = match atyp[0] {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets)?;
            TrojanUdpHost::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets)?;
            TrojanUdpHost::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let mut host = vec![0_u8; length[0] as usize];
            stream.read_exact(&mut host)?;
            TrojanUdpHost::Domain(String::from_utf8_lossy(&host).into_owned())
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported trojan udp atyp {other}"),
            ))
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    match host {
        TrojanUdpHost::Ip(ip) => Ok(std::net::SocketAddr::new(ip, port)),
        TrojanUdpHost::Domain(host) => {
            let mut addrs = (host.as_str(), port).to_socket_addrs()?;
            addrs.next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "trojan udp fqdn target unresolved",
                )
            })
        }
    }
}

enum TrojanUdpHost {
    Ip(std::net::IpAddr),
    Domain(String),
}
