use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine as _;
use mihomo_core::BoxedTcpStream;

use crate::{h2_stream, TlsOptions, TransportError, TransportTarget};

const UDP_MAGIC_ADDRESS: &str = "_udp2";
const TCP_USER_AGENT: &str = "mihomo-rust trusttunnel";
const UDP_USER_AGENT: &str = "mihomo-rust _udp2";
const APP_NAME: &str = "mihomo-rust";

pub(crate) fn wrap_tls_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    h2_stream::wrap_tls_stream_with_request(
        stream,
        proxy,
        tls,
        alpn,
        request_options(target.authority(), TCP_USER_AGENT, username, password),
    )
}

pub(crate) fn open_udp_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    h2_stream::wrap_tls_stream_with_request(
        stream,
        proxy,
        tls,
        alpn,
        request_options(UDP_MAGIC_ADDRESS.to_owned(), UDP_USER_AGENT, username, password),
    )
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let app_name = APP_NAME.as_bytes();
    let header_len = 4 + 16 + 2 + 16 + 2 + 1 + app_name.len();
    let payload_len = payload.len();
    let length_field = u32::try_from(16 + 2 + 16 + 2 + 1 + app_name.len() + payload_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "trusttunnel udp packet too large"))?;

    let mut frame = Vec::with_capacity(header_len + payload_len);
    frame.extend_from_slice(&length_field.to_be_bytes());
    frame.extend_from_slice(&[0_u8; 16]);
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&build_padding_ip(target.ip()));
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.push(u8::try_from(app_name.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "trusttunnel app name is too long")
    })?);
    frame.extend_from_slice(app_name);
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(stream: &mut dyn Read) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 4 + 16 + 2 + 16 + 2];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
    let source_ip = parse_16_bytes_ip(header[4..20].try_into().unwrap());
    let source_port = u16::from_be_bytes(header[20..22].try_into().unwrap());
    let payload_len = length
        .checked_sub(16 + 2 + 16 + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid trusttunnel udp length"))?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    Ok((SocketAddr::new(source_ip, source_port), payload))
}

fn request_options(
    authority: String,
    user_agent: &str,
    username: &str,
    password: &str,
) -> h2_stream::H2RequestOptions {
    h2_stream::H2RequestOptions {
        authority,
        path: "/".to_owned(),
        method: "CONNECT".to_owned(),
        headers: vec![
            ("user-agent".to_owned(), user_agent.to_owned()),
            (
                "proxy-authorization".to_owned(),
                build_basic_auth(username, password),
            ),
        ],
    }
}

fn build_basic_auth(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

fn build_padding_ip(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ipv4) => {
            let mut buffer = [0_u8; 16];
            buffer[12..16].copy_from_slice(&ipv4.octets());
            buffer
        }
        IpAddr::V6(ipv6) => ipv6.octets(),
    }
}

fn parse_16_bytes_ip(buffer: [u8; 16]) -> IpAddr {
    if buffer[..12].iter().all(|value| *value == 0)
        && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1)
    {
        return IpAddr::V4(Ipv4Addr::new(
            buffer[12], buffer[13], buffer[14], buffer[15],
        ));
    }
    IpAddr::V6(Ipv6Addr::from(buffer))
}

