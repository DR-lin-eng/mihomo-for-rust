use std::io;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use base64::Engine;
use http::Method;
use rcgen::{CertificateParams, KeyPair};
use sha2::Digest;

use mihomo_core::BoxedTcpStream;

use crate::transport_types::MasqueConnectOptions;
use crate::{h2_stream, ip_packet_tunnel, masque_dns, TlsOptions, TransportError, TransportTarget};

struct MasqueIpPacketIo {
    write_stream: BoxedTcpStream,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
}

impl ip_packet_tunnel::IpPacketIo for MasqueIpPacketIo {
    fn write_ip_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        write_h2_ip_packet(&mut *self.write_stream, packet)
    }

    fn read_ip_packet_timeout(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        match self.read_rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "masque h2 read timed out"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(Vec::new()),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        self.write_stream.shutdown_all()
    }
}

pub(crate) fn connect_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &MasqueConnectOptions,
    tls: &TlsOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let source_ip = local_ipv4_from_options(options)?;
    let mut tunnel = open_h2_ip_tunnel(stream, proxy, options, tls)?;
    let target = if options.remote_dns_resolve && !options.dns.is_empty() {
        let resolved = resolve_remote_target_host(&mut *tunnel, options, &target.host)?;
        TransportTarget::new(resolved.to_string(), target.port)
    } else {
        target.clone()
    };
    ip_packet_tunnel::connect_tcp_stream(
        MasqueIpPacketIo::new(tunnel)?,
        source_ip,
        options.mtu.max(1280),
        &target,
    )
}

pub(crate) fn open_udp_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &MasqueConnectOptions,
    tls: &TlsOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let source_ip = local_ipv4_from_options(options)?;
    let tunnel = open_h2_ip_tunnel(stream, proxy, options, tls)?;
    ip_packet_tunnel::open_udp_stream(MasqueIpPacketIo::new(tunnel)?, source_ip)
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    ip_packet_tunnel::write_udp_packet(stream, target, payload)
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    ip_packet_tunnel::read_udp_packet(stream)
}

pub(crate) fn resolve_remote_target_host(
    stream: &mut dyn mihomo_core::TcpStream,
    options: &MasqueConnectOptions,
    host: &str,
) -> Result<Ipv4Addr, TransportError> {
    masque_dns::resolve_masque_host_via_udp_stream(stream, &options.dns, host)
}

fn local_ipv4_from_options(options: &MasqueConnectOptions) -> Result<Ipv4Addr, TransportError> {
    ip_packet_tunnel::first_ipv4_from_prefixes(&[options.ip.clone()]).map_err(TransportError::from)
}

fn open_h2_ip_tunnel(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &MasqueConnectOptions,
    tls: &TlsOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if options.network != "h2" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!(
                "masque network={} is not implemented",
                if options.network.trim().is_empty() {
                    "<default>"
                } else {
                    options.network.as_str()
                }
            ),
        });
    }
    let request = h2_stream::H2RequestOptions {
        authority: connect_ip_authority(&options.uri)?,
        path: connect_ip_path(&options.uri)?,
        method: Method::CONNECT.as_str().to_owned(),
        headers: vec![
            ("cf-connect-proto".to_owned(), "cf-connect-ip".to_owned()),
            ("pq-enabled".to_owned(), "false".to_owned()),
            ("capsule-protocol".to_owned(), "?1".to_owned()),
        ],
    };

    let mut masque_tls = tls.clone();
    if !masque_tls.enabled {
        masque_tls.enabled = true;
    }
    if masque_tls.sni.trim().is_empty() {
        masque_tls.sni = proxy.host.clone();
    }
    let (cert_pem, key_pem) = build_client_cert_pem(&options.private_key)?;
    masque_tls.certificate = cert_pem;
    masque_tls.private_key = key_pem;
    masque_tls.fingerprint = encode_masque_public_key_fingerprint(&options.public_key)?;

    h2_stream::wrap_tls_stream_with_request(
        stream,
        proxy,
        &masque_tls,
        &["h2".to_owned()],
        request,
    )
    .map_err(|err| match err {
        TransportError::UnsupportedFeature { .. } => err,
        other => other,
    })
}

fn connect_ip_authority(uri: &str) -> Result<String, TransportError> {
    let parsed = uri.parse::<http::Uri>().map_err(|err| {
        TransportError::InvalidPlan(format!("invalid masque uri {uri:?}: {err}"))
    })?;
    let authority = parsed
        .authority()
        .map(|value| value.as_str().to_owned())
        .ok_or_else(|| TransportError::InvalidPlan(format!("masque uri missing authority: {uri}")))?;
    Ok(authority)
}

fn connect_ip_path(uri: &str) -> Result<String, TransportError> {
    let parsed = uri.parse::<http::Uri>().map_err(|err| {
        TransportError::InvalidPlan(format!("invalid masque uri {uri:?}: {err}"))
    })?;
    Ok(parsed
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/".to_owned()))
}

fn build_client_cert_pem(private_key_b64: &str) -> Result<(String, String), TransportError> {
    let private_key_der = base64::engine::general_purpose::STANDARD
        .decode(private_key_b64)
        .map_err(|err| TransportError::InvalidPlan(format!("invalid masque private-key: {err}")))?;
    let key_pair = KeyPair::try_from(private_key_der.as_slice())
        .map_err(|err| TransportError::InvalidPlan(format!("invalid masque private-key der: {err}")))?;
    let cert = CertificateParams::default()
        .self_signed(&key_pair)
        .map_err(|err| TransportError::InvalidPlan(format!("build masque client certificate failed: {err}")))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

impl MasqueIpPacketIo {
    fn new(mut stream: BoxedTcpStream) -> Result<Self, TransportError> {
        let write_stream = stream.try_clone_box().map_err(TransportError::from)?;
        let (read_tx, read_rx) = mpsc::channel();
        thread::spawn(move || loop {
            let result = read_h2_ip_packet(&mut *stream);
            let terminal = match &result {
                Ok(packet) => packet.is_empty(),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    true
                }
                Err(_) => false,
            };
            let _ = read_tx.send(result);
            if terminal {
                break;
            }
        });
        Ok(Self {
            write_stream,
            read_rx,
        })
    }
}

fn encode_masque_public_key_fingerprint(public_key_b64: &str) -> Result<String, TransportError> {
    let expected = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|err| TransportError::InvalidPlan(format!("invalid masque public-key: {err}")))?;
    let hash = sha2::Sha256::digest(expected);
    Ok(hex::encode(hash))
}

fn read_h2_ip_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    read_varint(stream).and_then(|capsule_type| {
        let payload_len = read_varint(stream)? as usize;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload)?;
        if capsule_type != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected masque h2 capsule type: {capsule_type}"),
            ));
        }
        Ok(payload)
    })
}

fn write_h2_ip_packet(stream: &mut dyn Write, packet: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(16 + packet.len());
    append_varint(&mut frame, 0);
    append_varint(&mut frame, packet.len() as u64);
    frame.extend_from_slice(packet);
    stream.write_all(&frame)?;
    stream.flush()
}

fn append_varint(buf: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => buf.push(value as u8),
        64..=16383 => {
            let encoded = 0x4000 | value as u16;
            buf.extend_from_slice(&encoded.to_be_bytes());
        }
        16384..=1_073_741_823 => {
            let encoded = 0x8000_0000 | value as u32;
            buf.extend_from_slice(&encoded.to_be_bytes());
        }
        _ => {
            let encoded = 0xC000_0000_0000_0000 | value;
            buf.extend_from_slice(&encoded.to_be_bytes());
        }
    }
}

fn read_varint(stream: &mut dyn Read) -> io::Result<u64> {
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first)?;
    let prefix = first[0] >> 6;
    let value = match prefix {
        0 => (first[0] & 0x3f) as u64,
        1 => {
            let mut rest = [0_u8; 1];
            stream.read_exact(&mut rest)?;
            u16::from_be_bytes([first[0], rest[0]]) as u64 & 0x3fff
        }
        2 => {
            let mut rest = [0_u8; 3];
            stream.read_exact(&mut rest)?;
            u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as u64 & 0x3fff_ffff
        }
        _ => {
            let mut rest = [0_u8; 7];
            stream.read_exact(&mut rest)?;
            u64::from_be_bytes([
                first[0], rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6],
            ]) & 0x3fff_ffff_ffff_ffff
        }
    };
    Ok(value)
}
