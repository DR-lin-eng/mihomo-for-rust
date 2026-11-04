use std::io::{self, Read, Write};
use std::convert::TryInto;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata, NetworkKind, PacketEnvelope, SessionKind, UdpPacket, WriteBack};
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};

use crate::listener_service::listener_service_configs::{
    AnyTlsListenerConfig, TrustTunnelListenerConfig,
};
use crate::listener_service_support::accept_tls_server_stream;
use crate::stream_udp;

pub(super) fn handle_anytls_connection(
    config: AnyTlsListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let stream = accept_tls_server_stream(stream, config.tls_config).map_err(ListenerRuntimeError::Io)?;
    let passwords = config
        .users
        .iter()
        .map(|user| user.password.clone())
        .collect::<Vec<String>>();
    let (target, matched_user, mut stream) =
        mihomo_transport::accept_anytls_server_stream_with_passwords(stream, &passwords)
            .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?;
    let inbound_user = config
        .users
        .get(matched_user)
        .map(|user| user.username.clone())
        .unwrap_or_default();
    if target.host == mihomo_transport::ANYTLS_UOT_MAGIC_HOST && target.port == 0 {
        let (is_connect, source) = mihomo_transport::read_anytls_uot_request(&mut *stream)
            .map_err(ListenerRuntimeError::Io)?;
        if is_connect {
            return forward_anytls_connect_udp_over_tcp(
                stream,
                tunnel,
                &config.base,
                peer_addr.or(Some(source)),
                source,
            );
        }
        return stream_udp::forward_stream_udp_over_tcp(
            stream,
            tunnel,
            &config.base,
            SessionKind::AnyTls,
            peer_addr.or(Some(source)),
            mihomo_transport::read_anytls_udp_packet,
            mihomo_transport::write_anytls_udp_packet,
            "anytls inbound udp stream mutex poisoned",
            inbound_user,
        );
    }
    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::AnyTls,
        inbound_name: config.base.name.clone(),
        inbound_user,
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata
        .set_remote_address(&target.authority())
        .map_err(ListenerRuntimeError::from)?;
    let mut context = ConnectionContext::new(stream, metadata);
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)?;
    Ok(())
}

fn forward_anytls_connect_udp_over_tcp(
    stream: BoxedTcpStream,
    tunnel: Arc<RuntimeTunnel>,
    base: &mihomo_inbound::BaseInboundConfig,
    peer_addr: Option<SocketAddr>,
    destination: SocketAddr,
) -> Result<(), ListenerRuntimeError> {
    let _ = stream.set_timeouts(None, None);
    let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let stream = Arc::new(Mutex::new(stream));
    loop {
        let payload = {
            let mut guard = stream
                .lock()
                .map_err(|_| ListenerRuntimeError::Io(io::Error::other(
                    "anytls inbound udp connect stream mutex poisoned",
                )))?;
            read_anytls_uot_connect_payload(&mut **guard).map_err(ListenerRuntimeError::Io)?
        };
        let packet = Arc::new(AnyTlsConnectUdpPacket {
            payload: ByteWindow::freeze(payload),
            local_addr,
            peer_addr,
            stream: Arc::clone(&stream),
        });
        let mut metadata = Metadata {
            network: NetworkKind::Udp,
            kind: SessionKind::AnyTls,
            inbound_name: base.name.clone(),
            special_proxy: base.special_proxy.clone(),
            special_rules: base.special_rules.clone(),
            src_ip: Some(peer_addr.ip()),
            src_port: Some(peer_addr.port()),
            ..Metadata::default()
        };
        metadata
            .set_remote_address(&destination.to_string())
            .map_err(ListenerRuntimeError::from)?;
        let envelope = PacketEnvelope::new(packet, metadata);
        let mut udp_session =
            crate::listener_service::SystemUdpSession::new(tunnel.clone(), None)
                .map_err(ListenerRuntimeError::Io)?;
        let _ = tunnel
            .send_udp_packet(&envelope, &mut udp_session)
            .map_err(ListenerRuntimeError::Io)?;
        if let Some((response, responder)) =
            udp_session.recv_once().map_err(ListenerRuntimeError::Io)?
        {
            tunnel
                .write_back_udp(&envelope, ByteWindow::freeze(response), responder)
                .map_err(ListenerRuntimeError::Io)?;
        }
    }
}

fn read_anytls_uot_connect_payload(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

struct AnyTlsConnectUdpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    stream: Arc<Mutex<BoxedTcpStream>>,
}

impl WriteBack for AnyTlsConnectUdpPacket {
    fn write_back(&self, payload: ByteWindow, _source: Option<SocketAddr>) -> io::Result<usize> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("anytls inbound udp connect stream mutex poisoned"))?;
        let length = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "anytls udp payload too large"))?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(payload.as_slice())?;
        stream.flush()?;
        Ok(payload.len())
    }
}

impl UdpPacket for AnyTlsConnectUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
}

pub(super) fn handle_trusttunnel_connection(
    config: TrustTunnelListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let (request, stream) =
        mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), config.tls_config)
            .map_err(ListenerRuntimeError::Io)?;
    if request.method != "CONNECT" {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected trusttunnel listener request method: {}",
                request.method
            ),
        )));
    }
    let provided_auth = request
        .headers
        .get("proxy-authorization")
        .map(String::as_str)
        .unwrap_or_default();
    let Some(username) = config
        .users
        .iter()
        .find(|user| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", user.username, user.password))
            ) == provided_auth
        })
        .map(|user| user.username.clone())
    else {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusttunnel listener authentication failed",
        )));
    };
    if request.authority == "_udp2" {
        return stream_udp::forward_stream_udp_over_tcp(
            stream,
            tunnel,
            &config.base,
            SessionKind::TrustTunnel,
            peer_addr,
            read_trusttunnel_client_udp_packet,
            write_trusttunnel_server_udp_packet,
            "trusttunnel inbound udp stream mutex poisoned",
            username,
        );
    }

    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::TrustTunnel,
        inbound_name: config.base.name.clone(),
        inbound_user: username,
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata
        .set_remote_address(&request.authority)
        .map_err(ListenerRuntimeError::from)?;
    let mut context = ConnectionContext::new(stream, metadata);
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)?;
    Ok(())
}

fn read_trusttunnel_client_udp_packet(stream: &mut dyn Read) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 4 + 16 + 2 + 16 + 2 + 1];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
    let destination_ip = parse_trusttunnel_ip(header[22..38].try_into().unwrap());
    let destination_port = u16::from_be_bytes(header[38..40].try_into().unwrap());
    let app_name_len = header[40] as usize;
    if app_name_len > 0 {
        let mut app_name = vec![0_u8; app_name_len];
        stream.read_exact(&mut app_name)?;
    }
    let payload_len = length
        .checked_sub(16 + 2 + 16 + 2 + 1 + app_name_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid trusttunnel udp length"))?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    Ok((SocketAddr::new(destination_ip, destination_port), payload))
}

fn write_trusttunnel_server_udp_packet(
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let length = u32::try_from(16 + 2 + 16 + 2 + payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "trusttunnel udp packet too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    write_trusttunnel_ip(stream, target.ip())?;
    stream.write_all(&target.port().to_be_bytes())?;
    stream.write_all(&[0_u8; 16])?;
    stream.write_all(&0_u16.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

fn write_trusttunnel_ip(stream: &mut dyn Write, ip: std::net::IpAddr) -> io::Result<()> {
    match ip {
        std::net::IpAddr::V4(addr) => {
            stream.write_all(&[0_u8; 12])?;
            stream.write_all(&addr.octets())
        }
        std::net::IpAddr::V6(addr) => stream.write_all(&addr.octets()),
    }
}

fn parse_trusttunnel_ip(buffer: [u8; 16]) -> std::net::IpAddr {
    if buffer[..12].iter().all(|value| *value == 0)
        && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1)
    {
        return std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            buffer[12], buffer[13], buffer[14], buffer[15],
        ));
    }
    std::net::IpAddr::V6(std::net::Ipv6Addr::from(buffer))
}
