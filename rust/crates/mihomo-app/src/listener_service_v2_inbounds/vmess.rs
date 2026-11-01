use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata, NetworkKind, PacketEnvelope, SessionKind};
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};

use crate::listener_service::SystemUdpSession;
use crate::listener_service_support::{
    accept_http_server_stream, accept_tls_server_stream, accept_websocket_server_stream,
};
use crate::listener_udp_support::{VmessStreamBackedUdpPacket, VmessStreamBackedXudpPacket};
use mihomo_transport::{
    accept_vmess_stream_with_uuids, decode_packetaddr_udp_packet, read_vmess_udp_packet,
    read_vmess_xudp_packet, VmessAcceptedStream,
};

use super::super::listener_service_configs::VmessInboundConfig;
use super::super::listener_service_xhttp::*;

pub(crate) fn handle_vmess_connection(
    config: VmessInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    if config.network != "tcp"
        && config.network != "ws"
        && config.network != "grpc"
        && config.network != "http"
        && config.network != "h2"
        && config.network != "xhttp"
        && !config.network.is_empty()
    {
        return Err(ListenerRuntimeError::Io(io::Error::other(format!(
            "vmess inbound network is not implemented yet: {}",
            config.network
        ))));
    }
    let stream: BoxedTcpStream = if config.network == "ws" {
        let stream = if let Some(tls_config) = config.tls_config.clone() {
            accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
        } else {
            Box::new(stream)
        };
        accept_websocket_server_stream(stream, &config.ws_path).map_err(ListenerRuntimeError::Io)?
    } else if config.network == "grpc" {
        let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
            mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
                .map_err(ListenerRuntimeError::Io)?
        } else {
            mihomo_transport::accept_h2_test_stream(Box::new(stream))
                .map_err(ListenerRuntimeError::Io)?
        };
        let expected_path = format!("/{}/Tun", config.grpc_service_name);
        if request.method != "POST" || request.path != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess grpc request: method={}, path={}",
                    request.method, request.path
                ),
            )));
        }
        mihomo_transport::accept_grpc_test_stream(stream)
    } else if config.network == "http" {
        let stream: BoxedTcpStream = if let Some(tls_config) = config.tls_config.clone() {
            accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
        } else {
            Box::new(stream)
        };
        let (request, stream) = accept_http_server_stream(stream).map_err(ListenerRuntimeError::Io)?;
        let request_line = request
            .lines()
            .next()
            .ok_or_else(|| ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing vmess http request line",
            )))?;
        let mut parts = request_line.split_whitespace();
        let actual_method = parts.next().unwrap_or_default();
        let actual_path = parts.next().unwrap_or_default();
        let method = if config.http.method.trim().is_empty() {
            "GET"
        } else {
            config.http.method.trim()
        };
        let expected_path = config
            .http
            .path
            .first()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                if value.starts_with('/') {
                    value.clone()
                } else {
                    format!("/{value}")
                }
            })
            .unwrap_or_else(|| "/".to_owned());
        let expected_host = config
            .http
            .host
            .first()
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_default();
        if actual_method != method || actual_path != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess http request: method={}, path={}",
                    actual_method, actual_path
                ),
            )));
        }
        if !expected_host.is_empty() && !request.contains(&format!("Host: {expected_host}\r\n")) {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected vmess http host: expected={expected_host}"),
            )));
        }
        for (name, values) in &config.http.headers {
            if name.eq_ignore_ascii_case("host") || values.is_empty() {
                continue;
            }
            let expected = format!("{name}: {}\r\n", values[0]);
            if !request.contains(&expected) {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected vmess http header: expected={expected:?}"),
                )));
            }
        }
        stream
    } else if config.network == "h2" {
        let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
            mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
                .map_err(ListenerRuntimeError::Io)?
        } else {
            mihomo_transport::accept_h2_test_stream(Box::new(stream))
                .map_err(ListenerRuntimeError::Io)?
        };
        let expected_path = if config.h2_path.trim().is_empty() {
            "/".to_owned()
        } else {
            config.h2_path.clone()
        };
        if request.method != "PUT" || request.path != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess h2 request: method={}, path={}",
                    request.method, request.path
                ),
            )));
        }
        if !config.h2_hosts.is_empty()
            && !config.h2_hosts.iter().any(|host| host == &request.authority)
        {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected vmess h2 authority: {}", request.authority),
            )));
        }
        stream
    } else if config.network == "xhttp" {
        let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
            mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
                .map_err(ListenerRuntimeError::Io)?
        } else {
            mihomo_transport::accept_h2_test_stream(Box::new(stream))
                .map_err(ListenerRuntimeError::Io)?
        };
        let Some(stream) = accept_inbound_xhttp_stream(
            "vmess",
            &config.xhttp,
            &config.xhttp_sessions,
            AcceptedXhttpRequest {
                method: request.method,
                authority: request.authority,
                path: request.path,
                headers: request.headers,
            },
            stream,
        )? else {
            return Ok(());
        };
        stream
    } else if let Some(tls_config) = config.tls_config.clone() {
        accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
    } else {
        Box::new(stream)
    };
    let (accepted, matched_uuid) = accept_vmess_stream_with_uuids(stream, &config.uuids)
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?;
    match accepted
    {
        VmessAcceptedStream::Tcp { target, stream } => {
            let mut metadata = Metadata {
                network: NetworkKind::Tcp,
                kind: SessionKind::Vmess,
                inbound_name: config.base.name.clone(),
                inbound_user: matched_uuid.clone(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                ..Metadata::default()
            };
            if let Some(peer) = peer_addr {
                metadata.src_ip = Some(peer.ip());
                metadata.src_port = Some(peer.port());
            }
            metadata
                .set_remote_address(&target)
                .map_err(ListenerRuntimeError::from)?;
            let mut context = ConnectionContext::new(stream, metadata);
            tunnel
                .forward_tcp_context_with_system_dialer(&mut context)
                .map_err(ListenerRuntimeError::from)?;
            Ok(())
        }
        VmessAcceptedStream::Udp { target, stream } => {
            let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let stream = Arc::new(Mutex::new(stream));
            let packet_addr = target
                == format!(
                    "{}:{}",
                    mihomo_transport::PACKETADDR_MAGIC_HOST,
                    mihomo_transport::PACKETADDR_MAGIC_PORT
                );
            loop {
                let (source, payload) = {
                    let mut guard = stream.lock().map_err(|_| {
                        ListenerRuntimeError::Io(io::Error::other(
                            "vmess inbound udp stream mutex poisoned",
                        ))
                    })?;
                    let payload = read_vmess_udp_packet(&mut **guard)
                        .map_err(ListenerRuntimeError::Io)?;
                    if payload.is_empty() {
                        return Ok(());
                    }
                    if packet_addr {
                        decode_packetaddr_udp_packet(&payload).map_err(|err| {
                            ListenerRuntimeError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                err.to_string(),
                            ))
                        })?
                    } else {
                        let source = target.parse::<SocketAddr>().map_err(|err| {
                            ListenerRuntimeError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid vmess inbound udp target {target}: {err}"),
                            ))
                        })?;
                        (source, payload)
                    }
                };

                let packet = Arc::new(VmessStreamBackedUdpPacket {
                    payload: ByteWindow::freeze(payload),
                    local_addr,
                    peer_addr,
                    outbound_source: source,
                    stream: Arc::clone(&stream),
                    packet_addr,
                });
                let mut metadata = Metadata {
                    network: NetworkKind::Udp,
                    kind: SessionKind::Vmess,
                    inbound_name: config.base.name.clone(),
                    inbound_user: matched_uuid.clone(),
                    special_proxy: config.base.special_proxy.clone(),
                    special_rules: config.base.special_rules.clone(),
                    src_ip: Some(peer_addr.ip()),
                    src_port: Some(peer_addr.port()),
                    ..Metadata::default()
                };
                metadata
                    .set_remote_address(&source.to_string())
                    .map_err(ListenerRuntimeError::from)?;
                let envelope = PacketEnvelope::new(packet, metadata);
                let mut udp_session =
                    SystemUdpSession::new(tunnel.clone(), None).map_err(ListenerRuntimeError::Io)?;
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
        VmessAcceptedStream::Xudp { stream, .. } => {
            let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let stream = Arc::new(Mutex::new(stream));
            loop {
                let (source, payload) = {
                    let mut guard = stream.lock().map_err(|_| {
                        ListenerRuntimeError::Io(io::Error::other(
                            "vmess inbound xudp stream mutex poisoned",
                        ))
                    })?;
                    match read_vmess_xudp_packet(&mut **guard) {
                        Ok(packet) => packet,
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::BrokenPipe
                            ) =>
                        {
                            return Ok(());
                        }
                        Err(err) => return Err(ListenerRuntimeError::Io(err)),
                    }
                };

                let packet = Arc::new(VmessStreamBackedXudpPacket {
                    payload: ByteWindow::freeze(payload),
                    local_addr,
                    peer_addr,
                    outbound_source: source,
                    stream: Arc::clone(&stream),
                });
                let mut metadata = Metadata {
                    network: NetworkKind::Udp,
                    kind: SessionKind::Vmess,
                    inbound_name: config.base.name.clone(),
                    inbound_user: matched_uuid.clone(),
                    special_proxy: config.base.special_proxy.clone(),
                    special_rules: config.base.special_rules.clone(),
                    src_ip: Some(peer_addr.ip()),
                    src_port: Some(peer_addr.port()),
                    ..Metadata::default()
                };
                metadata
                    .set_remote_address(&source.to_string())
                    .map_err(ListenerRuntimeError::from)?;
                let envelope = PacketEnvelope::new(packet, metadata);
                let mut udp_session =
                    SystemUdpSession::new(tunnel.clone(), None).map_err(ListenerRuntimeError::Io)?;
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
    }
}
