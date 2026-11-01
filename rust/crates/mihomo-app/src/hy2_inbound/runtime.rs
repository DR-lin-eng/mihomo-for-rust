use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mihomo_buf::ByteWindow;
use mihomo_core::{
    ConnectionContext, Metadata, NetworkKind, PacketEnvelope, SessionKind,
};
use mihomo_runtime::RuntimeTunnel;
use quinn::{
    Connection as QuinnConnection, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::listener_service::SystemUdpSession;
use crate::listener_udp_support::quic_runtime_worker_threads;
use crate::quic_tls::{build_quic_server_tls_config, QuicServerTlsOptions};

use super::config::Hy2ListenerConfig;
use super::packet::{
    decode_hy2_packet, defragment_hy2_packet, write_hy2_varint, Hy2InboundUdpPacket,
};
use super::realm;
use super::stream::Hy2QuicStream;

pub(crate) fn spawn_hy2_listener(
    address: String,
    config: Hy2ListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let bind_addr = address
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let join_handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(quic_runtime_worker_threads())
            .enable_all()
            .build();
        let Ok(runtime) = runtime else {
            let _ = addr_tx.send(Err(io::Error::other("failed to build hy2 runtime")));
            return;
        };
        runtime.block_on(async move {
            let endpoint = match build_endpoint(bind_addr, &config, Arc::clone(&tunnel)) {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    let _ = addr_tx.send(Err(err));
                    return;
                }
            };
            let Ok(local_addr) = endpoint.local_addr() else {
                let _ = addr_tx.send(Err(io::Error::other("failed to read hy2 local addr")));
                return;
            };
            let _ = addr_tx.send(Ok(local_addr));
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    incoming = endpoint.accept() => {
                        let Some(connecting) = incoming else { break };
                        let tunnel = Arc::clone(&tunnel);
                        let config = config.clone();
                        tokio::spawn(async move {
                            let Ok(connection) = connecting.await else { return; };
                            let _ = handle_connection(connection, tunnel, config, local_addr).await;
                        });
                    }
                }
            }
        });
    });
    let local_addr = addr_rx
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hy2 listener failed before binding"))??;
    Ok((local_addr, join_handle))
}

fn build_endpoint(
    bind_addr: SocketAddr,
    config: &Hy2ListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
) -> io::Result<QuinnEndpoint> {
    let _ = quinn::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let server_crypto = build_quic_server_tls_config(&QuicServerTlsOptions {
        certificate: config.certificate.clone(),
        private_key: config.private_key.clone(),
        alpn: config.alpn.clone(),
        client_auth_type: config.client_auth_type.clone(),
        client_auth_cert: config.client_auth_cert.clone(),
    })?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(io::Error::other)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    server_config.transport_config(Arc::new(transport));
    let obfs_password = if config.obfs == "salamander" {
        config.obfs_password.as_bytes().to_vec()
    } else {
        Vec::new()
    };
    realm::build_endpoint_with_optional_realm(
        bind_addr,
        server_config,
        obfs_password,
        tunnel,
        config.realm.clone(),
    )
}

async fn handle_connection(
    connection: QuinnConnection,
    tunnel: Arc<RuntimeTunnel>,
    config: Hy2ListenerConfig,
    local_addr: SocketAddr,
) -> io::Result<()> {
    authenticate(&connection, &config).await?;
    let tunnel_udp = Arc::clone(&tunnel);
    let config_udp = config.clone();
    let connection_udp = connection.clone();
    tokio::spawn(async move {
        let _ = run_udp_loop(connection_udp, tunnel_udp, config_udp, local_addr).await;
    });
    loop {
        let Ok((send, recv)) = connection.accept_bi().await else {
            break;
        };
        let (target, stream) = accept_tcp_stream(send, recv).await?;
        let tunnel = Arc::clone(&tunnel);
        let inbound_name = config.base.name.clone();
        let special_proxy = config.base.special_proxy.clone();
        let special_rules = config.base.special_rules.clone();
        let mut metadata = Metadata {
            network: NetworkKind::Tcp,
            kind: SessionKind::Hysteria2,
            inbound_name,
            special_proxy,
            special_rules,
            inbound_ip: Some(local_addr.ip()),
            inbound_port: Some(local_addr.port()),
            ..Metadata::default()
        };
        metadata
            .set_remote_address(&target)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let mut context = ConnectionContext::new(stream, metadata);
            let _ = tunnel.forward_tcp_context_with_system_dialer(&mut context);
        });
    }
    Ok(())
}

async fn run_udp_loop(
    connection: QuinnConnection,
    tunnel: Arc<RuntimeTunnel>,
    config: Hy2ListenerConfig,
    local_addr: SocketAddr,
) -> io::Result<()> {
    let mut fragments = BTreeMap::new();
    loop {
        let bytes = connection.read_datagram().await.map_err(io::Error::other)?;
        let message = decode_hy2_packet(bytes.as_ref())?;
        let Some(message) = defragment_hy2_packet(&mut fragments, message) else {
            continue;
        };
        let target = message
            .destination
            .parse::<SocketAddr>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let packet = Arc::new(Hy2InboundUdpPacket {
            local_addr,
            payload: ByteWindow::freeze(message.payload),
            source: target,
            session_id: message.session_id,
            packet_id: message.packet_id,
            connection: connection.clone(),
            udp_mtu: config.udp_mtu,
        });
        let mut metadata = Metadata {
            network: NetworkKind::Udp,
            kind: SessionKind::Hysteria2,
            inbound_name: config.base.name.clone(),
            special_proxy: config.base.special_proxy.clone(),
            special_rules: config.base.special_rules.clone(),
            inbound_ip: Some(local_addr.ip()),
            inbound_port: Some(local_addr.port()),
            ..Metadata::default()
        };
        metadata
            .set_remote_address(&target.to_string())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let envelope = PacketEnvelope::new(packet, metadata);
        let mut session = SystemUdpSession::new(Arc::clone(&tunnel), None)?;
        let _ = tunnel.send_udp_packet(&envelope, &mut session)?;
        if let Some((response, responder)) = session.recv_once()? {
            tunnel.write_back_udp(&envelope, ByteWindow::freeze(response), responder)?;
        }
    }
}

async fn accept_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> io::Result<(String, Hy2QuicStream)> {
    let target = read_hy2_target(&mut recv).await?;
    write_hy2_tcp_response(&mut recv, &mut send, true, "").await?;
    Ok((target, Hy2QuicStream::new(send, recv)))
}

async fn read_hy2_target(stream: &mut quinn::RecvStream) -> io::Result<String> {
    let frame_type = read_hy2_varint(stream).await?;
    if frame_type != 0x401 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected hysteria2 tcp frame type: {frame_type}"),
        ));
    }
    let address_len = read_hy2_varint(stream).await? as usize;
    let mut address = vec![0_u8; address_len];
    stream.read_exact(&mut address).await.map_err(io::Error::other)?;
    let padding_len = read_hy2_varint(stream).await? as usize;
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        stream.read_exact(&mut padding).await.map_err(io::Error::other)?;
    }
    String::from_utf8(address)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

async fn read_hy2_varint<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> io::Result<u64> {
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first).await.map_err(io::Error::other)?;
    let tag = first[0] >> 6;
    let mut buf = [0_u8; 8];
    match tag {
        0 => Ok((first[0] & 0x3f) as u64),
        1 => {
            buf[0] = first[0];
            stream.read_exact(&mut buf[1..2]).await.map_err(io::Error::other)?;
            Ok(u16::from_be_bytes(buf[..2].try_into().unwrap()) as u64 & 0x3fff)
        }
        2 => {
            buf[0] = first[0];
            stream.read_exact(&mut buf[1..4]).await.map_err(io::Error::other)?;
            Ok(u32::from_be_bytes(buf[..4].try_into().unwrap()) as u64 & 0x3fff_ffff)
        }
        _ => {
            buf[0] = first[0];
            stream.read_exact(&mut buf[1..8]).await.map_err(io::Error::other)?;
            Ok(u64::from_be_bytes(buf) & 0x3fff_ffff_ffff_ffff)
        }
    }
}

async fn write_hy2_tcp_response(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    ok: bool,
    message: &str,
) -> io::Result<()> {
    let _ = recv;
    let mut response = Vec::new();
    response.push(if ok { 0x00 } else { 0x01 });
    write_hy2_varint(&mut response, message.len() as u64)?;
    response.extend_from_slice(message.as_bytes());
    write_hy2_varint(&mut response, 0)?;
    send.write_all(&response).await.map_err(io::Error::other)?;
    send.flush().await.map_err(io::Error::other)
}

async fn authenticate(connection: &QuinnConnection, config: &Hy2ListenerConfig) -> io::Result<()> {
    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let mut incoming =
        h3::server::Connection::<_, bytes::Bytes>::new(h3_conn)
            .await
            .map_err(io::Error::other)?;
    let resolver = incoming
        .accept()
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "hy2 auth request missing"))?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(io::Error::other)?;
    let auth = config
        .users
        .values()
        .next()
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hy2 listener missing user password"))?;
    if request.method() != http::Method::POST
        || request.uri().authority().map(|value| value.as_str()) != Some("hysteria")
        || request.uri().path() != "/auth"
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hy2 auth request",
        ));
    }
    if request
        .headers()
        .get("Hysteria-Auth")
        .and_then(|value| value.to_str().ok())
        != Some(auth.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hy2 auth password mismatch",
        ));
    }
    let response = http::Response::builder()
        .status(233)
        .header("Hysteria-UDP", "true")
        .header("Hysteria-CC-RX", "0")
        .body(())
        .map_err(io::Error::other)?;
    stream.send_response(response).await.map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)?;
    let guard_connection = connection.clone();
    tokio::spawn(async move {
        let _h3_guard = incoming;
        let _ = guard_connection.closed().await;
    });
    Ok(())
}
