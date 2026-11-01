use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use blake3::hash as blake3_hash;
use mihomo_buf::ByteWindow;
use mihomo_core::{
    push_log, ConnectionContext, LogLevel, Metadata, NetworkKind, PacketEnvelope, SessionKind,
};
use mihomo_runtime::RuntimeTunnel;
use quinn::{
    Connection as QuinnConnection, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig,
};
use tokio::runtime::Builder;
use uuid::Uuid;

use crate::listener_service::SystemUdpSession;
use crate::listener_udp_support::quic_runtime_worker_threads;
use crate::quic_tls::{build_quic_server_tls_config, QuicServerTlsOptions};

use super::config::TuicListenerConfig;
use super::packet::{
    decode_tuic_v4_packet, decode_tuic_v5_packet, TuicInboundUdpPacket,
};
use super::stream::TuicQuicStream;

pub(crate) fn spawn_tuic_listener(
    address: String,
    config: TuicListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let bind_addr = address.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "tuic listener bind address unresolved",
        )
    })?;
    let (addr_tx, addr_rx) = mpsc::channel();
    let join_handle = thread::spawn(move || {
        let runtime = Builder::new_multi_thread()
            .worker_threads(quic_runtime_worker_threads())
            .enable_all()
            .build();
        let Ok(runtime) = runtime else {
            let _ = addr_tx.send(Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to build tuic listener runtime",
            )));
            return;
        };
        runtime.block_on(async move {
            let endpoint = match build_endpoint(bind_addr, &config) {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    let _ = addr_tx.send(Err(err));
                    return;
                }
            };
            let local_addr = match endpoint.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    let _ = addr_tx.send(Err(err));
                    return;
                }
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
                        let Some(connecting) = incoming else {
                            break;
                        };
                        let tunnel = Arc::clone(&tunnel);
                        let config = config.clone();
                        tokio::spawn(async move {
                            let Ok(connection) = connecting.await else {
                                return;
                            };
                            let _ = handle_connection(connection, tunnel, config, local_addr).await;
                        });
                    }
                }
            }
        });
    });
    let local_addr = addr_rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "tuic listener failed before binding",
        )
    })??;
    Ok((local_addr, join_handle))
}

fn build_endpoint(bind_addr: SocketAddr, config: &TuicListenerConfig) -> io::Result<QuinnEndpoint> {
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
    transport.max_concurrent_uni_streams(1024_u32.into());
    transport.max_concurrent_bidi_streams(1024_u32.into());
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    server_config.transport_config(Arc::new(transport));
    QuinnEndpoint::server(server_config, bind_addr).map_err(io::Error::other)
}

async fn handle_connection(
    connection: QuinnConnection,
    tunnel: Arc<RuntimeTunnel>,
    config: TuicListenerConfig,
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
        #[cfg(test)]
        eprintln!("tuic listener accepted tcp target: {target}");
        let tunnel = Arc::clone(&tunnel);
        let inbound_name = config.base.name.clone();
        let special_proxy = config.base.special_proxy.clone();
        let special_rules = config.base.special_rules.clone();
        let mut metadata = Metadata {
            network: NetworkKind::Tcp,
            kind: SessionKind::Tuic,
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
            if let Err(_err) = tunnel.forward_tcp_context_with_system_dialer(&mut context) {
                #[cfg(test)]
                eprintln!("tuic listener tcp forward error: {_err}");
            }
        });
    }
    Ok(())
}

async fn authenticate(connection: &QuinnConnection, config: &TuicListenerConfig) -> io::Result<()> {
    let mut auth_stream = connection.accept_uni().await.map_err(io::Error::other)?;
    if !config.token.is_empty() {
        let mut auth_header = [0_u8; 2 + 32];
        auth_stream.read_exact(&mut auth_header).await.map_err(io::Error::other)?;
        if auth_header[0] != 0x04 || auth_header[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid tuic v4 auth",
            ));
        }
        let valid = config.token.iter().any(|token| {
            let expected = blake3_hash(token.as_bytes());
            &auth_header[2..] == expected.as_bytes()
        });
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tuic token authentication failed",
            ));
        }
        return Ok(());
    }

    let mut auth_header = [0_u8; 2 + 16 + 32];
    auth_stream
        .read_exact(&mut auth_header)
        .await
        .map_err(io::Error::other)?;
    if auth_header[0] != 0x05 || auth_header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid tuic v5 auth",
        ));
    }
    let mut got_uuid = [0_u8; 16];
    got_uuid.copy_from_slice(&auth_header[2..18]);
    let valid = config.users.iter().any(|(user, password)| {
        let Ok(uuid) = Uuid::parse_str(user) else {
            return false;
        };
        if got_uuid != *uuid.as_bytes() {
            return false;
        }
        let mut expected = [0_u8; 32];
        if connection
            .export_keying_material(&mut expected, uuid.as_bytes(), password.as_bytes())
            .is_err()
        {
            return false;
        }
        &auth_header[18..] == expected.as_slice()
    });
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tuic uuid/password authentication failed",
        ));
    }
    Ok(())
}

async fn accept_tcp_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> io::Result<(String, TuicQuicStream)> {
    let mut header = [0_u8; 2];
    recv.read_exact(&mut header).await.map_err(io::Error::other)?;
    if header != [0x05, 0x01] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tuic tcp header",
        ));
    }
    let target = read_tuic_target(&mut recv).await?;
    Ok((target, TuicQuicStream::new(send, recv)))
}

async fn read_tuic_target(stream: &mut quinn::RecvStream) -> io::Result<String> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp).await.map_err(io::Error::other)?;
    let host = match atyp[0] {
        0x00 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await.map_err(io::Error::other)?;
            let mut host = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut host).await.map_err(io::Error::other)?;
            String::from_utf8(host)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?
        }
        0x01 => {
            let mut ip = [0_u8; 4];
            stream.read_exact(&mut ip).await.map_err(io::Error::other)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x02 => {
            let mut ip = [0_u8; 16];
            stream.read_exact(&mut ip).await.map_err(io::Error::other)?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected tuic atyp {other}"),
            ));
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await.map_err(io::Error::other)?;
    Ok(format!("{host}:{}", u16::from_be_bytes(port)))
}

async fn run_udp_loop(
    connection: QuinnConnection,
    tunnel: Arc<RuntimeTunnel>,
    config: TuicListenerConfig,
    local_addr: SocketAddr,
) -> io::Result<()> {
    let v4 = !config.token.is_empty();
    loop {
        let bytes = connection.read_datagram().await.map_err(io::Error::other)?;
        let mut cursor = io::Cursor::new(bytes.to_vec());
        let (target, payload) = if v4 {
            decode_tuic_v4_packet(&mut cursor)?
        } else {
            decode_tuic_v5_packet(&mut cursor)?
        };
        let packet = Arc::new(TuicInboundUdpPacket {
            local_addr,
            payload: ByteWindow::freeze(payload),
            source: target,
            connection: connection.clone(),
            v4,
            max_udp_relay_packet_size: config.max_udp_relay_packet_size,
        });
        let mut metadata = Metadata {
            network: NetworkKind::Udp,
            kind: SessionKind::Tuic,
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
            if let Err(err) = tunnel.write_back_udp(&envelope, ByteWindow::freeze(response), responder) {
                let message = format!("tuic inbound udp write-back error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
            }
        }
    }
}
