use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use mihomo_buf::ByteWindow;
use mihomo_core::{
    BoxedTcpStream, ConnectionContext, Metadata, NetworkKind, PacketEnvelope, SessionKind,
};
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};
use mihomo_transport::{
    accept_sudoku_stream, accept_sudoku_stream_allow_suspicious,
    accept_sudoku_stream_with_custom_tables, accept_sudoku_stream_with_custom_tables_allow_suspicious,
    accept_sudoku_stream_with_custom_tables_and_http_mask, accept_sudoku_stream_with_http_mask,
    read_sudoku_udp_packet, SudokuAcceptedStream, SudokuInboundAccept, TransportError,
};

use crate::listener_service_support::accept_tls_server_stream;
use crate::listener_udp_support::StreamBackedUdpPacket;

use super::listener_service_configs::SudokuInboundConfig;
use super::SystemUdpSession;

pub(super) fn handle_sudoku_connection(
    config: SudokuInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let stream: BoxedTcpStream = if let Some(tls_config) = config.tls_config.clone() {
        accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
    } else {
        Box::new(stream)
    };
    let maybe_accept = if config.custom_table.trim().is_empty() && config.custom_tables.is_empty() {
        if config.http_mask_enabled && !config.http_mask_mode.trim().is_empty() {
            accept_sudoku_stream_with_http_mask(
                stream,
                config
                    .http_mask_acceptor
                    .as_ref()
                    .expect("http-mask acceptor missing"),
                &config.key,
                &config.aead_method,
                &config.table_type,
                config.padding_min,
                config.padding_max,
                config.enable_pure_downlink,
                false,
            )
        } else {
            let accepted: Result<SudokuInboundAccept, TransportError> = if config.fallback.is_empty() {
                accept_sudoku_stream(
                    stream,
                    &config.key,
                    &config.aead_method,
                    &config.table_type,
                    config.padding_min,
                    config.padding_max,
                    config.enable_pure_downlink,
                    config.http_mask_enabled,
                )
                .map(SudokuInboundAccept::Session)
            } else {
                accept_sudoku_stream_allow_suspicious(
                    stream,
                    &config.key,
                    &config.aead_method,
                    &config.table_type,
                    config.padding_min,
                    config.padding_max,
                    config.enable_pure_downlink,
                    config.http_mask_enabled,
                )
            };
            accepted.map(Some)
        }
    } else if config.http_mask_enabled && !config.http_mask_mode.trim().is_empty() {
        accept_sudoku_stream_with_custom_tables_and_http_mask(
            stream,
            config
                .http_mask_acceptor
                .as_ref()
                .expect("http-mask acceptor missing"),
            &config.key,
            &config.aead_method,
            &config.table_type,
            config.padding_min,
            config.padding_max,
            config.enable_pure_downlink,
            false,
            &config.custom_table,
            &config.custom_tables,
        )
    } else {
        let accepted: Result<SudokuInboundAccept, TransportError> = if config.fallback.is_empty() {
            accept_sudoku_stream_with_custom_tables(
                stream,
                &config.key,
                &config.aead_method,
                &config.table_type,
                config.padding_min,
                config.padding_max,
                config.enable_pure_downlink,
                config.http_mask_enabled,
                &config.custom_table,
                &config.custom_tables,
            )
            .map(SudokuInboundAccept::Session)
        } else {
            accept_sudoku_stream_with_custom_tables_allow_suspicious(
                stream,
                &config.key,
                &config.aead_method,
                &config.table_type,
                config.padding_min,
                config.padding_max,
                config.enable_pure_downlink,
                config.http_mask_enabled,
                &config.custom_table,
                &config.custom_tables,
            )
        };
        accepted.map(Some)
    };
    let maybe_accept =
        maybe_accept.map_err(|err| ListenerRuntimeError::Io(io::Error::new(io::ErrorKind::Other, err)))?;
    let Some(accept) = maybe_accept else {
        return Ok(());
    };

    let session = match accept {
        SudokuInboundAccept::Session(session) => session,
        SudokuInboundAccept::PassThrough(stream) | SudokuInboundAccept::Rejected(stream) => {
            if config.fallback.is_empty() {
                return Ok(());
            }
            return forward_sudoku_fallback(stream, &config, tunnel, peer_addr);
        }
    };

    match session {
        SudokuAcceptedStream::Tcp { target, stream } => {
            let mut metadata = Metadata {
                network: NetworkKind::Tcp,
                kind: SessionKind::Sudoku,
                inbound_name: config.base.name.clone(),
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
        SudokuAcceptedStream::Multiplex { server } => loop {
            let (stream, target) = match server.accept_tcp() {
                Ok(accepted) => accepted,
                Err(err) if matches!(err.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) => {
                    return Ok(());
                }
                Err(err) => return Err(ListenerRuntimeError::Io(err)),
            };
            let tunnel = tunnel.clone();
            let inbound_name = config.base.name.clone();
            let special_proxy = config.base.special_proxy.clone();
            let special_rules = config.base.special_rules.clone();
            let peer = peer_addr;
            crate::blocking_executor::spawn_blocking(move || {
                let mut metadata = Metadata {
                    network: NetworkKind::Tcp,
                    kind: SessionKind::Sudoku,
                    inbound_name,
                    special_proxy,
                    special_rules,
                    ..Metadata::default()
                };
                if let Some(peer) = peer {
                    metadata.src_ip = Some(peer.ip());
                    metadata.src_port = Some(peer.port());
                }
                if metadata.set_remote_address(&target).is_err() {
                    return;
                }
                let mut context = ConnectionContext::new(stream, metadata);
                let _ = tunnel.forward_tcp_context_with_system_dialer(&mut context);
            });
        },
        SudokuAcceptedStream::Udp { stream } => {
            let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let stream = Arc::new(Mutex::new(stream));
            loop {
                let (source, payload) = {
                    let mut guard = stream.lock().map_err(|_| {
                        ListenerRuntimeError::Io(io::Error::other(
                            "sudoku udp inbound stream mutex poisoned",
                        ))
                    })?;
                    match read_sudoku_udp_packet(&mut **guard) {
                        Ok(packet) => packet,
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                        Err(err) => return Err(ListenerRuntimeError::Io(err)),
                    }
                };

                let packet = Arc::new(StreamBackedUdpPacket {
                    payload: ByteWindow::freeze(payload),
                    local_addr,
                    peer_addr,
                    outbound_source: source,
                    stream: Arc::clone(&stream),
                });
                let mut metadata = Metadata {
                    network: NetworkKind::Udp,
                    kind: SessionKind::Sudoku,
                    inbound_name: config.base.name.clone(),
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

fn forward_sudoku_fallback(
    stream: BoxedTcpStream,
    config: &SudokuInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::Inner,
        inbound_name: config.base.name.clone(),
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata
        .set_remote_address(&config.fallback)
        .map_err(ListenerRuntimeError::from)?;
    let mut context = ConnectionContext::new(stream, metadata);
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)?;
    Ok(())
}
