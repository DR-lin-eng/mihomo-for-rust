use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, Metadata, UdpSession};
use mihomo_dns::DnsRuntime;
use mihomo_inbound::{BaseInboundConfig, TunnelInboundConfig};
use mihomo_runtime::{RuntimeTunnel, UdpSudokuRoute};

use super::listener_udp_outbound_tunnels::connect_sudoku_udp_stream;

pub(crate) fn connect_sudoku_udp_stream_for_tests(
    route: &UdpSudokuRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    connect_sudoku_udp_stream(route, tunnel, dns_runtime)
}

pub(crate) fn exercise_sudoku_udp_route_for_tests(
    tunnel: Arc<RuntimeTunnel>,
    metadata: &mut Metadata,
    payload: ByteWindow,
    target: SocketAddr,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut session = super::super::SystemUdpSession::new(tunnel, None)?;
    session.prepare_send(metadata)?;
    session.send_to(payload, target)?;
    session.recv_once()
}

pub(crate) fn exercise_openvpn_udp_route_for_tests(
    tunnel: Arc<RuntimeTunnel>,
    metadata: &mut Metadata,
    payload: ByteWindow,
    target: SocketAddr,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut session = super::super::SystemUdpSession::new(tunnel, None)?;
    session.prepare_send(metadata)?;
    session.send_to(payload, target)?;
    session.recv_once()
}

pub(crate) fn exercise_sudoku_udp_write_back_for_tests(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    tunnel: Arc<RuntimeTunnel>,
    special_proxy: &str,
    target: &str,
    dns_runtime: Option<DnsRuntime>,
    payload: Vec<u8>,
) -> io::Result<()> {
    let listener = super::super::listener_service_models::ManagedUdpListenerConfig {
        name: "edge-udp".into(),
        address: "127.0.0.1:0".into(),
        handler: super::super::listener_service_models::ManagedUdpListenerHandler::Tunnel(
            TunnelInboundConfig {
                base: BaseInboundConfig {
                    name: "edge-udp".into(),
                    listen: "127.0.0.1".into(),
                    port: "0".into(),
                    special_rules: String::new(),
                    special_proxy: special_proxy.to_owned(),
                },
                target: target.to_owned(),
                network: vec!["udp".into()],
                extra: BTreeMap::new(),
            },
        ),
    };
    super::super::listener_udp_dispatch::handle_udp_packet(
        socket,
        peer_addr,
        payload,
        tunnel,
        listener,
        dns_runtime,
    )
}
