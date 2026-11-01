use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, Metadata};
use mihomo_dns::DnsRuntime;
use mihomo_runtime::{RuntimeTunnel, UdpSudokuRoute};

use super::listener_udp_outbound;

pub(crate) fn connect_sudoku_udp_stream_for_tests(
    route: &UdpSudokuRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    listener_udp_outbound::connect_sudoku_udp_stream_for_tests(route, tunnel, dns_runtime)
}

pub(crate) fn exercise_openvpn_udp_route_for_tests(
    tunnel: Arc<RuntimeTunnel>,
    metadata: &mut Metadata,
    payload: ByteWindow,
    target: SocketAddr,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    listener_udp_outbound::exercise_openvpn_udp_route_for_tests(tunnel, metadata, payload, target)
}

pub(crate) fn exercise_sudoku_udp_route_for_tests(
    tunnel: Arc<RuntimeTunnel>,
    metadata: &mut Metadata,
    payload: ByteWindow,
    target: SocketAddr,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    listener_udp_outbound::exercise_sudoku_udp_route_for_tests(tunnel, metadata, payload, target)
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
    listener_udp_outbound::exercise_sudoku_udp_write_back_for_tests(
        socket,
        peer_addr,
        tunnel,
        special_proxy,
        target,
        dns_runtime,
        payload,
    )
}
