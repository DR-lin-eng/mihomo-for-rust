#[path = "listener_udp_outbound_socks5.rs"]
mod listener_udp_outbound_socks5;
#[path = "listener_udp_outbound_streams.rs"]
mod listener_udp_outbound_streams;
#[path = "listener_udp_outbound_support.rs"]
mod listener_udp_outbound_support;
#[path = "listener_udp_outbound_tunnels.rs"]
mod listener_udp_outbound_tunnels;
#[cfg(test)]
#[path = "listener_udp_outbound_test_support.rs"]
mod listener_udp_outbound_test_support;

pub(super) use listener_udp_outbound_socks5::{
    socks5_udp_associate,
};
pub(super) use listener_udp_outbound_streams::{
    connect_anytls_udp_stream, connect_gost_relay_udp_stream,
    connect_snell_udp_stream, connect_trojan_udp_stream,
    connect_trusttunnel_udp_stream, connect_tuic_udp_stream,
    connect_vless_udp_stream, connect_vmess_udp_stream,
};
pub(super) use listener_udp_outbound_support::{
    format_target, resolve_host_to_ipaddr, resolve_udp_proxy_server_addr,
};
pub(super) use listener_udp_outbound_tunnels::{
    connect_hy2_udp_stream, connect_hysteria_udp_stream,
    connect_masque_udp_stream, connect_openvpn_udp_stream,
    connect_sudoku_udp_stream, connect_wireguard_udp_stream,
};
#[cfg(test)]
pub(crate) use listener_udp_outbound_test_support::{
    connect_sudoku_udp_stream_for_tests,
    exercise_openvpn_udp_route_for_tests,
    exercise_sudoku_udp_route_for_tests,
    exercise_sudoku_udp_write_back_for_tests,
};
