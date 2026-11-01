use std::time::Duration;

#[path = "listener_udp_dispatch.rs"]
mod listener_udp_dispatch;
#[path = "listener_udp_session.rs"]
mod listener_udp_session;
#[path = "listener_udp_session_ops.rs"]
mod listener_udp_session_ops;
#[path = "listener_udp_prepare.rs"]
mod listener_udp_prepare;
#[path = "listener_udp_socks5.rs"]
mod listener_udp_socks5;
#[path = "listener_udp_stream_io.rs"]
mod listener_udp_stream_io;
#[path = "listener_service_builders.rs"]
mod listener_service_builders;
#[path = "listener_service_configs.rs"]
mod listener_service_configs;
#[path = "listener_service_dialer.rs"]
mod listener_service_dialer;
#[path = "listener_service_models.rs"]
mod listener_service_models;
#[path = "listener_service_runtime.rs"]
mod listener_service_runtime;
#[path = "listener_service_runner.rs"]
mod listener_service_runner;
#[path = "listener_service_special_inbounds.rs"]
mod listener_service_special_inbounds;
#[path = "listener_service_sudoku.rs"]
mod listener_service_sudoku;
#[cfg(test)]
#[path = "listener_service_test_support.rs"]
mod listener_service_test_support;
#[path = "listener_service_types.rs"]
mod listener_service_types;
#[path = "transparent/mod.rs"]
pub(crate) mod transparent;
#[path = "listener_service_xhttp.rs"]
mod listener_service_xhttp;
#[path = "listener_service_v2_inbounds.rs"]
mod listener_service_v2_inbounds;
#[path = "listener_udp_outbound.rs"]
mod listener_udp_outbound;
#[path = "hy2_inbound/mod.rs"]
mod hy2_inbound;
#[path = "hy2_realm_inbound/mod.rs"]
mod hy2_realm_inbound;
#[path = "tuic_inbound/mod.rs"]
mod tuic_inbound;
#[path = "special_inbounds.rs"]
mod special_inbounds;
pub(crate) use listener_service_dialer::DnsAwareTcpDialer;
pub use listener_service_runner::RunningListenerService;
#[cfg(test)]
pub(crate) use listener_service_test_support::{
    connect_sudoku_udp_stream_for_tests, exercise_openvpn_udp_route_for_tests,
    exercise_sudoku_udp_route_for_tests, exercise_sudoku_udp_write_back_for_tests,
};
pub use listener_service_types::{BoundTcpListener, ListenerServiceError};
pub(crate) use transparent::configure_tproxy_udp_listener_socket;
pub(crate) use listener_udp_socks5::build_socks5_udp_packet;
pub(crate) use listener_udp_session::SystemUdpSession;

const LISTENER_POLL_TIMEOUT: Duration = Duration::from_millis(200);
