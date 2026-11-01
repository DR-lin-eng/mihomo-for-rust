use std::io::{self, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;

use mihomo_core::{push_log, BoxedTcpStream, LogLevel, SessionKind};
use mihomo_dns::DnsRuntime;
use mihomo_inbound::{HttpInboundConfig, TlsInboundConfig};
use mihomo_runtime::{
    dispatch_http_proxy_tcp_stream_with_dialer,
    dispatch_prepared_socks5_tcp_context_with_dialer, dispatch_tunnel_tcp_stream_with_dialer,
    prepare_socks5_dispatch, write_socks5_udp_associate_reply, ListenerRuntimeError,
    PreparedSocks5Dispatch, PreparedSocks5UdpAssociate, RuntimeTunnel,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::{
    listener_service_builders, listener_service_special_inbounds, listener_service_sudoku,
    listener_service_v2_inbounds, special_inbounds, DnsAwareTcpDialer,
    LISTENER_POLL_TIMEOUT,
};
use super::listener_service_models::{
    ManagedTcpListenerHandler, ManagedUdpListenerConfig, ManagedUdpListenerHandler,
};
use super::listener_udp_dispatch::{log_listener_error, UdpDispatchQueue, UdpDispatchTask};
use super::listener_udp_dispatch;
use super::transparent;
use crate::listener_service_support::build_server_tls_config;

include!("listener_service_runtime_streams.rs");
include!("listener_service_runtime_accept.rs");
include!("listener_service_runtime_udp.rs");
include!("listener_service_runtime_tls.rs");
