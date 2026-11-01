use std::io;
use std::net::SocketAddr;

use mihomo_core::BoxedTcpStream;
use mihomo_dns::DnsRuntime;
use mihomo_runtime::{
    ExecutionPlan, RuntimeTunnel, UdpAnyTlsRoute, UdpGostRelayRoute, UdpSnellRoute,
    UdpTrojanRoute, UdpTrustTunnelRoute, UdpTuicRoute, UdpVlessRoute, UdpVmessRoute,
};
use mihomo_transport::{
    open_anytls_udp_stream, open_gost_relay_udp_stream, open_trojan_udp_stream,
    open_trusttunnel_quic_udp_stream, open_trusttunnel_quic_udp_stream_with_socks5_stream,
    open_trusttunnel_udp_stream, open_tuic_udp_stream_with_dialer,
    open_tuic_udp_stream_with_socks5_stream, open_vless_packetaddr_udp_stream,
    open_vless_udp_stream, open_vless_xudp_stream, open_vmess_packetaddr_udp_stream,
    open_vmess_udp_stream, open_vmess_xudp_stream, wrap_grpc_proxy_stream,
    wrap_grpc_tls_proxy_stream, wrap_h2_proxy_stream, wrap_h2_tls_proxy_stream,
    wrap_http_proxy_stream, wrap_smux_stream, wrap_snell_udp_stream, wrap_tls_proxy_stream,
    wrap_websocket_proxy_stream, wrap_xhttp_proxy_stream, wrap_xhttp_tls_proxy_stream,
    TransportTarget, TuicUdpOptions,
};

use super::listener_udp_outbound_support::{
    connect_udp_dialer_proxy_stream, resolve_outer_socks5_udp_stream,
    resolve_tuic_outer_socks5_stream,
};

include!("listener_udp_outbound_streams_basic.rs");
include!("listener_udp_outbound_streams_trojanish.rs");
include!("listener_udp_outbound_streams_v.rs");
include!("listener_udp_outbound_streams_gost.rs");
