use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;

use mihomo_dns::DnsRuntime;
use mihomo_inbound::{RedirInboundConfig, TProxyInboundConfig};
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};

pub(crate) fn handle_redir_connection(
    _config: RedirInboundConfig,
    _tunnel: Arc<RuntimeTunnel>,
    _stream: TcpStream,
    _peer_addr: Option<SocketAddr>,
    _dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    Err(ListenerRuntimeError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "redir listener is only implemented on Linux/Android",
    )))
}

pub(crate) fn handle_tproxy_connection(
    _config: TProxyInboundConfig,
    _tunnel: Arc<RuntimeTunnel>,
    _stream: TcpStream,
    _peer_addr: Option<SocketAddr>,
    _dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    Err(ListenerRuntimeError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "tproxy listener is only implemented on Linux/Android",
    )))
}

pub(crate) fn create_or_get_local_conn(
    _original_target_addr: &SocketAddr,
    _original_client_addr: &SocketAddr,
    _tunnel: &RuntimeTunnel,
) -> io::Result<Arc<UdpSocket>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transparent udp write-back is only implemented on Linux/Android",
    ))
}

pub(crate) fn configure_tproxy_udp_listener_socket(_listener: &UdpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transparent udp recvmsg is only implemented on Linux/Android",
    ))
}

pub(crate) fn configure_tproxy_tcp_listener_socket(
    _listener: &std::net::TcpListener,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tproxy listener is only implemented on Linux/Android",
    ))
}

pub(crate) fn recv_transparent_udp_packet(
    _listener: &UdpSocket,
) -> io::Result<Option<(Vec<u8>, SocketAddr, SocketAddr)>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transparent udp recvmsg is only implemented on Linux/Android",
    ))
}
