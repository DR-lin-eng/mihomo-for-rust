use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use mihomo_buf::ByteWindow;
use mihomo_core::{Metadata, NetworkKind, PacketEnvelope, SessionKind, UdpPacket, WriteBack};
use mihomo_dns::DnsRuntime;
use mihomo_runtime::RuntimeTunnel;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux_android;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod non_linux;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) use linux_android::{handle_redir_connection, handle_tproxy_connection};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux_android::create_or_get_local_conn;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux_android::{
    configure_tproxy_tcp_listener_socket, configure_tproxy_udp_listener_socket,
    recv_transparent_udp_packet,
};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) use non_linux::{handle_redir_connection, handle_tproxy_connection};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) use non_linux::create_or_get_local_conn;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) use non_linux::{
    configure_tproxy_tcp_listener_socket, configure_tproxy_udp_listener_socket,
    recv_transparent_udp_packet,
};

pub(crate) fn handle_tproxy_udp_packet(
    inbound_listener_addr: SocketAddr,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: Vec<u8>,
    tunnel: Arc<RuntimeTunnel>,
    inbound_name: String,
    special_proxy: String,
    special_rules: String,
    dns_runtime: Option<DnsRuntime>,
    session_kind: SessionKind,
) -> io::Result<()> {
    let packet = Arc::new(TransparentUdpPacket {
        payload: ByteWindow::freeze(payload),
        inbound_listener_addr,
        original_client_addr: peer_addr,
        original_target_addr: target_addr,
        tunnel: Arc::clone(&tunnel),
    });
    let metadata = Metadata {
        network: NetworkKind::Udp,
        kind: session_kind,
        inbound_name,
        special_proxy,
        special_rules,
        src_ip: Some(peer_addr.ip()),
        src_port: Some(peer_addr.port()),
        dst_ip: Some(target_addr.ip()),
        dst_port: Some(target_addr.port()),
        ..Metadata::default()
    };
    let envelope = PacketEnvelope::new(packet, metadata);
    let mut session = crate::listener_service::SystemUdpSession::new(tunnel.clone(), dns_runtime)?;
    let _ = tunnel.send_udp_packet(&envelope, &mut session)?;
    if let Some((response, responder)) = session.recv_once()? {
        tunnel.write_back_udp(&envelope, ByteWindow::freeze(response), responder)?;
    }
    Ok(())
}

struct TransparentUdpPacket {
    payload: ByteWindow,
    inbound_listener_addr: SocketAddr,
    original_client_addr: SocketAddr,
    original_target_addr: SocketAddr,
    tunnel: Arc<RuntimeTunnel>,
}

impl WriteBack for TransparentUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.original_target_addr);
        let conn = create_or_get_local_conn(&source, &self.original_client_addr, &self.tunnel)?;
        conn.send(payload.as_slice())
    }
}

impl UdpPacket for TransparentUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.original_client_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.inbound_listener_addr)
    }
}
