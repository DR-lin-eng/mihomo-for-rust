use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mihomo_core::BoxedTcpStream;

use crate::ip_packet_tunnel;
use crate::TransportError;

use super::OpenVpnClient;

struct OpenVpnIpPacketIo {
    client: Arc<Mutex<OpenVpnClient>>,
}

impl ip_packet_tunnel::IpPacketIo for OpenVpnIpPacketIo {
    fn write_ip_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.client
            .lock()
            .map_err(|_| io::Error::other("openvpn packet io mutex poisoned"))?
            .write_ip_packet(packet)
            .map_err(map_transport_error)
    }

    fn read_ip_packet_timeout(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        self.client
            .lock()
            .map_err(|_| io::Error::other("openvpn packet io mutex poisoned"))?
            .read_ip_packet_timeout(timeout)
            .map_err(map_transport_error)
    }

    fn close(&mut self) -> io::Result<()> {
        self.client
            .lock()
            .map_err(|_| io::Error::other("openvpn packet io mutex poisoned"))?
            .close()
    }
}

pub(super) fn connect_stream(
    client: Arc<Mutex<OpenVpnClient>>,
    source_ip: Ipv4Addr,
    mtu: usize,
    target: &crate::TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    ip_packet_tunnel::connect_tcp_stream(
        OpenVpnIpPacketIo { client },
        source_ip,
        mtu,
        target,
    )
}

fn map_transport_error(err: TransportError) -> io::Error {
    match err {
        TransportError::Io { kind, message } => io::Error::new(kind, message),
        other => io::Error::new(io::ErrorKind::Other, other.to_string()),
    }
}
