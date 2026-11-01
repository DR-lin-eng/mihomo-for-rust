use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use mihomo_core::TcpStream;

use crate::ip_packet_tunnel;
use crate::tunnel_dns::{self, TunnelDnsDatagramIo, DNS_SOURCE_PORT};
use crate::TransportError;

pub(crate) fn resolve_host_via_ip_packet_io<T: crate::ip_packet_tunnel::IpPacketIo>(
    io: &mut T,
    source_ip: Ipv4Addr,
    nameservers: &[String],
    host: &str,
) -> Result<Ipv4Addr, TransportError> {
    let mut datagram_io = IpPacketDnsIo { io, source_ip };
    tunnel_dns::resolve_ipv4_host_with_datagram_io(
        &mut datagram_io,
        nameservers,
        host,
        "<masque>",
    )
}

pub fn resolve_masque_host_via_udp_stream(
    stream: &mut dyn TcpStream,
    nameservers: &[String],
    host: &str,
) -> Result<Ipv4Addr, TransportError> {
    let mut datagram_io = UdpStreamDnsIo { stream };
    tunnel_dns::resolve_ipv4_host_with_datagram_io(
        &mut datagram_io,
        nameservers,
        host,
        "<masque>",
    )
}

struct IpPacketDnsIo<'a, T> {
    io: &'a mut T,
    source_ip: Ipv4Addr,
}

impl<T: crate::ip_packet_tunnel::IpPacketIo> TunnelDnsDatagramIo for IpPacketDnsIo<'_, T> {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let packet = ip_packet_tunnel::encode_ipv4_udp_packet(self.source_ip, target, payload)?;
        self.io.write_ip_packet(&packet)
    }

    fn recv_datagram_timeout(&mut self, timeout: std::time::Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        let packet = self.io.read_ip_packet_timeout(timeout)?;
        let (source, destination, payload) = ip_packet_tunnel::decode_ipv4_udp_packet_parts(&packet)?;
        if destination.port() != DNS_SOURCE_PORT {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("unexpected masque dns destination port: {}", destination.port()),
            ));
        }
        Ok((source, payload))
    }
}

struct UdpStreamDnsIo<'a> {
    stream: &'a mut dyn TcpStream,
}

impl TunnelDnsDatagramIo for UdpStreamDnsIo<'_> {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        crate::masque_stream::write_udp_packet(self.stream, target, payload).map(|_| ())
    }

    fn recv_datagram_timeout(&mut self, _timeout: std::time::Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        crate::masque_stream::read_udp_packet(self.stream)
    }
}
