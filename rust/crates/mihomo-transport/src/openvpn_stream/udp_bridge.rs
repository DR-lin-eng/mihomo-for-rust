use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket as NetUdpSocket};

use mihomo_core::BoxedTcpStream;

use super::{
    DatagramPacketIo, OpenVpnClient, OpenVpnOptions, PacketIo, StreamPacketIo, PROTO_TCP,
};
use crate::ip_packet_tunnel;
use crate::socks5_udp_underlay::{
    build_socks5_udp_frame, connect_socks5_udp_associate_over_stream, parse_socks5_udp_frame,
};
use crate::{BasicAuth, TransportError};

pub(crate) struct Socks5UdpPacketIo {
    socket: NetUdpSocket,
    relay_addr: SocketAddr,
    remote_addr: SocketAddr,
    control_stream: BoxedTcpStream,
}

struct OpenVpnIpPacketIo {
    client: OpenVpnClient,
}

pub(crate) struct OpenVpnIpPacketIoForDns<'a> {
    pub(crate) client: &'a mut OpenVpnClient,
    pub(crate) source_ip: Ipv4Addr,
}

pub(crate) struct OpenVpnUdpStreamDnsIo<'a> {
    pub(crate) stream: &'a mut dyn mihomo_core::TcpStream,
}

impl ip_packet_tunnel::IpPacketIo for OpenVpnIpPacketIo {
    fn write_ip_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.client
            .write_ip_packet(packet)
            .map_err(map_transport_error)
    }

    fn read_ip_packet_timeout(&mut self, timeout: std::time::Duration) -> io::Result<Vec<u8>> {
        self.client
            .read_ip_packet_timeout(timeout)
            .map_err(map_transport_error)
    }

    fn close(&mut self) -> io::Result<()> {
        self.client.close()
    }
}

impl crate::tunnel_dns::TunnelDnsDatagramIo for OpenVpnIpPacketIoForDns<'_> {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let packet = ip_packet_tunnel::encode_ipv4_udp_packet(self.source_ip, target, payload)?;
        self.client
            .write_ip_packet(&packet)
            .map_err(map_transport_error)
    }

    fn recv_datagram_timeout(&mut self, timeout: std::time::Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        let packet = self
            .client
            .read_ip_packet_timeout(timeout)
            .map_err(map_transport_error)?;
        let (source, _destination, payload) = ip_packet_tunnel::decode_ipv4_udp_packet_parts(&packet)?;
        Ok((source, payload))
    }
}

impl crate::tunnel_dns::TunnelDnsDatagramIo for OpenVpnUdpStreamDnsIo<'_> {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        super::write_udp_packet(self.stream, target, payload).map(|_| ())
    }

    fn recv_datagram_timeout(&mut self, _timeout: std::time::Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        super::read_udp_packet(self.stream)
    }
}

pub(crate) fn open_udp_stream(options: &OpenVpnOptions) -> Result<BoxedTcpStream, TransportError> {
    let config = super::prepare_config(options)?;
    let io = connect_packet_io(&config)?;
    let mut client = OpenVpnClient::new(config, io)?;
    let push = client.handshake()?;
    let source_ip = ip_packet_tunnel::first_ipv4_from_prefixes(&push.prefixes)?;
    ip_packet_tunnel::open_udp_stream(OpenVpnIpPacketIo { client }, source_ip)
}

pub(crate) fn open_udp_stream_with_boxed_tcp(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
) -> Result<BoxedTcpStream, TransportError> {
    let config = super::prepare_config(options)?;
    if config.proto != PROTO_TCP {
        return Err(TransportError::UnsupportedFeature {
            proxy: format!("{}:{}", config.remote_host, config.remote_port),
            feature: "openvpn chained udp stream requires proto=tcp".to_owned(),
        });
    }
    let io = super::BoxedStreamPacketIo::new(stream).map_err(TransportError::from)?;
    let mut client = OpenVpnClient::new(config, Box::new(io))?;
    let push = client.handshake()?;
    let source_ip = ip_packet_tunnel::first_ipv4_from_prefixes(&push.prefixes)?;
    ip_packet_tunnel::open_udp_stream(OpenVpnIpPacketIo { client }, source_ip)
}

pub(crate) fn open_udp_stream_with_socks5_stream(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    let config = super::prepare_config(options)?;
    let remote_addr = resolve_openvpn_udp_remote_addr(&config)?;
    let io = Socks5UdpPacketIo::new(stream, auth, remote_addr).map_err(TransportError::from)?;
    let mut client = OpenVpnClient::new(config, Box::new(io))?;
    let push = client.handshake()?;
    let source_ip = ip_packet_tunnel::first_ipv4_from_prefixes(&push.prefixes)?;
    ip_packet_tunnel::open_udp_stream(OpenVpnIpPacketIo { client }, source_ip)
}

fn connect_packet_io(config: &super::OpenVpnConfig) -> Result<Box<dyn PacketIo>, TransportError> {
    if config.proto == PROTO_TCP {
        let stream = std::net::TcpStream::connect((config.remote_host.as_str(), config.remote_port))
            .map_err(TransportError::from)?;
        Ok(Box::new(StreamPacketIo::new(stream)))
    } else {
        let socket = mihomo_core::bind_outbound_udp("0.0.0.0:0").map_err(TransportError::from)?;
        socket
            .connect((config.remote_host.as_str(), config.remote_port))
            .map_err(TransportError::from)?;
        Ok(Box::new(DatagramPacketIo::new(socket)))
    }
}

impl Socks5UdpPacketIo {
    pub(crate) fn new(
        mut control_stream: BoxedTcpStream,
        auth: Option<BasicAuth>,
        remote_addr: SocketAddr,
    ) -> io::Result<Self> {
        let (socket, relay_addr) = connect_socks5_udp_associate_over_stream(
            &mut *control_stream,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            auth.as_ref(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_secs(1)))?;
        Ok(Self {
            socket,
            relay_addr,
            remote_addr,
            control_stream,
        })
    }
}

impl PacketIo for Socks5UdpPacketIo {
    fn read_packet(&mut self, timeout: Option<std::time::Duration>) -> io::Result<Vec<u8>> {
        self.socket.set_read_timeout(timeout)?;
        let mut buf = [0_u8; 64 * 1024];
        loop {
            let read = self.socket.recv(&mut buf)?;
            let (source, payload) = parse_socks5_udp_frame(&buf[..read])?;
            if source == self.remote_addr {
                return Ok(payload);
            }
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let framed = build_socks5_udp_frame(self.remote_addr, packet);
        self.socket.send_to(&framed, self.relay_addr).map(|_| ())
    }

    fn close(&mut self) -> io::Result<()> {
        let _ = self.control_stream.shutdown_all();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.remote_addr)
    }
}

pub(crate) fn resolve_openvpn_udp_remote_addr(
    config: &super::OpenVpnConfig,
) -> Result<SocketAddr, TransportError> {
    (config.remote_host.as_str(), config.remote_port)
        .to_socket_addrs()
        .map_err(TransportError::from)?
        .find(|addr| matches!(addr, SocketAddr::V4(_)))
        .ok_or_else(|| {
            TransportError::InvalidPlan(format!(
                "openvpn udp remote endpoint could not resolve an ipv4 address for {}:{}",
                config.remote_host, config.remote_port
            ))
        })
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn std::io::Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    ip_packet_tunnel::write_udp_packet(stream, target, payload)
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn std::io::Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    ip_packet_tunnel::read_udp_packet(stream)
}

pub(crate) fn first_ipv4_from_prefixes(prefixes: &[String]) -> io::Result<std::net::Ipv4Addr> {
    ip_packet_tunnel::first_ipv4_from_prefixes(prefixes)
}

pub(crate) fn encode_ipv4_udp_packet(
    source: std::net::Ipv4Addr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    ip_packet_tunnel::encode_ipv4_udp_packet(source, target, payload)
}

pub(crate) fn decode_ipv4_udp_packet_parts(
    packet: &[u8],
) -> io::Result<(std::net::SocketAddr, std::net::SocketAddr, Vec<u8>)> {
    ip_packet_tunnel::decode_ipv4_udp_packet_parts(packet)
}

pub(crate) fn decode_ipv4_udp_packet(
    packet: &[u8],
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    ip_packet_tunnel::decode_ipv4_udp_packet(packet)
}

fn map_transport_error(err: TransportError) -> io::Error {
    match err {
        TransportError::Io { kind, message } => io::Error::new(kind, message),
        other => io::Error::new(io::ErrorKind::Other, other.to_string()),
    }
}
