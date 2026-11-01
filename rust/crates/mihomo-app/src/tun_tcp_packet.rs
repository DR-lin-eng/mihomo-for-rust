use std::io;
use std::net::{IpAddr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress as SmolIpAddress, IpProtocol, IpRepr, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpPacket as SmolTcpPacket, TcpRepr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedTunTcpPacket {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub hop_limit: u8,
    pub ip_repr: IpRepr,
    pub tcp_repr: TcpReprOwned,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TunTcpFlowKey {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TcpReprOwned {
    pub src_port: u16,
    pub dst_port: u16,
    pub control: smoltcp::wire::TcpControl,
    pub seq_number: smoltcp::wire::TcpSeqNumber,
    pub ack_number: Option<smoltcp::wire::TcpSeqNumber>,
    pub window_len: u16,
    pub window_scale: Option<u8>,
    pub max_seg_size: Option<u16>,
    pub sack_permitted: bool,
    pub sack_ranges: [Option<(u32, u32)>; 3],
    pub payload: Vec<u8>,
}

impl TcpReprOwned {
    pub(crate) fn as_repr(&self) -> TcpRepr<'_> {
        TcpRepr {
            src_port: self.src_port,
            dst_port: self.dst_port,
            control: self.control,
            seq_number: self.seq_number,
            ack_number: self.ack_number,
            window_len: self.window_len,
            window_scale: self.window_scale,
            max_seg_size: self.max_seg_size,
            sack_permitted: self.sack_permitted,
            sack_ranges: self.sack_ranges,
            payload: &self.payload,
        }
    }
}

impl ParsedTunTcpPacket {
    pub(crate) fn flow_key(&self) -> TunTcpFlowKey {
        TunTcpFlowKey {
            source: self.source,
            destination: self.destination,
        }
    }
}

pub(crate) fn parse_tun_tcp_packet(frame: &[u8]) -> io::Result<ParsedTunTcpPacket> {
    let checksum_caps = ChecksumCapabilities::default();
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun tcp packet is empty",
        ));
    }
    match frame[0] >> 4 {
        4 => parse_tun_tcp_ipv4_packet(frame, &checksum_caps),
        6 => parse_tun_tcp_ipv6_packet(frame, &checksum_caps),
        version => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tun tcp packet uses unsupported ip version: {version}"),
        )),
    }
}

pub(crate) fn encode_tun_tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    hop_limit: u8,
    tcp_repr: &TcpRepr<'_>,
) -> io::Result<Vec<u8>> {
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            encode_tun_tcp_ipv4_packet(source, destination, hop_limit, tcp_repr)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            encode_tun_tcp_ipv6_packet(source, destination, hop_limit, tcp_repr)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and destination ip families must match",
        )),
    }
}

pub(crate) fn encode_loopback_rewritten_tun_tcp_packet(
    packet: &ParsedTunTcpPacket,
    source_override: IpAddr,
    destination_override: IpAddr,
) -> io::Result<Vec<u8>> {
    let source = SocketAddr::new(source_override, packet.source.port());
    let destination = SocketAddr::new(destination_override, packet.destination.port());
    encode_tun_tcp_packet(
        source,
        destination,
        packet.hop_limit,
        &packet.tcp_repr.as_repr(),
    )
}

fn parse_tun_tcp_ipv4_packet(
    frame: &[u8],
    checksum_caps: &ChecksumCapabilities,
) -> io::Result<ParsedTunTcpPacket> {
    let ipv4 = Ipv4Packet::new_checked(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 packet"))?;
    let ipv4_repr = Ipv4Repr::parse(&ipv4, checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 repr"))?;
    if ipv4_repr.next_header != IpProtocol::Tcp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun packet is not tcp",
        ));
    }
    let src_addr = SmolIpAddress::Ipv4(ipv4_repr.src_addr);
    let dst_addr = SmolIpAddress::Ipv4(ipv4_repr.dst_addr);
    let tcp = SmolTcpPacket::new_checked(ipv4.payload())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tcp packet"))?;
    let tcp_repr = TcpRepr::parse(&tcp, &src_addr, &dst_addr, checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tcp repr"))?;
    Ok(ParsedTunTcpPacket {
        source: SocketAddr::new(IpAddr::V4(ipv4_repr.src_addr.into()), tcp_repr.src_port),
        destination: SocketAddr::new(IpAddr::V4(ipv4_repr.dst_addr.into()), tcp_repr.dst_port),
        hop_limit: ipv4_repr.hop_limit,
        ip_repr: IpRepr::Ipv4(ipv4_repr),
        tcp_repr: TcpReprOwned {
            src_port: tcp_repr.src_port,
            dst_port: tcp_repr.dst_port,
            control: tcp_repr.control,
            seq_number: tcp_repr.seq_number,
            ack_number: tcp_repr.ack_number,
            window_len: tcp_repr.window_len,
            window_scale: tcp_repr.window_scale,
            max_seg_size: tcp_repr.max_seg_size,
            sack_permitted: tcp_repr.sack_permitted,
            sack_ranges: tcp_repr.sack_ranges,
            payload: tcp_repr.payload.to_vec(),
        },
    })
}

fn parse_tun_tcp_ipv6_packet(
    frame: &[u8],
    checksum_caps: &ChecksumCapabilities,
) -> io::Result<ParsedTunTcpPacket> {
    let ipv6 = Ipv6Packet::new_checked(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv6 packet"))?;
    let ipv6_repr = Ipv6Repr::parse(&ipv6)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv6 repr"))?;
    if ipv6_repr.next_header != IpProtocol::Tcp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun packet is not tcp",
        ));
    }
    let src_addr = SmolIpAddress::Ipv6(ipv6_repr.src_addr);
    let dst_addr = SmolIpAddress::Ipv6(ipv6_repr.dst_addr);
    let tcp = SmolTcpPacket::new_checked(ipv6.payload())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tcp packet"))?;
    let tcp_repr = TcpRepr::parse(&tcp, &src_addr, &dst_addr, checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tcp repr"))?;
    Ok(ParsedTunTcpPacket {
        source: SocketAddr::new(IpAddr::V6(ipv6_repr.src_addr.into()), tcp_repr.src_port),
        destination: SocketAddr::new(IpAddr::V6(ipv6_repr.dst_addr.into()), tcp_repr.dst_port),
        hop_limit: ipv6_repr.hop_limit,
        ip_repr: IpRepr::Ipv6(ipv6_repr),
        tcp_repr: TcpReprOwned {
            src_port: tcp_repr.src_port,
            dst_port: tcp_repr.dst_port,
            control: tcp_repr.control,
            seq_number: tcp_repr.seq_number,
            ack_number: tcp_repr.ack_number,
            window_len: tcp_repr.window_len,
            window_scale: tcp_repr.window_scale,
            max_seg_size: tcp_repr.max_seg_size,
            sack_permitted: tcp_repr.sack_permitted,
            sack_ranges: tcp_repr.sack_ranges,
            payload: tcp_repr.payload.to_vec(),
        },
    })
}

fn encode_tun_tcp_ipv4_packet(
    source: std::net::SocketAddrV4,
    destination: std::net::SocketAddrV4,
    hop_limit: u8,
    tcp_repr: &TcpRepr<'_>,
) -> io::Result<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let ip_repr = Ipv4Repr {
        src_addr: (*source.ip()).into(),
        dst_addr: (*destination.ip()).into(),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit,
    };
    let mut bytes = vec![0_u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
    {
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_packet, &checksum_caps);
        let mut tcp_packet = SmolTcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_repr.emit(
            &mut tcp_packet,
            &SmolIpAddress::Ipv4(ip_repr.src_addr),
            &SmolIpAddress::Ipv4(ip_repr.dst_addr),
            &checksum_caps,
        );
    }
    Ok(bytes)
}

fn encode_tun_tcp_ipv6_packet(
    source: std::net::SocketAddrV6,
    destination: std::net::SocketAddrV6,
    hop_limit: u8,
    tcp_repr: &TcpRepr<'_>,
) -> io::Result<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let ip_repr = Ipv6Repr {
        src_addr: (*source.ip()).into(),
        dst_addr: (*destination.ip()).into(),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit,
    };
    let mut bytes = vec![0_u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
    {
        let mut ip_packet = Ipv6Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_packet);
        let mut tcp_packet = SmolTcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_repr.emit(
            &mut tcp_packet,
            &SmolIpAddress::Ipv6(ip_repr.src_addr),
            &SmolIpAddress::Ipv6(ip_repr.dst_addr),
            &checksum_caps,
        );
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use smoltcp::wire::{TcpControl, TcpRepr, TcpSeqNumber};

    use super::{encode_tun_tcp_packet, parse_tun_tcp_packet};

    #[test]
    fn tun_tcp_packet_round_trips_ipv4_and_ipv6() {
        let cases: [(SocketAddr, SocketAddr, u8); 2] = [
            (
                "10.0.0.2:50000".parse().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                64_u8,
            ),
            (
                "[fd00::2]:50000".parse().unwrap(),
                "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap(),
                48_u8,
            ),
        ];
        for (source, destination, hop_limit) in cases {
            let tcp_repr = TcpRepr {
                src_port: source.port(),
                dst_port: destination.port(),
                control: TcpControl::Syn,
                seq_number: TcpSeqNumber(100),
                ack_number: None,
                window_len: 65535,
                window_scale: Some(7),
                max_seg_size: Some(1460),
                sack_permitted: true,
                sack_ranges: [None, None, None],
                payload: &[],
            };
            let encoded = encode_tun_tcp_packet(source, destination, hop_limit, &tcp_repr).unwrap();
            let parsed = parse_tun_tcp_packet(&encoded).unwrap();
            assert_eq!(parsed.source, source);
            assert_eq!(parsed.destination, destination);
            assert_eq!(parsed.hop_limit, hop_limit);
            assert_eq!(parsed.tcp_repr.control, TcpControl::Syn);
            assert_eq!(parsed.tcp_repr.seq_number, TcpSeqNumber(100));
            assert_eq!(parsed.tcp_repr.max_seg_size, Some(1460));
            assert!(parsed.tcp_repr.sack_permitted);
        }
    }

    #[test]
    fn tun_tcp_packet_keeps_payload_and_flow_key() {
        let source: SocketAddr = "10.0.0.2:50001".parse().unwrap();
        let destination: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let tcp_repr = TcpRepr {
            src_port: source.port(),
            dst_port: destination.port(),
            control: TcpControl::Psh,
            seq_number: TcpSeqNumber(1000),
            ack_number: Some(TcpSeqNumber(2000)),
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: b"hello",
        };
        let encoded = encode_tun_tcp_packet(source, destination, 32, &tcp_repr).unwrap();
        let parsed = parse_tun_tcp_packet(&encoded).unwrap();
        assert_eq!(parsed.flow_key().source, source);
        assert_eq!(parsed.flow_key().destination, destination);
        assert_eq!(parsed.tcp_repr.payload, b"hello");
        assert_eq!(parsed.tcp_repr.ack_number, Some(TcpSeqNumber(2000)));
    }
}
