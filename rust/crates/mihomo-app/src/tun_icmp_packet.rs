use std::io;
use std::net::{IpAddr, SocketAddr};

use mihomo_tun::TunRuntimeSpec;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress as SmolIpAddress,
    IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedTunIcmpPacket {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub hop_limit: u8,
    pub response_frame: Vec<u8>,
}

pub(crate) fn parse_tun_icmp_packet(
    spec: &TunRuntimeSpec,
    frame: &[u8],
) -> io::Result<Option<ParsedTunIcmpPacket>> {
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun packet is empty",
        ));
    }

    match frame[0] >> 4 {
        4 => parse_tun_icmp_ipv4_packet(spec, frame),
        6 => parse_tun_icmp_ipv6_packet(spec, frame),
        _ => Ok(None),
    }
}

fn parse_tun_icmp_ipv4_packet(
    spec: &TunRuntimeSpec,
    frame: &[u8],
) -> io::Result<Option<ParsedTunIcmpPacket>> {
    let checksum_caps = ChecksumCapabilities::default();
    let ipv4 = Ipv4Packet::new_checked(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 packet"))?;
    let ipv4_repr = Ipv4Repr::parse(&ipv4, &checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 repr"))?;
    if ipv4_repr.next_header != IpProtocol::Icmp {
        return Ok(None);
    }

    let icmp = Icmpv4Packet::new_checked(ipv4.payload())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid icmp packet"))?;
    let repr = Icmpv4Repr::parse(&icmp, &checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid icmpv4 repr"))?;
    let Icmpv4Repr::EchoRequest { ident, seq_no, data } = repr else {
        return Ok(None);
    };
    if !spec.config.disable_icmp_forwarding {
        return Ok(None);
    }

    let reply_repr = Icmpv4Repr::EchoReply { ident, seq_no, data };
    let mut response = vec![0_u8; ipv4_repr.buffer_len() + reply_repr.buffer_len()];
    {
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut response);
        let ip_reply = Ipv4Repr {
            src_addr: ipv4_repr.dst_addr,
            dst_addr: ipv4_repr.src_addr,
            next_header: IpProtocol::Icmp,
            payload_len: reply_repr.buffer_len(),
            hop_limit: ipv4_repr.hop_limit,
        };
        ip_reply.emit(&mut ip_packet, &checksum_caps);
        let mut icmp_packet = Icmpv4Packet::new_unchecked(ip_packet.payload_mut());
        reply_repr.emit(&mut icmp_packet, &checksum_caps);
    }

    Ok(Some(ParsedTunIcmpPacket {
        source: SocketAddr::new(IpAddr::V4(ipv4_repr.dst_addr.into()), 0),
        destination: SocketAddr::new(IpAddr::V4(ipv4_repr.src_addr.into()), 0),
        hop_limit: ipv4_repr.hop_limit,
        response_frame: response,
    }))
}

fn parse_tun_icmp_ipv6_packet(
    spec: &TunRuntimeSpec,
    frame: &[u8],
) -> io::Result<Option<ParsedTunIcmpPacket>> {
    let checksum_caps = ChecksumCapabilities::default();
    let ipv6 = Ipv6Packet::new_checked(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv6 packet"))?;
    let ipv6_repr = Ipv6Repr::parse(&ipv6)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv6 repr"))?;
    if ipv6_repr.next_header != IpProtocol::Icmpv6 {
        return Ok(None);
    }

    let src_addr = SmolIpAddress::Ipv6(ipv6_repr.src_addr);
    let dst_addr = SmolIpAddress::Ipv6(ipv6_repr.dst_addr);
    let icmp = Icmpv6Packet::new_checked(ipv6.payload())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid icmp packet"))?;
    let repr = Icmpv6Repr::parse(&src_addr, &dst_addr, &icmp, &checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid icmpv6 repr"))?;
    let Icmpv6Repr::EchoRequest { ident, seq_no, data } = repr else {
        return Ok(None);
    };
    if !spec.config.disable_icmp_forwarding {
        return Ok(None);
    }

    let reply_repr = Icmpv6Repr::EchoReply { ident, seq_no, data };
    let mut response = vec![0_u8; ipv6_repr.buffer_len() + reply_repr.buffer_len()];
    {
        let mut ip_packet = Ipv6Packet::new_unchecked(&mut response);
        let ip_reply = Ipv6Repr {
            src_addr: ipv6_repr.dst_addr,
            dst_addr: ipv6_repr.src_addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: reply_repr.buffer_len(),
            hop_limit: ipv6_repr.hop_limit,
        };
        ip_reply.emit(&mut ip_packet);
        let mut icmp_packet = Icmpv6Packet::new_unchecked(ip_packet.payload_mut());
        reply_repr.emit(&dst_addr, &src_addr, &mut icmp_packet, &checksum_caps);
    }

    Ok(Some(ParsedTunIcmpPacket {
        source: SocketAddr::new(IpAddr::V6(ipv6_repr.dst_addr.into()), 0),
        destination: SocketAddr::new(IpAddr::V6(ipv6_repr.src_addr.into()), 0),
        hop_limit: ipv6_repr.hop_limit,
        response_frame: response,
    }))
}
