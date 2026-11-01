use std::io::{self, Read};
use std::net::{SocketAddr, ToSocketAddrs};

use bytes::Bytes;
use mihomo_buf::ByteWindow;
use mihomo_core::{UdpPacket, WriteBack};
use quinn::Connection as QuinnConnection;

pub(super) struct TuicInboundUdpPacket {
    pub local_addr: SocketAddr,
    pub payload: ByteWindow,
    pub source: SocketAddr,
    pub connection: QuinnConnection,
    pub v4: bool,
    pub max_udp_relay_packet_size: usize,
}

impl WriteBack for TuicInboundUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.source);
        let packet = if self.v4 {
            encode_tuic_v4_packet(source, payload.as_slice(), self.max_udp_relay_packet_size)?
        } else {
            encode_tuic_v5_packet(source, payload.as_slice(), self.max_udp_relay_packet_size)?
        };
        self.connection
            .send_datagram(Bytes::from(packet))
            .map_err(io::Error::other)?;
        Ok(payload.len())
    }
}

impl UdpPacket for TuicInboundUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

pub(super) fn decode_tuic_v5_packet(reader: &mut dyn Read) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    if header != [0x05, 0x02] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tuic v5 packet header",
        ));
    }
    let mut assoc = [0_u8; 2];
    reader.read_exact(&mut assoc)?;
    let _ = assoc;
    let mut packet_id = [0_u8; 2];
    reader.read_exact(&mut packet_id)?;
    let _ = packet_id;
    let mut frag = [0_u8; 2];
    reader.read_exact(&mut frag)?;
    let _ = frag;
    let mut size = [0_u8; 2];
    reader.read_exact(&mut size)?;
    let size = u16::from_be_bytes(size) as usize;
    let target = decode_tuic_socket_addr(reader)?;
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    Ok((target, payload))
}

pub(super) fn encode_tuic_v5_packet(
    source: SocketAddr,
    payload: &[u8],
    max_udp_relay_packet_size: usize,
) -> io::Result<Vec<u8>> {
    let mut frame = vec![0x05, 0x02];
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[1, 0]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_tuic_socket_addr(&mut frame, source);
    ensure_tuic_udp_payload_fits(payload, frame.len(), max_udp_relay_packet_size)?;
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub(super) fn decode_tuic_v4_packet(reader: &mut dyn Read) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    if header != [0x04, 0x02] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tuic v4 packet header",
        ));
    }
    let mut assoc = [0_u8; 4];
    reader.read_exact(&mut assoc)?;
    let _ = assoc;
    let mut size = [0_u8; 2];
    reader.read_exact(&mut size)?;
    let size = u16::from_be_bytes(size) as usize;
    let target = decode_tuic_socket_addr(reader)?;
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    Ok((target, payload))
}

pub(super) fn encode_tuic_v4_packet(
    source: SocketAddr,
    payload: &[u8],
    max_udp_relay_packet_size: usize,
) -> io::Result<Vec<u8>> {
    let mut frame = vec![0x04, 0x02];
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_tuic_socket_addr(&mut frame, source);
    ensure_tuic_udp_payload_fits(payload, frame.len(), max_udp_relay_packet_size)?;
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn ensure_tuic_udp_payload_fits(
    payload: &[u8],
    overhead_bytes: usize,
    max_udp_relay_packet_size: usize,
) -> io::Result<()> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp payload exceeds 65535 bytes",
        )
    })?;
    let frame_len = overhead_bytes
        .checked_add(payload_len as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tuic udp frame too large"))?;
    if frame_len > max_udp_relay_packet_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "tuic udp frame exceeds max-udp-relay-packet-size: frame={frame_len}, limit={max_udp_relay_packet_size}"
            ),
        ));
    }
    Ok(())
}

fn decode_tuic_socket_addr(reader: &mut dyn Read) -> io::Result<SocketAddr> {
    let mut atyp = [0_u8; 1];
    reader.read_exact(&mut atyp)?;
    match atyp[0] {
        0x00 => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len)?;
            let mut host = vec![0_u8; len[0] as usize];
            reader.read_exact(&mut host)?;
            let host = String::from_utf8_lossy(&host).into_owned();
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            let port = u16::from_be_bytes(port);
            (host.as_str(), port).to_socket_addrs()?.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "tuic target unresolved")
            })
        }
        0x01 => {
            let mut ip = [0_u8; 4];
            reader.read_exact(&mut ip)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                u16::from_be_bytes(port),
            ))
        }
        0x02 => {
            let mut ip = [0_u8; 16];
            reader.read_exact(&mut ip)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes(port),
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected tuic udp atyp {other}"),
        )),
    }
}

fn encode_tuic_socket_addr(buffer: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(addr) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buffer.push(0x02);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}
