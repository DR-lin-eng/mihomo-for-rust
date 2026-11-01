use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use bytes::Bytes;
use mihomo_buf::ByteWindow;
use mihomo_core::{UdpPacket, WriteBack};
use quinn::{Connection as QuinnConnection, SendDatagramError};

pub(super) struct Hy2InboundUdpPacket {
    pub local_addr: SocketAddr,
    pub payload: ByteWindow,
    pub source: SocketAddr,
    pub session_id: u32,
    pub packet_id: u16,
    pub connection: QuinnConnection,
    pub udp_mtu: usize,
}

impl WriteBack for Hy2InboundUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.source);
        let response = Hy2UdpMessage {
            session_id: self.session_id,
            packet_id: self.packet_id,
            fragment_id: 0,
            fragment_total: 1,
            destination: source.to_string(),
            payload: payload.as_slice().to_vec(),
        };
        send_hy2_packet(&self.connection, response, self.udp_mtu)?;
        Ok(payload.len())
    }
}

impl UdpPacket for Hy2InboundUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[derive(Clone, Debug)]
pub(super) struct Hy2UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_total: u8,
    pub destination: String,
    pub payload: Vec<u8>,
}

pub(super) fn decode_hy2_varint(stream: &mut dyn Read) -> io::Result<u64> {
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first)?;
    let tag = first[0] >> 6;
    let mut buf = [0_u8; 8];
    match tag {
        0 => Ok((first[0] & 0x3f) as u64),
        1 => {
            buf[0] = first[0];
            stream.read_exact(&mut buf[1..2])?;
            Ok(u16::from_be_bytes(buf[..2].try_into().unwrap()) as u64 & 0x3fff)
        }
        2 => {
            buf[0] = first[0];
            stream.read_exact(&mut buf[1..4])?;
            Ok(u32::from_be_bytes(buf[..4].try_into().unwrap()) as u64 & 0x3fff_ffff)
        }
        _ => {
            buf[0] = first[0];
            stream.read_exact(&mut buf[1..8])?;
            Ok(u64::from_be_bytes(buf) & 0x3fff_ffff_ffff_ffff)
        }
    }
}

pub(super) fn write_hy2_varint(stream: &mut dyn Write, value: u64) -> io::Result<()> {
    if value < (1 << 6) {
        stream.write_all(&[value as u8])?;
    } else if value < (1 << 14) {
        let mut bytes = ((1_u16 << 14) | value as u16).to_be_bytes();
        bytes[0] |= 0b01 << 6;
        stream.write_all(&bytes)?;
    } else if value < (1 << 30) {
        let mut bytes = ((1_u32 << 30) | value as u32).to_be_bytes();
        bytes[0] |= 0b10 << 6;
        stream.write_all(&bytes)?;
    } else {
        let mut bytes = ((1_u64 << 62) | value).to_be_bytes();
        bytes[0] |= 0b11 << 6;
        stream.write_all(&bytes)?;
    }
    Ok(())
}

pub(super) fn decode_hy2_packet(data: &[u8]) -> io::Result<Hy2UdpMessage> {
    let mut stream = io::Cursor::new(data);
    let mut session_id = [0_u8; 4];
    std::io::Read::read_exact(&mut stream, &mut session_id)?;
    let mut packet_id = [0_u8; 2];
    std::io::Read::read_exact(&mut stream, &mut packet_id)?;
    let mut fragment_id = [0_u8; 1];
    std::io::Read::read_exact(&mut stream, &mut fragment_id)?;
    let mut fragment_total = [0_u8; 1];
    std::io::Read::read_exact(&mut stream, &mut fragment_total)?;
    let destination_len = decode_hy2_varint(&mut stream)? as usize;
    let mut destination = vec![0_u8; destination_len];
    std::io::Read::read_exact(&mut stream, &mut destination)?;
    let mut payload = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut payload)?;
    Ok(Hy2UdpMessage {
        session_id: u32::from_be_bytes(session_id),
        packet_id: u16::from_be_bytes(packet_id),
        fragment_id: fragment_id[0],
        fragment_total: fragment_total[0],
        destination: String::from_utf8(destination)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
        payload,
    })
}

fn encode_hy2_packet(message: &Hy2UdpMessage) -> io::Result<Vec<u8>> {
    let mut response = Vec::new();
    response.extend_from_slice(&message.session_id.to_be_bytes());
    response.extend_from_slice(&message.packet_id.to_be_bytes());
    response.push(message.fragment_id);
    response.push(message.fragment_total);
    write_hy2_varint(&mut response, message.destination.len() as u64)?;
    response.extend_from_slice(message.destination.as_bytes());
    response.extend_from_slice(&message.payload);
    Ok(response)
}

fn fragment_hy2_packet(message: &Hy2UdpMessage, max_datagram_size: usize) -> Vec<Hy2UdpMessage> {
    let mut header = Vec::new();
    header.extend_from_slice(&message.session_id.to_be_bytes());
    header.extend_from_slice(&message.packet_id.to_be_bytes());
    header.push(0);
    header.push(0);
    let _ = write_hy2_varint(&mut header, message.destination.len() as u64);
    header.extend_from_slice(message.destination.as_bytes());
    let payload_mtu = max_datagram_size.saturating_sub(header.len()).max(1);
    if message.payload.len() <= payload_mtu {
        return vec![message.clone()];
    }
    let chunks = message.payload.chunks(payload_mtu).collect::<Vec<_>>();
    let total = chunks.len() as u8;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| Hy2UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            fragment_id: index as u8,
            fragment_total: total,
            destination: message.destination.clone(),
            payload: chunk.to_vec(),
        })
        .collect()
}

pub(super) fn defragment_hy2_packet(
    fragments: &mut BTreeMap<(u32, u16), Vec<Option<Hy2UdpMessage>>>,
    message: Hy2UdpMessage,
) -> Option<Hy2UdpMessage> {
    if message.fragment_total <= 1 {
        return Some(message);
    }
    if message.fragment_id >= message.fragment_total {
        return None;
    }
    let key = (message.session_id, message.packet_id);
    let entry = fragments
        .entry(key)
        .or_insert_with(|| vec![None; message.fragment_total as usize]);
    if entry.len() != message.fragment_total as usize {
        *entry = vec![None; message.fragment_total as usize];
    }
    if entry[message.fragment_id as usize].is_some() {
        return None;
    }
    let fragment_index = message.fragment_id as usize;
    entry[fragment_index] = Some(message);
    if entry.iter().any(Option::is_none) {
        return None;
    }
    let mut completed = entry
        .iter_mut()
        .map(|fragment| fragment.take().unwrap())
        .collect::<Vec<_>>();
    fragments.remove(&key);
    let first = completed.first().cloned()?;
    let mut payload = Vec::new();
    for fragment in completed.drain(..) {
        payload.extend_from_slice(&fragment.payload);
    }
    Some(Hy2UdpMessage {
        payload,
        fragment_id: 0,
        fragment_total: 1,
        ..first
    })
}

pub(super) fn send_hy2_packet(
    connection: &QuinnConnection,
    message: Hy2UdpMessage,
    udp_mtu: usize,
) -> io::Result<()> {
    let max_datagram_size = connection.max_datagram_size().unwrap_or(udp_mtu.max(1200));
    for fragment in fragment_hy2_packet(&message, max_datagram_size) {
        let packet = encode_hy2_packet(&fragment)?;
        match connection.send_datagram(Bytes::from(packet)) {
            Ok(()) => {}
            Err(SendDatagramError::TooLarge) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hysteria2 udp datagram too large",
                ));
            }
            Err(SendDatagramError::UnsupportedByPeer) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hysteria2 udp is disabled by peer",
                ));
            }
            Err(SendDatagramError::Disabled) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hysteria2 udp datagrams are disabled",
                ));
            }
            Err(SendDatagramError::ConnectionLost(err)) => {
                return Err(io::Error::other(err));
            }
        }
    }
    Ok(())
}
