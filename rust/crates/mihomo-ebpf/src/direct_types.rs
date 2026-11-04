use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DirectFlowKey {
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
    pub family: u32,
    pub protocol: u32,
}
impl DirectFlowKey {
    pub fn source_socket(&self) -> SocketAddr {
        SocketAddr::new(self.address(self.source), u16::from_be(self.source_port))
    }
    pub fn destination_socket(&self) -> SocketAddr {
        SocketAddr::new(
            self.address(self.destination),
            u16::from_be(self.destination_port),
        )
    }
    fn address(&self, bytes: [u8; 16]) -> IpAddr {
        if self.family == 4 {
            IpAddr::V4([bytes[0], bytes[1], bytes[2], bytes[3]].into())
        } else {
            IpAddr::V6(bytes.into())
        }
    }
    pub fn new(source: SocketAddr, destination: SocketAddr, udp: bool) -> Option<Self> {
        let mut key = Self {
            source_port: source.port().to_be(),
            destination_port: destination.port().to_be(),
            protocol: if udp { 17 } else { 6 },
            ..Self::default()
        };
        match (source.ip(), destination.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                key.family = 4;
                key.source[..4].copy_from_slice(&a.octets());
                key.destination[..4].copy_from_slice(&b.octets());
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                key.family = 6;
                key.source = a.octets();
                key.destination = b.octets();
            }
            _ => return None,
        }
        Some(key)
    }
    pub fn with_destination(mut self, destination: SocketAddr) -> Option<Self> {
        match destination.ip() {
            IpAddr::V4(ip) if self.family == 4 => {
                self.destination = [0; 16];
                self.destination[..4].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) if self.family == 6 => self.destination = ip.octets(),
            _ => return None,
        }
        self.destination_port = destination.port().to_be();
        Some(self)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DirectFlowValue {
    pub lock: u32,
    pub active: u32,
    pub id: u64,
    pub target: [u8; 16],
    pub target_port: u16,
    pub flags: u16,
    pub padding: u32,
    pub timeout_ns: u64,
    pub last_seen_ns: u64,
    pub upload: u64,
    pub download: u64,
    pub upload_ack: u32,
    pub download_ack: u32,
    pub upload_end: u32,
    pub download_end: u32,
    pub upload_fin: u32,
    pub download_fin: u32,
}

#[derive(Clone, Debug)]
pub struct DirectFlowSample {
    pub key: DirectFlowKey,
    pub id: u64,
    pub active: bool,
    pub closed: bool,
    pub last_seen_ns: u64,
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DirectOffloadStatus {
    pub enabled: bool,
    pub running: bool,
    pub interfaces: Vec<String>,
    pub program_ids: Vec<u32>,
    pub capacity: u32,
    pub flows: usize,
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Debug)]
pub struct DirectPacket {
    pub key: Option<DirectFlowKey>,
    pub tcp_syn: bool,
    pub tcp_sequence: u32,
    pub fragment: Option<DirectFragmentKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_map_layouts_and_network_ports_match() {
        assert_eq!(std::mem::size_of::<DirectFlowKey>(), 44);
        assert_eq!(std::mem::size_of::<DirectFlowValue>(), 96);
        assert_eq!(std::mem::size_of::<DirectFragmentKey>(), 44);
        for (s, d) in [
            ("192.0.2.2:32000", "198.18.0.4:443"),
            ("[2001:db8::2]:32000", "[fdfe:dcba::4]:443"),
        ] {
            let source = s.parse().unwrap();
            let destination = d.parse().unwrap();
            let key = DirectFlowKey::new(source, destination, false).unwrap();
            assert_eq!(key.source_socket(), source);
            assert_eq!(key.destination_socket(), destination);
            assert_eq!(key.destination_port.to_ne_bytes(), 443u16.to_be_bytes());
        }
        assert!(DirectPacket::parse(&[0x45, 0, 0]).is_none());
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DirectFragmentKey {
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub identifier: u32,
    pub family: u32,
    pub protocol: u32,
}

impl DirectPacket {
    pub fn parse(frame: &[u8]) -> Option<Self> {
        let version = *frame.first()? >> 4;
        let mut key = DirectFlowKey::default();
        let mut fragment_id = 0;
        let mut fragment_offset = 0;
        let mut more = false;
        let mut offset = match version {
            4 => {
                if frame.len() < 20 {
                    return None;
                }
                let n = usize::from(frame[0] & 15) * 4;
                if n < 20 || n > frame.len() {
                    return None;
                }
                key.family = 4;
                key.protocol = u32::from(frame[9]);
                key.source[..4].copy_from_slice(&frame[12..16]);
                key.destination[..4].copy_from_slice(&frame[16..20]);
                let flags = u16::from_be_bytes(frame[6..8].try_into().ok()?);
                fragment_offset = flags & 0x1fff;
                more = flags & 0x2000 != 0;
                fragment_id = u32::from(u16::from_ne_bytes(frame[4..6].try_into().ok()?));
                n
            }
            6 => {
                if frame.len() < 40 {
                    return None;
                }
                key.family = 6;
                key.protocol = u32::from(frame[6]);
                key.source.copy_from_slice(&frame[8..24]);
                key.destination.copy_from_slice(&frame[24..40]);
                40
            }
            _ => return None,
        };
        if version == 6 {
            for _ in 0..4 {
                match key.protocol {
                    0 | 43 | 60 => {
                        let h = frame.get(offset..offset + 2)?;
                        key.protocol = u32::from(h[0]);
                        offset += (usize::from(h[1]) + 1) * 8;
                    }
                    44 => {
                        let h = frame.get(offset..offset + 8)?;
                        key.protocol = u32::from(h[0]);
                        let f = u16::from_be_bytes(h[2..4].try_into().ok()?);
                        fragment_offset = f >> 3;
                        more = f & 1 != 0;
                        fragment_id = u32::from_ne_bytes(h[4..8].try_into().ok()?);
                        offset += 8;
                    }
                    _ => break,
                }
            }
        }
        if key.protocol != 6 && key.protocol != 17 {
            return None;
        }
        let fragment = (fragment_offset != 0 || more).then_some(DirectFragmentKey {
            source: key.source,
            destination: key.destination,
            identifier: fragment_id,
            family: key.family,
            protocol: key.protocol,
        });
        if fragment_offset != 0 {
            return Some(Self {
                key: None,
                tcp_syn: false,
                tcp_sequence: 0,
                fragment,
            });
        }
        let h = frame.get(offset..offset + 4)?;
        key.source_port = u16::from_ne_bytes(h[..2].try_into().ok()?);
        key.destination_port = u16::from_ne_bytes(h[2..4].try_into().ok()?);
        let (tcp_syn, tcp_sequence) = if key.protocol == 6 {
            let h = frame.get(offset..offset + 20)?;
            (
                (h[13] & 0x12) == 2,
                u32::from_be_bytes(h[4..8].try_into().ok()?),
            )
        } else {
            (false, 0)
        };
        Some(Self {
            key: Some(key),
            tcp_syn,
            tcp_sequence,
            fragment,
        })
    }
}

#[cfg(unix)]
pub fn monotonic_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}
#[cfg(not(unix))]
pub fn monotonic_ns() -> u64 {
    0
}
