use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mihomo_buf::ByteWindow;
use mihomo_core::{UdpPacket, WriteBack};
use mihomo_inbound::TunStack;
use mihomo_runtime::{dispatch_tun_udp_packet, RuntimeTunnel};
use mihomo_tun::{TunRuntimeSpec, TunUdpRuntimeMode};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress as SmolIpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    UdpPacket as SmolUdpPacket, UdpRepr,
};

use crate::listener_service::SystemUdpSession;

const DEFAULT_TUN_UDP_SESSION_POOL_CAPACITY: usize = 256;
const DEFAULT_TUN_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunUdpSessionReuseMode {
    EndpointDependent,
    EndpointIndependent,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TunUdpSessionKey {
    pub source: SocketAddr,
    pub destination: Option<SocketAddr>,
}

pub(crate) struct TunUdpSessionPool {
    state: Mutex<TunUdpSessionPoolState>,
    reuse_mode: TunUdpSessionReuseMode,
}

struct TunUdpSessionPoolState {
    sessions: HashMap<TunUdpSessionKey, TunUdpSessionEntry>,
    order: VecDeque<TunUdpSessionKey>,
    max_entries: usize,
    idle_timeout: Duration,
}

#[derive(Clone)]
struct TunUdpSessionEntry {
    session: Arc<Mutex<SystemUdpSession>>,
    last_used_at: Instant,
}

impl Default for TunUdpSessionPool {
    fn default() -> Self {
        Self::new_with_capacity(DEFAULT_TUN_UDP_SESSION_POOL_CAPACITY)
    }
}

impl TunUdpSessionPool {
    fn new_with_capacity(max_entries: usize) -> Self {
        Self::new_with_capacity_and_timeout(
            max_entries,
            DEFAULT_TUN_UDP_IDLE_TIMEOUT,
            TunUdpSessionReuseMode::EndpointDependent,
        )
    }

    pub(crate) fn from_tun_spec(spec: &TunRuntimeSpec) -> Self {
        let idle_timeout = if spec.config.udp_timeout > 0 {
            Duration::from_secs(spec.config.udp_timeout as u64)
        } else {
            DEFAULT_TUN_UDP_IDLE_TIMEOUT
        };
        let reuse_mode = if spec.uses_source_reuse_udp_runtime_path() {
            TunUdpSessionReuseMode::EndpointIndependent
        } else {
            TunUdpSessionReuseMode::EndpointDependent
        };
        Self::new_with_timeout_and_mode(idle_timeout, reuse_mode)
    }

    pub(crate) fn from_tun_config(
        udp_timeout_secs: i64,
        endpoint_independent_nat: bool,
        stack: TunStack,
    ) -> Self {
        let idle_timeout = if udp_timeout_secs > 0 {
            Duration::from_secs(udp_timeout_secs as u64)
        } else {
            DEFAULT_TUN_UDP_IDLE_TIMEOUT
        };
        let runtime_mode = if matches!(stack, TunStack::Mixed) {
            TunUdpRuntimeMode::MixedLikeRelay
        } else {
            TunUdpRuntimeMode::DirectRelay
        };
        let reuse_mode = if endpoint_independent_nat || matches!(runtime_mode, TunUdpRuntimeMode::MixedLikeRelay) {
            TunUdpSessionReuseMode::EndpointIndependent
        } else {
            TunUdpSessionReuseMode::EndpointDependent
        };
        Self::new_with_timeout_and_mode(idle_timeout, reuse_mode)
    }

    pub(crate) fn new_with_timeout(idle_timeout: Duration) -> Self {
        Self::new_with_timeout_and_mode(
            idle_timeout,
            TunUdpSessionReuseMode::EndpointDependent,
        )
    }

    fn new_with_timeout_and_mode(
        idle_timeout: Duration,
        reuse_mode: TunUdpSessionReuseMode,
    ) -> Self {
        Self::new_with_capacity_and_timeout(
            DEFAULT_TUN_UDP_SESSION_POOL_CAPACITY,
            idle_timeout,
            reuse_mode,
        )
    }

    fn new_with_capacity_and_timeout(
        max_entries: usize,
        idle_timeout: Duration,
        reuse_mode: TunUdpSessionReuseMode,
    ) -> Self {
        Self {
            state: Mutex::new(TunUdpSessionPoolState {
                sessions: HashMap::new(),
                order: VecDeque::new(),
                max_entries: max_entries.max(1),
                idle_timeout,
            }),
            reuse_mode,
        }
    }

    pub(crate) fn with_session<R>(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        tunnel: Arc<RuntimeTunnel>,
        dns_runtime: Option<mihomo_dns::DnsRuntime>,
        f: impl FnOnce(&mut SystemUdpSession) -> io::Result<R>,
    ) -> io::Result<R> {
        let key = self.session_key(source, destination);
        let session = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("tun udp session cache mutex poisoned"))?;
            let now = Instant::now();
            state.evict_expired(now);
            if let Some(existing) = state.sessions.get_mut(&key) {
                let session = Arc::clone(&existing.session);
                existing.last_used_at = now;
                state.order.retain(|entry| entry != &key);
                state.order.push_back(key.clone());
                session
            } else {
                if state.sessions.len() >= state.max_entries {
                    if let Some(evicted) = state.order.pop_front() {
                        state.sessions.remove(&evicted);
                    }
                }
                let created = Arc::new(Mutex::new(SystemUdpSession::new(tunnel, dns_runtime)?));
                state.order.push_back(key.clone());
                state.sessions.insert(
                    key.clone(),
                    TunUdpSessionEntry {
                        session: Arc::clone(&created),
                        last_used_at: now,
                    },
                );
                created
            }
        };
        let mut session = session
            .lock()
            .map_err(|_| io::Error::other("tun udp session mutex poisoned"))?;
        let result = f(&mut session);
        drop(session);
        if let Ok(mut state) = self.state.lock() {
            if let Some(existing) = state.sessions.get_mut(&key) {
                existing.last_used_at = Instant::now();
                state.order.retain(|entry| entry != &key);
                state.order.push_back(key);
            }
        }
        result
    }

    fn session_key(&self, source: SocketAddr, destination: SocketAddr) -> TunUdpSessionKey {
        TunUdpSessionKey {
            source,
            destination: match self.reuse_mode {
                TunUdpSessionReuseMode::EndpointDependent => Some(destination),
                TunUdpSessionReuseMode::EndpointIndependent => None,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.sessions.len())
            .unwrap_or(0)
    }
}


impl TunUdpSessionPoolState {
    fn evict_expired(&mut self, now: Instant) {
        let idle_timeout = self.idle_timeout;
        let mut expired = Vec::new();
        for key in self.order.iter() {
            let Some(entry) = self.sessions.get(key) else {
                expired.push(key.clone());
                continue;
            };
            if now.duration_since(entry.last_used_at) >= idle_timeout {
                expired.push(key.clone());
            }
        }
        if expired.is_empty() {
            return;
        }
        self.order.retain(|key| !expired.iter().any(|expired_key| expired_key == key));
        for key in expired {
            self.sessions.remove(&key);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedTunUdpPacket {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
    pub hop_limit: u8,
}

pub(crate) fn parse_tun_udp_packet(frame: &[u8]) -> io::Result<ParsedTunUdpPacket> {
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun packet is empty",
        ));
    }
    match frame[0] >> 4 {
        4 => parse_tun_udp_ipv4_packet(frame),
        6 => parse_tun_udp_ipv6_packet(frame),
        version => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tun packet uses unsupported ip version: {version}"),
        )),
    }
}

pub(crate) fn relay_tun_udp_packet(
    spec: &TunRuntimeSpec,
    tunnel: Arc<RuntimeTunnel>,
    parsed: ParsedTunUdpPacket,
    dns_runtime: Option<mihomo_dns::DnsRuntime>,
    session_pool: Option<&TunUdpSessionPool>,
) -> io::Result<Option<Vec<u8>>> {
    let packet = Arc::new(TunUdpPacket {
        payload: ByteWindow::freeze(parsed.payload),
        inbound_addr: parsed.source,
        sink: Arc::new(Mutex::new(None)),
    });
    let prepared = dispatch_tun_udp_packet(
        spec,
        &tunnel,
        packet.clone(),
        Some(parsed.source),
        parsed.destination,
    );
    match session_pool {
        Some(pool) => pool.with_session(
            parsed.source,
            parsed.destination,
            tunnel.clone(),
            dns_runtime,
            |session| {
                let _ = tunnel.send_udp_packet(&prepared.envelope, session)?;
                if let Some((response, responder)) = session.recv_once()? {
                    tunnel.write_back_udp(&prepared.envelope, ByteWindow::freeze(response), responder)?;
                }
                Ok(())
            },
        )?,
        None => {
            let mut session = SystemUdpSession::new(tunnel.clone(), dns_runtime)?;
            let _ = tunnel.send_udp_packet(&prepared.envelope, &mut session)?;
            if let Some((response, responder)) = session.recv_once()? {
                tunnel.write_back_udp(&prepared.envelope, ByteWindow::freeze(response), responder)?;
            }
        }
    }
    packet
        .take_frame(parsed.destination, parsed.source, parsed.hop_limit)
        .transpose()
}

fn parse_tun_udp_ipv4_packet(frame: &[u8]) -> io::Result<ParsedTunUdpPacket> {
    let checksum_caps = ChecksumCapabilities::default();
    let ipv4 = Ipv4Packet::new_checked(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 packet"))?;
    let ipv4_repr = Ipv4Repr::parse(&ipv4, &checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 repr"))?;
    if ipv4_repr.next_header != IpProtocol::Udp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun packet is not udp",
        ));
    }

    let src_addr = SmolIpAddress::Ipv4(ipv4_repr.src_addr);
    let dst_addr = SmolIpAddress::Ipv4(ipv4_repr.dst_addr);
    let udp = SmolUdpPacket::new_checked(ipv4.payload())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid udp packet"))?;
    let udp_repr = UdpRepr::parse(&udp, &src_addr, &dst_addr, &checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid udp repr"))?;

    Ok(ParsedTunUdpPacket {
        source: SocketAddr::new(IpAddr::V4(ipv4_repr.src_addr.into()), udp_repr.src_port),
        destination: SocketAddr::new(IpAddr::V4(ipv4_repr.dst_addr.into()), udp_repr.dst_port),
        payload: udp.payload().to_vec(),
        hop_limit: ipv4_repr.hop_limit,
    })
}

fn parse_tun_udp_ipv6_packet(frame: &[u8]) -> io::Result<ParsedTunUdpPacket> {
    let checksum_caps = ChecksumCapabilities::default();
    let ipv6 = Ipv6Packet::new_checked(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv6 packet"))?;
    let ipv6_repr = Ipv6Repr::parse(&ipv6)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv6 repr"))?;
    if ipv6_repr.next_header != IpProtocol::Udp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tun packet is not udp",
        ));
    }

    let src_addr = SmolIpAddress::Ipv6(ipv6_repr.src_addr);
    let dst_addr = SmolIpAddress::Ipv6(ipv6_repr.dst_addr);
    let udp = SmolUdpPacket::new_checked(ipv6.payload())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid udp packet"))?;
    let udp_repr = UdpRepr::parse(&udp, &src_addr, &dst_addr, &checksum_caps)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid udp repr"))?;

    Ok(ParsedTunUdpPacket {
        source: SocketAddr::new(IpAddr::V6(ipv6_repr.src_addr.into()), udp_repr.src_port),
        destination: SocketAddr::new(IpAddr::V6(ipv6_repr.dst_addr.into()), udp_repr.dst_port),
        payload: udp.payload().to_vec(),
        hop_limit: ipv6_repr.hop_limit,
    })
}

pub(crate) fn encode_tun_udp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    hop_limit: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            encode_tun_udp_ipv4_packet(source, destination, hop_limit, payload)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            encode_tun_udp_ipv6_packet(source, destination, hop_limit, payload)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and destination ip families must match",
        )),
    }
}

fn encode_tun_udp_ipv4_packet(
    source: std::net::SocketAddrV4,
    destination: std::net::SocketAddrV4,
    hop_limit: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let ip_repr = Ipv4Repr {
        src_addr: (*source.ip()).into(),
        dst_addr: (*destination.ip()).into(),
        next_header: IpProtocol::Udp,
        payload_len: payload.len() + UdpRepr {
            src_port: source.port(),
            dst_port: destination.port(),
        }
        .header_len(),
        hop_limit,
    };
    let udp_repr = UdpRepr {
        src_port: source.port(),
        dst_port: destination.port(),
    };
    let mut bytes = vec![0_u8; ip_repr.buffer_len() + udp_repr.header_len() + payload.len()];
    {
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_packet, &checksum_caps);
        let mut udp_packet = SmolUdpPacket::new_unchecked(ip_packet.payload_mut());
        udp_repr.emit(
            &mut udp_packet,
            &SmolIpAddress::Ipv4(ip_repr.src_addr),
            &SmolIpAddress::Ipv4(ip_repr.dst_addr),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &checksum_caps,
        );
    }
    Ok(bytes)
}

fn encode_tun_udp_ipv6_packet(
    source: std::net::SocketAddrV6,
    destination: std::net::SocketAddrV6,
    hop_limit: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let ip_repr = Ipv6Repr {
        src_addr: (*source.ip()).into(),
        dst_addr: (*destination.ip()).into(),
        next_header: IpProtocol::Udp,
        payload_len: payload.len() + UdpRepr {
            src_port: source.port(),
            dst_port: destination.port(),
        }
        .header_len(),
        hop_limit,
    };
    let udp_repr = UdpRepr {
        src_port: source.port(),
        dst_port: destination.port(),
    };
    let mut bytes = vec![0_u8; ip_repr.buffer_len() + udp_repr.header_len() + payload.len()];
    {
        let mut ip_packet = Ipv6Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_packet);
        let mut udp_packet = SmolUdpPacket::new_unchecked(ip_packet.payload_mut());
        udp_repr.emit(
            &mut udp_packet,
            &SmolIpAddress::Ipv6(ip_repr.src_addr),
            &SmolIpAddress::Ipv6(ip_repr.dst_addr),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &checksum_caps,
        );
    }
    Ok(bytes)
}

struct TunUdpPacket {
    payload: ByteWindow,
    inbound_addr: SocketAddr,
    sink: Arc<Mutex<Option<(Vec<u8>, Option<SocketAddr>)>>>,
}

impl TunUdpPacket {
    fn take_frame(
        &self,
        original_destination: SocketAddr,
        original_source: SocketAddr,
        hop_limit: u8,
    ) -> Option<io::Result<Vec<u8>>> {
        let stored = self.sink.lock().ok()?.take()?;
        let source = stored.1.unwrap_or(original_destination);
        Some(encode_tun_udp_packet(source, original_source, hop_limit, &stored.0))
    }
}

impl WriteBack for TunUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let len = payload.len();
        let mut guard = self
            .sink
            .lock()
            .map_err(|_| io::Error::other("tun udp sink mutex poisoned"))?;
        *guard = Some((payload.as_slice().to_vec(), source));
        Ok(len)
    }
}

impl UdpPacket for TunUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.inbound_addr
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use mihomo_config::parse_runtime_config_document;
    use mihomo_inbound::TunStack;
    use mihomo_runtime::build_runtime_registry;

    use super::{
        encode_tun_udp_packet, parse_tun_udp_packet, relay_tun_udp_packet, TunUdpSessionPool,
    };

    #[test]
    fn tun_udp_packet_round_trips_ipv4_and_ipv6() {
        let cases = [
            (
                "10.0.0.2:50000".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
                64,
            ),
            (
                "[fd00::2]:50000".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
                48,
            ),
        ];
        for (source, destination, hop_limit) in cases {
            let encoded = encode_tun_udp_packet(source, destination, hop_limit, b"ping").unwrap();
            let parsed = parse_tun_udp_packet(&encoded).unwrap();
            assert_eq!(parsed.source, source);
            assert_eq!(parsed.destination, destination);
            assert_eq!(parsed.hop_limit, hop_limit);
            assert_eq!(parsed.payload, b"ping");
        }
    }

    #[test]
    fn relay_tun_udp_packet_returns_raw_udp_response_frame() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let target = echo.local_addr().unwrap();
        let join = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = echo.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping");
            echo.send_to(b"pong", peer).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(mihomo_runtime::RuntimeTunnel::new(document.mode.clone(), registry));
        let request = super::ParsedTunUdpPacket {
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: target,
            payload: b"ping".to_vec(),
            hop_limit: 64,
        };

        let response = relay_tun_udp_packet(&spec, tunnel, request.clone(), None, None).unwrap();
        join.join().unwrap();
        assert!(response.is_some());
        let parsed = parse_tun_udp_packet(&response.unwrap()).unwrap();
        assert_eq!(parsed.source, request.destination);
        assert_eq!(parsed.destination, request.source);
        assert_eq!(parsed.payload, b"pong");
    }

    #[test]
    fn relay_tun_udp_packet_reuses_session_pool_for_same_flow() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let target = echo.local_addr().unwrap();
        let join = thread::spawn(move || {
            for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
                let mut buf = [0_u8; 1500];
                let (read, peer) = echo.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..read], expected);
                let response = if expected == b"ping-1" {
                    b"pong-1".as_slice()
                } else {
                    b"pong-2".as_slice()
                };
                echo.send_to(response, peer).unwrap();
            }
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(mihomo_runtime::RuntimeTunnel::new(document.mode.clone(), registry));
        let pool = TunUdpSessionPool::default();
        let first = super::ParsedTunUdpPacket {
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: target,
            payload: b"ping-1".to_vec(),
            hop_limit: 64,
        };
        let second = super::ParsedTunUdpPacket {
            payload: b"ping-2".to_vec(),
            ..first.clone()
        };

        let first_response =
            relay_tun_udp_packet(&spec, Arc::clone(&tunnel), first, None, Some(&pool)).unwrap();
        let second_response =
            relay_tun_udp_packet(&spec, tunnel, second, None, Some(&pool)).unwrap();

        join.join().unwrap();
        assert_eq!(pool.len(), 1);
        assert!(first_response.is_some());
        assert!(second_response.is_some());
        assert_eq!(
            parse_tun_udp_packet(&first_response.unwrap()).unwrap().payload,
            b"pong-1"
        );
        assert_eq!(
            parse_tun_udp_packet(&second_response.unwrap()).unwrap().payload,
            b"pong-2"
        );
    }

    #[test]
    fn tun_udp_session_pool_evicts_oldest_entry_when_capacity_is_exceeded() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(mihomo_runtime::RuntimeTunnel::new(document.mode.clone(), registry));
        let pool = TunUdpSessionPool::new_with_capacity(1);
        let first = super::ParsedTunUdpPacket {
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "1.1.1.1:53".parse().unwrap(),
            payload: b"first".to_vec(),
            hop_limit: 64,
        };
        let second = super::ParsedTunUdpPacket {
            source: "10.0.0.3:50001".parse().unwrap(),
            destination: "1.1.1.1:53".parse().unwrap(),
            payload: b"second".to_vec(),
            hop_limit: 64,
        };

        let _ = relay_tun_udp_packet(
            &spec,
            Arc::clone(&tunnel),
            first,
            None,
            Some(&pool),
        )
        .unwrap();
        let _ = relay_tun_udp_packet(&spec, tunnel, second, None, Some(&pool)).unwrap();

        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn tun_udp_session_pool_expires_idle_entry_after_configured_timeout() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let target = echo.local_addr().unwrap();
        let (peer_tx, peer_rx) = std::sync::mpsc::channel();
        let join = thread::spawn(move || {
            for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
                let mut buf = [0_u8; 1500];
                let (read, peer) = echo.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..read], expected);
                peer_tx.send(peer).unwrap();
                let response = if expected == b"ping-1" {
                    b"pong-1".as_slice()
                } else {
                    b"pong-2".as_slice()
                };
                echo.send_to(response, peer).unwrap();
            }
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(mihomo_runtime::RuntimeTunnel::new(document.mode.clone(), registry));
        let pool = TunUdpSessionPool::new_with_timeout(Duration::from_millis(50));
        let first = super::ParsedTunUdpPacket {
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: target,
            payload: b"ping-1".to_vec(),
            hop_limit: 64,
        };
        let second = super::ParsedTunUdpPacket {
            payload: b"ping-2".to_vec(),
            ..first.clone()
        };

        let first_response =
            relay_tun_udp_packet(&spec, Arc::clone(&tunnel), first, None, Some(&pool)).unwrap();
        thread::sleep(Duration::from_millis(80));
        let second_response =
            relay_tun_udp_packet(&spec, tunnel, second, None, Some(&pool)).unwrap();

        join.join().unwrap();
        let first_peer = peer_rx.recv().unwrap();
        let second_peer = peer_rx.recv().unwrap();
        assert_ne!(first_peer, second_peer);
        assert_eq!(pool.len(), 1);
        assert_eq!(
            parse_tun_udp_packet(&first_response.unwrap()).unwrap().payload,
            b"pong-1"
        );
        assert_eq!(
            parse_tun_udp_packet(&second_response.unwrap()).unwrap().payload,
            b"pong-2"
        );
    }

    #[test]
    fn tun_udp_session_pool_reuses_source_session_across_destinations_when_endpoint_independent_nat_is_enabled() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        first.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let first_target = first.local_addr().unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        second.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let second_target = second.local_addr().unwrap();
        let (peer_tx_1, peer_rx_1) = std::sync::mpsc::channel();
        let (peer_tx_2, peer_rx_2) = std::sync::mpsc::channel();
        let first_join = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = first.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-1");
            peer_tx_1.send(peer).unwrap();
            first.send_to(b"pong-1", peer).unwrap();
        });
        let second_join = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = second.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-2");
            peer_tx_2.send(peer).unwrap();
            second.send_to(b"pong-2", peer).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  endpoint-independent-nat: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(mihomo_runtime::RuntimeTunnel::new(document.mode.clone(), registry));
        let pool = TunUdpSessionPool::from_tun_config(
            spec.config.udp_timeout,
            true,
            TunStack::System,
        );
        let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let first_packet = super::ParsedTunUdpPacket {
            source,
            destination: first_target,
            payload: b"ping-1".to_vec(),
            hop_limit: 64,
        };
        let second_packet = super::ParsedTunUdpPacket {
            source,
            destination: second_target,
            payload: b"ping-2".to_vec(),
            hop_limit: 64,
        };

        let first_response = relay_tun_udp_packet(
            &spec,
            Arc::clone(&tunnel),
            first_packet,
            None,
            Some(&pool),
        )
        .unwrap();
        let second_response = relay_tun_udp_packet(&spec, tunnel, second_packet, None, Some(&pool)).unwrap();

        first_join.join().unwrap();
        second_join.join().unwrap();
        let first_peer = peer_rx_1.recv().unwrap();
        let second_peer = peer_rx_2.recv().unwrap();
        assert_eq!(first_peer, second_peer);
        assert_eq!(pool.len(), 1);
        assert_eq!(
            parse_tun_udp_packet(&first_response.unwrap()).unwrap().payload,
            b"pong-1"
        );
        assert_eq!(
            parse_tun_udp_packet(&second_response.unwrap()).unwrap().payload,
            b"pong-2"
        );
    }

    #[test]
    fn tun_udp_session_pool_reuses_source_session_across_destinations_for_mixed_stack_by_default() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        first.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let first_target = first.local_addr().unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        second.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let second_target = second.local_addr().unwrap();
        let (peer_tx_1, peer_rx_1) = std::sync::mpsc::channel();
        let (peer_tx_2, peer_rx_2) = std::sync::mpsc::channel();
        let first_join = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = first.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-1");
            peer_tx_1.send(peer).unwrap();
            first.send_to(b"mixed-reply-1", peer).unwrap();
        });
        let second_join = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = second.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-2");
            peer_tx_2.send(peer).unwrap();
            second.send_to(b"mixed-reply-2", peer).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  stack: mixed
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(mihomo_runtime::RuntimeTunnel::new(document.mode.clone(), registry));
        let pool = TunUdpSessionPool::from_tun_config(
            spec.config.udp_timeout,
            false,
            TunStack::Mixed,
        );
        let source: SocketAddr = "10.0.0.2:50010".parse().unwrap();
        let first_packet = super::ParsedTunUdpPacket {
            source,
            destination: first_target,
            payload: b"mixed-1".to_vec(),
            hop_limit: 64,
        };
        let second_packet = super::ParsedTunUdpPacket {
            source,
            destination: second_target,
            payload: b"mixed-2".to_vec(),
            hop_limit: 64,
        };

        let first_response = relay_tun_udp_packet(
            &spec,
            Arc::clone(&tunnel),
            first_packet,
            None,
            Some(&pool),
        )
        .unwrap();
        let second_response =
            relay_tun_udp_packet(&spec, tunnel, second_packet, None, Some(&pool)).unwrap();

        first_join.join().unwrap();
        second_join.join().unwrap();
        let first_peer = peer_rx_1.recv().unwrap();
        let second_peer = peer_rx_2.recv().unwrap();
        assert_eq!(first_peer, second_peer);
        assert_eq!(pool.len(), 1);
        assert_eq!(
            parse_tun_udp_packet(&first_response.unwrap()).unwrap().payload,
            b"mixed-reply-1"
        );
        assert_eq!(
            parse_tun_udp_packet(&second_response.unwrap()).unwrap().payload,
            b"mixed-reply-2"
        );
    }

    #[test]
    fn tun_udp_session_pool_does_not_enable_source_only_reuse_for_mixed_without_runtime_path_support() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  stack: mixed
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
        let pool = TunUdpSessionPool::from_tun_spec(&spec);
        let first_key = pool.session_key(
            "10.0.0.2:50010".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
        );
        let second_key = pool.session_key(
            "10.0.0.2:50010".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
        );
        assert_ne!(first_key, second_key);
    }
}
