use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};

use mihomo_buf::ByteWindow;
use mihomo_core::{DnsMode, Metadata, PacketEnvelope, UdpSession};

#[derive(Default, Debug)]
pub struct NatMappings {
    origin_to_target: HashMap<String, IpAddr>,
    target_to_origin: HashMap<IpAddr, IpAddr>,
}

impl NatMappings {
    pub fn add_mapping(&mut self, origin: &Metadata, resolved: &Metadata) {
        let origin_key = origin.display_host();
        if let Some(target_addr) = resolved.dst_ip {
            self.origin_to_target.entry(origin_key).or_insert(target_addr);
            if let Some(origin_addr) = origin.dst_ip {
                self.target_to_origin.entry(target_addr).or_insert(origin_addr);
            }
        }
    }

    pub fn target_for(&self, metadata: &Metadata) -> Option<SocketAddr> {
        let target_addr = self.origin_to_target.get(&metadata.display_host())?;
        let port = metadata.dst_port?;
        Some(SocketAddr::new(*target_addr, port))
    }

    pub fn restore_read_from(&self, addr: IpAddr) -> IpAddr {
        self.target_to_origin.get(&addr).copied().unwrap_or(addr)
    }
}

#[derive(Default)]
pub struct QueuedUdpRelay {
    mappings: NatMappings,
    queue: VecDeque<PacketEnvelope>,
}

impl QueuedUdpRelay {
    pub fn enqueue(&mut self, packet: PacketEnvelope) {
        self.queue.push_back(packet);
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn mappings(&self) -> &NatMappings {
        &self.mappings
    }

    pub fn process_next(&mut self, session: &mut impl UdpSession) -> io::Result<Option<SocketAddr>> {
        let Some(packet) = self.queue.pop_front() else {
            return Ok(None);
        };
        let target = self.send_packet(session, &packet)?;
        Ok(Some(target))
    }

    pub fn send_packet(
        &mut self,
        session: &mut impl UdpSession,
        packet: &PacketEnvelope,
    ) -> io::Result<SocketAddr> {
        let origin_metadata = packet.metadata().clone();
        let mut dial_metadata = packet.metadata().clone();

        if dial_metadata.host.is_some()
            && (dial_metadata.dst_ip.is_none()
                || matches!(dial_metadata.dns_mode, DnsMode::Mapping | DnsMode::Hosts))
        {
            session.resolve_udp(&mut dial_metadata)?;
        }
        session.prepare_send(&mut dial_metadata)?;
        dial_metadata = dial_metadata.pure();

        if let Some(mapped) = self.mappings.target_for(&origin_metadata) {
            session.send_to(packet.payload(), mapped)?;
            return Ok(mapped);
        }

        let target = dial_metadata
            .destination_socket_addr()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved"))?;

        self.mappings.add_mapping(&origin_metadata, &dial_metadata);
        session.send_to(packet.payload(), target)?;
        Ok(target)
    }

    pub fn restore_source(&self, remote: SocketAddr) -> SocketAddr {
        SocketAddr::new(self.mappings.restore_read_from(remote.ip()), remote.port())
    }

    pub fn write_back(
        &self,
        packet: &PacketEnvelope,
        payload: ByteWindow,
        remote: SocketAddr,
    ) -> io::Result<usize> {
        packet.write_back(payload, Some(self.restore_source(remote)))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use mihomo_buf::ByteWindow;
    use mihomo_core::{DnsMode, Metadata, PacketEnvelope, UdpPacket, UdpSession, WriteBack};

    use super::QueuedUdpRelay;

    #[derive(Default)]
    struct RecordingSink {
        writes: Mutex<Vec<(Vec<u8>, Option<SocketAddr>)>>,
    }

    impl RecordingSink {
        fn take(&self) -> Vec<(Vec<u8>, Option<SocketAddr>)> {
            std::mem::take(&mut *self.writes.lock().unwrap())
        }
    }

    struct TestPacket {
        payload: ByteWindow,
        local_addr: SocketAddr,
        sink: Arc<RecordingSink>,
    }

    impl WriteBack for TestPacket {
        fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
            let len = payload.len();
            self.sink
                .writes
                .lock()
                .unwrap()
                .push((payload.as_slice().to_vec(), source));
            Ok(len)
        }
    }

    impl UdpPacket for TestPacket {
        fn payload(&self) -> ByteWindow {
            self.payload.clone()
        }

        fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }
    }

    #[derive(Default)]
    struct FakeUdpSession {
        writes: Vec<(Vec<u8>, SocketAddr)>,
    }

    impl UdpSession for FakeUdpSession {
        fn resolve_udp(&mut self, metadata: &mut Metadata) -> io::Result<()> {
            if metadata.host.as_deref() == Some("example.com") {
                metadata.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
                return Ok(());
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "missing resolver result"))
        }

        fn send_to(&mut self, payload: ByteWindow, target: SocketAddr) -> io::Result<usize> {
            let len = payload.len();
            self.writes.push((payload.as_slice().to_vec(), target));
            Ok(len)
        }
    }

    #[test]
    fn queued_relay_resolves_host_and_sends_zero_copy_payload() {
        let sink = Arc::new(RecordingSink::default());
        let packet = Arc::new(TestPacket {
            payload: ByteWindow::freeze(b"hello".to_vec()),
            local_addr: "127.0.0.1:5300".parse().unwrap(),
            sink,
        });
        let metadata = Metadata {
            host: Some("example.com".into()),
            dst_port: Some(443),
            dns_mode: DnsMode::Normal,
            ..Metadata::default()
        };
        let envelope = PacketEnvelope::new(packet, metadata);

        let mut relay = QueuedUdpRelay::default();
        let mut session = FakeUdpSession::default();
        relay.enqueue(envelope);

        let target = relay.process_next(&mut session).unwrap().unwrap();
        assert_eq!(target, "1.1.1.1:443".parse().unwrap());
        assert_eq!(session.writes, vec![(b"hello".to_vec(), target)]);
    }

    #[test]
    fn restore_source_uses_original_fake_ip_when_present() {
        let sink = Arc::new(RecordingSink::default());
        let packet = Arc::new(TestPacket {
            payload: ByteWindow::freeze(b"ping".to_vec()),
            local_addr: "127.0.0.1:5301".parse().unwrap(),
            sink: Arc::clone(&sink),
        });
        let metadata = Metadata {
            host: Some("example.com".into()),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2))),
            dst_port: Some(53),
            dns_mode: DnsMode::Mapping,
            ..Metadata::default()
        };
        let envelope = PacketEnvelope::new(packet, metadata);

        let mut relay = QueuedUdpRelay::default();
        let mut session = FakeUdpSession::default();
        let target = relay.send_packet(&mut session, &envelope).unwrap();
        assert_eq!(target, "1.1.1.1:53".parse().unwrap());

        let remote: SocketAddr = "1.1.1.1:53".parse().unwrap();
        relay
            .write_back(&envelope, ByteWindow::freeze(b"pong".to_vec()), remote)
            .unwrap();

        let writes = sink.take();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, b"pong".to_vec());
        assert_eq!(writes[0].1, Some("198.18.0.2:53".parse().unwrap()));
    }
}
