use std::net::SocketAddr;
use std::sync::Arc;

use mihomo_config::RuntimeConfigDocument;
use mihomo_core::{
    ConnectionContext, DnsMode, Metadata, PacketEnvelope, TcpStream, UdpPacket,
};
use mihomo_inbound::InboundDefinition;
use mihomo_transport::TcpDialer;
use mihomo_tun::TunRuntimeSpec;

use crate::{RuntimeTunnel, TcpForwardError, TcpRelayStats};

#[derive(Clone)]
pub struct PreparedTunUdpPacket {
    pub envelope: PacketEnvelope,
    pub hijacked_dns: bool,
}

pub fn build_tun_runtime_specs(document: &RuntimeConfigDocument) -> Vec<TunRuntimeSpec> {
    let mut specs = Vec::new();
    if document.tun.enable {
        specs.push(TunRuntimeSpec::new(
            "__top_level_tun__",
            document.tun.config.clone(),
        ));
    }

    specs.extend(document.listeners.iter().filter_map(|listener| match listener {
        InboundDefinition::Tun(config) => {
            let name = if config.base.name.is_empty() {
                "__listener_tun__".to_owned()
            } else {
                config.base.name.clone()
            };
            Some(TunRuntimeSpec::new(name, config.clone()))
        }
        _ => None,
    }));
    specs
}

pub fn prepare_tun_tcp_context(
    spec: &TunRuntimeSpec,
    stream: impl TcpStream + 'static,
    source: Option<SocketAddr>,
    destination: SocketAddr,
) -> ConnectionContext {
    ConnectionContext::new(stream, spec.prepare_tcp_metadata(source, destination))
}

pub fn dispatch_tun_tcp_stream(
    spec: &TunRuntimeSpec,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    source: Option<SocketAddr>,
    destination: SocketAddr,
) -> Result<TcpRelayStats, TcpForwardError> {
    let mut context = prepare_tun_tcp_context(spec, stream, source, destination);
    tunnel.forward_tcp_context_with_system_dialer(&mut context)
}

pub fn dispatch_tun_tcp_stream_with_dialer<D>(
    spec: &TunRuntimeSpec,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    source: Option<SocketAddr>,
    destination: SocketAddr,
    dialer: D,
) -> Result<TcpRelayStats, TcpForwardError>
where
    D: TcpDialer,
{
    let mut context = prepare_tun_tcp_context(spec, stream, source, destination);
    tunnel.forward_tcp_context_with_dialer(&mut context, dialer)
}

pub fn prepare_tun_udp_metadata(
    spec: &TunRuntimeSpec,
    source: Option<SocketAddr>,
    destination: SocketAddr,
) -> Metadata {
    let mut metadata = spec.prepare_udp_metadata(source, destination);
    if spec.should_hijack_dns(destination) {
        metadata.dns_mode = DnsMode::Mapping;
    }
    metadata
}

pub fn prepare_tun_udp_packet(
    spec: &TunRuntimeSpec,
    packet: Arc<dyn UdpPacket>,
    source: Option<SocketAddr>,
    destination: SocketAddr,
) -> PreparedTunUdpPacket {
    let hijacked_dns = spec.should_hijack_dns(destination);
    let metadata = prepare_tun_udp_metadata(spec, source, destination);
    PreparedTunUdpPacket {
        envelope: PacketEnvelope::new(packet, metadata),
        hijacked_dns,
    }
}

pub fn dispatch_tun_udp_packet(
    spec: &TunRuntimeSpec,
    tunnel: &RuntimeTunnel,
    packet: Arc<dyn UdpPacket>,
    source: Option<SocketAddr>,
    destination: SocketAddr,
) -> PreparedTunUdpPacket {
    let prepared = prepare_tun_udp_packet(spec, packet, source, destination);
    tunnel.enqueue_udp_packet(prepared.envelope.clone());
    prepared
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use mihomo_buf::ByteWindow;
    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{BoxedTcpStream, DnsMode, Metadata, SessionKind, UdpPacket, UdpSession, WriteBack};
    use mihomo_inbound::TunStack;
    use mihomo_transport::{SocketOptions, TcpDialPurpose, TcpDialer, TransportError, TransportTarget};

    use crate::build_runtime_registry;

    use super::{
        build_tun_runtime_specs, dispatch_tun_tcp_stream_with_dialer, dispatch_tun_udp_packet,
        prepare_tun_tcp_context, prepare_tun_udp_metadata,
    };

    struct MemoryStream(Cursor<Vec<u8>>);

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for MemoryStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(Self(Cursor::new(self.0.get_ref().clone()))))
        }
    }

    #[derive(Default)]
    struct SharedStreamState {
        reader: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    #[derive(Clone)]
    struct SharedStreamHandle(Arc<Mutex<SharedStreamState>>);

    impl SharedStreamHandle {
        fn new(readable: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(SharedStreamState {
                reader: Cursor::new(readable),
                written: Vec::new(),
            })))
        }

        fn stream(&self) -> SharedStream {
            SharedStream(Arc::clone(&self.0))
        }

        fn written(&self) -> Vec<u8> {
            self.0.lock().unwrap().written.clone()
        }
    }

    struct SharedStream(Arc<Mutex<SharedStreamState>>);

    impl Read for SharedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().reader.read(buf)
        }
    }

    impl Write for SharedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for SharedStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(SharedStream(Arc::clone(&self.0))))
        }
    }

    struct FakeDialer {
        expected: Vec<(String, SharedStreamHandle)>,
    }

    impl FakeDialer {
        fn new(expected: Vec<(String, SharedStreamHandle)>) -> Self {
            Self { expected }
        }
    }

    impl TcpDialer for FakeDialer {
        fn connect(
            &mut self,
            target: &TransportTarget,
            _socket: &SocketOptions,
            _purpose: TcpDialPurpose,
        ) -> Result<BoxedTcpStream, TransportError> {
            let (expected, handle) = self.expected.remove(0);
            if expected != target.authority() {
                return Err(TransportError::InvalidPlan(format!(
                    "expected dial {expected} but got {}",
                    target.authority()
                )));
            }
            Ok(Box::new(handle.stream()))
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        writes: Mutex<Vec<(Vec<u8>, Option<SocketAddr>)>>,
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
            if metadata.dst_ip == Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))) {
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
    fn top_level_and_listener_tun_specs_are_built() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  stack: system
  dns-hijack:
    - 0.0.0.0:53
listeners:
  - type: tun
    name: custom-tun
    stack: mixed
"#,
        )
        .unwrap();
        let specs = build_tun_runtime_specs(&document);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].name, "__top_level_tun__");
        assert_eq!(specs[0].stack(), TunStack::System);
        assert_eq!(specs[1].name, "custom-tun");
        assert_eq!(specs[1].stack(), TunStack::Mixed);
    }

    #[test]
    fn tun_context_and_udp_metadata_use_tun_session_kind() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  stack: system
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let destination: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let context = prepare_tun_tcp_context(
            &spec,
            MemoryStream(Cursor::new(Vec::new())),
            Some(source),
            destination,
        );
        assert_eq!(context.metadata().kind, SessionKind::Tun);
        assert_eq!(context.metadata().src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        let udp = prepare_tun_udp_metadata(&spec, Some(source), "1.1.1.1:53".parse().unwrap());
        assert_eq!(udp.kind, SessionKind::Tun);
        assert_eq!(udp.network, mihomo_core::NetworkKind::Udp);
    }

    #[test]
    fn tun_udp_dispatch_marks_dns_hijack_and_enqueues_packet() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  dns-hijack:
    - 0.0.0.0:53
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let packet = Arc::new(TestPacket {
            payload: ByteWindow::freeze(b"hello".to_vec()),
            local_addr: "127.0.0.1:5300".parse().unwrap(),
            sink: Arc::new(RecordingSink::default()),
        });
        let prepared = dispatch_tun_udp_packet(
            &spec,
            &tunnel,
            packet,
            Some("10.0.0.2:50000".parse().unwrap()),
            "1.1.1.1:53".parse().unwrap(),
        );
        assert!(prepared.hijacked_dns);
        assert_eq!(prepared.envelope.metadata().dns_mode, DnsMode::Mapping);
        assert_eq!(tunnel.pending_udp_packets(), 1);
        let mut session = FakeUdpSession::default();
        let target = tunnel.process_udp_queue(&mut session).unwrap().unwrap();
        assert_eq!(target, "1.1.1.1:53".parse().unwrap());
        assert_eq!(session.writes, vec![(b"hello".to_vec(), target)]);
    }

    #[test]
    fn tun_tcp_dispatch_forwards_via_runtime_tunnel() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  proxy: special
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let inbound = SharedStreamHandle::new(b"client-data".to_vec());
        let upstream = SharedStreamHandle::new(
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );
        let stats = dispatch_tun_tcp_stream_with_dialer(
            &spec,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            "93.184.216.34:443".parse().unwrap(),
            FakeDialer::new(vec![("special.example.com:8080".into(), upstream.clone())]),
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
        assert!(inbound.written().ends_with(b"server-data"));
    }
}
