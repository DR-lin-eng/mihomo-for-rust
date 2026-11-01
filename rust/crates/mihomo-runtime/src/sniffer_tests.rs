use crate::sniffer::*;
use mihomo_buf::ByteWindow;
use mihomo_core::{
    ConnectionContext, DnsMode, Metadata, NetworkKind, PacketEnvelope, SessionKind, UdpPacket,
    WriteBack,
};
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};
fn config() -> Sniffer {
    Sniffer::new(mihomo_config::parse_runtime_config_document("sniffer:\n  enable: true\n  parse-pure-ip: true\n  force-dns-mapping: true\n  override-destination: true\n  sniff:\n    TLS: {ports: [443,8443]}\n    HTTP: {ports: [80,8080-8880]}\n    QUIC: {ports: [443]}\n").unwrap().sniffer)
}
fn metadata() -> Metadata {
    Metadata {
        kind: SessionKind::Redir,
        dst_ip: Some("203.0.113.1".parse().unwrap()),
        dst_port: Some(443),
        src_ip: Some("192.0.2.1".parse().unwrap()),
        src_port: Some(60001),
        ..Default::default()
    }
}
fn hello(host: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend(sni);
    let mut body = vec![3, 3];
    body.extend([0; 32]);
    body.extend([0, 0, 2, 0, 47, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut out = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    out.extend(body);
    out
}
fn record(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 3];
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}
#[test]
fn fragmented_tcp_tls_is_replayed_and_metadata_is_routable() {
    let h = hello("Video.Example.com");
    let bytes = [record(&h[..h.len() / 2]), record(&h[h.len() / 2..])].concat();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let sent = bytes.clone();
    let sender = std::thread::spawn(move || {
        let mut client = client;
        client.write_all(&sent[..7]).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        client.write_all(&sent[7..]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
    });
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut context = ConnectionContext::new(stream, metadata());
    config().sniff_tcp(&mut context);
    assert_eq!(
        context.metadata().host.as_deref(),
        Some("video.example.com")
    );
    assert_eq!(
        context.metadata().sniff_host.as_deref(),
        Some("video.example.com")
    );
    assert!(context.metadata().dst_ip.is_none());
    assert_eq!(context.stream_mut().read_timeout().unwrap(), None);
    let mut replayed = Vec::new();
    context.stream_mut().read_to_end(&mut replayed).unwrap();
    assert_eq!(replayed, bytes);
    sender.join().unwrap();
}
#[test]
fn http_host_absolute_uri_and_boundaries() {
    assert_eq!(
        http_host(b"GET / HTTP/1.1\r\nHost: Media.Example.com:8443\r\n\r\n"),
        Parsed::Domain("media.example.com".into())
    );
    assert_eq!(
        http_host(b"GET http://cdn.example.com/ HTTP/1.1\r\nHost: proxy.test\r\n\r\n"),
        Parsed::Domain("cdn.example.com".into())
    );
    assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: x"), Parsed::NeedMore);
    assert_eq!(http_host(&vec![b'A'; 32769]), Parsed::NoDomain);
    assert_eq!(tls_hello(&[1, 255, 255, 255]), Parsed::NoDomain);
    assert_eq!(tls_hello(&hello("203.0.113.1")), Parsed::NoDomain);
}
#[test]
fn skip_domains_ip_filters_force_flags_and_override_policy() {
    let mut sniff = config();
    sniff.config.skip_domain = vec!["+.apple.com".into()];
    let mut m = metadata();
    sniff.apply_host(&mut m, "push.apple.com".into(), true);
    assert!(m.sniff_host.is_none());
    assert!(m.dst_ip.is_some());
    sniff.config.skip_src_address = vec!["192.0.2.0/24".into()];
    assert!(!sniff.eligible(&m));
    sniff.config.skip_src_address.clear();
    m.host = Some("old.example.com".into());
    m.dns_mode = DnsMode::Mapping;
    assert!(sniff.eligible(&m));
    sniff.config.force_dns_mapping = false;
    assert!(!sniff.eligible(&m));
    sniff.config.force_domain = vec!["+.example.com".into()];
    assert!(sniff.eligible(&m));
    let original = m.dst_ip;
    sniff.apply_host(&mut m, "new.example.com".into(), false);
    assert_eq!(m.dst_ip, original);
    assert_eq!(m.host.as_deref(), Some("old.example.com"));
    assert_eq!(m.rule_host(), Some("new.example.com"));
    assert_eq!(m.dns_mode, DnsMode::Mapping);
    assert_eq!(sniff.protocol("TLS", 8443), Some(true));
    assert_eq!(sniff.protocol("TLS", 80), None);
}
#[test]
fn idle_tls_socket_has_a_single_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut context = ConnectionContext::new(stream, metadata());
    let start = Instant::now();
    config().sniff_tcp(&mut context);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(context.metadata().host.is_none());
}
#[derive(Clone)]
struct Packet(Vec<u8>);
impl WriteBack for Packet {
    fn write_back(&self, _: ByteWindow, _: Option<SocketAddr>) -> std::io::Result<usize> {
        Ok(0)
    }
}
impl UdpPacket for Packet {
    fn payload(&self) -> ByteWindow {
        ByteWindow::freeze(self.0.clone())
    }
    fn local_addr(&self) -> SocketAddr {
        "127.0.0.1:60001".parse().unwrap()
    }
}
fn envelope(bytes: Vec<u8>) -> PacketEnvelope {
    let mut m = metadata();
    m.network = NetworkKind::Udp;
    PacketEnvelope::new(Arc::new(Packet(bytes)), m)
}
#[test]
fn upstream_quic_captures_reassemble_before_any_datagram_is_forwarded() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("sniffer-quic-fixtures.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let sniff = config();
        let mut sent = Vec::new();
        let mut raw = Vec::new();
        for item in case["packets"].as_array().unwrap() {
            let text = item.as_str().unwrap();
            let bytes = (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>();
            raw.push(bytes.clone());
            sent.extend(sniff.sniff_udp(envelope(bytes)));
        }
        assert!(!sent.is_empty(), "{}", case["domain"]);
        assert!(
            sent.iter()
                .any(|packet| packet.metadata().sniff_host.as_deref() == case["domain"].as_str()),
            "expected {}",
            case["domain"]
        );
        assert_eq!(
            sent.iter()
                .map(|p| p.payload().as_slice().to_vec())
                .collect::<Vec<_>>(),
            raw,
            "UDP inspection must preserve order and every byte"
        );
        sniff.clear_udp();
    }
}
