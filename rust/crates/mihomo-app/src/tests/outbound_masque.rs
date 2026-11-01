use super::*;
use std::net::Ipv4Addr;

use rcgen::{generate_simple_self_signed, KeyPair};
use rustls::ServerConfig;
use smoltcp::wire::{
    IpAddress as SmolIpAddress, IpProtocol as SmolIpProtocol,
    Ipv4Address as SmolIpv4Address, Ipv4Packet as SmolIpv4Packet,
    Ipv4Repr as SmolIpv4Repr, TcpControl as SmolTcpControl,
    TcpPacket as SmolTcpPacket, TcpRepr as SmolTcpRepr,
    TcpSeqNumber as SmolTcpSeqNumber,
};

fn build_tls_server_config_with_pem_and_public_key() -> (
    std::sync::Arc<ServerConfig>,
    String,
    String,
) {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let cert_pem = cert.cert.pem();
    let public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(cert.key_pair.public_key_der());
    let key_der = cert.key_pair.serialize_der();
    (
        std::sync::Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                .unwrap(),
        ),
        cert_pem,
        public_key_b64,
    )
}

fn build_masque_key_material() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(key.serialize_der());
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(key.public_key_der());
    (private_key_b64, public_key_b64)
}

fn encode_h2_varint(value: u64, dst: &mut Vec<u8>) {
    match value {
        0..=63 => dst.push(value as u8),
        64..=16383 => {
            let encoded = 0x4000 | value as u16;
            dst.extend_from_slice(&encoded.to_be_bytes());
        }
        16384..=1_073_741_823 => {
            let encoded = 0x8000_0000 | value as u32;
            dst.extend_from_slice(&encoded.to_be_bytes());
        }
        _ => {
            let encoded = 0xC000_0000_0000_0000 | value;
            dst.extend_from_slice(&encoded.to_be_bytes());
        }
    }
}

fn decode_h2_varint(stream: &mut dyn Read) -> u64 {
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first).unwrap();
    match first[0] >> 6 {
        0 => (first[0] & 0x3f) as u64,
        1 => {
            let mut rest = [0_u8; 1];
            stream.read_exact(&mut rest).unwrap();
            u16::from_be_bytes([first[0], rest[0]]) as u64 & 0x3fff
        }
        2 => {
            let mut rest = [0_u8; 3];
            stream.read_exact(&mut rest).unwrap();
            u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as u64 & 0x3fff_ffff
        }
        _ => {
            let mut rest = [0_u8; 7];
            stream.read_exact(&mut rest).unwrap();
            u64::from_be_bytes([
                first[0], rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6],
            ]) & 0x3fff_ffff_ffff_ffff
        }
    }
}

fn read_h2_capsule(stream: &mut dyn Read) -> (u64, Vec<u8>) {
    let capsule_type = decode_h2_varint(stream);
    let payload_len = decode_h2_varint(stream) as usize;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).unwrap();
    (capsule_type, payload)
}

fn write_h2_capsule(stream: &mut dyn Write, capsule_type: u64, payload: &[u8]) {
    let mut frame = Vec::new();
    encode_h2_varint(capsule_type, &mut frame);
    encode_h2_varint(payload.len() as u64, &mut frame);
    frame.extend_from_slice(payload);
    stream.write_all(&frame).unwrap();
    stream.flush().unwrap();
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn encode_masque_ipv4_udp_packet_for_tests(
    source: Ipv4Addr,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let SocketAddr::V4(target) = target else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "masque app test currently supports ipv4 targets only",
        ));
    };
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.ip().octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&53_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&target.port().to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    Ok(packet)
}

fn decode_masque_ipv4_udp_packet_for_tests(
    packet: &[u8],
) -> io::Result<(SocketAddr, SocketAddr, Vec<u8>)> {
    if packet.len() < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "masque app test packet too short",
        ));
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let source = SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
        u16::from_be_bytes([packet[20], packet[21]]),
    );
    let destination = SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
        u16::from_be_bytes([packet[22], packet[23]]),
    );
    Ok((source, destination, packet[28..total_len].to_vec()))
}

struct MasqueTestTcpSession {
    client_ip: Ipv4Addr,
    client_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
    server_seq: u32,
    next_ack: u32,
    syn_acked: bool,
    pong_sent: bool,
}

fn build_masque_test_tcp_packet(
    session: &MasqueTestTcpSession,
    control: SmolTcpControl,
    ack_number: Option<u32>,
    seq_number: u32,
    payload: &[u8],
) -> Vec<u8> {
    let src_ip = SmolIpv4Address::from(session.server_ip);
    let dst_ip = SmolIpv4Address::from(session.client_ip);
    let ip_repr = SmolIpv4Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: SmolIpProtocol::Tcp,
        payload_len: 20 + payload.len(),
        hop_limit: 64,
    };
    let tcp_repr = SmolTcpRepr {
        src_port: session.server_port,
        dst_port: session.client_port,
        control,
        seq_number: SmolTcpSeqNumber(seq_number as i32),
        ack_number: ack_number.map(|value| SmolTcpSeqNumber(value as i32)),
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload,
    };
    let mut bytes = vec![0_u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
    {
        let mut ipv4_packet = SmolIpv4Packet::new_unchecked(&mut bytes);
        ip_repr.emit(
            &mut ipv4_packet,
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
    }
    {
        let mut tcp_packet =
            SmolTcpPacket::new_unchecked(&mut bytes[ip_repr.buffer_len()..]);
        tcp_repr.emit(
            &mut tcp_packet,
            &SmolIpAddress::Ipv4(src_ip),
            &SmolIpAddress::Ipv4(dst_ip),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
    }
    bytes
}

#[test]
fn start_serves_tunnel_udp_with_masque_h2_proxy() {
    let (tls_config, cert_pem, server_public_key) =
        build_tls_server_config_with_pem_and_public_key();
    mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let (private_key, _client_public_key) = build_masque_key_material();

    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (request, mut stream) =
            accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.authority, "localhost");
        assert_eq!(request.path, "/");
        assert_eq!(
            request.headers.get("cf-connect-proto").map(String::as_str),
            Some("cf-connect-ip")
        );

        let (capsule_type, packet) = read_h2_capsule(&mut *stream);
        assert_eq!(capsule_type, 0);
        let (source, destination, payload) = decode_masque_ipv4_udp_packet_for_tests(&packet).unwrap();
        assert_eq!(destination, "8.8.8.8:53".parse().unwrap());
        assert_eq!(payload, b"via-masque-app");

        let mut reply = encode_masque_ipv4_udp_packet_for_tests(
            Ipv4Addr::new(1, 1, 1, 1),
            source,
            b"masque-app-ok",
        )
        .unwrap();
        reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
        write_h2_capsule(&mut *stream, 0, &reply);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-masque");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: masque
    name: proxy-masque
    server: 127.0.0.1
    port: {proxy_port}
    private-key: {private_key}
    public-key: {public_key}
    ip: 10.10.0.2/32
    network: h2
    uri: https://localhost/
    mtu: 1300
    sni: localhost
    udp: true
    skip-cert-verify: false
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-masque
    target: 8.8.8.8:53
"#,
            proxy_port = listen_addr.port(),
            private_key = private_key,
            public_key = server_public_key,
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };
    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client.send_to(b"via-masque-app", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"masque-app-ok");

    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_tunnel_udp_with_masque_h2_remote_dns_resolve() {
    let (tls_config, cert_pem, server_public_key) =
        build_tls_server_config_with_pem_and_public_key();
    mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let (private_key, _client_public_key) = build_masque_key_material();

    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (request, mut stream) =
            accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.authority, "localhost");
        assert_eq!(request.path, "/");

        let (capsule_type, packet) = read_h2_capsule(&mut *stream);
        assert_eq!(capsule_type, 0);
        let (source, destination, payload) = decode_masque_ipv4_udp_packet_for_tests(&packet).unwrap();
        assert_eq!(destination, "1.1.1.1:53".parse().unwrap());
        let query_id = u16::from_be_bytes([payload[0], payload[1]]);
        let expected = mihomo_dns::build_dns_query_for_tests(
            "edge.example.com",
            mihomo_dns::DnsRecordType::A,
            query_id,
        )
        .unwrap();
        assert_eq!(payload, expected);

        let mut response = Vec::new();
        response.extend_from_slice(&query_id.to_be_bytes());
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&payload[12..]);
        response.extend_from_slice(&0xC00C_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[8, 8, 8, 8]);

        let mut reply = encode_masque_ipv4_udp_packet_for_tests(
            Ipv4Addr::new(1, 1, 1, 1),
            source,
            &response,
        )
        .unwrap();
        reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
        write_h2_capsule(&mut *stream, 0, &reply);

        let (capsule_type, packet) = read_h2_capsule(&mut *stream);
        assert_eq!(capsule_type, 0);
        let (_source, destination, payload) = decode_masque_ipv4_udp_packet_for_tests(&packet).unwrap();
        assert_eq!(destination, "8.8.8.8:53".parse().unwrap());
        assert_eq!(payload, b"via-masque-remote-dns");

        let mut reply = encode_masque_ipv4_udp_packet_for_tests(
            Ipv4Addr::new(9, 9, 9, 9),
            "8.8.8.8:53".parse().unwrap(),
            b"masque-remote-dns-ok",
        )
        .unwrap();
        reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
        write_h2_capsule(&mut *stream, 0, &reply);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-masque-remote-dns");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: masque
    name: proxy-masque
    server: 127.0.0.1
    port: {proxy_port}
    private-key: {private_key}
    public-key: {public_key}
    ip: 10.10.0.2/32
    network: h2
    uri: https://localhost/
    mtu: 1300
    sni: localhost
    udp: true
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
    skip-cert-verify: false
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-masque
    target: edge.example.com:53
"#,
            proxy_port = listen_addr.port(),
            private_key = private_key,
            public_key = server_public_key,
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };
    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client.send_to(b"via-masque-remote-dns", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"masque-remote-dns-ok");

    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_masque_h2_proxy_end_to_end() {
    let (tls_config, cert_pem, server_public_key) =
        build_tls_server_config_with_pem_and_public_key();
    mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let (private_key, _client_public_key) = build_masque_key_material();

    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (request, mut stream) =
            accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.authority, "localhost");
        assert_eq!(request.path, "/");

        let mut session = None::<MasqueTestTcpSession>;
        loop {
            let (capsule_type, packet) = read_h2_capsule(&mut *stream);
            assert_eq!(capsule_type, 0);
            let ipv4 = SmolIpv4Packet::new_checked(&packet).unwrap();
            assert_eq!(ipv4.next_header(), SmolIpProtocol::Tcp);
            let tcp = SmolTcpPacket::new_checked(ipv4.payload()).unwrap();
            let src_ip = Ipv4Addr::from(ipv4.src_addr());
            let dst_ip = Ipv4Addr::from(ipv4.dst_addr());

            if tcp.syn() && !tcp.ack() {
                let client_seq = tcp.seq_number().0 as u32;
                let new_session = MasqueTestTcpSession {
                    client_ip: src_ip,
                    client_port: tcp.src_port(),
                    server_ip: dst_ip,
                    server_port: tcp.dst_port(),
                    server_seq: 0x1020_3040,
                    next_ack: client_seq.wrapping_add(1),
                    syn_acked: false,
                    pong_sent: false,
                };
                let syn_ack = build_masque_test_tcp_packet(
                    &new_session,
                    SmolTcpControl::Syn,
                    Some(new_session.next_ack),
                    new_session.server_seq,
                    &[],
                );
                let mut stored = new_session;
                stored.server_seq = stored.server_seq.wrapping_add(1);
                session = Some(stored);
                write_h2_capsule(&mut *stream, 0, &syn_ack);
                continue;
            }

            let Some(current) = session.as_mut() else {
                continue;
            };
            if src_ip != current.client_ip
                || dst_ip != current.server_ip
                || tcp.src_port() != current.client_port
                || tcp.dst_port() != current.server_port
            {
                continue;
            }

            let payload = tcp.payload();
            let seq = tcp.seq_number().0 as u32;

            if tcp.ack() && !current.syn_acked && payload.is_empty() && seq == current.next_ack {
                current.syn_acked = true;
                continue;
            }

            if !payload.is_empty() && payload == b"ping" && !current.pong_sent {
                current.next_ack = seq.wrapping_add(payload.len() as u32);
                let pong = build_masque_test_tcp_packet(
                    current,
                    SmolTcpControl::Psh,
                    Some(current.next_ack),
                    current.server_seq,
                    b"pong",
                );
                current.server_seq = current.server_seq.wrapping_add(4);
                current.pong_sent = true;
                write_h2_capsule(&mut *stream, 0, &pong);
                break;
            }
        }
    });

    let temp = unique_temp_dir("mihomo-app-tunnel-masque");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: masque
    name: proxy-masque
    server: 127.0.0.1
    port: {proxy_port}
    private-key: {private_key}
    public-key: {public_key}
    ip: 10.10.0.2/32
    network: h2
    uri: https://localhost/
    mtu: 1300
    sni: localhost
    udp: true
    skip-cert-verify: false
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: proxy-masque
    target: 8.8.8.8:443
"#,
            proxy_port = listen_addr.port(),
            private_key = private_key,
            public_key = server_public_key,
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };
    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
    let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

    let mut client = TcpStream::connect(tunnel_addr).unwrap();
    client.write_all(b"ping").unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");

    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_tunnel_udp_with_masque_h2_over_http_dialer_proxy() {
    let (tls_config, cert_pem, server_public_key) =
        build_tls_server_config_with_pem_and_public_key();
    mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (private_key, _client_public_key) = build_masque_key_material();

    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let request = read_http_headers(&mut stream);
        assert_eq!(
            request.lines().next().unwrap_or_default(),
            format!("CONNECT 127.0.0.1:{} HTTP/1.1", upstream_addr.port())
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let (request, mut stream) =
            accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.authority, "localhost");
        assert_eq!(request.path, "/");
        assert_eq!(
            request.headers.get("cf-connect-proto").map(String::as_str),
            Some("cf-connect-ip")
        );

        let (capsule_type, packet) = read_h2_capsule(&mut *stream);
        assert_eq!(capsule_type, 0);
        let (source, destination, payload) = decode_masque_ipv4_udp_packet_for_tests(&packet).unwrap();
        assert_eq!(destination, "8.8.8.8:53".parse().unwrap());
        assert_eq!(payload, b"via-masque-http-dialer");

        let mut reply = encode_masque_ipv4_udp_packet_for_tests(
            Ipv4Addr::new(1, 1, 1, 1),
            source,
            b"masque-http-dialer-ok",
        )
        .unwrap();
        reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
        write_h2_capsule(&mut *stream, 0, &reply);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-masque-http-dialer");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: masque
    name: proxy-masque
    server: 127.0.0.1
    port: {proxy_port}
    private-key: {private_key}
    public-key: {public_key}
    ip: 10.10.0.2/32
    network: h2
    uri: https://localhost/
    mtu: 1300
    sni: localhost
    udp: true
    skip-cert-verify: false
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-masque
    target: 8.8.8.8:53
"#,
            outer_port = upstream_addr.port(),
            proxy_port = upstream_addr.port(),
            private_key = private_key,
            public_key = server_public_key,
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };
    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client.send_to(b"via-masque-http-dialer", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"masque-http-dialer-ok");

    upstream_worker.join().unwrap();
    app.shutdown();
}
