use super::*;

#[test]
fn start_serves_vmess_h2_tls_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let milestones = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let milestones_worker = Arc::clone(&milestones);
    let upstream_worker = thread::spawn(move || {
        milestones_worker.lock().unwrap().push("upstream-accept");
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        milestones_worker.lock().unwrap().push("upstream-read");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-h2-tls-inbound").unwrap();
        milestones_worker.lock().unwrap().push("upstream-write");
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmh2
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
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
    let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

    let plan = TransportPlan {
        requested: "edge-vmess".into(),
        selected_path: vec!["edge-vmess".into()],
        leaf_name: "edge-vmess".into(),
        hops: vec![TransportHop {
            name: "edge-vmess".into(),
            action: TransportAction::VmessConnect {
                proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 0,
                cipher: "none".into(),
                udp: false,
                network: "h2".into(),
                websocket: Default::default(),
                grpc: Default::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["localhost".into()],
                    path: "/vmh2".into(),
                },
                http: Default::default(),
                xhttp: Default::default(),
                packet_addr: false,
                xudp: false,
                global_padding: false,
                authenticated_length: false,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
                alpn: Vec::new(),
                socket: SocketOptions::default(),
                target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
            },
        }],
    };
    let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    let read_err = client.read_to_end(&mut reply).err();
    if let Some(err) = read_err {
        panic!(
            "vmess h2 tls inbound read failed: {err}; milestones={:?}",
            milestones.lock().unwrap().clone()
        );
    }
    assert_eq!(reply, b"pong-vmess-h2-tls-inbound");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_tls_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-h2-tls-udp");
        upstream.send_to(b"pong-vmess-h2-tls-udp", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2tls
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
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
    let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

    let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/vmuh2tls".into(),
        },
    )
    .unwrap();
    let mut stream = mihomo_transport::open_vmess_udp_stream(
        stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        0,
        "none",
        false,
        false,
        upstream_addr,
    )
    .unwrap();
    write_vmess_udp_packet(&mut *stream, b"ping-vmess-h2-tls-udp").unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    assert_eq!(payload, b"pong-vmess-h2-tls-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_tls_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-h2-tls-xudp");
        upstream.send_to(b"pong-vmess-h2-tls-xudp", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls-xudp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2tlsx
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
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
    let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

    let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/vmuh2tlsx".into(),
        },
    )
    .unwrap();
    let mut stream = mihomo_transport::open_vmess_xudp_stream(
        stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        0,
        "aes-128-gcm",
        false,
        false,
    )
    .unwrap();
    write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-h2-tls-xudp").unwrap();
    let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(payload, b"pong-vmess-h2-tls-xudp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_tls_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-h2-tls-pa");
        upstream.send_to(b"pong-vmess-h2-tls-pa", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls-packetaddr");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2tlspa
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
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
    let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

    let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/vmuh2tlspa".into(),
        },
    )
    .unwrap();
    let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
        stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        0,
        "none",
        false,
        false,
    )
    .unwrap();
    let payload =
        mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-h2-tls-pa");
    write_vmess_udp_packet(&mut *stream, &payload).unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(packet, b"pong-vmess-h2-tls-pa");

    upstream_worker.join().unwrap();
    app.shutdown();
}
