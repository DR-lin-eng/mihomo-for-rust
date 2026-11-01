use super::*;

#[test]
fn vmess_listener_rejects_invalid_configured_uuid() {
    let temp = unique_temp_dir("mihomo-app-inbound-vmess-invalid-uuid");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: not-a-uuid
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let err = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap_err();
    assert!(err.to_string().contains("vmess listener edge-vmess has invalid user uuid"));
}

#[test]
fn start_serves_vmess_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 5];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping!");
        stream.write_all(b"pong-vmess-inbound").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess");
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
    network: tcp
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: {upstream_addr}
"#
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
                network: "tcp".into(),
                websocket: Default::default(),
                grpc: Default::default(),
                h2: Default::default(),
                http: Default::default(),
                xhttp: Default::default(),
                packet_addr: false,
                xudp: false,
                global_padding: false,
                authenticated_length: false,
                tls: Default::default(),
                alpn: Vec::new(),
                socket: SocketOptions::default(),
                target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
            },
        }],
    };
    let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
    let mut stream = executor.run_plan(&plan).unwrap();
    stream.write_all(b"ping!").unwrap();
    stream.shutdown_write().unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-inbound");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_top_level_vmess_config_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 5];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping!");
        stream.write_all(b"pong-top-vmess").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-top-level-vmess");
    fs::write(
        temp.join("config.yaml"),
        r#"
vmess-config: vmess://test:b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:0
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vmess_addr = find_listener_addr(&app, "__top_level_vmess__", "vmess");

    let plan = TransportPlan {
        requested: "__top_level_vmess__".into(),
        selected_path: vec!["__top_level_vmess__".into()],
        leaf_name: "__top_level_vmess__".into(),
        hops: vec![TransportHop {
            name: "__top_level_vmess__".into(),
            action: TransportAction::VmessConnect {
                proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 0,
                cipher: "none".into(),
                udp: false,
                network: "tcp".into(),
                websocket: Default::default(),
                grpc: Default::default(),
                h2: Default::default(),
                http: Default::default(),
                xhttp: Default::default(),
                packet_addr: false,
                xudp: false,
                global_padding: false,
                authenticated_length: false,
                tls: Default::default(),
                alpn: Vec::new(),
                socket: SocketOptions::default(),
                target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
            },
        }],
    };
    let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
    let mut stream = executor.run_plan(&plan).unwrap();
    stream.write_all(b"ping!").unwrap();
    stream.shutdown_write().unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-top-vmess");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-udp");
        upstream.send_to(b"pong-vmess-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-udp");
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
    network: tcp
"#
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

    let mut stream = mihomo_transport::open_vmess_udp_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        0,
        "none",
        false,
        false,
        upstream_addr,
    )
    .unwrap();
    write_vmess_udp_packet(&mut *stream, b"ping-vmess-udp").unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    assert_eq!(payload, b"pong-vmess-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-xudp");
        upstream.send_to(b"pong-vmess-xudp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-xudp");
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
    network: tcp
"#
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

    let mut stream = mihomo_transport::open_vmess_xudp_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        0,
        "aes-128-gcm",
        false,
        false,
    )
    .unwrap();
    write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-xudp").unwrap();
    let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(payload, b"pong-vmess-xudp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-pa");
        upstream.send_to(b"pong-vmess-pa", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-packetaddr");
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
    network: tcp
"#
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

    let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        0,
        "none",
        false,
        false,
    )
    .unwrap();
    let payload =
        mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-pa");
    write_vmess_udp_packet(&mut *stream, &payload).unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(packet, b"pong-vmess-pa");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_listener_with_multiple_users_end_to_end() {
    const ALICE_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const BOB_UUID: &str = "3f2d2c8e-9a41-4f2b-9c8d-1a2b3c4d5e6f";

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-multi").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        }
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-multi");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: alice
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
      - username: bob
        uuid: 3f2d2c8e-9a41-4f2b-9c8d-1a2b3c4d5e6f
        alterId: 0
    network: tcp
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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

    for uuid in [ALICE_UUID, BOB_UUID] {
        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: uuid.into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "tcp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-multi");
    }

    upstream_worker.join().unwrap();
    app.shutdown();
}
