use super::*;

#[test]
fn start_serves_vmess_ws_listener_end_to_end() {
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
        stream.write_all(b"pong-vmess-ws-inbound").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws");
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
    network: ws
    ws-opts:
      path: /ws
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws
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
                network: "ws".into(),
                websocket: mihomo_transport::WebsocketOptions {
                    path: "/ws".into(),
                    ..Default::default()
                },
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
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    let read_err = client.read_to_end(&mut reply).err();
    if let Some(err) = read_err {
        panic!(
            "vmess ws inbound read failed: {err}; milestones={:?}",
            milestones.lock().unwrap().clone()
        );
    }
    assert_eq!(reply, b"pong-vmess-ws-inbound");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_grpc_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-grpc-inbound").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc");
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
    network: grpc
    grpc-service-name: example
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
                network: "grpc".into(),
                websocket: Default::default(),
                grpc: mihomo_transport::GrpcOptions {
                    service_name: "example".into(),
                    ..Default::default()
                },
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
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-grpc-inbound");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-h2-inbound").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2");
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
                tls: Default::default(),
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
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-h2-inbound");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_xhttp_stream_one_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-xhttp-stream-one").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-stream-one");
    fs::write(
        temp.join("config.yaml"),
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
    network: xhttp
    xhttp-opts:
      path: /vmx
      host: localhost
      mode: stream-one
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
                network: "xhttp".into(),
                websocket: Default::default(),
                grpc: Default::default(),
                h2: Default::default(),
                http: Default::default(),
                xhttp: mihomo_transport::XHttpOptions {
                    host: "localhost".into(),
                    path: "/vmx".into(),
                    mode: "stream-one".into(),
                    ..Default::default()
                },
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
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-xhttp-stream-one");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_xhttp_stream_up_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-xhttp-stream-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-stream-up");
    fs::write(
        temp.join("config.yaml"),
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
    network: xhttp
    xhttp-opts:
      path: /vmx
      host: localhost
      mode: stream-up
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
                network: "xhttp".into(),
                websocket: Default::default(),
                grpc: Default::default(),
                h2: Default::default(),
                http: Default::default(),
                xhttp: mihomo_transport::XHttpOptions {
                    host: "localhost".into(),
                    path: "/vmx".into(),
                    mode: "stream-up".into(),
                    ..Default::default()
                },
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
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-xhttp-stream-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_xhttp_packet_up_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-xhttp-packet-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up");
    fs::write(
        temp.join("config.yaml"),
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
    network: xhttp
    xhttp-opts:
      path: /vmx
      host: localhost
      mode: packet-up
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
                network: "xhttp".into(),
                websocket: Default::default(),
                grpc: Default::default(),
                h2: Default::default(),
                http: Default::default(),
                xhttp: mihomo_transport::XHttpOptions {
                    host: "localhost".into(),
                    path: "/vmx".into(),
                    mode: "packet-up".into(),
                    ..Default::default()
                },
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
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-xhttp-packet-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_ws_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-ws-udp");
        upstream.send_to(b"pong-vmess-ws-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-udp");
    fs::write(
        temp.join("config.yaml"),
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
    network: ws
    ws-path: /ws-udp
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

    let stream = mihomo_transport::wrap_websocket_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::WebsocketOptions {
            path: "/ws-udp".into(),
            ..Default::default()
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
    write_vmess_udp_packet(&mut *stream, b"ping-vmess-ws-udp").unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    assert_eq!(payload, b"pong-vmess-ws-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_ws_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-ws-xudp");
        upstream.send_to(b"pong-vmess-ws-xudp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-xudp");
    fs::write(
        temp.join("config.yaml"),
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
    network: ws
    ws-path: /ws-xudp
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

    let stream = mihomo_transport::wrap_websocket_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::WebsocketOptions {
            path: "/ws-xudp".into(),
            ..Default::default()
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
    write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-ws-xudp").unwrap();
    let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(payload, b"pong-vmess-ws-xudp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_ws_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-ws-pa");
        upstream.send_to(b"pong-vmess-ws-pa", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-packetaddr");
    fs::write(
        temp.join("config.yaml"),
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
    network: ws
    ws-path: /ws-pa
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

    let stream = mihomo_transport::wrap_websocket_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::WebsocketOptions {
            path: "/ws-pa".into(),
            ..Default::default()
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
        mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-ws-pa");
    write_vmess_udp_packet(&mut *stream, &payload).unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(packet, b"pong-vmess-ws-pa");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_grpc_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-grpc-udp");
        upstream.send_to(b"pong-vmess-grpc-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-udp");
    fs::write(
        temp.join("config.yaml"),
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
    network: grpc
    grpc-service-name: example
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

    let stream = mihomo_transport::wrap_grpc_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
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
    write_vmess_udp_packet(&mut *stream, b"ping-vmess-grpc-udp").unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    assert_eq!(payload, b"pong-vmess-grpc-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_grpc_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-grpc-xudp");
        upstream.send_to(b"pong-vmess-grpc-xudp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-xudp");
    fs::write(
        temp.join("config.yaml"),
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
    network: grpc
    grpc-service-name: example
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

    let stream = mihomo_transport::wrap_grpc_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
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
    write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-grpc-xudp").unwrap();
    let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(payload, b"pong-vmess-grpc-xudp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_grpc_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-grpc-pa");
        upstream.send_to(b"pong-vmess-grpc-pa", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-packetaddr");
    fs::write(
        temp.join("config.yaml"),
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
    network: grpc
    grpc-service-name: example
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

    let stream = mihomo_transport::wrap_grpc_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        TransportTarget::new("127.0.0.1", vmess_addr.port()),
        &mihomo_transport::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
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
        mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-grpc-pa");
    write_vmess_udp_packet(&mut *stream, &payload).unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(packet, b"pong-vmess-grpc-pa");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-h2-udp");
        upstream.send_to(b"pong-vmess-h2-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-udp");
    fs::write(
        temp.join("config.yaml"),
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
      path: /vmuh2
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

    let stream = mihomo_transport::wrap_h2_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/vmuh2".into(),
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
    write_vmess_udp_packet(&mut *stream, b"ping-vmess-h2-udp").unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    assert_eq!(payload, b"pong-vmess-h2-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-h2-xudp");
        upstream.send_to(b"pong-vmess-h2-xudp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-xudp");
    fs::write(
        temp.join("config.yaml"),
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
      path: /vmuh2x
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

    let stream = mihomo_transport::wrap_h2_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/vmuh2x".into(),
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
    write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-h2-xudp").unwrap();
    let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(payload, b"pong-vmess-h2-xudp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_h2_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vmess-h2-pa");
        upstream.send_to(b"pong-vmess-h2-pa", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-packetaddr");
    fs::write(
        temp.join("config.yaml"),
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
      path: /vmuh2pa
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

    let stream = mihomo_transport::wrap_h2_proxy_stream(
        Box::new(TcpStream::connect(vmess_addr).unwrap()),
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/vmuh2pa".into(),
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
        mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-h2-pa");
    write_vmess_udp_packet(&mut *stream, &payload).unwrap();
    let payload = read_vmess_udp_packet(&mut *stream).unwrap();
    let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
    assert_eq!(target, upstream_addr);
    assert_eq!(packet, b"pong-vmess-h2-pa");

    upstream_worker.join().unwrap();
    app.shutdown();
}
