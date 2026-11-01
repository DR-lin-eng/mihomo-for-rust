use super::*;

#[test]
fn start_serves_vmess_ws_query_early_data_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-ws-ed").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-ed");
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
    network: ws
    ws-path: /ws-early
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
                    path: "/ws-early?ed=2048&foo=bar".into(),
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
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-ws-ed");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_ws_header_early_data_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-ws-hed").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-header-ed");
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
    network: ws
    ws-path: /ws-header-early
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
                    path: "/ws-header-early".into(),
                    max_early_data: 2048,
                    early_data_header_name: "Sec-WebSocket-Protocol".into(),
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
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-ws-hed");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_ws_http_upgrade_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-ws-upgrade").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-upgrade");
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
    network: ws
    ws-path: /ws-upgrade-plain
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
                    path: "/ws-upgrade-plain".into(),
                    v2ray_http_upgrade: true,
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
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-ws-upgrade");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vmess_ws_http_upgrade_fast_open_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vmess-ws-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-upgrade");
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
    network: ws
    ws-path: /ws-upgrade
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
                    path: "/ws-upgrade".into(),
                    v2ray_http_upgrade: true,
                    v2ray_http_upgrade_fast_open: true,
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
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vmess-ws-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}
