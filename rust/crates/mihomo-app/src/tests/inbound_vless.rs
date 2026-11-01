use super::*;

#[test]
fn start_serves_vless_reality_listener_end_to_end() {
    // Outbound REALITY client ↔ inbound REALITY listener, over loopback.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
        stream.write_all(b"pong-reality").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });

    // Site that the REALITY server borrows its ServerHello from.
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let site_addr = site.local_addr().unwrap();
    let site_worker = thread::spawn(move || {
        let (mut stream, _) = site.accept().unwrap();
        let mut header = [0_u8; 5];
        let _ = stream.read_exact(&mut header);
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0_u8; len];
        let _ = stream.read_exact(&mut body);
        stream
            .write_all(&mihomo_transport::test_support_reality_site_hello())
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
    });

    let keys = mihomo_transport::generate_reality_keys();
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keys.private_key);
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keys.public_key);

    let temp = unique_temp_dir("mihomo-app-inbound-vless-reality");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - username: alice
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    reality-config:
      dest: 127.0.0.1:{site_port}
      server-names:
        - www.example.com
      private-key: {private_key}
      short-id:
        - "0123456789abcdef"
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            site_port = site_addr.port(),
            private_key = private_key_b64,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    // Establish the REALITY session by hand, then speak plain VLESS over it.
    let raw = TcpStream::connect(vless_addr).unwrap();
    let reality_config = mihomo_transport::RealityClientConfig {
        public_key: mihomo_transport::parse_reality_private_key(&public_key_b64).unwrap(),
        short_id: mihomo_transport::parse_reality_short_id("0123456789abcdef").unwrap(),
        server_name: "www.example.com".to_owned(),
        ..Default::default()
    };
    let reality = mihomo_transport::wrap_reality_stream(
        Box::new(raw),
        &reality_config,
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    let mut vless_client = mihomo_transport::open_vless_tcp_stream_for_tests(
        reality,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    vless_client.write_all(b"ping").unwrap();
    vless_client.flush().unwrap();
    let mut reply = vec![0_u8; 12];
    vless_client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong-reality");

    upstream_worker.join().unwrap();
    site_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_dials_vless_reality_outbound_end_to_end() {
    // Inbound REALITY listener (standalone transport threads) + an app whose
    // vless proxy carries reality-opts; proves the full outbound path.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
        stream.write_all(b"pong-out-reality").unwrap();
    });

    let keys = mihomo_transport::generate_reality_keys();
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keys.private_key);
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keys.public_key);

    // REALITY inbound transport (outside any app): terminates REALITY and
    // hands the plaintext stream to a plain VLESS acceptor.
    let reality_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let reality_addr = reality_listener.local_addr().unwrap();
    // A site for the ServerHello borrow (must exist before the config so
    // the REALITY server can dial it lazily).
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let site_addr = site.local_addr().unwrap();
    let reality_server_config = mihomo_transport::RealityServerConfig {
        private_key: keys.private_key,
        server_names: vec!["www.example.com".to_owned()],
        short_ids: vec![mihomo_transport::parse_reality_short_id("0123456789abcdef").unwrap()],
        dest: format!("127.0.0.1:{}", site_addr.port()),
        max_time_diff: 60,
    };
    let site_worker = thread::spawn(move || {
        let (mut stream, _) = site.accept().unwrap();
        let mut header = [0_u8; 5];
        let _ = stream.read_exact(&mut header);
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0_u8; len];
        let _ = stream.read_exact(&mut body);
        stream
            .write_all(&mihomo_transport::test_support_reality_site_hello())
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
    });
    // The dest the vless server dials after REALITY: an upstream.
    let vless_upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let vless_upstream_addr = vless_upstream.local_addr().unwrap();
    let reality_worker = thread::spawn(move || {
        let (stream, _) = reality_listener.accept().unwrap();
        let mut reality = mihomo_transport::accept_reality_stream(
            Box::new(stream),
            &reality_server_config,
        )
        .unwrap();
        // Accept plain VLESS over the REALITY session (server side).
        let (accepted, _) = mihomo_transport::accept_vless_stream_with_uuids(
            reality,
            &["b831381d-6324-4d53-ad4f-8cda48b30811".to_owned()],
        )
        .unwrap();
        let mihomo_transport::VlessAcceptedStream::Tcp { target, mut stream } = accepted else {
            panic!("expected vless tcp");
        };
        let mut upstream = std::net::TcpStream::connect(target).unwrap();
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).unwrap();
        upstream.write_all(&buf).unwrap();
        let mut reply = [0_u8; 16];
        upstream.read_exact(&mut reply).unwrap();
        stream.write_all(&reply).unwrap();
        stream.flush().unwrap();
    });

    // App with a tunnel listener proxying through the vless reality outbound.
    let temp = unique_temp_dir("mihomo-app-outbound-vless-reality");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: out-vless
    target: 127.0.0.1:{upstream_port}
proxies:
  - type: vless
    name: out-vless
    server: 127.0.0.1
    port: {reality_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    server-name: www.example.com
    reality-opts:
      public-key: {public_key}
      short-id: "0123456789abcdef"
    client-fingerprint: chrome
rules:
  - MATCH,out-vless
"#,
            upstream_port = upstream_addr.port(),
            reality_port = reality_addr.port(),
            public_key = public_key_b64,
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
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"ping").unwrap();
    client.flush().unwrap();
    let mut reply = vec![0_u8; 16];
    match client.read_exact(&mut reply) {
        Ok(()) => assert_eq!(&reply, b"pong-out-reality"),
        Err(err) => panic!("tunnel read failed: {err}"),
    }

    upstream_worker.join().unwrap();
    reality_worker.join().unwrap();
    site_worker.join().unwrap();
    app.shutdown();
}

fn start_serves_vless_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
        stream.write_all(b"pong-vless-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_ws_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-ws-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-ws");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: ws
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    ws-opts:
      path: /edge-vless
      headers:
        Host: localhost
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = Box::new(connect_websocket_client_stream(
        vless_addr,
        "/edge-vless",
        Some("localhost"),
    ));
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-ws-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_h2_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-h2-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-h2");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: h2
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    h2-opts:
      host: [localhost]
      path: /edge-h2
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = mihomo_transport::wrap_h2_proxy_stream(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        &mihomo_transport::Http2Options {
            host: vec!["localhost".into()],
            path: "/edge-h2".into(),
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-h2-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_grpc_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-grpc-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-grpc");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: grpc
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    grpc-opts:
      grpc-service-name: example
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = mihomo_transport::wrap_grpc_proxy_stream(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
        &mihomo_transport::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-grpc-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_http_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-http-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-http");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: http
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    http-opts:
      method: GET
      host: [localhost]
      path: [/edge-http]
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = mihomo_transport::wrap_http_proxy_stream(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
        &mihomo_transport::HttpStreamOptions {
            method: "GET".into(),
            host: vec!["localhost".into()],
            path: vec!["/edge-http".into()],
            headers: BTreeMap::new(),
        },
    );
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-http-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_xhttp_stream_one_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-xhttp-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-one
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = mihomo_transport::wrap_xhttp_proxy_stream(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
        &mihomo_transport::XHttpOptions {
            host: "localhost".into(),
            path: "/vx".into(),
            mode: "stream-one".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-xhttp-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_xhttp_stream_up_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-xhttp-stream-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp-stream-up");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-up
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = mihomo_transport::wrap_xhttp_proxy_stream(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
        &mihomo_transport::XHttpOptions {
            host: "localhost".into(),
            path: "/vx".into(),
            mode: "stream-up".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-xhttp-stream-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_listener_with_xhttp_packet_up_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-vless-xhttp-packet-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp-packet-up");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: packet-up
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let client_stream = mihomo_transport::wrap_xhttp_proxy_stream(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
        &mihomo_transport::XHttpOptions {
            host: "localhost".into(),
            path: "/vx".into(),
            mode: "packet-up".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        client_stream,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-vless-xhttp-packet-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn vless_listener_rejects_unknown_uuid() {
    let temp = unique_temp_dir("mihomo-app-inbound-vless-auth");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
        Box::new(TcpStream::connect(vless_addr).unwrap()),
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        &mihomo_transport::TransportTarget::new("127.0.0.1", 80),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    match client.read_to_end(&mut reply) {
        Ok(_) => assert!(reply.is_empty(), "{reply:?}"),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset),
    }

    app.shutdown();
}

#[test]
fn start_serves_vless_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vless-udp");
        upstream.send_to(b"pong-vless-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let worker = thread::spawn(move || {
        let mut stream = mihomo_transport::open_vless_udp_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            upstream_addr,
        )
        .unwrap();
        write_vless_udp_packet(&mut *stream, b"ping-vless-udp").unwrap();
        let payload = read_vless_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vless-udp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vless-xudp");
        upstream.send_to(b"pong-vless-xudp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xudp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let worker = thread::spawn(move || {
        let mut stream = mihomo_transport::open_vless_xudp_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        .unwrap();
        write_vless_xudp_packet(&mut *stream, upstream_addr, b"ping-vless-xudp").unwrap();
        let (target, payload) = read_vless_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vless-xudp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vless-pa");
        upstream.send_to(b"pong-vless-pa", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-packetaddr");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let worker = thread::spawn(move || {
        let mut stream = mihomo_transport::open_vless_packetaddr_udp_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        .unwrap();
        let framed = mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vless-pa");
        write_vless_udp_packet(&mut *stream, &framed).unwrap();
        let payload = read_vless_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vless-pa");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_xhttp_stream_up_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vless-xhttp-udp");
        upstream.send_to(b"pong-vless-xhttp-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp-stream-up-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vxsu
      host: localhost
      mode: stream-up
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_xhttp_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
            &mihomo_transport::XHttpOptions {
                host: "localhost".into(),
                path: "/vxsu".into(),
                mode: "stream-up".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vless_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            upstream_addr,
        )
        .unwrap();
        write_vless_udp_packet(&mut *stream, b"ping-vless-xhttp-udp").unwrap();
        let payload = read_vless_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vless-xhttp-udp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_xhttp_packetaddr_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vless-xhttp-pa");
        upstream.send_to(b"pong-vless-xhttp-pa", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp-packetaddr");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vxpa
      host: localhost
      mode: packet-up
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_xhttp_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
            &mihomo_transport::XHttpOptions {
                host: "localhost".into(),
                path: "/vxpa".into(),
                mode: "packet-up".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vless_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        .unwrap();
        let framed =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vless-xhttp-pa");
        write_vless_udp_packet(&mut *stream, &framed).unwrap();
        let payload = read_vless_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vless-xhttp-pa");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_vless_xhttp_xudp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-vless-xhttp-xudp");
        upstream.send_to(b"pong-vless-xhttp-xudp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp-xudp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vxxu
      host: localhost
      mode: packet-up
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_xhttp_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
            &mihomo_transport::XHttpOptions {
                host: "localhost".into(),
                path: "/vxxu".into(),
                mode: "packet-up".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vless_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        .unwrap();
        write_vless_xudp_packet(&mut *stream, upstream_addr, b"ping-vless-xhttp-xudp").unwrap();
        let (target, payload) = read_vless_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vless-xhttp-xudp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn vless_listener_rejects_invalid_configured_uuid() {
    let temp = unique_temp_dir("mihomo-app-inbound-vless-invalid-uuid");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: vless
    name: edge-vless
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
    assert!(err.to_string().contains("vless listener edge-vless has invalid user uuid"));
}

#[test]
fn start_serves_vless_listener_with_multiple_users_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong-vless-multi").unwrap();
        }
    });

    let temp = unique_temp_dir("mihomo-app-inbound-vless-multi");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - username: alice
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
      - username: bob
        uuid: 3f2d2c8e-9a41-4f2b-9c8d-1a2b3c4d5e6f
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
    let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

    for uuid in [
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        "3f2d2c8e-9a41-4f2b-9c8d-1a2b3c4d5e6f",
    ] {
        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            uuid,
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-multi");
    }

    upstream_worker.join().unwrap();
    app.shutdown();
}
