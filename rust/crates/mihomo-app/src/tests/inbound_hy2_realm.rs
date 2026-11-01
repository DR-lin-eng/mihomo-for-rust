use super::*;

#[test]
fn start_serves_hy2_realm_listener_end_to_end() {
    let temp = unique_temp_dir("mihomo-app-inbound-hy2-realm");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: hysteria2-realm
    name: edge-hy2-realm
    listen: 127.0.0.1
    port: "0"
    token: public
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
    let realm_addr = find_listener_addr(&app, "edge-hy2-realm", "hysteria2-realm");

    let register = send_http_request(
        realm_addr,
        "POST",
        "/v1/testrealm",
        Some("public"),
        Some(br#"{"addresses":["127.0.0.1:6001"]}"#),
    );
    assert!(register.starts_with("HTTP/1.1 200 OK"), "{register}");
    let register_json = parse_http_json(&register);
    let session_id = register_json["session_id"].as_str().unwrap().to_owned();

    let heartbeat = send_http_request(
        realm_addr,
        "POST",
        "/v1/testrealm/heartbeat",
        Some(&session_id),
        Some(br#"{"addresses":["127.0.0.1:6002"]}"#),
    );
    assert!(heartbeat.starts_with("HTTP/1.1 200 OK"), "{heartbeat}");

    let events = send_http_request(realm_addr, "GET", "/v1/testrealm/events", Some(&session_id), None);
    assert!(events.starts_with("HTTP/1.1 200 OK"), "{events}");
    assert!(events.contains("event: heartbeat_ack"), "{events}");

    let connect_addr = realm_addr;
    let connect_thread = thread::spawn(move || {
        send_http_request(
            connect_addr,
            "POST",
            "/v1/testrealm/connect",
            Some("public"),
            Some(
                br#"{"addresses":["127.0.0.1:7001"],"nonce":"00112233445566778899aabbccddeeff","obfs":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#,
            ),
        )
    });

    thread::sleep(Duration::from_millis(100));
    let punch = send_http_request(realm_addr, "GET", "/v1/testrealm/events", Some(&session_id), None);
    assert!(punch.contains("event: punch"), "{punch}");
    assert!(punch.contains("\"nonce\":\"00112233445566778899aabbccddeeff\""), "{punch}");

    let connect_response = send_http_request(
        realm_addr,
        "POST",
        "/v1/testrealm/connects/00112233445566778899aabbccddeeff",
        Some(&session_id),
        Some(br#"{"addresses":["127.0.0.1:7002"]}"#),
    );
    assert!(connect_response.starts_with("HTTP/1.1 204 No Content"), "{connect_response}");

    let connect = connect_thread.join().unwrap();
    assert!(connect.starts_with("HTTP/1.1 200 OK"), "{connect}");
    let connect_json = parse_http_json(&connect);
    assert_eq!(
        connect_json["addresses"].as_array().unwrap(),
        &vec![Value::String("127.0.0.1:7002".to_owned())]
    );

    let delete =
        send_http_request(realm_addr, "DELETE", "/v1/testrealm", Some(&session_id), None);
    assert!(delete.starts_with("HTTP/1.1 204 No Content"), "{delete}");

    app.shutdown();
}

#[test]
fn start_serves_hy2_realm_listener_with_tls_end_to_end() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-realm-tls");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: hysteria2-realm
    name: edge-hy2-realm
    listen: 127.0.0.1
    port: "0"
    token: public
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
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
    let realm_addr = find_listener_addr(&app, "edge-hy2-realm", "hysteria2-realm");

    let register = send_https_request_skip_verify(
        realm_addr,
        "POST",
        "/v1/testrealm",
        Some("public"),
        Some(br#"{"addresses":["127.0.0.1:6001"]}"#),
    );
    assert!(register.starts_with("HTTP/1.1 200 OK"), "{register}");
    let register_json = parse_http_json(&register);
    let session_id = register_json["session_id"].as_str().unwrap().to_owned();

    let events = send_https_request_skip_verify(
        realm_addr,
        "GET",
        "/v1/testrealm/events",
        Some(&session_id),
        None,
    );
    assert!(events.starts_with("HTTP/1.1 200 OK"), "{events}");

    app.shutdown();
}

#[test]
fn start_serves_hy2_listener_with_realm_opts_registers_to_native_realm_server() {
    let stun_server = TestStunServer::start();
    let realm_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-realm-enabled");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: hysteria2-realm
    name: edge-hy2-realm
    listen: 127.0.0.1
    port: "{realm_port}"
    token: public
  - type: hysteria2
    name: edge-hy2
    listen: 127.0.0.1
    port: "0"
    users:
      user-a: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    realm-opts:
      enable: true
      server-url: http://127.0.0.1:{realm_port}
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - {stun_addr}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            realm_port = realm_port,
            stun_addr = stun_server.addr,
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
    thread::sleep(Duration::from_millis(500));

    let connect = send_http_request(
        SocketAddr::from(([127, 0, 0, 1], realm_port)),
        "POST",
        "/v1/my-cabin-1f3a8c2e9b/connect",
        Some("public"),
        Some(
            br#"{"addresses":["127.0.0.1:7001"],"nonce":"00112233445566778899aabbccddeeff","obfs":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#,
        ),
    );
    assert!(connect.starts_with("HTTP/1.1 200 OK"), "{connect}");
    let body = parse_http_json(&connect);
    assert!(
        body["addresses"].as_array().is_some_and(|items| !items.is_empty()),
        "{body}"
    );

    app.shutdown();
    stun_server.shutdown();
}

#[test]
fn start_serves_hy2_listener_with_realm_opts_proxy_registers_via_socks5_proxy() {
    let stun_server = TestStunServer::start();
    let realm_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let realm_addr = realm_server.local_addr().unwrap();
    let proxy_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_server.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let realm_worker = thread::spawn(move || {
        let (mut stream, _) = realm_server.accept().unwrap();
        let request = read_http_headers(&mut stream);
        assert!(request.starts_with("POST /v1/my-cabin-1f3a8c2e9b HTTP/1.1\r\n"), "{request}");
        assert!(request.contains("Authorization: Bearer public\r\n"), "{request}");
        send_http_response(&mut stream, "200 OK", br#"{"session_id":"sess-1","ttl":60}"#);
    });
    let proxy_worker = thread::spawn(move || {
        let (mut control, _) = proxy_server.accept().unwrap();
        let mut greeting = [0_u8; 3];
        control.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        control.write_all(&[0x05, 0x00]).unwrap();

        let mut header = [0_u8; 4];
        control.read_exact(&mut header).unwrap();
        assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
        match header[3] {
            0x01 => {
                let mut addr = [0_u8; 4];
                control.read_exact(&mut addr).unwrap();
                assert_eq!(SocketAddr::from((addr, 0)).ip(), realm_addr.ip());
            }
            other => panic!("unexpected atyp {other}"),
        }
        let mut port = [0_u8; 2];
        control.read_exact(&mut port).unwrap();
        assert_eq!(u16::from_be_bytes(port), realm_addr.port());

        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        reply.extend_from_slice(&[127, 0, 0, 1]);
        reply.extend_from_slice(&0_u16.to_be_bytes());
        control.write_all(&reply).unwrap();

        let mut upstream = TcpStream::connect(realm_addr).unwrap();
        let mut control_writer = control.try_clone().unwrap();
        let mut upstream_writer = upstream.try_clone().unwrap();
        let upload = thread::spawn(move || {
            let _ = std::io::copy(&mut control, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
        });
        let download = thread::spawn(move || {
            let _ = std::io::copy(&mut upstream, &mut control_writer);
            let _ = control_writer.shutdown(Shutdown::Write);
        });
        upload.join().unwrap();
        download.join().unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-realm-proxy");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: hysteria2
    name: edge-hy2
    listen: 127.0.0.1
    port: "0"
    users:
      user-a: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    realm-opts:
      enable: true
      server-url: http://127.0.0.1:{realm_port}
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - {stun_addr}
      proxy: socks5://127.0.0.1:{proxy_port}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
            realm_port = realm_addr.port(),
            stun_addr = stun_server.addr,
            proxy_port = proxy_addr.port(),
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
    thread::sleep(Duration::from_millis(500));

    realm_worker.join().unwrap();
    proxy_worker.join().unwrap();
    app.shutdown();
    stun_server.shutdown();
}

#[test]
fn start_serves_hy2_listener_with_realm_opts_proxy_name_registers_via_named_socks5_proxy() {
    let stun_server = TestStunServer::start();
    let realm_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let realm_addr = realm_server.local_addr().unwrap();
    let proxy_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_server.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let realm_worker = thread::spawn(move || {
        let (mut stream, _) = realm_server.accept().unwrap();
        let request = read_http_headers(&mut stream);
        assert!(request.starts_with("POST /v1/my-cabin-1f3a8c2e9b HTTP/1.1\r\n"), "{request}");
        assert!(request.contains("Authorization: Bearer public\r\n"), "{request}");
        send_http_response(&mut stream, "200 OK", br#"{"session_id":"sess-2","ttl":60}"#);
    });
    let proxy_worker = thread::spawn(move || {
        let (mut control, _) = proxy_server.accept().unwrap();
        let mut greeting = [0_u8; 3];
        control.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        control.write_all(&[0x05, 0x00]).unwrap();

        let mut header = [0_u8; 4];
        control.read_exact(&mut header).unwrap();
        assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
        match header[3] {
            0x01 => {
                let mut addr = [0_u8; 4];
                control.read_exact(&mut addr).unwrap();
                assert_eq!(SocketAddr::from((addr, 0)).ip(), realm_addr.ip());
            }
            other => panic!("unexpected atyp {other}"),
        }
        let mut port = [0_u8; 2];
        control.read_exact(&mut port).unwrap();
        assert_eq!(u16::from_be_bytes(port), realm_addr.port());

        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        reply.extend_from_slice(&[127, 0, 0, 1]);
        reply.extend_from_slice(&0_u16.to_be_bytes());
        control.write_all(&reply).unwrap();

        let mut upstream = TcpStream::connect(realm_addr).unwrap();
        let mut control_writer = control.try_clone().unwrap();
        let mut upstream_writer = upstream.try_clone().unwrap();
        let upload = thread::spawn(move || {
            let _ = std::io::copy(&mut control, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
        });
        let download = thread::spawn(move || {
            let _ = std::io::copy(&mut upstream, &mut control_writer);
            let _ = control_writer.shutdown(Shutdown::Write);
        });
        upload.join().unwrap();
        download.join().unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-realm-proxy-name");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: hysteria2
    name: edge-hy2
    listen: 127.0.0.1
    port: "0"
    users:
      user-a: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    realm-opts:
      enable: true
      server-url: http://127.0.0.1:{realm_port}
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - {stun_addr}
      proxy: outer-socks
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: {proxy_port}
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
            realm_port = realm_addr.port(),
            stun_addr = stun_server.addr,
            proxy_port = proxy_addr.port(),
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
    thread::sleep(Duration::from_millis(500));

    realm_worker.join().unwrap();
    proxy_worker.join().unwrap();
    app.shutdown();
    stun_server.shutdown();
}

#[test]
fn start_serves_hy2_listener_with_realm_opts_end_to_end() {
    let stun_server = TestStunServer::start();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let realm_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-realm-full");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: hysteria2-realm
    name: edge-hy2-realm
    listen: 127.0.0.1
    port: "{realm_port}"
    token: public
  - type: hysteria2
    name: edge-hy2
    listen: 127.0.0.1
    port: "0"
    users:
      user-a: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    realm-opts:
      enable: true
      server-url: http://127.0.0.1:{realm_port}
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - {stun_addr}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            realm_port = realm_port,
            stun_addr = stun_server.addr,
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
    thread::sleep(Duration::from_millis(500));

    let hy2_addr = find_listener_addr(&app, "edge-hy2", "hysteria2");
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-hy2-realm").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let plan = TransportPlan {
        requested: "edge-hy2".into(),
        selected_path: vec!["edge-hy2".into()],
        leaf_name: "edge-hy2".into(),
        hops: vec![TransportHop {
            name: "edge-hy2".into(),
            action: TransportAction::Hy2Connect {
                proxy: TransportTarget::new("127.0.0.1", hy2_addr.port()),
                password: "secret".into(),
                sni: "localhost".into(),
                certificate: String::new(),
                private_key: String::new(),
                obfs: String::new(),
                obfs_password: String::new(),
                realm_enabled: true,
                realm_server_url: format!("http://127.0.0.1:{realm_port}"),
                realm_token: "public".into(),
                realm_id: "my-cabin-1f3a8c2e9b".into(),
                realm_stun_servers: vec![stun_server.addr.to_string()],
                realm_sni: String::new(),
                realm_skip_cert_verify: false,
                realm_fingerprint: String::new(),
                realm_certificate: String::new(),
                realm_private_key: String::new(),
                realm_alpn: Vec::new(),
                realm_proxy: String::new(),
                realm_proxy_plan: None,
                skip_cert_verify: true,
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
    assert_eq!(reply, b"pong-hy2-realm");

    upstream_worker.join().unwrap();
    app.shutdown();
    stun_server.shutdown();
}
