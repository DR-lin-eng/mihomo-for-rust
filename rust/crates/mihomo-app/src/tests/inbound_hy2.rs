use super::*;

#[test]
fn start_serves_hy2_listener_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-hy2");
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
    let hy2_addr = find_listener_addr(&app, "edge-hy2", "hysteria2");

    let mut stream = open_hy2_udp_stream(
        &TransportTarget::new("127.0.0.1", hy2_addr.port()),
        &mihomo_transport::Hy2UdpOptions {
            password: "secret".into(),
            sni: "localhost".into(),
            skip_cert_verify: true,
            certificate: String::new(),
            private_key: String::new(),
            obfs: String::new(),
            obfs_password: String::new(),
            udp_mtu: 1200,
            realm: mihomo_transport::Hy2RealmOptions::default(),
        },
    )
    .unwrap();
    write_hy2_udp_packet(&mut *stream, target, b"ping-hy2-udp").unwrap();

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"ping-hy2-udp");
    upstream.send_to(b"pong-hy2-udp", from).unwrap();

    let (source, payload) = read_hy2_udp_packet(&mut *stream).unwrap();
    assert_eq!(source, target);
    assert_eq!(payload, b"pong-hy2-udp".to_vec());

    app.shutdown();
}

#[test]
fn start_serves_hy2_listener_with_salamander_obfs_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-salamander");
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
    obfs: salamander
    obfs-password: demo-obfs
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
    let hy2_addr = find_listener_addr(&app, "edge-hy2", "hysteria2");

    let mut stream = open_hy2_udp_stream(
        &TransportTarget::new("127.0.0.1", hy2_addr.port()),
        &mihomo_transport::Hy2UdpOptions {
            password: "secret".into(),
            sni: "localhost".into(),
            skip_cert_verify: true,
            certificate: String::new(),
            private_key: String::new(),
            obfs: "salamander".into(),
            obfs_password: "demo-obfs".into(),
            udp_mtu: 1200,
            realm: mihomo_transport::Hy2RealmOptions::default(),
        },
    )
    .unwrap();
    write_hy2_udp_packet(&mut *stream, target, b"ping-hy2-salamander").unwrap();

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"ping-hy2-salamander");
    upstream.send_to(b"pong-hy2-salamander", from).unwrap();

    let (source, payload) = read_hy2_udp_packet(&mut *stream).unwrap();
    assert_eq!(source, target);
    assert_eq!(payload, b"pong-hy2-salamander".to_vec());

    app.shutdown();
}

#[test]
fn start_serves_hy2_listener_with_client_auth_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-hy2-mtls");
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
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
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
    let hy2_addr = find_listener_addr(&app, "edge-hy2", "hysteria2");

    let mut stream = open_hy2_udp_stream(
        &TransportTarget::new("127.0.0.1", hy2_addr.port()),
        &mihomo_transport::Hy2UdpOptions {
            password: "secret".into(),
            sni: "localhost".into(),
            skip_cert_verify: true,
            certificate: client_cert_pem.clone(),
            private_key: client_key_pem.clone(),
            obfs: String::new(),
            obfs_password: String::new(),
            udp_mtu: 1200,
            realm: mihomo_transport::Hy2RealmOptions::default(),
        },
    )
    .unwrap();
    write_hy2_udp_packet(&mut *stream, target, b"ping-hy2-mtls").unwrap();

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"ping-hy2-mtls");
    upstream.send_to(b"pong-hy2-mtls", from).unwrap();

    let (source, payload) = read_hy2_udp_packet(&mut *stream).unwrap();
    assert_eq!(source, target);
    assert_eq!(payload, b"pong-hy2-mtls".to_vec());

    app.shutdown();
}

#[test]
fn start_serves_tunnel_udp_with_hy2_over_outer_socks5_udp_associate() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let outer_socks = spawn_socks5_udp_associate_proxy();
    let outer_socks_addr = outer_socks.addr;
    let hy2_bind = UdpSocket::bind("127.0.0.1:0").unwrap();
    let hy2_port = hy2_bind.local_addr().unwrap().port();
    drop(hy2_bind);

    let temp = unique_temp_dir("mihomo-app-hy2-udp-over-outer-socks5");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-hy2
    target: 127.0.0.1:{target_port}
  - type: hysteria2
    name: edge-hy2-in
    listen: 127.0.0.1
    port: "{hy2_port}"
    users:
      user-a: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: {outer_port}
    udp: true
  - type: hysteria2
    name: edge-hy2
    server: 127.0.0.1
    port: {hy2_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - DST-PORT,{hy2_port},DIRECT
  - DST-PORT,{target_port},DIRECT
  - MATCH,edge-hy2
"#,
            target_port = target.port(),
            hy2_port = hy2_port,
            outer_port = outer_socks_addr.port(),
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
    let tunnel_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    client.send_to(b"ping-hy2-outer-socks", tunnel_addr).unwrap();

    upstream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"ping-hy2-outer-socks");
    upstream.send_to(b"pong-hy2-outer-socks", from).unwrap();

    let mut reply = [0_u8; 2048];
    let (reply_read, _) = client.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..reply_read], b"pong-hy2-outer-socks");

    app.shutdown();
    outer_socks.shutdown();
}

#[test]
fn start_serves_hy2_listener_tcp_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-hy2").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let temp = unique_temp_dir("mihomo-app-inbound-hy2-tcp");
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
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert.cert.pem().trim_end(), 6),
            key_pem = indent_block(cert.key_pair.serialize_pem().trim_end(), 6),
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
    let hy2_addr = find_listener_addr(&app, "edge-hy2", "hysteria2");

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
                realm_enabled: false,
                realm_server_url: String::new(),
                realm_token: String::new(),
                realm_id: String::new(),
                realm_stun_servers: Vec::new(),
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
    assert_eq!(reply, b"pong-hy2");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn hy2_transport_plan_dualstack_proxy_host_fallback() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-hy2").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let temp = unique_temp_dir("mihomo-app-hy2-transport-dualstack");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
hosts:
  relay.invalid:
    - "::1"
    - "127.0.0.1"
dns:
  enable: true
  use-hosts: true
  use-system-hosts: false
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
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert.cert.pem().trim_end(), 6),
            key_pem = indent_block(cert.key_pair.serialize_pem().trim_end(), 6),
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
    let hy2_addr = find_listener_addr(&app, "edge-hy2", "hysteria2");

    let plan = TransportPlan {
        requested: "edge-hy2".into(),
        selected_path: vec!["edge-hy2".into()],
        leaf_name: "edge-hy2".into(),
        hops: vec![TransportHop {
            name: "edge-hy2".into(),
            action: TransportAction::Hy2Connect {
                proxy: TransportTarget::new("relay.invalid", hy2_addr.port()),
                password: "secret".into(),
                sni: "localhost".into(),
                certificate: String::new(),
                private_key: String::new(),
                obfs: String::new(),
                obfs_password: String::new(),
                realm_enabled: false,
                realm_server_url: String::new(),
                realm_token: String::new(),
                realm_id: String::new(),
                realm_stun_servers: Vec::new(),
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
    let dns_runtime = app.state.build_dns_runtime().unwrap();
    let mut executor =
        TcpTransportExecutor::new(crate::listener_service::DnsAwareTcpDialer::new(Some(dns_runtime)));
    let mut client = executor.run_plan(&plan).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-hy2");

    upstream_worker.join().unwrap();
    app.shutdown();
}
