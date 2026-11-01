use super::*;

#[test]
fn start_serves_custom_tunnel_listener_with_tuic_proxy_end_to_end() {
    let tuic_server = TestTuicServer::start_v5(
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        "secret",
    );
    let temp = unique_temp_dir("mihomo-app-tunnel-tuic");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: tuic
    name: relay
    server: 127.0.0.1
    port: {tuic_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    sni: localhost
    skip-cert-verify: true
    alpn: [h3]
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: tuic-target.example.com:443
"#,
            tuic_port = tuic_server.addr.port(),
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
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-tuic");

    tuic_server.shutdown();
    app.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_tuic_proxy_dualstack_host_fallback() {
    let tuic_server = TestTuicServer::start_v5(
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        "secret",
    );
    let temp = unique_temp_dir("mihomo-app-tunnel-tuic-dualstack");
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
proxies:
  - type: tuic
    name: relay
    server: relay.invalid
    port: {tuic_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    sni: localhost
    skip-cert-verify: true
    alpn: [h3]
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: tuic-target.example.com:443
"#,
            tuic_port = tuic_server.addr.port(),
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
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-tuic");

    tuic_server.shutdown();
    app.shutdown();
}

#[test]
fn start_serves_tuic_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-tuic-in").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-tuic");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
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
    let tuic_addr = find_listener_addr(&app, "edge-tuic", "tuic");

    let plan = TransportPlan {
        requested: "edge-tuic".into(),
        selected_path: vec!["edge-tuic".into()],
        leaf_name: "edge-tuic".into(),
        hops: vec![TransportHop {
            name: "edge-tuic".into(),
            action: TransportAction::TuicConnect {
                proxy: TransportTarget::new("127.0.0.1", tuic_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                password: "secret".into(),
                token: String::new(),
                udp: false,
                sni: "localhost".into(),
                certificate: String::new(),
                private_key: String::new(),
                alpn: vec!["h3".into()],
                disable_sni: false,
                request_timeout_ms: 8000,
                heartbeat_interval_ms: 10000,
                congestion_controller: String::new(),
                max_open_streams: 100,
                max_udp_relay_packet_size: 1500,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
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
    assert_eq!(reply, b"pong-tuic-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_tuic_listener_with_client_auth_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-tuic-mtls").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-tuic-mtls");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
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
    let tuic_addr = find_listener_addr(&app, "edge-tuic", "tuic");

    let plan = TransportPlan {
        requested: "edge-tuic".into(),
        selected_path: vec!["edge-tuic".into()],
        leaf_name: "edge-tuic".into(),
        hops: vec![TransportHop {
            name: "edge-tuic".into(),
            action: TransportAction::TuicConnect {
                proxy: TransportTarget::new("127.0.0.1", tuic_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                password: "secret".into(),
                token: String::new(),
                udp: false,
                sni: "localhost".into(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
                alpn: vec!["h3".into()],
                disable_sni: false,
                request_timeout_ms: 8000,
                heartbeat_interval_ms: 10000,
                congestion_controller: String::new(),
                max_open_streams: 100,
                max_udp_relay_packet_size: 1500,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: client_cert_pem.clone(),
                    private_key: client_key_pem.clone(),
                },
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
    assert_eq!(reply, b"pong-tuic-mtls");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_tuic_listener_with_require_any_client_auth_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-tuic-require-any").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let trusted_ca = rcgen::generate_simple_self_signed(vec!["trusted.local".into()]).unwrap();
    let trusted_ca_pem = trusted_ca.cert.pem();

    let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-tuic-require-any");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require-any
    client-auth-cert: |
{trusted_ca_pem}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
            trusted_ca_pem = indent_block(trusted_ca_pem.trim_end(), 6),
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
    let tuic_addr = find_listener_addr(&app, "edge-tuic", "tuic");

    let plan = TransportPlan {
        requested: "edge-tuic".into(),
        selected_path: vec!["edge-tuic".into()],
        leaf_name: "edge-tuic".into(),
        hops: vec![TransportHop {
            name: "edge-tuic".into(),
            action: TransportAction::TuicConnect {
                proxy: TransportTarget::new("127.0.0.1", tuic_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                password: "secret".into(),
                token: String::new(),
                udp: false,
                sni: "localhost".into(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
                alpn: vec!["h3".into()],
                disable_sni: false,
                request_timeout_ms: 8000,
                heartbeat_interval_ms: 10000,
                congestion_controller: String::new(),
                max_open_streams: 100,
                max_udp_relay_packet_size: 1500,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: client_cert_pem.clone(),
                    private_key: client_key_pem.clone(),
                },
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
    assert_eq!(reply, b"pong-tuic-require-any");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_tuic_listener_with_request_client_auth_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-tuic-request").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let trusted_ca = rcgen::generate_simple_self_signed(vec!["trusted.local".into()]).unwrap();
    let trusted_ca_pem = trusted_ca.cert.pem();

    let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-tuic-request");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: request
    client-auth-cert: |
{trusted_ca_pem}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
            trusted_ca_pem = indent_block(trusted_ca_pem.trim_end(), 6),
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
    let tuic_addr = find_listener_addr(&app, "edge-tuic", "tuic");

    let plan = TransportPlan {
        requested: "edge-tuic".into(),
        selected_path: vec!["edge-tuic".into()],
        leaf_name: "edge-tuic".into(),
        hops: vec![TransportHop {
            name: "edge-tuic".into(),
            action: TransportAction::TuicConnect {
                proxy: TransportTarget::new("127.0.0.1", tuic_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                password: "secret".into(),
                token: String::new(),
                udp: false,
                sni: "localhost".into(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
                alpn: vec!["h3".into()],
                disable_sni: false,
                request_timeout_ms: 8000,
                heartbeat_interval_ms: 10000,
                congestion_controller: String::new(),
                max_open_streams: 100,
                max_udp_relay_packet_size: 1500,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: client_cert_pem.clone(),
                    private_key: client_key_pem.clone(),
                },
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
    assert_eq!(reply, b"pong-tuic-request");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn tuic_listener_verify_if_given_rejects_untrusted_client_cert() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let trusted_ca = rcgen::generate_simple_self_signed(vec!["trusted.local".into()]).unwrap();
    let trusted_ca_pem = trusted_ca.cert.pem();

    let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-tuic-verify-if-given");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: verify-if-given
    client-auth-cert: |
{trusted_ca_pem}
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
            cert_pem = indent_block(cert_pem.trim_end(), 6),
            key_pem = indent_block(key_pem.trim_end(), 6),
            trusted_ca_pem = indent_block(trusted_ca_pem.trim_end(), 6),
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
    let tuic_addr = find_listener_addr(&app, "edge-tuic", "tuic");

    let plan = TransportPlan {
        requested: "edge-tuic".into(),
        selected_path: vec!["edge-tuic".into()],
        leaf_name: "edge-tuic".into(),
        hops: vec![TransportHop {
            name: "edge-tuic".into(),
            action: TransportAction::TuicConnect {
                proxy: TransportTarget::new("127.0.0.1", tuic_addr.port()),
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                password: "secret".into(),
                token: String::new(),
                udp: false,
                sni: "localhost".into(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
                alpn: vec!["h3".into()],
                disable_sni: false,
                request_timeout_ms: 8000,
                heartbeat_interval_ms: 10000,
                congestion_controller: String::new(),
                max_open_streams: 100,
                max_udp_relay_packet_size: 1500,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: client_cert_pem.clone(),
                    private_key: client_key_pem.clone(),
                },
                socket: SocketOptions::default(),
                target: TransportTarget::new("127.0.0.1", 80),
            },
        }],
    };
    let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
    let message = match executor.run_plan(&plan) {
        Ok(_) => panic!("expected verify-if-given listener to reject untrusted client cert"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("certificate")
            || message.contains("alert")
            || message.contains("tls")
            || message.contains("closed")
            || message.contains("connection lost"),
        "{message}"
    );

    app.shutdown();
}

#[test]
fn start_serves_tuic_udp_listener_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-tuic-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
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
    let tuic_addr = find_listener_addr(&app, "edge-tuic", "tuic");

    let mut stream = open_tuic_udp_stream(
        &TransportTarget::new("127.0.0.1", tuic_addr.port()),
        &mihomo_transport::TuicUdpOptions {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            password: "secret".into(),
            token: String::new(),
            sni: "localhost".into(),
            certificate: String::new(),
            private_key: String::new(),
            alpn: vec!["h3".into()],
            disable_sni: false,
            request_timeout_ms: 8000,
            heartbeat_interval_ms: 10000,
            congestion_controller: String::new(),
            max_open_streams: 100,
            max_udp_relay_packet_size: 1500,
            skip_cert_verify: true,
        },
    )
    .unwrap();
    write_tuic_udp_packet(&mut *stream, target, b"ping-tuic-udp").unwrap();

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"ping-tuic-udp");
    upstream.send_to(b"pong-tuic-udp", from).unwrap();

    let (source, payload) = read_tuic_udp_packet(&mut *stream).unwrap();
    assert_eq!(source, target);
    assert_eq!(payload, b"pong-tuic-udp".to_vec());

    app.shutdown();
}
