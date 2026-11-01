use super::*;

#[test]
fn start_serves_trojan_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = Box::new(TcpStream::connect(trojan_addr).unwrap());
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_ws_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-ws-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-ws");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: ws
    ws-opts:
      path: /tr
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_websocket_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::WebsocketOptions {
            path: "/tr".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-ws-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_http_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-http-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-http");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: http
    http-opts:
      path: [/tr]
      host: [localhost]
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_http_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::HttpStreamOptions {
            method: "GET".into(),
            host: vec!["localhost".into()],
            path: vec!["/tr".into()],
            headers: BTreeMap::new(),
        },
    );
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-http-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_grpc_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-grpc-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-grpc");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: grpc
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_grpc_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-grpc-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_h2_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-h2-in").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-h2");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: h2
    h2-opts:
      host: [localhost]
      path: /trh2
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
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
            path: "/trh2".into(),
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-h2-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_xhttp_network_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-xhttp-in").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-xhttp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /trx
      host: localhost
      mode: stream-one
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &["h2".into()],
        &mihomo_transport::XHttpOptions {
            path: "/trx".into(),
            host: "localhost".into(),
            mode: "stream-one".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-xhttp-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_xhttp_stream_up_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-xhttp-stream-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-xhttp-stream-up");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /trx
      host: localhost
      mode: stream-up
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &["h2".into()],
        &mihomo_transport::XHttpOptions {
            path: "/trx".into(),
            host: "localhost".into(),
            mode: "stream-up".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-xhttp-stream-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_xhttp_packet_up_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-xhttp-packet-up").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-xhttp-packet-up");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /trx
      host: localhost
      mode: packet-up
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &["h2".into()],
        &mihomo_transport::XHttpOptions {
            path: "/trx".into(),
            host: "localhost".into(),
            mode: "packet-up".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-xhttp-packet-up");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_ss_option_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-ss-in").unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-ss-option");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    ss-option:
      enabled: true
      method: aes-128-gcm
      password: inner
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_tls_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        TransportTarget::new("127.0.0.1", trojan_addr.port()),
        &mihomo_transport::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &["h2".into(), "http/1.1".into()],
    )
    .unwrap();
    let stream =
        mihomo_transport::accept_shadowsocks_test_stream(stream, "aes-128-gcm", "inner")
            .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-ss-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_ws_network_and_ss_option_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-ws-ss-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-ws-ss-option");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: ws
    ws-opts:
      path: /tr
    ss-option:
      enabled: true
      method: aes-128-gcm
      password: inner
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream = mihomo_transport::wrap_websocket_proxy_stream(
        Box::new(TcpStream::connect(trojan_addr).unwrap()),
        mihomo_transport::TransportTarget::new(trojan_addr.ip().to_string(), trojan_addr.port()),
        &mihomo_transport::WebsocketOptions {
            path: "/tr".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let stream =
        mihomo_transport::accept_shadowsocks_test_stream(stream, "aes-128-gcm", "inner")
            .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-ws-ss-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_ss_option_without_tls_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-trojan-ss-notls").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-ss-option-notls");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    ss-option:
      enabled: true
      method: aes-128-gcm
      password: inner
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let stream =
        mihomo_transport::accept_shadowsocks_test_stream(
            Box::new(TcpStream::connect(trojan_addr).unwrap()),
            "aes-128-gcm",
            "inner",
        )
        .unwrap();
    let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-trojan-ss-notls");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_anytls_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-anytls-in").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-anytls");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: anytls
    name: edge-anytls
    listen: 127.0.0.1
    port: "0"
    password: secret
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
    let anytls_addr = find_listener_addr(&app, "edge-anytls", "anytls");

    let plan = TransportPlan {
        requested: "edge-anytls".into(),
        selected_path: vec!["edge-anytls".into()],
        leaf_name: "edge-anytls".into(),
        hops: vec![TransportHop {
            name: "edge-anytls".into(),
            action: TransportAction::AnyTlsConnect {
                proxy: TransportTarget::new("127.0.0.1", anytls_addr.port()),
                password: "secret".into(),
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "localhost".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
                alpn: vec!["h2".into(), "http/1.1".into()],
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
    assert_eq!(reply, b"pong-anytls-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_anytls_listener_udp_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-anytls-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: anytls
    name: edge-anytls
    listen: 127.0.0.1
    port: "0"
    password: secret
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
    let anytls_addr = find_listener_addr(&app, "edge-anytls", "anytls");

    let worker = thread::spawn(move || {
        let stream = std::net::TcpStream::connect(anytls_addr).unwrap();
        let stream = wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", anytls_addr.port()),
            &TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into(), "http/1.1".into()],
        )
        .unwrap();
        let mut stream = open_anytls_udp_stream(Box::new(stream), "secret", target).unwrap();
        write_anytls_udp_packet(&mut *stream, target, b"udp-ping-anytls-in").unwrap();
        let (packet_target, payload) = read_anytls_udp_packet(&mut *stream).unwrap();
        assert_eq!(packet_target, target);
        assert_eq!(payload, b"udp-pong-anytls-in".to_vec());
    });

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"udp-ping-anytls-in");
    upstream.send_to(b"udp-pong-anytls-in", from).unwrap();

    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_anytls_listener_udp_connect_mode_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-anytls-udp-connect");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: anytls
    name: edge-anytls
    listen: 127.0.0.1
    port: "0"
    password: secret
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
    let anytls_addr = find_listener_addr(&app, "edge-anytls", "anytls");

    let worker = thread::spawn(move || {
        let stream = std::net::TcpStream::connect(anytls_addr).unwrap();
        let mut stream = wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", anytls_addr.port()),
            &TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into(), "http/1.1".into()],
        )
        .unwrap();
        stream = mihomo_transport::open_anytls_tcp_stream_for_tests(
            stream,
            "secret",
            &TransportTarget::new(mihomo_transport::ANYTLS_UOT_MAGIC_HOST, 0),
        )
        .unwrap();

        let mut request = Vec::new();
        request.push(0x01);
        request.push(0x00);
        request.extend_from_slice(&target.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&request).unwrap();

        let payload = b"udp-connect-anytls-in";
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(payload).unwrap();
        stream.flush().unwrap();

        let mut len = [0_u8; 2];
        stream.read_exact(&mut len).unwrap();
        let length = u16::from_be_bytes(len) as usize;
        let mut response = vec![0_u8; length];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(response, b"udp-connect-anytls-ok".to_vec());
    });

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"udp-connect-anytls-in");
    upstream.send_to(b"udp-connect-anytls-ok", from).unwrap();

    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-trojan-udp");
        upstream.send_to(b"pong-trojan-udp", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(trojan_addr).unwrap()),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into(), "http/1.1".into()],
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &mihomo_transport::TrojanShadowsocksOptions::default(),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .unwrap_or_else(|err| panic!("open_trojan_udp_stream failed: {err:?}"));
        write_trojan_udp_packet(&mut *stream, upstream_addr, b"ping-trojan-udp").unwrap();
        let (source, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, upstream_addr);
        assert_eq!(payload, b"pong-trojan-udp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_udp_listener_with_ss_option_without_tls_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-trojan-udp-ss");
        upstream.send_to(b"pong-trojan-udp-ss", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-udp-ss-option-notls");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    ss-option:
      enabled: true
      method: aes-128-gcm
      password: inner
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::accept_shadowsocks_test_stream(
            Box::new(TcpStream::connect(trojan_addr).unwrap()),
            "aes-128-gcm",
            "inner",
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &mihomo_transport::TrojanShadowsocksOptions::default(),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .unwrap_or_else(|err| panic!("open_trojan_udp_stream failed: {err:?}"));
        write_trojan_udp_packet(&mut *stream, upstream_addr, b"ping-trojan-udp-ss").unwrap();
        let (source, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, upstream_addr);
        assert_eq!(payload, b"pong-trojan-udp-ss");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_xhttp_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-trojan-xhttp-udp");
        upstream.send_to(b"pong-trojan-xhttp-udp", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-xhttp-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /trxu
      host: localhost
      mode: stream-one
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(trojan_addr).unwrap()),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into()],
            &mihomo_transport::XHttpOptions {
                path: "/trxu".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &mihomo_transport::TrojanShadowsocksOptions::default(),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .unwrap_or_else(|err| panic!("open_trojan_udp_stream failed: {err:?}"));
        write_trojan_udp_packet(&mut *stream, upstream_addr, b"ping-trojan-xhttp-udp").unwrap();
        let (source, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, upstream_addr);
        assert_eq!(payload, b"pong-trojan-xhttp-udp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_xhttp_stream_up_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-trojan-xhttp-stream-up-udp");
        upstream.send_to(b"pong-trojan-xhttp-stream-up-udp", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-xhttp-stream-up-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /trxsu
      host: localhost
      mode: stream-up
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(trojan_addr).unwrap()),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into()],
            &mihomo_transport::XHttpOptions {
                path: "/trxsu".into(),
                host: "localhost".into(),
                mode: "stream-up".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &mihomo_transport::TrojanShadowsocksOptions::default(),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .unwrap_or_else(|err| panic!("open_trojan_udp_stream failed: {err:?}"));
        write_trojan_udp_packet(
            &mut *stream,
            upstream_addr,
            b"ping-trojan-xhttp-stream-up-udp",
        )
        .unwrap();
        let (source, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, upstream_addr);
        assert_eq!(payload, b"pong-trojan-xhttp-stream-up-udp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_xhttp_packet_up_udp_listener_end_to_end() {
    let _guard = sudoku_udp_test_guard();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-trojan-xhttp-packet-up-udp");
        upstream.send_to(b"pong-trojan-xhttp-packet-up-udp", from).unwrap();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-xhttp-packet-up-udp");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /trxpu
      host: localhost
      mode: packet-up
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    let worker = thread::spawn(move || {
        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(trojan_addr).unwrap()),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into()],
            &mihomo_transport::XHttpOptions {
                path: "/trxpu".into(),
                host: "localhost".into(),
                mode: "packet-up".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &mihomo_transport::TrojanShadowsocksOptions::default(),
            TransportTarget::new("127.0.0.1", trojan_addr.port()),
            TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .unwrap_or_else(|err| panic!("open_trojan_udp_stream failed: {err:?}"));
        write_trojan_udp_packet(
            &mut *stream,
            upstream_addr,
            b"ping-trojan-xhttp-packet-up-udp",
        )
        .unwrap();
        let (source, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, upstream_addr);
        assert_eq!(payload, b"pong-trojan-xhttp-packet-up-udp");
    });

    upstream_worker.join().unwrap();
    worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_trojan_listener_with_users_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-users").unwrap();
        }
    });

    let temp = unique_temp_dir("mihomo-app-inbound-trojan-users");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    users:
      - username: alice
        password: secret-a
      - username: bob
        password: secret-b
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
    let trojan_addr = find_listener_addr(&app, "edge-trojan", "trojan");

    for password in ["secret-a", "secret-b"] {
        let stream = Box::new(TcpStream::connect(trojan_addr).unwrap());
        let mut client = mihomo_transport::open_trojan_tcp_stream_for_tests(
            stream,
            password,
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-trojan-users");
    }

    let stream = Box::new(TcpStream::connect(trojan_addr).unwrap());
    let mut rejected = mihomo_transport::open_trojan_tcp_stream_for_tests(
        stream,
        "wrong-password",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    rejected.write_all(b"ping").unwrap();
    rejected.shutdown_write().unwrap();
    let mut reply = Vec::new();
    // A wrong password closes the stream without any upstream data: the read
    // must end with EOF (clean close) or an error (reset), never with payload.
    let rejected_read = rejected.read_to_end(&mut reply);
    assert!(
        rejected_read.is_err() || reply.is_empty(),
        "unexpected password must be rejected without a reply: {reply:?}"
    );

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_anytls_listener_with_users_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-anytls-users").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        }
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let temp = unique_temp_dir("mihomo-app-inbound-anytls-users");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: anytls
    name: edge-anytls
    listen: 127.0.0.1
    port: "0"
    users:
      username1: secret-one
      username2: secret-two
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
    let anytls_addr = find_listener_addr(&app, "edge-anytls", "anytls");

    for password in ["secret-one", "secret-two"] {
        let plan = TransportPlan {
            requested: "edge-anytls".into(),
            selected_path: vec!["edge-anytls".into()],
            leaf_name: "edge-anytls".into(),
            hops: vec![TransportHop {
                name: "edge-anytls".into(),
                action: TransportAction::AnyTlsConnect {
                    proxy: TransportTarget::new("127.0.0.1", anytls_addr.port()),
                    password: password.into(),
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
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
        assert_eq!(reply, b"pong-anytls-users");
    }

    upstream_worker.join().unwrap();
    app.shutdown();
}
