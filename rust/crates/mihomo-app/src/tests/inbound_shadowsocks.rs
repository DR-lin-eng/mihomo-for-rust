use super::*;

#[test]
fn start_serves_shadowsocks_listener_end_to_end() {    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-ss-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: shadowsocks
    name: edge-ss
    listen: 127.0.0.1
    port: "0"
    cipher: aes-128-gcm
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
    let ss_addr = find_listener_addr(&app, "edge-ss", "shadowsocks");

    let mut client = mihomo_transport::open_shadowsocks_tcp_stream_for_tests(
        Box::new(TcpStream::connect(ss_addr).unwrap()),
        "aes-128-gcm",
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-ss-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_udp_listener_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-ss-udp");
        upstream.send_to(b"pong-ss-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss-udp");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: shadowsocks
    name: edge-ss
    listen: 127.0.0.1
    port: "0"
    cipher: aes-128-gcm
    password: secret
    udp: true
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
    let ss_addr = find_listener_addr(&app, "edge-ss", "shadowsocks/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let packet = encode_shadowsocks_udp_packet(
        "aes-128-gcm",
        "secret",
        upstream_addr,
        b"ping-ss-udp",
    )
    .unwrap();
    client.send_to(&packet, ss_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    let (source, payload) =
        decode_shadowsocks_udp_packet("aes-128-gcm", "secret", &buf[..read]).unwrap();
    assert_eq!(source, upstream_addr);
    assert_eq!(payload, b"pong-ss-udp".to_vec());

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_top_level_shadowsocks_config_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-top-ss").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-top-level-ss");
    fs::write(
        temp.join("config.yaml"),
        r#"
ss-config: ss://aes-128-gcm:secret@127.0.0.1:0
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
    let ss_addr = find_listener_addr(&app, "__top_level_shadowsocks__", "shadowsocks");

    let mut client = mihomo_transport::open_shadowsocks_tcp_stream_for_tests(
        Box::new(TcpStream::connect(ss_addr).unwrap()),
        "aes-128-gcm",
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-top-ss");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_listener_with_http_obfs_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-ss-obfs-http-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss-obfs-http");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: shadowsocks
    name: edge-ss
    listen: 127.0.0.1
    port: "0"
    cipher: aes-128-gcm
    password: secret
    simple-obfs:
      enable: true
      mode: http
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
    let ss_addr = find_listener_addr(&app, "edge-ss", "shadowsocks");

    let stream = mihomo_transport::open_simple_obfs_http_stream_for_tests(
        Box::new(TcpStream::connect(ss_addr).unwrap()),
        "bing.com",
        &ss_addr.port().to_string(),
    );
    let mut client = mihomo_transport::open_shadowsocks_tcp_stream_for_tests(
        stream,
        "aes-128-gcm",
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-ss-obfs-http-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_listener_with_tls_obfs_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-ss-obfs-tls-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss-obfs-tls");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: shadowsocks
    name: edge-ss
    listen: 127.0.0.1
    port: "0"
    cipher: aes-128-gcm
    password: secret
    simple-obfs:
      enable: true
      mode: tls
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
    let ss_addr = find_listener_addr(&app, "edge-ss", "shadowsocks");

    let stream = mihomo_transport::open_simple_obfs_tls_stream_for_tests(
        Box::new(TcpStream::connect(ss_addr).unwrap()),
        "bing.com",
    );
    let mut client = mihomo_transport::open_shadowsocks_tcp_stream_for_tests(
        stream,
        "aes-128-gcm",
        "secret",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-ss-obfs-tls-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_2022_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-ss2022-in").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss2022");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: shadowsocks
    name: edge-ss2022
    listen: 127.0.0.1
    port: "0"
    cipher: 2022-blake3-aes-256-gcm
    password: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
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
    let ss_addr = find_listener_addr(&app, "edge-ss2022", "shadowsocks");

    let mut client = mihomo_transport::open_shadowsocks_2022_tcp_stream_for_tests(
        Box::new(TcpStream::connect(ss_addr).unwrap()),
        "2022-blake3-aes-256-gcm",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-ss2022-in");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_2022_chacha_udp_listener_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-ss2022-udp");
        upstream.send_to(b"pong-ss2022-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss2022-chacha-udp");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: shadowsocks
    name: edge-ss2022
    listen: 127.0.0.1
    port: "0"
    cipher: 2022-blake3-chacha20-poly1305
    password: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
    udp: true
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
    let ss_addr = find_listener_addr(&app, "edge-ss2022", "shadowsocks/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let mut state = mihomo_transport::Shadowsocks2022UdpState::client();
    let target =
        mihomo_transport::TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port());
    let packet = mihomo_transport::encode_shadowsocks_2022_udp_packet(
        "2022-blake3-chacha20-poly1305",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        &mut state,
        &target,
        b"ping-ss2022-udp",
    )
    .unwrap();
    client.send_to(&packet, ss_addr).unwrap();

    let mut buf = [0_u8; 4096];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    // Decode the server→client response with the response decoder.
    let (reply_target, payload) = mihomo_transport::decode_shadowsocks_2022_udp_response(
        "2022-blake3-chacha20-poly1305",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        &buf[..read],
    )
    .unwrap();
    assert_eq!(reply_target.authority(), upstream_addr.to_string());
    assert_eq!(payload, b"pong-ss2022-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_2022_aes128_listener_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-ss2022-aes128").unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss2022-aes128");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: shadowsocks
    name: edge-ss2022
    listen: 127.0.0.1
    port: "0"
    cipher: 2022-blake3-aes-128-gcm
    password: AQIDBAUGBwgJCgsMDQ4PEA==
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
    let ss_addr = find_listener_addr(&app, "edge-ss2022", "shadowsocks");

    let mut client = mihomo_transport::open_shadowsocks_2022_tcp_stream_for_tests(
        Box::new(TcpStream::connect(ss_addr).unwrap()),
        "2022-blake3-aes-128-gcm",
        "AQIDBAUGBwgJCgsMDQ4PEA==",
        &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
    )
    .unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown_write().unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong-ss2022-aes128");

    upstream_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn tunnel_tcp_respects_shadowsocks_2022_outbound_selection() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong-ss2022-out").unwrap();
    });

    // Mock SIP022 server: accepts the app's ss2022 outbound, then relays to
    // the requested target like a real ss server would.
    let mock = TcpListener::bind("127.0.0.1:0").unwrap();
    let mock_addr = mock.local_addr().unwrap();
    let mock_worker = thread::spawn(move || {
        let (stream, _) = mock.accept().unwrap();
        let (target, mut server) = mihomo_transport::accept_shadowsocks_2022_stream(
            Box::new(stream),
            "2022-blake3-aes-256-gcm",
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        )
        .unwrap();
        assert_eq!(
            target.authority(),
            format!("127.0.0.1:{}", upstream_addr.port())
        );
        let mut payload = [0_u8; 4];
        server.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");

        let mut upstream_conn = TcpStream::connect(upstream_addr).unwrap();
        upstream_conn.write_all(&payload).unwrap();
        let mut reply = Vec::new();
        upstream_conn.read_to_end(&mut reply).unwrap();

        server.write_all(&reply).unwrap();
        server.flush().unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-ss2022-outbound");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: proxy-ss2022
    target: 127.0.0.1:{upstream_port}
proxies:
  - type: ss
    name: proxy-ss2022
    server: 127.0.0.1
    port: {mock_port}
    cipher: 2022-blake3-aes-256-gcm
    password: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
rules:
  - MATCH,proxy-ss2022
"#,
            upstream_port = upstream_addr.port(),
            mock_port = mock_addr.port(),
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
    assert_eq!(reply, b"pong-ss2022-out");

    upstream_worker.join().unwrap();
    mock_worker.join().unwrap();
    app.shutdown();
}

#[test]
fn start_serves_shadowsocks_2022_udp_listener_end_to_end() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_worker = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (read, from) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ping-ss2022-udp");
        upstream.send_to(b"pong-ss2022-udp", from).unwrap();
    });

    let temp = unique_temp_dir("mihomo-app-inbound-ss2022-udp");
    fs::write(
        temp.join("config.yaml"),
        r#"
listeners:
  - type: shadowsocks
    name: edge-ss2022
    listen: 127.0.0.1
    port: "0"
    cipher: 2022-blake3-aes-256-gcm
    password: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
    udp: true
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
    let ss_addr = find_listener_addr(&app, "edge-ss2022", "shadowsocks/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let mut state = mihomo_transport::Shadowsocks2022UdpState::client();
    let target =
        mihomo_transport::TransportTarget::new(upstream_addr.ip().to_string(), upstream_addr.port());
    let packet = mihomo_transport::encode_shadowsocks_2022_udp_packet(
        "2022-blake3-aes-256-gcm",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        &mut state,
        &target,
        b"ping-ss2022-udp",
    )
    .unwrap();
    client.send_to(&packet, ss_addr).unwrap();

    let mut buf = [0_u8; 4096];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    // Decode the server→client response with the response decoder.
    let (reply_target, payload) = mihomo_transport::decode_shadowsocks_2022_udp_response(
        "2022-blake3-aes-256-gcm",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        &buf[..read],
    )
    .unwrap();
    assert_eq!(reply_target.authority(), upstream_addr.to_string());
    assert_eq!(payload, b"pong-ss2022-udp");

    upstream_worker.join().unwrap();
    app.shutdown();
}
