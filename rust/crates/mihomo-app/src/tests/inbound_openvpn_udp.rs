use super::*;

#[test]
fn tunnel_udp_roundtrips_over_openvpn_local_test_server() {
    let ovpn_server = OpenVpnTestServer::start().unwrap();
    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {}
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ovpn
    target: 8.8.8.8:53
"#,
            ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = ovpn_server
                .tls_crypt_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-openvpn", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"openvpn-ok");

    app.shutdown();
    ovpn_server.shutdown();
}

#[test]
fn tunnel_udp_roundtrips_over_openvpn_udp_transport_with_outer_socks5() {
    let ovpn_server = OpenVpnTestServer::start().unwrap();
    let outer_socks = spawn_socks5_udp_associate_proxy();
    let outer_socks_addr = outer_socks.addr;
    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-udp-outer-socks");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: {outer_port}
    udp: true
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {ovpn_port}
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
    dialer-proxy: outer-socks
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ovpn
    target: 8.8.8.8:53
rules:
  - DST-PORT,{outer_port},DIRECT
  - MATCH,proxy-ovpn
"#,
            outer_port = outer_socks_addr.port(),
            ovpn_port = ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = ovpn_server
                .tls_crypt_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-openvpn", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"openvpn-ok");

    drop(client);
    app.shutdown();
    ovpn_server.shutdown();
    outer_socks.shutdown();
}

#[test]
fn tunnel_udp_roundtrips_over_openvpn_tcp_transport_local_test_server() {
    let ovpn_server = OpenVpnTestServer::start_tcp().unwrap();
    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-tcp-transport");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ovpn
    target: 8.8.8.8:53
"#,
            ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = ovpn_server
                .tls_crypt_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-openvpn", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"openvpn-ok");

    app.shutdown();
    ovpn_server.shutdown();
}

#[test]
fn tunnel_udp_roundtrips_over_openvpn_tcp_transport_with_http_dialer_proxy() {
    let ovpn_server = OpenVpnTestServer::start_tcp().unwrap();
    let ovpn_addr = ovpn_server.addr();
    let ovpn_port = ovpn_addr.port();
    let ca_pem = ovpn_server.ca_pem().to_owned();
    let tls_crypt_pem = ovpn_server.tls_crypt_pem().to_owned();
    let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer_http_addr = outer_http.local_addr().unwrap();

    let outer_worker = thread::spawn(move || {
        let (mut control, _) = outer_http.accept().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
        assert!(request.starts_with(&format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
            ovpn_port
        )));
        control
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        control.flush().unwrap();

        let mut upstream = TcpStream::connect(ovpn_addr).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if !tail.is_empty() {
            upstream.write_all(&tail).unwrap();
            upstream.flush().unwrap();
        }
        relay_test_tcp_bidirectional(control, upstream);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-tcp-http-dialer");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {ovpn_port}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    udp: true
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ovpn
    target: 8.8.8.8:53
"#,
            outer_port = outer_http_addr.port(),
            ovpn_port = ovpn_port,
            ca = ca_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = tls_crypt_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-openvpn", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"openvpn-ok");

    drop(client);
    app.shutdown();
    ovpn_server.shutdown();
    outer_worker.join().unwrap();
}

#[test]
fn tunnel_udp_roundtrips_over_openvpn_tcp_transport_with_http_dialer_proxy_chain() {
    let ovpn_server = OpenVpnTestServer::start_tcp().unwrap();
    let ovpn_addr = ovpn_server.addr();
    let ovpn_port = ovpn_addr.port();
    let ca_pem = ovpn_server.ca_pem().to_owned();
    let tls_crypt_pem = ovpn_server.tls_crypt_pem().to_owned();

    let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let middle_http_addr = middle_http.local_addr().unwrap();
    let middle_worker = thread::spawn(move || {
        let (mut control, _) = middle_http.accept().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
        assert!(request.starts_with(&format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
            ovpn_port
        )));
        control
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        control.flush().unwrap();

        let mut upstream = TcpStream::connect(ovpn_addr).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if !tail.is_empty() {
            upstream.write_all(&tail).unwrap();
            upstream.flush().unwrap();
        }
        relay_test_tcp_bidirectional(control, upstream);
    });

    let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer_http_addr = outer_http.local_addr().unwrap();
    let outer_worker = thread::spawn(move || {
        let (mut control, _) = outer_http.accept().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
        assert!(request.starts_with(&format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
            middle_http_addr.port()
        )));
        control
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        control.flush().unwrap();

        let mut upstream = TcpStream::connect(middle_http_addr).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if !tail.is_empty() {
            upstream.write_all(&tail).unwrap();
            upstream.flush().unwrap();
        }
        relay_test_tcp_bidirectional(control, upstream);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-tcp-http-dialer-chain");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: http
    name: middle-http
    server: 127.0.0.1
    port: {middle_port}
    dialer-proxy: outer-http
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {ovpn_port}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    udp: true
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ovpn
    target: 8.8.8.8:53
"#,
            outer_port = outer_http_addr.port(),
            middle_port = middle_http_addr.port(),
            ovpn_port = ovpn_port,
            ca = ca_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = tls_crypt_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-openvpn", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"openvpn-ok");

    drop(client);
    app.shutdown();
    ovpn_server.shutdown();
    middle_worker.join().unwrap();
    outer_worker.join().unwrap();
}

#[test]
fn tunnel_udp_roundtrips_over_openvpn_tcp_transport_with_socks5_http_dialer_proxy_chain() {
    let ovpn_server = OpenVpnTestServer::start_tcp().unwrap();
    let ovpn_addr = ovpn_server.addr();
    let ovpn_port = ovpn_addr.port();
    let ca_pem = ovpn_server.ca_pem().to_owned();
    let tls_crypt_pem = ovpn_server.tls_crypt_pem().to_owned();

    let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let middle_http_addr = middle_http.local_addr().unwrap();
    let middle_worker = thread::spawn(move || {
        let (mut control, _) = middle_http.accept().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
        assert!(request.starts_with(&format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
            ovpn_port
        )));
        control
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        control.flush().unwrap();

        let mut upstream = TcpStream::connect(ovpn_addr).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if !tail.is_empty() {
            upstream.write_all(&tail).unwrap();
            upstream.flush().unwrap();
        }
        relay_test_tcp_bidirectional(control, upstream);
    });

    let outer_socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer_socks_addr = outer_socks.local_addr().unwrap();
    let outer_worker = thread::spawn(move || {
        let (mut control, _) = outer_socks.accept().unwrap();
        let target = read_socks5_connect_target(&mut control);
        assert_eq!(target.port(), middle_http_addr.port());
        write_socks5_connect_reply(&mut control, middle_http_addr);

        let upstream = TcpStream::connect(middle_http_addr).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        relay_test_tcp_bidirectional(control, upstream);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-socks-http-dialer-chain");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: {outer_port}
  - type: http
    name: middle-http
    server: 127.0.0.1
    port: {middle_port}
    dialer-proxy: outer-socks
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {ovpn_port}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    udp: true
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ovpn
    target: 8.8.8.8:53
"#,
            outer_port = outer_socks_addr.port(),
            middle_port = middle_http_addr.port(),
            ovpn_port = ovpn_port,
            ca = ca_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = tls_crypt_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-openvpn", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"openvpn-ok");

    drop(client);
    app.shutdown();
    ovpn_server.shutdown();
    middle_worker.join().unwrap();
    outer_worker.join().unwrap();
}

#[test]
fn openvpn_udp_session_route_roundtrips_over_local_test_server() {
    let ovpn_server = OpenVpnTestServer::start().unwrap();
    let temp = unique_temp_dir("mihomo-app-openvpn-udp-session-route");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {}
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
rules:
  - MATCH,proxy-ovpn
"#,
            ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = ovpn_server
                .tls_crypt_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    )
    .unwrap();

    let config_text = fs::read_to_string(temp.join("config.yaml")).unwrap();
    let document = mihomo_config::parse_runtime_config_document(&config_text).unwrap();
    let registry = build_runtime_registry(&document).unwrap();
    let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
    let mut metadata = mihomo_core::Metadata {
        host: Some("8.8.8.8".into()),
        dst_port: Some(53),
        special_proxy: "proxy-ovpn".into(),
        ..mihomo_core::Metadata::default()
    };
    let result = listener_service::exercise_openvpn_udp_route_for_tests(
        tunnel,
        &mut metadata,
        mihomo_buf::ByteWindow::freeze(b"via-openvpn".to_vec()),
        "8.8.8.8:53".parse().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(result.0, b"openvpn-ok");
    assert_eq!(result.1, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    ovpn_server.shutdown();
}

#[test]
fn openvpn_udp_session_route_resolves_domain_via_remote_dns() {
    let ovpn_server = OpenVpnTestServer::start().unwrap();
    let temp = unique_temp_dir("mihomo-app-openvpn-udp-session-route-remote-dns");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: openvpn
    name: proxy-ovpn
    server: 127.0.0.1
    port: {}
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    tls-crypt: |
{tls_crypt}
    username: demo
    password: secret
    remote-dns-resolve: true
    dns: [udp://10.8.0.1:5353]
rules:
  - MATCH,proxy-ovpn
"#,
            ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            tls_crypt = ovpn_server
                .tls_crypt_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    )
    .unwrap();

    let config_text = fs::read_to_string(temp.join("config.yaml")).unwrap();
    let document = mihomo_config::parse_runtime_config_document(&config_text).unwrap();
    let registry = build_runtime_registry(&document).unwrap();
    let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
    let mut metadata = mihomo_core::Metadata {
        host: Some("edge.example.com".into()),
        dst_port: Some(5353),
        special_proxy: "proxy-ovpn".into(),
        ..mihomo_core::Metadata::default()
    };
    let result = listener_service::exercise_openvpn_udp_route_for_tests(
        tunnel,
        &mut metadata,
        mihomo_buf::ByteWindow::freeze(b"via-openvpn".to_vec()),
        "10.8.0.1:5353".parse().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(result.0, b"openvpn-ok");
    assert_eq!(result.1, "8.8.8.8:5353".parse::<SocketAddr>().unwrap());
    ovpn_server.shutdown();
}
