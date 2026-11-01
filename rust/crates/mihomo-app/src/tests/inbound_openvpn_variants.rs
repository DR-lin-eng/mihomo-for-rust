use super::*;

#[test]
fn start_serves_custom_tunnel_listener_with_openvpn_client_cert_proxy_end_to_end() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let temp = unique_temp_dir("mihomo-app-tunnel-openvpn-client-cert");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: openvpn
    name: relay
    server: 127.0.0.1
    port: {}
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 8.8.8.8:443
"#,
            ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
    let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

    let mut client = TcpStream::connect(tunnel_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong");

    app.shutdown();
    ovpn_server.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_openvpn_tcp_transport_client_cert_proxy_end_to_end() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_tcp_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let temp = unique_temp_dir("mihomo-app-tunnel-openvpn-tcp-client-cert");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: openvpn
    name: relay
    server: 127.0.0.1
    port: {}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 8.8.8.8:443
"#,
            ovpn_server.addr().port(),
            ca = ovpn_server
                .ca_pem()
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
    let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

    let mut client = TcpStream::connect(tunnel_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong");

    app.shutdown();
    ovpn_server.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_openvpn_tcp_transport_client_cert_over_http_dialer_proxy_end_to_end() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_tcp_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let ovpn_addr = ovpn_server.addr();
    let ovpn_port = ovpn_addr.port();
    let ca_pem = ovpn_server.ca_pem().to_owned();
    let tls_crypt_pem = ovpn_server.tls_crypt_pem().to_owned();

    let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer_http_addr = outer_http.local_addr().unwrap();
    let outer_worker = thread::spawn(move || {
        let (mut control, _) = outer_http.accept().unwrap();
        control.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        control.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
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
        upstream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        upstream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        if !tail.is_empty() {
            upstream.write_all(&tail).unwrap();
            upstream.flush().unwrap();
        }
        relay_test_tcp_bidirectional(control, upstream);
    });

    let temp = unique_temp_dir("mihomo-app-tunnel-openvpn-tcp-client-cert-http-dialer");
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
    name: relay
    server: 127.0.0.1
    port: {ovpn_port}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 8.8.8.8:443
"#,
            outer_port = outer_http_addr.port(),
            ovpn_port = ovpn_port,
            ca = ca_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
    let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

    let mut client = TcpStream::connect(tunnel_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong");

    drop(client);
    app.shutdown();
    ovpn_server.shutdown();
    outer_worker.join().unwrap();
}

#[test]
fn start_serves_custom_tunnel_listener_with_openvpn_tcp_transport_client_cert_over_socks5_http_dialer_proxy_chain_end_to_end() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_tcp_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let ovpn_addr = ovpn_server.addr();
    let ovpn_port = ovpn_addr.port();
    let ca_pem = ovpn_server.ca_pem().to_owned();
    let tls_crypt_pem = ovpn_server.tls_crypt_pem().to_owned();

    let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let middle_http_addr = middle_http.local_addr().unwrap();
    let middle_worker = thread::spawn(move || {
        let (mut control, _) = middle_http.accept().unwrap();
        control.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        control.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
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
        upstream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        upstream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
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
        upstream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        upstream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        relay_test_tcp_bidirectional(control, upstream);
    });

    let temp = unique_temp_dir("mihomo-app-tunnel-openvpn-tcp-client-cert-socks-http-dialer");
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
    name: relay
    server: 127.0.0.1
    port: {ovpn_port}
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
{ca}
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 8.8.8.8:443
"#,
            outer_port = outer_socks_addr.port(),
            middle_port = middle_http_addr.port(),
            ovpn_port = ovpn_port,
            ca = ca_pem
                .lines()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
    let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

    let mut client = TcpStream::connect(tunnel_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"pong");

    drop(client);
    app.shutdown();
    ovpn_server.shutdown();
    middle_worker.join().unwrap();
    outer_worker.join().unwrap();
}

#[test]
fn tunnel_udp_roundtrips_over_openvpn_client_cert_local_test_server() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-client-cert");
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
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
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
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
fn tunnel_udp_roundtrips_over_openvpn_tcp_transport_client_cert_local_test_server() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_tcp_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-tcp-client-cert");
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
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
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
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
fn tunnel_udp_roundtrips_over_openvpn_tcp_transport_client_cert_with_http_dialer_proxy() {
    let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let client_cert_pem = client_cert.cert.pem();
    let client_key_pem = client_cert.key_pair.serialize_pem();
    let ovpn_server =
        OpenVpnTestServer::start_tcp_with_client_auth(client_cert.cert.der().to_vec()).unwrap();
    let ovpn_addr = ovpn_server.addr();
    let ovpn_port = ovpn_addr.port();
    let ca_pem = ovpn_server.ca_pem().to_owned();
    let tls_crypt_pem = ovpn_server.tls_crypt_pem().to_owned();

    let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer_http_addr = outer_http.local_addr().unwrap();
    let outer_worker = thread::spawn(move || {
        let (mut control, _) = outer_http.accept().unwrap();
        control.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        control.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
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
        upstream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        upstream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        if !tail.is_empty() {
            upstream.write_all(&tail).unwrap();
            upstream.flush().unwrap();
        }
        relay_test_tcp_bidirectional(control, upstream);
    });

    let temp = unique_temp_dir("mihomo-app-udp-outbound-openvpn-tcp-client-cert-http-dialer");
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
    cert: |
{client_cert_pem}
    key: |
{client_key_pem}
    tls-crypt: |
{tls_crypt}
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
            client_cert_pem = indent_block(client_cert_pem.trim_end(), 6),
            client_key_pem = indent_block(client_key_pem.trim_end(), 6),
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
