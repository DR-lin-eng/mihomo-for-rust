use super::*;

#[test]
fn start_serves_tunnel_udp_with_tuic_over_outer_socks5_udp_associate() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let outer_socks = spawn_socks5_udp_associate_proxy();
    let outer_socks_addr = outer_socks.addr;
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_port = upstream.local_addr().unwrap().port();
    let tuic_bind = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tuic_port = tuic_bind.local_addr().unwrap().port();
    drop(tuic_bind);

    let temp = unique_temp_dir("mihomo-app-tuic-udp-over-outer-socks5");
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
    proxy: edge-tuic
    target: 127.0.0.1:{target_port}
  - type: tuic
    name: edge-tuic-in
    listen: 127.0.0.1
    port: "{tuic_port}"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
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
  - type: tuic
    name: edge-tuic
    server: 127.0.0.1
    port: {tuic_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
    sni: localhost
    alpn: [h3]
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - DST-PORT,{tuic_port},DIRECT
  - DST-PORT,{target_port},DIRECT
  - MATCH,edge-tuic
"#,
            target_port = target_port,
            tuic_port = tuic_port,
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
    upstream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    client.send_to(b"ping-tuic-outer-socks", tunnel_addr).unwrap();

    let mut buf = [0_u8; 2048];
    let (read, from) = upstream.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"ping-tuic-outer-socks");
    upstream.send_to(b"pong-tuic-outer-socks", from).unwrap();

    let mut reply = [0_u8; 2048];
    let (reply_read, _) = client.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..reply_read], b"pong-tuic-outer-socks");

    app.shutdown();
    outer_socks.shutdown();
}

#[test]
fn start_serves_tunnel_udp_with_wireguard_over_outer_socks5_udp_associate() {
    let wg_server = TestWireGuardServer::start();
    let outer_socks = spawn_socks5_udp_associate_proxy();
    let outer_socks_addr = outer_socks.addr;
    let temp = unique_temp_dir("mihomo-app-wireguard-udp-over-outer-socks5");
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
    proxy: edge-wg
    target: 100.64.0.1:5353
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: {outer_port}
    udp: true
  - type: wireguard
    name: edge-wg
    server: 127.0.0.1
    port: {wg_port}
    private-key: {client_private_key}
    public-key: {server_public_key}
    ip: 100.64.0.2/32
    allowed-ips:
      - 100.64.0.0/24
    dialer-proxy: outer-socks
rules:
  - DST-PORT,{outer_port},DIRECT
  - MATCH,edge-wg
"#,
            outer_port = outer_socks_addr.port(),
            wg_port = wg_server.addr.port(),
            client_private_key = wg_server.client_private_key,
            server_public_key = wg_server.server_public_key,
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
    client.send_to(b"via-wireguard", tunnel_addr).unwrap();

    let mut reply = [0_u8; 2048];
    let (reply_read, _) = client.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..reply_read], b"wireguard-ok");

    app.shutdown();
    wg_server.shutdown();
    outer_socks.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_wireguard_over_outer_socks5_udp_associate() {
    let wg_server = TestWireGuardServer::start();
    let outer_socks = spawn_socks5_udp_associate_proxy();
    let outer_socks_addr = outer_socks.addr;
    let temp = unique_temp_dir("mihomo-app-wireguard-tcp-over-outer-socks5");
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
  - type: wireguard
    name: relay
    server: 127.0.0.1
    port: {wg_port}
    private-key: {client_private_key}
    public-key: {server_public_key}
    ip: 100.64.0.2/32
    allowed-ips:
      - 100.64.0.0/24
    dialer-proxy: outer-socks
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 100.64.0.1:8080
rules:
  - DST-PORT,{outer_port},DIRECT
  - MATCH,relay
"#,
            outer_port = outer_socks_addr.port(),
            wg_port = wg_server.addr.port(),
            client_private_key = wg_server.client_private_key,
            server_public_key = wg_server.server_public_key,
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
    if let Err(err) = client.read_to_end(&mut reply) {
        panic!("wireguard outer tcp read failed: {err}");
    }
    assert_eq!(reply, b"pong-wireguard");

    app.shutdown();
    wg_server.shutdown();
    outer_socks.shutdown();
}

#[test]
fn start_serves_tunnel_udp_with_hysteria_over_outer_socks5_udp_associate() {
    let hysteria_server = TestHysteriaServer::start("secret");
    let outer_socks = spawn_socks5_udp_associate_proxy();
    let outer_socks_addr = outer_socks.addr;

    let temp = unique_temp_dir("mihomo-app-hysteria-udp-over-outer-socks5");
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
    proxy: edge-hy
    target: 127.0.0.1:5353
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: {outer_port}
    udp: true
  - type: hysteria
    name: edge-hy
    server: 127.0.0.1
    port: {hy_port}
    auth-str: secret
    sni: localhost
    skip-cert-verify: true
    up: 10 Mbps
    down: 50 Mbps
    dialer-proxy: outer-socks
rules:
  - MATCH,edge-hy
"#,
            outer_port = outer_socks_addr.port(),
            hy_port = hysteria_server.addr.port(),
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
    client.send_to(b"via-hysteria", tunnel_addr).unwrap();

    let mut reply = [0_u8; 2048];
    let (reply_read, _) = client.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..reply_read], b"hysteria-ok");

    app.shutdown();
    outer_socks.shutdown();
    hysteria_server.shutdown();
}
