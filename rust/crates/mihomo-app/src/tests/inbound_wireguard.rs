use super::*;

#[test]
fn start_serves_custom_tunnel_listener_with_wireguard_proxy_end_to_end() {
    let wg_server = TestWireGuardServer::start();
    let temp = unique_temp_dir("mihomo-app-tunnel-wireguard");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: wireguard
    name: relay
    server: 127.0.0.1
    port: {wg_port}
    private-key: {client_private_key}
    public-key: {server_public_key}
    ip: 100.64.0.2/32
    persistent-keepalive: 15
    allowed-ips:
      - 100.64.0.0/24
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 100.64.0.1:8080
"#,
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
        panic!("wireguard tcp read failed: {err}");
    }
    assert_eq!(reply, b"pong-wireguard");

    wg_server.shutdown();
    app.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_wireguard_proxy_resolves_localhost_endpoint() {
    let wg_server = TestWireGuardServer::start();
    let temp = unique_temp_dir("mihomo-app-tunnel-wireguard-localhost");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: wireguard
    name: relay
    server: localhost
    port: {wg_port}
    private-key: {client_private_key}
    public-key: {server_public_key}
    ip: 100.64.0.2/32
    persistent-keepalive: 15
    allowed-ips:
      - 100.64.0.0/24
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 100.64.0.1:8080
"#,
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
    let reply = run_tunnel_roundtrip(tunnel_addr, b"ping");
    assert_eq!(reply, b"pong-wireguard");

    wg_server.shutdown();
    app.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_wireguard_multi_peer_proxy_end_to_end() {
    let wg_server = TestWireGuardServer::start();
    let temp = unique_temp_dir("mihomo-app-tunnel-wireguard-multi-peer");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: wireguard
    name: relay
    private-key: {client_private_key}
    ip: 100.64.0.2/32
    peers:
      - server: 127.0.0.1
        port: {wg_port}
        public-key: {server_public_key}
        persistent-keepalive: 15
        allowed-ips:
          - 100.64.0.0/24
      - server: 127.0.0.1
        port: 9
        public-key: {server_public_key}
        allowed-ips:
          - 10.0.0.0/8
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 100.64.0.1:8080
"#,
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
        panic!("wireguard multi-peer tcp read failed: {err}");
    }
    assert_eq!(reply, b"pong-wireguard");

    wg_server.shutdown();
    app.shutdown();
}

#[test]
fn start_serves_custom_tunnel_listener_with_wireguard_multi_peer_routes_second_peer_tcp() {
    let wg_server = TestWireGuardMultiPeerServer::start();
    let temp = unique_temp_dir("mihomo-app-tunnel-wireguard-multi-peer-second");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: wireguard
    name: relay
    private-key: {client_private_key}
    ip: 100.64.0.2/32
    peers:
      - server: 127.0.0.1
        port: {primary_port}
        public-key: {primary_public_key}
        persistent-keepalive: 15
        allowed-ips:
          - 100.64.0.0/24
      - server: 127.0.0.1
        port: {secondary_port}
        public-key: {secondary_public_key}
        persistent-keepalive: 15
        allowed-ips:
          - 100.65.0.0/24
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 100.65.0.1:8080
"#,
            client_private_key = wg_server.client_private_key,
            primary_port = wg_server.primary_addr.port(),
            primary_public_key = wg_server.primary_public_key,
            secondary_port = wg_server.secondary_addr.port(),
            secondary_public_key = wg_server.secondary_public_key,
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

    let reply = run_tunnel_roundtrip(tunnel_addr, b"ping");
    assert_eq!(reply, b"pong-wireguard-b");

    wg_server.shutdown();
    app.shutdown();
}

#[test]
fn tunnel_udp_respects_wireguard_multi_peer_second_outbound_selection() {
    let wg_server = TestWireGuardMultiPeerServer::start();

    let temp = unique_temp_dir("mihomo-app-udp-outbound-wireguard-multi-peer-second");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: wireguard
    name: proxy-wg
    private-key: {client_private_key}
    ip: 100.64.0.2/32
    peers:
      - server: 127.0.0.1
        port: {primary_port}
        public-key: {primary_public_key}
        persistent-keepalive: 15
        allowed-ips:
          - 100.64.0.0/24
      - server: 127.0.0.1
        port: {secondary_port}
        public-key: {secondary_public_key}
        persistent-keepalive: 15
        allowed-ips:
          - 100.65.0.0/24
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-wg
    target: 100.65.0.1:5353
"#,
            client_private_key = wg_server.client_private_key,
            primary_port = wg_server.primary_addr.port(),
            primary_public_key = wg_server.primary_public_key,
            secondary_port = wg_server.secondary_addr.port(),
            secondary_public_key = wg_server.secondary_public_key,
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
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    client.send_to(b"via-wireguard", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"wireguard-b-ok");

    wg_server.shutdown();
    app.shutdown();
}

#[test]
fn tunnel_udp_resolves_domain_target_via_wireguard_remote_dns() {
    let wg_server = TestWireGuardServer::start();
    let temp = unique_temp_dir("mihomo-app-udp-outbound-wireguard-remote-dns");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: wireguard
    name: proxy-wg
    server: 127.0.0.1
    port: {wg_port}
    private-key: {client_private_key}
    public-key: {server_public_key}
    ip: 100.64.0.2/32
    persistent-keepalive: 15
    allowed-ips:
      - 100.64.0.0/24
    remote-dns-resolve: true
    dns: [udp://100.64.0.1:5353]
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-wg
    target: edge.example.com:5353
"#,
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
    let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"via-wireguard", listener_addr).unwrap();
    let mut buf = [0_u8; 2048];
    let (read, _) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"wireguard-ok");

    wg_server.shutdown();
    app.shutdown();
}

#[test]
#[ignore="requires Linux CAP_NET_ADMIN/CAP_NET_RAW for SO_MARK; run separately"]
fn ebpf_marked_wireguard_tcp_and_udp_remain_usable(){
 struct Reset;
 impl Drop for Reset{fn drop(&mut self){mihomo_transport::clear_default_routing_mark();}}
 mihomo_transport::set_default_routing_mark(0x636c746d);
 let _reset=Reset;
 start_serves_custom_tunnel_listener_with_wireguard_proxy_end_to_end();
 tunnel_udp_resolves_domain_target_via_wireguard_remote_dns();
}
