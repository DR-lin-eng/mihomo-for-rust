    #[test]
    fn start_serves_custom_tunnel_listener_with_dns_outbound_tcp() {
        let temp = unique_temp_dir("mihomo-app-tcp-outbound-dns");
        fs::write(
            temp.join("config.yaml"),
            r#"
hosts:
  example.test: 1.2.3.4
dns:
  enable: true
  use-hosts: true
proxies:
  - type: dns
    name: proxy-dns
listeners:
  - type: tunnel
    name: edge-tcp
    listen: 127.0.0.1
    port: "0"
    proxy: proxy-dns
    target: 8.8.8.8:53
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
        let listener_addr = find_listener_addr(&app, "edge-tcp", "tunnel");

        let mut client = TcpStream::connect(listener_addr).unwrap();
        let query = build_dns_query_packet("example.test", 1, 0x6789);
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        client.write_all(&query).unwrap();
        client.flush().unwrap();

        let mut header = [0_u8; 2];
        client.read_exact(&mut header).unwrap();
        let length = u16::from_be_bytes(header) as usize;
        let mut response = vec![0_u8; length];
        client.read_exact(&mut response).unwrap();
        let answer = parse_first_a_answer(&response);
        assert_eq!(answer, Some("1.2.3.4".parse().unwrap()));

        app.shutdown();
    }

    #[test]
    fn tunnel_udp_resolves_socks5_proxy_host_via_dns_runtime() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-proxy-host");
            upstream.send_to(b"proxy-host-ok", from).unwrap();
        });

        let proxy_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_tcp_addr = proxy_tcp.local_addr().unwrap();
        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut control, _) = proxy_tcp.accept().unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            control.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x03, 0x00]);
            match header[3] {
                0x01 => {
                    let mut addr = [0_u8; 4];
                    control.read_exact(&mut addr).unwrap();
                }
                0x04 => {
                    let mut addr = [0_u8; 16];
                    control.read_exact(&mut addr).unwrap();
                }
                other => panic!("unexpected atyp {other}"),
            }
            let mut port = [0_u8; 2];
            control.read_exact(&mut port).unwrap();

            let reply = build_socks_udp_reply(proxy_udp_addr);
            control.write_all(&reply).unwrap();

            let mut buf = [0_u8; 2048];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) = parse_socks_udp_response(&buf[..read]);
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-proxy-host");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response = build_socks_udp_request(upstream_addr, &buf[..read]);
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-socks5-host");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
  proxy.invalid: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: socks5
    name: proxy-socks
    server: proxy.invalid
    port: {proxy_port}
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-socks
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_tcp_addr.port(),
                upstream_port = upstream_addr.port(),
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
        client.send_to(b"via-proxy-host", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"proxy-host-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_socks5_domain_relay_and_source_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-proxy-domain");
            upstream.send_to(b"proxy-domain-ok", from).unwrap();
        });

        let proxy_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_tcp_addr = proxy_tcp.local_addr().unwrap();
        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut control, _) = proxy_tcp.accept().unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            control.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x03, 0x00]);
            match header[3] {
                0x01 => {
                    let mut addr = [0_u8; 4];
                    control.read_exact(&mut addr).unwrap();
                }
                0x04 => {
                    let mut addr = [0_u8; 16];
                    control.read_exact(&mut addr).unwrap();
                }
                other => panic!("unexpected atyp {other}"),
            }
            let mut port = [0_u8; 2];
            control.read_exact(&mut port).unwrap();

            let reply = build_socks_udp_reply_with_domain("relay.invalid", proxy_udp_addr.port());
            control.write_all(&reply).unwrap();

            let mut buf = [0_u8; 2048];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) = parse_socks_udp_response(&buf[..read]);
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-proxy-domain");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                build_socks_udp_request_with_domain("upstream.test", upstream_addr.port(), &buf[..read]);
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-socks5-domain-addr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
  proxy.invalid: 127.0.0.1
  relay.invalid: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: socks5
    name: proxy-socks
    server: proxy.invalid
    port: {proxy_port}
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-socks
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_tcp_addr.port(),
                upstream_port = upstream_addr.port(),
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
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        client.send_to(b"via-proxy-domain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"proxy-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_dns_listener_for_hosts_answer() {
        let temp = unique_temp_dir("mihomo-app-dns");
        fs::write(
            temp.join("config.yaml"),
            r#"
hosts:
  example.test: 1.2.3.4
dns:
  enable: true
  listen: 127.0.0.1:0
  use-hosts: true
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
        let dns_addr = find_listener_addr(&app, "__dns__", "dns");

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let query = build_dns_query_packet("example.test", 1, 0x1234);
        client.send_to(&query, dns_addr).unwrap();
        let mut buf = [0_u8; 1500];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        let answer = parse_first_a_answer(&buf[..read]);
        assert_eq!(answer, Some("1.2.3.4".parse().unwrap()));

        app.shutdown();
    }

    #[test]
    fn controller_proxy_update_switches_runtime_tunnel_selection() {
        let upstream_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();

        let worker_a = thread::spawn(move || {
            let (mut stream, _) = upstream_a.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("CONNECT dest.test:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-a").unwrap();
        });

        let worker_b = thread::spawn(move || {
            let (mut stream, _) = upstream_b.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("CONNECT dest.test:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-b").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-selector");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller: 127.0.0.1:0
secret: top-secret
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "0"
    proxy: selector
    target: dest.test:443
proxy-groups:
  - name: selector
    type: select
    proxies: [leaf-a, leaf-b]
proxies:
  - type: http
    name: leaf-a
    server: 127.0.0.1
    port: {port_a}
  - type: http
    name: leaf-b
    server: 127.0.0.1
    port: {port_b}
"#,
                port_a = upstream_a_addr.port(),
                port_b = upstream_b_addr.port(),
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
        let tunnel_addr = find_listener_addr(&app, "edge", "tunnel");
        let controller_addr = app.controller_addr().unwrap();

        let first = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(first, b"pong-a");

        let update = send_http_request(
            controller_addr,
            "PUT",
            "/proxies/selector",
            Some("top-secret"),
            Some(br#"{"name":"leaf-b"}"#),
        );
        assert!(
            update.starts_with("HTTP/1.1 204 No Content"),
            "unexpected controller response: {update}"
        );
        let selected = send_http_request(
            controller_addr,
            "GET",
            "/proxies/selector",
            Some("top-secret"),
            None,
        );
        assert!(selected.contains(r#""now":"leaf-b""#), "{selected}");
        assert_eq!(app.runtime_tunnel.group_selected("selector").as_deref(), Some("leaf-b"));
        let traffic_after_first = send_http_request(
            controller_addr,
            "GET",
            "/traffic",
            Some("top-secret"),
            None,
        );
        assert!(traffic_after_first.contains(r#""upTotal":4"#), "{traffic_after_first}");
        assert!(traffic_after_first.contains(r#""downTotal":6"#), "{traffic_after_first}");

        let second = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(second, b"pong-b");
        let traffic_after_second = send_http_request(
            controller_addr,
            "GET",
            "/traffic",
            Some("top-secret"),
            None,
        );
        assert!(traffic_after_second.contains(r#""upTotal":8"#), "{traffic_after_second}");
        assert!(traffic_after_second.contains(r#""downTotal":12"#), "{traffic_after_second}");

        worker_a.join().unwrap();
        worker_b.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn controller_proxy_provider_update_switches_runtime_tunnel_selection() {
        let upstream_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();

        let worker_a = thread::spawn(move || {
            let (mut stream, _) = upstream_a.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("CONNECT dest.test:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-a").unwrap();
        });

        let worker_b = thread::spawn(move || {
            let (mut stream, _) = upstream_b.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("CONNECT dest.test:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-b").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-proxy-provider-update");
        fs::write(
            temp.join("provider.yaml"),
            format!(
                r#"
proxies:
  - name: provider-a
    type: http
    server: 127.0.0.1
    port: {port_a}
"#,
                port_a = upstream_a_addr.port(),
            ),
        )
        .unwrap();
        fs::write(
            temp.join("config.yaml"),
            r#"
external-controller: 127.0.0.1:0
secret: top-secret
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "0"
    proxy: selector
    target: dest.test:443
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
proxy-groups:
  - name: selector
    type: select
    use: [provider1]
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
        let tunnel_addr = find_listener_addr(&app, "edge", "tunnel");
        let controller_addr = app.controller_addr().unwrap();

        let first = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(first, b"pong-a");

        fs::write(
            temp.join("provider.yaml"),
            format!(
                r#"
proxies:
  - name: provider-a
    type: http
    server: 127.0.0.1
    port: {port_a}
  - name: provider-b
    type: http
    server: 127.0.0.1
    port: {port_b}
"#,
                port_a = upstream_a_addr.port(),
                port_b = upstream_b_addr.port(),
            ),
        )
        .unwrap();

        let update = send_http_request(
            controller_addr,
            "PUT",
            "/providers/proxies/provider1",
            Some("top-secret"),
            None,
        );
        assert!(
            update.starts_with("HTTP/1.1 204 No Content"),
            "unexpected controller response: {update}"
        );

        let provider = send_http_request(
            controller_addr,
            "GET",
            "/providers/proxies/provider1",
            Some("top-secret"),
            None,
        );
        assert!(provider.contains(r#""provider-a""#), "{provider}");
        assert!(provider.contains(r#""provider-b""#), "{provider}");

        let select_update = send_http_request(
            controller_addr,
            "PUT",
            "/proxies/selector",
            Some("top-secret"),
            Some(br#"{"name":"provider-b"}"#),
        );
        assert!(
            select_update.starts_with("HTTP/1.1 204 No Content"),
            "unexpected selector update response: {select_update}"
        );

        let selected = send_http_request(
            controller_addr,
            "GET",
            "/proxies/selector",
            Some("top-secret"),
            None,
        );
        assert!(selected.contains(r#""now":"provider-b""#), "{selected}");
        assert_eq!(app.runtime_tunnel.group_selected("selector").as_deref(), Some("provider-b"));

        let second = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(second, b"pong-b");

        worker_a.join().unwrap();
        worker_b.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn controller_patch_configs_updates_runtime_mode() {
        let temp = unique_temp_dir("mihomo-app-configs-patch");
        fs::write(
            temp.join("config.yaml"),
            r#"
mode: direct
external-controller: 127.0.0.1:0
secret: top-secret
proxies:
  - type: direct
    name: direct-a
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
        let controller_addr = app.controller_addr().unwrap();

        let update = send_http_request(
            controller_addr,
            "PATCH",
            "/configs",
            Some("top-secret"),
            Some(br#"{"mode":"global"}"#),
        );
        assert!(update.starts_with("HTTP/1.1 204 No Content"), "{update}");
        assert_eq!(app.runtime_tunnel.current_mode(), "global");

        let current = send_http_request(
            controller_addr,
            "GET",
            "/configs",
            Some("top-secret"),
            None,
        );
        assert!(current.contains(r#""mode":"global""#), "{current}");

        app.shutdown();
    }

    #[test]
    fn controller_connections_reports_live_tunnel_connection() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            ready_tx.send(()).unwrap();
            resume_rx.recv().unwrap();
            stream.write_all(b"pong").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-connections");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller: 127.0.0.1:0
secret: top-secret
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: {upstream_addr}
"#
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
        let tunnel_addr = find_listener_addr(&app, "edge", "tunnel");
        let controller_addr = app.controller_addr().unwrap();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(tunnel_addr).unwrap();
            stream.write_all(b"ping").unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            reply
        });

        ready_rx.recv().unwrap();
        let snapshot = send_http_request(
            controller_addr,
            "GET",
            "/connections",
            Some("top-secret"),
            None,
        );
        let body = parse_http_json(&snapshot);
        assert!(body["connections"].is_array(), "{snapshot}");
        assert!(body["memory"].is_u64(), "{snapshot}");
        assert_eq!(body["connections"][0]["chains"][0], "DIRECT", "{snapshot}");
        assert!(body["connections"][0]["providerChains"].is_array(), "{snapshot}");
        assert_eq!(body["connections"][0]["rule"], "", "{snapshot}");
        assert_eq!(body["connections"][0]["rulePayload"], "", "{snapshot}");
        assert_eq!(body["connections"][0]["metadata"]["inboundName"], "edge", "{snapshot}");
        assert_eq!(
            body["connections"][0]["metadata"]["destinationIP"],
            "127.0.0.1",
            "{snapshot}"
        );
        assert_eq!(body["connections"][0]["metadata"]["dnsMode"], "normal", "{snapshot}");
        assert!(body["connections"][0]["metadata"]["remoteDestination"].is_string(), "{snapshot}");
        assert_eq!(body["connections"][0]["upload"], 4, "{snapshot}");

        resume_tx.send(()).unwrap();
        let reply = client.join().unwrap();
        assert_eq!(reply, b"pong");
        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn controller_connections_report_rule_selected_chain() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            ready_tx.send(()).unwrap();
            resume_rx.recv().unwrap();
            stream.write_all(b"pong").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-connections-rule-chain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller: 127.0.0.1:0
secret: top-secret
mode: rule
proxies:
  - type: direct
    name: leaf-a
  - type: direct
    name: leaf-b
proxy-groups:
  - name: auto
    type: url-test
    proxies: [leaf-a, leaf-b]
rules:
  - MATCH,auto
listeners:
  - type: socks
    name: edge
    listen: 127.0.0.1
    port: "0"
"#
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
        app.runtime_tunnel.set_candidate_state(mihomo_runtime::CandidateState {
            name: "leaf-a".into(),
            alive: true,
            last_delay_ms: 80,
            supports_udp: true,
        });
        app.runtime_tunnel.set_candidate_state(mihomo_runtime::CandidateState {
            name: "leaf-b".into(),
            alive: true,
            last_delay_ms: 20,
            supports_udp: true,
        });

        let socks_addr = find_listener_addr(&app, "edge", "socks");
        let controller_addr = app.controller_addr().unwrap();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(socks_addr).unwrap();
            stream.write_all(b"\x05\x01\x00").unwrap();
            let mut method = [0_u8; 2];
            stream.read_exact(&mut method).unwrap();
            assert_eq!(&method, b"\x05\x00");
            let host = b"127.0.0.1";
            let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            request.extend_from_slice(host);
            request.extend_from_slice(&upstream_addr.port().to_be_bytes());
            stream.write_all(&request).unwrap();
            let mut response = [0_u8; 10];
            stream.read_exact(&mut response).unwrap();
            assert_eq!(response[1], 0x00);
            stream.write_all(b"ping").unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            reply
        });

        ready_rx.recv().unwrap();
        let snapshot = send_http_request(
            controller_addr,
            "GET",
            "/connections",
            Some("top-secret"),
            None,
        );
        let body = parse_http_json(&snapshot);
        assert_eq!(body["connections"][0]["chains"][0], "leaf-b", "{snapshot}");
        assert_eq!(body["connections"][0]["chains"][1], "auto", "{snapshot}");
        assert_eq!(body["connections"][0]["rule"], "Match", "{snapshot}");
        assert_eq!(body["connections"][0]["rulePayload"], "", "{snapshot}");
        assert_eq!(body["connections"][0]["metadata"]["type"], "socks5", "{snapshot}");
        assert_eq!(body["connections"][0]["metadata"]["destinationIP"], "127.0.0.1", "{snapshot}");

        resume_tx.send(()).unwrap();
        let reply = client.join().unwrap();
        assert_eq!(reply, b"pong");
        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn controller_connections_do_not_report_rule_for_special_proxy_path() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            ready_tx.send(()).unwrap();
            resume_rx.recv().unwrap();
            stream.write_all(b"pong").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-connections-special-proxy");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller: 127.0.0.1:0
secret: top-secret
mode: rule
proxies:
  - type: direct
    name: leaf-a
rules:
  - MATCH,leaf-a
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "0"
    proxy: leaf-a
    target: {upstream_addr}
"#
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
        let tunnel_addr = find_listener_addr(&app, "edge", "tunnel");
        let controller_addr = app.controller_addr().unwrap();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(tunnel_addr).unwrap();
            stream.write_all(b"ping").unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            reply
        });

        ready_rx.recv().unwrap();
        let snapshot = send_http_request(
            controller_addr,
            "GET",
            "/connections",
            Some("top-secret"),
            None,
        );
        let body = parse_http_json(&snapshot);
        assert_eq!(body["connections"][0]["chains"][0], "leaf-a", "{snapshot}");
        assert_eq!(body["connections"][0]["rule"], "", "{snapshot}");
        assert_eq!(body["connections"][0]["rulePayload"], "", "{snapshot}");

        resume_tx.send(()).unwrap();
        let reply = client.join().unwrap();
        assert_eq!(reply, b"pong");
        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn controller_delete_connection_closes_live_tunnel_connection() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            ready_tx.send(()).unwrap();
            let mut trailing = [0_u8; 1];
            let _ = stream.read(&mut trailing);
        });

        let temp = unique_temp_dir("mihomo-app-connections-delete");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller: 127.0.0.1:0
secret: top-secret
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: {upstream_addr}
"#
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
        let tunnel_addr = find_listener_addr(&app, "edge", "tunnel");
        let controller_addr = app.controller_addr().unwrap();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(tunnel_addr).unwrap();
            stream.write_all(b"ping").unwrap();
            let mut reply = Vec::new();
            let _ = stream.read_to_end(&mut reply);
            reply
        });

        ready_rx.recv().unwrap();
        let snapshot = send_http_request(
            controller_addr,
            "GET",
            "/connections",
            Some("top-secret"),
            None,
        );
        let body = parse_http_json(&snapshot);
        let id = body["connections"][0]["id"].as_str().unwrap().to_owned();

        let delete = send_http_request(
            controller_addr,
            "DELETE",
            &format!("/connections/{id}"),
            Some("top-secret"),
            None,
        );
        assert!(delete.starts_with("HTTP/1.1 204 No Content"), "{delete}");

        let reply = client.join().unwrap();
        assert!(reply.is_empty());
        upstream_worker.join().unwrap();
        app.shutdown();
    }
