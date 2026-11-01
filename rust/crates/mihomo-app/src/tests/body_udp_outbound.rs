    #[test]
    fn tunnel_udp_respects_socks5_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-proxy");
            upstream.send_to(b"proxy-ok", from).unwrap();
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
            assert_eq!(payload, b"via-proxy");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response = build_socks_udp_request(upstream_addr, &buf[..read]);
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-socks5");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: socks5
    name: proxy-socks
    server: 127.0.0.1
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
        client.send_to(b"via-proxy", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"proxy-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn tunnel_udp_respects_socks5_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-proxy-tls");
            upstream.send_to(b"proxy-tls-ok", from).unwrap();
        });

        let proxy_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_tcp_addr = proxy_tcp.local_addr().unwrap();
        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy_tcp.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut control = StreamOwned::new(conn, stream);
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
            control.flush().unwrap();

            let mut buf = [0_u8; 2048];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) = parse_socks_udp_response(&buf[..read]);
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-proxy-tls");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response = build_socks_udp_request(upstream_addr, &buf[..read]);
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-socks5-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: socks5
    name: proxy-socks
    server: 127.0.0.1
    port: {proxy_port}
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
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
        client.send_to(b"via-proxy-tls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"proxy-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn tunnel_udp_respects_gost_relay_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-gost");
            upstream.send_to(b"gost-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let (command, requested) = read_gost_relay_target(&mut stream);
            assert_eq!(command, 0x81);
            assert_eq!(requested, Some(upstream_addr));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-gost".to_vec());
            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_gost_relay_udp_packet(&mut stream, &buf[..read]).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-gost");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: gost-relay
    name: proxy-gost
    server: 127.0.0.1
    port: {proxy_port}
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-gost
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-gost", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"gost-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_gost_relay_outbound_selection_with_http_dialer_proxy() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-gost-dialer");
            upstream.send_to(b"gost-dialer-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (mut stream, _) = inner_proxy.accept().unwrap();
            let (command, requested) = read_gost_relay_target(&mut stream);
            assert_eq!(command, 0x81);
            assert_eq!(requested, Some(upstream_addr));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-gost-dialer".to_vec());
            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_gost_relay_udp_packet(&mut stream, &buf[..read]).unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-gost-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: gost-relay
    name: proxy-gost
    server: 127.0.0.1
    port: {inner_port}
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-gost
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-gost-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"gost-dialer-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_gost_relay_outbound_selection_with_http_dialer_proxy_chain() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-gost-dialer-chain");
            upstream.send_to(b"gost-dialer-chain-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (mut stream, _) = inner_proxy.accept().unwrap();
            let (command, requested) = read_gost_relay_target(&mut stream);
            assert_eq!(command, 0x81);
            assert_eq!(requested, Some(upstream_addr));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-gost-dialer-chain".to_vec());
            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_gost_relay_udp_packet(&mut stream, &buf[..read]).unwrap();
        });

        let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let middle_http_addr = middle_http.local_addr().unwrap();
        let middle_http_worker = thread::spawn(move || {
            let (mut control, _) = middle_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                middle_http_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                middle_http_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(middle_http_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-gost-http-dialer-chain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
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
  - type: gost-relay
    name: proxy-gost
    server: 127.0.0.1
    port: {inner_port}
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-gost
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                middle_port = middle_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-gost-dialer-chain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"gost-dialer-chain-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        middle_http_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_gost_relay_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-gost-tls");
            upstream.send_to(b"gost-tls-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (command, requested) = read_gost_relay_target_reader(&mut stream);
            assert_eq!(command, 0x81);
            assert_eq!(requested, Some(upstream_addr));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();
            stream.flush().unwrap();

            let payload = read_gost_relay_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-gost-tls".to_vec());
            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_gost_relay_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-gost-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: gost-relay
    name: proxy-gost
    server: 127.0.0.1
    port: {proxy_port}
    tls: true
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-gost
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-gost-tls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"gost-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_gost_relay_mux_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-gost-mux");
            upstream.send_to(b"gost-mux-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let (command, requested) = read_gost_relay_target_reader(&mut *stream);
            assert_eq!(command, 0x81);
            assert_eq!(requested, Some(upstream_addr));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-gost-mux".to_vec());
            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_gost_relay_udp_packet(&mut *stream, &buf[..read]).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-gost-mux");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: gost-relay
    name: proxy-gost
    server: 127.0.0.1
    port: {proxy_port}
    mux: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-gost
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-gost-mux", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"gost-mux-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_gost_relay_mux_outbound_selection_with_http_dialer_proxy() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-gost-mux-dialer");
            upstream.send_to(b"gost-mux-dialer-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (stream, _) = inner_proxy.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let (command, requested) = read_gost_relay_target_reader(&mut *stream);
            assert_eq!(command, 0x81);
            assert_eq!(requested, Some(upstream_addr));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-gost-mux-dialer".to_vec());
            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_gost_relay_udp_packet(&mut *stream, &buf[..read]).unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-gost-mux-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: gost-relay
    name: proxy-gost
    server: 127.0.0.1
    port: {inner_port}
    mux: true
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-gost
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-gost-mux-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"gost-mux-dialer-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_shadowsocks_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ss");
            upstream.send_to(b"ss-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &buf[..read])
                    .unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ss");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response = encode_shadowsocks_udp_packet(
                "chacha20-ietf-poly1305",
                "secret",
                upstream_addr,
                &buf[..read],
            )
            .unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ss");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ss
    name: proxy-ss
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ss
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-ss", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ss-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_shadowsocks_domain_response_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ss-domain");
            upstream.send_to(b"ss-domain-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &buf[..read])
                    .unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ss-domain");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response = encode_shadowsocks_udp_packet_for_target(
                "chacha20-ietf-poly1305",
                "secret",
                &mihomo_transport::TransportTarget::new("localhost", upstream_addr.port()),
                &buf[..read],
            )
            .unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ss-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ss
    name: proxy-ss
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ss
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ss-domain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ss-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_shadowsocks_plugin_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ss-plugin");
            upstream.send_to(b"ss-plugin-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &buf[..read])
                    .unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ss-plugin");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response = encode_shadowsocks_udp_packet(
                "chacha20-ietf-poly1305",
                "secret",
                upstream_addr,
                &buf[..read],
            )
            .unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ss-plugin");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ss
    name: proxy-ss
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: obfs
    plugin-opts:
      mode: http
      host: bing.com
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ss
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-ss-plugin", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ss-plugin-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_snell_http_obfs_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-snell-obfs");
            upstream.send_to(b"snell-obfs-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream = accept_snell_udp_stream(stream, "secret-psk", 3).unwrap();
            let mut header = [0_u8; 3];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 6, 0]);
            let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-snell-obfs".to_vec());

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            stream.write_all(&[0x00]).unwrap();
            write_snell_udp_packet(&mut *stream, upstream_addr, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-snell-http-obfs");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: snell
    name: proxy-snell
    server: 127.0.0.1
    port: {proxy_port}
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: http
      host: bing.com
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-snell
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-snell-obfs", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"snell-obfs-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_snell_outbound_selection_with_http_dialer_proxy() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-snell-dialer");
            upstream.send_to(b"snell-dialer-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (stream, _) = inner_proxy.accept().unwrap();
            let mut stream = accept_snell_udp_stream(Box::new(stream), "secret-psk", 3).unwrap();
            let mut header = [0_u8; 3];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 6, 0]);
            let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-snell-dialer".to_vec());

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            stream.write_all(&[0x00]).unwrap();
            write_snell_udp_packet(&mut *stream, upstream_addr, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-snell-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: snell
    name: proxy-snell
    server: 127.0.0.1
    port: {inner_port}
    psk: secret-psk
    version: 3
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-snell
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
        client.send_to(b"via-snell-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"snell-dialer-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_snell_http_obfs_domain_response_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-snell-obfs-domain");
            upstream.send_to(b"snell-obfs-domain-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream = accept_snell_udp_stream(stream, "secret-psk", 3).unwrap();
            let mut header = [0_u8; 3];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 6, 0]);
            let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-snell-obfs-domain".to_vec());

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            stream.write_all(&[0x00]).unwrap();
            write_snell_udp_packet_with_domain(
                &mut *stream,
                "localhost",
                upstream_addr.port(),
                &buf[..read],
            );
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-snell-http-obfs-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: snell
    name: proxy-snell
    server: 127.0.0.1
    port: {proxy_port}
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: http
      host: bing.com
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-snell
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client
            .send_to(b"via-snell-obfs-domain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"snell-obfs-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_snell_tls_obfs_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-snell-obfs-tls");
            upstream.send_to(b"snell-obfs-tls-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream = accept_snell_udp_stream(stream, "secret-psk", 3).unwrap();
            let mut header = [0_u8; 3];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 6, 0]);
            let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-snell-obfs-tls".to_vec());

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            stream.write_all(&[0x00]).unwrap();
            write_snell_udp_packet(&mut *stream, upstream_addr, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-snell-tls-obfs");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: snell
    name: proxy-snell
    server: 127.0.0.1
    port: {proxy_port}
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: tls
      host: bing.com
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-snell
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-snell-obfs-tls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"snell-obfs-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr");
            upstream.send_to(b"ssr-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("dummy", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                encode_ssr_udp_packet("dummy", "secret", upstream_addr, &buf[..read]).unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: dummy
    password: secret
    protocol: origin
    obfs: plain
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_cfb_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr-cfb");
            upstream.send_to(b"ssr-cfb-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("aes-128-cfb", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr-cfb");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                encode_ssr_udp_packet("aes-128-cfb", "secret", upstream_addr, &buf[..read]).unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr-cfb");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-128-cfb
    password: secret
    protocol: origin
    obfs: plain
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr-cfb", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-cfb-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_cfb_aes_256_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr-cfb-256");
            upstream.send_to(b"ssr-cfb-256-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("aes-256-cfb", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr-cfb-256");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                encode_ssr_udp_packet("aes-256-cfb", "secret", upstream_addr, &buf[..read]).unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr-cfb-256");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-256-cfb
    password: secret
    protocol: origin
    obfs: plain
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr-cfb-256", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-cfb-256-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_cfb_aes_192_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr-cfb-192");
            upstream.send_to(b"ssr-cfb-192-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("aes-192-cfb", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr-cfb-192");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                encode_ssr_udp_packet("aes-192-cfb", "secret", upstream_addr, &buf[..read]).unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr-cfb-192");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-192-cfb
    password: secret
    protocol: origin
    obfs: plain
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr-cfb-192", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-cfb-192-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_domain_response_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr-domain");
            upstream.send_to(b"ssr-domain-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("dummy", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr-domain");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);

            let mut response = vec![0x03, 0x09];
            response.extend_from_slice(b"localhost");
            response.extend_from_slice(&upstream_addr.port().to_be_bytes());
            response.extend_from_slice(&buf[..read]);
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: none
    password: secret
    obfs: plain
    protocol: origin
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr-domain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_http_simple_obfs_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr-http-simple");
            upstream.send_to(b"ssr-http-simple-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("dummy", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr-http-simple");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                encode_ssr_udp_packet("dummy", "secret", upstream_addr, &buf[..read]).unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr-http-simple");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: dummy
    password: secret
    protocol: origin
    obfs: http_simple
    obfs-param: obfs.example.com
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr-http-simple", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-http-simple-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_ssr_http_post_obfs_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-ssr-http-post");
            upstream.send_to(b"ssr-http-post-ok", from).unwrap();
        });

        let proxy_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let mut buf = [0_u8; 64 * 1024];
            let (read, client_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            let (target, payload) =
                decode_ssr_udp_packet("aes-128-cfb", "secret", &buf[..read]).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-ssr-http-post");

            proxy_udp.send_to(&payload, upstream_addr).unwrap();
            let (read, source_addr) = proxy_udp.recv_from(&mut buf).unwrap();
            assert_eq!(source_addr, upstream_addr);
            let response =
                encode_ssr_udp_packet("aes-128-cfb", "secret", upstream_addr, &buf[..read]).unwrap();
            proxy_udp.send_to(&response, client_addr).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-ssr-http-post");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: ssr
    name: proxy-ssr
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-128-cfb
    password: secret
    protocol: origin
    obfs: http_post
    obfs-param: obfs.example.com
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-ssr
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_udp_addr.port(),
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
        client.send_to(b"via-ssr-http-post", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"ssr-http-post-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_dns_outbound_selection() {
        let temp = unique_temp_dir("mihomo-app-udp-outbound-dns");
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
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
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
        let listener_addr = find_listener_addr(&app, "edge-udp", "tunnel/udp");

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let query = build_dns_query_packet("example.test", 1, 0x4567);
        client.send_to(&query, listener_addr).unwrap();
        let mut buf = [0_u8; 1500];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        let answer = parse_first_a_answer(&buf[..read]);
        assert_eq!(answer, Some("1.2.3.4".parse().unwrap()));

        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, command, header_target) = read_trojan_request(&mut stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan");
            write_trojan_udp_packet_frame(&mut stream, target, b"trojan-ok");
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_outbound_selection_with_http_dialer_proxy() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let inner_tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_tls_addr = inner_tls_listener.local_addr().unwrap();
        let inner_tls_config = build_tls_server_config();
        let inner_worker = thread::spawn(move || {
            let (stream, _) = inner_tls_listener.accept().unwrap();
            let conn = ServerConnection::new(inner_tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, command, header_target) = read_trojan_request(&mut stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan-dialer");
            write_trojan_udp_packet_frame(&mut stream, target, b"trojan-dialer-ok");
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_tls_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_tls_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_tls_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {inner_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-dialer-ok");

        inner_worker.join().unwrap();
        outer_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_domain_response_addresses() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (_password, command, header_target) = read_trojan_request(&mut stream);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan-domain");
            write_trojan_udp_packet_frame_with_domain(
                &mut stream,
                "localhost",
                target.port(),
                b"trojan-domain-ok",
            );
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan-domain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-domain-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_shadowsocks_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream =
                accept_shadowsocks_test_stream(Box::new(stream), "aes-128-gcm", "inner").unwrap();
            let (password, command, header_target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan-ss");
            write_trojan_udp_packet_frame(&mut *stream, target, b"trojan-ss-ok");
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan-ss");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    ss-opts:
      enabled: true
      method: aes-128-gcm
      password: inner
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan-ss", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-ss-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_http_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(
                ServerConnection::new(tls_config).unwrap(),
                stream,
            ));
            let (request, mut stream) = accept_http_stream_test(Box::new(stream));
            assert!(request.starts_with("GET /tr-udp HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (password, command, header_target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan-http");
            write_trojan_udp_packet_frame(&mut *stream, target, b"trojan-http-ok");
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    network: http
    http-opts:
      path: [/tr-udp]
      host: [localhost]
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan-http", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-http-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_ws_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /tr-udp HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (password, command, header_target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan-ws");
            write_trojan_udp_packet_frame(&mut *stream, target, b"trojan-ws-ok");
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /tr-udp
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan-ws", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-ws-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trojan_grpc_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("127.0.0.1:{}", tls_addr.port()));
            assert_eq!(request.path, "/example/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (password, command, header_target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x03);
            assert_eq!(header_target, target.to_string());
            let (packet_target, payload) = read_trojan_udp_packet_frame(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trojan-grpc");
            write_trojan_udp_packet_frame(&mut *stream, target, b"trojan-grpc-ok");
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trojan-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: proxy-trojan
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    network: grpc
    sni: localhost
    skip-cert-verify: true
    grpc-opts:
      grpc-service-name: example
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trojan
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trojan-grpc", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trojan-grpc-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trusttunnel_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "_udp2");
            assert_eq!(
                request.headers.get("proxy-authorization").map(String::as_str),
                Some("Basic YWxpY2U6c2VjcmV0")
            );
            let (packet_target, payload) = read_trusttunnel_udp_packet_frame_from_client(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trusttunnel");
            write_trusttunnel_udp_packet_frame_to_client(&mut *stream, target, b"trusttunnel-ok");
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trusttunnel");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trusttunnel
    name: proxy-trusttunnel
    server: 127.0.0.1
    port: {proxy_port}
    username: alice
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trusttunnel
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trusttunnel", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trusttunnel-ok");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_tuic_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tuic_server = TestTuicServer::start_v5(
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "secret",
        );

        let temp = unique_temp_dir("mihomo-app-udp-outbound-tuic");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: tuic
    name: proxy-tuic
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    alpn: [h3]
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-tuic
    target: {target}
"#,
                proxy_port = tuic_server.addr.port(),
                target = target,
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
        client.send_to(b"via-tuic", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"tuic-ok");

        tuic_server.shutdown();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_tuic_v4_token_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tuic_server = TestTuicServer::start_v4("secret");

        let temp = unique_temp_dir("mihomo-app-udp-outbound-tuic-v4");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: tuic
    name: proxy-tuic
    server: 127.0.0.1
    port: {proxy_port}
    token: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    alpn: [h3]
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-tuic
    target: {target}
"#,
                proxy_port = tuic_server.addr.port(),
                target = target,
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
        client.send_to(b"via-tuic-v4", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"tuic-v4-ok");

        tuic_server.shutdown();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_hy2_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let hy2_server = TestHy2Server::start("secret");

        let temp = unique_temp_dir("mihomo-app-udp-outbound-hy2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: hysteria2
    name: proxy-hy2
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-hy2
    target: {target}
"#,
                proxy_port = hy2_server.addr.port(),
                target = target,
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
        client.send_to(b"via-hy2", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"hy2-ok");

        hy2_server.shutdown();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trusttunnel_outbound_selection_with_http_dialer_proxy() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let inner_tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_tls_addr = inner_tls_listener.local_addr().unwrap();
        let inner_tls_config = build_tls_server_config();
        let inner_worker = thread::spawn(move || {
            let (stream, _) = inner_tls_listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), inner_tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "_udp2");
            assert_eq!(
                request.headers.get("proxy-authorization").map(String::as_str),
                Some("Basic YWxpY2U6c2VjcmV0")
            );
            let (packet_target, payload) =
                read_trusttunnel_udp_packet_frame_from_client(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trusttunnel-dialer");
            write_trusttunnel_udp_packet_frame_to_client(
                &mut *stream,
                target,
                b"trusttunnel-dialer-ok",
            );
            stream.shutdown_write().unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_tls_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_tls_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_tls_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trusttunnel-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: trusttunnel
    name: proxy-trusttunnel
    server: 127.0.0.1
    port: {inner_port}
    username: alice
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trusttunnel
    target: {target}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_tls_addr.port(),
                target = target,
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
        client.send_to(b"via-trusttunnel-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trusttunnel-dialer-ok");

        inner_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trusttunnel_outbound_selection_with_http_dialer_proxy_chain() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let inner_tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_tls_addr = inner_tls_listener.local_addr().unwrap();
        let inner_tls_config = build_tls_server_config();
        let inner_worker = thread::spawn(move || {
            let (stream, _) = inner_tls_listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), inner_tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "_udp2");
            assert_eq!(
                request.headers.get("proxy-authorization").map(String::as_str),
                Some("Basic YWxpY2U6c2VjcmV0")
            );
            let (packet_target, payload) =
                read_trusttunnel_udp_packet_frame_from_client(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trusttunnel-dialer-chain");
            write_trusttunnel_udp_packet_frame_to_client(
                &mut *stream,
                target,
                b"trusttunnel-dialer-chain-ok",
            );
            stream.shutdown_write().unwrap();
        });

        let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let middle_http_addr = middle_http.local_addr().unwrap();
        let middle_http_worker = thread::spawn(move || {
            let (mut control, _) = middle_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_tls_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_tls_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_tls_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                middle_http_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                middle_http_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(middle_http_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trusttunnel-http-dialer-chain");
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
  - type: trusttunnel
    name: proxy-trusttunnel
    server: 127.0.0.1
    port: {inner_port}
    username: alice
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trusttunnel
    target: {target}
"#,
                outer_port = outer_http_addr.port(),
                middle_port = middle_http_addr.port(),
                inner_port = inner_tls_addr.port(),
                target = target,
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
        client
            .send_to(b"via-trusttunnel-dialer-chain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trusttunnel-dialer-chain-ok");

        inner_worker.join().unwrap();
        middle_http_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_trusttunnel_outbound_selection_with_socks5_http_dialer_proxy_chain() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let inner_tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_tls_addr = inner_tls_listener.local_addr().unwrap();
        let inner_tls_config = build_tls_server_config();
        let inner_worker = thread::spawn(move || {
            let (stream, _) = inner_tls_listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), inner_tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "_udp2");
            assert_eq!(
                request.headers.get("proxy-authorization").map(String::as_str),
                Some("Basic YWxpY2U6c2VjcmV0")
            );
            let (packet_target, payload) =
                read_trusttunnel_udp_packet_frame_from_client(&mut *stream);
            assert_eq!(packet_target, target);
            assert_eq!(payload, b"via-trusttunnel-socks-http-chain");
            write_trusttunnel_udp_packet_frame_to_client(
                &mut *stream,
                target,
                b"trusttunnel-socks-http-chain-ok",
            );
            stream.shutdown_write().unwrap();
        });

        let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let middle_http_addr = middle_http.local_addr().unwrap();
        let middle_http_worker = thread::spawn(move || {
            let (mut control, _) = middle_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_tls_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_tls_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_tls_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let outer_socks_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_socks_tcp_addr = outer_socks_tcp.local_addr().unwrap();
        let outer_socks_worker = thread::spawn(move || {
            let (mut control, _) = outer_socks_tcp.accept().unwrap();
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
                    assert_eq!(SocketAddr::from((addr, 0)).ip(), middle_http_addr.ip());
                }
                other => panic!("unexpected atyp {other}"),
            }
            let mut port = [0_u8; 2];
            control.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), middle_http_addr.port());

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&[127, 0, 0, 1]);
            reply.extend_from_slice(&0_u16.to_be_bytes());
            control.write_all(&reply).unwrap();

            let mut upstream = TcpStream::connect(middle_http_addr).unwrap();
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-trusttunnel-socks-http-dialer-chain");
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
  - type: trusttunnel
    name: proxy-trusttunnel
    server: 127.0.0.1
    port: {inner_port}
    username: alice
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-trusttunnel
    target: {target}
"#,
                outer_port = outer_socks_tcp_addr.port(),
                middle_port = middle_http_addr.port(),
                inner_port = inner_tls_addr.port(),
                target = target,
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
        client
            .send_to(b"via-trusttunnel-socks-http-chain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"trusttunnel-socks-http-chain-ok");

        inner_worker.join().unwrap();
        middle_http_worker.join().unwrap();
        outer_socks_worker.join().unwrap();
        app.shutdown();
    }



    #[test]
    fn tunnel_udp_respects_vless_http_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-http");
            upstream.send_to(b"vless-http-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, mut stream) = accept_http_stream_test(Box::new(stream));
            assert!(request.starts_with("GET /vuh HTTP/1.1\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-http");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: http
    http-opts:
      path: [/vuh]
      host: [localhost]
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-http", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-http-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_h2_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-h2");
            upstream.send_to(b"vless-h2-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, mut stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vuh2");
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-h2");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-h2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: h2
    h2-opts:
      host: [localhost]
      path: /vuh2
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-h2", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-h2-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_grpc_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-grpc");
            upstream.send_to(b"vless-grpc-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/example/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-grpc");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: grpc
    grpc-opts:
      grpc-service-name: example
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-grpc", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-grpc-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xhttp_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xhttp");
            upstream.send_to(b"vless-xhttp-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vxu/");
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-xhttp");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xhttp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxu
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xhttp", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xhttp-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xhttp_without_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xhttp-notls");
            upstream.send_to(b"vless-xhttp-notls-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, mut stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vxun/");
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-xhttp-notls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xhttp-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: xhttp
    xhttp-opts:
      path: /vxun
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xhttp-notls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xhttp-notls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xhttp_stream_up_without_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xhttp-sn");
            upstream.send_to(b"vless-xhttp-sn-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream_a, _) = proxy.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = proxy.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request, upload_stream)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxsun/"));
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vless-xhttp-sn");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xhttp-stream-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: xhttp
    xhttp-opts:
      path: /vxsun
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xhttp-sn", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xhttp-sn-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xhttp_packet_up_without_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xhttp-pn");
            upstream.send_to(b"vless-xhttp-pn-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream_a, _) = proxy.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = proxy.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request0, mut upload_stream0)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxpun/"));
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vless-xhttp-pn");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xhttp-packet-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: xhttp
    xhttp-opts:
      path: /vxpun
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xhttp-pn", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xhttp-pn-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xhttp_stream_up_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xhttp-s");
            upstream.send_to(b"vless-xhttp-s-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (download_stream, _) = proxy.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxsu/"));

            let (upload_stream, _) = proxy.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vless-xhttp-s");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xhttp-stream-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxsu
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xhttp-s", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xhttp-s-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xhttp_packet_up_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xhttp-p");
            upstream.send_to(b"vless-xhttp-p-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (download_stream, _) = proxy.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxpu/"));

            let (upload_stream0, _) = proxy.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vless-xhttp-p");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xhttp-packet-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxpu
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xhttp-p", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xhttp-p-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_outbound_selection() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku");
            upstream.send_to(b"sudoku-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-sudoku", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_outbound_selection_with_http_dialer_proxy() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-dialer");
            upstream.send_to(b"sudoku-dialer-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (stream, _) = inner_proxy.accept().unwrap();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-dialer");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            )
            .unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {inner_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
        client.send_to(b"via-sudoku-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-dialer-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_packed_downlink_outbound_selection() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-packed-sudoku");
            upstream.send_to(b"packed-sudoku-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "up_ascii_down_entropy",
                10,
                30,
                false,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-packed-sudoku");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-packed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: false
    http-mask: false
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-packed-sudoku", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"packed-sudoku-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_poll_http_mask_outbound_selection() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let _udp_guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-poll");
            upstream.send_to(b"sudoku-poll-ok", from).unwrap();
        });

        let mut proxy = SudokuHttpMaskTestServer::start(
            SudokuHttpMaskTestMode::Poll,
            "secret-seed",
            "mask",
            "",
        );
        let proxy_addr = proxy.addr;
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-poll");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-poll");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: poll
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-sudoku-poll", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-poll-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_poll_http_mask_tls_outbound_selection() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let _udp_guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-poll-tls");
            upstream.send_to(b"sudoku-poll-tls-ok", from).unwrap();
        });

        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let mut proxy = SudokuHttpMaskTestServer::start_with_tls(
            SudokuHttpMaskTestMode::Poll,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let proxy_addr = proxy.addr;
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-poll-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-poll-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: poll
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-sudoku-poll-tls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-poll-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_auto_http_mask_outbound_selection() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let _udp_guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-auto");
            upstream.send_to(b"sudoku-auto-ok", from).unwrap();
        });

        let mut proxy = SudokuHttpMaskTestServer::start(
            SudokuHttpMaskTestMode::Poll,
            "secret-seed",
            "mask",
            "",
        );
        let proxy_addr = proxy.addr;
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-auto");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-auto");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: auto
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-sudoku-auto", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-auto-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_auto_http_mask_tls_outbound_selection() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let _udp_guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-auto-tls");
            upstream.send_to(b"sudoku-auto-tls-ok", from).unwrap();
        });

        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let mut proxy = SudokuHttpMaskTestServer::start_with_tls(
            SudokuHttpMaskTestMode::Poll,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let proxy_addr = proxy.addr;
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-auto-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-auto-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: auto
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-sudoku-auto-tls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-auto-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_stream_http_mask_tls_outbound_selection() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let _udp_guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-stream-tls");
            upstream.send_to(b"sudoku-stream-tls-ok", from).unwrap();
        });

        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let mut proxy = SudokuHttpMaskTestServer::start_with_tls(
            SudokuHttpMaskTestMode::Stream,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let proxy_addr = proxy.addr;
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-stream-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-stream-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-sudoku-stream-tls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-stream-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_stream_http_mask_outbound_selection() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let _udp_guard = sudoku_udp_test_guard();
        let (milestone_tx, milestone_rx) = mpsc::channel();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_milestone_tx = milestone_tx.clone();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            let _ = upstream_milestone_tx.send("upstream-recv");
            assert_eq!(&buf[..read], b"via-sudoku-stream");
            upstream.send_to(b"sudoku-stream-ok", from).unwrap();
            let _ = upstream_milestone_tx.send("upstream-send");
        });

        let mut proxy = SudokuHttpMaskTestServer::start(
            SudokuHttpMaskTestMode::Stream,
            "secret-seed",
            "mask",
            "cdn.example.com:8443",
        );
        let proxy_addr = proxy.addr;
        let proxy_milestone_tx = milestone_tx.clone();
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let _ = proxy_milestone_tx.send("proxy-session");
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let _ = proxy_milestone_tx.send("proxy-accepted-udp");
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            let _ = proxy_milestone_tx.send("proxy-recv");
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-stream");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            let _ = proxy_milestone_tx.send("proxy-upstream-recv");
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            let _ = proxy_milestone_tx.send("proxy-write-back");
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-stream");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    http-mask-host: cdn.example.com:8443
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client.send_to(b"via-sudoku-stream", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = match client.recv_from(&mut buf) {
            Ok(value) => value,
            Err(err) => {
                let mut milestones = Vec::new();
                while let Ok(step) = milestone_rx.try_recv() {
                    milestones.push(step);
                }
                panic!("sudoku stream udp recv failed: {err}; milestones={milestones:?}");
            }
        };
        assert_eq!(&buf[..read], b"sudoku-stream-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_ws_http_mask_outbound_selection() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-ws");
            upstream.send_to(b"sudoku-ws-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.contains("GET /mask/ws HTTP/1.1\r\n"));
            assert!(request.contains("Host: cdn.example.com:8443\r\n"));
            let session = accept_sudoku_test_stream(
                stream,
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-ws");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    http-mask-host: cdn.example.com:8443
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-sudoku-ws", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-ws-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_wss_http_mask_outbound_selection() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-wss");
            upstream.send_to(b"sudoku-wss-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.contains("GET /mask/ws HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost:8443\r\n"));
            let session = accept_sudoku_test_stream(
                stream,
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-wss");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-wss");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-sudoku-wss", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-wss-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_sudoku_domain_response_addresses() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-sudoku-domain");
            upstream.send_to(b"sudoku-domain-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Udp { mut stream } = session else {
                panic!("expected sudoku udp session");
            };
            let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-sudoku-domain");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet_with_domain(
                &mut *stream,
                "localhost",
                upstream_addr.port(),
                &buf[..read],
            );
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-sudoku-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {proxy_port}
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-sudoku
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-sudoku-domain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"sudoku-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless");
            upstream.send_to(b"vless-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vless");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_outbound_selection_with_http_dialer_proxy() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-dialer");
            upstream.send_to(b"vless-dialer-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (mut stream, _) = inner_proxy.accept().unwrap();
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vless-dialer");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {inner_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
        client.send_to(b"via-vless-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-dialer-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-ws");
            upstream.send_to(b"vless-ws-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, mut stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-udp HTTP/1.1\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-ws");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: ws
    ws-opts:
      path: /vless-udp
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-ws", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-ws-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_ignored_early_data_header_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-ws-ignored-ed");
            upstream.send_to(b"vless-ws-ignored-ed-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, mut stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-udp-ignored-ed HTTP/1.1\r\n"));
            assert!(!request.contains("X-Ignored-Early:"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-ws-ignored-ed");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws-ignored-ed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: ws
    ws-opts:
      path: /vless-udp-ignored-ed
      early-data-header-name: X-Ignored-Early
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-ws-ignored-ed", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-ws-ignored-ed-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_early_data_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-wsed");
            upstream.send_to(b"vless-wsed-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_early_data_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-early-udp HTTP/1.1\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: "));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-wsed");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws-early-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-early-udp
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-wsed", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-wsed-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_query_early_data_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-wsqed");
            upstream.send_to(b"vless-wsqed-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_early_data_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-query-early-udp?foo=bar HTTP/1.1\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: "));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-wsqed");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws-query-early-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-query-early-udp?ed=2048&foo=bar
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-wsqed", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-wsqed-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_http_upgrade_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-wsup");
            upstream.send_to(b"vless-wsup-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_upgrade_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-upgrade-udp HTTP/1.1\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-wsup");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws-http-upgrade");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-upgrade-udp
      v2ray-http-upgrade: true
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-wsup", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-wsup-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_early_data_http_upgrade_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-wsued");
            upstream.send_to(b"vless-wsued-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_upgrade_early_data_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-upgrade-early-udp HTTP/1.1\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: "));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-wsued");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws-early-data-http-upgrade");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-upgrade-early-udp
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      v2ray-http-upgrade: true
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-wsued", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-wsued-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_ws_http_upgrade_fast_open_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-wsupf");
            upstream.send_to(b"vless-wsupf-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_upgrade_fast_open_test_stream(stream);
            assert!(request.starts_with("GET /vless-upgrade-fast-udp HTTP/1.1\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, upstream_addr.to_string());
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vless-wsupf");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-ws-http-upgrade-fast-open");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-upgrade-fast-udp
      v2ray-http-upgrade: true
      v2ray-http-upgrade-fast-open: true
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-wsupf", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-wsupf-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_http_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-http");
            upstream.send_to(b"vmess-http-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_http_stream_test(Box::new(stream));
            assert!(request.starts_with("GET /vmuh HTTP/1.1\r\n"));
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-http");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: http
    http-opts:
      path: [/vmuh]
      host: [localhost]
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-http", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-http-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_h2_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-h2");
            upstream.send_to(b"vmess-h2-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmuh2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-h2");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-h2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-h2", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-h2-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_grpc_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-grpc");
            upstream.send_to(b"vmess-grpc-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/example/Tun");
            let stream = accept_grpc_test_stream(stream);
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-grpc");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: grpc
    grpc-opts:
      grpc-service-name: example
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-grpc", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-grpc-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xhttp_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xhttp");
            upstream.send_to(b"vmess-xhttp-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmxu/");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-xhttp");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xhttp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmxu
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xhttp", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xhttp-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xhttp_without_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xhttp-notls");
            upstream.send_to(b"vmess-xhttp-notls-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmxun/");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-xhttp-notls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xhttp-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: xhttp
    xhttp-opts:
      path: /vmxun
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xhttp-notls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xhttp-notls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xhttp_stream_up_without_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xhttp-sn");
            upstream.send_to(b"vmess-xhttp-sn-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream_a, _) = proxy.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = proxy.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request, upload_stream)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxsun/"));
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);

            let stream = SplitTestStream::new(upload_stream, download_stream);
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-xhttp-sn");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xhttp-stream-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: xhttp
    xhttp-opts:
      path: /vmxsun
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xhttp-sn", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xhttp-sn-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xhttp_packet_up_without_tls_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xhttp-pn");
            upstream.send_to(b"vmess-xhttp-pn-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream_a, _) = proxy.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = proxy.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request0, mut upload_stream0)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxpun/"));
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            let stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-xhttp-pn");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xhttp-packet-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: xhttp
    xhttp-opts:
      path: /vmxpun
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xhttp-pn", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xhttp-pn-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xhttp_stream_up_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xhttp-s");
            upstream.send_to(b"vmess-xhttp-s-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (download_stream, _) = proxy.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxsu/"));

            let (upload_stream, _) = proxy.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);

            let stream = SplitTestStream::new(upload_stream, download_stream);
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-xhttp-s");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xhttp-stream-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmxsu
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xhttp-s", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xhttp-s-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xhttp_packet_up_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xhttp-p");
            upstream.send_to(b"vmess-xhttp-p-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let proxy_worker = thread::spawn(move || {
            let (download_stream, _) = proxy.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxpu/"));

            let (upload_stream0, _) = proxy.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            let stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-xhttp-p");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xhttp-packet-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmxpu
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xhttp-p", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xhttp-p-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_packetaddr_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-pa");
            upstream.send_to(b"vless-pa-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x02);
            assert_eq!(target, "sp.packet-addr.v2fly.arpa:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let payload = read_vless_udp_packet(&mut stream).unwrap();
            let (packet_target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
            assert_eq!(packet_target, upstream_addr);
            assert_eq!(packet, b"via-vless-pa");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&packet, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            let payload = mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, &buf[..read]);
            write_vless_udp_packet(&mut stream, &payload).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    packet-addr: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-pa", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-pa-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xudp_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xudp");
            upstream.send_to(b"vless-xudp-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x03);
            assert_eq!(target, "v1.mux.cool:666");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let (target, payload) = read_vless_xudp_packet(&mut stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-vless-xudp");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vless_xudp_packet(&mut stream, target, &buf[..read]).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    xudp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vless-xudp", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xudp-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vless_xudp_domain_response_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vless-xudp-domain");
            upstream.send_to(b"vless-xudp-domain-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x03);
            assert_eq!(target, "v1.mux.cool:666");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let (target, payload) = read_vless_xudp_packet(&mut stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-vless-xudp-domain");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_xudp_packet_frame_with_domain(
                &mut stream,
                "localhost",
                upstream_addr.port(),
                &buf[..read],
            );
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vless-xudp-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vless
    name: proxy-vless
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    xudp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vless
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client
            .send_to(b"via-vless-xudp-domain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vless-xudp-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess");
            upstream.send_to(b"vmess-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_outbound_selection_with_http_dialer_proxy() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-dialer");
            upstream.send_to(b"vmess-dialer-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (stream, _) = inner_proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-dialer");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {inner_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
        client.send_to(b"via-vmess-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-dialer-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_outbound_selection_with_http_dialer_proxy_chain() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-dialer-chain");
            upstream.send_to(b"vmess-dialer-chain-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (stream, _) = inner_proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-dialer-chain");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let middle_http_addr = middle_http.local_addr().unwrap();
        let middle_http_worker = thread::spawn(move || {
            let (mut control, _) = middle_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_http_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                middle_http_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                middle_http_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(middle_http_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-http-dialer-chain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
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
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {inner_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_http_addr.port(),
                middle_port = middle_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
        client
            .send_to(b"via-vmess-dialer-chain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-dialer-chain-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        middle_http_worker.join().unwrap();
        outer_http_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_outbound_selection_with_socks5_http_dialer_proxy_chain() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-socks-http-chain");
            upstream.send_to(b"vmess-socks-http-chain-ok", from).unwrap();
        });

        let inner_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_proxy_addr = inner_proxy.local_addr().unwrap();
        let inner_proxy_worker = thread::spawn(move || {
            let (stream, _) = inner_proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-socks-http-chain");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let middle_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let middle_http_addr = middle_http.local_addr().unwrap();
        let middle_http_worker = thread::spawn(move || {
            let (mut control, _) = middle_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_proxy_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_proxy_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_proxy_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let outer_socks_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_socks_tcp_addr = outer_socks_tcp.local_addr().unwrap();
        let outer_socks_worker = thread::spawn(move || {
            let (mut control, _) = outer_socks_tcp.accept().unwrap();
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
                    assert_eq!(SocketAddr::from((addr, 0)).ip(), middle_http_addr.ip());
                }
                other => panic!("unexpected atyp {other}"),
            }
            let mut port = [0_u8; 2];
            control.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), middle_http_addr.port());

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&[127, 0, 0, 1]);
            reply.extend_from_slice(&0_u16.to_be_bytes());
            control.write_all(&reply).unwrap();

            let mut upstream = TcpStream::connect(middle_http_addr).unwrap();
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-socks-http-dialer-chain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
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
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {inner_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    dialer-proxy: middle-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                outer_port = outer_socks_tcp_addr.port(),
                middle_port = middle_http_addr.port(),
                inner_port = inner_proxy_addr.port(),
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
        client
            .send_to(b"via-vmess-socks-http-chain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-socks-http-chain-ok");

        upstream_worker.join().unwrap();
        inner_proxy_worker.join().unwrap();
        middle_http_worker.join().unwrap();
        outer_socks_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_ws_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-ws");
            upstream.send_to(b"vmess-ws-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /udp HTTP/1.1\r\n"));
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());

            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-ws");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: ws
    ws-opts:
      path: /udp
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-ws", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-ws-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_legacy_alter_id_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-legacy");
            upstream.send_to(b"legacy-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-legacy");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-legacy");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 16
    cipher: none
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-legacy", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"legacy-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_legacy_security_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-cfb");
            upstream.send_to(b"legacy-cfb-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-cfb",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-cfb");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut *stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-legacy-cfb");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 16
    cipher: aes-128-cfb
    udp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-cfb", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"legacy-cfb-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_authenticated_length_and_global_padding() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-auth");
            upstream.send_to(b"vmess-auth-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, upstream_addr.to_string());
            let payload = read_vmess_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"via-vmess-auth");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_udp_packet(&mut stream, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-authlen");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    udp: true
    global-padding: true
    authenticated-length: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-auth", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-auth-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xudp_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xudp");
            upstream.send_to(b"vmess-xudp-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedTestStream::Xudp { target, mut stream } = accepted else {
                panic!("expected vmess xudp stream");
            };
            assert_eq!(target, "v1.mux.cool:666");
            let (target, payload) = read_vmess_xudp_packet(&mut stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-vmess-xudp");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_vmess_xudp_packet(&mut stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    udp: true
    xudp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-xudp", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xudp-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_xudp_domain_response_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-xudp-domain");
            upstream.send_to(b"vmess-xudp-domain-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedTestStream::Xudp { target, mut stream } = accepted else {
                panic!("expected vmess xudp stream");
            };
            assert_eq!(target, "v1.mux.cool:666");
            let (target, payload) = read_vmess_xudp_packet(&mut stream).unwrap();
            assert_eq!(target, upstream_addr);
            assert_eq!(payload, b"via-vmess-xudp-domain");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_xudp_packet_frame_with_domain(
                &mut stream,
                "localhost",
                upstream_addr.port(),
                &buf[..read],
            );
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-xudp-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    udp: true
    xudp: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client
            .send_to(b"via-vmess-xudp-domain", listener_addr)
            .unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-xudp-domain-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_vmess_packetaddr_outbound_selection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-vmess-pa");
            upstream.send_to(b"vmess-pa-ok", from).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, "sp.packet-addr.v2fly.arpa:443");
            let payload = read_vmess_udp_packet(&mut *stream).unwrap();
            let (packet_target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
            assert_eq!(packet_target, upstream_addr);
            assert_eq!(packet, b"via-vmess-pa");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&packet, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            let payload = mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, &buf[..read]);
            write_vmess_udp_packet(&mut *stream, &payload).unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-vmess-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: vmess
    name: proxy-vmess
    server: 127.0.0.1
    port: {proxy_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    packet-addr: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-vmess
    target: upstream.test:{upstream_port}
"#,
                proxy_port = proxy_addr.port(),
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
        client.send_to(b"via-vmess-pa", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"vmess-pa-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_anytls_outbound_selection() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = std::io::Cursor::new(payload);
            let target_magic = read_shadowsocks_target_reader(&mut payload_reader);
            assert_eq!(target_magic, "sp.v2.udp-over-tcp.arpa:0");

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (is_connect, destination) = read_anytls_uot_request(&payload);
            assert!(!is_connect);
            assert_eq!(destination, target);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (packet_target, packet) = read_anytls_uot_packet(&payload);
            assert_eq!(packet_target, target);
            assert_eq!(packet, b"via-anytls".to_vec());

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);
            let mut response = Vec::new();
            response.push(0x00);
            response.extend_from_slice(&[127, 0, 0, 1]);
            response.extend_from_slice(&5353_u16.to_be_bytes());
            response.extend_from_slice(&(10_u16).to_be_bytes());
            response.extend_from_slice(b"anytls-ok!");
            write_anytls_frame(&mut stream, 0x02, 1, &response);
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-anytls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: anytls
    name: proxy-anytls
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-anytls
    target: {target}
"#,
                proxy_port = tls_addr.port(),
                target = target,
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
        client.send_to(b"via-anytls", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"anytls-ok!");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_anytls_outbound_selection_with_http_dialer_proxy() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let inner_tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inner_tls_addr = inner_tls_listener.local_addr().unwrap();
        let inner_tls_config = build_tls_server_config();
        let inner_worker = thread::spawn(move || {
            let (stream, _) = inner_tls_listener.accept().unwrap();
            let conn = ServerConnection::new(inner_tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = std::io::Cursor::new(payload);
            let target_magic = read_shadowsocks_target_reader(&mut payload_reader);
            assert_eq!(target_magic, "sp.v2.udp-over-tcp.arpa:0");

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (is_connect, destination) = read_anytls_uot_request(&payload);
            assert!(!is_connect);
            assert_eq!(destination, target);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (packet_target, packet) = read_anytls_uot_packet(&payload);
            assert_eq!(packet_target, target);
            assert_eq!(packet, b"via-anytls-dialer".to_vec());

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);
            let mut response = Vec::new();
            response.push(0x00);
            response.extend_from_slice(&[127, 0, 0, 1]);
            response.extend_from_slice(&5353_u16.to_be_bytes());
            response.extend_from_slice(&(16_u16).to_be_bytes());
            response.extend_from_slice(b"anytls-dialer-ok");
            write_anytls_frame(&mut stream, 0x02, 1, &response);
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let outer_http = TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_http_addr = outer_http.local_addr().unwrap();
        let outer_worker = thread::spawn(move || {
            let (mut control, _) = outer_http.accept().unwrap();
            let (request, tail) = read_http_headers_with_tail(&mut control).unwrap();
            assert!(request.starts_with(&format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
                inner_tls_addr.port()
            )));
            assert!(request.contains(&format!(
                "Host: 127.0.0.1:{}\r\n",
                inner_tls_addr.port()
            )));
            control
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            control.flush().unwrap();

            let mut upstream = TcpStream::connect(inner_tls_addr).unwrap();
            if !tail.is_empty() {
                upstream.write_all(&tail).unwrap();
                upstream.flush().unwrap();
            }
            match mihomo_runtime::relay_bidirectional(
                &mut control,
                &mut upstream,
                mihomo_runtime::TcpRelayStrategy::BufferedCopy,
            ) {
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(err) => panic!("{err}"),
            }
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-anytls-http-dialer");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: {outer_port}
  - type: anytls
    name: proxy-anytls
    server: 127.0.0.1
    port: {inner_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-http
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-anytls
    target: {target}
"#,
                outer_port = outer_http_addr.port(),
                inner_port = inner_tls_addr.port(),
                target = target,
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
        client.send_to(b"via-anytls-dialer", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"anytls-dialer-ok");

        inner_worker.join().unwrap();
        outer_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn tunnel_udp_respects_anytls_domain_response_addresses() {
        let target = SocketAddr::from(([127, 0, 0, 1], 5353));
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = std::io::Cursor::new(payload);
            let target_magic = read_shadowsocks_target_reader(&mut payload_reader);
            assert_eq!(target_magic, "sp.v2.udp-over-tcp.arpa:0");

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (is_connect, destination) = read_anytls_uot_request(&payload);
            assert!(!is_connect);
            assert_eq!(destination, target);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (packet_target, packet) = read_anytls_uot_packet(&payload);
            assert_eq!(packet_target, target);
            assert_eq!(packet, b"via-anytls-domain".to_vec());

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);
            let mut response = Vec::new();
            response.push(0x02);
            response.push(9);
            response.extend_from_slice(b"localhost");
            response.extend_from_slice(&5353_u16.to_be_bytes());
            response.extend_from_slice(&(17_u16).to_be_bytes());
            response.extend_from_slice(b"anytls-domain-ok!");
            write_anytls_frame(&mut stream, 0x02, 1, &response);
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-udp-outbound-anytls-domain");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: anytls
    name: proxy-anytls
    server: 127.0.0.1
    port: {proxy_port}
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: proxy-anytls
    target: upstream.test:{upstream_port}
"#,
                proxy_port = tls_addr.port(),
                upstream_port = target.port(),
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
        client.send_to(b"via-anytls-domain", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"anytls-domain-ok!");

        worker.join().unwrap();
        app.shutdown();
    }
