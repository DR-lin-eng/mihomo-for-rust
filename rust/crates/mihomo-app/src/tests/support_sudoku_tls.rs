    #[test]
    fn connect_sudoku_udp_stream_helper_supports_stream_http_mask_tls() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-helper-stream-tls");
            upstream.send_to(b"helper-stream-tls-ok", from).unwrap();
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
            assert_eq!(payload, b"via-helper-stream-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let registry = build_runtime_registry(&serde_yaml::from_str::<mihomo_config::RuntimeConfigDocument>(
            "proxies: []\n",
        ).unwrap()).unwrap();
        let tunnel = RuntimeTunnel::new("rule", registry);
        let route = UdpSudokuRoute {
            dialer_proxy: None,
            server: "127.0.0.1".into(),
            port: proxy_addr.port(),
            key: "secret-seed".into(),
            aead_method: "aes-128-gcm".into(),
            table_type: "prefer_ascii".into(),
            padding_min: 10,
            padding_max: 30,
            enable_pure_downlink: true,
            http_mask_enabled: true,
            http_mask_mode: "stream".into(),
            http_mask_tls: true,
            http_mask_host: "localhost:8443".into(),
            path_root: "mask".into(),
            custom_table: String::new(),
            custom_tables: Vec::new(),
        };
        let mut stream = listener_service::connect_sudoku_udp_stream_for_tests(&route, &tunnel, None).unwrap();
        write_sudoku_udp_packet(&mut *stream, upstream_addr, b"via-helper-stream-tls").unwrap();
        let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"helper-stream-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
    }

    #[test]
    fn connect_sudoku_udp_stream_helper_supports_stream_http_mask_tls_with_dns_runtime() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-helper-stream-tls-dns");
            upstream.send_to(b"helper-stream-tls-dns-ok", from).unwrap();
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
            assert_eq!(payload, b"via-helper-stream-tls-dns");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let route = UdpSudokuRoute {
            dialer_proxy: None,
            server: "127.0.0.1".into(),
            port: proxy_addr.port(),
            key: "secret-seed".into(),
            aead_method: "aes-128-gcm".into(),
            table_type: "prefer_ascii".into(),
            padding_min: 10,
            padding_max: 30,
            enable_pure_downlink: true,
            http_mask_enabled: true,
            http_mask_mode: "stream".into(),
            http_mask_tls: true,
            http_mask_host: "localhost:8443".into(),
            path_root: "mask".into(),
            custom_table: String::new(),
            custom_tables: Vec::new(),
        };
        let tunnel = Arc::new(RuntimeTunnel::new(
            "rule",
            build_runtime_registry(
                &serde_yaml::from_str::<mihomo_config::RuntimeConfigDocument>(
                    r#"
proxies:
  - type: direct
    name: direct-a
"#,
                )
                .unwrap(),
            )
            .unwrap(),
        ));
        let mut dns_runtime = mihomo_dns::DnsRuntime::from_document(
            &serde_yaml::from_str::<mihomo_config::RuntimeConfigDocument>(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
"#,
            )
            .unwrap(),
        )
        .ok();
        let mut stream = listener_service::connect_sudoku_udp_stream_for_tests(
            &route,
            &tunnel,
            dns_runtime.as_mut(),
        )
        .unwrap();
        write_sudoku_udp_packet(&mut *stream, upstream_addr, b"via-helper-stream-tls-dns").unwrap();
        let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"helper-stream-tls-dns-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
    }

    #[test]
    fn system_udp_session_supports_sudoku_stream_http_mask_tls_route() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-session-stream-tls");
            upstream.send_to(b"session-stream-tls-ok", from).unwrap();
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
            assert_eq!(payload, b"via-session-stream-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let registry = build_runtime_registry(&serde_yaml::from_str::<mihomo_config::RuntimeConfigDocument>(
            &format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {}
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
"#,
                proxy_addr.port(),
            ),
        ).unwrap()).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new("rule", registry));
        let mut metadata = mihomo_core::Metadata {
            network: mihomo_core::NetworkKind::Udp,
            kind: mihomo_core::SessionKind::Tunnel,
            host: Some("upstream.test".into()),
            dst_port: Some(upstream_addr.port()),
            special_proxy: "proxy-sudoku".into(),
            ..mihomo_core::Metadata::default()
        };
        metadata.dst_ip = Some(upstream_addr.ip());
        let response = listener_service::exercise_sudoku_udp_route_for_tests(
            tunnel,
            &mut metadata,
            mihomo_buf::ByteWindow::freeze(b"via-session-stream-tls".to_vec()),
            upstream_addr,
        )
        .unwrap();
        assert_eq!(response, Some((b"session-stream-tls-ok".to_vec(), upstream_addr)));

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
    }

    #[test]
    fn socket_backed_udp_write_back_supports_sudoku_stream_http_mask_tls_route() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-writeback-stream-tls");
            upstream.send_to(b"writeback-stream-tls-ok", from).unwrap();
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
            assert_eq!(payload, b"via-writeback-stream-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let registry = build_runtime_registry(&serde_yaml::from_str::<mihomo_config::RuntimeConfigDocument>(
            &format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
proxies:
  - type: sudoku
    name: proxy-sudoku
    server: 127.0.0.1
    port: {}
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
"#,
                proxy_addr.port(),
            ),
        ).unwrap()).unwrap();
        let dns_runtime = mihomo_dns::DnsRuntime::from_document(&serde_yaml::from_str::<mihomo_config::RuntimeConfigDocument>(
            &format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
"#,
            ),
        ).unwrap()).ok();
        let tunnel = Arc::new(RuntimeTunnel::new("rule", registry));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.connect(socket.local_addr().unwrap()).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        listener_service::exercise_sudoku_udp_write_back_for_tests(
            Arc::clone(&socket),
            peer_addr,
            Arc::clone(&tunnel),
            "proxy-sudoku",
            &format!("upstream.test:{}", upstream_addr.port()),
            dns_runtime,
            b"via-writeback-stream-tls".to_vec(),
        )
        .unwrap();
        let mut buf = [0_u8; 2048];
        let read = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"writeback-stream-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
    }

    #[test]
    fn running_app_runtime_supports_sudoku_stream_http_mask_tls_write_back_path() {
        let _httpmask_guard = sudoku_httpmask_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"via-running-app-stream-tls");
            upstream.send_to(b"running-app-stream-tls-ok", from).unwrap();
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
            assert_eq!(payload, b"via-running-app-stream-tls");

            let relay_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay_udp.send_to(&payload, upstream_addr).unwrap();
            let mut buf = [0_u8; 2048];
            let (read, _) = relay_udp.recv_from(&mut buf).unwrap();
            write_sudoku_udp_packet(&mut *stream, target, &buf[..read]).unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-running-runtime-sudoku-stream-tls");
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
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.connect(socket.local_addr().unwrap()).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let dns_runtime = app.state.build_dns_runtime().ok();
        listener_service::exercise_sudoku_udp_write_back_for_tests(
            Arc::clone(&socket),
            peer_addr,
            Arc::clone(&app.runtime_tunnel),
            "proxy-sudoku",
            &format!("upstream.test:{}", upstream_addr.port()),
            dns_runtime,
            b"via-running-app-stream-tls".to_vec(),
        )
        .unwrap();
        let mut buf = [0_u8; 2048];
        let read = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"running-app-stream-tls-ok");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }
