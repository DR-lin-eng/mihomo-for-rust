    #[test]
    fn start_serves_custom_tunnel_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: tunnel
    name: tcp-forward
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
        let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

        let mut client = TcpStream::connect(tunnel_addr).unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");

        upstream_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_custom_tunnel_listener_with_dns_runtime_direct_resolution() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong-host").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-dns-direct");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.invalid: 127.0.0.1
dns:
  enable: true
  use-hosts: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: upstream.invalid:{port}
"#,
                port = upstream_addr.port(),
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
        assert_eq!(reply, b"pong-host");

        upstream_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_custom_tunnel_listener_with_dns_runtime_proxy_resolution() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong-proxy").unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
            let target = match header[3] {
                0x01 => {
                    let mut addr = [0_u8; 4];
                    stream.read_exact(&mut addr).unwrap();
                    let mut port = [0_u8; 2];
                    stream.read_exact(&mut port).unwrap();
                    SocketAddr::new(addr.into(), u16::from_be_bytes(port))
                }
                other => panic!("unexpected atyp {other}"),
            };
            assert_eq!(target, upstream_addr);

            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();

            let mut upstream = TcpStream::connect(upstream_addr).unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            upstream.write_all(&buffer).unwrap();

            let mut reply = [0_u8; 10];
            let read = upstream.read(&mut reply).unwrap();
            stream.write_all(&reply[..read]).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-dns-proxy");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  proxy.invalid: 127.0.0.1
dns:
  enable: true
  use-hosts: true
proxies:
  - type: socks5
    name: proxy-socks
    server: proxy.invalid
    port: {proxy_port}
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: proxy-socks
    target: {target}
"#,
                proxy_port = proxy_addr.port(),
                target = upstream_addr,
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
        assert_eq!(reply, b"pong-proxy");

        upstream_worker.join().unwrap();
        proxy_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_custom_tunnel_listener_with_gost_relay_proxy_end_to_end() {
        let target = SocketAddr::from(([127, 0, 0, 1], 40443));
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let relay_worker = thread::spawn(move || {
            let (mut stream, _) = relay.accept().unwrap();
            let (command, requested) = read_gost_relay_target(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(requested, Some(target));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-relay").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-gost-relay");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: gost-relay
    name: relay
    server: 127.0.0.1
    port: {relay_port}
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: {target}
"#,
                relay_port = relay_addr.port(),
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
        let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

        let reply = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(reply, b"pong-relay");

        relay_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_gost_relay_mux_proxy_end_to_end() {
        let target = SocketAddr::from(([127, 0, 0, 1], 40444));
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let relay_worker = thread::spawn(move || {
            let (stream, _) = relay.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let (command, requested) = read_gost_relay_target_reader(&mut *stream);
            assert_eq!(command, 0x01);
            assert_eq!(requested, Some(target));
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-relay-mux").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-gost-relay-mux");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: gost-relay
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    mux: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: {target}
"#,
                relay_port = relay_addr.port(),
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
        let tunnel_addr = find_listener_addr(&app, "tcp-forward", "tunnel");

        let reply = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(reply, b"pong-relay-mux");

        relay_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let target = read_shadowsocks_target_reader(&mut stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: dummy
    password: secret
    obfs: plain
    protocol: origin
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr");

        proxy_worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_ignored_params_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            let target = read_shadowsocks_target_reader(&mut stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-params").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr-ignored-params");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: dummy
    password: secret
    obfs: plain
    obfs-param: ignored-host
    protocol: origin
    protocol-param: ignored-user
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr-params");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_http_simple_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_ssr_http_obfs_test_stream(Box::new(stream)).unwrap();
            assert!(request.starts_with("GET /%"));
            assert!(request.contains("\r\nHost: obfs.example.com"));
            let mut stream = accept_ssr_test_stream(stream, "aes-128-cfb", "secret").unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-http-simple").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr-http-simple");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-128-cfb
    password: secret
    obfs: http_simple
    obfs-param: obfs.example.com
    protocol: origin
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr-http-simple");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_http_post_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_ssr_http_obfs_test_stream(Box::new(stream)).unwrap();
            assert!(request.starts_with("POST /%"));
            assert!(request.contains("\r\nHost: obfs.example.com"));
            assert!(request.contains("Content-Type: multipart/form-data; boundary=----ssrhttpobfsboundary"));
            let mut stream = accept_ssr_test_stream(stream, "aes-128-cfb", "secret").unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-http-post").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr-http-post");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-128-cfb
    password: secret
    obfs: http_post
    obfs-param: obfs.example.com
    protocol: origin
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr-http-post");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_cfb_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let mut stream = accept_ssr_test_stream(Box::new(stream), "aes-128-cfb", "secret").unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-cfb").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr-cfb");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-128-cfb
    password: secret
    obfs: plain
    protocol: origin
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr-cfb");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_cfb_aes_256_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let mut stream = accept_ssr_test_stream(Box::new(stream), "aes-256-cfb", "secret").unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-cfb-256").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr-cfb-256");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-256-cfb
    password: secret
    obfs: plain
    protocol: origin
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr-cfb-256");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_ssr_cfb_aes_192_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let mut stream = accept_ssr_test_stream(Box::new(stream), "aes-192-cfb", "secret").unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-cfb-192").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ssr-cfb-192");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssr
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: aes-192-cfb
    password: secret
    obfs: plain
    protocol: origin
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ssr-cfb-192");

        proxy_worker.join().unwrap();
        app.shutdown();
    }


    #[test]
    fn start_serves_custom_tunnel_listener_with_snell_http_obfs_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream = mihomo_transport::accept_snell_udp_stream(stream, "secret-psk", 3).unwrap();
            let target = read_snell_target_reader(&mut *stream, 3);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-obfs").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-snell-http-obfs");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: snell
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: http
      host: bing.com
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-snell-obfs");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_snell_v2_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let mut stream = mihomo_transport::accept_snell_udp_stream(Box::new(stream), "secret-psk", 2).unwrap();
            let target = read_snell_target_reader(&mut *stream, 2);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-v2").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-snell-v2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: snell
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    psk: secret-psk
    version: 2
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-snell-v2");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_snell_tls_obfs_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream = accept_snell_udp_stream(stream, "secret-psk", 3).unwrap();
            let target = read_snell_target_reader(&mut *stream, 3);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-obfs-tls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-snell-tls-obfs");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: snell
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: tls
      host: bing.com
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-snell-obfs-tls");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[cfg(feature = "ssh-transport-tests")]
    #[test]
    fn start_serves_custom_tunnel_listener_with_ssh_proxy_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssh").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let ssh_server = TestSshServer::start_password();
        let temp = unique_temp_dir("mihomo-app-tunnel-ssh");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ssh
    name: relay
    server: 127.0.0.1
    port: {ssh_port}
    username: user
    password: secret
    host-key:
      - {host_key}
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: 127.0.0.1:{target_port}
"#,
                ssh_port = ssh_server.addr.port(),
                host_key = ssh_server.host_key,
                target_port = upstream_addr.port(),
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
        assert_eq!(reply, b"pong-ssh");

        ssh_server.shutdown();
        upstream_worker.join().unwrap();
        app.shutdown();
    }

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
    fn start_serves_custom_tunnel_listener_with_tuic_v4_token_proxy_end_to_end() {
        let tuic_server = TestTuicServer::start_v4("secret");
        let temp = unique_temp_dir("mihomo-app-tunnel-tuic-v4");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: tuic
    name: relay
    server: 127.0.0.1
    port: {tuic_port}
    token: secret
    sni: localhost
    skip-cert-verify: true
    alpn: [h3]
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: tuic-v4-target.example.com:443
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
        assert_eq!(reply, b"pong-tuic-v4");

        tuic_server.shutdown();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_shadowsocks_ws_plugin_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));
            assert!(request.contains("\r\nX-Proxy: enabled\r\n"));

            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-ws").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ss-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ss
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /shadow
      mux: false
      headers:
        X-Proxy: enabled
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ss-ws");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_shadowsocks_ws_mux_plugin_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-mux HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));

            let stream = accept_v2ray_plugin_mux_test_stream(stream).unwrap();
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-ws-mux").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ss-ws-mux");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ss
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /shadow-mux
      mux: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ss-ws-mux");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_shadowsocks_gost_ws_mux_plugin_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-gost-mux HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));

            let stream = accept_smux_test_stream(stream).unwrap();
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-gost-ws-mux").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ss-gost-ws-mux");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ss
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: gost-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /shadow-gost-mux
      mux: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ss-gost-ws-mux");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_shadowsocks_http_obfs_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-obfs").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ss-obfs");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ss
    name: relay
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
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ss-obfs");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_shadowsocks_tls_obfs_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target_reader(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-obfs-tls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-ss-tls-obfs");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: ss
    name: relay
    server: 127.0.0.1
    port: {proxy_port}
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: obfs
    plugin-opts:
      mode: tls
      host: bing.com
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                proxy_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-ss-obfs-tls");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: false,
                    http_mask_mode: String::new(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: String::new(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_listener_end_to_end_with_minimal_defaults() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-defaults").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-defaults");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: secret-seed
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-defaults");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_listener_end_to_end_with_keypair_material() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-keypair").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: {private_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_packed_downlink_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-packed").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-packed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: false
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: false
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            "secret-seed",
            "chacha20-poly1305",
            "up_ascii_down_entropy",
            10,
            30,
            false,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-packed");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_packed_downlink_listener_end_to_end_with_keypair_material() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-packed-keypair").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-packed-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: {private_key}
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: false
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: false
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            &private_key,
            "chacha20-poly1305",
            "up_ascii_down_entropy",
            10,
            30,
            false,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-packed-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_custom_table_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-custom").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-custom");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-table: xpxvvpvv
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-table: xpxvvpvv
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "xpxvvpvv",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-custom");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_custom_table_listener_end_to_end_with_keypair_material() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-custom-keypair").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-custom-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: {private_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-table: xpxvvpvv
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-table: xpxvvpvv
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "xpxvvpvv",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-custom-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_custom_table_rotation_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-rotation").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-custom-rotation");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");
        let custom_tables = vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()];

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "",
            &custom_tables,
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-rotation");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_custom_table_rotation_listener_end_to_end_with_keypair_material() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream
                .write_all(b"pong-sudoku-inbound-rotation-keypair")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-custom-rotation-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: {private_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");
        let custom_tables = vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()];

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "",
            &custom_tables,
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-rotation-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_entropy_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-entropy").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-entropy");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: test_key_entropy
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: test_key_entropy
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            "test_key_entropy",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-entropy");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_entropy_listener_end_to_end_with_keypair_material() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-entropy-keypair").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-entropy-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: {private_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-entropy-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_padding_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-padding").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-padding");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: test_key_padding
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 100
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: test_key_padding
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 100
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            "test_key_padding",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            100,
            true,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-padding");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_padding_listener_end_to_end_with_keypair_material() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-padding-keypair").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-padding-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: 0
    key: {private_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 100
    http-mask: false
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 100
    http-mask: false
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = open_sudoku_inbound_test_client(
            sudoku_addr,
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            100,
            true,
            "",
            &[],
            TransportTarget::new("127.0.0.1", upstream_addr.port()),
        );
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-inbound-padding-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_stream_http_mask_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-stream").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-stream");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "stream".into(),
                    http_mask_tls: false,
                    http_mask_host: "cdn.example.com:8443".into(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-stream");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_stream_http_mask_tls_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-stream-tls").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-stream-tls");
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    certificate: |
{cert}
    private-key: |
{key}
    http-mask: true
    http-mask-mode: stream
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: {upstream_addr}
"#,
                cert = indent_block(cert_pem.trim_end(), 6),
                key = indent_block(key_pem.trim_end(), 6),
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-stream-tls");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_stream_http_mask_listener_end_to_end_with_keypair_material() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream
                .write_all(b"pong-sudoku-inbound-stream-keypair")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-stream-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: private_key.clone(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "stream".into(),
                    http_mask_tls: false,
                    http_mask_host: "cdn.example.com:8443".into(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-stream-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_nested_stream_httpmask_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-nested-stream").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-nested-stream");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    httpmask:
      mode: stream
      path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "stream".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-nested-stream");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_nested_httpmask_disable_false_falls_back_to_plain_listener() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-nested-disable").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-nested-disable");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    httpmask:
      disable: true
      mode: stream
      path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: false,
                    http_mask_mode: String::new(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: String::new(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-nested-disable");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_poll_http_mask_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-poll").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-poll");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: poll
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "poll".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-poll");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_poll_http_mask_tls_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-poll-tls").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-poll-tls");
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    certificate: |
{cert}
    private-key: |
{key}
    http-mask: true
    http-mask-mode: poll
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: {upstream_addr}
"#,
                cert = indent_block(cert_pem.trim_end(), 6),
                key = indent_block(key_pem.trim_end(), 6),
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "poll".into(),
                    http_mask_tls: true,
                    http_mask_host: "localhost:8443".into(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-poll-tls");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_poll_http_mask_listener_end_to_end_with_keypair_material() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream
                .write_all(b"pong-sudoku-inbound-poll-keypair")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-poll-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: poll
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: private_key.clone(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "poll".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-poll-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_auto_http_mask_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-auto").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-auto");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: auto
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "auto".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-auto");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_auto_http_mask_listener_end_to_end_with_keypair_material() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream
                .write_all(b"pong-sudoku-inbound-auto-keypair")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-auto-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: auto
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: private_key.clone(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "auto".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-auto-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_ws_http_mask_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-ws").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "ws".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-ws");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_wss_http_mask_listener_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-wss").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-wss");
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    certificate: |
{cert}
    private-key: |
{key}
    http-mask: true
    http-mask-mode: ws
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: DIRECT
    target: {upstream_addr}
"#,
                cert = indent_block(cert_pem.trim_end(), 6),
                key = indent_block(key_pem.trim_end(), 6),
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "ws".into(),
                    http_mask_tls: true,
                    http_mask_host: "localhost:8443".into(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-wss");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_ws_http_mask_listener_end_to_end_with_keypair_material() {
        let _guard = sudoku_httpmask_test_guard();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-inbound-ws-keypair").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-ws-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    path-root: mask
  - type: tunnel
    name: tcp-forward
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", sudoku_addr.port()),
                    key: private_key.clone(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "ws".into(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
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
        assert_eq!(reply, b"pong-sudoku-inbound-ws-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_http_mask_rejected_request_falls_back_to_target() {
        let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        let fallback_worker = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.contains("GET /mask/session?auth=bad-token HTTP/1.1\r\n"));
            assert!(request.contains("Host: 127.0.0.1\r\n"));
            assert!(request.contains("X-Sudoku-Tunnel: stream\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-fallback");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    path-root: mask
    fallback: {fallback_addr}
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = TcpStream::connect(sudoku_addr).unwrap();
        client
            .write_all(
                b"GET /mask/session?auth=bad-token HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Sudoku-Tunnel: stream\r\n\r\n",
            )
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).contains("HTTP/1.1 200 OK"));
        assert!(reply.ends_with(b"ok"));

        fallback_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_ws_http_mask_rejected_request_falls_back_to_target() {
        let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        let fallback_worker = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.contains("GET /mask/ws?auth=bad-token HTTP/1.1\r\n"));
            assert!(request.contains("Host: 127.0.0.1\r\n"));
            assert!(request.contains("Connection: Upgrade\r\n"));
            assert!(request.contains("Upgrade: websocket\r\n"));
            assert!(request.contains("X-Sudoku-Tunnel: ws\r\n"));
            assert!(request.contains("Sec-WebSocket-Key: test-key\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-ws-fallback");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    path-root: mask
    fallback: {fallback_addr}
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = TcpStream::connect(sudoku_addr).unwrap();
        client
            .write_all(
                b"GET /mask/ws?auth=bad-token HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: test-key\r\nX-Sudoku-Tunnel: ws\r\nX-Sudoku-Version: 1\r\n\r\n",
            )
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).contains("HTTP/1.1 200 OK"));
        assert!(reply.ends_with(b"ok"));

        fallback_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_plain_http_request_falls_back_to_target() {
        let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        let fallback_worker = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.contains("GET / HTTP/1.1\r\n"));
            assert!(request.contains("Host: 127.0.0.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-plain-http-fallback");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    path-root: mask
    fallback: {fallback_addr}
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = TcpStream::connect(sudoku_addr).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).contains("HTTP/1.1 200 OK"));
        assert!(reply.ends_with(b"ok"));

        fallback_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_non_http_bytes_fall_back_to_target() {
        let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        let fallback_worker = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING /raw-fallback");
            stream.write_all(b"raw-ok").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-raw-fallback");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    path-root: mask
    fallback: {fallback_addr}
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = TcpStream::connect(sudoku_addr).unwrap();
        client.write_all(b"PING /raw-fallback").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"raw-ok");

        fallback_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_plain_non_http_bytes_fall_back_to_target() {
        let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        let fallback_worker = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING /plain-raw-fallback");
            stream.write_all(b"plain-raw-ok").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-plain-raw-fallback");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    fallback: {fallback_addr}
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut client = TcpStream::connect(sudoku_addr).unwrap();
        client.write_all(b"PING /plain-raw-fallback").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"plain-raw-ok");

        fallback_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-sudoku-udp");
            upstream.send_to(b"pong-sudoku-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: true
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut stream = open_sudoku_udp_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
        )
        .unwrap();
        write_sudoku_udp_packet(&mut *stream, upstream_addr, b"ping-sudoku-udp").unwrap();
        let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-sudoku-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_udp_listener_end_to_end_with_keypair_material() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-sudoku-udp-keypair");
            upstream.send_to(b"pong-sudoku-udp-keypair", from).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-udp-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: true
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut stream = open_sudoku_udp_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            &private_key,
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
        )
        .unwrap();
        write_sudoku_udp_packet(&mut *stream, upstream_addr, b"ping-sudoku-udp-keypair").unwrap();
        let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-sudoku-udp-keypair");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_udp_custom_table_rotation_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-sudoku-udp-rotation");
            upstream.send_to(b"pong-sudoku-udp-rotation", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-udp-rotation");
        fs::write(
            temp.join("config.yaml"),
            r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: true
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");
        let custom_tables = vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()];

        let mut stream = open_sudoku_udp_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &custom_tables,
        )
        .unwrap();
        write_sudoku_udp_packet(&mut *stream, upstream_addr, b"ping-sudoku-udp-rotation").unwrap();
        let (target, payload) = read_sudoku_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-sudoku-udp-rotation");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_multiplex_listener_end_to_end() {
        let upstream_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_a_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_a.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloA");
            stream.write_all(b"replyA").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();
        let upstream_b_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_b.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloB");
            stream.write_all(b"replyB").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-mux");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut stream = open_sudoku_multiplex_test_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
            &TransportTarget::new("placeholder.invalid", 0),
        )
        .unwrap();
        let target_a = encode_test_sudoku_address(&upstream_a_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 1, &target_a);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 1, b"helloA");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 1, &[]);

        let target_b = encode_test_sudoku_address(&upstream_b_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 2, &target_b);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 2, b"helloB");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 2, &[]);

        let mut seen = std::collections::HashMap::new();
        for _ in 0..4 {
            let (frame_type, stream_id, payload) = read_test_sudoku_mux_frame(&mut *stream);
            seen.entry(stream_id)
                .or_insert_with(Vec::new)
                .push((frame_type, payload));
        }
        let stream1 = seen.remove(&1).expect("expected stream 1 frames");
        assert_eq!(stream1.len(), 2);
        assert_eq!(stream1[0].0, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream1[0].1, b"replyA");
        assert_eq!(stream1[1].0, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert!(stream1[1].1.is_empty());

        let stream2 = seen.remove(&2).expect("expected stream 2 frames");
        assert_eq!(stream2.len(), 2);
        assert_eq!(stream2[0].0, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream2[0].1, b"replyB");
        assert_eq!(stream2[1].0, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert!(stream2[1].1.is_empty());
        assert!(seen.is_empty());

        upstream_a_worker.join().unwrap();
        upstream_b_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_multiplex_listener_end_to_end_with_keypair_material() {
        let upstream_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_a_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_a.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloA");
            stream.write_all(b"replyA").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();
        let upstream_b_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_b.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloB");
            stream.write_all(b"replyB").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-mux-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: false
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");

        let mut stream = open_sudoku_multiplex_test_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
            &TransportTarget::new("placeholder.invalid", 0),
        )
        .unwrap();
        let target_a = encode_test_sudoku_address(&upstream_a_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 1, &target_a);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 1, b"helloA");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 1, &[]);

        let target_b = encode_test_sudoku_address(&upstream_b_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 2, &target_b);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 2, b"helloB");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 2, &[]);

        let (frame_type1, stream_id1, payload1) = read_test_sudoku_mux_frame(&mut *stream);
        assert_eq!(frame_type1, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream_id1, 1);
        assert_eq!(payload1, b"replyA");
        let (frame_type1_fin, stream_id1_fin, payload1_fin) = read_test_sudoku_mux_frame(&mut *stream);
        assert_eq!(frame_type1_fin, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert_eq!(stream_id1_fin, 1);
        assert!(payload1_fin.is_empty());

        let (frame_type2, stream_id2, payload2) = read_test_sudoku_mux_frame(&mut *stream);
        assert_eq!(frame_type2, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream_id2, 2);
        assert_eq!(payload2, b"replyB");
        let (frame_type2_fin, stream_id2_fin, payload2_fin) = read_test_sudoku_mux_frame(&mut *stream);
        assert_eq!(frame_type2_fin, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert_eq!(stream_id2_fin, 2);
        assert!(payload2_fin.is_empty());

        upstream_a_worker.join().unwrap();
        upstream_b_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_multiplex_custom_table_rotation_listener_end_to_end() {
        let upstream_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_a_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_a.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloA");
            stream.write_all(b"replyA").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();
        let upstream_b_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_b.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloB");
            stream.write_all(b"replyB").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-mux-rotation");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");
        let custom_tables = vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()];

        let mut stream = open_sudoku_multiplex_test_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &custom_tables,
            &TransportTarget::new("placeholder.invalid", 0),
        )
        .unwrap();
        let target_a = encode_test_sudoku_address(&upstream_a_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 1, &target_a);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 1, b"helloA");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 1, &[]);

        let target_b = encode_test_sudoku_address(&upstream_b_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 2, &target_b);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 2, b"helloB");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 2, &[]);

        let mut seen = std::collections::HashMap::new();
        for _ in 0..4 {
            let (frame_type, stream_id, payload) = read_test_sudoku_mux_frame(&mut *stream);
            seen.entry(stream_id)
                .or_insert_with(Vec::new)
                .push((frame_type, payload));
        }
        let stream1 = seen.remove(&1).expect("expected stream 1 frames");
        assert_eq!(stream1.len(), 2);
        assert_eq!(stream1[0].0, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream1[0].1, b"replyA");
        assert_eq!(stream1[1].0, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert!(stream1[1].1.is_empty());

        let stream2 = seen.remove(&2).expect("expected stream 2 frames");
        assert_eq!(stream2.len(), 2);
        assert_eq!(stream2[0].0, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream2[0].1, b"replyB");
        assert_eq!(stream2[1].0, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert!(stream2[1].1.is_empty());
        assert!(seen.is_empty());

        upstream_a_worker.join().unwrap();
        upstream_b_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_sudoku_multiplex_custom_table_rotation_listener_end_to_end_with_keypair_material(
    ) {
        let upstream_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_a_addr = upstream_a.local_addr().unwrap();
        let upstream_a_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_a.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloA");
            stream.write_all(b"replyA").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();
        let upstream_b_worker = thread::spawn(move || {
            let (mut stream, _) = upstream_b.accept().unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"helloB");
            stream.write_all(b"replyB").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let master = random_edwards_scalar();
        let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let split_r = random_edwards_scalar();
        let split_k = master - split_r;
        let mut private = [0_u8; 64];
        private[..32].copy_from_slice(&split_r.to_bytes());
        private[32..].copy_from_slice(&split_k.to_bytes());
        let public_key = hex_encode(&public);
        let private_key = hex_encode(&private);

        let temp = unique_temp_dir("mihomo-app-inbound-sudoku-mux-rotation-keypair");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: {public_key}
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
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
        let sudoku_addr = find_listener_addr(&app, "edge-sudoku", "sudoku");
        let custom_tables = vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()];

        let mut stream = open_sudoku_multiplex_test_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            &private_key,
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &custom_tables,
            &TransportTarget::new("placeholder.invalid", 0),
        )
        .unwrap();
        let target_a = encode_test_sudoku_address(&upstream_a_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 1, &target_a);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 1, b"helloA");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 1, &[]);

        let target_b = encode_test_sudoku_address(&upstream_b_addr.to_string());
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_OPEN, 2, &target_b);
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_DATA, 2, b"helloB");
        write_test_sudoku_mux_frame(&mut *stream, TEST_SUDOKU_MUX_FRAME_CLOSE, 2, &[]);

        let mut seen = std::collections::HashMap::new();
        for _ in 0..4 {
            let (frame_type, stream_id, payload) = read_test_sudoku_mux_frame(&mut *stream);
            seen.entry(stream_id)
                .or_insert_with(Vec::new)
                .push((frame_type, payload));
        }
        let stream1 = seen.remove(&1).expect("expected stream 1 frames");
        assert_eq!(stream1.len(), 2);
        assert_eq!(stream1[0].0, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream1[0].1, b"replyA");
        assert_eq!(stream1[1].0, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert!(stream1[1].1.is_empty());

        let stream2 = seen.remove(&2).expect("expected stream 2 frames");
        assert_eq!(stream2.len(), 2);
        assert_eq!(stream2[0].0, TEST_SUDOKU_MUX_FRAME_DATA);
        assert_eq!(stream2[0].1, b"replyB");
        assert_eq!(stream2[1].0, TEST_SUDOKU_MUX_FRAME_CLOSE);
        assert!(stream2[1].1.is_empty());
        assert!(seen.is_empty());

        upstream_a_worker.join().unwrap();
        upstream_b_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_packed_downlink_proxy_end_to_end() {
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
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "packed.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-packed-sudoku").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-packed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 10
    padding-max: 30
    enable-pure-downlink: false
    http-mask: false
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: packed.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-packed-sudoku");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_stream_http_mask_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
        let mut proxy = SudokuHttpMaskTestServer::start(
            SudokuHttpMaskTestMode::Stream,
            "secret-seed",
            "mask",
            "cdn.example.com:8443",
        );
        let proxy_addr = proxy.addr;
        let proxy_worker = thread::spawn(move || {
            let stream = proxy.next_stream();
            let session = accept_sudoku_test_stream(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-stream").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-stream");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    http-mask-host: cdn.example.com:8443
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-stream");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_poll_http_mask_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
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
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "poll.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-poll").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-poll");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: poll
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: poll.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-poll");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_stream_http_mask_over_tls_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
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
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-stream-tls").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-stream-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: stream
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-stream-tls");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_auto_http_mask_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
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
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "auto.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-auto").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-auto");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: auto
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: auto.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-auto");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_auto_http_mask_over_tls_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
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
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "auto-tls.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-auto-tls").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-auto-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: auto
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: auto-tls.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-auto-tls");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_nested_httpmask_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
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
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "nested.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-nested").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-nested-httpmask");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    httpmask:
      disable: false
      mode: auto
      tls: true
      host: localhost:8443
      path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: nested.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-nested");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_poll_http_mask_over_tls_proxy_end_to_end() {
        let _guard = sudoku_httpmask_test_guard();
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
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "poll-tls.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-poll-tls").unwrap();
            stream.shutdown_write().unwrap();
            proxy.assert_clean();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-poll-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: poll
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: poll-tls.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-poll-tls");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_ws_http_mask_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.contains("GET /mask/ws HTTP/1.1\r\n"));
            assert!(request.contains("Host: cdn.example.com:8443\r\n"));
            assert!(request.contains("X-Sudoku-Tunnel: ws\r\n"));
            assert!(request.contains("X-Sudoku-Version: 1\r\n"));
            let session = accept_sudoku_test_stream(
                stream,
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-ws").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    http-mask-host: cdn.example.com:8443
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-ws");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_wss_http_mask_proxy_end_to_end() {
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
            assert!(request.contains("X-Sudoku-Tunnel: ws\r\n"));
            assert!(request.contains("X-Sudoku-Version: 1\r\n"));
            let session = accept_sudoku_test_stream(
                stream,
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-wss").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-wss");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 10
    padding-max: 30
    http-mask: true
    http-mask-mode: ws
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-wss");

        proxy_worker.join().unwrap();
        app.shutdown();
    }


    #[test]
    fn start_serves_custom_tunnel_listener_with_sudoku_custom_table_rotation_proxy_end_to_end() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            let session = accept_sudoku_test_stream_with_custom_tables(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
                "",
                &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-rot").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-custom-rotation");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: sudoku
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
    padding-min: 10
    padding-max: 30
    http-mask: false
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = proxy_addr.port(),
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
        assert_eq!(reply, b"pong-sudoku-rot");

        proxy_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_proxy_end_to_end() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "final.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-vless");

        worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_custom_http_listener_with_vless_proxy_without_client_half_close() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "final.example.com:80");

            stream.write_all(&[0x00, 0x00]).unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("GET /hello HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .unwrap();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-http-vless-no-half-close");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
mode: global
hosts:
  final.example.com: 127.0.0.1
dns:
  enable: true
  use-hosts: true
  use-system-hosts: false
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
listeners:
  - type: http
    name: http-proxy
    listen: 127.0.0.1
    port: "0"
    proxy: relay
"#,
                relay_port = tls_addr.port(),
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
        let proxy_addr = find_listener_addr(&app, "http-proxy", "http");

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(
            client,
            "GET http://final.example.com/hello HTTP/1.1\r\nHost: final.example.com\r\nConnection: keep-alive\r\n\r\n"
        )
        .unwrap();
        let response = read_http_response_message(&mut client);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("\r\n\r\nok"));

        worker.join().unwrap();
        app.shutdown();
    }
    #[test]
    fn start_serves_vless_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong-vless-in").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vless");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-in");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vless_listener_with_ws_network_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-ws-in").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vless-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: ws
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    ws-opts:
      path: /edge-vless
      headers:
        Host: localhost
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let client_stream = Box::new(connect_websocket_client_stream(
            vless_addr,
            "/edge-vless",
            Some("localhost"),
        ));
        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            client_stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-ws-in");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vless_listener_with_h2_network_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-h2-in").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vless-h2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: h2
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    h2-opts:
      host: [localhost]
      path: /edge-h2
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let client_stream = mihomo_transport::wrap_h2_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            &mihomo_transport::Http2Options {
                host: vec!["localhost".into()],
                path: "/edge-h2".into(),
            },
        )
        .unwrap();
        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            client_stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-h2-in");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vless_listener_with_grpc_network_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-grpc-in").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vless-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: grpc
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let client_stream = mihomo_transport::wrap_grpc_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            client_stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-grpc-in");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vless_listener_with_http_network_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-http-in").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vless-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: http
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    http-opts:
      method: GET
      host: [localhost]
      path: [/edge-http]
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let client_stream = mihomo_transport::wrap_http_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/edge-http".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            client_stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-http-in");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vless_listener_with_xhttp_stream_one_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-in").unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vless-xhttp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-one
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let client_stream = mihomo_transport::wrap_xhttp_proxy_stream(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            mihomo_transport::TransportTarget::new(vless_addr.ip().to_string(), vless_addr.port()),
            &mihomo_transport::XHttpOptions {
                host: "localhost".into(),
                path: "/vx".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            client_stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &mihomo_transport::TransportTarget::new("127.0.0.1", upstream_addr.port()),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-xhttp-in");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_shadowsocks_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
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
    fn vless_listener_rejects_unknown_uuid() {
        let temp = unique_temp_dir("mihomo-app-inbound-vless-auth");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
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
        let vless_addr = find_listener_addr(&app, "edge-vless", "vless");

        let mut client = mihomo_transport::open_vless_tcp_stream_for_tests(
            Box::new(TcpStream::connect(vless_addr).unwrap()),
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            &mihomo_transport::TransportTarget::new("127.0.0.1", 80),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        match client.read_to_end(&mut reply) {
            Ok(_) => assert!(reply.is_empty(), "{reply:?}"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset),
        }

        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_packetaddr_xudp_tcp_end_to_end() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "final.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-px").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-packetaddr-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    packet-addr: true
    xudp: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-vless-px");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_http_listener_with_vmess_proxy_without_client_half_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:80");
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("GET /hello HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .unwrap();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-http-vmess-no-half-close");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  final.example.com: 127.0.0.1
dns:
  enable: true
  use-hosts: true
  use-system-hosts: false
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: http
    name: http-proxy
    listen: 127.0.0.1
    port: "0"
    proxy: relay
"#,
                relay_port = listen_addr.port(),
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
        let proxy_addr = find_listener_addr(&app, "http-proxy", "http");

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(
            client,
            "GET http://final.example.com/hello HTTP/1.1\r\nHost: final.example.com\r\nConnection: keep-alive\r\n\r\n"
        )
        .unwrap();
        let response = read_http_response_message(&mut client);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("\r\n\r\nok"));

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 5];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping!");
            stream.write_all(b"pong-vmess-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: tcp
  - type: tunnel
    name: tcp-forward
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "tcp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping!").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-udp");
            upstream.send_to(b"pong-vmess-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: tcp
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let mut stream = mihomo_transport::open_vmess_udp_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xudp");
            upstream.send_to(b"pong-vmess-xudp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: tcp
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-pa");
            upstream.send_to(b"pong-vmess-pa", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: tcp
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload = mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let milestones = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let milestones_worker = Arc::clone(&milestones);
        let upstream_worker = thread::spawn(move || {
            milestones_worker.lock().unwrap().push("upstream-accept");
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            milestones_worker.lock().unwrap().push("upstream-read");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-ws-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: ws
    ws-opts:
      path: /ws
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "ws".into(),
                    websocket: mihomo_transport::WebsocketOptions {
                        path: "/ws".into(),
                        ..Default::default()
                    },
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        let read_err = client.read_to_end(&mut reply).err();
        if let Some(err) = read_err {
            panic!(
                "vmess ws inbound read failed: {err}; milestones={:?}",
                milestones.lock().unwrap().clone()
            );
        }
        assert_eq!(reply, b"pong-vmess-ws-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-ws-udp");
            upstream.send_to(b"pong-vmess-ws-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-udp
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_websocket_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: "/ws-udp".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-ws-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-ws-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-ws-xudp");
            upstream.send_to(b"pong-vmess-ws-xudp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-xudp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-xudp
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_websocket_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: "/ws-xudp".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-ws-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-ws-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-ws-pa");
            upstream.send_to(b"pong-vmess-ws-pa", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-pa
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_websocket_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: "/ws-pa".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-ws-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-ws-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_query_early_data_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-ws-ed").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-ed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-early
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "ws".into(),
                    websocket: mihomo_transport::WebsocketOptions {
                        path: "/ws-early?ed=2048&foo=bar".into(),
                        ..Default::default()
                    },
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-ws-ed");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_header_early_data_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-ws-hed").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-header-ed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-header-early
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "ws".into(),
                    websocket: mihomo_transport::WebsocketOptions {
                        path: "/ws-header-early".into(),
                        max_early_data: 2048,
                        early_data_header_name: "Sec-WebSocket-Protocol".into(),
                        ..Default::default()
                    },
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-ws-hed");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_http_upgrade_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-ws-upgrade").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-upgrade");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-upgrade-plain
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "ws".into(),
                    websocket: mihomo_transport::WebsocketOptions {
                        path: "/ws-upgrade-plain".into(),
                        v2ray_http_upgrade: true,
                        ..Default::default()
                    },
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-ws-upgrade");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "grpc".into(),
                    websocket: Default::default(),
                    grpc: mihomo_transport::GrpcOptions {
                        service_name: "example".into(),
                        ..Default::default()
                    },
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-grpc-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-grpc-udp");
            upstream.send_to(b"pong-vmess-grpc-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_grpc_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-grpc-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-grpc-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-grpc-xudp");
            upstream.send_to(b"pong-vmess-grpc-xudp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-xudp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_grpc_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-grpc-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-grpc-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-grpc-pa");
            upstream.send_to(b"pong-vmess-grpc-pa", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_grpc_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-grpc-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-grpc-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmh2
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "h2".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: mihomo_transport::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vmh2".into(),
                    },
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-h2-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-h2-udp");
            upstream.send_to(b"pong-vmess-h2-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_h2_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            &mihomo_transport::Http2Options {
                host: vec!["localhost".into()],
                path: "/vmuh2".into(),
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-h2-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-h2-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-h2-xudp");
            upstream.send_to(b"pong-vmess-h2-xudp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-xudp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2x
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_h2_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            &mihomo_transport::Http2Options {
                host: vec!["localhost".into()],
                path: "/vmuh2x".into(),
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-h2-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-h2-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-h2-pa");
            upstream.send_to(b"pong-vmess-h2-pa", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2pa
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_h2_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            &mihomo_transport::Http2Options {
                host: vec!["localhost".into()],
                path: "/vmuh2pa".into(),
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-h2-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-h2-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let milestones = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let milestones_worker = Arc::clone(&milestones);
        let upstream_worker = thread::spawn(move || {
            milestones_worker.lock().unwrap().push("upstream-accept");
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            milestones_worker.lock().unwrap().push("upstream-read");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2-tls-inbound").unwrap();
            milestones_worker.lock().unwrap().push("upstream-write");
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmh2
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "h2".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: mihomo_transport::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vmh2".into(),
                    },
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
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
        let read_err = client.read_to_end(&mut reply).err();
        if let Some(err) = read_err {
            panic!(
                "vmess h2 tls inbound read failed: {err}; milestones={:?}",
                milestones.lock().unwrap().clone()
            );
        }
        assert_eq!(reply, b"pong-vmess-h2-tls-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_tls_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-h2-tls-udp");
            upstream.send_to(b"pong-vmess-h2-tls-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2tls
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
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
                path: "/vmuh2tls".into(),
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-h2-tls-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-h2-tls-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_tls_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-h2-tls-xudp");
            upstream.send_to(b"pong-vmess-h2-tls-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2tlsx
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
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
                path: "/vmuh2tlsx".into(),
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-h2-tls-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-h2-tls-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_h2_tls_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-h2-tls-pa");
            upstream.send_to(b"pong-vmess-h2-tls-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-h2-tls-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2tlspa
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_h2_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
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
                path: "/vmuh2tlspa".into(),
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-h2-tls-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-h2-tls-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmx
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmx".into(),
                        host: "localhost".into(),
                        mode: "stream-one".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_stream_up_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-su").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-stream-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxsu
      host: localhost
      mode: stream-up
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxsu".into(),
                        host: "localhost".into(),
                        mode: "stream-up".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-su");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pu").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpu
      host: localhost
      mode: packet-up
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpu".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut client = executor.run_plan(&plan).unwrap();
        client.write_all(b"pi").unwrap();
        client.write_all(b"ng").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-xhttp-pu");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_download_settings_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pd").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-download-settings");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpu
      host: upload.local
      mode: packet-up
      download-settings:
        host: download.local
        path: /vmxpd
        headers:
          X-Download: yes
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpu".into(),
                        host: "upload.local".into(),
                        mode: "packet-up".into(),
                        has_download_settings: true,
                        download_host: "download.local".into(),
                        download_path: "/vmxpd".into(),
                        download_headers: BTreeMap::from([(
                            "X-Download".into(),
                            "yes".into(),
                        )]),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-pd");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_cookie_meta_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pc").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-cookie-meta");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpc
      host: localhost
      mode: packet-up
      session-placement: header
      session-key: X-Session
      seq-placement: cookie
      seq-key: x_seq
      uplink-data-placement: cookie
      uplink-data-key: x_data
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpc".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        session_placement: "header".into(),
                        session_key: "X-Session".into(),
                        seq_placement: "cookie".into(),
                        seq_key: "x_seq".into(),
                        uplink_data_placement: "cookie".into(),
                        uplink_data_key: "x_data".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-pc");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_buffered_upload_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let milestones = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let milestones_worker = Arc::clone(&milestones);
        let upstream_worker = thread::spawn(move || {
            milestones_worker.lock().unwrap().push("upstream-accept");
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 7];
            stream.read_exact(&mut payload).unwrap();
            milestones_worker.lock().unwrap().push("upstream-read");
            assert_eq!(&payload, b"abcdefg");
            stream.write_all(b"pong-vmess-xhttp-pb").unwrap();
            milestones_worker.lock().unwrap().push("upstream-write");
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-buffered");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpb
      host: localhost
      mode: packet-up
      sc-max-each-post-bytes: "3"
      sc-min-posts-interval-ms: "1000"
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpb".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        sc_max_each_post_bytes: "3".into(),
                        sc_min_posts_interval_ms: "1000".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut client = executor.run_plan(&plan).unwrap();
        client.write_all(b"abcdefg").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        let read_err = client.read_to_end(&mut reply).err();
        if let Some(err) = read_err {
            panic!(
                "vmess xhttp packet-up buffered inbound read failed: {err}; milestones={:?}; partial_reply={:?}",
                milestones.lock().unwrap().clone()
                , reply
            );
        }
        assert_eq!(reply, b"pong-vmess-xhttp-pb");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_auto_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-auto").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-auto");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxa
      host: localhost
      mode: auto
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxa".into(),
                        host: "localhost".into(),
                        mode: "auto".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-auto");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_query_meta_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pq").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-query");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpq
      host: localhost
      mode: packet-up
      session-placement: query
      session-key: sid
      seq-placement: query
      seq-key: n
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpq".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        session_placement: "query".into(),
                        session_key: "sid".into(),
                        seq_placement: "query".into(),
                        seq_key: "n".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-pq");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_stream_up_download_settings_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-sd").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-stream-up-download-settings");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxsu
      host: upload.local
      mode: stream-up
      download-settings:
        host: download.local
        path: /vmxsd
        headers:
          X-Download: yes
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxsu".into(),
                        host: "upload.local".into(),
                        mode: "stream-up".into(),
                        has_download_settings: true,
                        download_host: "download.local".into(),
                        download_path: "/vmxsd".into(),
                        download_headers: BTreeMap::from([(
                            "X-Download".into(),
                            "yes".into(),
                        )]),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-sd");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_no_grpc_header_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-nogrpc").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-no-grpc-header");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxnogrpc
      host: localhost
      mode: stream-one
      no-grpc-header: true
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxnogrpc".into(),
                        host: "localhost".into(),
                        mode: "stream-one".into(),
                        no_grpc_header: true,
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-nogrpc");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_header_data_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-ph").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-header-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxph
      host: localhost
      mode: packet-up
      uplink-data-placement: header
      uplink-data-key: x-data
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxph".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        uplink_data_placement: "header".into(),
                        uplink_data_key: "x-data".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-ph");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_empty_cookie_key_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pck").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-empty-cookie-key");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpck
      host: localhost
      mode: packet-up
      uplink-data-placement: cookie
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpck".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        uplink_data_placement: "cookie".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-pck");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_without_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-notls-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-notls");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: xhttp
    xhttp-opts:
      path: /vmxn
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxn".into(),
                        host: "localhost".into(),
                        mode: "stream-one".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions::default(),
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-notls-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_stream_up_without_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-sn-notls").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-stream-up-notls");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: xhttp
    xhttp-opts:
      path: /vmxsn
      host: localhost
      mode: stream-up
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxsn".into(),
                        host: "localhost".into(),
                        mode: "stream-up".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions::default(),
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-sn-notls");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packet_up_without_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pn-notls").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packet-up-notls");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: xhttp
    xhttp-opts:
      path: /vmxpn
      host: localhost
      mode: packet-up
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxpn".into(),
                        host: "localhost".into(),
                        mode: "packet-up".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions::default(),
                    alpn: vec!["h2".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", upstream_addr.port()),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut client = executor.run_plan(&plan).unwrap();
        client.write_all(b"pi").unwrap();
        client.write_all(b"ng").unwrap();
        client.shutdown_write().unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-xhttp-pn-notls");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-http-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: http
    http-opts:
      path: [/vmh]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "http".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: mihomo_transport::HttpStreamOptions {
                        method: "GET".into(),
                        host: vec!["localhost".into()],
                        path: vec!["/vmh".into()],
                        headers: BTreeMap::new(),
                    },
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-http-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-http-tls-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: http
    http-opts:
      path: [/vmht]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "http".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: mihomo_transport::HttpStreamOptions {
                        method: "GET".into(),
                        host: vec!["localhost".into()],
                        path: vec!["/vmht".into()],
                        headers: BTreeMap::new(),
                    },
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-http-tls-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_headers_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-http-headers-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-headers");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: http
    http-opts:
      path: [/vmhh]
      host: [localhost]
      headers:
        X-Test: [yes]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "http".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: mihomo_transport::HttpStreamOptions {
                        method: "GET".into(),
                        host: vec!["localhost".into()],
                        path: vec!["/vmhh".into()],
                        headers: BTreeMap::from([("X-Test".into(), vec!["yes".into()])]),
                    },
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-http-headers-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_mtls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-mtls").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-mtls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxmtls
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "xhttp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: mihomo_transport::XHttpOptions {
                        path: "/vmxmtls".into(),
                        host: "localhost".into(),
                        mode: "stream-one".into(),
                        ..Default::default()
                    },
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: client_cert_pem.clone(),
                        private_key: client_key_pem.clone(),
                    },
                    alpn: vec!["h2".into()],
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
        assert_eq!(reply, b"pong-vmess-xhttp-mtls");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_mtls_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xhttp-mtls-udp");
            upstream.send_to(b"pong-vmess-xhttp-mtls-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-mtls-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxmtlsu
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
            },
            &["h2".into()],
            &mihomo_transport::XHttpOptions {
                path: "/vmxmtlsu".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-xhttp-mtls-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-xhttp-mtls-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_mtls_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xhttp-mtls-xudp");
            upstream.send_to(b"pong-vmess-xhttp-mtls-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-mtls-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxmtlsx
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
            },
            &["h2".into()],
            &mihomo_transport::XHttpOptions {
                path: "/vmxmtlsx".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-xhttp-mtls-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-xhttp-mtls-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_mtls_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xhttp-mtls-pa");
            upstream.send_to(b"pong-vmess-xhttp-mtls-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-mtls-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxmtlspa
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
            },
            &["h2".into()],
            &mihomo_transport::XHttpOptions {
                path: "/vmxmtlspa".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload = mihomo_transport::encode_packetaddr_udp_packet(
            upstream_addr,
            b"ping-vmess-xhttp-mtls-pa",
        );
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-xhttp-mtls-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_mtls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-http-mtls").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-mtls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: http
    http-opts:
      path: [/vmhmtls]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "http".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: mihomo_transport::HttpStreamOptions {
                        method: "GET".into(),
                        host: vec!["localhost".into()],
                        path: vec!["/vmhmtls".into()],
                        headers: BTreeMap::new(),
                    },
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: client_cert_pem.clone(),
                        private_key: client_key_pem.clone(),
                    },
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-http-mtls");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_mtls_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-mtls-udp");
            upstream.send_to(b"pong-vmess-http-mtls-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-mtls-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: http
    http-opts:
      path: [/vmhmtlsu]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
            },
            &[],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_http_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmhmtlsu".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-http-mtls-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-http-mtls-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_mtls_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-mtls-xudp");
            upstream.send_to(b"pong-vmess-http-mtls-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-mtls-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: http
    http-opts:
      path: [/vmhmtlsx]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
            },
            &[],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_http_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmhmtlsx".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-http-mtls-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-http-mtls-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_mtls_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-mtls-pa");
            upstream.send_to(b"pong-vmess-http-mtls-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-mtls-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    client-auth-type: require
    client-auth-cert: |
{client_cert_pem}
    network: http
    http-opts:
      path: [/vmhmtlspa]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: client_cert_pem.clone(),
                private_key: client_key_pem.clone(),
            },
            &[],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_http_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmhmtlspa".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload = mihomo_transport::encode_packetaddr_udp_packet(
            upstream_addr,
            b"ping-vmess-http-mtls-pa",
        );
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-http-mtls-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_tls_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-tls-udp");
            upstream.send_to(b"pong-vmess-http-tls-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-tls-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: http
    http-opts:
      path: [/vmuhtls]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &[],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_http_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmuhtls".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-http-tls-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-http-tls-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_tls_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-tls-pa");
            upstream.send_to(b"pong-vmess-http-tls-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-tls-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: http
    http-opts:
      path: [/vmuhtlspa]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &[],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_http_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmuhtlspa".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload = mihomo_transport::encode_packetaddr_udp_packet(
            upstream_addr,
            b"ping-vmess-http-tls-pa",
        );
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-http-tls-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_tls_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-tls-xudp");
            upstream.send_to(b"pong-vmess-http-tls-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-tls-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: http
    http-opts:
      path: [/vmuhtlsx]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &[],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_http_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmuhtlsx".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-http-tls-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-http-tls-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-udp");
            upstream.send_to(b"pong-vmess-http-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: http
    http-opts:
      path: [/vmuh]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_http_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmuh".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-http-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-http-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-pa");
            upstream.send_to(b"pong-vmess-http-pa", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: http
    http-opts:
      path: [/vmuhpa]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_http_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmuhpa".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-http-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-http-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xhttp-udp");
            upstream.send_to(b"pong-vmess-xhttp-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxudp
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
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
                path: "/vmxudp".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-xhttp-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-xhttp-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xhttp-pa");
            upstream.send_to(b"pong-vmess-xhttp-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxpa
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
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
                path: "/vmxpa".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-xhttp-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-xhttp-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_xhttp_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-xhttp-xudp");
            upstream.send_to(b"pong-vmess-xhttp-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-xhttp-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    tls: true
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
    network: xhttp
    xhttp-opts:
      path: /vmxxu
      host: localhost
      mode: stream-one
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_xhttp_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
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
                path: "/vmxxu".into(),
                host: "localhost".into(),
                mode: "stream-one".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-xhttp-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-xhttp-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_http_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-http-xudp");
            upstream.send_to(b"pong-vmess-http-xudp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-http-xudp");
        fs::write(
            temp.join("config.yaml"),
            r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: http
    http-opts:
      path: [/vmuxh]
      host: [localhost]
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_http_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::HttpStreamOptions {
                method: "GET".into(),
                host: vec!["localhost".into()],
                path: vec!["/vmuxh".into()],
                headers: BTreeMap::new(),
            },
        );
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-http-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-http-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let milestones = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let milestones_worker = Arc::clone(&milestones);
        let upstream_worker = thread::spawn(move || {
            milestones_worker.lock().unwrap().push("upstream-accept");
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            milestones_worker.lock().unwrap().push("upstream-read");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-tls-inbound").unwrap();
            milestones_worker.lock().unwrap().push("upstream-write");
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "tcp".into(),
                    websocket: Default::default(),
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
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
        let read_err = client.read_to_end(&mut reply).err();
        if let Some(err) = read_err {
            panic!(
                "vmess tls inbound read failed: {err}; milestones={:?}",
                milestones.lock().unwrap().clone()
            );
        }
        assert_eq!(reply, b"pong-vmess-tls-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_wss_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-wss-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-wss");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "ws".into(),
                    websocket: mihomo_transport::WebsocketOptions {
                        path: "/ws".into(),
                        ..Default::default()
                    },
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-wss-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_wss_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-wss-udp");
            upstream.send_to(b"pong-vmess-wss-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-wss-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /wss-udp
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["http/1.1".into()],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: "/wss-udp".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-wss-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-wss-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_wss_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-wss-xudp");
            upstream.send_to(b"pong-vmess-wss-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-wss-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /wss-xudp
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["http/1.1".into()],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: "/wss-xudp".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-wss-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-wss-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_wss_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-wss-pa");
            upstream.send_to(b"pong-vmess-wss-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-wss-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /wss-pa
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["http/1.1".into()],
        )
        .unwrap();
        let stream = mihomo_transport::wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: "/wss-pa".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload =
            mihomo_transport::encode_packetaddr_udp_packet(upstream_addr, b"ping-vmess-wss-pa");
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-wss-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_tls_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc-tls-inbound").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-tls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "grpc".into(),
                    websocket: Default::default(),
                    grpc: mihomo_transport::GrpcOptions {
                        service_name: "example".into(),
                        ..Default::default()
                    },
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: mihomo_transport::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-grpc-tls-inbound");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_tls_udp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-grpc-tls-udp");
            upstream.send_to(b"pong-vmess-grpc-tls-udp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-tls-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_grpc_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            upstream_addr,
        )
        .unwrap();
        write_vmess_udp_packet(&mut *stream, b"ping-vmess-grpc-tls-udp").unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"pong-vmess-grpc-tls-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_tls_xudp_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-grpc-tls-xudp");
            upstream.send_to(b"pong-vmess-grpc-tls-xudp", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-tls-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_grpc_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_xudp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_vmess_xudp_packet(&mut *stream, upstream_addr, b"ping-vmess-grpc-tls-xudp").unwrap();
        let (target, payload) = read_vmess_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(payload, b"pong-vmess-grpc-tls-xudp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_grpc_tls_packetaddr_listener_end_to_end() {
        let _guard = sudoku_udp_test_guard();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-vmess-grpc-tls-pa");
            upstream.send_to(b"pong-vmess-grpc-tls-pa", from).unwrap();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-grpc-tls-packetaddr");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: 0
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: grpc
    grpc-service-name: example
    certificate: |
{cert_pem}
    private-key: |
{key_pem}
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let stream = mihomo_transport::wrap_grpc_tls_proxy_stream(
            Box::new(TcpStream::connect(vmess_addr).unwrap()),
            TransportTarget::new("127.0.0.1", vmess_addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &mihomo_transport::GrpcOptions {
                service_name: "example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mihomo_transport::open_vmess_packetaddr_udp_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
        )
        .unwrap();
        let payload = mihomo_transport::encode_packetaddr_udp_packet(
            upstream_addr,
            b"ping-vmess-grpc-tls-pa",
        );
        write_vmess_udp_packet(&mut *stream, &payload).unwrap();
        let payload = read_vmess_udp_packet(&mut *stream).unwrap();
        let (target, packet) = decode_packetaddr_udp_packet(&payload).unwrap();
        assert_eq!(target, upstream_addr);
        assert_eq!(packet, b"pong-vmess-grpc-tls-pa");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_vmess_ws_http_upgrade_fast_open_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-ws-up").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-inbound-vmess-ws-upgrade");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - username: test
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
    ws-path: /ws-upgrade
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
        let vmess_addr = find_listener_addr(&app, "edge-vmess", "vmess");

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", vmess_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "ws".into(),
                    websocket: mihomo_transport::WebsocketOptions {
                        path: "/ws-upgrade".into(),
                        v2ray_http_upgrade: true,
                        v2ray_http_upgrade_fast_open: true,
                        ..Default::default()
                    },
                    grpc: Default::default(),
                    h2: Default::default(),
                    http: Default::default(),
                    xhttp: Default::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: Default::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess-ws-up");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_packetaddr_xudp_tcp_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-px").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-packetaddr-xudp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    packet-addr: true
    xudp: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-px");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-ws.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-ws").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-ws.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-ws");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_ignored_early_data_header_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-ignored-ed HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(!request.contains("X-Ignored-Early:"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-ws-ignored-ed.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-ws-ignored-ed").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws-ignored-ed");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-ignored-ed
      early-data-header-name: X-Ignored-Early
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-ws-ignored-ed.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-ws-ignored-ed");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_http_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) = accept_http_stream_test(Box::new(stream));
            assert!(request.starts_with("GET /vh HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-http.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-http").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: http
    http-opts:
      path: [/vh]
      host: [localhost]
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-http.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-http");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_early_data_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_early_data_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-early HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: "));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-wsed.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-wsed").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws-early-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-early
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-wsed.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-wsed");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_query_early_data_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_early_data_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-query-early?foo=bar HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: "));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-wsqed.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-wsqed").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws-query-early-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-query-early?ed=2048&foo=bar
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-wsqed.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-wsqed");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_http_upgrade_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_upgrade_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-upgrade HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-wsup.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-wsup").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws-http-upgrade");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-upgrade
      v2ray-http-upgrade: true
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-wsup.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-wsup");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_early_data_http_upgrade_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_upgrade_early_data_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-upgrade-early HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: "));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-wsued.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-wsued").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws-early-data-http-upgrade");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-upgrade-early
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      v2ray-http-upgrade: true
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-wsued.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-wsued");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_ws_http_upgrade_fast_open_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_upgrade_fast_open_test_stream(stream);
            assert!(request.starts_with("GET /vless-upgrade-fast HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-wsupf.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-wsupf").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-ws-http-upgrade-fast-open");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-upgrade-fast
      v2ray-http-upgrade: true
      v2ray-http-upgrade-fast-open: true
      headers:
        Host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-wsupf.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-wsupf");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_h2_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vh2");
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-h2.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-h2").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-h2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: h2
    h2-opts:
      host: [localhost]
      path: /vh2
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-h2.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-h2");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_grpc_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/example/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-grpc.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-grpc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: grpc
    grpc-opts:
      grpc-service-name: example
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-grpc.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-grpc");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vx/");
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_without_tls_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vxn/");
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-notls.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-notls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts:
      path: /vxn
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-notls.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-notls");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_without_tls_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream_a, _) = listener.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = listener.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request, upload_stream)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxsn/"));
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);
            assert_eq!(
                upload_request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-sn.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-sn").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts:
      path: /vxsn
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-sn.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-sn");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxs/"));

            let (upload_stream, _) = listener.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);
            assert_eq!(
                upload_request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-s.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-s").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxs
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-s.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-s");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_reuse_settings_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxsr/"));

            let (upload_stream, _) = listener.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);
            assert_eq!(
                upload_request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-r.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-r").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up-reuse-settings");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxsr
      host: localhost
      mode: stream-up
      reuse-settings:
        max-concurrency: "8"
      download-settings:
        reuse-settings: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-r.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-r");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_no_grpc_header_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vxnogrpc/");
            assert!(!request.headers.contains_key("content-type"));
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-nogrpc.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-nogrpc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-no-grpc-header");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxnogrpc
      host: localhost
      mode: stream-one
      no-grpc-header: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-nogrpc.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-nogrpc");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_obfs_tokenish_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vxobfs/");
            let pad = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-pad"))
                .map(|(_, value)| value.as_str())
                .unwrap();
            assert_eq!(pad.len(), 12);
            assert!(pad.chars().all(|ch| ch.is_ascii_alphanumeric()));
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-obfs.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-obfs").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-obfs-tokenish");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxobfs
      host: localhost
      mode: stream-one
      x-padding-bytes: "12"
      x-padding-obfs-mode: true
      x-padding-method: tokenish
      x-padding-placement: header
      x-padding-key: pad
      x-padding-header: X-Pad
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-obfs.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-obfs");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_obfs_query_in_header_overwrites_existing_query_end_to_end()
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vxobfsq?foo=bar/");
            let pad = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-pad"))
                .map(|(_, value)| value.as_str())
                .unwrap();
            assert!(pad.starts_with("https://localhost/vxobfsq?pad="));
            assert!(!pad.contains("foo=bar"));
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            let (version, uuid, command, target) = read_vless_request(&mut *stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-obfs-query.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-obfs-query").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-obfs-query-in-header");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxobfsq?foo=bar
      host: localhost
      mode: stream-one
      x-padding-bytes: "8"
      x-padding-obfs-mode: true
      x-padding-placement: queryInHeader
      x-padding-key: pad
      x-padding-header: X-Pad
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-obfs-query.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-obfs-query");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_download_settings_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "download.local");
            assert_eq!(
                download_request.headers.get("x-download").map(String::as_str),
                Some("yes")
            );
            let session_id = download_request.path.strip_prefix("/vxsd/").unwrap();

            let (upload_stream, _) = listener.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "upload.local");
            assert_eq!(upload_request.path, format!("/vxsu/{session_id}"));

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-sd.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-sd").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up-download-settings");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxsu
      host: upload.local
      mode: stream-up
      download-settings:
        host: download.local
        path: /vxsd
        headers:
          X-Download: yes
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-sd.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-sd");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_download_transport_proxy_end_to_end() {
        let upload_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upload_addr = upload_listener.local_addr().unwrap();
        let download_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let download_addr = download_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_tx, download_rx) = mpsc::sync_channel(1);
            let download_worker = thread::spawn(move || {
                let (download_stream, _) = download_listener.accept().unwrap();
                let (download_request, download_stream) =
                    accept_h2_test_stream(Box::new(download_stream)).unwrap();
                download_tx.send((download_request, download_stream)).unwrap();
            });
            let (upload_stream, _) = upload_listener.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            let (download_request, download_stream) = download_rx.recv().unwrap();
            download_worker.join().unwrap();

            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "upload.local");
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "download.local");
            assert!(upload_request.path.starts_with("/vxut/"));
            assert!(download_request.path.starts_with("/vxdt/"));

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-st.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-st").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up-download-transport");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {upload_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxut
      host: upload.local
      mode: stream-up
      download-settings:
        server: 127.0.0.1
        port: {download_port}
        tls: false
        host: download.local
        path: /vxdt
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-st.example.com:443
"#,
                upload_port = upload_addr.port(),
                download_port = download_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-st");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_download_transport_mtls_proxy_end_to_end() {
        let upload_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upload_addr = upload_listener.local_addr().unwrap();
        let download_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let download_addr = download_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let client_cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let client_cert_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();
        let download_tls_config =
            build_tls_server_config_with_client_auth(client_cert.cert.der().to_vec());
        let worker = thread::spawn(move || {
            let (download_tx, download_rx) = mpsc::sync_channel(1);
            let download_worker = thread::spawn(move || {
                let (download_stream, _) = download_listener.accept().unwrap();
                let (download_request, download_stream) =
                    accept_h2_tls_test_stream(Box::new(download_stream), download_tls_config).unwrap();
                download_tx.send((download_request, download_stream)).unwrap();
            });
            let (upload_stream, _) = upload_listener.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), tls_config).unwrap();
            let (download_request, download_stream) = download_rx.recv().unwrap();
            download_worker.join().unwrap();

            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "upload.local");
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "download.local");
            assert!(upload_request.path.starts_with("/vxum/"));
            assert!(download_request.path.starts_with("/vxdm/"));

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-stm.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-stm").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up-download-transport-mtls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {upload_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxum
      host: upload.local
      mode: stream-up
      download-settings:
        server: 127.0.0.1
        port: {download_port}
        tls: true
        servername: localhost
        skip-cert-verify: true
        certificate: |
{client_cert_pem}
        private-key: |
{client_key_pem}
        host: download.local
        path: /vxdm
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-stm.example.com:443
"#,
                upload_port = upload_addr.port(),
                download_port = download_addr.port(),
                client_cert_pem = indent_block(client_cert_pem.trim_end(), 10),
                client_key_pem = indent_block(client_key_pem.trim_end(), 10),
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
        assert_eq!(reply, b"pong-vless-xhttp-stm");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_stream_up_download_transport_fingerprint_proxy_end_to_end() {
        let upload_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upload_addr = upload_listener.local_addr().unwrap();
        let download_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let download_addr = download_listener.local_addr().unwrap();
        let upload_tls_config = build_tls_server_config();
        let (download_tls_config, download_fingerprint) = build_tls_server_config_with_fingerprint();
        let worker = thread::spawn(move || {
            let (download_tx, download_rx) = mpsc::sync_channel(1);
            let download_worker = thread::spawn(move || {
                let (download_stream, _) = download_listener.accept().unwrap();
                let (download_request, download_stream) =
                    accept_h2_tls_test_stream(Box::new(download_stream), download_tls_config).unwrap();
                download_tx.send((download_request, download_stream)).unwrap();
            });
            let (upload_stream, _) = upload_listener.accept().unwrap();
            let (upload_request, upload_stream) =
                accept_h2_tls_test_stream(Box::new(upload_stream), upload_tls_config).unwrap();
            let (download_request, download_stream) = download_rx.recv().unwrap();
            download_worker.join().unwrap();

            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "upload.local");
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "download.local");
            assert!(upload_request.path.starts_with("/vxuf/"));
            assert!(download_request.path.starts_with("/vxdf/"));

            let mut stream = SplitTestStream::new(upload_stream, download_stream);
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-stf.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-stf").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp =
            unique_temp_dir("mihomo-app-tunnel-vless-xhttp-stream-up-download-transport-fingerprint");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {upload_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxuf
      host: upload.local
      mode: stream-up
      download-settings:
        server: 127.0.0.1
        port: {download_port}
        tls: true
        servername: localhost
        skip-cert-verify: true
        fingerprint: {download_fingerprint}
        host: download.local
        path: /vxdf
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-stf.example.com:443
"#,
                upload_port = upload_addr.port(),
                download_port = download_addr.port(),
                download_fingerprint = download_fingerprint,
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
        assert_eq!(reply, b"pong-vless-xhttp-stf");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxp/"));

            let (upload_stream0, _) = listener.accept().unwrap();
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
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-p.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-p").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxp
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-p.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-p");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_buffered_upload_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxpb/"));

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();

            listener.set_nonblocking(true).unwrap();
            thread::sleep(Duration::from_millis(100));
            match listener.accept() {
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(_) => panic!("unexpected extra packet-up upload stream"),
                Err(err) => panic!("unexpected accept error: {err}"),
            }

            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-pb.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-pb").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-buffered");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxpb
      host: localhost
      mode: packet-up
      sc-max-each-post-bytes: "64"
      sc-min-posts-interval-ms: "1000"
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-pb.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        client.write_all(b"pi").unwrap();
        client.write_all(b"ng").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vless-xhttp-pb");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_without_tls_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream_a, _) = listener.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = listener.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request0, mut upload_stream0)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxpn/"));
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-pn.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-pn").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts:
      path: /vxpn
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-pn.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-pn");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_download_settings_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "download.local");
            assert_eq!(
                download_request.headers.get("x-download").map(String::as_str),
                Some("yes")
            );
            let session_id = download_request.path.strip_prefix("/vxpd/").unwrap();

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "upload.local");
            assert_eq!(upload_request0.path, format!("/vxpu/{session_id}/0"));
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
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-pd.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-pd").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-download-settings");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxpu
      host: upload.local
      mode: packet-up
      download-settings:
        host: download.local
        path: /vxpd
        headers:
          X-Download: yes
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-pd.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-pd");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_query_meta_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            let (download_path, download_query) = download_request.path.split_once('?').unwrap();
            assert_eq!(download_path, "/vxpq/");
            let session_id = download_query.strip_prefix("sid=").unwrap();

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("/vxpq/?sid={session_id}&n=0"));
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
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-pq.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-pq").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-query");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxpq
      host: localhost
      mode: packet-up
      session-placement: query
      session-key: sid
      seq-placement: query
      seq-key: n
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-pq.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-pq");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_header_data_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxph/"));

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            assert!(upload0.is_empty());
            let upload0 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(upload_request0.headers.get("x-data-0").unwrap())
                .unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-ph.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-ph").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-header-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxph
      host: localhost
      mode: packet-up
      uplink-data-placement: header
      uplink-data-key: x-data
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-ph.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-ph");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_empty_header_key_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxphk/"));

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            assert!(upload0.is_empty());
            let upload0 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(upload_request0.headers.get("-0").unwrap())
                .unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-phk.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-phk").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-empty-header-key");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxphk
      host: localhost
      mode: packet-up
      uplink-data-placement: header
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-phk.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-phk");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_cookie_data_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert_eq!(download_request.path, "/vxpc/");
            let session_id = download_request.headers.get("x-session").unwrap().to_owned();

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, "/vxpc/");
            assert_eq!(
                upload_request0.headers.get("x-session").map(String::as_str),
                Some(session_id.as_str())
            );
            let cookie0 = upload_request0.headers.get("cookie").unwrap();
            assert!(cookie0.contains("x_seq=0"));
            let encoded0 = cookie0
                .split("; ")
                .find_map(|part| part.strip_prefix("x_data_0="))
                .unwrap();
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            assert!(upload0.is_empty());
            let upload0 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded0)
                .unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-pc.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-pc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-cookie-data");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxpc
      host: localhost
      mode: packet-up
      session-placement: header
      session-key: X-Session
      seq-placement: cookie
      seq-key: x_seq
      uplink-data-placement: cookie
      uplink-data-key: x_data
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-pc.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-pc");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_auto_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxa/"));

            let (upload_stream0, _) = listener.accept().unwrap();
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
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-auto.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-auto").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-auto");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxa
      host: localhost
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-auto.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-auto");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_ws_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
            assert!(request.contains("Upgrade: websocket\r\n"));
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "ws.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-ws").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: ws
    ws-opts:
      path: /ws
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: ws.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-ws");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_http_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_http_stream_test(Box::new(stream));
            assert!(request.starts_with("GET /vmh HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-http.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-http").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: http
    http-opts:
      path: [/vmh]
      host: [localhost]
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-http.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-http");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_h2_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmh2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-h2.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-h2");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmh2
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-h2.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-h2");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_grpc_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
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
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-grpc.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: grpc
    grpc-opts:
      grpc-service-name: example
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-grpc.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-grpc");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vless_xhttp_packet_up_empty_cookie_key_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vxpck/"));

            let (upload_stream0, _) = listener.accept().unwrap();
            let (upload_request0, mut upload_stream0) =
                accept_h2_tls_test_stream(Box::new(upload_stream0), tls_config.clone()).unwrap();
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
            upload_stream0.shutdown_write().unwrap();
            assert!(upload0.is_empty());
            let cookie_header = upload_request0
                .headers
                .get("cookie")
                .or_else(|| upload_request0.headers.get("Cookie"))
                .unwrap();
            let upload0 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(cookie_header.trim_start_matches("_0="))
                .unwrap();
            let mut stream = TestPrefixedStream {
                prefix: std::io::Cursor::new(upload0),
                inner: download_stream,
            };
            let (version, uuid, command, target) = read_vless_request(&mut stream);
            assert_eq!(version, 0);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, 0x01);
            assert_eq!(target, "vless-xhttp-pck.example.com:443");
            stream.write_all(&[0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless-xhttp-pck").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vless-xhttp-packet-up-empty-cookie-key");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vless
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vxpck
      host: localhost
      mode: packet-up
      uplink-data-placement: cookie
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vless-xhttp-pck.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vless-xhttp-pck");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_xhttp_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmx/");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-xhttp.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-xhttp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmx
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-xhttp.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-xhttp");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_xhttp_without_tls_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmxn/");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-xhttp-notls.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-notls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-xhttp-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: xhttp
    xhttp-opts:
      path: /vmxn
      host: localhost
      mode: stream-one
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-xhttp-notls.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-xhttp-notls");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_xhttp_stream_up_without_tls_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream_a, _) = listener.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = listener.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request, upload_stream)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxsn/"));
            assert_eq!(upload_request.method, "POST");
            assert_eq!(upload_request.authority, "localhost");
            assert_eq!(upload_request.path, download_request.path);
            assert_eq!(
                upload_request.headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );

            let stream = SplitTestStream::new(upload_stream, download_stream);
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-xhttp-sn.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-sn").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-xhttp-stream-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: xhttp
    xhttp-opts:
      path: /vmxsn
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-xhttp-sn.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-xhttp-sn");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_xhttp_packet_up_without_tls_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream_a, _) = listener.accept().unwrap();
            let (request_a, stream_a) = accept_h2_test_stream(Box::new(stream_a)).unwrap();
            let (stream_b, _) = listener.accept().unwrap();
            let (request_b, stream_b) = accept_h2_test_stream(Box::new(stream_b)).unwrap();
            let ((download_request, download_stream), (upload_request0, mut upload_stream0)) =
                match (request_a.method.as_str(), request_b.method.as_str()) {
                    ("GET", "POST") => ((request_a, stream_a), (request_b, stream_b)),
                    ("POST", "GET") => ((request_b, stream_b), (request_a, stream_a)),
                    _ => panic!("expected xhttp GET/POST pair"),
                };
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxpn/"));
            assert_eq!(upload_request0.method, "POST");
            assert_eq!(upload_request0.authority, "localhost");
            assert_eq!(upload_request0.path, format!("{}/0", download_request.path));
            let mut upload0 = Vec::new();
            upload_stream0.read_to_end(&mut upload0).unwrap();
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
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-xhttp-pn.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-pn").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-xhttp-packet-up-notls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: xhttp
    xhttp-opts:
      path: /vmxpn
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-xhttp-pn.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        client.write_all(b"pi").unwrap();
        client.write_all(b"ng").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-xhttp-pn");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_xhttp_stream_up_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxs/"));

            let (upload_stream, _) = listener.accept().unwrap();
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
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-xhttp-s.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-s").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-xhttp-stream-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmxs
      host: localhost
      mode: stream-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-xhttp-s.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-xhttp-s");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_xhttp_packet_up_proxy_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, download_stream) =
                accept_h2_tls_test_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert_eq!(download_request.authority, "localhost");
            assert!(download_request.path.starts_with("/vmxp/"));

            let (upload_stream0, _) = listener.accept().unwrap();
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
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "vmess-xhttp-p.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-xhttp-p").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-xhttp-packet-up");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmxp
      host: localhost
      mode: packet-up
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: vmess-xhttp-p.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess-xhttp-p");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_legacy_alter_id_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "legacy.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-legacy").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-legacy");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 16
    cipher: none
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: legacy.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-legacy");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_legacy_security_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-cfb",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "legacy-cfb.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-cfb").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-legacy-cfb");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 16
    cipher: aes-128-cfb
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: legacy-cfb.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-cfb");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_vmess_authenticated_length_and_global_padding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_vmess_test_stream(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-vmess-authlen");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: vmess
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    global-padding: true
    authenticated-length: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = listen_addr.port(),
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
        assert_eq!(reply, b"pong-vmess");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_trojan_proxy_end_to_end() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, command, target) = read_trojan_request(&mut stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-trojan");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-trojan");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_trojan_shadowsocks_proxy_end_to_end() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream =
                accept_shadowsocks_test_stream(Box::new(stream), "aes-128-gcm", "inner").unwrap();
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, "trojan-ss.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-ss").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-trojan-ss");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
    ss-opts:
      enabled: true
      method: aes-128-gcm
      password: inner
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: trojan-ss.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-trojan-ss");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_trojan_http_proxy_end_to_end() {
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
            assert!(request.starts_with("GET /tr HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, "http-trojan.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-http").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-trojan-http");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
    network: http
    http-opts:
      path: [/tr]
      host: [localhost]
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: http-trojan.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-trojan-http");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_trojan_ws_proxy_end_to_end() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /tr HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            let mut stream = stream;
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, "ws-trojan.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-ws").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-trojan-ws");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /tr
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: ws-trojan.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-trojan-ws");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_trojan_grpc_proxy_end_to_end() {
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
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, "grpc-trojan.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-grpc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-trojan-grpc");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trojan
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: example
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: grpc-trojan.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-trojan-grpc");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_trusttunnel_proxy_end_to_end() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = tls_listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "trusttunnel.example.com:443");
            assert_eq!(
                request.headers.get("proxy-authorization").map(String::as_str),
                Some("Basic YWxpY2U6c2VjcmV0")
            );
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trusttunnel").unwrap();
            stream.shutdown_write().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-trusttunnel");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: trusttunnel
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    username: alice
    password: secret
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: trusttunnel.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-trusttunnel");

        worker.join().unwrap();
        app.shutdown();
    }



    #[test]
    fn start_serves_custom_tunnel_listener_with_anytls_proxy_end_to_end() {
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

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);
            assert!(String::from_utf8(payload).unwrap().contains("v=2"));

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);
            assert!(payload.is_empty());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = std::io::Cursor::new(payload);
            let target = read_shadowsocks_target_reader(&mut payload_reader);
            assert_eq!(target, "final.example.com:443");

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            assert_eq!(payload, b"ping".to_vec());

            write_anytls_frame(&mut stream, 0x02, 1, b"pong-anytls");
            write_anytls_frame(&mut stream, 0x03, 1, &[]);
            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x03);
            assert_eq!(stream_id, 1);
            assert!(payload.is_empty());
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-anytls");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
proxies:
  - type: anytls
    name: relay
    server: 127.0.0.1
    port: {relay_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: final.example.com:443
"#,
                relay_port = tls_addr.port(),
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
        assert_eq!(reply, b"pong-anytls");

        worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_listener_with_special_rules_end_to_end() {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = unused.local_addr().unwrap().port();
        drop(unused);
        let upstream_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_b_addr = upstream_b.local_addr().unwrap();

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

        let temp = unique_temp_dir("mihomo-app-tunnel-special-rules");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "0"
    rule: listener
    target: dest.test:443
rules:
  - DOMAIN,dest.test,leaf-a
sub-rules:
  listener:
    - DOMAIN,dest.test,leaf-b
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
                port_a = unused_port,
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

        let reply = run_tunnel_roundtrip(tunnel_addr, b"ping");
        assert_eq!(reply, b"pong-b");

        worker_b.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_http_proxy_listener_end_to_end() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("GET /hello HTTP/1.1\r\n"));
            assert!(!request.contains("GET http://"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-http-proxy");
        fs::write(
            temp.join("config.yaml"),
            r#"
mode: direct
listeners:
  - type: http
    name: http-proxy
    listen: 127.0.0.1
    port: "0"
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
        let proxy_addr = find_listener_addr(&app, "http-proxy", "http");

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        write!(
            client,
            "GET http://{upstream_addr}/hello HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let response = read_http_until_close(&mut client);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("\r\n\r\nok"));

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_http_proxy_listener_without_client_half_close() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("GET /hello HTTP/1.1\r\n"));
            assert!(!request.contains("GET http://"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .unwrap();
            stream.flush().unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-http-proxy-no-half-close");
        fs::write(
            temp.join("config.yaml"),
            r#"
mode: direct
listeners:
  - type: http
    name: http-proxy
    listen: 127.0.0.1
    port: "0"
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
        let proxy_addr = find_listener_addr(&app, "http-proxy", "http");

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(
            client,
            "GET http://{upstream_addr}/hello HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: keep-alive\r\n\r\n"
        )
        .unwrap();
        let response = read_http_response_message(&mut client);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("\r\n\r\nok"));

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_custom_tunnel_udp_listener_end_to_end() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-udp");
            upstream.send_to(b"pong-udp", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-tunnel-udp");
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
hosts:
  upstream.test: 127.0.0.1
dns:
  enable: true
  use-hosts: true
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: DIRECT
    target: upstream.test:{port}
"#,
                port = upstream_addr.port(),
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
        client.send_to(b"ping-udp", listener_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"pong-udp");

        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_socks_udp_associate_end_to_end() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"socks-udp");
            upstream.send_to(b"socks-ok", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-socks-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "0"
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
        let socks_addr = find_listener_addr(&app, "edge-socks", "socks");

        let mut control = TcpStream::connect(socks_addr).unwrap();
        control.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut greeting = [0_u8; 2];
        control.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let associate_request = build_socks_udp_associate_request();
        control.write_all(&associate_request).unwrap();
        let bind_addr = read_socks_udp_associate_reply(&mut control);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let frame = build_socks_udp_request(upstream_addr, b"socks-udp");
        client.send_to(&frame, bind_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        let (returned_target, payload) = parse_socks_udp_response(&buf[..read]);
        assert_eq!(returned_target, upstream_addr);
        assert_eq!(payload, b"socks-ok");

        drop(control);
        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_socks_udp_associate_with_fragment_reassembly_end_to_end() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"socks-fragmented");
            upstream.send_to(b"frag-ok", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-socks-udp-frag");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "0"
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
        let socks_addr = find_listener_addr(&app, "edge-socks", "socks");

        let mut control = TcpStream::connect(socks_addr).unwrap();
        control.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut greeting = [0_u8; 2];
        control.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let associate_request = build_socks_udp_associate_request();
        control.write_all(&associate_request).unwrap();
        let bind_addr = read_socks_udp_associate_reply(&mut control);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let first = build_socks_udp_request_with_frag(upstream_addr, 0x01, b"socks-");
        let second = build_socks_udp_request_with_frag(upstream_addr, 0x82, b"fragmented");
        client.send_to(&first, bind_addr).unwrap();
        client.send_to(&second, bind_addr).unwrap();

        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        let (returned_target, payload) = parse_socks_udp_response(&buf[..read]);
        assert_eq!(returned_target, upstream_addr);
        assert_eq!(payload, b"frag-ok");

        drop(control);
        upstream_worker.join().unwrap();
        app.shutdown();
    }

    #[test]
    fn start_serves_mixed_udp_associate_end_to_end() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-udp");
            upstream.send_to(b"mixed-ok", from).unwrap();
        });

        let temp = unique_temp_dir("mihomo-app-mixed-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: mixed
    name: edge-mixed
    listen: 127.0.0.1
    port: "0"
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
        let mixed_addr = find_listener_addr(&app, "edge-mixed", "mixed");

        let mut control = TcpStream::connect(mixed_addr).unwrap();
        control.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut greeting = [0_u8; 2];
        control.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let associate_request = build_socks_udp_associate_request();
        control.write_all(&associate_request).unwrap();
        let bind_addr = read_socks_udp_associate_reply(&mut control);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let frame = build_socks_udp_request(upstream_addr, b"mixed-udp");
        client.send_to(&frame, bind_addr).unwrap();
        let mut buf = [0_u8; 2048];
        let (read, _) = client.recv_from(&mut buf).unwrap();
        let (returned_target, payload) = parse_socks_udp_response(&buf[..read]);
        assert_eq!(returned_target, upstream_addr);
        assert_eq!(payload, b"mixed-ok");

        drop(control);
        upstream_worker.join().unwrap();
        app.shutdown();
    }
