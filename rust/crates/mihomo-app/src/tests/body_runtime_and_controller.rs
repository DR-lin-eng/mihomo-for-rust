    #[test]
    fn start_binds_external_controller_from_config() {
        let temp = unique_temp_dir("mihomo-app-config");
        fs::write(
            temp.join("config.yaml"),
            r#"
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
        let addr = app.controller_addr().unwrap();
        assert!(app.has_background_services());
        assert!(app.summary().contains("controllers="));

        let response = fetch_http(addr, Some("top-secret"));
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"meta\":\"mihomo-rust\""));

        app.shutdown();
    }

    #[test]
    fn start_accepts_allow_lan_with_implicit_wildcard_bind() {
        let temp = unique_temp_dir("mihomo-app-allow-lan");
        let mixed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mixed_port = mixed_listener.local_addr().unwrap().port();
        drop(mixed_listener);
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
allow-lan: true
mixed-port: {mixed_port}
external-controller: 127.0.0.1:0
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
                mixed_port = mixed_port,
            ),
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(app.has_background_services());
        assert!(!app.listener_addrs().is_empty());
        assert!(app.summary().contains("bound_listeners="));
        app.shutdown();
    }

    #[test]
    fn start_binds_top_level_redir_listener() {
        let temp = unique_temp_dir("mihomo-app-top-level-redir");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redir_port = listener.local_addr().unwrap().port();
        drop(listener);
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
redir-port: {redir_port}
bind-address: 127.0.0.1
proxies:
  - type: direct
    name: direct-a
"#,
                redir_port = redir_port,
            ),
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
            assert!(
                app.listener_addrs()
                    .iter()
                    .any(|listener| listener.name == "__top_level_redir__" && listener.kind == "redir")
            );
            app.shutdown();
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let err = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap_err();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let message = err.to_string();
            assert!(
                message.contains("tproxy udp listener is only implemented on Linux/Android"),
                "{message}"
            );
            return;
        }
    }

    #[test]
    fn start_binds_top_level_tproxy_listener() {
        let temp = unique_temp_dir("mihomo-app-top-level-tproxy");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tproxy_port = listener.local_addr().unwrap().port();
        drop(listener);
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
tproxy-port: {tproxy_port}
bind-address: 127.0.0.1
proxies:
  - type: direct
    name: direct-a
"#,
                tproxy_port = tproxy_port,
            ),
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
            assert!(
                app.listener_addrs()
                    .iter()
                    .any(|listener| listener.name == "__top_level_tproxy__" && listener.kind == "tproxy")
            );
            app.shutdown();
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let err = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap_err();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let message = err.to_string();
            assert!(
                message.contains("tproxy listener is only implemented on Linux/Android"),
                "{message}"
            );
            return;
        }
    }

    #[test]
    #[cfg(unix)]
    fn start_with_tun_fd_worker_consumes_udp_frame() {
        let temp = unique_temp_dir("mihomo-app-tun-fd-worker");
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let target = echo.local_addr().unwrap();
        let echo_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = echo.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping");
            echo.send_to(b"pong", peer).unwrap();
        });

        let (writer, reader) = UnixStream::pair().unwrap();
        let fd = reader.as_raw_fd();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
tun:
  enable: true
  file-descriptor: {fd}
proxies:
  - type: direct
    name: direct-a
rules:
  - MATCH,direct-a
"#,
                fd = fd,
            ),
        )
        .unwrap();

        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };

        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(app.has_background_services());
        let frame = crate::tun_packet::encode_tun_udp_packet(
            "10.0.0.2:50000".parse().unwrap(),
            target,
            64,
            b"ping",
        )
        .unwrap();
        let mut writer = writer;
        writer.write_all(&frame).unwrap();
        writer.flush().unwrap();

        echo_thread.join().unwrap();
        app.shutdown();
        drop(writer);
    }

    #[test]
    #[cfg(unix)]
    fn start_with_listener_tun_fd_worker_consumes_udp_frame() {
        let temp = unique_temp_dir("mihomo-app-listener-tun-fd-worker");
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let target = echo.local_addr().unwrap();
        let echo_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = echo.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping");
            echo.send_to(b"pong", peer).unwrap();
        });

        let (writer, reader) = UnixStream::pair().unwrap();
        let fd = reader.as_raw_fd();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
listeners:
  - type: tun
    name: edge-tun
    file-descriptor: {fd}
proxies:
  - type: direct
    name: direct-a
rules:
  - MATCH,direct-a
"#,
                fd = fd,
            ),
        )
        .unwrap();

        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };

        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(app.has_background_services());
        let frame = crate::tun_packet::encode_tun_udp_packet(
            "10.0.0.2:50001".parse().unwrap(),
            target,
            64,
            b"ping",
        )
        .unwrap();
        let mut writer = writer;
        writer.write_all(&frame).unwrap();
        writer.flush().unwrap();

        echo_thread.join().unwrap();
        app.shutdown();
        drop(writer);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn start_binds_top_level_redir_udp_listener() {
        let temp = unique_temp_dir("mihomo-app-top-level-redir-udp");
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let redir_port = listener.local_addr().unwrap().port();
        drop(listener);
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
redir-port: {redir_port}
bind-address: 127.0.0.1
proxies:
  - type: direct
    name: direct-a
"#,
                redir_port = redir_port,
            ),
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(
            app.listener_addrs().iter().any(|listener| {
                listener.name == "__top_level_redir__" && listener.kind == "redir/udp"
            })
        );
        app.shutdown();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn start_binds_top_level_tproxy_udp_listener() {
        let temp = unique_temp_dir("mihomo-app-top-level-tproxy-udp");
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tproxy_port = listener.local_addr().unwrap().port();
        drop(listener);
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
tproxy-port: {tproxy_port}
bind-address: 127.0.0.1
proxies:
  - type: direct
    name: direct-a
"#,
                tproxy_port = tproxy_port,
            ),
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(
            app.listener_addrs().iter().any(|listener| {
                listener.name == "__top_level_tproxy__" && listener.kind == "tproxy/udp"
            })
        );
        app.shutdown();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn start_binds_explicit_redir_udp_listener() {
        let temp = unique_temp_dir("mihomo-app-explicit-redir-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: redir
    name: edge-redir
    listen: 127.0.0.1
    port: "0"
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
        assert!(
            app.listener_addrs()
                .iter()
                .any(|listener| listener.name == "edge-redir" && listener.kind == "redir/udp")
        );
        app.shutdown();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn start_binds_explicit_tproxy_udp_listener() {
        let temp = unique_temp_dir("mihomo-app-explicit-tproxy-udp");
        fs::write(
            temp.join("config.yaml"),
            r#"
listeners:
  - type: tproxy
    name: edge-tproxy
    listen: 127.0.0.1
    port: "0"
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
        assert!(
            app.listener_addrs()
                .iter()
                .any(|listener| listener.name == "edge-tproxy" && listener.kind == "tproxy/udp")
        );
        app.shutdown();
    }

    #[test]
    fn start_honors_external_controller_override_flag() {
        let temp = unique_temp_dir("mihomo-app-override");
        fs::write(
            temp.join("config.yaml"),
            r#"
external-controller: 127.0.0.1:9090
secret: from-config
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
            external_controller: Some("127.0.0.1:0".into()),
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: Some("from-flag".into()),
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        let addr = app.controller_addr().unwrap();

        let response = fetch_http(addr, Some("from-flag"));
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"version\":\"0.1.0\""));

        let unauthorized = fetch_http(addr, Some("from-config"));
        assert!(unauthorized.contains("HTTP/1.1 401 Unauthorized"));

        app.shutdown();
    }

    #[test]
    fn start_binds_external_controller_tls_from_config() {
        let temp = unique_temp_dir("mihomo-app-controller-tls");
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller-tls: 127.0.0.1:0
secret: top-secret
tls:
  certificate: |
{cert}
  private-key: |
{key}
proxies:
  - type: direct
    name: direct-a
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
        let addr = app.controller_addr().unwrap();

        let response = send_https_request(addr, "GET", "/version", Some("top-secret"), None);
        assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"meta\":\"mihomo-rust\""), "{response}");

        app.shutdown();
    }

    #[test]
    fn start_binds_external_controller_and_tls_from_config() {
        let temp = unique_temp_dir("mihomo-app-controller-dual");
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller: 127.0.0.1:0
external-controller-tls: 127.0.0.1:0
secret: top-secret
tls:
  certificate: |
{cert}
  private-key: |
{key}
proxies:
  - type: direct
    name: direct-a
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
        let addrs = app.controller_addrs();
        assert_eq!(addrs.len(), 2);

        let http_addr = addrs
            .iter()
            .copied()
            .find(|addr| fetch_http(*addr, Some("top-secret")).contains("HTTP/1.1 200 OK"))
            .unwrap();
        let https_addr = addrs.into_iter().find(|addr| *addr != http_addr).unwrap();

        let http_response = fetch_http(http_addr, Some("top-secret"));
        assert!(http_response.contains("\"meta\":\"mihomo-rust\""), "{http_response}");

        let https_response = send_https_request(https_addr, "GET", "/version", Some("top-secret"), None);
        assert!(https_response.contains("HTTP/1.1 200 OK"), "{https_response}");
        assert!(https_response.contains("\"meta\":\"mihomo-rust\""), "{https_response}");

        app.shutdown();
    }

    #[cfg(unix)]
    #[test]
    fn start_binds_external_controller_unix_from_config() {
        use std::os::unix::net::UnixStream;

        let temp = unique_temp_dir("mihomo-app-controller-unix");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("mhapp-{nanos}.sock"));
        fs::write(
            temp.join("config.yaml"),
            format!(
                r#"
external-controller-unix: {}
proxies:
  - type: direct
    name: direct-a
"#,
                socket_path.display()
            ),
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();
        assert!(app.has_background_services());
        assert!(app.summary().contains("controllers="));

        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"meta\":\"mihomo-rust\""), "{response}");

        app.shutdown();
        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn controller_restart_route_emits_app_control_command() {
        let temp = unique_temp_dir("mihomo-app-controller-restart");
        fs::write(
            temp.join("config.yaml"),
            r#"
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
        let addr = app.controller_addr().unwrap();

        let response = send_http_request(addr, "POST", "/restart", Some("top-secret"), None);
        assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
        assert!(
            matches!(
                app.poll_control_command(),
                Some(mihomo_api::ApiControlCommand::Restart)
            ),
            "expected restart control command"
        );

        app.shutdown();
    }

    #[test]
    fn restore_selected_proxy_mapping_applies_env_override() {
        let temp = unique_temp_dir("mihomo-app-selected-proxy-env");
        let mut state = mihomo_runtime::bootstrap_from_boot_options(
            &BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                config_file: None,
                config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                    r#"
profile:
  store-selected: true
proxies:
  - type: direct
    name: a
  - type: direct
    name: b
proxy-groups:
  - name: auto
    type: url-test
    proxies: [a, b]
rules:
  - MATCH,auto
"#,
                )),
                external_ui: None,
                external_controller: None,
                external_controller_unix: None,
                external_controller_pipe: None,
                secret: None,
                post_up: None,
                post_down: None,
                geodata_mode: false,
                show_version: false,
                test_config: false,
                command: Command::Run,
            },
            &temp,
            &BootEnvironment::default(),
        )
        .unwrap();
        unsafe {
            std::env::set_var(super::SELECTED_PROXY_ENV, r#"{"auto":"b"}"#);
        }
        super::restore_selected_proxy_mapping(&mut state);
        assert_eq!(
            state
                .registry
                .groups
                .get("auto")
                .and_then(|view| view.runtime.selected().map(ToOwned::to_owned))
                .as_deref(),
            Some("b")
        );
        unsafe {
            std::env::remove_var(super::SELECTED_PROXY_ENV);
        }
    }

    #[test]
    fn reload_replaces_runtime_state_from_updated_config() {
        let temp = unique_temp_dir("mihomo-app-reload");
        let config_path = temp.join("config.yaml");
        fs::write(
            &config_path,
            r#"
external-controller: 127.0.0.1:0
secret: old-secret
proxies:
  - type: direct
    name: direct-a
"#,
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(config_path.to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let env = BootEnvironment::default();
        let mut app = RunningApp::start(&options, &temp, &env).unwrap();
        let old_addr = app.controller_addr().unwrap();
        let old_response = send_http_request(old_addr, "GET", "/proxies", Some("old-secret"), None);
        assert!(old_response.contains("HTTP/1.1 200 OK"));

        fs::write(
            &config_path,
            r#"
external-controller: 127.0.0.1:0
secret: new-secret
proxies:
  - type: direct
    name: direct-b
"#,
        )
        .unwrap();
        app.reload(&options, &temp, &env).unwrap();

        let new_addr = app.controller_addr().unwrap();
        let new_response = send_http_request(new_addr, "GET", "/proxies", Some("new-secret"), None);
        assert!(new_response.contains("HTTP/1.1 200 OK"));
        assert!(new_response.contains("\"direct-b\""));

        let unauthorized = send_http_request(new_addr, "GET", "/proxies", Some("old-secret"), None);
        assert!(unauthorized.contains("HTTP/1.1 401 Unauthorized"));
        app.shutdown();
    }

    #[test]
    fn reload_keeps_previous_runtime_when_new_config_is_invalid() {
        let temp = unique_temp_dir("mihomo-app-reload-invalid");
        let config_path = temp.join("config.yaml");
        fs::write(
            &config_path,
            r#"
external-controller: 127.0.0.1:0
secret: stable-secret
proxies:
  - type: direct
    name: direct-a
"#,
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(config_path.to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let env = BootEnvironment::default();
        let mut app = RunningApp::start(&options, &temp, &env).unwrap();
        let addr = app.controller_addr().unwrap();

        fs::write(
            &config_path,
            r#"
external-controller: 127.0.0.1:0
secret: broken
proxy-groups:
  - type: select
    name: missing
    proxies: [not-found]
"#,
        )
        .unwrap();
        assert!(app.reload(&options, &temp, &env).is_err());

        let response = send_http_request(addr, "GET", "/proxies", Some("stable-secret"), None);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"direct-a\""));
        app.shutdown();
    }
