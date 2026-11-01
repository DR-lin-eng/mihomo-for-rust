use super::*;

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
fn start_serves_custom_tunnel_listener_with_sudoku_stream_httpmask_over_dialer_proxy_end_to_end() {
    let _guard = sudoku_httpmask_test_guard();
    let dialer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dialer_addr = dialer_listener.local_addr().unwrap();
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

    let dialer_worker = thread::spawn(move || {
        let (mut inbound, _) = dialer_listener.accept().unwrap();
        let target = read_socks5_connect_target(&mut inbound);
        assert_eq!(target, proxy_addr);
        write_socks5_connect_reply(&mut inbound, SocketAddr::from(([127, 0, 0, 1], 0)));

        let mut upstream = TcpStream::connect(proxy_addr).unwrap();
        let mut inbound_writer = inbound.try_clone().unwrap();
        let mut upstream_writer = upstream.try_clone().unwrap();
        let upload = thread::spawn(move || {
            std::io::copy(&mut inbound, &mut upstream_writer).unwrap();
            upstream_writer.shutdown(Shutdown::Write).unwrap();
        });
        let download = thread::spawn(move || {
            std::io::copy(&mut upstream, &mut inbound_writer).unwrap();
            inbound_writer.shutdown(Shutdown::Write).unwrap();
        });
        upload.join().unwrap();
        download.join().unwrap();
    });

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
        stream.write_all(b"pong-sudoku-stream-dialer").unwrap();
        stream.shutdown_write().unwrap();
        proxy.assert_clean();
    });

    let temp = unique_temp_dir("mihomo-app-tunnel-sudoku-stream-httpmask-dialer");
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
proxies:
  - type: socks5
    name: outer
    server: 127.0.0.1
    port: {dialer_port}
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
    dialer-proxy: outer
listeners:
  - type: tunnel
    name: tcp-forward
    listen: 127.0.0.1
    port: "0"
    proxy: relay
    target: nested.example.com:443
"#,
            dialer_port = dialer_addr.port(),
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
    assert_eq!(reply, b"pong-sudoku-stream-dialer");

    proxy_worker.join().unwrap();
    dialer_worker.join().unwrap();
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
