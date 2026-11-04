    #[cfg(feature = "ssh-transport-tests")]
    struct TestSshServer {
        addr: SocketAddr,
        host_key: String,
        shutdown: russh_server::RunningServerHandle,
        thread: Option<thread::JoinHandle<()>>,
    }

    #[cfg(feature = "ssh-transport-tests")]
    impl TestSshServer {
        fn start_password() -> Self {
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let mut rng = rng();
                    let host_key =
                        RusshPrivateKey::random(&mut rng, russh_keys::Algorithm::Ed25519).unwrap();
                    let host_key_blob = host_key.public_key_base64();
                    let config = std::sync::Arc::new(russh_server::Config {
                        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                        keys: vec![host_key],
                        ..Default::default()
                    });
                    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let mut server = PasswordSshServer;
                    let running = server.run_on_socket(config, &listener);
                    let handle = running.handle();
                    tx.send((addr, host_key_blob, handle)).unwrap();
                    running.await.unwrap();
                });
            });
            let (addr, host_key, shutdown) = rx.recv().unwrap();
            Self {
                addr,
                host_key,
                shutdown,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            self.shutdown.shutdown("test complete".into());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    struct TestTuicServer {
        addr: SocketAddr,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestTuicServer {
        fn start_v4(token: &str) -> Self {
            Self::start(TestTuicAuth::V4 {
                token: token.to_owned(),
            })
        }

        fn start_v5(uuid: &str, password: &str) -> Self {
            Self::start(TestTuicAuth::V5 {
                uuid: uuid.to_owned(),
                password: password.to_owned(),
            })
        }

        fn start(auth: TestTuicAuth) -> Self {
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let _ = quinn::rustls::crypto::aws_lc_rs::default_provider().install_default();
                    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let cert_der = cert.cert.der().clone();
                    let key_der = cert.key_pair.serialize_der();
                    let certs = vec![quinn::rustls::pki_types::CertificateDer::from(cert_der)];
                    let key =
                        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into();
                    let mut server_crypto = quinn::rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();
                    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
                    let tls_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
                        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
                    ));
                    let udp_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
                    let endpoint = quinn::Endpoint::server(tls_config, udp_bind).unwrap();
                    let addr = endpoint.local_addr().unwrap();
                    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                    tx.send((addr, shutdown_tx)).unwrap();

                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            incoming = endpoint.accept() => {
                                let Some(incoming) = incoming else { break };
                                let auth_mode = auth.clone();
                                tokio::spawn(async move {
                                    let connection = incoming.await.unwrap();
                                    let auth_stream = connection.accept_uni().await.unwrap();
                                    let mut auth_stream = auth_stream;
                                    match &auth_mode {
                                        TestTuicAuth::V4 { token } => {
                                            let mut auth_header = [0_u8; 2 + 32];
                                            auth_stream.read_exact(&mut auth_header).await.unwrap();
                                            assert_eq!(auth_header[0], 0x04);
                                            assert_eq!(auth_header[1], 0x00);
                                            let expected = blake3::hash(token.as_bytes());
                                            assert_eq!(&auth_header[2..], expected.as_bytes());
                                        }
                                        TestTuicAuth::V5 { uuid, password } => {
                                            let expected_uuid = Uuid::parse_str(&uuid).unwrap();
                                            let mut auth_header = [0_u8; 2 + 16 + 32];
                                            auth_stream.read_exact(&mut auth_header).await.unwrap();
                                            assert_eq!(auth_header[0], 0x05);
                                            assert_eq!(auth_header[1], 0x00);
                                            let mut got_uuid = [0_u8; 16];
                                            got_uuid.copy_from_slice(&auth_header[2..18]);
                                            assert_eq!(got_uuid, *expected_uuid.as_bytes());
                                            let mut expected_token = [0_u8; 32];
                                            connection
                                                .export_keying_material(
                                                    &mut expected_token,
                                                    expected_uuid.as_bytes(),
                                                    password.as_bytes(),
                                                )
                                                .unwrap();
                                            assert_eq!(&auth_header[18..], &expected_token);
                                        }
                                    }

                                    tokio::select! {
                                        bi = connection.accept_bi() => {
                                            let (send, recv) = bi.unwrap();
                                            let mut recv = recv;
                                            let mut header = [0_u8; 2];
                                            recv.read_exact(&mut header).await.unwrap();
                                            assert_eq!(header, [0x05, 0x01]);
                                            let target = read_tuic_v5_target(&mut recv).await.unwrap();
                                            match &auth_mode {
                                                TestTuicAuth::V4 { .. } => {
                                                    assert_eq!(target, "tuic-v4-target.example.com:443");
                                                }
                                                TestTuicAuth::V5 { .. } => {
                                                    assert_eq!(target, "tuic-target.example.com:443");
                                                }
                                            }
                                            let mut stream = TestQuicStream::new(send, recv);
                                            let mut payload = [0_u8; 4];
                                            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                                                .await
                                                .unwrap();
                                            assert_eq!(&payload, b"ping");
                                            match &auth_mode {
                                                TestTuicAuth::V4 { .. } => {
                                                    tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong-tuic-v4")
                                                        .await
                                                        .unwrap();
                                                }
                                                TestTuicAuth::V5 { .. } => {
                                                    tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong-tuic")
                                                        .await
                                                        .unwrap();
                                                }
                                            }
                                            tokio::io::AsyncWriteExt::shutdown(&mut stream)
                                                .await
                                                .unwrap();
                                        }
                                        datagram = connection.read_datagram() => {
                                            let datagram = datagram.unwrap();
                                            match &auth_mode {
                                                TestTuicAuth::V4 { .. } => {
                                                    let mut reader = std::io::Cursor::new(datagram.to_vec());
                                                    let (packet_target, payload) = read_tuic_v4_udp_packet_from_client(&mut reader);
                                                    assert_eq!(packet_target, SocketAddr::from(([127, 0, 0, 1], 5353)));
                                                    assert_eq!(payload, b"via-tuic-v4");
                                                    let mut response = Vec::new();
                                                    write_tuic_v4_udp_packet_to_client(
                                                        &mut response,
                                                        packet_target,
                                                        b"tuic-v4-ok",
                                                    );
                                                    connection.send_datagram(Bytes::from(response)).unwrap();
                                                }
                                                TestTuicAuth::V5 { .. } => {
                                                    let mut reader = std::io::Cursor::new(datagram.to_vec());
                                                    let (packet_target, payload) = read_tuic_v5_udp_packet_from_client(&mut reader);
                                                    assert_eq!(packet_target, SocketAddr::from(([127, 0, 0, 1], 5353)));
                                                    assert_eq!(payload, b"via-tuic");
                                                    let mut response = Vec::new();
                                                    write_tuic_v5_udp_packet_to_client(
                                                        &mut response,
                                                        packet_target,
                                                        b"tuic-ok",
                                                    );
                                                    connection.send_datagram(Bytes::from(response)).unwrap();
                                                }
                                            }
                                        }
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    let _ = connection.closed().await;
                                });
                            }
                        }
                    }
                });
            });
            let (addr, shutdown_tx) = rx.recv().unwrap();
            Self {
                addr,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[derive(Clone)]
    enum TestTuicAuth {
        V4 { token: String },
        V5 { uuid: String, password: String },
    }

    struct TestHy2Server {
        addr: SocketAddr,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestHy2Server {
        fn start(password: &str) -> Self {
            let password = password.to_owned();
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let _ = quinn::rustls::crypto::aws_lc_rs::default_provider().install_default();
                    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let cert_der = cert.cert.der().clone();
                    let key_der = cert.key_pair.serialize_der();
                    let certs = vec![quinn::rustls::pki_types::CertificateDer::from(cert_der)];
                    let key =
                        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into();
                    let mut server_crypto = quinn::rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();
                    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
                    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
                        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
                    ));
                    let mut transport = quinn::TransportConfig::default();
                    transport.datagram_receive_buffer_size(Some(1024 * 1024));
                    transport.datagram_send_buffer_size(1024 * 1024);
                    server_config.transport_config(std::sync::Arc::new(transport));
                    let endpoint =
                        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                            .unwrap();
                    let addr = endpoint.local_addr().unwrap();
                    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                    tx.send((addr, shutdown_tx)).unwrap();

                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            incoming = endpoint.accept() => {
                                let Some(incoming) = incoming else { break };
                                let expected_password = password.clone();
                                tokio::spawn(async move {
                                    let connection = incoming.await.unwrap();
                                    let h3_conn = h3_quinn::Connection::new(connection.clone());
                                    let mut incoming =
                                        h3::server::Connection::<_, bytes::Bytes>::new(h3_conn)
                                            .await
                                            .unwrap();
                                    let resolver = incoming.accept().await.unwrap().unwrap();
                                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                                    assert_eq!(request.method(), http::Method::POST);
                                    assert_eq!(request.uri().authority().map(|value| value.as_str()), Some("hysteria"));
                                    assert_eq!(request.uri().path(), "/auth");
                                    assert_eq!(
                                        request.headers().get("Hysteria-Auth").and_then(|value| value.to_str().ok()),
                                        Some(expected_password.as_str())
                                    );
                                    let response = http::Response::builder()
                                        .status(233)
                                        .header("Hysteria-UDP", "true")
                                        .header("Hysteria-CC-RX", "0")
                                        .body(())
                                        .unwrap();
                                    stream.send_response(response).await.unwrap();
                                    stream.finish().await.unwrap();

                                    let datagram = connection.read_datagram().await.unwrap();
                                    let mut reader = std::io::Cursor::new(datagram.to_vec());
                                    let packet = read_hy2_udp_packet_from_client(&mut reader);
                                    assert_eq!(packet.0, SocketAddr::from(([127, 0, 0, 1], 5353)));
                                    assert_eq!(packet.1, b"via-hy2");
                                    let mut response = Vec::new();
                                    write_hy2_udp_packet_to_client(&mut response, packet.0, b"hy2-ok");
                                    connection.send_datagram(Bytes::from(response)).unwrap();
                                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    let _ = connection.closed().await;
                                });
                            }
                        }
                    }
                });
            });
            let (addr, shutdown_tx) = rx.recv().unwrap();
            Self {
                addr,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    struct TestHysteriaServer {
        addr: SocketAddr,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestHysteriaServer {
        fn start(password: &str) -> Self {
            Self::start_with_obfs(password, None)
        }

        fn start_with_obfs(password: &str, obfs: Option<&str>) -> Self {
            let password = password.as_bytes().to_vec();
            let obfs = obfs.map(|value| value.as_bytes().to_vec());
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let _ = quinn::rustls::crypto::aws_lc_rs::default_provider().install_default();
                    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let cert_der = cert.cert.der().clone();
                    let key_der = cert.key_pair.serialize_der();
                    let certs = vec![quinn::rustls::pki_types::CertificateDer::from(cert_der)];
                    let key =
                        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into();
                    let mut server_crypto = quinn::rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();
                    server_crypto.alpn_protocols = vec![b"hysteria".to_vec()];
                    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
                        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
                    ));
                    let mut transport = quinn::TransportConfig::default();
                    transport.datagram_receive_buffer_size(Some(1024 * 1024));
                    transport.datagram_send_buffer_size(1024 * 1024);
                    server_config.transport_config(std::sync::Arc::new(transport));
                    let endpoint = if let Some(obfs_password) = obfs.clone() {
                        let runtime = Arc::new(TestTokioQuinnRuntime);
                        let socket = Arc::new(
                            TestHysteriaXPlusUdpSocket::new(
                                std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                                obfs_password,
                            )
                            .unwrap(),
                        );
                        quinn::Endpoint::new_with_abstract_socket(
                            quinn::EndpointConfig::default(),
                            Some(server_config),
                            socket,
                            runtime,
                        )
                        .unwrap()
                    } else {
                        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                            .unwrap()
                    };
                    let addr = endpoint.local_addr().unwrap();
                    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                    tx.send((addr, shutdown_tx)).unwrap();

                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            incoming = endpoint.accept() => {
                                let Some(incoming) = incoming else { break };
                                let expected_auth = password.clone();
                                tokio::spawn(async move {
                                    let connection = incoming.await.unwrap();

                                    let uni = connection.accept_uni().await.unwrap();
                                    let mut uni = uni;
                                    let mut hello = [0_u8; 19];
                                    uni.read_exact(&mut hello).await.unwrap();
                                    assert_eq!(hello[0], 3);
                                    let auth_len = u16::from_be_bytes([hello[17], hello[18]]) as usize;
                                    let mut auth = vec![0_u8; auth_len];
                                    uni.read_exact(&mut auth).await.unwrap();
                                    assert_eq!(auth, expected_auth);

                                    let mut server_hello = Vec::new();
                                    server_hello.push(1);
                                    server_hello.extend_from_slice(&0_u64.to_be_bytes());
                                    server_hello.extend_from_slice(&0_u64.to_be_bytes());
                                    server_hello.extend_from_slice(&0_u16.to_be_bytes());
                                    let mut send = connection.open_uni().await.unwrap();
                                    send.write_all(&server_hello).await.unwrap();
                                    send.finish().unwrap();

                                    let (send_stream, recv_stream) = connection.accept_bi().await.unwrap();
                                    let mut recv_stream = recv_stream;
                                    let mut udp_flag = [0_u8; 1];
                                    recv_stream.read_exact(&mut udp_flag).await.unwrap();
                                    let mut host_len = [0_u8; 2];
                                    recv_stream.read_exact(&mut host_len).await.unwrap();
                                    let host_len = u16::from_be_bytes(host_len) as usize;
                                    let mut host = vec![0_u8; host_len];
                                    recv_stream.read_exact(&mut host).await.unwrap();
                                    let host = String::from_utf8(host).unwrap();
                                    let mut port = [0_u8; 2];
                                    recv_stream.read_exact(&mut port).await.unwrap();
                                    let port = u16::from_be_bytes(port);

                                    let mut response = Vec::new();
                                    response.push(1);
                                    response.extend_from_slice(&1_u32.to_be_bytes());
                                    response.extend_from_slice(&0_u16.to_be_bytes());
                                    let mut send_stream = send_stream;
                                    send_stream.write_all(&response).await.unwrap();

                                    if udp_flag[0] == 0 {
                                        assert_eq!(format!("{host}:{port}"), "hysteria-target.example.com:443");
                                        let mut payload = [0_u8; 4];
                                        recv_stream.read_exact(&mut payload).await.unwrap();
                                        assert_eq!(&payload, b"ping");
                                        send_stream.write_all(b"pong-hysteria").await.unwrap();
                                        send_stream.finish().unwrap();
                                    } else {
                                        let datagram = connection.read_datagram().await.unwrap();
                                        let mut reader = std::io::Cursor::new(datagram.to_vec());
                                        let (packet_target, packet_payload) =
                                            read_hysteria_udp_packet_from_client(&mut reader);
                                        assert_eq!(packet_target.ip().to_string(), "127.0.0.1");
                                        assert!(
                                            packet_payload == b"via-hysteria"
                                                || packet_payload == b"ping-hysteria-outer-socks"
                                        );
                                        let mut response = Vec::new();
                                        write_hysteria_udp_packet_to_client(
                                            &mut response,
                                            packet_target,
                                            if packet_payload == b"via-hysteria" {
                                                b"hysteria-ok"
                                            } else {
                                                b"pong-hysteria-outer-socks"
                                            },
                                        );
                                        connection.send_datagram(Bytes::from(response)).unwrap();
                                    }

                                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    let _ = connection.closed().await;
                                });
                            }
                        }
                    }
                });
            });
            let (addr, shutdown_tx) = rx.recv().unwrap();
            Self {
                addr,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    struct TestStunServer {
        addr: SocketAddr,
        shutdown_tx: mpsc::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestStunServer {
        fn start() -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = socket.local_addr().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let (shutdown_tx, shutdown_rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let socket = socket;
                let mut buf = [0_u8; 1500];
                loop {
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }
                    match socket.recv_from(&mut buf) {
                        Ok((read, from)) => {
                            if read < 20 {
                                continue;
                            }
                            let txid = &buf[8..20];
                            let mut response = vec![0_u8; 32];
                            response[0..2].copy_from_slice(&0x0101_u16.to_be_bytes());
                            response[2..4].copy_from_slice(&12_u16.to_be_bytes());
                            response[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
                            response[8..20].copy_from_slice(txid);
                            response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
                            response[22..24].copy_from_slice(&8_u16.to_be_bytes());
                            response[24] = 0;
                            response[25] = 0x01;
                            let port = from.port() ^ 0x2112;
                            response[26..28].copy_from_slice(&port.to_be_bytes());
                            if let std::net::IpAddr::V4(ip) = from.ip() {
                                let cookie = 0x2112_A442_u32.to_be_bytes();
                                let octets = ip.octets();
                                response[28] = octets[0] ^ cookie[0];
                                response[29] = octets[1] ^ cookie[1];
                                response[30] = octets[2] ^ cookie[2];
                                response[31] = octets[3] ^ cookie[3];
                                let _ = socket.send_to(&response, from);
                            }
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    struct TestTrustTunnelQuicServer {
        addr: SocketAddr,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestTrustTunnelQuicServer {
        fn start() -> Self {
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let _ = quinn::rustls::crypto::aws_lc_rs::default_provider().install_default();
                    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let cert_der = cert.cert.der().clone();
                    let key_der = cert.key_pair.serialize_der();
                    let certs = vec![quinn::rustls::pki_types::CertificateDer::from(cert_der)];
                    let key =
                        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into();
                    let mut server_crypto = quinn::rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();
                    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
                    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
                        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
                    ));
                    let mut transport = quinn::TransportConfig::default();
                    transport.datagram_receive_buffer_size(Some(1024 * 1024));
                    transport.datagram_send_buffer_size(1024 * 1024);
                    server_config.transport_config(std::sync::Arc::new(transport));
                    let endpoint =
                        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                            .unwrap();
                    let addr = endpoint.local_addr().unwrap();
                    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                    tx.send((addr, shutdown_tx)).unwrap();

                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            incoming = endpoint.accept() => {
                                let Some(incoming) = incoming else { break };
                                tokio::spawn(async move {
                                    let connection = incoming.await.unwrap();
                                    let h3_conn = h3_quinn::Connection::new(connection.clone());
                                    let mut incoming =
                                        h3::server::Connection::<_, bytes::Bytes>::new(h3_conn)
                                            .await
                                            .unwrap();
                                    let resolver = incoming.accept().await.unwrap().unwrap();
                                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                                    assert_eq!(request.method(), http::Method::CONNECT);
                                    let authority = request.uri().authority().map(|value| value.as_str()).unwrap_or_default().to_owned();
                                    assert_eq!(
                                        request.headers().get("proxy-authorization").and_then(|value| value.to_str().ok()),
                                        Some("Basic YWxpY2U6c2VjcmV0")
                                    );
                                    let response = http::Response::builder()
                                        .status(200)
                                        .body(())
                                        .unwrap();
                                    stream.send_response(response).await.unwrap();

                                    if authority == "_udp2" {
                                        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                                            let payload = chunk.copy_to_bytes(chunk.remaining());
                                            let mut reader = std::io::Cursor::new(payload.to_vec());
                                            let (packet_target, packet_payload) =
                                                read_trusttunnel_udp_packet_frame_from_client(&mut reader);
                                            assert_eq!(packet_target, SocketAddr::from(([127, 0, 0, 1], 5353)));
                                            assert_eq!(packet_payload, b"via-trusttunnel-quic");
                                            let mut response = Vec::new();
                                            write_trusttunnel_udp_packet_frame_to_client(
                                                &mut response,
                                                packet_target,
                                                b"trusttunnel-quic-ok",
                                            );
                                            stream.send_data(Bytes::from(response)).await.unwrap();
                                            stream.finish().await.unwrap();
                                            break;
                                        }
                                    } else {
                                        assert_eq!(authority, "trusttunnel.example.com:443");
                                        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                                            let payload = chunk.copy_to_bytes(chunk.remaining());
                                            assert_eq!(payload.as_ref(), b"ping");
                                            stream.send_data(Bytes::from_static(b"pong-trusttunnel-quic")).await.unwrap();
                                            stream.finish().await.unwrap();
                                            break;
                                        }
                                    }

                                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    let _ = connection.closed().await;
                                });
                            }
                        }
                    }
                });
            });
            let (addr, shutdown_tx) = rx.recv().unwrap();
            Self {
                addr,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    struct TestQuicStream {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    }

    impl TestQuicStream {
        fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
            Self { send, recv }
        }
    }

    impl AsyncRead for TestQuicStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.recv)
                .poll_read(cx, buf)
                .map_err(std::io::Error::other)
        }
    }

    impl AsyncWrite for TestQuicStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.send)
                .poll_write(cx, buf)
                .map_err(std::io::Error::other)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.send)
                .poll_flush(cx)
                .map_err(std::io::Error::other)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(self.send.finish().map_err(std::io::Error::other))
        }
    }

    async fn read_tuic_v5_target(
        stream: &mut quinn::RecvStream,
    ) -> std::io::Result<String> {
        let mut atyp = [0_u8; 1];
        stream
            .read_exact(&mut atyp)
            .await
            .map_err(std::io::Error::other)?;
        let atyp = atyp[0];
        let host = match atyp {
            0x00 => {
                let mut len = [0_u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(std::io::Error::other)?;
                let len = len[0] as usize;
                let mut host = vec![0_u8; len];
                stream
                    .read_exact(&mut host)
                    .await
                    .map_err(std::io::Error::other)?;
                String::from_utf8(host)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?
            }
            0x01 => {
                let mut octets = [0_u8; 4];
                stream
                    .read_exact(&mut octets)
                    .await
                    .map_err(std::io::Error::other)?;
                std::net::Ipv4Addr::from(octets).to_string()
            }
            0x02 => {
                let mut octets = [0_u8; 16];
                stream
                    .read_exact(&mut octets)
                    .await
                    .map_err(std::io::Error::other)?;
                std::net::Ipv6Addr::from(octets).to_string()
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected tuic atyp {other}"),
                ))
            }
        };
        let mut port = [0_u8; 2];
        stream
            .read_exact(&mut port)
            .await
            .map_err(std::io::Error::other)?;
        let port = u16::from_be_bytes(port);
        Ok(format!("{host}:{port}"))
    }

    #[cfg(feature = "ssh-transport-tests")]
    #[derive(Clone)]
    struct PasswordSshServer;

    #[cfg(feature = "ssh-transport-tests")]
    impl russh_server::Server for PasswordSshServer {
        type Handler = Self;

        fn new_client(&mut self, _addr: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    #[cfg(feature = "ssh-transport-tests")]
    impl russh_server::Handler for PasswordSshServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<russh_server::Auth, Self::Error> {
            if user == "user" && password == "secret" {
                Ok(russh_server::Auth::Accept)
            } else {
                Ok(russh_server::Auth::reject())
            }
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<RusshServerMsg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut RusshSession,
        ) -> Result<bool, Self::Error> {
            let target = format!("{host_to_connect}:{port_to_connect}");
            tokio::spawn(async move {
                let mut channel = channel.into_stream();
                let mut upstream = TokioTcpStream::connect(&target).await.unwrap();
                copy_bidirectional(&mut channel, &mut upstream).await.unwrap();
                channel.shutdown().await.unwrap();
            });
            Ok(true)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn transparent_udp_recvmsg_extracts_original_destination() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        crate::listener_service::configure_tproxy_udp_listener_socket(&listener).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        client.send_to(b"ping-transparent-udp", listener_addr).unwrap();

        let (payload, peer_addr, target_addr) =
            crate::listener_service::transparent::recv_transparent_udp_packet(&listener)
                .unwrap()
                .unwrap();
        assert_eq!(payload, b"ping-transparent-udp".to_vec());
        assert_eq!(peer_addr, client_addr);
        assert_eq!(target_addr, listener_addr);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn transparent_udp_write_back_uses_requested_source_address() {
        let document = mihomo_config::parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default().resolve(
                std::path::Path::new("/tmp"),
                &mihomo_config::BootEnvironment::default(),
            ),
            document: document.clone(),
            provider_sources: Default::default(),
            registry: mihomo_runtime::build_runtime_registry(&document).unwrap(),
        };
        let tunnel = Arc::new(state.build_runtime_tunnel().unwrap());

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client_addr = client.local_addr().unwrap();

        let transparent_source = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();

        let conn = crate::listener_service::transparent::create_or_get_local_conn(
            &transparent_source,
            &client_addr,
            &tunnel,
        )
        .unwrap();
        conn.send(b"pong-transparent-udp").unwrap();

        let mut buf = [0_u8; 2048];
        let (read, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"pong-transparent-udp");
        assert_eq!(from.ip(), transparent_source.ip());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn transparent_udp_tproxy_round_trip_via_runtime() {
        let document = mihomo_config::parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: DIRECT
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default().resolve(
                std::path::Path::new("/tmp"),
                &mihomo_config::BootEnvironment::default(),
            ),
            document: document.clone(),
            provider_sources: Default::default(),
            registry: mihomo_runtime::build_runtime_registry(&document).unwrap(),
        };
        let tunnel = Arc::new(state.build_runtime_tunnel().unwrap());

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client_addr = client.local_addr().unwrap();

        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        // This unit fixture puts the upstream and transparent reply socket in
        // one namespace. Real LAN/WAN targets live in separate namespaces.
        // Permit the reply socket to bind this source port while the upstream
        // remains alive to send its unsolicited second response.
        let enabled: libc::c_int = 1;
        assert_eq!(unsafe { libc::setsockopt(std::os::fd::AsRawFd::as_raw_fd(&upstream),
            libc::SOL_SOCKET, libc::SO_REUSEADDR, &enabled as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t) }, 0);
        let upstream_worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (read, from) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping-tproxy-udp");
            upstream.send_to(b"pong-tproxy-udp", from).unwrap();
            thread::sleep(Duration::from_millis(25));
            upstream.send_to(b"later-tproxy-udp", from).unwrap();
        });

        let listener_addr = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let session_pool = Arc::new(crate::tun_packet::TunUdpSessionPool::default());
        crate::listener_service::transparent::handle_tproxy_udp_packet(
            listener_addr,
            client_addr,
            upstream_addr,
            b"ping-tproxy-udp".to_vec(),
            Arc::clone(&tunnel),
            "edge-tproxy".into(),
            String::new(),
            String::new(),
            None,
            mihomo_core::SessionKind::TProxy,
            session_pool.clone(),
        )
        .unwrap();

        let mut buf = [0_u8; 2048];
        let (read, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"pong-tproxy-udp");
        assert_eq!(from, upstream_addr);
        let (read, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"later-tproxy-udp");
        assert_eq!(from, upstream_addr);
        upstream_worker.join().unwrap();
        session_pool.shutdown();
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
