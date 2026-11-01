use super::*;

pub(super) struct TestSocks5UdpAssociateProxy {
    pub(super) addr: SocketAddr,
    shutdown_tx: std::sync::mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestSocks5UdpAssociateProxy {
    pub(super) fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

pub(super) fn spawn_socks5_udp_associate_proxy() -> TestSocks5UdpAssociateProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let relay_addr = relay.local_addr().unwrap();

        let mut stream = loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("outer socks accept failed: {err}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).unwrap();

        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header, [0x05, 0x03, 0x00, 0x01]);
        let mut bind_ip = [0_u8; 4];
        stream.read_exact(&mut bind_ip).unwrap();
        let mut bind_port = [0_u8; 2];
        stream.read_exact(&mut bind_port).unwrap();
        let announced_client_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(bind_ip)),
            u16::from_be_bytes(bind_port),
        );

        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        if let SocketAddr::V4(relay_addr) = relay_addr {
            reply.extend_from_slice(&relay_addr.ip().octets());
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
        } else {
            panic!("expected ipv4 relay addr");
        }
        stream.write_all(&reply).unwrap();
        stream.flush().unwrap();

        let mut packet = [0_u8; 4096];
            let mut client_peer = None;
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                let (read, peer) = match relay.recv_from(&mut packet) {
                    Ok(value) => value,
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(err) => panic!("outer socks udp relay failed: {err}"),
                };
            if client_peer.is_none() || client_peer == Some(peer) {
                client_peer = Some(peer);
                assert_eq!(peer.port(), announced_client_addr.port());
                assert!(read > 10);
                assert_eq!(&packet[0..3], &[0x00, 0x00, 0x00]);
                assert_eq!(packet[3], 0x01);
                let target = SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        packet[4], packet[5], packet[6], packet[7],
                    )),
                    u16::from_be_bytes([packet[8], packet[9]]),
                );
                let payload = &packet[10..read];
                relay.send_to(payload, target).unwrap();
            } else {
                let mut framed = vec![0x00, 0x00, 0x00, 0x01];
                if let SocketAddr::V4(source) = peer {
                    framed.extend_from_slice(&source.ip().octets());
                    framed.extend_from_slice(&source.port().to_be_bytes());
                } else {
                    panic!("expected ipv4 source addr");
                }
                framed.extend_from_slice(&packet[..read]);
                relay.send_to(&framed, client_peer.unwrap()).unwrap();
            }
        }
    });
    TestSocks5UdpAssociateProxy {
        addr,
        shutdown_tx,
        thread: Some(worker),
    }
}

pub(super) struct TestWireGuardServer {
    pub(super) addr: SocketAddr,
    pub(super) client_private_key: String,
    pub(super) server_public_key: String,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestWireGuardServer {
    pub(super) fn start() -> Self {
        let (server_private, server_public) = x25519::keypair();
        let (client_private, client_public) = x25519::keypair();
        let endpoint_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoint_addr = endpoint_socket.local_addr().unwrap();
        drop(endpoint_socket);
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let server_config = WgConfig {
                    interface: WgInterface {
                        address: "100.64.0.1/32".parse().unwrap(),
                        private_key: server_private,
                        listen_port: Some(endpoint_addr.port()),
                        mtu: Some(1380),
                    },
                    peers: vec![WgPeer {
                        endpoint: None,
                        allowed_ips: vec!["100.64.0.0/24".parse().unwrap()],
                        public_key: client_public,
                        persistent_keepalive: Some(15),
                    }],
                };

                let tcp_listener = WgTcpListener::bind("100.64.0.1:8080", server_config)
                    .await
                    .unwrap();
                let udp_socket =
                    WgUdpSocket::bind("100.64.0.1:5353", tcp_listener.interface().clone())
                        .await
                        .unwrap();

                let client_private_key = base64::engine::general_purpose::STANDARD
                    .encode(client_private.to_bytes());
                let server_public_key = base64::engine::general_purpose::STANDARD
                    .encode(server_public.to_bytes());
                let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                tx.send((endpoint_addr, client_private_key, server_public_key, shutdown_tx))
                    .unwrap();
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = tcp_listener.accept() => {
                            let Ok((mut stream, _peer)) = accept else { break };
                            tokio::spawn(async move {
                                let mut payload = [0_u8; 4];
                                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                                    .await
                                    .unwrap();
                                assert_eq!(&payload, b"ping");
                                tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong-wireguard")
                                    .await
                                    .unwrap();
                                tokio::io::AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                            });
                        }
                        recv = async {
                            let mut buf = Vec::with_capacity(2048);
                            udp_socket.recv_from(&mut buf).await.map(|(read, peer)| (buf, read, peer))
                        } => {
                            let Ok((buf, read, peer)) = recv else { break };
                            if &buf[..read] == b"via-wireguard" {
                                udp_socket.send_to(b"wireguard-ok", peer).await.unwrap();
                                continue;
                            }
                            let query_id = u16::from_be_bytes([buf[0], buf[1]]);
                            let expected = mihomo_dns::build_dns_query_for_tests(
                                "edge.example.com",
                                mihomo_dns::DnsRecordType::A,
                                query_id,
                            )
                            .unwrap();
                            assert_eq!(&buf[..read], expected);
                            let mut response = Vec::new();
                            response.extend_from_slice(&query_id.to_be_bytes());
                            response.extend_from_slice(&0x8180_u16.to_be_bytes());
                            response.extend_from_slice(&1_u16.to_be_bytes());
                            response.extend_from_slice(&1_u16.to_be_bytes());
                            response.extend_from_slice(&0_u16.to_be_bytes());
                            response.extend_from_slice(&0_u16.to_be_bytes());
                            response.extend_from_slice(&buf[12..read]);
                            response.extend_from_slice(&0xC00C_u16.to_be_bytes());
                            response.extend_from_slice(&1_u16.to_be_bytes());
                            response.extend_from_slice(&1_u16.to_be_bytes());
                            response.extend_from_slice(&60_u32.to_be_bytes());
                            response.extend_from_slice(&4_u16.to_be_bytes());
                            response.extend_from_slice(&[100, 64, 0, 1]);
                            udp_socket.send_to(&response, peer).await.unwrap();
                        }
                    }
                }
            });
        });
        let (addr, client_private_key, server_public_key, shutdown_tx) = rx.recv().unwrap();
        Self {
            addr,
            client_private_key,
            server_public_key,
            shutdown_tx,
            thread: Some(thread),
        }
    }

    pub(super) fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

pub(super) struct TestWireGuardMultiPeerServer {
    pub(super) primary_addr: SocketAddr,
    pub(super) primary_public_key: String,
    pub(super) secondary_addr: SocketAddr,
    pub(super) secondary_public_key: String,
    pub(super) client_private_key: String,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestWireGuardMultiPeerServer {
    pub(super) fn start() -> Self {
        let (client_private, client_public) = x25519::keypair();
        let (primary_private, primary_public) = x25519::keypair();
        let (secondary_private, secondary_public) = x25519::keypair();

        let primary_endpoint = UdpSocket::bind("127.0.0.1:0").unwrap();
        let primary_addr = primary_endpoint.local_addr().unwrap();
        drop(primary_endpoint);
        let secondary_endpoint = UdpSocket::bind("127.0.0.1:0").unwrap();
        let secondary_addr = secondary_endpoint.local_addr().unwrap();
        drop(secondary_endpoint);

        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let primary_config = WgConfig {
                    interface: WgInterface {
                        address: "100.64.0.1/32".parse().unwrap(),
                        private_key: primary_private,
                        listen_port: Some(primary_addr.port()),
                        mtu: Some(1380),
                    },
                    peers: vec![WgPeer {
                        endpoint: None,
                        allowed_ips: vec!["100.64.0.0/24".parse().unwrap()],
                        public_key: client_public,
                        persistent_keepalive: Some(15),
                    }],
                };
                let secondary_config = WgConfig {
                    interface: WgInterface {
                        address: "100.65.0.1/32".parse().unwrap(),
                        private_key: secondary_private,
                        listen_port: Some(secondary_addr.port()),
                        mtu: Some(1380),
                    },
                    peers: vec![WgPeer {
                        endpoint: None,
                        allowed_ips: vec!["100.64.0.0/24".parse().unwrap()],
                        public_key: client_public,
                        persistent_keepalive: Some(15),
                    }],
                };

                let primary_tcp = WgTcpListener::bind("100.64.0.1:8080", primary_config)
                    .await
                    .unwrap();
                let primary_udp =
                    WgUdpSocket::bind("100.64.0.1:5353", primary_tcp.interface().clone())
                        .await
                        .unwrap();
                let secondary_tcp = WgTcpListener::bind("100.65.0.1:8080", secondary_config)
                    .await
                    .unwrap();
                let secondary_udp =
                    WgUdpSocket::bind("100.65.0.1:5353", secondary_tcp.interface().clone())
                        .await
                        .unwrap();

                let client_private_key = base64::engine::general_purpose::STANDARD
                    .encode(client_private.to_bytes());
                let primary_public_key = base64::engine::general_purpose::STANDARD
                    .encode(primary_public.to_bytes());
                let secondary_public_key = base64::engine::general_purpose::STANDARD
                    .encode(secondary_public.to_bytes());
                let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                tx.send((
                    primary_addr,
                    primary_public_key,
                    secondary_addr,
                    secondary_public_key,
                    client_private_key,
                    shutdown_tx,
                ))
                .unwrap();

                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = primary_tcp.accept() => {
                            let Ok((mut stream, _peer)) = accept else { break };
                            tokio::spawn(async move {
                                let mut payload = [0_u8; 4];
                                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload).await.unwrap();
                                assert_eq!(&payload, b"ping");
                                tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong-wireguard-a").await.unwrap();
                                tokio::io::AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                            });
                        }
                        accept = secondary_tcp.accept() => {
                            let Ok((mut stream, _peer)) = accept else { break };
                            tokio::spawn(async move {
                                let mut payload = [0_u8; 4];
                                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload).await.unwrap();
                                assert_eq!(&payload, b"ping");
                                tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong-wireguard-b").await.unwrap();
                                tokio::io::AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                            });
                        }
                        recv = async {
                            let mut buf = Vec::with_capacity(2048);
                            primary_udp.recv_from(&mut buf).await.map(|(read, peer)| (buf, read, peer))
                        } => {
                            let Ok((buf, read, peer)) = recv else { break };
                            assert_eq!(&buf[..read], b"via-wireguard");
                            primary_udp.send_to(b"wireguard-a-ok", peer).await.unwrap();
                        }
                        recv = async {
                            let mut buf = Vec::with_capacity(2048);
                            secondary_udp.recv_from(&mut buf).await.map(|(read, peer)| (buf, read, peer))
                        } => {
                            let Ok((buf, read, peer)) = recv else { break };
                            assert_eq!(&buf[..read], b"via-wireguard");
                            secondary_udp.send_to(b"wireguard-b-ok", peer).await.unwrap();
                        }
                    }
                }
            });
        });
        let (
            primary_addr,
            primary_public_key,
            secondary_addr,
            secondary_public_key,
            client_private_key,
            shutdown_tx,
        ) = rx.recv().unwrap();
        Self {
            primary_addr,
            primary_public_key,
            secondary_addr,
            secondary_public_key,
            client_private_key,
            shutdown_tx,
            thread: Some(thread),
        }
    }

    pub(super) fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
