    use std::fs::File;
    use std::io;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    #[cfg(unix)]
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::thread;
    use std::time::Duration;

    use mihomo_config::parse_runtime_config_document;
    use mihomo_runtime::{build_runtime_registry, build_tun_runtime_specs, RuntimeTunnel};
    use mihomo_tun::TunUdpRuntimeMode;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Packet, Ipv4Repr};

    use crate::tun_packet::{encode_tun_udp_packet, parse_tun_udp_packet};
    use crate::tun_tcp_packet::{encode_tun_tcp_packet, parse_tun_tcp_packet};

    use super::{clone_fd_as_file, tun_fd_udp_loop};

    const TCP_TEST_READ_TIMEOUT: Duration = Duration::from_millis(200);

    #[test]
    fn tun_fd_udp_loop_round_trips_raw_frames_to_fd() {
        let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let target = echo.local_addr().unwrap();
        let echo_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = echo.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping");
            echo.send_to(b"pong", peer).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixStream::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new({
                clone_fd_as_file(reader_raw).unwrap()
            }));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let frame = encode_tun_udp_packet(
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
        let mut reply = vec![0_u8; 2048];
        let read = writer.read(&mut reply).unwrap();
        let reply = parse_tun_udp_packet(&reply[..read]).unwrap();
        assert_eq!(reply.source, target);
        assert_eq!(reply.destination, "10.0.0.2:50000".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(reply.payload, b"pong");
        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
    }

    #[test]
    fn tun_fd_loop_handles_single_tcp_bridge_flow() {
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"client-data");
            stream.write_all(b"server-data").unwrap();
            stream.flush().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let document = parse_runtime_config_document(
            &format!(
                r#"
tun:
  enable: true
  file-descriptor: 1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#
            ),
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new({
                clone_fd_as_file(reader_raw).unwrap()
            }));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let mut writer = writer;
        let client: std::net::SocketAddr = "10.0.0.2:50010".parse().unwrap();
        drive_tcp_flow(
            &mut writer,
            client,
            upstream_addr,
            b"client-data",
            b"server-data",
        );

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
        upstream_thread.join().unwrap();
    }

    #[test]
    fn mixed_tun_stack_with_auto_redirect_skips_passive_tcp_bridge() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-redirect: true
  device: mihmixed0
  inet4-address:
    - 198.19.0.1/30
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        assert!(spec.supports_transparent_tcp_runtime_path());
    }

    #[test]
    fn tun_udp_dispatch_queue_shards_by_mode() {
        let source: std::net::SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let first_destination: std::net::SocketAddr = "1.1.1.1:53".parse().unwrap();
        let second_destination: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();

        let direct = super::TunUdpDispatchQueue::new(TunUdpRuntimeMode::DirectRelay, 2);
        let mixed = super::TunUdpDispatchQueue::new(TunUdpRuntimeMode::MixedLikeRelay, 2);

        let direct_first = direct.shard_key_for_packet_for_tests(source, first_destination);
        let direct_second = direct.shard_key_for_packet_for_tests(source, second_destination);
        let mixed_first = mixed.shard_key_for_packet_for_tests(source, first_destination);
        let mixed_second = mixed.shard_key_for_packet_for_tests(source, second_destination);

        assert_ne!(direct_first, direct_second);
        assert_eq!(mixed_first, mixed_second);
    }

    #[test]
    fn system_tun_stack_with_auto_redirect_skips_passive_tcp_bridge() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  stack: system
  auto-route: true
  auto-redirect: true
  device: mihsys0
  inet4-address:
    - 198.19.0.1/30
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        assert!(spec.supports_transparent_tcp_runtime_path());
    }

    #[test]
    fn tun_fd_loop_handles_sequential_tcp_bridge_flows() {
        let first_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first_addr = first_listener.local_addr().unwrap();
        let first_thread = thread::spawn(move || {
            let (mut stream, _) = first_listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"first");
            stream.write_all(b"first-reply").unwrap();
            stream.flush().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let second_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second_addr = second_listener.local_addr().unwrap();
        let second_thread = thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"second");
            stream.write_all(b"second-reply").unwrap();
            stream.flush().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let mut writer = writer;
        let first_client: std::net::SocketAddr = "10.0.0.2:50020".parse().unwrap();
        let second_client: std::net::SocketAddr = "10.0.0.2:50021".parse().unwrap();

        drive_tcp_flow(&mut writer, first_client, first_addr, b"first", b"first-reply");
        drive_tcp_flow(&mut writer, second_client, second_addr, b"second", b"second-reply");

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
        first_thread.join().unwrap();
        second_thread.join().unwrap();
    }

    #[test]
    fn slow_udp_no_longer_blocks_tcp_flow_progress() {
        let slow_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        slow_udp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let slow_udp_addr = slow_udp.local_addr().unwrap();
        let slow_udp_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = slow_udp.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"slow-ping");
            thread::sleep(Duration::from_millis(300));
            slow_udp.send_to(b"slow-pong", peer).unwrap();
        });

        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"tcp-data");
            stream.write_all(b"tcp-reply").unwrap();
            stream.flush().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let mut writer = writer;
        writer
            .send(
                &encode_tun_udp_packet(
                    "10.0.0.2:50040".parse().unwrap(),
                    slow_udp_addr,
                    64,
                    b"slow-ping",
                )
                .unwrap(),
            )
            .unwrap();

        let tcp_client: std::net::SocketAddr = "10.0.0.2:50041".parse().unwrap();
        drive_tcp_flow(&mut writer, tcp_client, upstream_addr, b"tcp-data", b"tcp-reply");

        let mut reply = vec![0_u8; 2048];
        let read = loop {
            match writer.recv(&mut reply) {
                Ok(read) => {
                    if let Ok(parsed) = parse_tun_udp_packet(&reply[..read]) {
                        if parsed.destination
                            == "10.0.0.2:50040".parse::<std::net::SocketAddr>().unwrap()
                        {
                            assert_eq!(parsed.payload, b"slow-pong");
                            break read;
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("udp reply read failed: {err}"),
            }
        };
        assert!(read > 0);

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
        slow_udp_thread.join().unwrap();
        upstream_thread.join().unwrap();
    }

    #[test]
    fn mixed_tun_fd_loop_reuses_udp_session_across_destinations_when_runtime_path_is_supported() {
        let first = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        first.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let first_target = first.local_addr().unwrap();
        let second = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        second.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let second_target = second.local_addr().unwrap();
        let (peer_tx_1, peer_rx_1) = std::sync::mpsc::channel();
        let (peer_tx_2, peer_rx_2) = std::sync::mpsc::channel();
        let first_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = first.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-1");
            peer_tx_1.send(peer).unwrap();
            first.send_to(b"mixed-reply-1", peer).unwrap();
        });
        let second_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = second.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-2");
            peer_tx_2.send(peer).unwrap();
            second.send_to(b"mixed-reply-2", peer).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
  stack: mixed
  auto-route: true
  auto-redirect: true
  device: mihmixed0
  inet4-address:
    - 198.19.0.1/30
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let writer = writer;
        writer
            .send(
                &encode_tun_udp_packet(
                    "10.0.0.2:50060".parse().unwrap(),
                    first_target,
                    64,
                    b"mixed-1",
                )
                .unwrap(),
            )
            .unwrap();
        writer
            .send(
                &encode_tun_udp_packet(
                    "10.0.0.2:50060".parse().unwrap(),
                    second_target,
                    64,
                    b"mixed-2",
                )
                .unwrap(),
            )
            .unwrap();

        let mut replies = 0;
        let mut reply = vec![0_u8; 2048];
        while replies < 2 {
            let read = writer.recv(&mut reply).unwrap();
            let parsed = parse_tun_udp_packet(&reply[..read]).unwrap();
            if parsed.destination == "10.0.0.2:50060".parse::<std::net::SocketAddr>().unwrap() {
                replies += 1;
            }
        }

        first_thread.join().unwrap();
        second_thread.join().unwrap();
        let first_peer = peer_rx_1.recv().unwrap();
        let second_peer = peer_rx_2.recv().unwrap();
        assert_eq!(first_peer, second_peer);

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
    }

    #[test]
    fn mixed_tun_fd_loop_keeps_destination_bound_udp_sessions_without_runtime_path_support() {
        let first = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        first.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let first_target = first.local_addr().unwrap();
        let second = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        second.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let second_target = second.local_addr().unwrap();
        let (peer_tx_1, peer_rx_1) = std::sync::mpsc::channel();
        let (peer_tx_2, peer_rx_2) = std::sync::mpsc::channel();
        let first_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = first.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-1");
            peer_tx_1.send(peer).unwrap();
            first.send_to(b"mixed-reply-1", peer).unwrap();
        });
        let second_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (read, peer) = second.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"mixed-2");
            peer_tx_2.send(peer).unwrap();
            second.send_to(b"mixed-reply-2", peer).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
  stack: mixed
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let writer = writer;
        writer
            .send(
                &encode_tun_udp_packet(
                    "10.0.0.2:50060".parse().unwrap(),
                    first_target,
                    64,
                    b"mixed-1",
                )
                .unwrap(),
            )
            .unwrap();
        writer
            .send(
                &encode_tun_udp_packet(
                    "10.0.0.2:50060".parse().unwrap(),
                    second_target,
                    64,
                    b"mixed-2",
                )
                .unwrap(),
            )
            .unwrap();

        let mut replies = 0;
        let mut reply = vec![0_u8; 2048];
        while replies < 2 {
            let read = writer.recv(&mut reply).unwrap();
            let parsed = parse_tun_udp_packet(&reply[..read]).unwrap();
            if parsed.destination == "10.0.0.2:50060".parse::<std::net::SocketAddr>().unwrap() {
                replies += 1;
            }
        }

        first_thread.join().unwrap();
        second_thread.join().unwrap();
        let first_peer = peer_rx_1.recv().unwrap();
        let second_peer = peer_rx_2.recv().unwrap();
        assert_ne!(first_peer, second_peer);

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
    }

    #[test]
    fn tun_fd_loop_fake_echoes_icmp_when_disable_icmp_forwarding_is_enabled() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
  disable-icmp-forwarding: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let mut writer = writer;
        writer
            .send(&encode_tun_icmpv4_echo_request(
                "10.0.0.2".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                64,
                0x1234,
                7,
                b"icmp-ping",
            ))
            .unwrap();

        let mut reply = vec![0_u8; 2048];
        let read = writer.recv(&mut reply).unwrap();
        let parsed = parse_tun_icmpv4_echo_reply(&reply[..read]).unwrap();
        assert_eq!(parsed.0, "1.1.1.1".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(parsed.1, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(parsed.2, 0x1234);
        assert_eq!(parsed.3, 7);
        assert_eq!(parsed.4, b"icmp-ping");

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
    }

    #[test]
    fn tun_fd_loop_handles_second_tcp_flow_after_first_completes() {
        let first_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first_addr = first_listener.local_addr().unwrap();
        let first_thread = thread::spawn(move || {
            let (mut stream, _) = first_listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"first");
            stream.write_all(b"first-reply").unwrap();
            stream.flush().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let second_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second_addr = second_listener.local_addr().unwrap();
        let second_thread = thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"second");
            stream.write_all(b"second-reply").unwrap();
            stream.flush().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let mut writer = writer;
        let first_client: std::net::SocketAddr = "10.0.0.2:50030".parse().unwrap();
        let second_client: std::net::SocketAddr = "10.0.0.2:50031".parse().unwrap();

        drive_tcp_flow(&mut writer, first_client, first_addr, b"first", b"first-reply");
        thread::sleep(Duration::from_millis(200));
        drive_tcp_flow(&mut writer, second_client, second_addr, b"second", b"second-reply");

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
        first_thread.join().unwrap();
        second_thread.join().unwrap();
    }

    fn encode_tun_icmpv4_echo_request(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        hop_limit: u8,
        ident: u16,
        seq_no: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let checksum_caps = ChecksumCapabilities::default();
        let icmp_repr = Icmpv4Repr::EchoRequest { ident, seq_no, data };
        let ipv4_repr = Ipv4Repr {
            src_addr: source.into(),
            dst_addr: destination.into(),
            next_header: smoltcp::wire::IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit,
        };
        let mut bytes = vec![0_u8; ipv4_repr.buffer_len() + icmp_repr.buffer_len()];
        {
            let mut ip_packet = Ipv4Packet::new_unchecked(&mut bytes);
            ipv4_repr.emit(&mut ip_packet, &checksum_caps);
            let mut icmp_packet = Icmpv4Packet::new_unchecked(ip_packet.payload_mut());
            icmp_repr.emit(&mut icmp_packet, &checksum_caps);
        }
        bytes
    }

    fn parse_tun_icmpv4_echo_reply(
        frame: &[u8],
    ) -> io::Result<(std::net::Ipv4Addr, std::net::Ipv4Addr, u16, u16, Vec<u8>)> {
        let checksum_caps = ChecksumCapabilities::default();
        let ipv4 = Ipv4Packet::new_checked(frame)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 packet"))?;
        let ipv4_repr = Ipv4Repr::parse(&ipv4, &checksum_caps)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipv4 repr"))?;
        let icmp = Icmpv4Packet::new_checked(ipv4.payload())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid icmp packet"))?;
        let repr = Icmpv4Repr::parse(&icmp, &checksum_caps)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid icmpv4 repr"))?;
        match repr {
            Icmpv4Repr::EchoReply { ident, seq_no, data } => Ok((
                ipv4_repr.src_addr.into(),
                ipv4_repr.dst_addr.into(),
                ident,
                seq_no,
                data.to_vec(),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "icmp packet is not echo reply",
            )),
        }
    }

    #[test]
    fn tun_fd_loop_rewrites_loopback_address_tcp_packets_back_to_source() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  file-descriptor: 1
  loopback-address:
    - 10.0.0.1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
        )
        .unwrap();
        let spec = build_tun_runtime_specs(&document).remove(0);
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (writer, reader) = UnixDatagram::pair().unwrap();
        let reader_raw = reader.as_raw_fd();
        writer
            .set_read_timeout(Some(TCP_TEST_READ_TIMEOUT))
            .unwrap();
        let reader_file = {
            let raw = reader.into_raw_fd();
            unsafe { File::from_raw_fd(raw) }
        };
        let join = {
            let spec = spec.clone();
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            let writer_file = Arc::new(Mutex::new(clone_fd_as_file(reader_raw).unwrap()));
            thread::spawn(move || tun_fd_udp_loop(spec, tunnel, None, shutdown, reader_file, writer_file))
        };

        let mut writer = writer;
        let client: std::net::SocketAddr = "10.0.0.2:50050".parse().unwrap();
        let loopback_target: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
        writer
            .send(
                &encode_tun_tcp_packet(
                    client,
                    loopback_target,
                    64,
                    &smoltcp::wire::TcpRepr {
                        src_port: client.port(),
                        dst_port: loopback_target.port(),
                        control: smoltcp::wire::TcpControl::Syn,
                        seq_number: smoltcp::wire::TcpSeqNumber(1),
                        ack_number: None,
                        window_len: 65535,
                        window_scale: Some(7),
                        max_seg_size: Some(1460),
                        sack_permitted: true,
                        sack_ranges: [None, None, None],
                        payload: &[],
                    },
                )
                .unwrap(),
            )
            .unwrap();

        let mut reply = vec![0_u8; 4096];
        let read = writer.recv(&mut reply).unwrap();
        let parsed = parse_tun_tcp_packet(&reply[..read]).unwrap();
        assert_eq!(parsed.source.ip(), loopback_target.ip());
        assert_eq!(parsed.destination.ip(), client.ip());
        assert_eq!(parsed.source.port(), client.port());
        assert_eq!(parsed.destination.port(), loopback_target.port());
        assert_eq!(parsed.tcp_repr.control, smoltcp::wire::TcpControl::Syn);

        shutdown.store(true, Ordering::Relaxed);
        drop(writer);
        join.join().unwrap();
    }

    fn drive_tcp_flow(
        writer: &mut UnixDatagram,
        client: std::net::SocketAddr,
        server: std::net::SocketAddr,
        client_payload: &[u8],
        expected_reply: &[u8],
    ) {
        writer
            .send(
                &encode_tun_tcp_packet(
                    client,
                    server,
                    64,
                    &smoltcp::wire::TcpRepr {
                        src_port: client.port(),
                        dst_port: server.port(),
                        control: smoltcp::wire::TcpControl::Syn,
                        seq_number: smoltcp::wire::TcpSeqNumber(1),
                        ack_number: None,
                        window_len: 65535,
                        window_scale: Some(7),
                        max_seg_size: Some(1460),
                        sack_permitted: true,
                        sack_ranges: [None, None, None],
                        payload: &[],
                    },
                )
                .unwrap(),
            )
            .unwrap();

        let syn_ack = read_until_tcp_control(writer, client, smoltcp::wire::TcpControl::Syn);
        assert_eq!(syn_ack.destination, client);
        assert_eq!(syn_ack.source, server);

        writer
            .send(
                &encode_tun_tcp_packet(
                    client,
                    server,
                    64,
                    &smoltcp::wire::TcpRepr {
                        src_port: client.port(),
                        dst_port: server.port(),
                        control: smoltcp::wire::TcpControl::None,
                        seq_number: smoltcp::wire::TcpSeqNumber(2),
                        ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
                        window_len: 65535,
                        window_scale: None,
                        max_seg_size: None,
                        sack_permitted: false,
                        sack_ranges: [None, None, None],
                        payload: client_payload,
                    },
                )
                .unwrap(),
            )
            .unwrap();

        writer
            .send(
                &encode_tun_tcp_packet(
                    client,
                    server,
                    64,
                    &smoltcp::wire::TcpRepr {
                        src_port: client.port(),
                        dst_port: server.port(),
                        control: smoltcp::wire::TcpControl::Fin,
                        seq_number: smoltcp::wire::TcpSeqNumber(2 + client_payload.len() as i32),
                        ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
                        window_len: 65535,
                        window_scale: None,
                        max_seg_size: None,
                        sack_permitted: false,
                        sack_ranges: [None, None, None],
                        payload: &[],
                    },
                )
                .unwrap(),
            )
            .unwrap();

        let parsed = read_until_tcp_payload(writer, client);
        assert_eq!(parsed.destination, client);
        assert_eq!(parsed.source, server);
        assert_eq!(parsed.tcp_repr.payload, expected_reply);

        acknowledge_server_packet(
            writer,
            client,
            server,
            &parsed,
            2 + client_payload.len() as i32 + 1,
        );
        drain_and_ack_server_fin(writer, client, server, 2 + client_payload.len() as i32 + 1);
    }

    fn read_until_tcp_control(
        writer: &mut UnixDatagram,
        client: std::net::SocketAddr,
        control: smoltcp::wire::TcpControl,
    ) -> crate::tun_tcp_packet::ParsedTunTcpPacket {
        for _ in 0..20 {
            let mut reply = vec![0_u8; 4096];
            let read = match writer.recv(&mut reply) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(err) => panic!("tcp control read failed for client {client}: {err}"),
            };
            if read == 0 {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            let parsed = parse_tun_tcp_packet(&reply[..read]).unwrap();
            if parsed.destination == client && parsed.tcp_repr.control == control {
                return parsed;
            }
        }
        panic!("no tcp control packet {control:?} received from tun worker for client {client}");
    }

    fn read_until_tcp_payload(
        writer: &mut UnixDatagram,
        client: std::net::SocketAddr,
    ) -> crate::tun_tcp_packet::ParsedTunTcpPacket {
        for _ in 0..20 {
            let mut reply = vec![0_u8; 4096];
            let read = match writer.recv(&mut reply) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(err) => panic!("tcp payload read failed for client {client}: {err}"),
            };
            if read == 0 {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            let parsed = parse_tun_tcp_packet(&reply[..read]).unwrap();
            if parsed.destination == client && !parsed.tcp_repr.payload.is_empty() {
                return parsed;
            }
        }
        panic!("no tcp payload packet received from tun worker for client {client}");
    }

    fn acknowledge_server_packet(
        writer: &UnixDatagram,
        client: std::net::SocketAddr,
        server: std::net::SocketAddr,
        packet: &crate::tun_tcp_packet::ParsedTunTcpPacket,
        client_seq: i32,
    ) {
        let mut ack_number = packet.tcp_repr.seq_number + packet.tcp_repr.payload.len();
        if matches!(
            packet.tcp_repr.control,
            smoltcp::wire::TcpControl::Syn | smoltcp::wire::TcpControl::Fin
        ) {
            ack_number += 1usize;
        }
        writer
            .send(
                &encode_tun_tcp_packet(
                    client,
                    server,
                    packet.hop_limit,
                    &smoltcp::wire::TcpRepr {
                        src_port: client.port(),
                        dst_port: server.port(),
                        control: smoltcp::wire::TcpControl::None,
                        seq_number: smoltcp::wire::TcpSeqNumber(client_seq),
                        ack_number: Some(ack_number),
                        window_len: 65535,
                        window_scale: None,
                        max_seg_size: None,
                        sack_permitted: false,
                        sack_ranges: [None, None, None],
                        payload: &[],
                    },
                )
                .unwrap(),
            )
            .unwrap();
    }

    fn drain_and_ack_server_fin(
        writer: &UnixDatagram,
        client: std::net::SocketAddr,
        server: std::net::SocketAddr,
        client_seq: i32,
    ) {
        for _ in 0..4 {
            let mut reply = vec![0_u8; 4096];
            let read = match writer.recv(&mut reply) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(err) => panic!("tcp fin read failed for client {client}: {err}"),
            };
            if read == 0 {
                return;
            }
            let parsed = parse_tun_tcp_packet(&reply[..read]).unwrap();
            if parsed.destination != client {
                continue;
            }
            if matches!(parsed.tcp_repr.control, smoltcp::wire::TcpControl::Fin) {
                acknowledge_server_packet(writer, client, server, &parsed, client_seq);
                return;
            }
        }
    }
