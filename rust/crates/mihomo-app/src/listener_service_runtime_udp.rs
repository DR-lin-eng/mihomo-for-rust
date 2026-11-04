pub(super) fn handle_mixed_connection(
    config: TlsInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: impl mihomo_core::TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) -> Result<(), ListenerRuntimeError> {
    let mut stream: BoxedTcpStream = Box::new(stream);
    let mut first = [0_u8; 1];
    let peeked = stream.read(&mut first).map_err(ListenerRuntimeError::Io)?;
    if peeked == 0 {
        return Ok(());
    }
    let stream = prepend_stream(stream, first[..peeked].to_vec());
    if first[0] == 0x05 {
        handle_socks5_connection(config, tunnel, stream, peer_addr, dns_runtime, udp_queue)
    } else {
        let http_config = http_config_from_tls_config(&config);
        let _ = dispatch_http_proxy_tcp_stream_with_dialer(
            &http_config,
            &tunnel,
            stream,
            peer_addr,
            DnsAwareTcpDialer::new(dns_runtime),
        )?;
        Ok(())
    }
}

pub(super) fn handle_socks5_connection(
    config: TlsInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: impl mihomo_core::TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) -> Result<(), ListenerRuntimeError> {
    match prepare_socks5_dispatch(&config, stream, peer_addr)? {
        PreparedSocks5Dispatch::Connect(mut context) => {
            let _ = dispatch_prepared_socks5_tcp_context_with_dialer(
                &tunnel,
                &mut context,
                DnsAwareTcpDialer::new(dns_runtime),
            )?;
        }
        PreparedSocks5Dispatch::UdpAssociate(associate) => {
            handle_socks5_udp_associate(config, tunnel, associate, dns_runtime, udp_queue)?;
        }
    }
    Ok(())
}

pub(super) fn udp_loop(
    socket: UdpSocket,
    shutdown: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
    listener: ManagedUdpListenerConfig,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) {
    let socket = Arc::new(socket);
    let session_pool = Arc::new(crate::tun_packet::TunUdpSessionPool::new_with_timeout(
        super::transparent::TRANSPARENT_UDP_IDLE_TIMEOUT));
    while !shutdown.load(Ordering::Relaxed) {
        match &listener.handler {
            ManagedUdpListenerHandler::Redir(config) => {
                match super::transparent::recv_transparent_udp_packet(&socket) {
                    Ok(Some((payload, peer_addr, target_addr))) => {
                        let inbound_listener_addr = socket.local_addr().unwrap_or(peer_addr);
                        udp_queue.push(UdpDispatchTask::Transparent {
                            session_pool: session_pool.clone(),
                            inbound_listener_addr,
                            peer_addr,
                            target_addr,
                            payload,
                            tunnel: Arc::clone(&tunnel),
                            inbound_name: config.base.name.clone(),
                            special_proxy: config.base.special_proxy.clone(),
                            special_rules: config.base.special_rules.clone(),
                            dns_runtime: dns_runtime.clone(),
                            session_kind: SessionKind::Redir,
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let message = format!("udp listener recv error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                        break;
                    }
                }
            }
            ManagedUdpListenerHandler::TProxy(config) => {
                match super::transparent::recv_transparent_udp_packet(&socket) {
                    Ok(Some((payload, peer_addr, target_addr))) => {
                        let inbound_listener_addr = socket.local_addr().unwrap_or(peer_addr);
                        udp_queue.push(UdpDispatchTask::Transparent {
                            session_pool: session_pool.clone(),
                            inbound_listener_addr,
                            peer_addr,
                            target_addr,
                            payload,
                            tunnel: Arc::clone(&tunnel),
                            inbound_name: config.base.name.clone(),
                            special_proxy: config.base.special_proxy.clone(),
                            special_rules: config.base.special_rules.clone(),
                            dns_runtime: dns_runtime.clone(),
                            session_kind: SessionKind::TProxy,
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let message = format!("udp listener recv error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                        break;
                    }
                }
            }
            _ => {
                let mut buf = [0_u8; 64 * 1024];
                match socket.recv_from(&mut buf) {
                    Ok((read, peer_addr)) => {
                        let payload = buf[..read].to_vec();
                        udp_queue.push(UdpDispatchTask::Generic {
                            socket: Arc::clone(&socket),
                            peer_addr,
                            payload,
                            tunnel: Arc::clone(&tunnel),
                            listener: listener.clone(),
                            dns_runtime: dns_runtime.clone(),
                        });
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(err) => {
                        let message = format!("udp listener recv error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                        break;
                    }
                }
            }
        }
    }
    session_pool.shutdown();
}

pub(super) fn dns_loop(
    socket: UdpSocket,
    shutdown: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
) {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !shutdown.load(Ordering::Relaxed) {
        let mut buf = [0_u8; 65535];
        match socket.recv_from(&mut buf) {
            Ok((read, peer_addr)) => {
                // Local fake-IP answers must stay available while an unrelated
                // HTTPS/SVCB query waits for a remote resolver.
                let local = tunnel.dns_runtime().map(|runtime| {
                    runtime.lock().unwrap().local_query_packet(&buf[..read])
                });
                if let Some(Ok(Some(response))) = local {
                    let _ = socket.send_to(&response, peer_addr);
                    continue;
                }
                if in_flight.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < 64).then_some(n+1)).is_err() {
                    if let Ok(response) = mihomo_dns::build_servfail_response(&buf[..read]) {
                        let _ = socket.send_to(&response, peer_addr);
                    }
                    continue;
                }
                let permit = DnsQueryPermit(in_flight.clone());
                let payload = buf[..read].to_vec();
                let socket = socket.clone();
                let tunnel = tunnel.clone();
                crate::blocking_executor::spawn_blocking(move || {
                    let _permit = permit;
                    match crate::dns_transport::relay_shared_query_packet(tunnel, &payload) {
                        Ok(Some(response)) => { let _ = socket.send_to(&response, peer_addr); }
                        Ok(None) => {}
                        Err(err) => {
                            if let Ok(response) = mihomo_dns::build_servfail_response(&payload) {
                                let _ = socket.send_to(&response, peer_addr);
                            }
                            push_log(LogLevel::Error, format!("dns listener error: {err}"));
                        }
                    }
                });
            }
            Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(err) => {
                let message = format!("dns listener recv error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                break;
            }
        }
    }
}

struct DnsQueryPermit(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for DnsQueryPermit {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
}

pub(super) fn handle_socks5_udp_associate(
    config: TlsInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    mut associate: PreparedSocks5UdpAssociate,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) -> Result<(), ListenerRuntimeError> {
    if !config.udp {
        return Err(ListenerRuntimeError::SocksUnsupportedCommand(0x03));
    }

    let udp_socket = UdpSocket::bind(listener_service_builders::bind_ephemeral(&config.base.listen))?;
    udp_socket.set_read_timeout(Some(LISTENER_POLL_TIMEOUT))?;
    let bind_addr = udp_socket.local_addr()?;
    write_socks5_udp_associate_reply(&mut *associate.stream, bind_addr)?;
    // The accept path arms a short handshake deadline. The control channel is
    // established now and may legitimately remain idle while UDP packets use
    // the associated socket.
    let _ = associate.stream.set_timeouts(None, None);

    let stop = Arc::new(AtomicBool::new(false));
    let udp_socket = Arc::new(udp_socket);
    let tunnel_for_loop = Arc::clone(&tunnel);
    let stop_for_loop = Arc::clone(&stop);
    let dns_runtime_for_loop = dns_runtime.clone();
    let inbound_name = associate.inbound_name.clone();
    let special_proxy = associate.special_proxy.clone();
    let special_rules = associate.special_rules.clone();
    let inbound_user = associate.inbound_user.clone();
    let udp_queue_for_worker = Arc::clone(&udp_queue);
    let udp_worker = thread::spawn(move || {
        listener_udp_dispatch::socks_udp_loop(
            udp_socket,
            stop_for_loop,
            tunnel_for_loop,
            inbound_name,
            inbound_user,
            special_proxy,
            special_rules,
            dns_runtime_for_loop,
            udp_queue_for_worker,
        );
    });

    let mut buf = [0_u8; 1];
    loop {
        match associate.stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = udp_worker.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::listener_service::configure_tproxy_udp_listener_socket;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn transparent_recvmsg_reports_original_destination_for_tproxy_listener_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        configure_tproxy_udp_listener_socket(&server).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();

        client.send_to(b"transparent-ping", server_addr).unwrap();

        let (payload, peer_addr, target_addr) =
            super::transparent::recv_transparent_udp_packet(&server)
                .unwrap()
                .expect("expected transparent packet");
        assert_eq!(payload, b"transparent-ping".to_vec());
        assert_eq!(peer_addr, client_addr);
        assert_eq!(target_addr, server_addr);
    }
}


pub(super) fn dns_tcp_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, tunnel: Arc<RuntimeTunnel>) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let tunnel = Arc::clone(&tunnel);
                let shutdown = Arc::clone(&shutdown);
                thread::spawn(move || -> io::Result<()> {
                    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
                    while !shutdown.load(Ordering::Relaxed) {
                        let mut size = [0; 2];
                        stream.read_exact(&mut size)?;
                        let mut query = vec![0; u16::from_be_bytes(size) as usize];
                        stream.read_exact(&mut query)?;
                        let response = match crate::dns_transport::relay_shared_query_packet(Arc::clone(&tunnel), &query) {
                            Ok(Some(response)) => response,
                            Ok(None) => continue,
                            Err(_) => mihomo_dns::build_servfail_response(&query).map_err(io::Error::other)?,
                        };
                        let size = u16::try_from(response.len()).map_err(io::Error::other)?;
                        stream.write_all(&size.to_be_bytes())?;
                        stream.write_all(&response)?;
                    }
                    Ok(())
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => thread::sleep(LISTENER_POLL_TIMEOUT),
            Err(_) => break,
        }
    }
}
