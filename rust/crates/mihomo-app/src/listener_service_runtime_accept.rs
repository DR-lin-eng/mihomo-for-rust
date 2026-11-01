pub(super) fn accept_with_shutdown_poll(
    listener: &TcpListener,
    shutdown: &Arc<AtomicBool>,
) -> io::Result<(TcpStream, SocketAddr)> {
    listener.set_nonblocking(true)?;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "listener shutdown requested",
            ));
        }
        match listener.accept() {
            Ok((stream, addr)) => {
                let _ = listener.set_nonblocking(false);
                let _ = stream.set_nonblocking(false);
                return Ok((stream, addr));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(LISTENER_POLL_TIMEOUT);
            }
            Err(err) => {
                let _ = listener.set_nonblocking(false);
                return Err(err);
            }
        }
    }
}

pub(super) fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
    handler: ManagedTcpListenerHandler,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match accept_with_shutdown_poll(&listener, &shutdown) {
            Ok((stream, _)) => {
                let peer_addr = stream.peer_addr().ok();
                let listener_addr = stream.local_addr().ok();
                let listener_kind = handler.kind_name();
                let tunnel = tunnel.clone();
                let handler = handler.clone();
                let dns_runtime = dns_runtime.clone();
                let udp_queue = Arc::clone(&udp_queue);
                crate::blocking_executor::spawn_blocking(move || {
                    if let Err(err) = dispatch_connection(
                        handler,
                        tunnel,
                        stream,
                        peer_addr,
                        dns_runtime,
                        udp_queue,
                    ) {
                        if matches!(listener_kind, "http" | "socks" | "mixed")
                            && err.is_client_handshake_disconnect() {
                            push_log(LogLevel::Debug, format!(
                                "client disconnected during {listener_kind} handshake listener={listener_addr:?} peer={peer_addr:?}: {err}"));
                        } else {
                            log_listener_error(&format!(
                                "listener dispatch error protocol={listener_kind} listener={listener_addr:?} peer={peer_addr:?}"), err);
                        }
                    }
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted
                && shutdown.load(Ordering::Relaxed) => break,
            Err(err) => {
                let message = format!("listener accept error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                break;
            }
        }
    }
}

pub(super) fn dispatch_connection(
    handler: ManagedTcpListenerHandler,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) -> Result<(), ListenerRuntimeError> {
    match handler {
        ManagedTcpListenerHandler::Http(config) => {
            let stream = wrap_http_listener_stream(&config, stream)?;
            let _ = dispatch_http_proxy_tcp_stream_with_dialer(
                &config,
                &tunnel,
                stream,
                peer_addr,
                DnsAwareTcpDialer::new(dns_runtime),
            )?;
        }
        ManagedTcpListenerHandler::Socks(config) => {
            let stream = wrap_tls_listener_stream(&config, stream)?;
            handle_socks5_connection(config, tunnel, stream, peer_addr, dns_runtime, udp_queue)?;
        }
        ManagedTcpListenerHandler::Mixed(config) => {
            let stream = wrap_tls_listener_stream(&config, stream)?;
            handle_mixed_connection(config, tunnel, stream, peer_addr, dns_runtime, udp_queue)?;
        }
        ManagedTcpListenerHandler::Tunnel(config) => {
            let _ = dispatch_tunnel_tcp_stream_with_dialer(
                &config,
                &tunnel,
                stream,
                peer_addr,
                DnsAwareTcpDialer::new(dns_runtime),
            )?;
        }
        ManagedTcpListenerHandler::Redir(config) => {
            transparent::handle_redir_connection(
                config,
                tunnel,
                stream,
                peer_addr,
                dns_runtime,
            )?;
        }
        ManagedTcpListenerHandler::TProxy(config) => {
            transparent::handle_tproxy_connection(
                config,
                tunnel,
                stream,
                peer_addr,
                dns_runtime,
            )?;
        }
        ManagedTcpListenerHandler::ShadowSocks(config) => {
            listener_service_special_inbounds::handle_shadowsocks_connection(
                config, tunnel, stream, peer_addr,
            )?;
        }
        ManagedTcpListenerHandler::Trojan(config) => {
            listener_service_special_inbounds::handle_trojan_connection(
                config, tunnel, stream, peer_addr,
            )?;
        }
        ManagedTcpListenerHandler::AnyTls(config) => {
            special_inbounds::handle_anytls_connection(config, tunnel, stream, peer_addr)?;
        }
        ManagedTcpListenerHandler::Hy2Realm(config, server) => {
            let mut stream: BoxedTcpStream = if let Some(tls_config) = config.tls_config.clone() {
                crate::listener_service_support::accept_tls_server_stream(stream, tls_config)
                    .map_err(ListenerRuntimeError::Io)?
            } else {
                Box::new(stream)
            };
            server
                .handle_stream(&mut *stream)
                .map_err(ListenerRuntimeError::Io)?;
        }
        ManagedTcpListenerHandler::TrustTunnel(config) => {
            special_inbounds::handle_trusttunnel_connection(
                config, tunnel, stream, peer_addr,
            )?;
        }
        ManagedTcpListenerHandler::Sudoku(config) => {
            listener_service_sudoku::handle_sudoku_connection(
                config, tunnel, stream, peer_addr,
            )?;
        }
        ManagedTcpListenerHandler::Vless(config) => {
            listener_service_v2_inbounds::handle_vless_connection(
                config, tunnel, stream, peer_addr,
            )?;
        }
        ManagedTcpListenerHandler::Vmess(config) => {
            listener_service_v2_inbounds::handle_vmess_connection(
                config, tunnel, stream, peer_addr,
            )?;
        }
    }
    Ok(())
}
