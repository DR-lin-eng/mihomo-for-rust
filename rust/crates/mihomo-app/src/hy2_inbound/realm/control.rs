fn discover_realm_addresses_via_waiters(
    socket: &StdUdpSocket,
    state: &Arc<Hy2RealmRuntimeState>,
    last_known: &Mutex<Vec<SocketAddr>>,
) -> io::Result<Vec<SocketAddr>> {
    let mut resolved = Vec::new();
    for server in &state.stun_servers {
        let mut addrs = server.to_socket_addrs()?;
        let addr = addrs
            .next()
            .ok_or_else(|| io::Error::other("realm stun address unresolved"))?;
        let request = new_hy2_realm_stun_binding_request()
            .map_err(|err| io::Error::other(err.to_string()))?;
        let (tx, rx) = mpsc::sync_channel(1);
        if let Ok(mut waiters) = state.stun_waiters.lock() {
            waiters.insert(request.transaction_id, tx);
        }
        let _ = socket.send_to(&request.raw, addr);
        if let Ok(mapped) = rx.recv_timeout(Duration::from_millis(500)) {
            if !resolved.contains(&mapped) {
                resolved.push(mapped);
            }
        }
    }
    if resolved.is_empty() {
        let fallback = last_known
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();
        if !fallback.is_empty() {
            return Ok(fallback);
        }
        return Err(io::Error::other("realm stun discovery yielded no addresses"));
    }
    Ok(resolved)
}

fn respond_realm_punch_via_waiters(
    socket: &StdUdpSocket,
    state: &Arc<Hy2RealmRuntimeState>,
    local_addresses: &[SocketAddr],
    peer_addresses: &[SocketAddr],
    metadata: Hy2RealmPunchMetadata,
) -> io::Result<SocketAddr> {
    let candidates = peer_addresses
        .iter()
        .copied()
        .filter(|addr| {
            addr.ip().is_ipv4()
                == local_addresses
                    .first()
                    .map(|a| a.ip().is_ipv4())
                    .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let (tx, rx) = mpsc::sync_channel(8);
    if let Ok(mut waiters) = state.punch_waiters.lock() {
        waiters.push((metadata, tx));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let hello = encode_hy2_realm_punch_packet(Hy2RealmPunchPacketType::Hello, metadata)
            .map_err(|err| io::Error::other(err.to_string()))?;
        for candidate in &candidates {
            let _ = socket.send_to(&hello, candidate);
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((from, packet_type)) => {
                if matches!(packet_type, Hy2RealmPunchPacketType::Hello) {
                    let ack =
                        encode_hy2_realm_punch_packet(Hy2RealmPunchPacketType::Ack, metadata)
                            .map_err(|err| io::Error::other(err.to_string()))?;
                    let _ = socket.send_to(&ack, from);
                }
                return Ok(from);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(io::Error::other("realm punch timeout"))
}

fn connect_realm_http_with_runtime_tunnel(
    tunnel: &RuntimeTunnel,
    target: &mihomo_transport::TransportTarget,
    tls: &mihomo_transport::TlsOptions,
    alpn: &[String],
    proxy: &str,
) -> Result<BoxedTcpStream, mihomo_transport::TransportError> {
    let proxy = proxy.trim();
    if proxy.is_empty() || proxy.eq_ignore_ascii_case("DIRECT") || proxy.contains("://") {
        return connect_http_target_via_realm_proxy(target, tls, alpn, proxy);
    }

    let metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::Hysteria2,
        host: Some(target.host.clone()),
        dst_port: Some(target.port),
        special_proxy: proxy.to_owned(),
        ..Metadata::default()
    };
    let (stream, _plan) = tunnel
        .connect_tcp_with_system_dialer(&metadata)
        .map_err(|err| mihomo_transport::TransportError::Io {
            kind: io::ErrorKind::Other,
            message: err.to_string(),
        })?;
    if tls.enabled {
        mihomo_transport::wrap_tls_proxy_stream(stream, target.clone(), tls, alpn)
    } else {
        Ok(stream)
    }
}
