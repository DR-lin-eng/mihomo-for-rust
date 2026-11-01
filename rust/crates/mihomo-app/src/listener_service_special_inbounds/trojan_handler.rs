pub(in crate::listener_service) fn handle_trojan_connection(
    config: TrojanListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let Some(mut stream) = accept_trojan_stream(&config, stream)? else {
        return Ok(());
    };
    if config.shadowsocks.enabled {
        stream = mihomo_transport::accept_shadowsocks_test_stream(
            stream,
            &config.shadowsocks.method,
            &config.shadowsocks.password,
        )
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?;
    }

    let (password, command, target) = read_trojan_request(&mut *stream)?;
    let Some(username) = config.password_keys.get(&password).cloned() else {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trojan listener authentication failed",
        )));
    };
    if command != 0x01 && command != 0x03 {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("trojan listener command is not implemented yet: {command}"),
        )));
    }
    if command == 0x03 {
        return stream_udp::forward_stream_udp_over_tcp(
            stream,
            tunnel,
            &config.base,
            SessionKind::Trojan,
            peer_addr,
            read_trojan_udp_packet,
            write_trojan_udp_packet,
            "trojan inbound udp stream mutex poisoned",
            username,
        );
    }

    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::Trojan,
        inbound_name: config.base.name.clone(),
        inbound_user: username,
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata
        .set_remote_address(&target)
        .map_err(ListenerRuntimeError::from)?;
    let mut context = ConnectionContext::new(stream, metadata);
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)?;
    Ok(())
}

fn trojan_password_key(password: &str) -> String {
    sha2::Sha224::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
