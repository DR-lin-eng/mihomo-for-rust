fn http_config_from_tls_config(config: &TlsInboundConfig) -> HttpInboundConfig {
    HttpInboundConfig {
        base: config.base.clone(),
        users: config.users.clone(),
        certificate: config.certificate.clone(),
        private_key: config.private_key.clone(),
        client_auth_type: config.client_auth_type.clone(),
        client_auth_cert: config.client_auth_cert.clone(),
        ech_key: config.ech_key.clone(),
        reality_config: config.reality_config.clone(),
        extra: config.extra.clone(),
    }
}

fn prepend_stream(stream: BoxedTcpStream, prefix: Vec<u8>) -> BoxedTcpStream {
    if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedStream {
            prefix: Cursor::new(prefix),
            inner: stream,
        })
    }
}

fn wrap_http_listener_stream(
    config: &HttpInboundConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    let tls_enabled = !config.certificate.trim().is_empty() || !config.private_key.trim().is_empty();
    if !tls_enabled {
        return Ok(Box::new(stream));
    }
    let tls_config = Arc::new(
        build_server_tls_config(
            &config.certificate,
            &config.private_key,
            "",
            &config.client_auth_type,
            &config.client_auth_cert,
            &config.ech_key,
            config.reality_config != mihomo_inbound::RealityConfig::default(),
        )
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?,
    );
    bridge_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)
}

fn wrap_tls_listener_stream(
    config: &TlsInboundConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    let tls_enabled = !config.certificate.trim().is_empty() || !config.private_key.trim().is_empty();
    if !tls_enabled {
        return Ok(Box::new(stream));
    }
    let tls_config = Arc::new(
        build_server_tls_config(
            &config.certificate,
            &config.private_key,
            "",
            &config.client_auth_type,
            &config.client_auth_cert,
            &config.ech_key,
            config.reality_config != mihomo_inbound::RealityConfig::default(),
        )
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?,
    );
    bridge_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)
}

fn bridge_tls_server_stream(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
) -> io::Result<BoxedTcpStream> {
    let conn = ServerConnection::new(tls_config)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    stream.set_nonblocking(true)?;
    let tls_stream = StreamOwned::new(conn, stream);
    let (client, server) = local_tcp_stream_pair()?;
    client.set_nodelay(true)?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    client.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    server.set_nodelay(true)?;
    server.set_nonblocking(true)?;
    crate::blocking_executor::spawn_blocking(move || run_tls_bridge_loop(tls_stream, server));
    Ok(Box::new(client))
}

fn local_tcp_stream_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = TcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    Ok((client, server))
}

fn run_tls_bridge_loop(
    mut tls: StreamOwned<ServerConnection, TcpStream>,
    mut plain: TcpStream,
) {
    let handshake_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut plain_to_tls = Vec::new();
    let mut plain_to_tls_offset = 0usize;
    let mut tls_to_plain = Vec::new();
    let mut tls_to_plain_offset = 0usize;
    let mut plain_open = true;
    let mut tls_open = true;
    let mut close_notify_sent = false;
    let mut buf = [0_u8; 16 * 1024];

    loop {
        if tls.conn.is_handshaking() && std::time::Instant::now() >= handshake_deadline {
            let _ = plain.shutdown(std::net::Shutdown::Both);
            return;
        }
        let mut progressed = false;

        if plain_open && plain_to_tls_offset >= plain_to_tls.len() {
            plain_to_tls.clear();
            plain_to_tls_offset = 0;
            match plain.read(&mut buf) {
                Ok(0) => {
                    plain_open = false;
                }
                Ok(read) => {
                    plain_to_tls.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                Err(_) => {
                    plain_open = false;
                }
            }
        }

        if plain_to_tls_offset < plain_to_tls.len() {
            match tls.write(&plain_to_tls[plain_to_tls_offset..]) {
                Ok(0) => {}
                Ok(written) => {
                    plain_to_tls_offset += written;
                    progressed = true;
                }
                Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                Err(_) => {
                    tls_open = false;
                }
            }
            let _ = tls.flush();
        } else if !plain_open && !close_notify_sent {
            tls.conn.send_close_notify();
            let _ = tls.flush();
            close_notify_sent = true;
        }

        if tls_open && tls_to_plain_offset >= tls_to_plain.len() {
            tls_to_plain.clear();
            tls_to_plain_offset = 0;
            match tls.read(&mut buf) {
                Ok(0) => {
                    if !tls_to_plain.is_empty() && tls_to_plain_offset < tls_to_plain.len() {
                        // Let the buffered plaintext flush before closing the plain side.
                    } else {
                        tls_open = false;
                        let _ = plain.shutdown(std::net::Shutdown::Write);
                    }
                }
                Ok(read) => {
                    tls_to_plain.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                Err(_) => {
                    if !tls_to_plain.is_empty() && tls_to_plain_offset < tls_to_plain.len() {
                        // Preserve any buffered plaintext on transient shutdown paths.
                    } else {
                        tls_open = false;
                        let _ = plain.shutdown(std::net::Shutdown::Write);
                    }
                }
            }
        }

        if tls_to_plain_offset < tls_to_plain.len() {
            match plain.write(&tls_to_plain[tls_to_plain_offset..]) {
                Ok(0) => {}
                Ok(written) => {
                    tls_to_plain_offset += written;
                    progressed = true;
                }
                Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                Err(_) => break,
            }
            let _ = plain.flush();
            if tls_to_plain_offset >= tls_to_plain.len() && !tls_open {
                let _ = plain.shutdown(std::net::Shutdown::Write);
            }
        }

        if !plain_open
            && !tls_open
            && plain_to_tls_offset >= plain_to_tls.len()
            && tls_to_plain_offset >= tls_to_plain.len()
        {
            let _ = plain.shutdown(std::net::Shutdown::Both);
            break;
        }

        if !progressed {
            thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}
