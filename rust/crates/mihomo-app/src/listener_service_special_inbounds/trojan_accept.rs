fn accept_trojan_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<Option<BoxedTcpStream>, ListenerRuntimeError> {
    match config.network.as_str() {
        "ws" => accept_trojan_ws_stream(config, stream).map(Some),
        "h2" => accept_trojan_h2_stream(config, stream).map(Some),
        "xhttp" => accept_trojan_xhttp_stream(config, stream),
        "grpc" => accept_trojan_grpc_stream(config, stream).map(Some),
        "http" => accept_trojan_http_stream(config, stream).map(Some),
        _ => accept_trojan_tls_stream(config, stream).map(Some),
    }
}

fn accept_trojan_ws_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    let stream = accept_trojan_tls_stream(config, stream)?;
    accept_websocket_server_stream(stream, &config.ws_path).map_err(ListenerRuntimeError::Io)
}

fn accept_trojan_h2_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
        mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
            .map_err(ListenerRuntimeError::Io)?
    } else {
        mihomo_transport::accept_h2_test_stream(Box::new(stream))
            .map_err(ListenerRuntimeError::Io)?
    };
    let expected_authority = config
        .h2_hosts
        .first()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default();
    let expected_path = if config.h2_path.trim().is_empty() {
        "/".to_owned()
    } else {
        config.h2_path.clone()
    };
    if request.method != "PUT" {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected trojan h2 request method: {}", request.method),
        )));
    }
    if !expected_authority.is_empty() && request.authority != expected_authority {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected trojan h2 authority: expected={expected_authority}, got={}",
                request.authority
            ),
        )));
    }
    if request.path != expected_path {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected trojan h2 path: expected={expected_path}, got={}",
                request.path
            ),
        )));
    }
    Ok(stream)
}

fn accept_trojan_xhttp_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<Option<BoxedTcpStream>, ListenerRuntimeError> {
    let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
        mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
            .map_err(ListenerRuntimeError::Io)?
    } else {
        mihomo_transport::accept_h2_test_stream(Box::new(stream))
            .map_err(ListenerRuntimeError::Io)?
    };
    accept_inbound_xhttp_stream(
        "trojan",
        &config.xhttp,
        &config.xhttp_sessions,
        AcceptedXhttpRequest {
            method: request.method,
            authority: request.authority,
            path: request.path,
            headers: request.headers,
        },
        stream,
    )
}

fn accept_trojan_grpc_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
        mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
            .map_err(ListenerRuntimeError::Io)?
    } else {
        mihomo_transport::accept_h2_test_stream(Box::new(stream))
            .map_err(ListenerRuntimeError::Io)?
    };
    let expected_path = format!("/{}/Tun", config.grpc_service_name);
    if request.method != "POST" || request.path != expected_path {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected trojan grpc request: method={}, path={}",
                request.method, request.path
            ),
        )));
    }
    Ok(mihomo_transport::accept_grpc_test_stream(stream))
}

fn accept_trojan_http_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    let stream = accept_trojan_tls_stream(config, stream)?;
    let (request, stream) = accept_http_server_stream(stream).map_err(ListenerRuntimeError::Io)?;
    let request_line = request.lines().next().ok_or_else(|| {
        ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing trojan http request line",
        ))
    })?;
    let mut parts = request_line.split_whitespace();
    let actual_method = parts.next().unwrap_or_default();
    let actual_path = parts.next().unwrap_or_default();
    let method = if config.http.method.trim().is_empty() {
        "GET"
    } else {
        config.http.method.trim()
    };
    let expected_path = config
        .http
        .path
        .first()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            if value.starts_with('/') {
                value.clone()
            } else {
                format!("/{value}")
            }
        })
        .unwrap_or_else(|| "/".to_owned());
    let expected_host = config
        .http
        .host
        .first()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default();
    if actual_method != method || actual_path != expected_path {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected trojan http request: method={}, path={}",
                actual_method, actual_path
            ),
        )));
    }
    if !expected_host.is_empty() && !request.contains(&format!("Host: {expected_host}\r\n")) {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected trojan http host: expected={expected_host}"),
        )));
    }
    for (name, values) in &config.http.headers {
        if name.eq_ignore_ascii_case("host") || values.is_empty() {
            continue;
        }
        let expected = format!("{name}: {}\r\n", values[0]);
        if !request.contains(&expected) {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected trojan http header: expected={expected:?}"),
            )));
        }
    }
    Ok(stream)
}

fn accept_trojan_tls_stream(
    config: &TrojanListenerConfig,
    stream: TcpStream,
) -> Result<BoxedTcpStream, ListenerRuntimeError> {
    if let Some(tls_config) = config.tls_config.clone() {
        accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)
    } else {
        Ok(Box::new(stream))
    }
}
