pub(in super::super) fn connect_trojan_udp_stream(
    route: &UdpTrojanRoute,
    tunnel: &RuntimeTunnel,
    target: SocketAddr,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    let proxy = TransportTarget::new(route.server.clone(), route.port);
    let websocket_alpn = vec!["http/1.1".to_owned()];
    let mut websocket = route.websocket.clone();
    let tls = route.tls.clone();
    let has_host = websocket
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("host"));
    if !tls.sni.trim().is_empty() && !has_host {
        websocket.headers.insert("Host".to_owned(), tls.sni.clone());
    }
    if route.network == "grpc" {
        let stream: BoxedTcpStream = if route.tls.enabled {
            wrap_grpc_tls_proxy_stream(stream, proxy.clone(), &tls, &route.grpc)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            wrap_grpc_proxy_stream(stream, proxy.clone(), &route.grpc)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        };
        return open_trojan_udp_stream(
            stream,
            &route.password,
            &route.shadowsocks,
            proxy,
            TransportTarget::new(target.ip().to_string(), target.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    let stream = if route.network == "ws" {
        let stream: BoxedTcpStream = if route.tls.enabled {
            wrap_tls_proxy_stream(stream, proxy.clone(), &tls, &websocket_alpn)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            stream
        };
        wrap_websocket_proxy_stream(stream, proxy.clone(), &websocket)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else if route.network == "h2" && route.tls.enabled {
        wrap_h2_tls_proxy_stream(stream, proxy.clone(), &tls, &route.h2)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else if route.network == "h2" {
        wrap_h2_proxy_stream(stream, &route.h2)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else if route.network == "xhttp" && route.tls.enabled {
        wrap_xhttp_tls_proxy_stream(
            stream,
            proxy.clone(),
            &tls,
            &route.alpn,
            &route.xhttp,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else if route.network == "xhttp" {
        wrap_xhttp_proxy_stream(stream, proxy.clone(), &route.xhttp)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else if route.network == "http" {
        let stream: BoxedTcpStream = if route.tls.enabled {
            wrap_tls_proxy_stream(stream, proxy.clone(), &tls, &route.alpn)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            stream
        };
        wrap_http_proxy_stream(stream, proxy.clone(), &route.http)
    } else if route.tls.enabled {
        wrap_tls_proxy_stream(stream, proxy.clone(), &tls, &route.alpn)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        stream
    };
    open_trojan_udp_stream(
        stream,
        &route.password,
        &route.shadowsocks,
        proxy,
        TransportTarget::new(target.ip().to_string(), target.port()),
        &mihomo_transport::TlsOptions::default(),
        &[],
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_trusttunnel_udp_stream(
    route: &UdpTrustTunnelRoute,
    plan: &ExecutionPlan,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    if route.quic {
        let proxy = TransportTarget::new(route.server.clone(), route.port);
        if let Some((control_stream, auth)) = resolve_outer_socks5_udp_stream(
            plan,
            plan.hops.len().saturating_sub(1),
            "trusttunnel quic dialer-proxy requires socks5 udp support on the outer proxy",
            "trusttunnel quic dialer-proxy currently supports only an outer socks5 proxy",
            dns_runtime.cloned(),
        )? {
            return open_trusttunnel_quic_udp_stream_with_socks5_stream(
                proxy,
                &route.tls,
                &route.alpn,
                &route.username,
                &route.password,
                control_stream,
                auth,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
        }
        return open_trusttunnel_quic_udp_stream(
            proxy,
            &route.tls,
            &route.alpn,
            &route.username,
            &route.password,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    open_trusttunnel_udp_stream(
        stream,
        TransportTarget::new(route.server.clone(), route.port),
        &route.tls,
        &route.alpn,
        &route.username,
        &route.password,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_tuic_udp_stream(
    route: &UdpTuicRoute,
    plan: &ExecutionPlan,
    _tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let dns_runtime_clone = dns_runtime.cloned();
    let mut dialer = super::super::DnsAwareTcpDialer::new(dns_runtime_clone.clone());
    let options = TuicUdpOptions {
        uuid: route.uuid.clone(),
        password: route.password.clone(),
        token: route.token.clone(),
        sni: route.sni.clone(),
        certificate: route.certificate.clone(),
        private_key: route.private_key.clone(),
        alpn: route.alpn.clone(),
        disable_sni: route.disable_sni,
        request_timeout_ms: route.request_timeout_ms,
        heartbeat_interval_ms: route.heartbeat_interval_ms,
        congestion_controller: route.congestion_controller.clone(),
        max_open_streams: route.max_open_streams,
        max_udp_relay_packet_size: route.max_udp_relay_packet_size,
        skip_cert_verify: route.tls.skip_cert_verify,
    };
    let proxy = TransportTarget::new(route.server.as_str(), route.port);
    if let Some((control_stream, auth)) =
        resolve_tuic_outer_socks5_stream(route, plan, dns_runtime_clone)?
    {
        return open_tuic_udp_stream_with_socks5_stream(
            &mut dialer,
            &proxy,
            &options,
            control_stream,
            auth,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    open_tuic_udp_stream_with_dialer(&mut dialer, &proxy, &options)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}
