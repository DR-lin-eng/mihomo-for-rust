pub(in super::super) fn connect_vless_udp_stream(
    route: &UdpVlessRoute,
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
    if route.flow == "xtls-rprx-vision"
        || !route.reality_public_key.is_empty()
        || !route.reality_short_id.is_empty()
    {
        // This path reads a complete datagram across TLS records, rather than
        // polling a native UDP socket. The generic UDP dialer starts with a
        // short polling timeout; extend the raw connection before TLS wraps it.
        let _ = super::listener_udp_outbound_support::set_raw_tcp_stream_timeouts(
            &stream,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )?;
        let proxy = TransportTarget::new(route.server.clone(), route.port);
        let stream =
            if !route.reality_public_key.is_empty() || !route.reality_short_id.is_empty() {
                let config = mihomo_transport::RealityClientConfig {
                    public_key: mihomo_transport::parse_reality_public_key(
                        &route.reality_public_key,
                    )
                    .map_err(|err| io::Error::other(err.to_string()))?,
                    short_id: mihomo_transport::parse_reality_short_id(&route.reality_short_id)
                        .map_err(|err| io::Error::other(err.to_string()))?,
                    server_name: route.tls.sni.clone(),
                    support_x25519mlkem768: route.reality_support_x25519mlkem768,
                    alpn: route.alpn.clone(),
                };
                mihomo_transport::wrap_reality_stream(stream, &config, &proxy)
            } else {
                mihomo_transport::wrap_vless_vision_tls_stream(
                    stream,
                    proxy,
                    &route.tls,
                    &route.alpn,
                )
            }
            .map_err(|err| io::Error::other(err.to_string()))?;
        if route.flow == "xtls-rprx-vision" {
            return mihomo_transport::open_vless_vision_udp_stream(
                stream,
                &route.uuid,
                target,
                route.packet_addr,
                route.xudp,
            )
            .map_err(|err| io::Error::other(err.to_string()));
        }
        return if route.xudp {
            open_vless_xudp_stream(stream, &route.uuid)
        } else if route.packet_addr {
            open_vless_packetaddr_udp_stream(stream, &route.uuid)
        } else {
            open_vless_udp_stream(stream, &route.uuid, target)
        }
        .map_err(|err| io::Error::other(err.to_string()));
    }
    let websocket_alpn = vec!["http/1.1".to_owned()];
    let grpc_alpn = vec!["h2".to_owned()];
    let h2_alpn = vec!["h2".to_owned()];
    let websocket = route.websocket.clone();
    let mut tls = route.tls.clone();
    if tls.enabled && tls.sni.trim().is_empty() {
        if let Some((_, host)) = websocket
            .headers
            .iter()
            .find(|(name, value)| {
                name.eq_ignore_ascii_case("host") && !value.trim().is_empty()
            })
        {
            tls.sni = host.clone();
        }
    }
    let mut stream: BoxedTcpStream = if route.tls.enabled {
        if route.network == "xhttp" {
            wrap_xhttp_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                &route.alpn,
                &route.xhttp,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            wrap_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                if route.network == "ws" {
                    &websocket_alpn
                } else if route.network == "grpc" {
                    &grpc_alpn
                } else if route.network == "h2" {
                    &h2_alpn
                } else {
                    &route.alpn
                },
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        }
    } else {
        stream
    };
    if route.network == "ws" {
        stream = wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &websocket,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "grpc" {
        stream = wrap_grpc_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.grpc,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "http" {
        stream = wrap_http_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.http,
        );
    } else if route.network == "h2" {
        stream = wrap_h2_proxy_stream(stream, &route.h2)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "xhttp" && !route.tls.enabled {
        stream = wrap_xhttp_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.xhttp,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    }
    if route.xudp {
        open_vless_xudp_stream(stream, &route.uuid)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else if route.packet_addr {
        open_vless_packetaddr_udp_stream(stream, &route.uuid)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else {
        open_vless_udp_stream(stream, &route.uuid, target)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

pub(in super::super) fn connect_vmess_udp_stream(
    route: &UdpVmessRoute,
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
    let websocket_alpn = vec!["http/1.1".to_owned()];
    let grpc_alpn = vec!["h2".to_owned()];
    let h2_alpn = vec!["h2".to_owned()];
    let websocket = route.websocket.clone();
    let mut tls = route.tls.clone();
    if tls.enabled && tls.sni.trim().is_empty() {
        if let Some((_, host)) = websocket
            .headers
            .iter()
            .find(|(name, value)| {
                name.eq_ignore_ascii_case("host") && !value.trim().is_empty()
            })
        {
            tls.sni = host.clone();
        }
    }
    let mut stream: BoxedTcpStream = if route.tls.enabled {
        if route.network == "xhttp" {
            wrap_xhttp_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                &route.alpn,
                &route.xhttp,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            wrap_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                if route.network == "ws" {
                    &websocket_alpn
                } else if route.network == "grpc" {
                    &grpc_alpn
                } else if route.network == "h2" {
                    &h2_alpn
                } else {
                    &route.alpn
                },
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        }
    } else {
        stream
    };
    if route.network == "ws" {
        stream = wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &websocket,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "grpc" {
        stream = wrap_grpc_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.grpc,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "http" {
        stream = wrap_http_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.http,
        );
    } else if route.network == "h2" {
        stream = wrap_h2_proxy_stream(stream, &route.h2)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "xhttp" && !route.tls.enabled {
        stream = wrap_xhttp_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.xhttp,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    }
    if route.xudp {
        open_vmess_xudp_stream(
            stream,
            &route.uuid,
            route.alter_id,
            &route.cipher,
            route.global_padding,
            route.authenticated_length,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else if route.packet_addr {
        open_vmess_packetaddr_udp_stream(
            stream,
            &route.uuid,
            route.alter_id,
            &route.cipher,
            route.global_padding,
            route.authenticated_length,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else {
        open_vmess_udp_stream(
            stream,
            &route.uuid,
            route.alter_id,
            &route.cipher,
            route.global_padding,
            route.authenticated_length,
            target,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}
