pub(in super::super) fn connect_gost_relay_udp_stream(
    route: &UdpGostRelayRoute,
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
    let stream: BoxedTcpStream = if route.tls.enabled {
        wrap_tls_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.tls,
            &[],
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        stream
    };
    let stream = if route.mux {
        wrap_smux_stream(stream)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        stream
    };
    let auth = if route.username.is_empty() {
        None
    } else {
        Some(mihomo_transport::BasicAuth {
            username: route.username.clone(),
            password: route.password.clone(),
        })
    };
    open_gost_relay_udp_stream(stream, auth, route.forward, target)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}
