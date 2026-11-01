pub(in super::super) fn connect_snell_udp_stream(
    route: &UdpSnellRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    wrap_snell_udp_stream(
        stream,
        &route.psk,
        route.version,
        &route.obfs_mode,
        &route.obfs_host,
        route.port,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_anytls_udp_stream(
    route: &UdpAnyTlsRoute,
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
    let stream: BoxedTcpStream = wrap_tls_proxy_stream(
        stream,
        TransportTarget::new(route.server.clone(), route.port),
        &route.tls,
        &route.alpn,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    open_anytls_udp_stream(stream, &route.password, target)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}
