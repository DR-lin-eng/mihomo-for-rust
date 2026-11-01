use std::io;

use mihomo_core::BoxedTcpStream;
use mihomo_dns::DnsRuntime;
use mihomo_runtime::{
    ExecutionPlan, RuntimeTunnel, UdpHy2Route, UdpHysteriaRoute,
    UdpMasqueRoute, UdpOpenVpnRoute, UdpSudokuRoute, UdpWireGuardRoute,
};
use mihomo_transport::{
    open_hy2_udp_stream_with_dialer, open_hy2_udp_stream_with_socks5_stream,
    open_hysteria_udp_stream_with_dialer,
    open_hysteria_udp_stream_with_socks5_stream,
    open_masque_udp_stream, open_openvpn_udp_stream,
    open_openvpn_udp_stream_with_boxed_tcp,
    open_openvpn_udp_stream_with_socks5_stream, open_sudoku_udp_stream,
    open_wireguard_udp_stream, Hy2RealmOptions, Hy2UdpOptions,
    HysteriaOptions, MasqueConnectOptions, OpenVpnOptions,
    TransportTarget, WireGuardOptions,
};

use super::listener_udp_outbound_support::{
    clone_raw_tcp_stream, connect_udp_dialer_proxy_stream,
    connect_udp_dialer_proxy_stream_with_timeouts, normalize_openvpn_proto,
    resolve_outer_socks5_udp_stream,
    UDP_PROXY_STREAM_HANDSHAKE_READ_TIMEOUT, UDP_PROXY_STREAM_READ_TIMEOUT,
    UDP_PROXY_STREAM_WRITE_TIMEOUT,
};

pub(in super::super) fn connect_wireguard_udp_stream(
    route: &UdpWireGuardRoute,
    _tunnel: &RuntimeTunnel,
    _dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    open_wireguard_udp_stream(&WireGuardOptions {
        private_key: route.private_key.clone(),
        ip: route.ip.clone(),
        ipv6: route.ipv6.clone(),
        workers: route.workers,
        mtu: route.mtu,
        remote_dns_resolve: route.remote_dns_resolve,
        dns: route.dns.clone(),
        peers: route
            .peers
            .iter()
            .map(|peer| mihomo_transport::WireGuardPeerOptions {
                server: peer.server.clone(),
                port: peer.port,
                public_key: peer.public_key.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                persistent_keepalive: peer.persistent_keepalive,
            })
            .collect(),
    })
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_openvpn_udp_stream(
    route: &UdpOpenVpnRoute,
    plan: &ExecutionPlan,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let options = OpenVpnOptions {
        server: route.server.clone(),
        port: route.port,
        proto: route.proto.clone(),
        dev: route.dev.clone(),
        cipher: route.cipher.clone(),
        auth: route.auth.clone(),
        ca: route.ca.clone(),
        cert: route.cert.clone(),
        key: route.key.clone(),
        tls_crypt: route.tls_crypt.clone(),
        username: route.username.clone(),
        password: route.password.clone(),
        remote_dns_resolve: route.remote_dns_resolve,
        dns: route.dns.clone(),
        mtu: route.mtu,
    };
    let normalized_proto = normalize_openvpn_proto(&route.proto);
    if normalized_proto == "udp"
        && route
            .dialer_proxy
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        let Some((control_stream, auth)) = resolve_outer_socks5_udp_stream(
            plan,
            plan.hops.len().saturating_sub(1),
            "openvpn udp dialer-proxy requires socks5 udp support on the outer proxy",
            "openvpn udp dialer-proxy currently supports only an outer socks5 proxy",
            dns_runtime.cloned(),
        )? else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "openvpn udp dialer-proxy requires an outer proxy hop",
            ));
        };
        return open_openvpn_udp_stream_with_socks5_stream(&options, control_stream, auth)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    if normalized_proto == "tcp"
        && route
            .dialer_proxy
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        let stream = connect_udp_dialer_proxy_stream(
            tunnel,
            route.dialer_proxy.as_deref(),
            route.server.as_str(),
            route.port,
            dns_runtime,
        )?;
        return open_openvpn_udp_stream_with_boxed_tcp(&options, stream)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    open_openvpn_udp_stream(&options)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_masque_udp_stream(
    route: &UdpMasqueRoute,
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
    open_masque_udp_stream(
        stream,
        &TransportTarget::new(route.server.clone(), route.port),
        &MasqueConnectOptions {
            private_key: route.private_key.clone(),
            public_key: route.public_key.clone(),
            ip: route.ip.clone(),
            ipv6: route.ipv6.clone(),
            uri: route.uri.clone(),
            mtu: route.mtu,
            network: route.network.clone(),
            remote_dns_resolve: route.remote_dns_resolve,
            dns: route.dns.clone(),
        },
        &route.tls,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_hysteria_udp_stream(
    route: &UdpHysteriaRoute,
    plan: &ExecutionPlan,
    _tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let dns_runtime_clone = dns_runtime.cloned();
    let mut dialer = super::super::DnsAwareTcpDialer::new(dns_runtime_clone.clone());
    let options = HysteriaOptions {
        ports: route.ports.clone(),
        protocol: route.protocol.clone(),
        auth: route.auth.clone(),
        auth_str: route.auth_str.clone(),
        obfs: route.obfs.clone(),
        sni: route.sni.clone(),
        alpn: route.alpn.clone(),
        up: route.up.clone(),
        down: route.down.clone(),
        up_speed: route.up_speed,
        down_speed: route.down_speed,
        disable_mtu_discovery: route.disable_mtu_discovery,
        fast_open: route.fast_open,
        hop_interval: route.hop_interval,
        skip_cert_verify: route.tls.skip_cert_verify,
    };
    let proxy = TransportTarget::new(route.server.as_str(), route.port);
    if let Some((control_stream, auth)) = resolve_outer_socks5_udp_stream(
        plan,
        plan.hops.len().saturating_sub(1),
        "hysteria udp dialer-proxy requires socks5 udp support on the outer proxy",
        "hysteria udp dialer-proxy currently supports only an outer socks5 proxy",
        dns_runtime_clone,
    )? {
        return open_hysteria_udp_stream_with_socks5_stream(
            &mut dialer,
            &proxy,
            &options,
            control_stream,
            auth,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    open_hysteria_udp_stream_with_dialer(&mut dialer, &proxy, &options)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_hy2_udp_stream(
    route: &UdpHy2Route,
    plan: &ExecutionPlan,
    _tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let dns_runtime_clone = dns_runtime.cloned();
    let mut dialer = super::super::DnsAwareTcpDialer::new(dns_runtime_clone.clone());
    let options = Hy2UdpOptions {
        password: route.password.clone(),
        sni: route.tls.sni.clone(),
        skip_cert_verify: route.tls.skip_cert_verify,
        certificate: route.certificate.clone(),
        private_key: route.private_key.clone(),
        obfs: route.obfs.clone(),
        obfs_password: route.obfs_password.clone(),
        udp_mtu: 1200,
        realm: Hy2RealmOptions::default(),
    };
    let proxy = TransportTarget::new(route.server.as_str(), route.port);
    if let Some((control_stream, auth)) = resolve_outer_socks5_udp_stream(
        plan,
        plan.hops.len().saturating_sub(1),
        "hysteria2 udp dialer-proxy requires socks5 udp support on the outer proxy",
        "hysteria2 udp dialer-proxy currently supports only an outer socks5 proxy",
        dns_runtime_clone,
    )? {
        return open_hy2_udp_stream_with_socks5_stream(
            &mut dialer,
            &proxy,
            &options,
            control_stream,
            auth,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    open_hy2_udp_stream_with_dialer(&mut dialer, &proxy, &options)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

pub(in super::super) fn connect_sudoku_udp_stream(
    route: &UdpSudokuRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream_with_timeouts(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
        UDP_PROXY_STREAM_HANDSHAKE_READ_TIMEOUT,
        UDP_PROXY_STREAM_WRITE_TIMEOUT,
    )?;
    let timeout_reset = clone_raw_tcp_stream(&stream);
    let stream = open_sudoku_udp_stream(
        stream,
        &TransportTarget::new(route.server.as_str(), route.port),
        &route.key,
        &route.aead_method,
        &route.table_type,
        route.padding_min,
        route.padding_max,
        route.enable_pure_downlink,
        route.http_mask_enabled,
        &route.http_mask_mode,
        route.http_mask_tls,
        &route.http_mask_host,
        &route.path_root,
        &route.custom_table,
        &route.custom_tables,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    if let Some(socket) = timeout_reset {
        let _ = socket.set_read_timeout(Some(UDP_PROXY_STREAM_READ_TIMEOUT));
        let _ = socket.set_write_timeout(Some(UDP_PROXY_STREAM_WRITE_TIMEOUT));
    }
    Ok(stream)
}
