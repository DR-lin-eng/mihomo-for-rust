use std::io;
use std::net::IpAddr;

use mihomo_core::Metadata;
use mihomo_runtime::ExecutionPlan;
use mihomo_transport::{
    resolve_masque_host_via_udp_stream, resolve_openvpn_host_via_udp_stream,
    resolve_wireguard_host_via_udp_stream, MasqueConnectOptions,
    OpenVpnOptions, WireGuardOptions,
};

use super::super::listener_udp_session::{PreparedUdpRoute, SystemUdpSession};

pub(super) fn prepare_wireguard_route(
    session: &mut SystemUdpSession,
    metadata: &mut Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpWireGuardRoute,
) -> io::Result<()> {
    let mut stream = super::super::listener_udp_outbound::connect_wireguard_udp_stream(
        &route,
        session.tunnel.as_ref(),
        session.dns_runtime.as_mut(),
    )?;
    if route.remote_dns_resolve && !route.dns.is_empty() && metadata.dst_ip.is_none() {
        if let Some(host) = metadata.host.as_deref() {
            let resolved = resolve_wireguard_host_via_udp_stream(
                &mut *stream,
                &WireGuardOptions {
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
                },
                host,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            metadata.dst_ip = Some(IpAddr::V4(resolved));
        }
    }
    super::set_prepared_route(session, plan, PreparedUdpRoute::WireGuard, None, Some(stream))
}

pub(super) fn prepare_openvpn_route(
    session: &mut SystemUdpSession,
    metadata: &mut Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpOpenVpnRoute,
) -> io::Result<()> {
    let mut stream = super::super::listener_udp_outbound::connect_openvpn_udp_stream(
        &route,
        &plan,
        session.tunnel.as_ref(),
        session.dns_runtime.as_mut(),
    )?;
    if route.remote_dns_resolve && !route.dns.is_empty() && metadata.dst_ip.is_none() {
        if let Some(host) = metadata.host.as_deref() {
            let resolved = resolve_openvpn_host_via_udp_stream(
                &mut *stream,
                &OpenVpnOptions {
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
                },
                host,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            metadata.dst_ip = Some(IpAddr::V4(resolved));
        }
    }
    super::set_prepared_route(session, plan, PreparedUdpRoute::OpenVpn, None, Some(stream))
}

pub(super) fn prepare_masque_route(
    session: &mut SystemUdpSession,
    metadata: &mut Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpMasqueRoute,
) -> io::Result<()> {
    let mut stream = super::super::listener_udp_outbound::connect_masque_udp_stream(
        &route,
        session.tunnel.as_ref(),
        session.dns_runtime.as_mut(),
    )?;
    if route.remote_dns_resolve && !route.dns.is_empty() && metadata.dst_ip.is_none() {
        if let Some(host) = metadata.host.as_deref() {
            let resolved = resolve_masque_host_via_udp_stream(
                &mut *stream,
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
                host,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            metadata.dst_ip = Some(IpAddr::V4(resolved));
        }
    } else {
        let _ = metadata.destination_socket_addr().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved")
        })?;
    }
    super::set_prepared_route(session, plan, PreparedUdpRoute::Masque, None, Some(stream))
}
