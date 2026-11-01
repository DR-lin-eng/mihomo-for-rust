use std::io;

use mihomo_core::Metadata;
use mihomo_runtime::{ExecutionPlan, UdpOutboundRoute};

use super::listener_udp_session::{PreparedUdpRoute, SystemUdpSession};

#[path = "listener_udp_prepare_proxy.rs"]
mod listener_udp_prepare_proxy;
#[path = "listener_udp_prepare_tunnels.rs"]
mod listener_udp_prepare_tunnels;

pub(super) fn prepare_udp_send(
    session: &mut SystemUdpSession,
    metadata: &mut Metadata,
) -> io::Result<()> {
    let (route, plan) = session
        .tunnel
        .resolve_udp_outbound_with_plan(metadata)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    match route {
        UdpOutboundRoute::Direct => {
            if session.prepared_matches(&plan, &PreparedUdpRoute::Direct) {
                return Ok(());
            }
            set_prepared_route(session, plan, PreparedUdpRoute::Direct, None, None)
        }
        UdpOutboundRoute::Dns => {
            if session.prepared_matches(&plan, &PreparedUdpRoute::Dns) {
                return Ok(());
            }
            set_prepared_route(session, plan, PreparedUdpRoute::Dns, None, None)
        }
        UdpOutboundRoute::Socks5(route) => {
            listener_udp_prepare_proxy::prepare_socks5_route(session, plan, route)
        }
        UdpOutboundRoute::ShadowSocks(route) => {
            listener_udp_prepare_proxy::prepare_shadowsocks_route(session, plan, route)
        }
        UdpOutboundRoute::Ssr(route) => {
            listener_udp_prepare_proxy::prepare_ssr_route(session, plan, route)
        }
        UdpOutboundRoute::AnyTls(route) => {
            listener_udp_prepare_proxy::prepare_anytls_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::Hysteria(route) => prepare_stream_route(
            session,
            plan.clone(),
            PreparedUdpRoute::Hysteria,
            |session| {
                super::listener_udp_outbound::connect_hysteria_udp_stream(
                    &route,
                    &plan,
                    session.tunnel.as_ref(),
                    session.dns_runtime.as_mut(),
                )
            },
        ),
        UdpOutboundRoute::Hy2(route) => {
            prepare_stream_route(session, plan.clone(), PreparedUdpRoute::Hy2, |session| {
                super::listener_udp_outbound::connect_hy2_udp_stream(
                    &route,
                    &plan,
                    session.tunnel.as_ref(),
                    session.dns_runtime.as_mut(),
                )
            })
        }
        UdpOutboundRoute::Snell(route) => {
            prepare_stream_route(session, plan, PreparedUdpRoute::Snell, |session| {
                super::listener_udp_outbound::connect_snell_udp_stream(
                    &route,
                    session.tunnel.as_ref(),
                    session.dns_runtime.as_mut(),
                )
            })
        }
        UdpOutboundRoute::Trojan(route) => {
            listener_udp_prepare_proxy::prepare_trojan_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::TrustTunnel(route) => prepare_stream_route(
            session,
            plan.clone(),
            PreparedUdpRoute::TrustTunnel,
            |session| {
                super::listener_udp_outbound::connect_trusttunnel_udp_stream(
                    &route,
                    &plan,
                    session.tunnel.as_ref(),
                    session.dns_runtime.as_mut(),
                )
            },
        ),
        UdpOutboundRoute::Tuic(route) => {
            prepare_stream_route(session, plan.clone(), PreparedUdpRoute::Tuic, |session| {
                super::listener_udp_outbound::connect_tuic_udp_stream(
                    &route,
                    &plan,
                    session.tunnel.as_ref(),
                    session.dns_runtime.as_mut(),
                )
            })
        }
        UdpOutboundRoute::WireGuard(route) => {
            listener_udp_prepare_tunnels::prepare_wireguard_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::OpenVpn(route) => {
            listener_udp_prepare_tunnels::prepare_openvpn_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::Masque(route) => {
            listener_udp_prepare_tunnels::prepare_masque_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::Sudoku(route) => {
            prepare_stream_route(session, plan, PreparedUdpRoute::Sudoku, |session| {
                super::listener_udp_outbound::connect_sudoku_udp_stream(
                    &route,
                    session.tunnel.as_ref(),
                    session.dns_runtime.as_mut(),
                )
            })
        }
        UdpOutboundRoute::Vless(route) => {
            listener_udp_prepare_proxy::prepare_vless_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::Vmess(route) => {
            listener_udp_prepare_proxy::prepare_vmess_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::GostRelay(route) => {
            listener_udp_prepare_proxy::prepare_gost_relay_route(session, metadata, plan, route)
        }
        UdpOutboundRoute::Unsupported(message) => {
            Err(io::Error::new(io::ErrorKind::Unsupported, message))
        }
    }
}

fn prepare_stream_route<F>(
    session: &mut SystemUdpSession,
    plan: ExecutionPlan,
    prepared: PreparedUdpRoute,
    connect: F,
) -> io::Result<()>
where
    F: FnOnce(&mut SystemUdpSession) -> io::Result<mihomo_core::BoxedTcpStream>,
{
    let stream = connect(session)?;
    set_prepared_route(session, plan, prepared, None, Some(stream))
}

fn prepare_proxy_socket_route<F>(
    session: &mut SystemUdpSession,
    plan: ExecutionPlan,
    build: F,
) -> io::Result<()>
where
    F: FnOnce(&mut SystemUdpSession) -> io::Result<Option<PreparedUdpRoute>>,
{
    let Some(prepared) = build(session)? else {
        return Ok(());
    };
    set_prepared_route(session, plan, prepared, None, None)
}

fn destination_socket_addr(metadata: &Metadata) -> io::Result<std::net::SocketAddr> {
    metadata
        .destination_socket_addr()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved"))
}

fn set_prepared_route(
    session: &mut SystemUdpSession,
    plan: ExecutionPlan,
    route: PreparedUdpRoute,
    control: Option<mihomo_core::BoxedTcpStream>,
    stream: Option<mihomo_core::BoxedTcpStream>,
) -> io::Result<()> {
    session.prepared_plan = Some(plan);
    session.prepared_route = Some(route);
    session.proxy_control = control;
    session.proxy_stream = stream;
    session.pending_response = None;
    Ok(())
}
