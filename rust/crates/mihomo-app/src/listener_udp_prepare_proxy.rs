use std::io;

use mihomo_core::Metadata;
use mihomo_runtime::ExecutionPlan;

use super::super::listener_udp_session::{PreparedUdpRoute, SystemUdpSession};

pub(super) fn prepare_socks5_route(
    session: &mut SystemUdpSession,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpSocks5Route,
) -> io::Result<()> {
    if matches!(session.prepared_route, Some(PreparedUdpRoute::Socks5 { .. }))
        && session.prepared_plan.as_ref() == Some(&plan)
    {
        return Ok(());
    }
    let (control, relay_addr) = super::super::listener_udp_outbound::socks5_udp_associate(
        &session.socket,
        &route,
        session.dns_runtime.as_mut(),
    )?;
    super::set_prepared_route(
        session,
        plan,
        PreparedUdpRoute::Socks5 { relay_addr },
        Some(control),
        None,
    )
}

pub(super) fn prepare_shadowsocks_route(
    session: &mut SystemUdpSession,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpShadowSocksRoute,
) -> io::Result<()> {
    if let Some(PreparedUdpRoute::ShadowSocks { proxy_addr, cipher, password }) =
        session.prepared_route.as_ref()
    {
        if session.prepared_plan.as_ref() == Some(&plan)
            && *cipher == route.cipher
            && *password == route.password
            && super::super::listener_udp_outbound::resolve_udp_proxy_server_addr(
                route.server.as_str(),
                route.port,
                session.dns_runtime.as_mut(),
            )?
                == *proxy_addr
        {
            return Ok(());
        }
    }
    super::prepare_proxy_socket_route(session, plan, |session| {
        let proxy_addr = super::super::listener_udp_outbound::resolve_udp_proxy_server_addr(
            route.server.as_str(),
            route.port,
            session.dns_runtime.as_mut(),
        )?;
        Ok(Some(PreparedUdpRoute::ShadowSocks {
            proxy_addr,
            cipher: route.cipher,
            password: route.password,
        }))
    })
}

pub(super) fn prepare_ssr_route(
    session: &mut SystemUdpSession,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpSsrRoute,
) -> io::Result<()> {
    if let Some(PreparedUdpRoute::Ssr { proxy_addr, cipher, password }) =
        session.prepared_route.as_ref()
    {
        if session.prepared_plan.as_ref() == Some(&plan)
            && *cipher == route.cipher
            && *password == route.password
            && super::super::listener_udp_outbound::resolve_udp_proxy_server_addr(
                route.server.as_str(),
                route.port,
                session.dns_runtime.as_mut(),
            )?
                == *proxy_addr
        {
            return Ok(());
        }
    }
    super::prepare_proxy_socket_route(session, plan, |session| {
        let proxy_addr = super::super::listener_udp_outbound::resolve_udp_proxy_server_addr(
            route.server.as_str(),
            route.port,
            session.dns_runtime.as_mut(),
        )?;
        Ok(Some(PreparedUdpRoute::Ssr {
            proxy_addr,
            cipher: route.cipher,
            password: route.password,
        }))
    })
}

pub(super) fn prepare_anytls_route(
    session: &mut SystemUdpSession,
    metadata: &Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpAnyTlsRoute,
) -> io::Result<()> {
    let target = super::destination_socket_addr(metadata)?;
    super::prepare_stream_route(session, plan, PreparedUdpRoute::AnyTls, |session| {
        super::super::listener_udp_outbound::connect_anytls_udp_stream(
            &route,
            session.tunnel.as_ref(),
            target,
            session.dns_runtime.as_mut(),
        )
    })
}

pub(super) fn prepare_trojan_route(
    session: &mut SystemUdpSession,
    metadata: &Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpTrojanRoute,
) -> io::Result<()> {
    let target = super::destination_socket_addr(metadata)?;
    super::prepare_stream_route(session, plan, PreparedUdpRoute::Trojan, |session| {
        super::super::listener_udp_outbound::connect_trojan_udp_stream(
            &route,
            session.tunnel.as_ref(),
            target,
            session.dns_runtime.as_mut(),
        )
    })
}

pub(super) fn prepare_vless_route(
    session: &mut SystemUdpSession,
    metadata: &Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpVlessRoute,
) -> io::Result<()> {
    let target = super::destination_socket_addr(metadata)?;
    let stream = super::super::listener_udp_outbound::connect_vless_udp_stream(
        &route,
        session.tunnel.as_ref(),
        target,
        session.dns_runtime.as_mut(),
    )?;
    let prepared = if route.xudp {
        PreparedUdpRoute::VlessXudp
    } else if route.packet_addr {
        PreparedUdpRoute::VlessPacketAddr
    } else {
        PreparedUdpRoute::Vless { source: target }
    };
    super::set_prepared_route(session, plan, prepared, None, Some(stream))
}

pub(super) fn prepare_vmess_route(
    session: &mut SystemUdpSession,
    metadata: &Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpVmessRoute,
) -> io::Result<()> {
    let target = super::destination_socket_addr(metadata)?;
    let stream = super::super::listener_udp_outbound::connect_vmess_udp_stream(
        &route,
        session.tunnel.as_ref(),
        target,
        session.dns_runtime.as_mut(),
    )?;
    let prepared = if route.xudp {
        PreparedUdpRoute::VmessXudp
    } else if route.packet_addr {
        PreparedUdpRoute::VmessPacketAddr
    } else {
        PreparedUdpRoute::Vmess { source: target }
    };
    super::set_prepared_route(session, plan, prepared, None, Some(stream))
}

pub(super) fn prepare_gost_relay_route(
    session: &mut SystemUdpSession,
    metadata: &Metadata,
    plan: ExecutionPlan,
    route: mihomo_runtime::UdpGostRelayRoute,
) -> io::Result<()> {
    let target = super::destination_socket_addr(metadata)?;
    let stream = super::super::listener_udp_outbound::connect_gost_relay_udp_stream(
        &route,
        session.tunnel.as_ref(),
        target,
        session.dns_runtime.as_mut(),
    )?;
    super::set_prepared_route(
        session,
        plan,
        PreparedUdpRoute::GostRelay { source: target },
        None,
        Some(stream),
    )
}
