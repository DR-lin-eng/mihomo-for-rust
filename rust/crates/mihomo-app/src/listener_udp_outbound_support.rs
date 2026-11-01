use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use mihomo_core::{BoxedTcpStream, Metadata};
use mihomo_dns::DnsRuntime;
use mihomo_runtime::{ExecutionHopSpec, ExecutionPlan, RuntimeTunnel, UdpTuicRoute};
use mihomo_transport::{
    BasicAuth, SocketOptions, TcpDialPurpose, TcpDialer,
    TcpTransportExecutor, TransportTarget,
};

pub(super) const UDP_PROXY_STREAM_READ_TIMEOUT: Duration = Duration::from_millis(20);
pub(super) const UDP_PROXY_STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
pub(super) const UDP_PROXY_STREAM_HANDSHAKE_READ_TIMEOUT: Duration =
    Duration::from_millis(200);

pub(in super::super) fn resolve_udp_proxy_server_addr(
    server: &str,
    port: u16,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<SocketAddr> {
    Ok(resolve_udp_proxy_server_addrs(server, port, dns_runtime.as_deref_mut())?
        .into_iter()
        .next()
        .expect("non-empty checked by resolve_udp_proxy_server_addrs"))
}

pub(super) fn resolve_udp_proxy_server_addrs(
    server: &str,
    port: u16,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if let Some(runtime) = dns_runtime.as_mut() {
        match runtime.resolve_proxy_server_host_addrs_via_system(server) {
            Ok(ips) if !ips.is_empty() => {
                return Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect());
            }
            Ok(_) => {}
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
            }
        }
    }

    let addrs = (server, port).to_socket_addrs()?.collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to resolve proxy server: {server}"),
        ));
    }
    Ok(addrs)
}

pub(super) fn connect_tcp_addrs_with_timeouts(
    addrs: &[SocketAddr],
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                stream.set_read_timeout(Some(read_timeout))?;
                stream.set_write_timeout(Some(write_timeout))?;
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "failed to connect to any resolved proxy server address",
        )
    }))
}

pub(super) fn connect_udp_dialer_proxy_stream(
    tunnel: &RuntimeTunnel,
    dialer_proxy: Option<&str>,
    server: &str,
    port: u16,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    connect_udp_dialer_proxy_stream_with_timeouts(
        tunnel,
        dialer_proxy,
        server,
        port,
        dns_runtime,
        UDP_PROXY_STREAM_READ_TIMEOUT,
        UDP_PROXY_STREAM_WRITE_TIMEOUT,
    )
}

pub(super) fn connect_udp_dialer_proxy_stream_with_timeouts(
    tunnel: &RuntimeTunnel,
    dialer_proxy: Option<&str>,
    server: &str,
    port: u16,
    dns_runtime: Option<&mut DnsRuntime>,
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<BoxedTcpStream> {
    if let Some(dialer_proxy) = dialer_proxy.filter(|value| !value.is_empty()) {
        let metadata = Metadata {
            special_proxy: dialer_proxy.to_owned(),
            host: Some(server.to_owned()),
            dst_port: Some(port),
            ..Metadata::default()
        };
        return tunnel
            .connect_tcp_with_system_dialer(&metadata)
            .map(|(stream, _)| stream)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }

    let proxy_addrs = resolve_udp_proxy_server_addrs(server, port, dns_runtime)?;
    let stream = connect_tcp_addrs_with_timeouts(&proxy_addrs, read_timeout, write_timeout)?;
    Ok(Box::new(stream))
}

pub(super) fn clone_raw_tcp_stream(stream: &BoxedTcpStream) -> Option<std::net::TcpStream> {
    let any = stream.as_ref() as &dyn std::any::Any;
    if let Some(raw) = any.downcast_ref::<std::net::TcpStream>() {
        return raw.try_clone().ok();
    }
    if let Some(boxed) = any.downcast_ref::<BoxedTcpStream>() {
        return clone_raw_tcp_stream(boxed);
    }
    None
}

pub(super) fn set_raw_tcp_stream_timeouts(
    stream: &BoxedTcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<bool> {
    let any = stream.as_ref() as &dyn std::any::Any;
    if let Some(raw) = any.downcast_ref::<std::net::TcpStream>() {
        raw.set_read_timeout(Some(read_timeout))?;
        raw.set_write_timeout(Some(write_timeout))?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn resolve_tuic_outer_socks5_stream(
    route: &UdpTuicRoute,
    plan: &ExecutionPlan,
    dns_runtime: Option<DnsRuntime>,
) -> io::Result<Option<(BoxedTcpStream, Option<BasicAuth>)>> {
    if !route
        .dialer_proxy
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(None);
    }
    let Some((leaf_index, _leaf_hop)) = plan.hops.iter().enumerate().next_back() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp execution plan is empty",
        ));
    };
    if leaf_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tuic udp dialer-proxy requires an outer proxy hop",
        ));
    }
    resolve_outer_socks5_udp_stream(
        plan,
        leaf_index,
        "tuic udp dialer-proxy requires socks5 udp support on the outer proxy",
        "tuic udp dialer-proxy currently supports only an outer socks5 proxy",
        dns_runtime,
    )
}

pub(super) fn resolve_outer_socks5_udp_stream(
    plan: &ExecutionPlan,
    leaf_index: usize,
    udp_required_message: &str,
    only_socks5_message: &str,
    dns_runtime: Option<DnsRuntime>,
) -> io::Result<Option<(BoxedTcpStream, Option<BasicAuth>)>> {
    if leaf_index == 0 {
        return Ok(None);
    }
    let outer_hop = &plan.hops[leaf_index - 1];
    let outer_server = match &outer_hop.spec {
        ExecutionHopSpec::Socks5Connect(spec) if spec.udp => {
            (spec.server.clone(), spec.port, spec.auth.clone())
        }
        ExecutionHopSpec::Socks5Connect(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                udp_required_message,
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                only_socks5_message,
            ));
        }
    };
    let outer_target = TransportTarget::new(outer_server.0.clone(), outer_server.1);
    let mut dialer = super::super::DnsAwareTcpDialer::new(dns_runtime);
    let control_stream = if leaf_index == 1 {
        dialer
            .connect(
                &outer_target,
                &SocketOptions::default(),
                TcpDialPurpose::ProxyServer,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        let prefix_plan =
            mihomo_runtime::build_transport_plan_for_prefix(plan, leaf_index - 1, &outer_target)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        let mut executor = TcpTransportExecutor::new(dialer);
        mihomo_runtime::run_transport_plan(&mut executor, &prefix_plan)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    };
    let auth = outer_server.2.map(|auth| BasicAuth {
        username: auth.username,
        password: auth.password,
    });
    Ok(Some((control_stream, auth)))
}

pub(super) fn normalize_openvpn_proto(proto: &str) -> &'static str {
    match proto.trim().to_ascii_lowercase().as_str() {
        "" | "udp" | "udp4" => "udp",
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => "tcp",
        _ => "other",
    }
}

pub(in super::super) fn resolve_host_to_ipaddr(
    host: &str,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(runtime) = dns_runtime.as_mut() {
        match runtime.resolve_host_addrs_via_system(host) {
            Ok(ips) if !ips.is_empty() => return Ok(ips[0]),
            Ok(_) => {}
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
            }
        }
    }
    let mut addrs = (host, 0).to_socket_addrs()?;
    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host unresolved"))
}

pub(super) fn resolve_proxy_host_to_ipaddr(
    host: &str,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(runtime) = dns_runtime.as_mut() {
        match runtime.resolve_proxy_server_host_addrs_via_system(host) {
            Ok(ips) if !ips.is_empty() => return Ok(ips[0]),
            Ok(_) => {}
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
            }
        }
    }
    let mut addrs = (host, 0).to_socket_addrs()?;
    addrs.next().map(|addr| addr.ip()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "proxy host unresolved")
    })
}

pub(in super::super) fn format_target(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
