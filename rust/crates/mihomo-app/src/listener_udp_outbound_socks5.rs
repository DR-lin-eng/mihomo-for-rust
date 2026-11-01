use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use mihomo_core::BoxedTcpStream;
use mihomo_dns::DnsRuntime;
use mihomo_runtime::UdpSocks5Route;
use mihomo_transport::{wrap_tls_proxy_stream, TransportTarget};

use super::listener_udp_outbound_support::{
    connect_tcp_addrs_with_timeouts, resolve_proxy_host_to_ipaddr,
    resolve_udp_proxy_server_addrs,
};

pub(in super::super) fn socks5_udp_associate(
    udp_socket: &UdpSocket,
    route: &UdpSocks5Route,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<(BoxedTcpStream, SocketAddr)> {
    let mut dns_runtime = dns_runtime;
    let proxy_addrs = resolve_udp_proxy_server_addrs(
        route.server.as_str(),
        route.port,
        dns_runtime.as_deref_mut(),
    )?;
    let stream = connect_tcp_addrs_with_timeouts(
        &proxy_addrs,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )?;
    let mut stream: BoxedTcpStream = if route.tls.enabled {
        wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new(route.server.clone(), route.port),
            &route.tls,
            &[],
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        Box::new(stream)
    };
    let wants_auth = !route.username.is_empty();
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;

    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply)?;
    if method_reply[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected socks5 auth reply version",
        ));
    }
    if wants_auth {
        if method_reply[1] != 0x02 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5 proxy refused username/password auth",
            ));
        }
        let username = route.username.as_bytes();
        let password = route.password.as_bytes();
        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.push(0x01);
        auth.push(username.len() as u8);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream.write_all(&auth)?;
        stream.flush()?;
        let mut auth_reply = [0_u8; 2];
        stream.read_exact(&mut auth_reply)?;
        if auth_reply != [0x01, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5 username/password auth failed",
            ));
        }
    } else if method_reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 proxy refused no-auth method",
        ));
    }

    let local_addr = udp_socket.local_addr()?;
    let mut request = vec![0x05, 0x03, 0x00];
    match local_addr {
        SocketAddr::V4(addr) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            request.push(0x04);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream.write_all(&request)?;
    stream.flush()?;
    let relay_addr = read_socks5_udp_associate_target(&mut *stream, dns_runtime.as_deref_mut())?;
    Ok((stream, relay_addr))
}

pub(super) fn read_socks5_udp_associate_target(
    stream: &mut dyn Read,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<SocketAddr> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 || header[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks5 udp associate failed",
        ));
    }
    match header[3] {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream.read_exact(&mut addr)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    addr[0], addr[1], addr[2], addr[3],
                )),
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream.read_exact(&mut addr)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                u16::from_be_bytes(port),
            ))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut host = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut host)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            let host = String::from_utf8_lossy(&host).into_owned();
            let port = u16::from_be_bytes(port);
            let ip = resolve_proxy_host_to_ipaddr(host.as_str(), dns_runtime.as_deref_mut())?;
            Ok(SocketAddr::new(ip, port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported socks5 udp relay address type",
        )),
    }
}
