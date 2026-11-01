use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::Duration;

use mihomo_dns::DnsRuntime;
use mihomo_inbound::{RedirInboundConfig, TProxyInboundConfig};
use mihomo_runtime::{
    dispatch_redir_tcp_stream_with_dialer, dispatch_tproxy_tcp_stream_with_dialer,
    ListenerRuntimeError, RuntimeTunnel,
};

use crate::listener_service::DnsAwareTcpDialer;

const IPV6_TRANSPARENT: libc::c_int = 75;
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

pub(crate) fn handle_redir_connection(
    config: RedirInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    let local=stream.local_addr().map_err(ListenerRuntimeError::Io)?;
    let peer=peer_addr.or_else(||stream.peer_addr().ok());
    let ebpf_destination=match peer {Some(peer)=>tunnel.ebpf_original_destination(peer,local).map_err(ListenerRuntimeError::Io)?,None=>None};
    let original_dst = match ebpf_destination {Some(destination)=>destination,None=>redir_original_dst(&stream).map_err(ListenerRuntimeError::Io)?};
    let _ = dispatch_redir_tcp_stream_with_dialer(
        &config,
        &tunnel,
        stream,
        peer_addr,
        original_dst,
        DnsAwareTcpDialer::new(dns_runtime),
    )?;
    Ok(())
}

pub(crate) fn handle_tproxy_connection(
    config: TProxyInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    let original_dst = stream.local_addr().map_err(ListenerRuntimeError::Io)?;
    let _ = dispatch_tproxy_tcp_stream_with_dialer(
        &config,
        &tunnel,
        stream,
        peer_addr,
        original_dst,
        DnsAwareTcpDialer::new(dns_runtime),
    )?;
    Ok(())
}

pub(crate) fn create_or_get_local_conn(
    original_target_addr: &SocketAddr,
    original_client_addr: &SocketAddr,
    _tunnel: &RuntimeTunnel,
) -> io::Result<Arc<UdpSocket>> {
    // A connected IP_TRANSPARENT socket is eligible for future incoming
    // datagrams of this flow. There is no receive pump on reply-only sockets,
    // so keeping it in a global cache steals traffic from the TProxy listener.
    // Own it only for this synchronous reply and close immediately afterwards.
    let socket = Arc::new(dial_transparent_udp(*original_target_addr, *original_client_addr)?);
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

pub(crate) fn configure_tproxy_udp_listener_socket(listener: &UdpSocket) -> io::Result<()> {
    configure_transparent_listener_fd(listener.as_raw_fd(), listener.local_addr()?.is_ipv6())
}

pub(crate) fn configure_tproxy_tcp_listener_socket(
    listener: &std::net::TcpListener,
) -> io::Result<()> {
    configure_transparent_listener_fd(listener.as_raw_fd(), listener.local_addr()?.is_ipv6())
}

fn configure_transparent_listener_fd(fd: libc::c_int, is_ipv6: bool) -> io::Result<()> {
    let one: libc::c_int = 1;
    set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, one)?;
    set_sockopt_int(fd, libc::SOL_IP, libc::IP_TRANSPARENT, one)?;
    if is_ipv6 {
        set_sockopt_int(fd, libc::SOL_IPV6, IPV6_TRANSPARENT, one)?;
    }
    set_sockopt_int(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, one)?;
    if is_ipv6 {
        let _ = set_sockopt_int(fd, libc::SOL_IPV6, IPV6_RECVORIGDSTADDR, one);
        let _ = set_sockopt_int(fd, libc::SOL_IPV6, libc::IPV6_RECVTCLASS, one);
    }
    let _ = set_sockopt_int(fd, libc::SOL_IP, libc::IP_RECVTOS, one);
    Ok(())
}

fn set_sockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn recv_transparent_udp_packet(
    listener: &UdpSocket,
) -> io::Result<Option<(Vec<u8>, SocketAddr, SocketAddr)>> {
    let fd = listener.as_raw_fd();
    let mut payload = vec![0_u8; 64 * 1024];
    let mut control = vec![0_u8; 512];
    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = storage.as_mut_ptr() as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    let read = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if read < 0 {
        let err = io::Error::last_os_error();
        if matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
        ) {
            return Ok(None);
        }
        return Err(err);
    }
    let peer_addr = sockaddr_storage_to_socket_addr(
        unsafe { &storage.assume_init() },
        msg.msg_namelen,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid peer sockaddr"))?;
    let target_addr = parse_original_dst_from_cmsg(&msg)
        .or_else(|_| listener.local_addr())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    payload.truncate(read as usize);
    Ok(Some((payload, peer_addr, target_addr)))
}

pub(super) fn parse_original_dst_from_cmsg(msghdr: &libc::msghdr) -> io::Result<SocketAddr> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;
    let mut current = unsafe { libc::CMSG_FIRSTHDR(msghdr as *const _ as *mut _) };
    while !current.is_null() {
        let header = unsafe { &*current };
        if header.cmsg_level == libc::SOL_IP && header.cmsg_type == IP_ORIGDSTADDR {
            let sockaddr = unsafe { &*(libc::CMSG_DATA(current) as *const libc::sockaddr_in) };
            let port = u16::from_be(sockaddr.sin_port);
            let ip = std::net::Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes());
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }
        if header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == IPV6_ORIGDSTADDR {
            let sockaddr = unsafe { &*(libc::CMSG_DATA(current) as *const libc::sockaddr_in6) };
            let port = u16::from_be(sockaddr.sin6_port);
            let ip = std::net::Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
            return Ok(SocketAddr::new(IpAddr::V6(ip), port));
        }
        current = unsafe { libc::CMSG_NXTHDR(msghdr as *const _ as *mut _, current) };
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "udp original destination control message missing",
    ))
}

pub(super) fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sockaddr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let port = u16::from_be(sockaddr.sin_port);
            let ip = std::net::Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let sockaddr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let port = u16::from_be(sockaddr.sin6_port);
            let ip = std::net::Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

fn dial_transparent_udp(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = match (local_addr, remote_addr) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => libc::AF_INET,
        _ => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let setup = || -> io::Result<()> {
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        if matches!(local_addr, SocketAddr::V6(_)) || matches!(remote_addr, SocketAddr::V6(_)) {
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    IPV6_TRANSPARENT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mark=mihomo_core::outbound_mark();
        if mark!=0{set_sockopt_int(fd,libc::SOL_SOCKET,libc::SO_MARK,mark as libc::c_int)?;}
        bind_socket_addr(fd, local_addr)?;
        connect_socket_addr(fd, remote_addr)?;
        Ok(())
    };

    if let Err(err) = setup() {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    Ok(socket)
}

fn bind_socket_addr(fd: libc::c_int, addr: SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V4(addr) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let ret = unsafe {
                libc::bind(
                    fd,
                    &sockaddr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        SocketAddr::V6(addr) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            let ret = unsafe {
                libc::bind(
                    fd,
                    &sockaddr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn connect_socket_addr(fd: libc::c_int, addr: SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V4(addr) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let ret = unsafe {
                libc::connect(
                    fd,
                    &sockaddr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        SocketAddr::V6(addr) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            let ret = unsafe {
                libc::connect(
                    fd,
                    &sockaddr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn redir_original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    let fd = stream.as_raw_fd();
    let local = stream.local_addr()?;
    if matches!(local.ip(), IpAddr::V4(_)) {
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        let port = u16::from_be(addr.sin_port);
        let ip = std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    } else {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IP6T_SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        let port = u16::from_be(addr.sin6_port);
        let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    }
}
