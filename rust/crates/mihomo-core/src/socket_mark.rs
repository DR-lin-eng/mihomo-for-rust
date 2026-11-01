//! Core-originated sockets must bypass transparent capture before their first packet.
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
static OUTBOUND_MARK: AtomicU32 = AtomicU32::new(0);
pub fn set_outbound_mark(mark: u32) {
    OUTBOUND_MARK.store(mark, Ordering::Release);
}
pub fn outbound_mark() -> u32 {
    OUTBOUND_MARK.load(Ordering::Acquire)
}
pub fn bind_outbound_udp<A: ToSocketAddrs>(address: A) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(address)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if outbound_mark() != 0 {
        socket2::SockRef::from(&socket).set_mark(outbound_mark())?;
    }
    Ok(socket)
}
pub fn connect_outbound_tcp<A: ToSocketAddrs>(address: A) -> io::Result<TcpStream> {
    let mut last = None;
    for address in address.to_socket_addrs()? {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if outbound_mark() != 0 {
            socket.set_mark(outbound_mark())?;
        }
        match socket.connect_timeout(&address.into(), std::time::Duration::from_secs(5)) {
            Ok(()) => return Ok(socket.into()),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "outbound TCP destination has no addresses",
        )
    }))
}

pub fn mark_tcp_listener(socket: &std::net::TcpListener, mark: u32) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if mark != 0 {
        socket2::SockRef::from(socket).set_mark(mark)?;
    }
    let _ = (socket, mark);
    Ok(())
}
pub fn mark_udp_socket(socket: &UdpSocket, mark: u32) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if mark != 0 {
        socket2::SockRef::from(socket).set_mark(mark)?;
    }
    let _ = (socket, mark);
    Ok(())
}
