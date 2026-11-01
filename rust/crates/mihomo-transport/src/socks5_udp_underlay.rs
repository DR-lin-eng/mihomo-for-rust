use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use mihomo_core::BoxedTcpStream;
use quinn::{AsyncUdpSocket, UdpPoller};
use quinn_udp::{RecvMeta, Transmit};

use crate::{BasicAuth, TransportError, TransportTarget};

pub(crate) fn connect_socks5_udp_associate(
    proxy: &TransportTarget,
    auth: Option<&BasicAuth>,
    bind_addr: SocketAddr,
) -> Result<(std::net::TcpStream, SocketAddr), TransportError> {
    let udp_socket = mihomo_core::bind_outbound_udp(bind_addr).map_err(TransportError::from)?;
    connect_socks5_udp_associate_with_socket(proxy, auth, udp_socket)
}

pub(crate) fn connect_socks5_udp_associate_with_socket(
    proxy: &TransportTarget,
    auth: Option<&BasicAuth>,
    udp_socket: UdpSocket,
) -> Result<(std::net::TcpStream, SocketAddr), TransportError> {
    let mut tcp = std::net::TcpStream::connect((proxy.host.as_str(), proxy.port))
        .map_err(TransportError::from)?;
    let wants_auth = auth.is_some();
    if wants_auth {
        tcp.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        tcp.write_all(&[0x05, 0x01, 0x00])?;
    }
    tcp.flush()?;

    let mut method_reply = [0_u8; 2];
    tcp.read_exact(&mut method_reply)?;
    if method_reply[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(
            "unexpected socks5 auth reply version",
        ));
    }
    if let Some(auth) = auth {
        if method_reply[1] != 0x02 {
            return Err(TransportError::invalid_proxy_response(
                "socks5 proxy refused username/password auth",
            ));
        }
        let username = auth.username.as_bytes();
        let password = auth.password.as_bytes();
        let mut auth_frame = Vec::with_capacity(3 + username.len() + password.len());
        auth_frame.push(0x01);
        auth_frame.push(username.len() as u8);
        auth_frame.extend_from_slice(username);
        auth_frame.push(password.len() as u8);
        auth_frame.extend_from_slice(password);
        tcp.write_all(&auth_frame)?;
        tcp.flush()?;
        let mut auth_reply = [0_u8; 2];
        tcp.read_exact(&mut auth_reply)?;
        if auth_reply != [0x01, 0x00] {
            return Err(TransportError::invalid_proxy_response(
                "socks5 username/password auth failed",
            ));
        }
    } else if method_reply[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(
            "socks5 proxy refused no-auth method",
        ));
    }

    let local_addr = udp_socket.local_addr().map_err(TransportError::from)?;
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
    tcp.write_all(&request)?;
    tcp.flush()?;
    let relay_addr = read_socks5_udp_associate_target(&mut tcp)?;
    Ok((tcp, relay_addr))
}

pub(crate) fn connect_socks5_udp_associate_over_stream(
    stream: &mut dyn mihomo_core::TcpStream,
    bind_addr: SocketAddr,
    auth: Option<&BasicAuth>,
) -> Result<(UdpSocket, SocketAddr), TransportError> {
    let udp_socket = mihomo_core::bind_outbound_udp(bind_addr).map_err(TransportError::from)?;
    let local_addr = udp_socket.local_addr().map_err(TransportError::from)?;

    let wants_auth = auth.is_some();
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;

    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply)?;
    if method_reply[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(
            "unexpected socks5 auth reply version",
        ));
    }
    if let Some(auth) = auth {
        if method_reply[1] != 0x02 {
            return Err(TransportError::invalid_proxy_response(
                "socks5 proxy refused username/password auth",
            ));
        }
        let username = auth.username.as_bytes();
        let password = auth.password.as_bytes();
        let mut auth_frame = Vec::with_capacity(3 + username.len() + password.len());
        auth_frame.push(0x01);
        auth_frame.push(username.len() as u8);
        auth_frame.extend_from_slice(username);
        auth_frame.push(password.len() as u8);
        auth_frame.extend_from_slice(password);
        stream.write_all(&auth_frame)?;
        stream.flush()?;
        let mut auth_reply = [0_u8; 2];
        stream.read_exact(&mut auth_reply)?;
        if auth_reply != [0x01, 0x00] {
            return Err(TransportError::invalid_proxy_response(
                "socks5 username/password auth failed",
            ));
        }
    } else if method_reply[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(
            "socks5 proxy refused no-auth method",
        ));
    }

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
    let relay_addr = read_socks5_udp_associate_target(stream)?;
    Ok((udp_socket, relay_addr))
}

fn read_socks5_udp_associate_target(stream: &mut dyn Read) -> Result<SocketAddr, TransportError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(
            "unexpected socks5 udp associate version",
        ));
    }
    if header[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(format!(
            "socks5 udp associate failed with status {}",
            header[1]
        )));
    }
    match header[3] {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream.read_exact(&mut addr)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(addr)),
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream.read_exact(&mut addr)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                u16::from_be_bytes(port),
            ))
        }
        other => Err(TransportError::invalid_proxy_response(format!(
            "unsupported socks5 udp associate address type {other}"
        ))),
    }
}

pub(crate) fn build_socks5_udp_frame(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x00, 0x00, 0x00];
    match target {
        SocketAddr::V4(addr) => {
            frame.push(0x01);
            frame.extend_from_slice(&addr.ip().octets());
            frame.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            frame.push(0x04);
            frame.extend_from_slice(&addr.ip().octets());
            frame.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

pub(crate) fn parse_socks5_udp_frame(
    payload: &[u8],
) -> io::Result<(SocketAddr, Vec<u8>)> {
    if payload.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp frame too short",
        ));
    }
    if payload[0] != 0 || payload[1] != 0 || payload[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socks5 udp frame header",
        ));
    }
    let atyp = payload[3];
    let mut offset = 4;
    let addr = match atyp {
        0x01 => {
            let mut octets = [0_u8; 4];
            octets.copy_from_slice(&payload[offset..offset + 4]);
            offset += 4;
            IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported socks5 udp address type {other}"),
            ))
        }
    };
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok((SocketAddr::new(addr, port), payload[offset..].to_vec()))
}

pub(crate) struct Socks5UdpAssociateSocket {
    io: tokio::net::UdpSocket,
    relay_addr: SocketAddr,
    local_addr: SocketAddr,
    _control: Arc<Mutex<BoxedTcpStream>>,
}

impl std::fmt::Debug for Socks5UdpAssociateSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UdpAssociateSocket")
            .field("relay_addr", &self.relay_addr)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Socks5UdpAssociateSocket {
    pub(crate) fn new(
        udp_socket: UdpSocket,
        relay_addr: SocketAddr,
        control: BoxedTcpStream,
    ) -> io::Result<Self> {
        udp_socket.set_nonblocking(true)?;
        let local_addr = udp_socket.local_addr()?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(udp_socket)?,
            relay_addr,
            local_addr,
            _control: Arc::new(Mutex::new(control)),
        })
    }
}

impl AsyncUdpSocket for Socks5UdpAssociateSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5UdpAssociatePoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let frame = build_socks5_udp_frame(transmit.destination, transmit.contents);
        self.io.try_send_to(&frame, self.relay_addr).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.io.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
            let buf = match bufs.first_mut() {
                Some(buf) => buf,
                None => return Poll::Ready(Ok(0)),
            };
            let mut recv_buf = vec![0_u8; buf.len()];
            match self.io.try_recv_from(&mut recv_buf) {
                Ok((len, _)) => {
                    let (source, payload) = match parse_socks5_udp_frame(&recv_buf[..len]) {
                        Ok(value) => value,
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    let payload_len = payload.len().min(buf.len());
                    let dst = &mut buf[..payload_len];
                    dst.copy_from_slice(&payload[..payload_len]);
                    meta[0] = RecvMeta {
                        addr: source,
                        len: payload_len,
                        stride: payload_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

struct Socks5UdpAssociatePoller {
    socket: Arc<Socks5UdpAssociateSocket>,
}

impl std::fmt::Debug for Socks5UdpAssociatePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UdpAssociatePoller")
            .field("socket", &self.socket)
            .finish()
    }
}

impl UdpPoller for Socks5UdpAssociatePoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_socks5_udp_frame, parse_socks5_udp_frame};

    #[test]
    fn socks5_udp_frame_roundtrips_ipv4_payload() {
        let target: std::net::SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let frame = build_socks5_udp_frame(target, b"ping");
        let (decoded, payload) = parse_socks5_udp_frame(&frame).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(payload, b"ping".to_vec());
    }
}
