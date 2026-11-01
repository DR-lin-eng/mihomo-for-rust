use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, UdpPacket, WriteBack};
use mihomo_transport::{
    encode_packetaddr_udp_packet, encode_shadowsocks_udp_packet, write_sudoku_udp_packet,
    write_vless_udp_packet, write_vless_xudp_packet, write_vmess_udp_packet,
    write_vmess_xudp_packet, TransportTarget,
};

use crate::listener_service::build_socks5_udp_packet;

pub(crate) const UDP_WORKER_THREADS_MIN: usize = 2;
pub(crate) const UDP_WORKER_THREADS_MAX: usize = 4;
pub(crate) const QUIC_RUNTIME_WORKER_THREADS_MIN: usize = 2;
pub(crate) const QUIC_RUNTIME_WORKER_THREADS_MAX: usize = 8;

pub(crate) fn normalized_worker_threads(parallelism: usize, min: usize, max: usize) -> usize {
    parallelism.clamp(min, max)
}

fn auto_worker_threads(min: usize, max: usize) -> usize {
    std::thread::available_parallelism()
        .map(|count| normalized_worker_threads(count.get(), min, max))
        .unwrap_or(min)
}

pub(crate) fn udp_worker_threads() -> usize {
    auto_worker_threads(UDP_WORKER_THREADS_MIN, UDP_WORKER_THREADS_MAX)
}

pub(crate) fn quic_runtime_worker_threads() -> usize {
    auto_worker_threads(
        QUIC_RUNTIME_WORKER_THREADS_MIN,
        QUIC_RUNTIME_WORKER_THREADS_MAX,
    )
}

pub(crate) struct SocketBackedUdpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
}

pub(crate) struct StreamBackedUdpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub outbound_source: SocketAddr,
    pub stream: Arc<Mutex<BoxedTcpStream>>,
}

pub(crate) struct VmessStreamBackedUdpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub outbound_source: SocketAddr,
    pub stream: Arc<Mutex<BoxedTcpStream>>,
    pub packet_addr: bool,
}

pub(crate) struct VlessStreamBackedUdpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub outbound_source: SocketAddr,
    pub stream: Arc<Mutex<BoxedTcpStream>>,
    pub packet_addr: bool,
}

pub(crate) struct VmessStreamBackedXudpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub outbound_source: SocketAddr,
    pub stream: Arc<Mutex<BoxedTcpStream>>,
}

pub(crate) struct VlessStreamBackedXudpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub outbound_source: SocketAddr,
    pub stream: Arc<Mutex<BoxedTcpStream>>,
}

pub(crate) struct SocksUdpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
}

pub(crate) struct ShadowSocksUdpPacket {
    pub payload: ByteWindow,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
    pub cipher: String,
    pub password: String,
    pub ss2022_session: Option<std::sync::Arc<mihomo_transport::Shadowsocks2022UdpResponseSession>>,
}

impl WriteBack for SocksUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let Some(source) = source else {
            return self.socket.send_to(payload.as_slice(), self.peer_addr);
        };
        build_socks5_udp_packet(&self.socket, self.peer_addr, source, payload)
    }
}

impl UdpPacket for SocksUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl WriteBack for SocketBackedUdpPacket {
    fn write_back(&self, payload: ByteWindow, _source: Option<SocketAddr>) -> io::Result<usize> {
        self.socket.send_to(payload.as_slice(), self.peer_addr)
    }
}

impl WriteBack for ShadowSocksUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let Some(source) = source else {
            return self.socket.send_to(payload.as_slice(), self.peer_addr);
        };
        if let Some(session) = &self.ss2022_session {
            let packet = session
                .encode_response(
                    &self.cipher,
                    &self.password,
                    &TransportTarget::new(source.ip().to_string(), source.port()),
                    payload.as_slice(),
                )
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            return self.socket.send_to(&packet, self.peer_addr);
        }
        let packet = encode_shadowsocks_udp_packet(
            &self.cipher,
            &self.password,
            source,
            payload.as_slice(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.socket.send_to(&packet, self.peer_addr)
    }
}

impl WriteBack for StreamBackedUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.outbound_source);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("sudoku inbound udp stream mutex poisoned"))?;
        write_sudoku_udp_packet(&mut **stream, source, payload.as_slice())
    }
}

impl UdpPacket for SocketBackedUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl UdpPacket for ShadowSocksUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl UdpPacket for StreamBackedUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
}

impl WriteBack for VmessStreamBackedUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.outbound_source);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("vmess inbound udp stream mutex poisoned"))?;
        if self.packet_addr {
            let framed = encode_packetaddr_udp_packet(source, payload.as_slice());
            write_vmess_udp_packet(&mut **stream, &framed)
        } else {
            write_vmess_udp_packet(&mut **stream, payload.as_slice())
        }
    }
}

impl UdpPacket for VmessStreamBackedUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
}

impl WriteBack for VlessStreamBackedUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.outbound_source);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("vless inbound udp stream mutex poisoned"))?;
        if self.packet_addr {
            let framed = encode_packetaddr_udp_packet(source, payload.as_slice());
            write_vless_udp_packet(&mut **stream, &framed)
        } else {
            write_vless_udp_packet(&mut **stream, payload.as_slice())
        }
    }
}

impl UdpPacket for VlessStreamBackedUdpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::normalized_worker_threads;

    #[test]
    fn normalized_worker_threads_clamps_requested_parallelism() {
        assert_eq!(normalized_worker_threads(1, 2, 8), 2);
        assert_eq!(normalized_worker_threads(4, 2, 8), 4);
        assert_eq!(normalized_worker_threads(32, 2, 8), 8);
    }
}

impl WriteBack for VmessStreamBackedXudpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.outbound_source);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("vmess inbound xudp stream mutex poisoned"))?;
        write_vmess_xudp_packet(&mut **stream, source, payload.as_slice())
    }
}

impl UdpPacket for VmessStreamBackedXudpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
}

impl WriteBack for VlessStreamBackedXudpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.outbound_source);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("vless inbound xudp stream mutex poisoned"))?;
        write_vless_xudp_packet(&mut **stream, source, payload.as_slice())
    }
}

impl UdpPacket for VlessStreamBackedXudpPacket {
    fn payload(&self) -> ByteWindow {
        self.payload.clone()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn inbound_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
}
