use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, Metadata, PacketEnvelope, SessionKind, UdpPacket, WriteBack};
use mihomo_inbound::BaseInboundConfig;
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};

use crate::listener_service::SystemUdpSession;

pub(super) fn forward_stream_udp_over_tcp<ReadPacket, WritePacket>(
    stream: BoxedTcpStream,
    tunnel: Arc<RuntimeTunnel>,
    base: &BaseInboundConfig,
    session_kind: SessionKind,
    peer_addr: Option<SocketAddr>,
    read_packet: ReadPacket,
    write_packet: WritePacket,
    poisoned_message: &'static str,
    inbound_user: String,
) -> Result<(), ListenerRuntimeError>
where
    ReadPacket: Fn(&mut dyn io::Read) -> io::Result<(SocketAddr, Vec<u8>)>,
    WritePacket: Fn(&mut dyn io::Write, SocketAddr, &[u8]) -> io::Result<usize>
        + Send
        + Sync
        + 'static,
{
    let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let stream = Arc::new(Mutex::new(stream));
    let writer: Arc<UdpWritePacket> = Arc::new(write_packet);
    loop {
        let (source, payload) = {
            let mut guard = stream
                .lock()
                .map_err(|_| ListenerRuntimeError::Io(io::Error::other(poisoned_message)))?;
            match read_packet(&mut **guard) {
                Ok(packet) => packet,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Ok(());
                }
                Err(err) => return Err(ListenerRuntimeError::Io(err)),
            }
        };

        let packet = Arc::new(StreamBackedUdpPacket {
            payload: ByteWindow::freeze(payload),
            local_addr,
            peer_addr,
            outbound_source: source,
            stream: Arc::clone(&stream),
            write_packet: Arc::clone(&writer),
            poisoned_message,
        });
        let mut metadata = Metadata {
            network: mihomo_core::NetworkKind::Udp,
            kind: session_kind,
            inbound_name: base.name.clone(),
            inbound_user: inbound_user.clone(),
            special_proxy: base.special_proxy.clone(),
            special_rules: base.special_rules.clone(),
            src_ip: Some(peer_addr.ip()),
            src_port: Some(peer_addr.port()),
            ..Metadata::default()
        };
        metadata
            .set_remote_address(&source.to_string())
            .map_err(ListenerRuntimeError::from)?;
        let envelope = PacketEnvelope::new(packet, metadata);
        let mut udp_session =
            SystemUdpSession::new(tunnel.clone(), None).map_err(ListenerRuntimeError::Io)?;
        let _ = tunnel
            .send_udp_packet(&envelope, &mut udp_session)
            .map_err(ListenerRuntimeError::Io)?;
        if let Some((response, responder)) =
            udp_session.recv_once().map_err(ListenerRuntimeError::Io)?
        {
            tunnel
                .write_back_udp(&envelope, ByteWindow::freeze(response), responder)
                .map_err(ListenerRuntimeError::Io)?;
        }
    }
}

type UdpWritePacket = dyn Fn(&mut dyn io::Write, SocketAddr, &[u8]) -> io::Result<usize> + Send + Sync;

struct StreamBackedUdpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    outbound_source: SocketAddr,
    stream: Arc<Mutex<BoxedTcpStream>>,
    write_packet: Arc<UdpWritePacket>,
    poisoned_message: &'static str,
}

impl WriteBack for StreamBackedUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let source = source.unwrap_or(self.outbound_source);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other(self.poisoned_message))?;
        (self.write_packet)(&mut **stream, source, payload.as_slice())
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
