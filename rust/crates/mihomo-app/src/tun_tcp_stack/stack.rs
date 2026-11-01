use std::io;
use std::sync::{Arc, Condvar, Mutex};

use smoltcp::iface::{Config as SmolConfig, Interface as SmolInterface, SocketSet};
use smoltcp::socket::tcp::{
    Socket as SmolTcpSocket, SocketBuffer as SmolTcpSocketBuffer, State as SmolTcpState,
};
use smoltcp::wire::{HardwareAddress, IpCidr, IpListenEndpoint};

use crate::tun_tcp_packet::{
    encode_tun_tcp_packet, ParsedTunTcpPacket, TunTcpFlowKey,
};

use super::device::TunTcpDevice;

pub(crate) struct TunTcpPassiveStack {
    device: TunTcpDevice,
    iface: SmolInterface,
    sockets: SocketSet<'static>,
    handle: smoltcp::iface::SocketHandle,
    flow: TunTcpFlowKey,
    signal: TunTcpPassiveStackSignal,
}

#[derive(Clone, Default)]
pub(crate) struct TunTcpPassiveStackSignal {
    state: Arc<(Mutex<u64>, Condvar)>,
}

impl TunTcpPassiveStackSignal {
    fn new() -> Self {
        Self::default()
    }

    pub(crate) fn notify(&self) {
        let (state, ready) = &*self.state;
        if let Ok(mut generation) = state.lock() {
            *generation = generation.wrapping_add(1);
            ready.notify_all();
        }
    }

    pub(crate) fn current_generation(&self) -> io::Result<u64> {
        let (state, _) = &*self.state;
        state
            .lock()
            .map(|generation| *generation)
            .map_err(|_| io::Error::other("tun tcp signal mutex poisoned"))
    }

    pub(crate) fn wait_for_change(&self, generation: u64) -> io::Result<()> {
        let (state, ready) = &*self.state;
        let mut current = state
            .lock()
            .map_err(|_| io::Error::other("tun tcp signal mutex poisoned"))?;
        while *current == generation {
            current = ready
                .wait(current)
                .map_err(|_| io::Error::other("tun tcp signal mutex poisoned"))?;
        }
        Ok(())
    }
}

impl TunTcpPassiveStack {
    pub(crate) fn new(first_packet: &ParsedTunTcpPacket, mtu: usize) -> io::Result<Self> {
        let rx_buffer = SmolTcpSocketBuffer::new(vec![0_u8; 128 * 1024]);
        let tx_buffer = SmolTcpSocketBuffer::new(vec![0_u8; 128 * 1024]);
        let tcp_socket = SmolTcpSocket::new(rx_buffer, tx_buffer);

        let mut device = TunTcpDevice::new(mtu.max(1280));
        let mut iface = SmolInterface::new(
            SmolConfig::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::now(),
        );
        iface.update_ip_addrs(|addrs| {
            let prefix = match first_packet.destination.ip() {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            };
            let _ = addrs.push(IpCidr::new(first_packet.ip_repr.dst_addr(), prefix));
        });
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp_socket);
        {
            let socket = sockets.get_mut::<SmolTcpSocket>(handle);
            socket
                .listen(IpListenEndpoint::from((
                    first_packet.ip_repr.dst_addr(),
                    first_packet.destination.port(),
                )))
                .map_err(|err| io::Error::other(format!("tun tcp listen failed: {err:?}")))?;
        }

        Ok(Self {
            device,
            iface,
            sockets,
            handle,
            flow: first_packet.flow_key(),
            signal: TunTcpPassiveStackSignal::new(),
        })
    }

    pub(crate) fn signal(&self) -> TunTcpPassiveStackSignal {
        self.signal.clone()
    }

    pub(crate) fn ingest_packet(&mut self, packet: &ParsedTunTcpPacket) -> io::Result<()> {
        if packet.flow_key() != self.flow {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun tcp packet flow does not match passive stack",
            ));
        }
        let frame = encode_tun_tcp_packet(
            packet.source,
            packet.destination,
            packet.hop_limit,
            &packet.tcp_repr.as_repr(),
        )?;
        self.device.enqueue_received(frame);
        self.signal.notify();
        Ok(())
    }

    pub(crate) fn poll(&mut self) {
        let _ = self.iface.poll(
            smoltcp::time::Instant::now(),
            &mut self.device,
            &mut self.sockets,
        );
    }

    pub(crate) fn drain_outgoing(&mut self) -> Vec<Vec<u8>> {
        let mut emitted = Vec::new();
        while let Some(packet) = self.device.dequeue_sent() {
            emitted.push(packet);
        }
        emitted
    }

    pub(crate) fn state(&self) -> SmolTcpState {
        self.sockets.get::<SmolTcpSocket>(self.handle).state()
    }

    pub(crate) fn is_established(&self) -> bool {
        self.state() == SmolTcpState::Established
    }

    pub(crate) fn recv_application(&mut self) -> io::Result<Option<Vec<u8>>> {
        let socket = self.sockets.get_mut::<SmolTcpSocket>(self.handle);
        if !socket.can_recv() {
            return Ok(None);
        }
        match socket.recv(|buf| {
            let len = buf.len();
            (len, buf.to_vec())
        }) {
            Ok(bytes) if bytes.is_empty() => Ok(None),
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) => Err(io::Error::other(format!("tun tcp recv failed: {err:?}"))),
        }
    }

    pub(crate) fn send_application(&mut self, data: &[u8]) -> io::Result<usize> {
        let socket = self.sockets.get_mut::<SmolTcpSocket>(self.handle);
        let written = socket
            .send_slice(data)
            .map_err(|err| io::Error::other(format!("tun tcp send failed: {err:?}")))?;
        self.signal.notify();
        Ok(written)
    }

    pub(crate) fn close(&mut self) {
        let socket = self.sockets.get_mut::<SmolTcpSocket>(self.handle);
        socket.close();
        self.signal.notify();
    }

    pub(crate) fn receive_closed(&self) -> bool {
        let socket = self.sockets.get::<SmolTcpSocket>(self.handle);
        !socket.may_recv() && !socket.can_recv()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.receive_closed() || matches!(self.state(), SmolTcpState::Closed)
    }
}
