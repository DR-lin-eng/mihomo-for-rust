use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use mihomo_core::BoxedTcpStream;
use smoltcp::iface::{Config as SmolConfig, Interface as SmolInterface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    self as smol_tcp, Socket as SmolTcpSocket, SocketBuffer as SmolTcpSocketBuffer,
};
use smoltcp::wire::{
    HardwareAddress, IpAddress as SmolIpAddress, IpCidr, IpListenEndpoint,
    Ipv4Address as SmolIpv4Address, Ipv4Cidr,
};
use tokio::sync::mpsc as tokio_mpsc;

use crate::udp_channel::{
    decode_socket_addr, encode_udp_channel_frame, UdpChannelStream, UdpStreamCommand,
};
use crate::{TransportError, TransportTarget};

pub trait IpPacketIo: Send + 'static {
    fn write_ip_packet(&mut self, packet: &[u8]) -> io::Result<()>;
    fn read_ip_packet_timeout(&mut self, timeout: Duration) -> io::Result<Vec<u8>>;
    fn close(&mut self) -> io::Result<()>;
}

struct IpStackDevice {
    recv: IpStackToken,
    send: IpStackToken,
    mtu: usize,
}

struct IpStackToken {
    queue: std::collections::VecDeque<Vec<u8>>,
}

struct IpTcpStack<T: IpPacketIo> {
    io: Arc<Mutex<T>>,
    iface: SmolInterface,
    sockets: SocketSet<'static>,
    handle: smoltcp::iface::SocketHandle,
}

struct IpTcpStackStream {
    read_rx: Arc<Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>>,
    write_tx: mpsc::Sender<IpTcpWriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct IpTcpStackStreamClone {
    read_rx: Arc<Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>>,
    write_tx: mpsc::Sender<IpTcpWriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

enum IpTcpWriteCommand {
    Data(Vec<u8>),
    Close,
}

impl IpStackDevice {
    fn new(mtu: usize) -> Self {
        Self {
            recv: IpStackToken {
                queue: std::collections::VecDeque::new(),
            },
            send: IpStackToken {
                queue: std::collections::VecDeque::new(),
            },
            mtu,
        }
    }

    fn enqueue_received(&mut self, packet: Vec<u8>) {
        self.recv.queue.push_back(packet);
    }

    fn dequeue_sent(&mut self) -> Option<Vec<u8>> {
        self.send.queue.pop_front()
    }
}

impl Device for IpStackDevice {
    type RxToken<'a> = &'a mut IpStackToken;
    type TxToken<'a> = &'a mut IpStackToken;

    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.recv.queue.is_empty() {
            None
        } else {
            Some((&mut self.recv, &mut self.send))
        }
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(&mut self.send)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

impl RxToken for &mut IpStackToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.queue.pop_front().unwrap_or_default();
        f(&mut packet)
    }
}

impl TxToken for &mut IpStackToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.queue.push_back(packet);
        result
    }
}

impl<T: IpPacketIo> IpTcpStack<T> {
    fn new(
        io: Arc<Mutex<T>>,
        source_ip: Ipv4Addr,
        mtu: usize,
        target: &TransportTarget,
    ) -> Result<(Self, IpStackDevice), TransportError> {
        let rx_buffer = SmolTcpSocketBuffer::new(vec![0_u8; 128 * 1024]);
        let tx_buffer = SmolTcpSocketBuffer::new(vec![0_u8; 128 * 1024]);
        let tcp_socket = SmolTcpSocket::new(rx_buffer, tx_buffer);

        let mut device = IpStackDevice::new(mtu.max(1280));
        let mut iface = SmolInterface::new(
            SmolConfig::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::now(),
        );
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(
                SmolIpv4Address::from(source_ip),
                32,
            )));
        });
        iface.routes_mut()
            .add_default_ipv4_route(SmolIpv4Address::UNSPECIFIED)
            .map_err(|err| {
                TransportError::InvalidPlan(format!("ip tcp stack route init failed: {err}"))
            })?;

        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp_socket);
        {
            let socket = sockets.get_mut::<SmolTcpSocket>(handle);
            let remote_ip = resolve_target_ipv4(&target.host)?;
            socket
                .connect(
                    iface.context(),
                    (SmolIpAddress::Ipv4(remote_ip), target.port),
                    IpListenEndpoint::from(49152),
                )
                .map_err(|err| {
                    TransportError::InvalidPlan(format!("ip tcp stack connect init failed: {err}"))
                })?;
        }

        Ok((
            Self {
                io,
                iface,
                sockets,
                handle,
            },
            device,
        ))
    }

    fn run(
        mut self,
        mut device: IpStackDevice,
        read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
        write_rx: mpsc::Receiver<IpTcpWriteCommand>,
        ready_tx: mpsc::SyncSender<io::Result<()>>,
    ) -> io::Result<()> {
        let mut pending_writes = std::collections::VecDeque::<Vec<u8>>::new();
        let mut ready_sent = false;
        let mut close_requested = false;
        let mut write_channel_closed = false;
        loop {
            loop {
                match write_rx.try_recv() {
                    Ok(IpTcpWriteCommand::Data(outbound)) => pending_writes.push_back(outbound),
                    Ok(IpTcpWriteCommand::Close) => close_requested = true,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        write_channel_closed = true;
                        break;
                    }
                }
            }

            while let Some(packet) = device.dequeue_sent() {
                self.io
                    .lock()
                    .map_err(|_| io::Error::other("ip tcp stack io mutex poisoned"))?
                    .write_ip_packet(&packet)?;
            }

            match self
                .io
                .lock()
                .map_err(|_| io::Error::other("ip tcp stack io mutex poisoned"))?
                .read_ip_packet_timeout(Duration::from_millis(20))
            {
                Ok(packet) => device.enqueue_received(packet),
                Err(err)
                    if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {}
                Err(err) => {
                    if !ready_sent {
                        let _ = ready_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                    }
                    let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                    return Err(err);
                }
            }

            let _ = self.iface.poll(
                smoltcp::time::Instant::now(),
                &mut device,
                &mut self.sockets,
            );
            let socket = self.sockets.get_mut::<SmolTcpSocket>(self.handle);

            if !ready_sent && socket.may_send() {
                let _ = ready_tx.send(Ok(()));
                ready_sent = true;
            }

            while let Some(front) = pending_writes.front_mut() {
                if !socket.can_send() {
                    break;
                }
                match socket.send_slice(front) {
                    Ok(written) if written == front.len() => {
                        pending_writes.pop_front();
                    }
                    Ok(written) if written > 0 => {
                        front.drain(..written);
                        break;
                    }
                    Ok(_) => break,
                    Err(_) => break,
                }
            }

            if (close_requested || write_channel_closed)
                && pending_writes.is_empty()
                && socket.may_send()
                && socket.is_open()
            {
                socket.close();
            }

            if socket.can_recv() {
                match socket.recv(|buf| {
                    let len = buf.len();
                    (len, buf.to_vec())
                }) {
                    Ok(bytes) if !bytes.is_empty() => {
                        let _ = read_tx.send(Ok(bytes));
                    }
                    Ok(_) => {}
                    Err(smol_tcp::RecvError::Finished) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Err(_) => {}
                }
            }

            if matches!(socket.state(), smol_tcp::State::Closed) {
                if !ready_sent {
                    let _ = ready_tx.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "ip tcp stack closed before connect completed",
                    )));
                }
                let _ = read_tx.send(Ok(Vec::new()));
                return Ok(());
            }

            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl IpTcpStackStream {
    fn new(
        read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
        write_tx: mpsc::Sender<IpTcpWriteCommand>,
    ) -> Self {
        Self {
            read_rx: Arc::new(Mutex::new(read_rx)),
            write_tx,
            pending: Vec::new(),
            offset: 0,
            write_closed: false,
        }
    }
}

impl Read for IpTcpStackStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.pending.len() {
            let available = &self.pending[self.offset..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.offset += copied;
            if self.offset == self.pending.len() {
                self.pending.clear();
                self.offset = 0;
            }
            return Ok(copied);
        }
        let recv = self
            .read_rx
            .lock()
            .map_err(|_| io::Error::other("ip tcp stack read receiver mutex poisoned"))?
            .recv();
        match recv {
            Ok(Ok(bytes)) if bytes.is_empty() => Ok(0),
            Ok(Ok(bytes)) => {
                let copied = bytes.len().min(buf.len());
                buf[..copied].copy_from_slice(&bytes[..copied]);
                if copied < bytes.len() {
                    self.pending = bytes;
                    self.offset = copied;
                }
                Ok(copied)
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Ok(0),
        }
    }
}

impl Write for IpTcpStackStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(IpTcpWriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ip tcp stack stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl mihomo_core::TcpStream for IpTcpStackStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(IpTcpStackStreamClone {
            read_rx: Arc::clone(&self.read_rx),
            write_tx: self.write_tx.clone(),
            pending: Vec::new(),
            offset: 0,
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(IpTcpWriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl Read for IpTcpStackStreamClone {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.pending.len() {
            let available = &self.pending[self.offset..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.offset += copied;
            if self.offset == self.pending.len() {
                self.pending.clear();
                self.offset = 0;
            }
            return Ok(copied);
        }
        let recv = self
            .read_rx
            .lock()
            .map_err(|_| io::Error::other("ip tcp stack read receiver mutex poisoned"))?
            .recv();
        match recv {
            Ok(Ok(bytes)) if bytes.is_empty() => Ok(0),
            Ok(Ok(bytes)) => {
                let copied = bytes.len().min(buf.len());
                buf[..copied].copy_from_slice(&bytes[..copied]);
                if copied < bytes.len() {
                    self.pending = bytes;
                    self.offset = copied;
                }
                Ok(copied)
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Ok(0),
        }
    }
}

impl Write for IpTcpStackStreamClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(IpTcpWriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ip tcp stack stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl mihomo_core::TcpStream for IpTcpStackStreamClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_rx: Arc::clone(&self.read_rx),
            write_tx: self.write_tx.clone(),
            pending: Vec::new(),
            offset: 0,
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(IpTcpWriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

pub(crate) fn resolve_ipv4_target(host: &str) -> Result<SmolIpv4Address, TransportError> {
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(SmolIpv4Address::from(ipv4));
    }
    let resolved = (host, 0)
        .to_socket_addrs()
        .map_err(TransportError::from)?
        .find_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(ipv4) => Some(ipv4),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or_else(|| TransportError::UnsupportedFeature {
            proxy: "<ip-tunnel>".to_owned(),
            feature: format!("domain target without resolvable ipv4 address: {host}"),
        })?;
    Ok(SmolIpv4Address::from(resolved))
}

fn resolve_target_ipv4(host: &str) -> Result<SmolIpv4Address, TransportError> {
    resolve_ipv4_target(host)
}

pub(crate) fn first_ipv4_from_prefixes(prefixes: &[String]) -> io::Result<Ipv4Addr> {
    prefixes
        .iter()
        .find_map(|value| value.split('/').next())
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ip tunnel push reply missing ipv4 address",
            )
        })
}

pub(crate) fn encode_ipv4_udp_packet(
    source: Ipv4Addr,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let SocketAddr::V4(target) = target else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ip tunnel udp bridge currently supports ipv4 targets only",
        ));
    };
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    if total_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ip tunnel udp bridge packet too large",
        ));
    }

    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[10..12].copy_from_slice(&0_u16.to_be_bytes());
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.ip().octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&53_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&target.port().to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[26..28].copy_from_slice(&0_u16.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    Ok(packet)
}

pub(crate) fn decode_ipv4_udp_packet_parts(
    packet: &[u8],
) -> io::Result<(SocketAddr, SocketAddr, Vec<u8>)> {
    if packet.len() < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ip tunnel udp bridge ip packet too short",
        ));
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ip tunnel udp bridge expects ipv4 packets",
        ));
    }
    let header_len = ihl * 4;
    if packet.len() < header_len + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ip tunnel udp bridge truncated ipv4 header",
        ));
    }
    if packet[9] != 17 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ip tunnel udp bridge expects udp packets",
        ));
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ip tunnel udp bridge invalid ipv4 total length",
        ));
    }
    let source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
        u16::from_be_bytes([packet[20], packet[21]]),
    );
    let destination = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
        u16::from_be_bytes([packet[22], packet[23]]),
    );
    let udp_len = u16::from_be_bytes([packet[24], packet[25]]) as usize;
    if udp_len < 8 || header_len + udp_len > total_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ip tunnel udp bridge invalid udp length",
        ));
    }
    Ok((
        source,
        destination,
        packet[header_len + 8..header_len + udp_len].to_vec(),
    ))
}

pub(crate) fn decode_ipv4_udp_packet(packet: &[u8]) -> io::Result<(SocketAddr, Vec<u8>)> {
    let (source, _destination, payload) = decode_ipv4_udp_packet_parts(packet)?;
    Ok((source, payload))
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = header.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let frame = encode_udp_channel_frame(target, payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let target = decode_socket_addr(stream)?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((target, payload))
}

pub(crate) fn connect_tcp_stream<T: IpPacketIo>(
    io: T,
    source_ip: Ipv4Addr,
    mtu: usize,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let io = Arc::new(Mutex::new(io));
    let (stack, device) = IpTcpStack::new(Arc::clone(&io), source_ip, mtu, target)?;
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let _ = stack.run(device, read_tx, write_rx, ready_tx);
    });

    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(TransportError::from(err)),
        Err(_) => {
            return Err(TransportError::Io {
                kind: io::ErrorKind::ConnectionAborted,
                message: "ip tcp stack setup thread exited early".to_owned(),
            })
        }
    }

    Ok(Box::new(IpTcpStackStream::new(read_rx, write_tx)))
}

pub(crate) fn open_udp_stream<T: IpPacketIo>(
    mut io: T,
    source_ip: Ipv4Addr,
) -> Result<BoxedTcpStream, TransportError> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, mut write_rx) = tokio_mpsc::unbounded_channel();

    thread::spawn(move || loop {
        while let Ok(command) = write_rx.try_recv() {
            match command {
                UdpStreamCommand::Datagram { target, payload } => {
                    let packet = match encode_ipv4_udp_packet(source_ip, target, &payload) {
                        Ok(packet) => packet,
                        Err(err) => {
                            let _ = read_tx.send(Err(err));
                            return;
                        }
                    };
                    if let Err(err) = io.write_ip_packet(&packet) {
                        let _ = read_tx.send(Err(err));
                        return;
                    }
                }
                UdpStreamCommand::Close => {
                    let _ = io.close();
                    return;
                }
            }
        }

        match io.read_ip_packet_timeout(Duration::from_millis(50)) {
            Ok(packet) => match decode_ipv4_udp_packet(&packet) {
                Ok((source, payload)) => {
                    let _ = read_tx.send(Ok(encode_udp_channel_frame(source, &payload)));
                }
                Err(_) => continue,
            },
            Err(err) if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                continue;
            }
            Err(err) => {
                let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                let _ = io.close();
                return;
            }
        }
    });

    Ok(Box::new(UdpChannelStream::new(
        read_rx,
        write_tx,
        "ip tunnel udp stream",
    )))
}
