mod outer_socks5;

use std::io;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use ipnet::IpNet;
use mihomo_core::{BoxedTcpStream, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Builder;
use tokio::sync::mpsc as tokio_mpsc;
use tokio_wireguard::config::{Address, Config, Interface, Peer};
use tokio_wireguard::x25519::{PublicKey, StaticSecret};
use tokio_wireguard::{TcpStream as WgTcpStream, UdpSocket as WgUdpSocket};

use outer_socks5::{
    prepare_outer_socks5_underlay, resolve_wireguard_peer_endpoint,
    spawn_outer_socks5_udp_relay, WireGuardOuterSocks5Options, WireGuardOuterSocks5Prepared,
};
use crate::tunnel_dns::{self, TunnelDnsDatagramIo};
use crate::udp_channel::{encode_udp_channel_frame, UdpChannelStream, UdpStreamCommand};
use crate::{BasicAuth, TransportError, TransportTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardOptions {
    pub private_key: String,
    pub ip: String,
    pub ipv6: String,
    pub workers: usize,
    pub mtu: usize,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub peers: Vec<WireGuardPeerOptions>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPeerOptions {
    pub server: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

enum Ready<T> {
    Ok(T),
    Err(io::Error),
}

enum WriteCommand {
    Data(Vec<u8>),
    Close,
}

pub(crate) fn connect_stream(
    options: &WireGuardOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    connect_stream_with_optional_outer_socks5(options, target, None)
}

pub(crate) fn connect_stream_with_socks5_stream(
    options: &WireGuardOptions,
    target: &TransportTarget,
    control_stream: BoxedTcpStream,
    _proxy: TransportTarget,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    connect_stream_with_optional_outer_socks5(
        options,
        target,
        Some(WireGuardOuterSocks5Options {
            auth,
            control_stream,
        }),
    )
}

fn connect_stream_with_optional_outer_socks5(
    options: &WireGuardOptions,
    target: &TransportTarget,
    outer_socks5: Option<WireGuardOuterSocks5Options>,
) -> Result<BoxedTcpStream, TransportError> {
    let target = resolve_target_over_wireguard_if_needed(options, target)?;
    let outer_socks5 = prepare_outer_socks5_underlay(options, outer_socks5)?;
    let config = build_config(options, outer_socks5.as_ref())?;
    let worker_threads = normalized_worker_threads(options.workers);
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let target = target.clone();

    thread::spawn(move || {
        let runtime = Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    let _relay = outer_socks5.map(spawn_outer_socks5_udp_relay).transpose()?;
                    let mut stream = WgTcpStream::connect(target.authority(), config)
                        .await
                        .map_err(io::Error::other)?;
                    bridge_tcp_stream(&mut stream, worker_read_tx, write_rx, &worker_ready_tx).await
                });
                if let Err(err) = result {
                    let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                    let _ = ready_tx.send(Ready::Err(err));
                }
            }
            Err(err) => {
                let err = io::Error::other(err.to_string());
                let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                let _ = ready_tx.send(Ready::Err(err));
            }
        }
    });

    match ready_rx.recv() {
        Ok(Ready::Ok(())) => Ok(Box::new(WireGuardChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "wireguard tcp setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn open_udp_stream(
    options: &WireGuardOptions,
) -> Result<BoxedTcpStream, TransportError> {
    open_udp_stream_with_optional_outer_socks5(options, None)
}

pub(crate) fn open_udp_stream_with_socks5_stream(
    options: &WireGuardOptions,
    control_stream: BoxedTcpStream,
    _proxy: TransportTarget,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    open_udp_stream_with_optional_outer_socks5(
        options,
        Some(WireGuardOuterSocks5Options {
            auth,
            control_stream,
        }),
    )
}

fn open_udp_stream_with_optional_outer_socks5(
    options: &WireGuardOptions,
    outer_socks5: Option<WireGuardOuterSocks5Options>,
) -> Result<BoxedTcpStream, TransportError> {
    let outer_socks5 = prepare_outer_socks5_underlay(options, outer_socks5)?;
    let config = build_config(options, outer_socks5.as_ref())?;
    let worker_threads = normalized_worker_threads(options.workers);
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    let _relay = outer_socks5.map(spawn_outer_socks5_udp_relay).transpose()?;
                    let socket = WgUdpSocket::bind("0.0.0.0:0", config)
                        .await
                        .map_err(io::Error::other)?;
                    bridge_udp_socket(socket, worker_read_tx, write_rx, &worker_ready_tx).await
                });
                if let Err(err) = result {
                    let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                    let _ = ready_tx.send(Ready::Err(err));
                }
            }
            Err(err) => {
                let err = io::Error::other(err.to_string());
                let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                let _ = ready_tx.send(Ready::Err(err));
            }
        }
    });

    match ready_rx.recv() {
        Ok(Ready::Ok(())) => Ok(Box::new(UdpChannelStream::new(
            read_rx,
            write_tx,
            "wireguard udp stream",
        ))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "wireguard udp setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn resolve_remote_target_host(
    stream: &mut dyn TcpStream,
    options: &WireGuardOptions,
    host: &str,
) -> Result<Ipv4Addr, TransportError> {
    let mut datagram_io = WireGuardUdpStreamDnsIo { stream };
    tunnel_dns::resolve_ipv4_host_with_datagram_io(
        &mut datagram_io,
        &options.dns,
        host,
        "<wireguard>",
    )
}

fn resolve_target_over_wireguard_if_needed(
    options: &WireGuardOptions,
    target: &TransportTarget,
) -> Result<TransportTarget, TransportError> {
    if !options.remote_dns_resolve || options.dns.is_empty() {
        return Ok(target.clone());
    }
    if target.host.parse::<Ipv4Addr>().is_ok() {
        return Ok(target.clone());
    }
    if target.host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<wireguard>".to_owned(),
            feature: format!("wireguard remote dns ipv6 targets are not implemented: {}", target.host),
        });
    }
    let mut udp_stream = open_udp_stream(options)?;
    let resolved = resolve_remote_target_host(&mut *udp_stream, options, &target.host)?;
    Ok(TransportTarget::new(resolved.to_string(), target.port))
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
    let target = crate::udp_channel::decode_socket_addr(stream)?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((target, payload))
}

struct WireGuardUdpStreamDnsIo<'a> {
    stream: &'a mut dyn TcpStream,
}

impl TunnelDnsDatagramIo for WireGuardUdpStreamDnsIo<'_> {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        write_udp_packet(self.stream, target, payload).map(|_| ())
    }

    fn recv_datagram_timeout(&mut self, _timeout: Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        read_udp_packet(self.stream)
    }
}

fn build_config(
    options: &WireGuardOptions,
    outer_socks5: Option<&WireGuardOuterSocks5Prepared>,
) -> Result<Config, TransportError> {
    let private_key = parse_private_key(&options.private_key)?;
    let address = parse_address(&options.ip, &options.ipv6)?;
    let local_endpoints = outer_socks5.map(|prepared| {
        prepared
            .peer_relays
            .iter()
            .map(|relay| relay.local_endpoint)
            .collect::<Vec<_>>()
    });
    let peers = options
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            build_peer_config(
                peer,
                local_endpoints
                    .as_ref()
                    .and_then(|endpoints| endpoints.get(index).copied()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Config {
        interface: Interface {
            address,
            private_key,
            listen_port: None,
            mtu: Some(options.mtu),
        },
        peers,
    })
}

fn normalized_worker_threads(workers: usize) -> usize {
    const MIN_WORKER_THREADS: usize = 2;
    const MAX_WORKER_THREADS: usize = 8;

    if workers == 0 {
        return std::thread::available_parallelism()
            .map(|count| count.get().clamp(MIN_WORKER_THREADS, MAX_WORKER_THREADS))
            .unwrap_or(MIN_WORKER_THREADS);
    }

    workers.clamp(MIN_WORKER_THREADS, MAX_WORKER_THREADS)
}

fn build_peer_config(
    options: &WireGuardPeerOptions,
    endpoint_override: Option<SocketAddr>,
) -> Result<Peer, TransportError> {
    let public_key = parse_public_key(&options.public_key)?;
    let allowed_ips = options
        .allowed_ips
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|err| TransportError::InvalidPlan(format!("invalid wireguard allowed-ips entry {value:?}: {err}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let endpoint = endpoint_override.unwrap_or(resolve_wireguard_peer_endpoint(options)?);
    Ok(Peer {
        endpoint: Some(endpoint),
        allowed_ips,
        public_key,
        persistent_keepalive: if options.persistent_keepalive == 0 {
            None
        } else {
            Some(options.persistent_keepalive)
        },
    })
}

fn parse_private_key(value: &str) -> Result<StaticSecret, TransportError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|err| TransportError::InvalidPlan(format!("invalid wireguard private-key: {err}")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TransportError::InvalidPlan("wireguard private-key must decode to 32 bytes".to_owned()))?;
    Ok(StaticSecret::from(array))
}

fn parse_public_key(value: &str) -> Result<PublicKey, TransportError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|err| TransportError::InvalidPlan(format!("invalid wireguard public-key: {err}")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TransportError::InvalidPlan("wireguard public-key must decode to 32 bytes".to_owned()))?;
    Ok(PublicKey::from(array))
}

fn parse_address(ip: &str, ipv6: &str) -> Result<Address, TransportError> {
    let mut values = Vec::new();
    if !ip.trim().is_empty() {
        values.push(ip.trim());
    }
    if !ipv6.trim().is_empty() {
        values.push(ipv6.trim());
    }
    let joined = values.join(",");
    joined
        .parse::<Address>()
        .map_err(|err| TransportError::InvalidPlan(format!("invalid wireguard address: {err}")))
}

async fn bridge_tcp_stream(
    stream: &mut WgTcpStream,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "wireguard setup receiver dropped"))?;
    let mut read_buf = vec![0_u8; 64 * 1024];
    let mut write_closed = false;
    loop {
        tokio::select! {
            result = stream.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Ok(read) => {
                        let _ = read_tx.send(Ok(read_buf[..read].to_vec()));
                    }
                    Err(err) => return Err(io::Error::other(err)),
                }
            }
            maybe = write_rx.recv(), if !write_closed => {
                match maybe {
                    Some(WriteCommand::Data(data)) => {
                        stream.write_all(&data).await.map_err(io::Error::other)?;
                        stream.flush().await.map_err(io::Error::other)?;
                    }
                    Some(WriteCommand::Close) | None => {
                        write_closed = true;
                        stream.shutdown().await.map_err(io::Error::other)?;
                    }
                }
            }
        }
    }
}

async fn bridge_udp_socket(
    socket: WgUdpSocket,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<UdpStreamCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "wireguard udp setup receiver dropped"))?;
    loop {
        tokio::select! {
            result = async {
                let mut read_buf = Vec::with_capacity(64 * 1024);
                socket.recv_from(&mut read_buf).await.map(|(read, source)| (read_buf, read, source))
            } => {
                match result {
                    Ok((read_buf, read, source)) => {
                        let _ = read_tx.send(Ok(encode_udp_channel_frame(source, &read_buf[..read])));
                    }
                    Err(err) => return Err(io::Error::other(err)),
                }
            }
            maybe = write_rx.recv() => {
                match maybe {
                    Some(UdpStreamCommand::Datagram { target, payload }) => {
                        socket.send_to(&payload, target).await.map_err(io::Error::other)?;
                    }
                    Some(UdpStreamCommand::Close) | None => return Ok(()),
                }
            }
        }
    }
}

struct WireGuardChannelStream {
    read_rx: Arc<Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct WireGuardChannelClone {
    read_rx: Arc<Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

impl WireGuardChannelStream {
    fn new(
        read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
        write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
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

impl Read for WireGuardChannelStream {
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
            .map_err(|_| io::Error::other("wireguard tcp read receiver mutex poisoned"))?
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

impl Write for WireGuardChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "wireguard tcp stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for WireGuardChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(WireGuardChannelClone {
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
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl Read for WireGuardChannelClone {
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
            .map_err(|_| io::Error::other("wireguard tcp read receiver mutex poisoned"))?
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

impl Write for WireGuardChannelClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "wireguard tcp stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for WireGuardChannelClone {
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
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

#[cfg(test)]
mod tests {
    use super::normalized_worker_threads;

    #[test]
    fn wireguard_workers_are_clamped_to_supported_runtime_range() {
        assert!((2..=8).contains(&normalized_worker_threads(0)));
        assert_eq!(normalized_worker_threads(1), 2);
        assert_eq!(normalized_worker_threads(2), 2);
        assert_eq!(normalized_worker_threads(4), 4);
        assert_eq!(normalized_worker_threads(32), 8);
    }
}
