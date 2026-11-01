use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mihomo_core::BoxedTcpStream;

use super::{WireGuardOptions, WireGuardPeerOptions};
use crate::socks5_udp_underlay::{
    build_socks5_udp_frame, connect_socks5_udp_associate_over_stream, parse_socks5_udp_frame,
};
use crate::{BasicAuth, TransportError};

pub(super) struct WireGuardOuterSocks5Options {
    pub(super) auth: Option<BasicAuth>,
    pub(super) control_stream: BoxedTcpStream,
}

pub(super) struct WireGuardOuterSocks5Prepared {
    pub(super) relay_addr: SocketAddr,
    pub(super) outer_socket: UdpSocket,
    pub(super) peer_relays: Vec<WireGuardOuterPeerRelay>,
    pub(super) control_stream: Option<BoxedTcpStream>,
    pub(super) direct: bool,
}

pub(super) struct WireGuardOuterPeerRelay {
    pub(super) remote_endpoint: SocketAddr,
    pub(super) local_endpoint: SocketAddr,
    pub(super) socket: UdpSocket,
    pub(super) wg_source: Arc<Mutex<Option<SocketAddr>>>,
}

pub(super) struct WireGuardUdpRelayGuard {
    shutdown: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
    outer_socket: UdpSocket,
    control_stream: Option<BoxedTcpStream>,
}

pub(super) fn prepare_outer_socks5_underlay(
    options: &WireGuardOptions,
    outer_socks5: Option<WireGuardOuterSocks5Options>,
) -> Result<Option<WireGuardOuterSocks5Prepared>, TransportError> {
    let (outer_socket, relay_addr, control_stream, direct) = if let Some(mut outer) = outer_socks5 {
        let (socket, relay) = connect_socks5_udp_associate_over_stream(
            &mut *outer.control_stream,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            outer.auth.as_ref(),
        )?;
        (socket, relay, Some(outer.control_stream), false)
    } else if mihomo_core::outbound_mark() != 0 {
        let socket = mihomo_core::bind_outbound_udp("0.0.0.0:0").map_err(TransportError::from)?;
        let addr = socket.local_addr().map_err(TransportError::from)?;
        (socket, addr, None, true)
    } else {
        return Ok(None);
    };
    outer_socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(TransportError::from)?;
    outer_socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(TransportError::from)?;
    let peer_relays = options
        .peers
        .iter()
        .map(|peer| {
            let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .map_err(TransportError::from)?;
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .map_err(TransportError::from)?;
            socket
                .set_write_timeout(Some(Duration::from_secs(1)))
                .map_err(TransportError::from)?;
            let local_endpoint = socket.local_addr().map_err(TransportError::from)?;
            Ok(WireGuardOuterPeerRelay {
                remote_endpoint: resolve_wireguard_peer_endpoint(peer)?,
                local_endpoint,
                socket,
                wg_source: Arc::new(Mutex::new(None)),
            })
        })
        .collect::<Result<Vec<_>, TransportError>>()?;
    Ok(Some(WireGuardOuterSocks5Prepared {
        relay_addr,
        outer_socket,
        peer_relays,
        control_stream,
        direct,
    }))
}

pub(super) fn resolve_wireguard_peer_endpoint(
    peer: &WireGuardPeerOptions,
) -> Result<SocketAddr, TransportError> {
    (peer.server.as_str(), peer.port)
        .to_socket_addrs()
        .map_err(TransportError::from)?
        .find(|addr| matches!(addr, SocketAddr::V4(_)))
        .ok_or_else(|| {
            TransportError::InvalidPlan(format!(
                "wireguard peer endpoint could not resolve an ipv4 address for {}:{}",
                peer.server, peer.port
            ))
        })
}

pub(super) fn spawn_outer_socks5_udp_relay(
    prepared: WireGuardOuterSocks5Prepared,
) -> io::Result<WireGuardUdpRelayGuard> {
    WireGuardUdpRelayGuard::spawn(prepared)
}

impl WireGuardUdpRelayGuard {
    fn spawn(prepared: WireGuardOuterSocks5Prepared) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let relay_addr = prepared.relay_addr;
        let direct = prepared.direct;
        let outer_socket = prepared.outer_socket;
        let reader_socket = outer_socket.try_clone()?;
        let mut inbound_routes = Vec::new();

        for relay in prepared.peer_relays {
            inbound_routes.push((
                relay.remote_endpoint,
                relay.socket.try_clone()?,
                Arc::clone(&relay.wg_source),
            ));
            let writer_socket = relay.socket;
            let outer_sender = outer_socket.try_clone()?;
            let remote_endpoint = relay.remote_endpoint;
            let wg_source = relay.wg_source;
            let writer_shutdown = Arc::clone(&shutdown);
            threads.push(thread::spawn(move || {
                peer_relay_loop(
                    writer_socket,
                    outer_sender,
                    relay_addr,
                    remote_endpoint,
                    wg_source,
                    writer_shutdown,
                    direct,
                )
            }));
        }

        let reader_shutdown = Arc::clone(&shutdown);
        threads.push(thread::spawn(move || {
            outer_relay_loop(
                reader_socket,
                relay_addr,
                inbound_routes,
                reader_shutdown,
                direct,
            )
        }));

        Ok(Self {
            shutdown,
            threads,
            outer_socket,
            control_stream: prepared.control_stream,
        })
    }
}

impl Drop for WireGuardUdpRelayGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        let _ = self.outer_socket.local_addr();
        if let Some(stream) = &self.control_stream {
            let _ = stream.try_clone_box();
        }
    }
}

fn peer_relay_loop(
    writer_socket: UdpSocket,
    outer_sender: UdpSocket,
    relay_addr: SocketAddr,
    remote_endpoint: SocketAddr,
    wg_source: Arc<Mutex<Option<SocketAddr>>>,
    shutdown: Arc<AtomicBool>,
    direct: bool,
) {
    let mut buf = [0_u8; 64 * 1024];
    while !shutdown.load(Ordering::Acquire) {
        match writer_socket.recv_from(&mut buf) {
            Ok((read, source)) => {
                if let Ok(mut guard) = wg_source.lock() {
                    *guard = Some(source);
                }
                if direct {
                    let _ = outer_sender.send_to(&buf[..read], remote_endpoint);
                } else {
                    let frame = build_socks5_udp_frame(remote_endpoint, &buf[..read]);
                    let _ = outer_sender.send_to(&frame, relay_addr);
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}

fn outer_relay_loop(
    reader_socket: UdpSocket,
    relay_addr: SocketAddr,
    inbound_routes: Vec<(SocketAddr, UdpSocket, Arc<Mutex<Option<SocketAddr>>>)>,
    shutdown: Arc<AtomicBool>,
    direct: bool,
) {
    let mut buf = [0_u8; 64 * 1024];
    while !shutdown.load(Ordering::Acquire) {
        match reader_socket.recv_from(&mut buf) {
            Ok((read, source)) => {
                let (remote, payload) = if direct {
                    (source, buf[..read].to_vec())
                } else {
                    if source != relay_addr {
                        continue;
                    }
                    let Ok(value) = parse_socks5_udp_frame(&buf[..read]) else {
                        continue;
                    };
                    value
                };
                let Some((_, peer_socket, wg_source)) = inbound_routes
                    .iter()
                    .find(|(endpoint, _, _)| *endpoint == remote)
                else {
                    continue;
                };
                let Ok(guard) = wg_source.lock() else {
                    continue;
                };
                let Some(target) = *guard else {
                    continue;
                };
                let _ = peer_socket.send_to(&payload, target);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}
