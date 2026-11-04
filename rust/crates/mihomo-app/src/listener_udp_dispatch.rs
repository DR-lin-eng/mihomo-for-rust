use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mihomo_buf::ByteWindow;
use mihomo_core::{
    push_log, LogLevel, Metadata, NetworkKind, PacketEnvelope, SessionKind,
};
use mihomo_dns::DnsRuntime;
use mihomo_runtime::RuntimeTunnel;
use mihomo_transport::decode_shadowsocks_udp_packet;

use super::transparent;
use super::listener_service_models::{ManagedUdpListenerConfig, ManagedUdpListenerHandler};
use super::listener_udp_session::SystemUdpSession;
use super::listener_udp_socks5::{
    parse_socks5_udp_frame, reassemble_socks5_udp_frame, Socks5UdpReassembly,
};
use crate::listener_udp_support::{
    udp_worker_threads, ShadowSocksUdpPacket, SocketBackedUdpPacket, SocksUdpPacket,
};

pub(super) enum UdpDispatchTask {
    Generic {
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        payload: Vec<u8>,
        tunnel: Arc<RuntimeTunnel>,
        listener: ManagedUdpListenerConfig,
        dns_runtime: Option<DnsRuntime>,
    },
    Socks {
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        payload: Vec<u8>,
        fragments: Arc<Mutex<HashMap<SocketAddr, Socks5UdpReassembly>>>,
        tunnel: Arc<RuntimeTunnel>,
        inbound_name: String,
        inbound_user: String,
        special_proxy: String,
        special_rules: String,
        dns_runtime: Option<DnsRuntime>,
    },
    Transparent {
        session_pool: Arc<crate::tun_packet::TunUdpSessionPool>,
        inbound_listener_addr: SocketAddr,
        peer_addr: SocketAddr,
        target_addr: SocketAddr,
        payload: Vec<u8>,
        tunnel: Arc<RuntimeTunnel>,
        inbound_name: String,
        special_proxy: String,
        special_rules: String,
        dns_runtime: Option<DnsRuntime>,
        session_kind: SessionKind,
    },
}

impl UdpDispatchTask {
    fn run(self) {
        match self {
            Self::Generic {
                socket,
                peer_addr,
                payload,
                tunnel,
                listener,
                dns_runtime,
            } => {
                if let Err(err) = handle_udp_packet(
                    socket,
                    peer_addr,
                    payload,
                    tunnel,
                    listener,
                    dns_runtime,
                ) {
                    log_listener_error("udp listener error", err);
                }
            }
            Self::Socks {
                socket,
                peer_addr,
                payload,
                fragments,
                tunnel,
                inbound_name,
                inbound_user,
                special_proxy,
                special_rules,
                dns_runtime,
            } => {
                if let Err(err) = handle_socks_udp_packet(
                    socket,
                    peer_addr,
                    payload,
                    fragments,
                    tunnel,
                    inbound_name,
                    inbound_user,
                    special_proxy,
                    special_rules,
                    dns_runtime,
                ) {
                    log_listener_error("socks udp relay error", err);
                }
            }
            Self::Transparent {
                session_pool,
                inbound_listener_addr,
                peer_addr,
                target_addr,
                payload,
                tunnel,
                inbound_name,
                special_proxy,
                special_rules,
                dns_runtime,
                session_kind,
            } => {
                if let Err(err) = transparent::handle_tproxy_udp_packet(
                    inbound_listener_addr,
                    peer_addr,
                    target_addr,
                    payload,
                    tunnel,
                    inbound_name,
                    special_proxy,
                    special_rules,
                    dns_runtime,
                    session_kind,
                    session_pool,
                ) {
                    log_listener_error("transparent udp relay error", err);
                }
            }
        }
    }
}

const UDP_DISPATCH_QUEUE_LIMIT:usize=256;

pub(super) struct UdpDispatchQueue {
    state: Mutex<UdpDispatchQueueState>,
    ready: Condvar,
}

struct UdpDispatchQueueState {
    closed: bool,
    tasks: VecDeque<UdpDispatchTask>,
}

impl UdpDispatchQueue {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(UdpDispatchQueueState {
                closed: false,
                tasks: VecDeque::new(),
            }),
            ready: Condvar::new(),
        }
    }

    pub(super) fn push(&self, task: UdpDispatchTask) {
        let mut state = self.state.lock().unwrap();
        if state.closed || state.tasks.len()>=UDP_DISPATCH_QUEUE_LIMIT {
            return;
        }
        state.tasks.push_back(task);
        self.ready.notify_one();
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.tasks.clear();
        self.ready.notify_all();
    }

    fn pop(&self) -> Option<UdpDispatchTask> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(task) = state.tasks.pop_front() {
                return Some(task);
            }
            if state.closed {
                return None;
            }
            state = self.ready.wait(state).unwrap();
        }
    }
}

pub(super) fn spawn_udp_workers(queue: Arc<UdpDispatchQueue>) -> Vec<JoinHandle<()>> {
    let worker_count = udp_worker_threads();
    (0..worker_count)
        .map(|_| {
            let queue = Arc::clone(&queue);
            thread::spawn(move || {
                while let Some(task) = queue.pop() {
                    task.run();
                }
            })
        })
        .collect()
}

pub(super) fn log_listener_error(err_prefix: &str, err: impl std::fmt::Display) {
    let message = format!("{err_prefix}: {err}");
    eprintln!("{message}");
    push_log(LogLevel::Error, message);
}

pub(super) fn socks_udp_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
    inbound_name: String,
    inbound_user: String,
    special_proxy: String,
    special_rules: String,
    dns_runtime: Option<DnsRuntime>,
    udp_queue: Arc<UdpDispatchQueue>,
) {
    let fragments = Arc::new(Mutex::new(HashMap::<SocketAddr, Socks5UdpReassembly>::new()));
    while !stop.load(Ordering::Relaxed) {
        let mut buf = [0_u8; 64 * 1024];
        match socket.recv_from(&mut buf) {
            Ok((read, peer_addr)) => {
                let payload = buf[..read].to_vec();
                udp_queue.push(UdpDispatchTask::Socks {
                    socket: Arc::clone(&socket),
                    peer_addr,
                    payload,
                    fragments: Arc::clone(&fragments),
                    tunnel: Arc::clone(&tunnel),
                    inbound_name: inbound_name.clone(),
                    inbound_user: inbound_user.clone(),
                    special_proxy: special_proxy.clone(),
                    special_rules: special_rules.clone(),
                    dns_runtime: dns_runtime.clone(),
                });
            }
            Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(err) => {
                let message = format!("socks udp listener recv error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                break;
            }
        }
    }
}

fn handle_socks_udp_packet(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    payload: Vec<u8>,
    fragments: Arc<Mutex<HashMap<SocketAddr, Socks5UdpReassembly>>>,
    tunnel: Arc<RuntimeTunnel>,
    inbound_name: String,
    inbound_user: String,
    special_proxy: String,
    special_rules: String,
    dns_runtime: Option<DnsRuntime>,
) -> io::Result<()> {
    let frame = parse_socks5_udp_frame(&payload)?;
    let mut fragments = fragments
        .lock()
        .map_err(|_| io::Error::other("socks5 udp fragment state poisoned"))?;
    let Some((target, body)) = reassemble_socks5_udp_frame(&mut fragments, peer_addr, frame)? else {
        return Ok(());
    };
    let local_addr = socket.local_addr()?;
    let packet = Arc::new(SocksUdpPacket {
        payload: ByteWindow::freeze(body),
        local_addr,
        peer_addr,
        socket,
    });
    let mut metadata = Metadata {
        network: NetworkKind::Udp,
        kind: SessionKind::Socks5,
        inbound_name,
        inbound_user,
        special_proxy,
        special_rules,
        src_ip: Some(peer_addr.ip()),
        src_port: Some(peer_addr.port()),
        ..Metadata::default()
    };
    metadata
        .set_remote_address(&target)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let envelope = PacketEnvelope::new(packet, metadata);
    let mut session = SystemUdpSession::new(tunnel.clone(), dns_runtime)?;
    let remote = tunnel.send_udp_packet(&envelope, &mut session)?;
    if let Some((response, responder)) = session.recv_once()? {
        tunnel.write_back_udp(&envelope, ByteWindow::freeze(response), responder)?;
    } else {
        let _ = remote;
    }
    Ok(())
}

pub(super) fn handle_udp_packet(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    payload: Vec<u8>,
    tunnel: Arc<RuntimeTunnel>,
    listener: ManagedUdpListenerConfig,
    dns_runtime: Option<DnsRuntime>,
) -> io::Result<()> {
    match &listener.handler {
        ManagedUdpListenerHandler::Tunnel(config) => {
            let local_addr = socket.local_addr()?;
            let packet = Arc::new(SocketBackedUdpPacket {
                payload: ByteWindow::freeze(payload),
                local_addr,
                peer_addr,
                socket,
            });
            let mut metadata = Metadata {
                network: NetworkKind::Udp,
                kind: SessionKind::Tunnel,
                inbound_name: config.base.name.clone(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                src_ip: Some(peer_addr.ip()),
                src_port: Some(peer_addr.port()),
                ..Metadata::default()
            };
            metadata
                .set_remote_address(&config.target)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
            let envelope = PacketEnvelope::new(packet, metadata);

            let mut session = SystemUdpSession::new(tunnel.clone(), dns_runtime)?;
            let remote = tunnel.send_udp_packet(&envelope, &mut session)?;
            let _ = remote;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some((response, responder)) = session.recv_once()? {
                    tunnel.write_back_udp(&envelope, ByteWindow::freeze(response), responder)?;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
            Ok(())
        }
        ManagedUdpListenerHandler::ShadowSocks(config) => {
            let is_2022 = mihomo_transport::is_shadowsocks_2022_cipher(&config.cipher);
            let (target, body, ss2022_session) = if is_2022 {
                let (target, body, responder) =
                    mihomo_transport::decode_shadowsocks_2022_udp_packet(
                        &config.cipher,
                        &config.password,
                        mihomo_transport::shadowsocks_2022_udp_registry(),
                        &payload,
                    )
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                (target.authority(), body, Some(responder))
            } else {
                let (target, body) =
                    decode_shadowsocks_udp_packet(&config.cipher, &config.password, &payload)
                        .map_err(|err| {
                            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
                        })?;
                (target.to_string(), body, None)
            };
            let local_addr = socket.local_addr()?;
            let packet = Arc::new(ShadowSocksUdpPacket {
                payload: ByteWindow::freeze(body),
                local_addr,
                peer_addr,
                socket,
                cipher: config.cipher.clone(),
                password: config.password.clone(),
                ss2022_session,
            });
            let mut metadata = Metadata {
                network: NetworkKind::Udp,
                kind: SessionKind::ShadowSocks,
                inbound_name: config.base.name.clone(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                src_ip: Some(peer_addr.ip()),
                src_port: Some(peer_addr.port()),
                ..Metadata::default()
            };
            metadata
                .set_remote_address(&target)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
            let envelope = PacketEnvelope::new(packet, metadata);

            let mut session = SystemUdpSession::new(tunnel.clone(), dns_runtime)?;
            let remote = tunnel.send_udp_packet(&envelope, &mut session)?;
            if let Some((response, responder)) = session.recv_once()? {
                tunnel.write_back_udp(&envelope, ByteWindow::freeze(response), responder)?;
            } else {
                let _ = remote;
            }
            Ok(())
        }
        ManagedUdpListenerHandler::Redir(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redir udp listener is only implemented on Linux/Android",
        )),
        ManagedUdpListenerHandler::TProxy(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tproxy udp listener is only implemented on Linux/Android",
        )),
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    #[test]
    fn overload_keeps_udp_queue_bounded_and_close_releases_waiters(){
        let document=mihomo_config::parse_runtime_config_document("mode: direct\n").unwrap();
        let tunnel=Arc::new(RuntimeTunnel::new("direct",mihomo_runtime::build_runtime_registry(&document).unwrap()));
        let queue=UdpDispatchQueue::new();
        let session_pool=Arc::new(crate::tun_packet::TunUdpSessionPool::default());
        for _ in 0..UDP_DISPATCH_QUEUE_LIMIT+64{
            queue.push(UdpDispatchTask::Transparent{session_pool:session_pool.clone(),inbound_listener_addr:"127.0.0.1:1".parse().unwrap(),peer_addr:"127.0.0.1:2".parse().unwrap(),target_addr:"127.0.0.1:3".parse().unwrap(),payload:vec![0;8],tunnel:Arc::clone(&tunnel),inbound_name:String::new(),special_proxy:String::new(),special_rules:String::new(),dns_runtime:None,session_kind:SessionKind::TProxy});
        }
        assert_eq!(queue.state.lock().unwrap().tasks.len(),UDP_DISPATCH_QUEUE_LIMIT);
        queue.close();assert!(queue.pop().is_none());assert!(queue.state.lock().unwrap().tasks.is_empty());
    }
}
