use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mihomo_core::BoxedTcpStream;
use mihomo_dns::DnsRuntime;
use mihomo_runtime::{ExecutionPlan, RuntimeTunnel};
use mihomo_transport::{decode_shadowsocks_udp_packet, decode_ssr_udp_packet};

use super::listener_udp_socks5::parse_socks5_udp_source_frame;
use super::listener_udp_stream_io::{recv_stream_backed_packet, stream_route_missing_label};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PreparedUdpRoute {
    Direct,
    Dns,
    Socks5 { relay_addr: SocketAddr },
    ShadowSocks {
        proxy_addr: SocketAddr,
        cipher: String,
        password: String,
    },
    Ssr {
        proxy_addr: SocketAddr,
        cipher: String,
        password: String,
    },
    AnyTls,
    Hysteria,
    Hy2,
    Snell,
    Trojan,
    TrustTunnel,
    Tuic,
    WireGuard,
    OpenVpn,
    Masque,
    Sudoku,
    Vless { source: SocketAddr },
    VlessXudp,
    VlessPacketAddr,
    Vmess { source: SocketAddr },
    VmessXudp,
    VmessPacketAddr,
    GostRelay { source: SocketAddr },
}

pub(crate) struct SystemUdpSession {
    pub(super) socket: UdpSocket,
    pub(super) smart_tracker: Option<mihomo_runtime::smart::SmartTracker>,
    pub(super) tunnel: Arc<RuntimeTunnel>,
    pub(super) dns_runtime: Option<DnsRuntime>,
    pub(super) prepared_plan: Option<ExecutionPlan>,
    pub(super) prepared_route: Option<PreparedUdpRoute>,
    pub(super) proxy_control: Option<BoxedTcpStream>,
    pub(super) proxy_stream: Option<BoxedTcpStream>,
    pub(super) pending_response: Option<(Vec<u8>, SocketAddr)>,
    pub(super) ss2022_udp_state: Option<mihomo_transport::Shadowsocks2022UdpState>,
    pub(super) sniff_deferred: bool,
    pub(super) close_signal: Option<Arc<AtomicBool>>,
    pub(super) auto_interface_target: Option<SocketAddr>,
    pub(super) prepared_target: Option<SocketAddr>,
    pub(crate) receive_generation: u64,
    pub(crate) idle_timeout: Option<Duration>,
    pub(super) receive_barrier: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl SystemUdpSession {
    pub(crate) fn is_local_dns(&self) -> bool {
        matches!(self.prepared_route, Some(PreparedUdpRoute::Dns))
    }

    pub(crate) fn receive_ready(&self) -> bool {
        !self.sniff_deferred && self.prepared_route.is_some()
    }

    pub(crate) fn receiver_close_signal(&self) -> Option<Arc<AtomicBool>> {
        self.close_signal.clone()
    }

    pub(crate) fn invalidate_association(&mut self) {
        if let Some(signal) = &self.close_signal { signal.store(true, Ordering::Release); }
    }

    /// The receive clone never holds the sending session's mutex during I/O.
    pub(crate) fn split_for_receive(&mut self) -> io::Result<Self> {
        let socket = self.socket.try_clone()?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        // Several protocols (including VLESS/VMess) expose write-only clones.
        // The original must stay on the reader side so it can consume the
        // response header and retain decoder state across UDP frames.
        let proxy_stream = if let Some(stream) = self.proxy_stream.take() {
            match stream.try_clone_box() {
                Ok(writer) => { self.proxy_stream = Some(writer); Some(stream) }
                Err(error) => { self.proxy_stream = Some(stream); return Err(error); }
            }
        } else { None };
        if let Some(stream) = &proxy_stream {
            // Protocol framing is retained by the cancellation-aware reader
            // used by the TUN receiver across these short socket timeouts.
            if stream.set_read_timeout(Some(Duration::from_millis(100))).is_err() {
                stream.set_timeouts(Some(Duration::from_millis(100)), Some(Duration::from_secs(1)))?;
            }
        }
        Ok(Self {
            socket, smart_tracker: self.smart_tracker.clone(), tunnel: self.tunnel.clone(),
            dns_runtime: self.dns_runtime.clone(), prepared_plan: self.prepared_plan.clone(),
            prepared_route: self.prepared_route.clone(), proxy_control: None, proxy_stream,
            pending_response: None, ss2022_udp_state: None, sniff_deferred: false,
            close_signal: self.close_signal.clone(), auto_interface_target: self.auto_interface_target,
            prepared_target: self.prepared_target, receive_generation: self.receive_generation,
            idle_timeout: self.idle_timeout,
            receive_barrier: None,
        })
    }

    pub(crate) fn wrap_receive_stream(&mut self, wrap: impl FnOnce(BoxedTcpStream) -> BoxedTcpStream) {
        if let Some(stream) = self.proxy_stream.take() { self.proxy_stream = Some(wrap(stream)); }
    }

    pub(crate) fn receive_shutdown_handle(&self) -> io::Result<Option<BoxedTcpStream>> {
        self.proxy_stream.as_ref().map(|stream| stream.try_clone_box()).transpose()
    }

    pub(crate) fn set_receive_barrier(&mut self, barrier: Arc<dyn Fn() + Send + Sync>) {
        self.receive_barrier = Some(barrier);
    }

    pub(super) fn reset_route_transport(&mut self) -> io::Result<()> {
        let bind_addr = SocketAddr::new(self.socket.local_addr()?.ip(), 0);
        let read_timeout = self.socket.read_timeout()?;
        let write_timeout = self.socket.write_timeout()?;
        let socket = mihomo_core::bind_outbound_udp(bind_addr)?;
        socket.set_read_timeout(read_timeout)?;
        socket.set_write_timeout(write_timeout)?;
        self.socket = socket;
        self.proxy_control = None;
        self.proxy_stream = None;
        self.prepared_plan = None;
        self.prepared_route = None;
        self.prepared_target = None;
        self.pending_response = None;
        self.ss2022_udp_state = None;
        self.auto_interface_target = None;
        Ok(())
    }

    pub(super) fn prepared_matches(
        &self,
        plan: &ExecutionPlan,
        route: &PreparedUdpRoute,
    ) -> bool {
        self.prepared_plan.as_ref() == Some(plan) && self.prepared_route.as_ref() == Some(route)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{Metadata, UdpSession};
    use mihomo_runtime::{build_runtime_registry, RuntimeTunnel, UdpOutboundRoute};
    use mihomo_transport::decode_shadowsocks_udp_packet;

    use super::SystemUdpSession;

    #[test]
    fn prepare_send_reuses_socks5_udp_associate_for_same_route() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_worker = Arc::clone(&accept_count);
        let worker = thread::spawn(move || {
            let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let mut handled_first = false;
            let started = std::time::Instant::now();
            while started.elapsed() < Duration::from_secs(2) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accept_count_worker.fetch_add(1, Ordering::Relaxed);
                        if handled_first {
                            drop(stream);
                            continue;
                        }
                        handled_first = true;
                        stream.set_nonblocking(false).unwrap();
                        let mut greeting = [0_u8; 3];
                        stream.read_exact(&mut greeting).unwrap();
                        assert_eq!(greeting, [0x05, 0x01, 0x00]);
                        stream.write_all(&[0x05, 0x00]).unwrap();

                        let mut header = [0_u8; 4];
                        stream.read_exact(&mut header).unwrap();
                        assert_eq!(header, [0x05, 0x03, 0x00, 0x01]);
                        let mut bind_ip = [0_u8; 4];
                        stream.read_exact(&mut bind_ip).unwrap();
                        let mut bind_port = [0_u8; 2];
                        stream.read_exact(&mut bind_port).unwrap();

                        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                        if let std::net::SocketAddr::V4(relay_addr) = relay_addr {
                            reply.extend_from_slice(&relay_addr.ip().octets());
                            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
                        } else {
                            panic!("expected ipv4 relay addr");
                        }
                        stream.write_all(&reply).unwrap();
                        stream.flush().unwrap();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("socks5 test accept failed: {err}"),
                }
            }
        });

        let document = parse_runtime_config_document(&format!(
            r#"
mode: rule
proxies:
  - type: socks5
    name: edge-socks
    server: 127.0.0.1
    port: {}
    udp: true
rules:
  - MATCH,edge-socks
"#,
            proxy_addr.port()
        ))
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let mut session = SystemUdpSession::new(Arc::clone(&tunnel), None).unwrap();
        let mut metadata = Metadata {
            host: Some("example.com".into()),
            dst_port: Some(53),
            special_proxy: "edge-socks".into(),
            ..Metadata::default()
        };

        let (route, _plan) = tunnel.resolve_udp_outbound_with_plan(&metadata).unwrap();
        assert!(matches!(route, UdpOutboundRoute::Socks5 { .. }));

        session.prepare_send(&mut metadata).unwrap();
        assert!(matches!(
            session.prepared_route,
            Some(super::PreparedUdpRoute::Socks5 { .. })
        ));
        session.prepare_send(&mut metadata).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while accept_count.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(accept_count.load(Ordering::Relaxed), 1);
        drop(session);
        worker.join().unwrap();
    }

    #[test]
    fn prepare_send_reuses_shadowsocks_udp_route_for_same_route() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_worker = Arc::clone(&hits);
        let worker = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
                let (read, _peer) = server.recv_from(&mut buf).unwrap();
                let (_source, payload) =
                    decode_shadowsocks_udp_packet("aes-128-gcm", "secret", &buf[..read])
                        .unwrap();
                assert_eq!(payload, expected);
                hits_worker.fetch_add(1, Ordering::Relaxed);
            }
        });

        let document = parse_runtime_config_document(&format!(
            r#"
mode: rule
proxies:
  - type: ss
    name: edge-ss
    server: 127.0.0.1
    port: {}
    cipher: aes-128-gcm
    password: secret
    udp: true
rules:
  - MATCH,edge-ss
"#,
            server_addr.port()
        ))
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
        let mut session = SystemUdpSession::new(Arc::clone(&tunnel), None).unwrap();
        let mut metadata = Metadata {
            host: Some("example.com".into()),
            dst_port: Some(53),
            special_proxy: "edge-ss".into(),
            ..Metadata::default()
        };

        let (route, _plan) = tunnel.resolve_udp_outbound_with_plan(&metadata).unwrap();
        assert!(matches!(route, UdpOutboundRoute::ShadowSocks { .. }));

        session.prepare_send(&mut metadata).unwrap();
        assert!(matches!(
            session.prepared_route,
            Some(super::PreparedUdpRoute::ShadowSocks { .. })
        ));
        session.send_to(mihomo_buf::ByteWindow::freeze(b"ping-1".to_vec()), server_addr)
            .unwrap();
        session.prepare_send(&mut metadata).unwrap();
        session.send_to(mihomo_buf::ByteWindow::freeze(b"ping-2".to_vec()), server_addr)
            .unwrap();

        worker.join().unwrap();
        assert_eq!(hits.load(Ordering::Relaxed), 2);
    }
}

impl SystemUdpSession {
    pub(crate) fn new(
        tunnel: Arc<RuntimeTunnel>,
        dns_runtime: Option<DnsRuntime>,
    ) -> io::Result<Self> {
        Self::new_with_bind_addr_and_timeout(
            "0.0.0.0:0",
            Duration::from_secs(1),
            tunnel,
            dns_runtime,
        )
    }

    pub(crate) fn new_with_bind_addr_and_timeout(
        bind_addr: &str,
        socket_timeout: Duration,
        tunnel: Arc<RuntimeTunnel>,
        dns_runtime: Option<DnsRuntime>,
    ) -> io::Result<Self> {
        let socket = mihomo_core::bind_outbound_udp(bind_addr)?;
        socket.set_read_timeout(Some(socket_timeout))?;
        socket.set_write_timeout(Some(socket_timeout))?;
        Ok(Self {
            socket,
            smart_tracker: None,
            tunnel,
            dns_runtime,
            prepared_plan: None,
            prepared_route: None,
            proxy_control: None,
            proxy_stream: None,
            pending_response: None,
            ss2022_udp_state: None,
            sniff_deferred: false,
            close_signal: None,
            auto_interface_target: None,
            prepared_target: None,
            receive_generation: 0,
            idle_timeout: None,
            receive_barrier: None,
        })
    }

    pub(crate) fn recv_once(&mut self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        if self.sniff_deferred || self.is_closed() { return Ok(None); }
        let result=self.recv_once_inner();
        if self.is_closed() { return Ok(None); }
        match &result {
            Ok(Some((payload,_))) => {if let Some(tracker)=&self.smart_tracker {tracker.record_download(payload.len());}},
            Err(error) if matches!(error.kind(),io::ErrorKind::ConnectionRefused|io::ErrorKind::ConnectionReset) => {if let Some(tracker)=&self.smart_tracker {tracker.record_failure();}},
            _=>{}
        }
        result
    }

    pub(super) fn is_closed(&self) -> bool {
        self.close_signal.as_ref().is_some_and(|signal| signal.load(Ordering::Acquire))
    }

    fn recv_once_inner(&mut self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        if let Some(response) = self.pending_response.take() {
            return Ok(Some(response));
        }
        if let Some(route) = self.prepared_route.as_ref() {
            if let Some(label) = stream_route_missing_label(route) {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, format!("missing {label}"))
                })?;
                if let Some(packet) = recv_stream_backed_packet(route, &mut **stream)? {
                    return Ok(Some(packet));
                }
            }
        }

        let mut buf = vec![0_u8; 64 * 1024];
        match self.socket.recv_from(&mut buf) {
            Ok((read, remote)) => match &self.prepared_route {
                Some(PreparedUdpRoute::Socks5 { .. }) => {
                    let (source, payload) =
                        parse_socks5_udp_source_frame(&buf[..read], self.dns_runtime.as_mut())?;
                    Ok(Some((payload, source)))
                }
                Some(PreparedUdpRoute::ShadowSocks { cipher, password, .. }) => {
                    let (source, payload) = decode_shadowsocks_udp_packet(cipher, password, &buf[..read])
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                    Ok(Some((payload, source)))
                }
                Some(PreparedUdpRoute::Ssr { cipher, password, .. }) => {
                    let (source, payload) = decode_ssr_udp_packet(cipher, password, &buf[..read])?;
                    Ok(Some((payload, source)))
                }
                Some(PreparedUdpRoute::Dns) => {
                    unreachable!("dns udp replies are returned from pending response")
                }
                Some(PreparedUdpRoute::AnyTls) => {
                    unreachable!("anytls udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Hysteria) => {
                    unreachable!("hysteria udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Hy2) => {
                    unreachable!("hysteria2 udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Trojan) => {
                    unreachable!("trojan udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::TrustTunnel) => {
                    unreachable!("trusttunnel udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Tuic) => {
                    unreachable!("tuic udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::WireGuard) => {
                    unreachable!("wireguard udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::OpenVpn) => {
                    unreachable!("openvpn udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Masque) => {
                    unreachable!("masque udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Sudoku) => {
                    unreachable!("sudoku udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Vless { .. }) => {
                    unreachable!("vless udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::VlessXudp) => {
                    unreachable!("vless xudp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::VlessPacketAddr) => {
                    unreachable!("vless packet-addr udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Vmess { .. }) => {
                    unreachable!("vmess udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::VmessXudp) => {
                    unreachable!("vmess xudp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::VmessPacketAddr) => {
                    unreachable!("vmess packet-addr udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::GostRelay { .. }) => {
                    unreachable!("gost relay udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Snell) => {
                    unreachable!("snell udp replies are read from tcp stream")
                }
                Some(PreparedUdpRoute::Direct) | None => Ok(Some((buf[..read].to_vec(), remote))),
            },
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }
}
