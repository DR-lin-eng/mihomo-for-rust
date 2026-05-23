use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use mihomo_buf::ByteWindow;
use mihomo_config::RuntimeConfigDocument;
use mihomo_core::{push_log, BoxedTcpStream, ConnectionContext, LogLevel, Metadata, NetworkKind, PacketEnvelope, SessionKind, UdpPacket, UdpSession, WriteBack};
use mihomo_dns::DnsRuntime;
use mihomo_inbound::{
    AuthUser, BaseInboundConfig, GenericInboundConfig, HttpInboundConfig, InboundDefinition,
    TlsInboundConfig, TunnelInboundConfig,
};
use mihomo_runtime::{
    dispatch_http_proxy_tcp_stream_with_dialer,
    dispatch_prepared_socks5_tcp_context_with_dialer, dispatch_tunnel_tcp_stream_with_dialer,
    prepare_socks5_dispatch, write_socks5_udp_associate_reply, BootstrapState,
    ListenerRuntimeError, PreparedSocks5Dispatch, PreparedSocks5UdpAssociate, RuntimeTunnel,
    UdpAnyTlsRoute, UdpGostRelayRoute, UdpOutboundRoute, UdpSnellRoute, UdpSocks5Route,
    UdpSudokuRoute, UdpTrojanRoute, UdpTrustTunnelRoute, UdpVlessRoute, UdpVmessRoute,
};
use sha1::{Digest, Sha1};
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use mihomo_transport::{
    decode_shadowsocks_udp_packet, decode_ssr_udp_packet, encode_shadowsocks_udp_packet,
    encode_ssr_udp_packet, SocketOptions,
    TcpDialPurpose, TcpDialer, TransportError, TransportTarget,
};
use mihomo_transport::{
    accept_vmess_stream,
    accept_sudoku_stream, accept_sudoku_stream_allow_suspicious,
    accept_sudoku_stream_with_custom_tables,
    accept_sudoku_stream_with_custom_tables_allow_suspicious,
    accept_sudoku_stream_with_custom_tables_and_http_mask,
    accept_sudoku_stream_with_http_mask, SudokuAcceptedStream, SudokuHttpMaskServerAcceptor,
    SudokuInboundAccept,
    decode_packetaddr_udp_packet, encode_packetaddr_udp_packet, open_anytls_udp_stream,
    open_gost_relay_udp_stream, open_sudoku_udp_stream, open_trojan_udp_stream,
    wrap_grpc_proxy_stream, wrap_grpc_tls_proxy_stream, wrap_h2_proxy_stream, wrap_http_proxy_stream,
    open_vless_packetaddr_udp_stream, open_vless_udp_stream, open_vless_xudp_stream,
    open_vmess_packetaddr_udp_stream,
    open_vmess_udp_stream, open_vmess_xudp_stream,
    open_trusttunnel_udp_stream,
    read_anytls_udp_packet,
    read_gost_relay_udp_packet, read_snell_udp_packet, read_sudoku_udp_packet,
    read_trusttunnel_udp_packet,
    read_trojan_udp_packet, read_vless_udp_packet, read_vless_xudp_packet, read_vmess_udp_packet,
    read_vmess_xudp_packet,
    write_anytls_udp_packet,
    write_gost_relay_udp_packet, write_snell_udp_packet, write_sudoku_udp_packet,
    write_trusttunnel_udp_packet,
    write_trojan_udp_packet, write_vless_udp_packet, write_vless_xudp_packet,
    write_vmess_udp_packet,
    write_vmess_xudp_packet,
    wrap_smux_stream,
    wrap_snell_udp_stream,
    wrap_tls_proxy_stream,
    wrap_websocket_proxy_stream,
    wrap_xhttp_proxy_stream, wrap_xhttp_tls_proxy_stream,
    VmessAcceptedStream, XHttpOptions,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundTcpListener {
    pub name: String,
    pub kind: String,
    pub configured_addr: String,
    pub local_addr: SocketAddr,
}

#[derive(Debug)]
pub enum ListenerServiceError {
    Rule(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ListenerServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rule(message) => write!(f, "{message}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ListenerServiceError {}

impl From<std::io::Error> for ListenerServiceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub struct RunningListenerService {
    bound_listeners: Vec<BoundTcpListener>,
    shutdown: Arc<AtomicBool>,
    join_handles: Vec<JoinHandle<()>>,
}

impl RunningListenerService {
    pub fn start(state: &BootstrapState) -> Result<Self, ListenerServiceError> {
        let tunnel = Arc::new(
            state
                .build_runtime_tunnel()
                .map_err(|err| ListenerServiceError::Rule(err.to_string()))?,
        );
        Self::start_with_tunnel(state, tunnel)
    }

    pub fn start_with_tunnel(
        state: &BootstrapState,
        tunnel: Arc<RuntimeTunnel>,
    ) -> Result<Self, ListenerServiceError> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut bound_listeners = Vec::new();
        let mut join_handles = Vec::new();
        let dns_runtime = state.build_dns_runtime().ok();

        if let Some(runtime) = dns_runtime.clone().filter(|runtime| {
            runtime.config.enabled && !runtime.config.listen.trim().is_empty()
        }) {
            let dns_socket = UdpSocket::bind(&runtime.config.listen)?;
            let local_addr = dns_socket.local_addr()?;
            dns_socket.set_nonblocking(true)?;
            bound_listeners.push(BoundTcpListener {
                name: "__dns__".into(),
                kind: "dns".into(),
                configured_addr: runtime.config.listen.clone(),
                local_addr,
            });
            let shutdown_flag = shutdown.clone();
            let runtime = Arc::new(Mutex::new(runtime));
            let join_handle = thread::spawn(move || dns_loop(dns_socket, shutdown_flag, runtime));
            join_handles.push(join_handle);
        }

        for listener in build_tcp_listener_configs(&state.document)? {
            let tcp_listener = TcpListener::bind(&listener.address)?;
            let local_addr = tcp_listener.local_addr()?;
            tcp_listener.set_nonblocking(true)?;

            bound_listeners.push(BoundTcpListener {
                name: listener.name.clone(),
                kind: listener.handler.kind_name().to_owned(),
                configured_addr: listener.address.clone(),
                local_addr,
            });

            let shutdown_flag = shutdown.clone();
            let tunnel = tunnel.clone();
            let handler = listener.handler.clone();
            let dns_runtime = dns_runtime.clone();
            let join_handle = thread::spawn(move || {
                accept_loop(tcp_listener, shutdown_flag, tunnel, handler, dns_runtime);
            });
            join_handles.push(join_handle);
        }

        for listener in build_udp_listener_configs(&state.document) {
            let udp_socket = UdpSocket::bind(&listener.address)?;
            let local_addr = udp_socket.local_addr()?;
            udp_socket.set_nonblocking(true)?;

            bound_listeners.push(BoundTcpListener {
                name: listener.name.clone(),
                kind: listener.kind_name().to_owned(),
                configured_addr: listener.address.clone(),
                local_addr,
            });

            let shutdown_flag = shutdown.clone();
            let tunnel = tunnel.clone();
            let dns_runtime = dns_runtime.clone();
            let join_handle = thread::spawn(move || {
                udp_loop(udp_socket, shutdown_flag, tunnel, listener, dns_runtime);
            });
            join_handles.push(join_handle);
        }

        Ok(Self {
            bound_listeners,
            shutdown,
            join_handles,
        })
    }

    pub fn bound_listeners(&self) -> &[BoundTcpListener] {
        &self.bound_listeners
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for handle in self.join_handles.drain(..) {
            let _ = handle.join();
        }
    }
}

struct DnsAwareTcpDialer {
    dns_runtime: Option<DnsRuntime>,
}

impl DnsAwareTcpDialer {
    fn new(dns_runtime: Option<DnsRuntime>) -> Self {
        Self { dns_runtime }
    }

    fn resolve_addr(
        &mut self,
        target: &TransportTarget,
        purpose: TcpDialPurpose,
    ) -> Result<SocketAddr, TransportError> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, target.port));
        }
        if let Some(runtime) = self.dns_runtime.as_mut() {
            let resolved = match purpose {
                TcpDialPurpose::FinalTarget => runtime.resolve_direct_server_host_via_system(&target.host),
                TcpDialPurpose::ProxyServer => {
                    runtime.resolve_proxy_server_host_via_system(&target.host)
                }
            }
            .map_err(|err| TransportError::Io {
                kind: io::ErrorKind::Other,
                message: err.to_string(),
            })?;
            if let Some(ip) = resolved {
                return Ok(SocketAddr::new(ip, target.port));
            }
        }

        let mut addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(TransportError::from)?;
        addrs.next().ok_or_else(|| TransportError::Io {
            kind: io::ErrorKind::NotFound,
            message: format!("failed to resolve tcp target: {}", target.authority()),
        })
    }
}

impl TcpDialer for DnsAwareTcpDialer {
    fn connect(
        &mut self,
        target: &TransportTarget,
        _socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        let addr = self.resolve_addr(target, purpose)?;
        let stream = TcpStream::connect(addr).map_err(TransportError::from)?;
        Ok(Box::new(stream))
    }
}

impl Drop for RunningListenerService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Clone, Debug)]
struct ManagedTcpListenerConfig {
    name: String,
    address: String,
    handler: ManagedTcpListenerHandler,
}

#[derive(Clone, Debug)]
enum ManagedTcpListenerHandler {
    Http(HttpInboundConfig),
    Socks(TlsInboundConfig),
    Mixed(TlsInboundConfig),
    Tunnel(TunnelInboundConfig),
    Sudoku(SudokuInboundConfig),
    Vmess(VmessInboundConfig),
}

impl ManagedTcpListenerHandler {
    const fn kind_name(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Socks(_) => "socks",
            Self::Mixed(_) => "mixed",
            Self::Tunnel(_) => "tunnel",
            Self::Sudoku(_) => "sudoku",
            Self::Vmess(_) => "vmess",
        }
    }
}

#[derive(Clone, Debug)]
struct SudokuInboundConfig {
    base: BaseInboundConfig,
    key: String,
    aead_method: String,
    table_type: String,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: String,
    fallback: String,
    http_mask_acceptor: Option<Arc<SudokuHttpMaskServerAcceptor>>,
    tls_config: Option<Arc<ServerConfig>>,
    custom_table: String,
    custom_tables: Vec<String>,
}

#[derive(Clone, Debug)]
struct VmessInboundConfig {
    base: BaseInboundConfig,
    uuid: String,
    network: String,
    ws_path: String,
    grpc_service_name: String,
    http: mihomo_transport::HttpStreamOptions,
    h2_hosts: Vec<String>,
    h2_path: String,
    xhttp: XHttpOptions,
    xhttp_sessions: Arc<Mutex<HashMap<String, PendingVmessXhttpSession>>>,
    tls_config: Option<Arc<ServerConfig>>,
}

#[derive(Default)]
struct PendingVmessXhttpSession {
    download_stream: Option<BoxedTcpStream>,
    upload_stream: Option<BoxedTcpStream>,
    packet_up: Option<Arc<PacketUpSequenceState>>,
}

impl std::fmt::Debug for PendingVmessXhttpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingVmessXhttpSession")
            .field("has_download_stream", &self.download_stream.is_some())
            .field("has_upload_stream", &self.upload_stream.is_some())
            .field("has_packet_up_state", &self.packet_up.is_some())
            .finish()
    }
}

#[derive(Clone)]
struct SharedReadHalf(Arc<Mutex<BoxedTcpStream>>);

#[derive(Clone)]
struct SharedWriteHalf(Arc<Mutex<BoxedTcpStream>>);

struct SplitTcpStream {
    reader: SharedReadHalf,
    writer: SharedWriteHalf,
}

#[derive(Default)]
struct PacketUpSequenceInner {
    streams: HashMap<u64, BoxedTcpStream>,
    closed: bool,
}

struct PacketUpSequenceState {
    inner: Mutex<PacketUpSequenceInner>,
    ready: Condvar,
}

struct PacketUpSequenceReader {
    state: Arc<PacketUpSequenceState>,
    next_seq: u64,
    current: Option<BoxedTcpStream>,
}

impl Read for SplitTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .reader
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp reader mutex poisoned"))?;
        guard.read(buf)
    }
}

impl Write for SplitTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .writer
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .writer
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
        guard.flush()
    }
}

impl mihomo_core::TcpStream for SplitTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        let mut guard = self
            .writer
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
        guard.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        {
            let mut writer = self
                .writer
                .0
                .lock()
                .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
            writer.shutdown_write()?;
        }
        let mut reader = self
            .reader
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp reader mutex poisoned"))?;
        reader.shutdown_all()
    }
}

impl PacketUpSequenceReader {
    fn new(state: Arc<PacketUpSequenceState>) -> Self {
        Self {
            state,
            next_seq: 0,
            current: None,
        }
    }

    fn take_next_stream(&mut self) -> io::Result<Option<BoxedTcpStream>> {
        let mut guard = self.state.inner.lock().map_err(|_| {
            io::Error::other("vmess inbound xhttp packet-up sequence mutex poisoned")
        })?;
        loop {
            if let Some(stream) = guard.streams.remove(&self.next_seq) {
                self.next_seq = self
                    .next_seq
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("vmess xhttp packet-up seq overflow"))?;
                return Ok(Some(stream));
            }
            if guard.closed {
                return Ok(None);
            }
            guard = self.state.ready.wait(guard).map_err(|_| {
                io::Error::other("vmess inbound xhttp packet-up sequence mutex poisoned")
            })?;
        }
    }
}

impl Read for PacketUpSequenceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.is_none() {
                self.current = self.take_next_stream()?;
                if self.current.is_none() {
                    return Ok(0);
                }
            }
            let read = self.current.as_mut().unwrap().read(buf)?;
            if read != 0 {
                return Ok(read);
            }
            self.current = None;
        }
    }
}

impl Write for PacketUpSequenceReader {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet-up sequence reader is read-only",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl mihomo_core::TcpStream for PacketUpSequenceReader {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet-up sequence reader does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        let mut guard = self.state.inner.lock().map_err(|_| {
            io::Error::other("vmess inbound xhttp packet-up sequence mutex poisoned")
        })?;
        guard.closed = true;
        self.state.ready.notify_all();
        Ok(())
    }
}

impl VmessInboundConfig {
    fn try_from_generic(config: &GenericInboundConfig) -> Result<Self, ListenerServiceError> {
        let users = config
            .extra
            .get("users")
            .and_then(serde_yaml::Value::as_sequence)
            .ok_or_else(|| {
                ListenerServiceError::Rule("vmess listener requires users".to_owned())
            })?;
        let first_user = users.first().ok_or_else(|| {
            ListenerServiceError::Rule("vmess listener requires at least one user".to_owned())
        })?;
        let user = first_user.as_mapping().ok_or_else(|| {
            ListenerServiceError::Rule("vmess listener user entry must be a mapping".to_owned())
        })?;
        let uuid = user
            .get(serde_yaml::Value::String("uuid".to_owned()))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if uuid.is_empty() {
            return Err(ListenerServiceError::Rule(
                "vmess listener requires user uuid".to_owned(),
            ));
        }
        let network = non_empty_or(extra_string(&config.extra, "network"), "tcp");
        if network != "tcp"
            && network != "ws"
            && network != "grpc"
            && network != "http"
            && network != "h2"
            && network != "xhttp"
            && !network.is_empty()
        {
            return Err(ListenerServiceError::Rule(format!(
                "vmess listener inbound network is not implemented yet: {network}"
            )));
        }
        let ws_path = if network == "ws" {
            non_empty_or(extra_string(&config.extra, "ws-path"), "/")
        } else {
            String::new()
        };
        let grpc_service_name = if network == "grpc" {
            non_empty_or(extra_string(&config.extra, "grpc-service-name"), "GunService")
        } else {
            String::new()
        };
        let http = if network == "http" {
            let host = {
                let values = config
                    .extra
                    .get("http-opts")
                    .and_then(serde_yaml::Value::as_mapping)
                    .and_then(|mapping| mapping.get(&serde_yaml::Value::String("host".to_owned())))
                    .and_then(serde_yaml::Value::as_sequence)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(serde_yaml::Value::as_str)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if values.is_empty() {
                    let single = nested_string(&config.extra, "http-opts", "host");
                    if single.trim().is_empty() {
                        Vec::new()
                    } else {
                        vec![single]
                    }
                } else {
                    values
                }
            };
            let path = {
                let values = config
                    .extra
                    .get("http-opts")
                    .and_then(serde_yaml::Value::as_mapping)
                    .and_then(|mapping| mapping.get(&serde_yaml::Value::String("path".to_owned())))
                    .and_then(serde_yaml::Value::as_sequence)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(serde_yaml::Value::as_str)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if values.is_empty() {
                    let single = nested_string(&config.extra, "http-opts", "path");
                    if single.trim().is_empty() {
                        Vec::new()
                    } else {
                        vec![single]
                    }
                } else {
                    values
                }
            };
            mihomo_transport::HttpStreamOptions {
                method: nested_string(&config.extra, "http-opts", "method"),
                host,
                path,
                headers: nested_string_map_list(&config.extra, "http-opts", "headers"),
            }
        } else {
            mihomo_transport::HttpStreamOptions::default()
        };
        let h2_hosts = if network == "h2" {
            config
                .extra
                .get("h2-opts")
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|mapping| mapping.get(&serde_yaml::Value::String("host".to_owned())))
                .and_then(serde_yaml::Value::as_sequence)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(serde_yaml::Value::as_str)
                        .map(str::to_owned)
                        .filter(|value| !value.trim().is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let h2_path = if network == "h2" {
            config
                .extra
                .get("h2-opts")
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|mapping| mapping.get(&serde_yaml::Value::String("path".to_owned())))
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/".to_owned())
        } else {
            String::new()
        };
        let xhttp = if network == "xhttp" {
            xhttp_options(&config.extra)
        } else {
            XHttpOptions::default()
        };
        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        let tls_config = if certificate.trim().is_empty() && private_key.trim().is_empty() {
            None
        } else {
            Some(Arc::new(build_server_tls_config(
                &certificate,
                &private_key,
                &network,
                &extra_string(&config.extra, "client-auth-type"),
                &extra_string(&config.extra, "client-auth-cert"),
                &extra_string(&config.extra, "ech-key"),
                config.extra.get("reality-config").is_some(),
            )?))
        };
        Ok(Self {
            base: config.base.clone(),
            uuid,
            network,
            ws_path,
            grpc_service_name,
            http,
            h2_hosts,
            h2_path,
            xhttp,
            xhttp_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config,
        })
    }
}

fn xhttp_options(extra: &BTreeMap<String, serde_yaml::Value>) -> XHttpOptions {
    let mode = nested_string(extra, "xhttp-opts", "mode");
    let normalized_mode = if mode.trim().is_empty() || mode.trim() == "auto" {
        "packet-up".to_owned()
    } else {
        mode
    };
    XHttpOptions {
        host: nested_string(extra, "xhttp-opts", "host"),
        path: nested_string(extra, "xhttp-opts", "path"),
        mode: normalized_mode,
        headers: nested_string_map(extra, "xhttp-opts", "headers"),
        uplink_http_method: nested_string(extra, "xhttp-opts", "uplink-http-method"),
        session_placement: nested_string(extra, "xhttp-opts", "session-placement"),
        session_key: nested_string(extra, "xhttp-opts", "session-key"),
        seq_placement: nested_string(extra, "xhttp-opts", "seq-placement"),
        seq_key: nested_string(extra, "xhttp-opts", "seq-key"),
        uplink_data_placement: nested_string(extra, "xhttp-opts", "uplink-data-placement"),
        uplink_data_key: nested_string(extra, "xhttp-opts", "uplink-data-key"),
        uplink_chunk_size: nested_string(extra, "xhttp-opts", "uplink-chunk-size"),
        sc_max_each_post_bytes: nested_string(extra, "xhttp-opts", "sc-max-each-post-bytes"),
        sc_min_posts_interval_ms: nested_string(extra, "xhttp-opts", "sc-min-posts-interval-ms"),
        no_grpc_header: nested_optional_bool(extra, "xhttp-opts", "no-grpc-header")
            .unwrap_or(false),
        xpadding_bytes: nested_string(extra, "xhttp-opts", "x-padding-bytes"),
        xpadding_obfs_mode: nested_optional_bool(extra, "xhttp-opts", "x-padding-obfs-mode")
            .unwrap_or(false),
        xpadding_key: nested_string(extra, "xhttp-opts", "x-padding-key"),
        xpadding_header: nested_string(extra, "xhttp-opts", "x-padding-header"),
        xpadding_placement: nested_string(extra, "xhttp-opts", "x-padding-placement"),
        xpadding_method: nested_string(extra, "xhttp-opts", "x-padding-method"),
        has_reuse_settings: nested_value_exists(extra, "xhttp-opts", "reuse-settings"),
        has_download_settings: nested_value_exists(extra, "xhttp-opts", "download-settings"),
        download_host: doubly_nested_string(extra, "xhttp-opts", "download-settings", "host"),
        download_path: doubly_nested_string(extra, "xhttp-opts", "download-settings", "path"),
        download_headers: doubly_nested_string_map(
            extra,
            "xhttp-opts",
            "download-settings",
            "headers",
        ),
        download_server: doubly_nested_string(extra, "xhttp-opts", "download-settings", "server"),
        download_port: doubly_nested_u16(extra, "xhttp-opts", "download-settings", "port")
            .unwrap_or(0),
        has_download_port: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "port",
        ),
        download_tls: doubly_nested_bool(extra, "xhttp-opts", "download-settings", "tls")
            .unwrap_or(false),
        has_download_tls: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "tls",
        ),
        download_sni: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "servername",
        ),
        download_skip_cert_verify: doubly_nested_bool(
            extra,
            "xhttp-opts",
            "download-settings",
            "skip-cert-verify",
        )
        .unwrap_or(false),
        has_download_skip_cert_verify: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "skip-cert-verify",
        ),
        download_alpn: doubly_nested_string_list(extra, "xhttp-opts", "download-settings", "alpn"),
        download_fingerprint: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "fingerprint",
        ),
        download_certificate: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "certificate",
        ),
        download_private_key: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "private-key",
        ),
        has_download_reuse_settings: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "reuse-settings",
        ),
        has_download_transport_overrides: [
            "server",
            "port",
            "tls",
            "servername",
            "skip-cert-verify",
            "alpn",
            "fingerprint",
            "certificate",
            "private-key",
        ]
        .iter()
        .any(|key| doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", key)),
    }
}

fn normalize_xhttp_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        format!("{trimmed}/").replace("//", "/")
    } else {
        format!("/{trimmed}/")
    }
}

fn normalized_xhttp_mode(options: &XHttpOptions) -> &str {
    let mode = options.mode.trim();
    if mode.is_empty() || mode == "auto" {
        "packet-up"
    } else {
        mode
    }
}

fn normalized_xhttp_session_placement(options: &XHttpOptions) -> &str {
    let placement = options.session_placement.trim();
    if placement.is_empty() {
        "path"
    } else {
        placement
    }
}

fn normalized_xhttp_seq_placement(options: &XHttpOptions) -> &str {
    let placement = options.seq_placement.trim();
    if placement.is_empty() {
        "path"
    } else {
        placement
    }
}

fn normalized_xhttp_session_key(options: &XHttpOptions) -> String {
    let key = options.session_key.trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    match normalized_xhttp_session_placement(options) {
        "header" => "X-Session".to_owned(),
        "query" | "cookie" => "x_session".to_owned(),
        _ => String::new(),
    }
}

fn normalized_xhttp_seq_key(options: &XHttpOptions) -> String {
    let key = options.seq_key.trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    match normalized_xhttp_seq_placement(options) {
        "header" => "X-Seq".to_owned(),
        "query" | "cookie" => "x_seq".to_owned(),
        _ => String::new(),
    }
}

fn normalized_xhttp_uplink_data_placement(options: &XHttpOptions) -> &str {
    let placement = options.uplink_data_placement.trim();
    if placement.is_empty() || placement == "auto" {
        "body"
    } else {
        placement
    }
}

fn xhttp_uses_path_session(options: &XHttpOptions) -> bool {
    normalized_xhttp_session_placement(options) == "path"
}

fn xhttp_uses_path_seq(options: &XHttpOptions) -> bool {
    normalized_xhttp_seq_placement(options) == "path"
}

fn xhttp_download_authority(options: &XHttpOptions) -> &str {
    if !options.download_host.trim().is_empty() {
        &options.download_host
    } else {
        &options.host
    }
}

fn xhttp_download_path(options: &XHttpOptions) -> String {
    if !options.download_path.trim().is_empty() {
        normalize_xhttp_path(&options.download_path)
    } else {
        normalize_xhttp_path(&options.path)
    }
}

fn xhttp_download_headers(options: &XHttpOptions) -> BTreeMap<String, String> {
    if options.download_headers.is_empty() {
        options.headers.clone()
    } else {
        options.download_headers.clone()
    }
}

fn split_request_path(path: &str) -> (&str, Option<&str>) {
    if let Some((path, query)) = path.split_once('?') {
        (path, Some(query))
    } else {
        (path, None)
    }
}

fn parse_query_string(query: Option<&str>) -> BTreeMap<String, String> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

fn request_header_value(
    headers: &BTreeMap<String, String>,
    key: &str,
) -> Option<String> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
}

fn parse_cookie_header(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    request_header_value(headers, "cookie")
        .unwrap_or_default()
        .split(';')
        .filter_map(|part| {
            let trimmed = part.trim();
            let (key, value) = trimmed.split_once('=')?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

fn validate_expected_headers(
    headers: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
    label: &str,
) -> Result<(), ListenerRuntimeError> {
    for (key, expected_value) in expected {
        let actual = request_header_value(headers, key).ok_or_else(|| {
            ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing vmess xhttp {label} header: {key}"),
            ))
        })?;
        if actual != *expected_value {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess xhttp {label} header: key={key}, expected={expected_value}, got={actual}",
                ),
            )));
        }
    }
    Ok(())
}

fn take_xhttp_meta_from_request(
    headers: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
    cookies: &BTreeMap<String, String>,
    path_segments: &mut Vec<&str>,
    placement: &str,
    key: &str,
    label: &str,
) -> Result<String, ListenerRuntimeError> {
    let value = match placement {
        "path" => path_segments.first().copied().map(str::to_owned),
        "query" => query.get(key).cloned(),
        "header" => request_header_value(headers, key),
        "cookie" => cookies.get(key).cloned(),
        other => {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported vmess xhttp {label} placement: {other}"),
            )))
        }
    }
    .ok_or_else(|| {
        ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing vmess xhttp {label}"),
        ))
    })?;
    if placement == "path" {
        path_segments.remove(0);
    }
    Ok(value)
}

fn collect_xhttp_uplink_prefix(
    headers: &BTreeMap<String, String>,
    cookies: &BTreeMap<String, String>,
    options: &XHttpOptions,
) -> Result<Vec<u8>, ListenerRuntimeError> {
    let key = options.uplink_data_key.trim();
    let placement = normalized_xhttp_uplink_data_placement(options);
    let mut encoded = String::new();
    match placement {
        "body" => return Ok(Vec::new()),
        "header" => {
            for index in 0.. {
                let header_name = format!("{key}-{index}");
                let Some(chunk) = request_header_value(headers, &header_name) else {
                    break;
                };
                encoded.push_str(&chunk);
            }
        }
        "cookie" => {
            for index in 0.. {
                let cookie_name = format!("{key}_{index}");
                let Some(chunk) = cookies.get(&cookie_name) else {
                    break;
                };
                encoded.push_str(chunk);
            }
        }
        other => {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported vmess xhttp uplink-data placement: {other}"),
            )))
        }
    }
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| {
            ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid vmess xhttp uplink data: {err}"),
            ))
        })
}

fn maybe_prefix_xhttp_stream(stream: BoxedTcpStream, prefix: Vec<u8>) -> BoxedTcpStream {
    if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: stream,
        })
    }
}

impl SudokuInboundConfig {
    fn try_from_generic(config: &GenericInboundConfig) -> Result<Self, ListenerServiceError> {
        let extra = &config.extra;
        let key = extra_string(extra, "key");
        if key.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "sudoku listener requires key".to_owned(),
            ));
        }

        let nested_httpmask_disable = nested_optional_bool(extra, "httpmask", "disable");
        let nested_httpmask_mode = nested_string(extra, "httpmask", "mode");
        let nested_httpmask_path_root = nested_string(extra, "httpmask", "path-root");
        let nested_httpmask_host = nested_string(extra, "httpmask", "host");
        let nested_httpmask_tls = nested_optional_bool(extra, "httpmask", "tls").unwrap_or(false);
        let has_nested_httpmask = extra
            .get("httpmask")
            .and_then(serde_yaml::Value::as_mapping)
            .is_some();

        let http_mask_enabled = if extra_contains_key(extra, "http-mask") {
            extra_bool(extra, "http-mask")
        } else if extra_contains_key(extra, "disable-http-mask") {
            !extra_bool(extra, "disable-http-mask")
        } else if let Some(disable) = nested_httpmask_disable {
            !disable
        } else if has_nested_httpmask {
            true
        } else {
            false
        };
        let http_mask_mode = extra_string(extra, "http-mask-mode");
        let http_mask_mode = if http_mask_mode.trim().is_empty() {
            nested_httpmask_mode
        } else {
            http_mask_mode
        };
        let path_root = {
            let flat = extra_string(extra, "path-root");
            if flat.trim().is_empty() {
                nested_httpmask_path_root
            } else {
                flat
            }
        };
        let http_mask_host = {
            let flat = extra_string(extra, "http-mask-host");
            if flat.trim().is_empty() {
                nested_httpmask_host
            } else {
                flat
            }
        };
        let http_mask_tls = if extra_contains_key(extra, "http-mask-tls") {
            extra_bool(extra, "http-mask-tls")
        } else {
            nested_httpmask_tls
        };
        let http_mask_acceptor = if http_mask_enabled && !http_mask_mode.trim().is_empty() {
            SudokuHttpMaskServerAcceptor::new(
                &key,
                &http_mask_mode,
                http_mask_tls,
                &http_mask_host,
                &path_root,
                !extra_string(extra, "fallback").trim().is_empty(),
            )
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?
            .map(Arc::new)
        } else {
            None
        };
        let certificate = extra_string(extra, "certificate");
        let private_key = extra_string(extra, "private-key");
        let tls_config = if certificate.trim().is_empty() && private_key.trim().is_empty() {
            None
        } else {
            Some(Arc::new(build_server_tls_config(
                &certificate,
                &private_key,
                "",
                &extra_string(extra, "client-auth-type"),
                &extra_string(extra, "client-auth-cert"),
                &extra_string(extra, "ech-key"),
                extra.get("reality-config").is_some(),
            )?))
        };

        Ok(Self {
            base: config.base.clone(),
            key,
            aead_method: non_empty_or(extra_string(extra, "aead-method"), "chacha20-poly1305"),
            table_type: non_empty_or(extra_string(extra, "table-type"), "prefer_entropy"),
            padding_min: extra_i32(extra, "padding-min"),
            padding_max: if extra_contains_key(extra, "padding-max") {
                extra_i32(extra, "padding-max")
            } else {
                0
            },
            enable_pure_downlink: if extra_contains_key(extra, "enable-pure-downlink") {
                extra_bool(extra, "enable-pure-downlink")
            } else {
                true
            },
            http_mask_enabled,
            http_mask_mode,
            fallback: extra_string(extra, "fallback").trim().to_owned(),
            http_mask_acceptor,
            tls_config,
            custom_table: extra_string(extra, "custom-table"),
            custom_tables: extra_string_list(extra, "custom-tables"),
        })
    }
}

#[derive(Clone, Debug)]
struct ManagedUdpListenerConfig {
    name: String,
    address: String,
    config: TunnelInboundConfig,
}

impl ManagedUdpListenerConfig {
    const fn kind_name(&self) -> &'static str {
        "tunnel/udp"
    }
}

fn build_tcp_listener_configs(
    document: &RuntimeConfigDocument,
) -> Result<Vec<ManagedTcpListenerConfig>, ListenerServiceError> {
    let mut listeners = Vec::new();
    let auth_users = parse_authentication_users(&document.authentication);

    if document.port != 0 {
        let address = top_level_bind_address(document, document.port);
        listeners.push(ManagedTcpListenerConfig {
            name: "__top_level_http__".into(),
            address: address.clone(),
            handler: ManagedTcpListenerHandler::Http(HttpInboundConfig {
                base: base_from_address("__top_level_http__", &address),
                users: auth_users.clone(),
                ..HttpInboundConfig::default()
            }),
        });
    }
    if document.socks_port != 0 {
        let address = top_level_bind_address(document, document.socks_port);
        listeners.push(ManagedTcpListenerConfig {
            name: "__top_level_socks__".into(),
            address: address.clone(),
            handler: ManagedTcpListenerHandler::Socks(TlsInboundConfig {
                base: base_from_address("__top_level_socks__", &address),
                users: auth_users.clone(),
                ..TlsInboundConfig::default()
            }),
        });
    }
    if document.mixed_port != 0 {
        let address = top_level_bind_address(document, document.mixed_port);
        listeners.push(ManagedTcpListenerConfig {
            name: "__top_level_mixed__".into(),
            address: address.clone(),
            handler: ManagedTcpListenerHandler::Mixed(TlsInboundConfig {
                base: base_from_address("__top_level_mixed__", &address),
                users: auth_users,
                ..TlsInboundConfig::default()
            }),
        });
    }

    for listener in &document.listeners {
        match listener {
            InboundDefinition::Http(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Http(config.clone()),
                    });
                }
            }
            InboundDefinition::Socks(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Socks(config.clone()),
                    });
                }
            }
            InboundDefinition::Mixed(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Mixed(config.clone()),
                    });
                }
            }
            InboundDefinition::Tunnel(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Tunnel(config.clone()),
                    });
                }
            }
            InboundDefinition::Sudoku(config) => {
                let config = SudokuInboundConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Sudoku(config.clone()),
                    });
                }
            }
            InboundDefinition::Vmess(config) => {
                let config = VmessInboundConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Vmess(config.clone()),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(listeners)
}

fn build_udp_listener_configs(document: &RuntimeConfigDocument) -> Vec<ManagedUdpListenerConfig> {
    let mut listeners = Vec::new();
    for listener in &document.listeners {
        let InboundDefinition::Tunnel(config) = listener else {
            continue;
        };
        if !tunnel_network_supports_udp(&config.network) {
            continue;
        }
        for address in config.base.raw_addresses() {
            listeners.push(ManagedUdpListenerConfig {
                name: config.base.name.clone(),
                address,
                config: config.clone(),
            });
        }
    }
    listeners
}

fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
    handler: ManagedTcpListenerHandler,
    dns_runtime: Option<DnsRuntime>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let peer_addr = stream.peer_addr().ok();
                let tunnel = tunnel.clone();
                let handler = handler.clone();
                let dns_runtime = dns_runtime.clone();
                thread::spawn(move || {
                    if let Err(err) =
                        dispatch_connection(handler, tunnel, stream, peer_addr, dns_runtime)
                    {
                        let message = format!("listener dispatch error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                    }
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                let message = format!("listener accept error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                break;
            }
        }
    }
}

fn dispatch_connection(
    handler: ManagedTcpListenerHandler,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    match handler {
        ManagedTcpListenerHandler::Http(config) => {
            let _ = dispatch_http_proxy_tcp_stream_with_dialer(
                &config,
                &tunnel,
                stream,
                peer_addr,
                DnsAwareTcpDialer::new(dns_runtime),
            )?;
        }
        ManagedTcpListenerHandler::Socks(config) => {
            handle_socks5_connection(config, tunnel, stream, peer_addr, dns_runtime)?;
        }
        ManagedTcpListenerHandler::Mixed(config) => {
            handle_mixed_connection(config, tunnel, stream, peer_addr, dns_runtime)?;
        }
        ManagedTcpListenerHandler::Tunnel(config) => {
            let _ = dispatch_tunnel_tcp_stream_with_dialer(
                &config,
                &tunnel,
                stream,
                peer_addr,
                DnsAwareTcpDialer::new(dns_runtime),
            )?;
        }
        ManagedTcpListenerHandler::Sudoku(config) => {
            handle_sudoku_connection(config, tunnel, stream, peer_addr)?;
        }
        ManagedTcpListenerHandler::Vmess(config) => {
            handle_vmess_connection(config, tunnel, stream, peer_addr)?;
        }
    }
    Ok(())
}

fn handle_vmess_connection(
    config: VmessInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    if config.network != "tcp"
        && config.network != "ws"
        && config.network != "grpc"
        && config.network != "http"
        && config.network != "h2"
        && config.network != "xhttp"
        && !config.network.is_empty()
    {
        return Err(ListenerRuntimeError::Io(io::Error::other(format!(
            "vmess inbound network is not implemented yet: {}",
            config.network
        ))));
    }
    let stream: BoxedTcpStream = if config.network == "ws" {
        let stream = if let Some(tls_config) = config.tls_config.clone() {
            accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
        } else {
            Box::new(stream)
        };
        accept_websocket_server_stream(stream, &config.ws_path).map_err(ListenerRuntimeError::Io)?
    } else if config.network == "grpc" {
        let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
            mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
                .map_err(ListenerRuntimeError::Io)?
        } else {
            mihomo_transport::accept_h2_test_stream(Box::new(stream)).map_err(ListenerRuntimeError::Io)?
        };
        let expected_path = format!("/{}/Tun", config.grpc_service_name);
        if request.method != "POST" || request.path != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess grpc request: method={}, path={}",
                    request.method, request.path
                ),
            )));
        }
        mihomo_transport::accept_grpc_test_stream(stream)
    } else if config.network == "http" {
        let stream: BoxedTcpStream = if let Some(tls_config) = config.tls_config.clone() {
            accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
        } else {
            Box::new(stream)
        };
        let (request, stream) = accept_http_server_stream(stream).map_err(ListenerRuntimeError::Io)?;
        let request_line = request
            .lines()
            .next()
            .ok_or_else(|| ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing vmess http request line",
            )))?;
        let mut parts = request_line.split_whitespace();
        let actual_method = parts.next().unwrap_or_default();
        let actual_path = parts.next().unwrap_or_default();
        let method = if config.http.method.trim().is_empty() {
            "GET"
        } else {
            config.http.method.trim()
        };
        let expected_path = config
            .http
            .path
            .first()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                if value.starts_with('/') {
                    value.clone()
                } else {
                    format!("/{value}")
                }
            })
            .unwrap_or_else(|| "/".to_owned());
        let expected_host = config
            .http
            .host
            .first()
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_default();
        if actual_method != method || actual_path != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess http request: method={}, path={}",
                    actual_method, actual_path
                ),
            )));
        }
        if !expected_host.is_empty() && !request.contains(&format!("Host: {expected_host}\r\n")) {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected vmess http host: expected={expected_host}"),
            )));
        }
        for (name, values) in &config.http.headers {
            if name.eq_ignore_ascii_case("host") || values.is_empty() {
                continue;
            }
            let expected = format!("{name}: {}\r\n", values[0]);
            if !request.contains(&expected) {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected vmess http header: expected={expected:?}"),
                )));
            }
        }
        stream
    } else if config.network == "h2" {
        let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
            mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
                .map_err(ListenerRuntimeError::Io)?
        } else {
            mihomo_transport::accept_h2_test_stream(Box::new(stream)).map_err(ListenerRuntimeError::Io)?
        };
        let expected_path = if config.h2_path.trim().is_empty() {
            "/".to_owned()
        } else {
            config.h2_path.clone()
        };
        if request.method != "PUT" || request.path != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess h2 request: method={}, path={}",
                    request.method, request.path
                ),
            )));
        }
        if !config.h2_hosts.is_empty()
            && !config.h2_hosts.iter().any(|host| host == &request.authority)
        {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected vmess h2 authority: {}", request.authority),
            )));
        }
        stream
    } else if config.network == "xhttp" {
        let mode = normalized_xhttp_mode(&config.xhttp);
        if mode != "stream-one" && mode != "stream-up" && mode != "packet-up" {
            return Err(ListenerRuntimeError::Io(io::Error::other(format!(
                "vmess inbound xhttp mode is not implemented yet: {}",
                mode
            ))));
        }
        let (request, stream) = if let Some(tls_config) = config.tls_config.clone() {
            mihomo_transport::accept_h2_tls_test_stream(Box::new(stream), tls_config)
                .map_err(ListenerRuntimeError::Io)?
        } else {
            mihomo_transport::accept_h2_test_stream(Box::new(stream))
                .map_err(ListenerRuntimeError::Io)?
        };
        let expected_path = normalize_xhttp_path(&config.xhttp.path);
        let download_expected_path = xhttp_download_path(&config.xhttp);
        let upload_authority = config.xhttp.host.trim();
        let download_authority = xhttp_download_authority(&config.xhttp).trim();
        let (request_path_only, request_query) = split_request_path(&request.path);
        let request_query = parse_query_string(request_query);
        if mode == "stream-one" && request.method != "POST" {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected vmess xhttp request method: {}", request.method),
            )));
        }
        if mode == "stream-one" && request_path_only != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected vmess xhttp request path: expected={}, got={}",
                    expected_path, request.path
                ),
            )));
        }
        if mode == "stream-one" {
            if !upload_authority.is_empty() && request.authority != upload_authority {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected vmess xhttp authority: expected={}, got={}",
                        upload_authority, request.authority
                    ),
                )));
            }
            stream
        } else if mode == "stream-up" {
            if request.method != "GET" && request.method != "POST" {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected vmess xhttp stream-up request method: {}",
                        request.method
                    ),
                )));
            }
            let path_only = request_path_only;
            let query = request_query.clone();
            let cookies = parse_cookie_header(&request.headers);
            let (base_path, authority, expected_headers) = if request.method == "GET" {
                (
                    download_expected_path.as_str(),
                    download_authority,
                    xhttp_download_headers(&config.xhttp),
                )
            } else {
                (expected_path.as_str(), upload_authority, config.xhttp.headers.clone())
            };
            if !authority.is_empty() && request.authority != authority {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected vmess xhttp {} authority: expected={}, got={}",
                        request.method.to_ascii_lowercase(),
                        authority,
                        request.authority
                    ),
                )));
            }
            validate_expected_headers(
                &request.headers,
                &expected_headers,
                if request.method == "GET" { "download" } else { "upload" },
            )?;
            if !path_only.starts_with(base_path)
                || (path_only.len() <= base_path.len() && xhttp_uses_path_session(&config.xhttp))
            {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected vmess xhttp stream-up request path: base={}, got={}",
                            base_path, request.path
                    ),
                )));
            }
            let mut path_segments = path_only[base_path.len()..]
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>();
            let session_id = take_xhttp_meta_from_request(
                &request.headers,
                &query,
                &cookies,
                &mut path_segments,
                normalized_xhttp_session_placement(&config.xhttp),
                &normalized_xhttp_session_key(&config.xhttp),
                "session id",
            )?;
            if !path_segments.is_empty() {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected vmess xhttp stream-up extra path segments: {}",
                        path_segments.join("/")
                    ),
                )));
            }
            let paired = {
                let mut sessions = config
                    .xhttp_sessions
                    .lock()
                    .map_err(|_| {
                        ListenerRuntimeError::Io(io::Error::other(
                            "vmess inbound xhttp session map poisoned",
                        ))
                    })?;
                let session = sessions.entry(session_id.clone()).or_default();
                let slot = if request.method == "GET" {
                    &mut session.download_stream
                } else {
                    &mut session.upload_stream
                };
                if slot.is_some() {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "duplicate vmess xhttp {} stream for session {}",
                            request.method, session_id
                        ),
                    )));
                }
                *slot = Some(stream);
                if session.download_stream.is_some() && session.upload_stream.is_some() {
                    let download = session.download_stream.take().unwrap();
                    let upload = session.upload_stream.take().unwrap();
                    sessions.remove(&session_id);
                    Some(Box::new(SplitTcpStream {
                        reader: SharedReadHalf(Arc::new(Mutex::new(upload))),
                        writer: SharedWriteHalf(Arc::new(Mutex::new(download))),
                    }) as BoxedTcpStream)
                } else {
                    None
                }
            };
            let Some(stream) = paired else {
                return Ok(());
            };
            stream
        } else {
            if request.method != "GET" && request.method != "POST" {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected vmess xhttp packet-up request method: {}",
                        request.method
                    ),
                )));
            }
            let path_only = request_path_only;
            let query = request_query;
            let cookies = parse_cookie_header(&request.headers);
            if request.method == "GET" {
                if !download_authority.is_empty() && request.authority != download_authority {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected vmess xhttp packet-up download authority: expected={}, got={}",
                            download_authority, request.authority
                        ),
                    )));
                }
                validate_expected_headers(
                    &request.headers,
                    &xhttp_download_headers(&config.xhttp),
                    "download",
                )?;
                if !path_only.starts_with(&download_expected_path)
                    || (path_only.len() <= download_expected_path.len()
                        && xhttp_uses_path_session(&config.xhttp))
                {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected vmess xhttp packet-up download path: base={}, got={}",
                            download_expected_path, request.path
                        ),
                    )));
                }
                let mut path_segments = path_only[download_expected_path.len()..]
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .collect::<Vec<_>>();
                let session_id = take_xhttp_meta_from_request(
                    &request.headers,
                    &query,
                    &cookies,
                    &mut path_segments,
                    normalized_xhttp_session_placement(&config.xhttp),
                    &normalized_xhttp_session_key(&config.xhttp),
                    "session id",
                )?;
                if !path_segments.is_empty() {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected vmess xhttp packet-up download extra path segments: {}",
                            path_segments.join("/")
                        ),
                    )));
                }
                let maybe_stream = {
                    let mut sessions = config
                        .xhttp_sessions
                        .lock()
                        .map_err(|_| {
                            ListenerRuntimeError::Io(io::Error::other(
                                "vmess inbound xhttp session map poisoned",
                            ))
                        })?;
                    let session = sessions.entry(session_id.clone()).or_default();
                    if session.download_stream.is_some() {
                        return Err(ListenerRuntimeError::Io(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "duplicate vmess xhttp packet-up download stream for session {}",
                                session_id
                            ),
                        )));
                    }
                    session.download_stream = Some(stream);
                    let packet_up = Arc::clone(
                        session
                            .packet_up
                            .get_or_insert_with(|| {
                                Arc::new(PacketUpSequenceState {
                                    inner: Mutex::new(PacketUpSequenceInner::default()),
                                    ready: Condvar::new(),
                                })
                            }),
                    );
                    let has_seq0 = packet_up
                        .inner
                        .lock()
                        .map_err(|_| {
                            ListenerRuntimeError::Io(io::Error::other(
                                "vmess inbound xhttp packet-up sequence mutex poisoned",
                            ))
                        })?
                        .streams
                        .contains_key(&0);
                    if has_seq0 {
                        let download = session.download_stream.take().unwrap();
                        session.packet_up = None;
                        sessions.remove(&session_id);
                        Some(Box::new(SplitTcpStream {
                            reader: SharedReadHalf(Arc::new(Mutex::new(Box::new(
                                PacketUpSequenceReader::new(packet_up),
                            )))),
                            writer: SharedWriteHalf(Arc::new(Mutex::new(download))),
                        }) as BoxedTcpStream)
                    } else {
                        None
                    }
                };
                let Some(stream) = maybe_stream else {
                    return Ok(());
                };
                stream
            } else {
                if !upload_authority.is_empty() && request.authority != upload_authority {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected vmess xhttp packet-up upload authority: expected={}, got={}",
                            upload_authority, request.authority
                        ),
                    )));
                }
                validate_expected_headers(&request.headers, &config.xhttp.headers, "upload")?;
                if !path_only.starts_with(&expected_path)
                    || (path_only.len() <= expected_path.len()
                        && (xhttp_uses_path_session(&config.xhttp)
                            || xhttp_uses_path_seq(&config.xhttp)))
                {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected vmess xhttp packet-up upload path: base={}, got={}",
                            expected_path, request.path
                        ),
                    )));
                }
                let mut path_segments = path_only[expected_path.len()..]
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .collect::<Vec<_>>();
                let session_id = take_xhttp_meta_from_request(
                    &request.headers,
                    &query,
                    &cookies,
                    &mut path_segments,
                    normalized_xhttp_session_placement(&config.xhttp),
                    &normalized_xhttp_session_key(&config.xhttp),
                    "session id",
                )?;
                let seq = take_xhttp_meta_from_request(
                    &request.headers,
                    &query,
                    &cookies,
                    &mut path_segments,
                    normalized_xhttp_seq_placement(&config.xhttp),
                    &normalized_xhttp_seq_key(&config.xhttp),
                    "seq",
                )?;
                if !path_segments.is_empty() {
                    return Err(ListenerRuntimeError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected vmess xhttp packet-up upload extra path segments: {}",
                            path_segments.join("/")
                        ),
                    )));
                }
                let prefix = collect_xhttp_uplink_prefix(&request.headers, &cookies, &config.xhttp)?;
                let stream = maybe_prefix_xhttp_stream(stream, prefix);
                let maybe_stream = {
                    let mut sessions = config
                        .xhttp_sessions
                        .lock()
                        .map_err(|_| {
                            ListenerRuntimeError::Io(io::Error::other(
                                "vmess inbound xhttp session map poisoned",
                            ))
                        })?;
                    let session = sessions.entry(session_id.to_owned()).or_default();
                    let seq = seq.parse::<u64>().map_err(|err| {
                        ListenerRuntimeError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid vmess xhttp packet-up seq {seq}: {err}"),
                        ))
                    })?;
                    let packet_up = Arc::clone(
                        session
                            .packet_up
                            .get_or_insert_with(|| {
                                Arc::new(PacketUpSequenceState {
                                    inner: Mutex::new(PacketUpSequenceInner::default()),
                                    ready: Condvar::new(),
                                })
                            }),
                    );
                    {
                        let mut packet_guard = packet_up.inner.lock().map_err(|_| {
                            ListenerRuntimeError::Io(io::Error::other(
                                "vmess inbound xhttp packet-up sequence mutex poisoned",
                            ))
                        })?;
                        if packet_guard.streams.contains_key(&seq) {
                            return Err(ListenerRuntimeError::Io(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                format!(
                                    "duplicate vmess xhttp packet-up upload stream for session {} seq {}",
                                    session_id, seq
                                ),
                            )));
                        }
                        packet_guard.streams.insert(seq, stream);
                    }
                    packet_up.ready.notify_all();
                    if seq == 0 && session.download_stream.is_some() {
                        let download = session.download_stream.take().unwrap();
                        session.packet_up = None;
                        sessions.remove(&session_id);
                        Some(Box::new(SplitTcpStream {
                            reader: SharedReadHalf(Arc::new(Mutex::new(Box::new(
                                PacketUpSequenceReader::new(packet_up),
                            )))),
                            writer: SharedWriteHalf(Arc::new(Mutex::new(download))),
                        }) as BoxedTcpStream)
                    } else {
                        None
                    }
                };
                let Some(stream) = maybe_stream else {
                    return Ok(());
                };
                stream
            }
        }
    } else if let Some(tls_config) = config.tls_config.clone() {
        accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
    } else {
        Box::new(stream)
    };
    match accept_vmess_stream(stream, &config.uuid)
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?
    {
        VmessAcceptedStream::Tcp { target, stream } => {
            let mut metadata = Metadata {
                network: NetworkKind::Tcp,
                kind: SessionKind::Vmess,
                inbound_name: config.base.name.clone(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                ..Metadata::default()
            };
            if let Some(peer) = peer_addr {
                metadata.src_ip = Some(peer.ip());
                metadata.src_port = Some(peer.port());
            }
            metadata
                .set_remote_address(&target)
                .map_err(ListenerRuntimeError::from)?;
            let mut context = ConnectionContext::new(stream, metadata);
            tunnel
                .forward_tcp_context_with_system_dialer(&mut context)
                .map_err(ListenerRuntimeError::from)?;
            Ok(())
        }
        VmessAcceptedStream::Udp { target, stream } => {
            let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let stream = Arc::new(Mutex::new(stream));
            let packet_addr =
                target == format!("{}:{}", mihomo_transport::PACKETADDR_MAGIC_HOST, mihomo_transport::PACKETADDR_MAGIC_PORT);
            loop {
                let (source, payload) = {
                    let mut guard = stream
                        .lock()
                        .map_err(|_| ListenerRuntimeError::Io(io::Error::other("vmess inbound udp stream mutex poisoned")))?;
                    let payload = read_vmess_udp_packet(&mut **guard).map_err(ListenerRuntimeError::Io)?;
                    if payload.is_empty() {
                        return Ok(());
                    }
                    if packet_addr {
                        decode_packetaddr_udp_packet(&payload).map_err(|err| {
                            ListenerRuntimeError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                err.to_string(),
                            ))
                        })?
                    } else {
                        let source = target.parse::<SocketAddr>().map_err(|err| {
                            ListenerRuntimeError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid vmess inbound udp target {target}: {err}"),
                            ))
                        })?;
                        (source, payload)
                    }
                };

                let packet = Arc::new(VmessStreamBackedUdpPacket {
                    payload: ByteWindow::freeze(payload),
                    local_addr,
                    peer_addr,
                    outbound_source: source,
                    stream: Arc::clone(&stream),
                    packet_addr,
                });
                let mut metadata = Metadata {
                    network: NetworkKind::Udp,
                    kind: SessionKind::Vmess,
                    inbound_name: config.base.name.clone(),
                    special_proxy: config.base.special_proxy.clone(),
                    special_rules: config.base.special_rules.clone(),
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
        VmessAcceptedStream::Xudp { stream, .. } => {
            let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let stream = Arc::new(Mutex::new(stream));
            loop {
                let (source, payload) = {
                    let mut guard = stream
                        .lock()
                        .map_err(|_| ListenerRuntimeError::Io(io::Error::other("vmess inbound xudp stream mutex poisoned")))?;
                    match read_vmess_xudp_packet(&mut **guard) {
                        Ok(packet) => packet,
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::BrokenPipe
                            ) =>
                        {
                            return Ok(());
                        }
                        Err(err) => return Err(ListenerRuntimeError::Io(err)),
                    }
                };

                let packet = Arc::new(VmessStreamBackedXudpPacket {
                    payload: ByteWindow::freeze(payload),
                    local_addr,
                    peer_addr,
                    outbound_source: source,
                    stream: Arc::clone(&stream),
                });
                let mut metadata = Metadata {
                    network: NetworkKind::Udp,
                    kind: SessionKind::Vmess,
                    inbound_name: config.base.name.clone(),
                    special_proxy: config.base.special_proxy.clone(),
                    special_rules: config.base.special_rules.clone(),
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
    }
}

fn websocket_accept_key(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

struct ServerWebsocketStream {
    inner: BoxedTcpStream,
    pending: Vec<u8>,
    offset: usize,
}

struct ServerTlsStream(StreamOwned<ServerConnection, TcpStream>);

struct PrefixedTcpStream {
    prefix: io::Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
}

impl ServerWebsocketStream {
    fn new(inner: BoxedTcpStream) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            offset: 0,
        }
    }

    fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut header = [0_u8; 2];
        match self.inner.read_exact(&mut header) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
        let fin = header[0] & 0x80 != 0;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut len = u64::from(header[1] & 0x7f);
        if len == 126 {
            let mut ext = [0_u8; 2];
            self.inner.read_exact(&mut ext)?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0_u8; 8];
            self.inner.read_exact(&mut ext)?;
            len = u64::from_be_bytes(ext);
        }
        let mask = if masked {
            let mut mask = [0_u8; 4];
            self.inner.read_exact(&mut mask)?;
            Some(mask)
        } else {
            None
        };
        let mut payload = vec![0_u8; len as usize];
        self.inner.read_exact(&mut payload)?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            0x1 | 0x2 => {
                if !fin {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fragmented websocket frames are unsupported",
                    ));
                }
                Ok(Some(payload))
            }
            0x8 => Ok(None),
            0x9 => {
                self.write_frame(0xA, &payload)?;
                Ok(Some(Vec::new()))
            }
            0xA => Ok(Some(Vec::new())),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected websocket opcode {other}"),
            )),
        }
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut header = Vec::with_capacity(10);
        header.push(0x80 | (opcode & 0x0f));
        if payload.len() < 126 {
            header.push(payload.len() as u8);
        } else if payload.len() < 65_536 {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        self.inner.write_all(&header)?;
        self.inner.write_all(payload)?;
        self.inner.flush()
    }
}

impl Read for ServerWebsocketStream {
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
        loop {
            let Some(frame) = self.read_frame()? else {
                return Ok(0);
            };
            if frame.is_empty() {
                continue;
            }
            let copied = frame.len().min(buf.len());
            buf[..copied].copy_from_slice(&frame[..copied]);
            if copied < frame.len() {
                self.pending = frame;
                self.offset = copied;
            }
            return Ok(copied);
        }
    }
}

impl Write for ServerWebsocketStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_frame(0x2, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Read for ServerTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for ServerTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl mihomo_core::TcpStream for ServerTlsStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "server tls stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.0.conn.send_close_notify();
        self.0.flush()?;
        self.0.sock.shutdown(std::net::Shutdown::Write)
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.0.conn.send_close_notify();
        self.0.flush()?;
        self.0.sock.shutdown(std::net::Shutdown::Both)
    }
}

impl mihomo_core::TcpStream for ServerWebsocketStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self::new(self.inner.try_clone_box()?)))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

impl Read for PrefixedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.inner.read(buf)
    }
}

impl Write for PrefixedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl mihomo_core::TcpStream for PrefixedTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prefixed websocket stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

fn normalize_ws_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn resolve_pem_source(raw: &str) -> io::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains("-----BEGIN ") {
        return Ok(raw.to_owned());
    }
    fs::read_to_string(trimmed)
}

fn parse_certificates(pem: &str) -> io::Result<Vec<Certificate>> {
    if pem.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls certificate is required when private key is set",
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse tls certificate",
        ));
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn parse_private_key(pem: &str) -> io::Result<PrivateKey> {
    if pem.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls private key is required when certificate is set",
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }

    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "failed to parse tls private key",
    ))
}

fn build_server_tls_config(
    certificate: &str,
    private_key: &str,
    network: &str,
    client_auth_type: &str,
    client_auth_cert: &str,
    ech_key: &str,
    has_reality_config: bool,
) -> Result<ServerConfig, ListenerServiceError> {
    let client_auth_type = client_auth_type.trim();
    let require_client_auth = match client_auth_type {
        "" => false,
        "request" | "require" | "verify" => true,
        other => {
            return Err(ListenerServiceError::Rule(format!(
                "unsupported vmess listener client-auth-type: {other}"
            )))
        }
    };
    if require_client_auth && client_auth_cert.trim().is_empty() {
        return Err(ListenerServiceError::Rule(
            "vmess listener client-auth-cert is required when client-auth-type is set".to_owned(),
        ));
    }
    if !require_client_auth && !client_auth_cert.trim().is_empty() {
        return Err(ListenerServiceError::Rule(
            "vmess listener client-auth-type is required when client-auth-cert is set".to_owned(),
        ));
    }
    if !ech_key.trim().is_empty() {
        return Err(ListenerServiceError::Rule(
            "vmess listener inbound ech is not implemented yet".to_owned(),
        ));
    }
    if has_reality_config {
        return Err(ListenerServiceError::Rule(
            "vmess listener inbound reality is not implemented yet".to_owned(),
        ));
    }

    let cert_pem = resolve_pem_source(certificate)?;
    let key_pem = resolve_pem_source(private_key)?;
    let certs = parse_certificates(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;
    let mut config = if require_client_auth {
        let client_auth_pem = resolve_pem_source(client_auth_cert)?;
        let client_auth_certs = parse_certificates(&client_auth_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in client_auth_certs {
            roots
                .add(&cert)
                .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
        }
        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(certs, key)
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?
    } else {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?
    };
    if network == "grpc" {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Ok(config)
}

fn accept_tls_server_stream(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
) -> io::Result<BoxedTcpStream> {
    let conn = ServerConnection::new(tls_config)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(Box::new(ServerTlsStream(StreamOwned::new(conn, stream))))
}

fn read_http_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(err)
                if buffer.is_empty()
                    && matches!(
                        err.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ) =>
            {
                return Ok((String::new(), Vec::new()));
            }
            Err(err) => return Err(err),
        };
        if read == 0 {
            if buffer.is_empty() {
                return Ok((String::new(), Vec::new()));
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http request closed before headers completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return Ok((
                String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
                buffer[header_end..].to_vec(),
            ));
        }
    }
}

fn accept_websocket_server_stream(
    mut stream: BoxedTcpStream,
    expected_path: &str,
) -> io::Result<BoxedTcpStream> {
    let (request, tail) = read_http_headers_with_tail(&mut *stream)?;
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing websocket request line"))?;
    let request_target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing websocket request target"))?;
    let request_path = request_target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(request_target);
    let expected_path = normalize_ws_path(expected_path);
    if request_path != expected_path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected websocket request line: {request_line}"),
        ));
    }

    let key = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                Some(value.trim().to_owned())
            } else {
                None
            }
        });
    let early_data = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
                Some(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(value.trim())
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string())),
                )
            } else {
                None
            }
        })
        .transpose()?
        .unwrap_or_default();

    let response = if let Some(key) = key {
        let accept = websocket_accept_key(&key);
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
    } else {
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_owned()
    };
    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    if request
        .lines()
        .any(|line| line.starts_with("Sec-WebSocket-Key:"))
    {
        let inner: BoxedTcpStream = if tail.is_empty() {
            Box::new(ServerWebsocketStream::new(stream))
        } else {
            Box::new(ServerWebsocketStream::new(Box::new(PrefixedTcpStream {
                prefix: io::Cursor::new(tail),
                inner: stream,
            })))
        };
        if early_data.is_empty() {
            Ok(inner)
        } else {
            Ok(Box::new(PrefixedTcpStream {
                prefix: io::Cursor::new(early_data),
                inner,
            }))
        }
    } else {
        let mut prefix = early_data;
        prefix.extend_from_slice(&tail);
        if prefix.is_empty() {
            Ok(stream)
        } else {
            Ok(Box::new(PrefixedTcpStream {
                prefix: io::Cursor::new(prefix),
                inner: stream,
            }))
        }
    }
}

fn accept_http_server_stream(
    mut stream: BoxedTcpStream,
) -> io::Result<(String, BoxedTcpStream)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http stream closed before request headers completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let request = String::from_utf8(buffer[..header_end].to_vec())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let mut content_length = 0usize;
    for line in request.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.trim().parse::<usize>().map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid Content-Length: {err}"))
            })?;
        }
    }
    let mut prefix = buffer[header_end..].to_vec();
    if prefix.len() < content_length {
        let mut rest = vec![0_u8; content_length - prefix.len()];
        stream.read_exact(&mut rest)?;
        prefix.extend_from_slice(&rest);
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
    stream.flush()?;
    Ok((
        request,
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: stream,
        }),
    ))
}

fn handle_sudoku_connection(
    config: SudokuInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let stream: BoxedTcpStream = if config.http_mask_enabled && !config.http_mask_mode.trim().is_empty() {
        if let Some(tls_config) = config.tls_config.clone() {
            accept_tls_server_stream(stream, tls_config).map_err(ListenerRuntimeError::Io)?
        } else {
            Box::new(stream)
        }
    } else {
        Box::new(stream)
    };
    let maybe_accept = if config.custom_table.trim().is_empty() && config.custom_tables.is_empty() {
        if config.http_mask_enabled && !config.http_mask_mode.trim().is_empty() {
            accept_sudoku_stream_with_http_mask(
                stream,
                config.http_mask_acceptor.as_ref().expect("http-mask acceptor missing"),
                &config.key,
                &config.aead_method,
                &config.table_type,
                config.padding_min,
                config.padding_max,
                config.enable_pure_downlink,
                false,
            )
        } else {
            let accepted: Result<SudokuInboundAccept, TransportError> = if config.fallback.is_empty() {
                accept_sudoku_stream(
                    stream,
                    &config.key,
                    &config.aead_method,
                    &config.table_type,
                    config.padding_min,
                    config.padding_max,
                    config.enable_pure_downlink,
                    config.http_mask_enabled,
                )
                .map(SudokuInboundAccept::Session)
            } else {
                accept_sudoku_stream_allow_suspicious(
                    stream,
                    &config.key,
                    &config.aead_method,
                    &config.table_type,
                    config.padding_min,
                    config.padding_max,
                    config.enable_pure_downlink,
                    config.http_mask_enabled,
                )
            };
            accepted.map(Some)
        }
    } else {
        if config.http_mask_enabled && !config.http_mask_mode.trim().is_empty() {
            accept_sudoku_stream_with_custom_tables_and_http_mask(
                stream,
                config.http_mask_acceptor.as_ref().expect("http-mask acceptor missing"),
                &config.key,
                &config.aead_method,
                &config.table_type,
                config.padding_min,
                config.padding_max,
                config.enable_pure_downlink,
                false,
                &config.custom_table,
                &config.custom_tables,
            )
        } else {
            let accepted: Result<SudokuInboundAccept, TransportError> = if config.fallback.is_empty() {
                accept_sudoku_stream_with_custom_tables(
                    stream,
                    &config.key,
                    &config.aead_method,
                    &config.table_type,
                    config.padding_min,
                    config.padding_max,
                    config.enable_pure_downlink,
                    config.http_mask_enabled,
                    &config.custom_table,
                    &config.custom_tables,
                )
                .map(SudokuInboundAccept::Session)
            } else {
                accept_sudoku_stream_with_custom_tables_allow_suspicious(
                    stream,
                    &config.key,
                    &config.aead_method,
                    &config.table_type,
                    config.padding_min,
                    config.padding_max,
                    config.enable_pure_downlink,
                    config.http_mask_enabled,
                    &config.custom_table,
                    &config.custom_tables,
                )
            };
            accepted.map(Some)
        }
    };
    let maybe_accept =
        maybe_accept.map_err(|err| ListenerRuntimeError::Io(io::Error::new(io::ErrorKind::Other, err)))?;
    let Some(accept) = maybe_accept else {
        return Ok(());
    };

    let session = match accept {
        SudokuInboundAccept::Session(session) => session,
        SudokuInboundAccept::PassThrough(stream) => {
            if config.fallback.is_empty() {
                return Ok(());
            }
            return forward_sudoku_fallback(stream, &config, tunnel, peer_addr);
        }
        SudokuInboundAccept::Rejected(stream) => {
            if config.fallback.is_empty() {
                return Ok(());
            }
            return forward_sudoku_fallback(stream, &config, tunnel, peer_addr);
        }
    };

    match session {
        SudokuAcceptedStream::Tcp { target, stream } => {
            let mut metadata = Metadata {
                network: NetworkKind::Tcp,
                kind: SessionKind::Sudoku,
                inbound_name: config.base.name.clone(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                ..Metadata::default()
            };
            if let Some(peer) = peer_addr {
                metadata.src_ip = Some(peer.ip());
                metadata.src_port = Some(peer.port());
            }
            metadata
                .set_remote_address(&target)
                .map_err(ListenerRuntimeError::from)?;
            let mut context = ConnectionContext::new(stream, metadata);
            tunnel
                .forward_tcp_context_with_system_dialer(&mut context)
                .map_err(ListenerRuntimeError::from)?;
            Ok(())
        }
        SudokuAcceptedStream::Multiplex { server } => {
            loop {
                let (stream, target) = match server.accept_tcp() {
                    Ok(accepted) => accepted,
                    Err(err) if matches!(err.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) => {
                        return Ok(());
                    }
                    Err(err) => return Err(ListenerRuntimeError::Io(err)),
                };
                let tunnel = tunnel.clone();
                let inbound_name = config.base.name.clone();
                let special_proxy = config.base.special_proxy.clone();
                let special_rules = config.base.special_rules.clone();
                let peer = peer_addr;
                thread::spawn(move || {
                    let mut metadata = Metadata {
                        network: NetworkKind::Tcp,
                        kind: SessionKind::Sudoku,
                        inbound_name,
                        special_proxy,
                        special_rules,
                        ..Metadata::default()
                    };
                    if let Some(peer) = peer {
                        metadata.src_ip = Some(peer.ip());
                        metadata.src_port = Some(peer.port());
                    }
                    if metadata.set_remote_address(&target).is_err() {
                        return;
                    }
                    let mut context = ConnectionContext::new(stream, metadata);
                    let _ = tunnel.forward_tcp_context_with_system_dialer(&mut context);
                });
            }
        }
        SudokuAcceptedStream::Udp { stream } => {
            let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let peer_addr = peer_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let stream = Arc::new(Mutex::new(stream));
            loop {
                let (source, payload) = {
                    let mut guard = stream
                        .lock()
                        .map_err(|_| ListenerRuntimeError::Io(io::Error::other("sudoku udp inbound stream mutex poisoned")))?;
                    match read_sudoku_udp_packet(&mut **guard) {
                        Ok(packet) => packet,
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                        Err(err) => return Err(ListenerRuntimeError::Io(err)),
                    }
                };

                let packet = Arc::new(StreamBackedUdpPacket {
                    payload: ByteWindow::freeze(payload),
                    local_addr,
                    peer_addr,
                    outbound_source: source,
                    stream: Arc::clone(&stream),
                });
                let mut metadata = Metadata {
                    network: NetworkKind::Udp,
                    kind: SessionKind::Sudoku,
                    inbound_name: config.base.name.clone(),
                    special_proxy: config.base.special_proxy.clone(),
                    special_rules: config.base.special_rules.clone(),
                    src_ip: Some(peer_addr.ip()),
                    src_port: Some(peer_addr.port()),
                    ..Metadata::default()
                };
                metadata
                    .set_remote_address(&source.to_string())
                    .map_err(ListenerRuntimeError::from)?;
                let envelope = PacketEnvelope::new(packet, metadata);
                let mut udp_session = SystemUdpSession::new(tunnel.clone(), None)
                    .map_err(ListenerRuntimeError::Io)?;
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
    }
}

fn forward_sudoku_fallback(
    stream: BoxedTcpStream,
    config: &SudokuInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::Inner,
        inbound_name: config.base.name.clone(),
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata
        .set_remote_address(&config.fallback)
        .map_err(ListenerRuntimeError::from)?;
    let mut context = ConnectionContext::new(stream, metadata);
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)?;
    Ok(())
}

fn handle_mixed_connection(
    config: TlsInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    let mut first = [0_u8; 1];
    let peeked = stream.peek(&mut first).map_err(ListenerRuntimeError::Io)?;
    if peeked == 0 {
        return Ok(());
    }
    if first[0] == 0x05 {
        handle_socks5_connection(config, tunnel, stream, peer_addr, dns_runtime)
    } else {
        let http_config = http_config_from_tls_config(&config);
        let _ = dispatch_http_proxy_tcp_stream_with_dialer(
            &http_config,
            &tunnel,
            stream,
            peer_addr,
            DnsAwareTcpDialer::new(dns_runtime),
        )?;
        Ok(())
    }
}

fn handle_socks5_connection(
    config: TlsInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    match prepare_socks5_dispatch(&config, stream, peer_addr)? {
        PreparedSocks5Dispatch::Connect(mut context) => {
            let _ = dispatch_prepared_socks5_tcp_context_with_dialer(
                &tunnel,
                &mut context,
                DnsAwareTcpDialer::new(dns_runtime),
            )?;
        }
        PreparedSocks5Dispatch::UdpAssociate(associate) => {
            handle_socks5_udp_associate(config, tunnel, associate, dns_runtime)?;
        }
    }
    Ok(())
}

fn extra_string(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> String {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn nested_string(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> String {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn nested_string_map(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> BTreeMap<String, String> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str()?.to_owned(), value.as_str()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn nested_string_map_list(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> BTreeMap<String, Vec<String>> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(name, value)| {
                    let name = name.as_str()?.to_owned();
                    let values = if let Some(text) = value.as_str() {
                        vec![text.to_owned()]
                    } else {
                        value
                            .as_sequence()
                            .map(|sequence| {
                                sequence
                                    .iter()
                                    .filter_map(serde_yaml::Value::as_str)
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    };
                    Some((name, values))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn nested_optional_bool(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> Option<bool> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_bool)
}

fn nested_value_exists(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> bool {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|mapping| mapping.contains_key(&serde_yaml::Value::String(key.to_owned())))
}

fn extra_contains_key(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> bool {
    extra.contains_key(key)
}

fn extra_bool(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> bool {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
}

fn extra_i32(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> i32 {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or_default()
}

fn extra_string_list(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> Vec<String> {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_sequence)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_string(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> String {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn doubly_nested_u16(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> Option<u16> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_i64)
        .and_then(|value| u16::try_from(value).ok())
}

fn doubly_nested_bool(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> Option<bool> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_bool)
}

fn doubly_nested_string_map(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> BTreeMap<String, String> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str()?.to_owned(), value.as_str()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_string_list(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> Vec<String> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_value_exists(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> bool {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|mapping| mapping.contains_key(&serde_yaml::Value::String(key.to_owned())))
}

fn non_empty_or(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

fn udp_loop(
    socket: UdpSocket,
    shutdown: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
    listener: ManagedUdpListenerConfig,
    dns_runtime: Option<DnsRuntime>,
) {
    let socket = Arc::new(socket);
    while !shutdown.load(Ordering::Relaxed) {
        let mut buf = [0_u8; 64 * 1024];
        match socket.recv_from(&mut buf) {
            Ok((read, peer_addr)) => {
                let payload = buf[..read].to_vec();
                let socket = Arc::clone(&socket);
                let tunnel = Arc::clone(&tunnel);
                let listener = listener.clone();
                let dns_runtime = dns_runtime.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_udp_packet(
                        socket,
                        peer_addr,
                        payload,
                        tunnel,
                        listener,
                        dns_runtime,
                    ) {
                        let message = format!("udp listener error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                let message = format!("udp listener recv error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                break;
            }
        }
    }
}

fn dns_loop(socket: UdpSocket, shutdown: Arc<AtomicBool>, runtime: Arc<Mutex<DnsRuntime>>) {
    while !shutdown.load(Ordering::Relaxed) {
        let mut buf = [0_u8; 1500];
        match socket.recv_from(&mut buf) {
            Ok((read, peer_addr)) => {
                let response = {
                    let mut runtime = runtime.lock().unwrap();
                    runtime.handle_query_packet_via_system(&buf[..read])
                };
                match response {
                    Ok(Some(response)) => {
                        let _ = socket.send_to(&response, peer_addr);
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let message = format!("dns listener error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                let message = format!("dns listener recv error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                break;
            }
        }
    }
}

fn handle_socks5_udp_associate(
    config: TlsInboundConfig,
    tunnel: Arc<RuntimeTunnel>,
    mut associate: PreparedSocks5UdpAssociate,
    dns_runtime: Option<DnsRuntime>,
) -> Result<(), ListenerRuntimeError> {
    if !config.udp {
        return Err(ListenerRuntimeError::SocksUnsupportedCommand(0x03));
    }

    let udp_socket = UdpSocket::bind(bind_ephemeral(&config.base.listen))?;
    udp_socket.set_nonblocking(true)?;
    let bind_addr = udp_socket.local_addr()?;
    write_socks5_udp_associate_reply(&mut *associate.stream, bind_addr)?;

    let stop = Arc::new(AtomicBool::new(false));
    let udp_socket = Arc::new(udp_socket);
    let tunnel_for_loop = Arc::clone(&tunnel);
    let stop_for_loop = Arc::clone(&stop);
    let dns_runtime_for_loop = dns_runtime.clone();
    let inbound_name = associate.inbound_name.clone();
    let special_proxy = associate.special_proxy.clone();
    let special_rules = associate.special_rules.clone();
    let inbound_user = associate.inbound_user.clone();
    let udp_worker = thread::spawn(move || {
        socks_udp_loop(
            udp_socket,
            stop_for_loop,
            tunnel_for_loop,
            inbound_name,
            inbound_user,
            special_proxy,
            special_rules,
            dns_runtime_for_loop,
        );
    });

    let mut buf = [0_u8; 1];
    loop {
        match associate.stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = udp_worker.join();
    Ok(())
}

fn socks_udp_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    tunnel: Arc<RuntimeTunnel>,
    inbound_name: String,
    inbound_user: String,
    special_proxy: String,
    special_rules: String,
    dns_runtime: Option<DnsRuntime>,
) {
    let fragments = Arc::new(Mutex::new(HashMap::<SocketAddr, Socks5UdpReassembly>::new()));
    while !stop.load(Ordering::Relaxed) {
        let mut buf = [0_u8; 64 * 1024];
        match socket.recv_from(&mut buf) {
            Ok((read, peer_addr)) => {
                let payload = buf[..read].to_vec();
                let socket = Arc::clone(&socket);
                let tunnel = Arc::clone(&tunnel);
                let dns_runtime = dns_runtime.clone();
                let inbound_name = inbound_name.clone();
                let inbound_user = inbound_user.clone();
                let special_proxy = special_proxy.clone();
                let special_rules = special_rules.clone();
                let fragments = Arc::clone(&fragments);
                thread::spawn(move || {
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
                        let message = format!("socks udp relay error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
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
    let Some((target, body)) =
        reassemble_socks5_udp_frame(&mut fragments, peer_addr, frame)?
    else {
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

fn handle_udp_packet(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    payload: Vec<u8>,
    tunnel: Arc<RuntimeTunnel>,
    listener: ManagedUdpListenerConfig,
    dns_runtime: Option<DnsRuntime>,
) -> io::Result<()> {
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
        inbound_name: listener.config.base.name.clone(),
        special_proxy: listener.config.base.special_proxy.clone(),
        special_rules: listener.config.base.special_rules.clone(),
        src_ip: Some(peer_addr.ip()),
        src_port: Some(peer_addr.port()),
        ..Metadata::default()
    };
    metadata
        .set_remote_address(&listener.config.target)
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

fn tunnel_network_supports_udp(networks: &[String]) -> bool {
    if networks.is_empty() {
        return true;
    }
    networks.iter().any(|network| {
        let network = network.trim().to_ascii_lowercase();
        network == "udp" || network == "all"
    })
}

fn parse_authentication_users(values: &[String]) -> Vec<AuthUser> {
    values
        .iter()
        .filter_map(|value| {
            let (username, password) = value.split_once(':')?;
            Some(AuthUser {
                username: username.to_owned(),
                password: password.to_owned(),
            })
        })
        .collect()
}

fn top_level_bind_address(document: &RuntimeConfigDocument, port: u16) -> String {
    if document.allow_lan {
        if document.bind_address == "*" {
            format!(":{port}")
        } else {
            format!("{}:{port}", document.bind_address)
        }
    } else {
        format!("127.0.0.1:{port}")
    }
}

fn base_from_address(name: &str, address: &str) -> BaseInboundConfig {
    let (listen, port) = address.rsplit_once(':').unwrap_or((address, "0"));
    BaseInboundConfig {
        name: name.to_owned(),
        listen: listen.to_owned(),
        port: port.to_owned(),
        ..BaseInboundConfig::default()
    }
}

fn bind_ephemeral(host: &str) -> String {
    if host.is_empty() {
        "0.0.0.0:0".to_owned()
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:0")
    } else {
        format!("{host}:0")
    }
}

fn http_config_from_tls_config(config: &TlsInboundConfig) -> HttpInboundConfig {
    HttpInboundConfig {
        base: config.base.clone(),
        users: config.users.clone(),
        certificate: config.certificate.clone(),
        private_key: config.private_key.clone(),
        client_auth_type: config.client_auth_type.clone(),
        client_auth_cert: config.client_auth_cert.clone(),
        ech_key: config.ech_key.clone(),
        reality_config: config.reality_config.clone(),
        extra: config.extra.clone(),
    }
}

struct SocketBackedUdpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    socket: Arc<UdpSocket>,
}

struct StreamBackedUdpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    outbound_source: SocketAddr,
    stream: Arc<Mutex<BoxedTcpStream>>,
}

struct VmessStreamBackedUdpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    outbound_source: SocketAddr,
    stream: Arc<Mutex<BoxedTcpStream>>,
    packet_addr: bool,
}

struct VmessStreamBackedXudpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    outbound_source: SocketAddr,
    stream: Arc<Mutex<BoxedTcpStream>>,
}

struct SocksUdpPacket {
    payload: ByteWindow,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    socket: Arc<UdpSocket>,
}

impl WriteBack for SocksUdpPacket {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        let Some(source) = source else {
            return self.socket.send_to(payload.as_slice(), self.peer_addr);
        };
        let framed = build_socks5_udp_frame(source, payload.as_slice());
        self.socket.send_to(&framed, self.peer_addr)
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

struct SystemUdpSession {
    socket: UdpSocket,
    tunnel: Arc<RuntimeTunnel>,
    dns_runtime: Option<DnsRuntime>,
    prepared_route: Option<PreparedUdpRoute>,
    proxy_control: Option<BoxedTcpStream>,
    proxy_stream: Option<BoxedTcpStream>,
    pending_response: Option<(Vec<u8>, SocketAddr)>,
}

impl SystemUdpSession {
    fn new(tunnel: Arc<RuntimeTunnel>, dns_runtime: Option<DnsRuntime>) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        socket.set_write_timeout(Some(Duration::from_secs(1)))?;
        Ok(Self {
            socket,
            tunnel,
            dns_runtime,
            prepared_route: None,
            proxy_control: None,
            proxy_stream: None,
            pending_response: None,
        })
    }

    fn recv_once(&mut self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        if let Some(response) = self.pending_response.take() {
            return Ok(Some(response));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::Snell)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing snell udp stream")
            })?;
            let (source, payload) = read_snell_udp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::AnyTls)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing anytls udp stream")
            })?;
            let (source, payload) = read_anytls_udp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::Trojan)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing trojan udp stream")
            })?;
            let (source, payload) = read_trojan_udp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::TrustTunnel)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing trusttunnel udp stream")
            })?;
            let (source, payload) = read_trusttunnel_udp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::Sudoku)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing sudoku udp stream")
            })?;
            let (source, payload) = read_sudoku_udp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if let Some(PreparedUdpRoute::Vless { source }) = &self.prepared_route {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing vless udp stream")
            })?;
            let payload = read_vless_udp_packet(&mut **stream)?;
            return Ok(Some((payload, *source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::VlessXudp)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing vless xudp stream")
            })?;
            let (source, payload) = read_vless_xudp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::VlessPacketAddr)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing vless packet-addr udp stream")
            })?;
            let payload = read_vless_udp_packet(&mut **stream)?;
            let (source, packet) = decode_packetaddr_udp_packet(&payload)?;
            return Ok(Some((packet, source)));
        }
        if let Some(PreparedUdpRoute::Vmess { source }) = &self.prepared_route {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing vmess udp stream")
            })?;
            let payload = read_vmess_udp_packet(&mut **stream)?;
            return Ok(Some((payload, *source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::VmessXudp)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing vmess xudp stream")
            })?;
            let (source, payload) = read_vmess_xudp_packet(&mut **stream)?;
            return Ok(Some((payload, source)));
        }
        if matches!(self.prepared_route, Some(PreparedUdpRoute::VmessPacketAddr)) {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing vmess packet-addr udp stream")
            })?;
            let payload = read_vmess_udp_packet(&mut **stream)?;
            let (source, packet) = decode_packetaddr_udp_packet(&payload)?;
            return Ok(Some((packet, source)));
        }
        if let Some(PreparedUdpRoute::GostRelay { source }) = &self.prepared_route {
            let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "missing gost relay udp stream")
            })?;
            let payload = read_gost_relay_udp_packet(&mut **stream)?;
            return Ok(Some((payload, *source)));
        }

        let mut buf = [0_u8; 64 * 1024];
        match self.socket.recv_from(&mut buf) {
            Ok((read, remote)) => {
                match &self.prepared_route {
                    Some(PreparedUdpRoute::Socks5 { .. }) => {
                        let (source, payload) =
                            parse_socks5_udp_source_frame(&buf[..read], self.dns_runtime.as_mut())?;
                        Ok(Some((payload, source)))
                    }
                    Some(PreparedUdpRoute::ShadowSocks { cipher, password, .. }) => {
                        let (source, payload) =
                            decode_shadowsocks_udp_packet(cipher, password, &buf[..read])
                                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                        Ok(Some((payload, source)))
                    }
                    Some(PreparedUdpRoute::Ssr { cipher, password, .. }) => {
                        let (source, payload) =
                            decode_ssr_udp_packet(cipher, password, &buf[..read])?;
                        Ok(Some((payload, source)))
                    }
                    Some(PreparedUdpRoute::Dns) => unreachable!("dns udp replies are returned from pending response"),
                    Some(PreparedUdpRoute::AnyTls) => unreachable!("anytls udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::Trojan) => unreachable!("trojan udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::TrustTunnel) => {
                        unreachable!("trusttunnel udp replies are read from tcp stream")
                    }
                    Some(PreparedUdpRoute::Sudoku) => unreachable!("sudoku udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::Vless { .. }) => unreachable!("vless udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::VlessXudp) => unreachable!("vless xudp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::VlessPacketAddr) => unreachable!("vless packet-addr udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::Vmess { .. }) => unreachable!("vmess udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::VmessXudp) => unreachable!("vmess xudp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::VmessPacketAddr) => unreachable!("vmess packet-addr udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::GostRelay { .. }) => {
                        unreachable!("gost relay udp replies are read from tcp stream")
                    }
                    Some(PreparedUdpRoute::Snell) => unreachable!("snell udp replies are read from tcp stream"),
                    Some(PreparedUdpRoute::Direct) | None => Ok(Some((buf[..read].to_vec(), remote))),
                }
            }
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

impl UdpSession for SystemUdpSession {
    fn prepare_send(&mut self, metadata: &mut Metadata) -> io::Result<()> {
        let route = self
            .tunnel
            .resolve_udp_outbound(metadata)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        match route {
            UdpOutboundRoute::Direct => {
                self.prepared_route = Some(PreparedUdpRoute::Direct);
                self.proxy_control = None;
                self.proxy_stream = None;
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Dns => {
                self.prepared_route = Some(PreparedUdpRoute::Dns);
                self.proxy_control = None;
                self.proxy_stream = None;
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Socks5(route) => {
                let (control, relay_addr) =
                    socks5_udp_associate(&self.socket, &route, self.dns_runtime.as_mut())?;
                self.prepared_route = Some(PreparedUdpRoute::Socks5 { relay_addr });
                self.proxy_control = Some(control);
                self.proxy_stream = None;
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::ShadowSocks(route) => {
                let proxy_addr = resolve_udp_proxy_server_addr(
                    route.server.as_str(),
                    route.port,
                    self.dns_runtime.as_mut(),
                )?;
                self.prepared_route = Some(PreparedUdpRoute::ShadowSocks {
                    proxy_addr,
                    cipher: route.cipher,
                    password: route.password,
                });
                self.proxy_control = None;
                self.proxy_stream = None;
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Ssr(route) => {
                let proxy_addr = resolve_udp_proxy_server_addr(
                    route.server.as_str(),
                    route.port,
                    self.dns_runtime.as_mut(),
                )?;
                self.prepared_route = Some(PreparedUdpRoute::Ssr {
                    proxy_addr,
                    cipher: route.cipher,
                    password: route.password,
                });
                self.proxy_control = None;
                self.proxy_stream = None;
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::AnyTls(route) => {
                let target = metadata.destination_socket_addr().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved")
                })?;
                let stream = connect_anytls_udp_stream(
                    &route,
                    self.tunnel.as_ref(),
                    target,
                    self.dns_runtime.as_mut(),
                )?;
                self.prepared_route = Some(PreparedUdpRoute::AnyTls);
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Snell(route) => {
                let stream =
                    connect_snell_udp_stream(&route, self.tunnel.as_ref(), self.dns_runtime.as_mut())?;
                self.prepared_route = Some(PreparedUdpRoute::Snell);
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Trojan(route) => {
                let target = metadata.destination_socket_addr().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved")
                })?;
                let stream = connect_trojan_udp_stream(
                    &route,
                    self.tunnel.as_ref(),
                    target,
                    self.dns_runtime.as_mut(),
                )?;
                self.prepared_route = Some(PreparedUdpRoute::Trojan);
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::TrustTunnel(route) => {
                let stream =
                    connect_trusttunnel_udp_stream(&route, self.tunnel.as_ref(), self.dns_runtime.as_mut())?;
                self.prepared_route = Some(PreparedUdpRoute::TrustTunnel);
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Sudoku(route) => {
                let stream =
                    connect_sudoku_udp_stream(&route, self.tunnel.as_ref(), self.dns_runtime.as_mut())?;
                self.prepared_route = Some(PreparedUdpRoute::Sudoku);
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Vless(route) => {
                let target = metadata.destination_socket_addr().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved")
                })?;
                let stream =
                    connect_vless_udp_stream(&route, self.tunnel.as_ref(), target, self.dns_runtime.as_mut())?;
                self.prepared_route = Some(if route.xudp {
                    PreparedUdpRoute::VlessXudp
                } else if route.packet_addr {
                    PreparedUdpRoute::VlessPacketAddr
                } else {
                    PreparedUdpRoute::Vless { source: target }
                });
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Vmess(route) => {
                let target = metadata.destination_socket_addr().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved")
                })?;
                let stream =
                    connect_vmess_udp_stream(&route, self.tunnel.as_ref(), target, self.dns_runtime.as_mut())?;
                self.prepared_route = Some(if route.xudp {
                    PreparedUdpRoute::VmessXudp
                } else if route.packet_addr {
                    PreparedUdpRoute::VmessPacketAddr
                } else {
                    PreparedUdpRoute::Vmess { source: target }
                });
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::GostRelay(route) => {
                let target = metadata.destination_socket_addr().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "destination unresolved")
                })?;
                let stream = connect_gost_relay_udp_stream(
                    &route,
                    self.tunnel.as_ref(),
                    target,
                    self.dns_runtime.as_mut(),
                )?;
                self.prepared_route = Some(PreparedUdpRoute::GostRelay { source: target });
                self.proxy_control = None;
                self.proxy_stream = Some(stream);
                self.pending_response = None;
                Ok(())
            }
            UdpOutboundRoute::Unsupported(message) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                message,
            )),
        }
    }

    fn resolve_udp(&mut self, metadata: &mut Metadata) -> io::Result<()> {
        if let Some(dns_runtime) = &mut self.dns_runtime {
            dns_runtime
                .resolve_metadata(metadata)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            if metadata.dst_ip.is_some() {
                return Ok(());
            }
        }
        let Some(host) = metadata.host.clone() else {
            return Ok(());
        };
        let port = metadata.dst_port.unwrap_or(0);
        let mut addrs = (host.as_str(), port).to_socket_addrs()?;
        if let Some(addr) = addrs.next() {
            metadata.dst_ip = Some(addr.ip());
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to resolve host: {host}"),
            ))
        }
    }

    fn send_to(&mut self, payload: ByteWindow, target: SocketAddr) -> io::Result<usize> {
        match &self.prepared_route {
            Some(PreparedUdpRoute::Direct) | None => self.socket.send_to(payload.as_slice(), target),
            Some(PreparedUdpRoute::Dns) => {
                let runtime = self.dns_runtime.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "dns runtime is unavailable")
                })?;
                let response = runtime
                    .relay_query_packet_via_system(payload.as_slice())
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                self.pending_response = response.map(|packet| (packet, target));
                Ok(payload.len())
            }
            Some(PreparedUdpRoute::Socks5 { relay_addr }) => {
                let framed = build_socks5_udp_frame(target, payload.as_slice());
                self.socket.send_to(&framed, relay_addr)
            }
            Some(PreparedUdpRoute::ShadowSocks {
                proxy_addr,
                cipher,
                password,
            }) => {
                let packet = encode_shadowsocks_udp_packet(cipher, password, target, payload.as_slice())
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                self.socket.send_to(&packet, proxy_addr)
            }
            Some(PreparedUdpRoute::Ssr {
                proxy_addr,
                cipher,
                password,
            }) => {
                let packet = encode_ssr_udp_packet(cipher, password, target, payload.as_slice())
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                self.socket.send_to(&packet, proxy_addr)
            }
            Some(PreparedUdpRoute::AnyTls) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing anytls udp stream")
                })?;
                write_anytls_udp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::Snell) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing snell udp stream")
                })?;
                write_snell_udp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::Trojan) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing trojan udp stream")
                })?;
                write_trojan_udp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::TrustTunnel) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing trusttunnel udp stream")
                })?;
                write_trusttunnel_udp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::Sudoku) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing sudoku udp stream")
                })?;
                write_sudoku_udp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::Vless { .. }) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing vless udp stream")
                })?;
                write_vless_udp_packet(&mut **stream, payload.as_slice())
            }
            Some(PreparedUdpRoute::VlessXudp) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing vless xudp stream")
                })?;
                write_vless_xudp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::VlessPacketAddr) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing vless packet-addr udp stream")
                })?;
                let framed = encode_packetaddr_udp_packet(target, payload.as_slice());
                write_vless_udp_packet(&mut **stream, &framed)
            }
            Some(PreparedUdpRoute::Vmess { .. }) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing vmess udp stream")
                })?;
                write_vmess_udp_packet(&mut **stream, payload.as_slice())
            }
            Some(PreparedUdpRoute::VmessXudp) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing vmess xudp stream")
                })?;
                write_vmess_xudp_packet(&mut **stream, target, payload.as_slice())
            }
            Some(PreparedUdpRoute::VmessPacketAddr) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing vmess packet-addr udp stream")
                })?;
                let framed = encode_packetaddr_udp_packet(target, payload.as_slice());
                write_vmess_udp_packet(&mut **stream, &framed)
            }
            Some(PreparedUdpRoute::GostRelay { .. }) => {
                let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "missing gost relay udp stream")
                })?;
                write_gost_relay_udp_packet(&mut **stream, payload.as_slice())
            }
        }
    }
}

enum PreparedUdpRoute {
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
    Snell,
    Trojan,
    TrustTunnel,
    Sudoku,
    Vless { source: SocketAddr },
    VlessXudp,
    VlessPacketAddr,
    Vmess { source: SocketAddr },
    VmessXudp,
    VmessPacketAddr,
    GostRelay { source: SocketAddr },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Socks5UdpFrame {
    target: String,
    payload: Vec<u8>,
    fragment_index: u8,
    final_fragment: bool,
}

#[derive(Clone, Debug)]
struct Socks5UdpReassembly {
    target: String,
    highest_seen: u8,
    final_index: Option<u8>,
    parts: BTreeMap<u8, Vec<u8>>,
    updated_at: Instant,
}

fn parse_socks5_udp_frame(payload: &[u8]) -> io::Result<Socks5UdpFrame> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp frame too short",
        ));
    }
    if payload[0] != 0 || payload[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp reserved bytes must be zero",
        ));
    }
    let frag = payload[2];
    let fragment_index = frag & 0x7f;
    let final_fragment = (frag & 0x80) != 0;
    if frag != 0 && fragment_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp fragment index must be non-zero",
        ));
    }
    let atyp = payload[3];
    let mut offset = 4;
    let host = match atyp {
        0x01 => {
            if offset + 4 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv4 target truncated"));
            }
            let addr = std::net::Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            );
            offset += 4;
            addr.to_string()
        }
        0x03 => {
            let length = *payload
                .get(offset)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "domain length missing"))?
                as usize;
            offset += 1;
            if offset + length > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain target truncated"));
            }
            let host = String::from_utf8_lossy(&payload[offset..offset + length]).into_owned();
            offset += length;
            host
        }
        0x04 => {
            if offset + 16 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv6 target truncated"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported socks5 udp address type",
            ))
        }
    };
    if offset + 2 > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target port truncated",
        ));
    }
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok(Socks5UdpFrame {
        target: format_target(host.as_str(), port),
        payload: payload[offset..].to_vec(),
        fragment_index,
        final_fragment,
    })
}

fn reassemble_socks5_udp_frame(
    states: &mut HashMap<SocketAddr, Socks5UdpReassembly>,
    peer_addr: SocketAddr,
    frame: Socks5UdpFrame,
) -> io::Result<Option<(String, Vec<u8>)>> {
    let now = Instant::now();
    states.retain(|_, state| now.duration_since(state.updated_at) <= Duration::from_secs(5));

    if frame.fragment_index == 0 {
        states.remove(&peer_addr);
        return Ok(Some((frame.target, frame.payload)));
    }

    let state = states.entry(peer_addr).or_insert_with(|| Socks5UdpReassembly {
        target: frame.target.clone(),
        highest_seen: 0,
        final_index: None,
        parts: BTreeMap::new(),
        updated_at: now,
    });

    // UDP fragment arrival can be reordered on the receive loop. Only reset when the
    // target changes, or when a new first fragment clearly starts a fresh sequence.
    if state.target != frame.target
        || (frame.fragment_index == 1 && state.parts.contains_key(&1))
    {
        *state = Socks5UdpReassembly {
            target: frame.target.clone(),
            highest_seen: 0,
            final_index: None,
            parts: BTreeMap::new(),
            updated_at: now,
        };
    }

    state.updated_at = now;
    state.highest_seen = state.highest_seen.max(frame.fragment_index);
    if frame.final_fragment {
        state.final_index = Some(frame.fragment_index);
    }
    state.parts.insert(frame.fragment_index, frame.payload);

    let Some(final_index) = state.final_index else {
        return Ok(None);
    };
    for expected in 1..=final_index {
        if !state.parts.contains_key(&expected) {
            return Ok(None);
        }
    }

    let mut payload = Vec::new();
    for expected in 1..=final_index {
        if let Some(part) = state.parts.get(&expected) {
            payload.extend_from_slice(part);
        }
    }
    let target = state.target.clone();
    states.remove(&peer_addr);
    Ok(Some((target, payload)))
}

fn parse_socks5_udp_source_frame(
    payload: &[u8],
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    if payload.len() < 4 {
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
            if offset + 4 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv4 source truncated"));
            }
            let addr = std::net::Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            );
            offset += 4;
            std::net::IpAddr::V4(addr)
        }
        0x04 => {
            if offset + 16 > payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv6 source truncated"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        0x03 => {
            let length = *payload
                .get(offset)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "domain length missing"))?
                as usize;
            offset += 1;
            if offset + length > payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain source truncated",
                ));
            }
            let host = String::from_utf8_lossy(&payload[offset..offset + length]).into_owned();
            offset += length;
            resolve_host_to_ipaddr(host.as_str(), dns_runtime.as_deref_mut())?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported socks5 udp source address type",
            ))
        }
    };
    if offset + 2 > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 udp source port truncated",
        ));
    }
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok((SocketAddr::new(addr, port), payload[offset..].to_vec()))
}

fn build_socks5_udp_frame(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut framed = vec![0x00, 0x00, 0x00];
    match source {
        SocketAddr::V4(addr) => {
            framed.push(0x01);
            framed.extend_from_slice(&addr.ip().octets());
            framed.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            framed.push(0x04);
            framed.extend_from_slice(&addr.ip().octets());
            framed.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    framed.extend_from_slice(payload);
    framed
}

fn socks5_udp_associate(
    udp_socket: &UdpSocket,
    route: &UdpSocks5Route,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<(BoxedTcpStream, SocketAddr)> {
    let mut dns_runtime = dns_runtime;
    let proxy_addr = resolve_proxy_server_addr(route, dns_runtime.as_deref_mut())?;
    let stream = TcpStream::connect(proxy_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut stream: BoxedTcpStream = if route.tls.enabled {
        wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new(route.server.clone(), route.port),
            &route.tls,
            &[],
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        Box::new(stream)
    };
    let wants_auth = !route.username.is_empty();
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;

    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply)?;
    if method_reply[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected socks5 auth reply version",
        ));
    }
    if wants_auth {
        if method_reply[1] != 0x02 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5 proxy refused username/password auth",
            ));
        }
        let username = route.username.as_bytes();
        let password = route.password.as_bytes();
        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.push(0x01);
        auth.push(username.len() as u8);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream.write_all(&auth)?;
        stream.flush()?;
        let mut auth_reply = [0_u8; 2];
        stream.read_exact(&mut auth_reply)?;
        if auth_reply != [0x01, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5 username/password auth failed",
            ));
        }
    } else if method_reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 proxy refused no-auth method",
        ));
    }

    let local_addr = udp_socket.local_addr()?;
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
    let relay_addr = read_socks5_udp_associate_target(&mut *stream, dns_runtime.as_deref_mut())?;
    Ok((stream, relay_addr))
}

fn resolve_proxy_server_addr(
    route: &UdpSocks5Route,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<SocketAddr> {
    resolve_udp_proxy_server_addr(route.server.as_str(), route.port, dns_runtime)
}

fn resolve_udp_proxy_server_addr(
    server: &str,
    port: u16,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<SocketAddr> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(runtime) = dns_runtime.as_mut() {
        match runtime.resolve_proxy_server_host_via_system(server) {
            Ok(Some(ip)) => return Ok(SocketAddr::new(ip, port)),
            Ok(None) => {}
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
            }
        }
    }

    let mut addrs = (server, port).to_socket_addrs()?;
    addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to resolve proxy server: {server}"),
        )
    })
}

fn connect_udp_dialer_proxy_stream(
    tunnel: &RuntimeTunnel,
    dialer_proxy: Option<&str>,
    server: &str,
    port: u16,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    if let Some(dialer_proxy) = dialer_proxy.filter(|value| !value.is_empty()) {
        let metadata = Metadata {
            special_proxy: dialer_proxy.to_owned(),
            host: Some(server.to_owned()),
            dst_port: Some(port),
            ..Metadata::default()
        };
        return tunnel
            .connect_tcp_with_system_dialer(&metadata)
            .map(|(stream, _)| stream)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }

    let proxy_addr = resolve_udp_proxy_server_addr(server, port, dns_runtime)?;
    let stream = TcpStream::connect(proxy_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    Ok(Box::new(stream))
}

fn connect_snell_udp_stream(
    route: &UdpSnellRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    wrap_snell_udp_stream(
        stream,
        &route.psk,
        route.version,
        &route.obfs_mode,
        &route.obfs_host,
        route.port,
    )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

fn connect_anytls_udp_stream(
    route: &UdpAnyTlsRoute,
    tunnel: &RuntimeTunnel,
    target: SocketAddr,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    let stream: BoxedTcpStream = wrap_tls_proxy_stream(
        stream,
        TransportTarget::new(route.server.clone(), route.port),
        &route.tls,
        &route.alpn,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    open_anytls_udp_stream(stream, &route.password, target)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

fn connect_trojan_udp_stream(
    route: &UdpTrojanRoute,
    tunnel: &RuntimeTunnel,
    target: SocketAddr,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    let proxy = TransportTarget::new(route.server.clone(), route.port);
    let websocket_alpn = vec!["http/1.1".to_owned()];
    let mut websocket = route.websocket.clone();
    let tls = route.tls.clone();
    let has_host = websocket
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("host"));
    if !tls.sni.trim().is_empty() && !has_host {
        websocket.headers.insert("Host".to_owned(), tls.sni.clone());
    }
    if route.network == "grpc" {
        let stream: BoxedTcpStream = if route.tls.enabled {
            wrap_grpc_tls_proxy_stream(stream, proxy.clone(), &tls, &route.grpc)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            wrap_grpc_proxy_stream(stream, proxy.clone(), &route.grpc)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        };
        return open_trojan_udp_stream(
            stream,
            &route.password,
            &route.shadowsocks,
            proxy,
            TransportTarget::new(target.ip().to_string(), target.port()),
            &mihomo_transport::TlsOptions::default(),
            &[],
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    let stream: BoxedTcpStream = if route.tls.enabled {
        wrap_tls_proxy_stream(
            stream,
            proxy.clone(),
            &tls,
            if route.network == "ws" { &websocket_alpn } else { &route.alpn },
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        stream
    };
    let stream = if route.network == "ws" {
        wrap_websocket_proxy_stream(stream, proxy.clone(), &websocket)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else if route.network == "http" {
        wrap_http_proxy_stream(stream, proxy.clone(), &route.http)
    } else {
        stream
    };
    open_trojan_udp_stream(
        stream,
        &route.password,
        &route.shadowsocks,
        proxy,
        TransportTarget::new(target.ip().to_string(), target.port()),
        &mihomo_transport::TlsOptions::default(),
        &[],
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

fn connect_trusttunnel_udp_stream(
    route: &UdpTrustTunnelRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    if route.quic {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "trusttunnel quic udp is not implemented",
        ));
    }
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    open_trusttunnel_udp_stream(
        stream,
        TransportTarget::new(route.server.clone(), route.port),
        &route.tls,
        &route.alpn,
        &route.username,
        &route.password,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

fn connect_sudoku_udp_stream(
    route: &UdpSudokuRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    open_sudoku_udp_stream(
        stream,
        &mihomo_transport::TransportTarget::new(route.server.as_str(), route.port),
        &route.key,
        &route.aead_method,
        &route.table_type,
        route.padding_min,
        route.padding_max,
        route.enable_pure_downlink,
        route.http_mask_enabled,
        &route.http_mask_mode,
        route.http_mask_tls,
        &route.http_mask_host,
        &route.path_root,
        &route.custom_table,
        &route.custom_tables,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

#[cfg(test)]
pub(crate) fn connect_sudoku_udp_stream_for_tests(
    route: &UdpSudokuRoute,
    tunnel: &RuntimeTunnel,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    connect_sudoku_udp_stream(route, tunnel, dns_runtime)
}

#[cfg(test)]
pub(crate) fn exercise_sudoku_udp_route_for_tests(
    tunnel: Arc<RuntimeTunnel>,
    metadata: &mut Metadata,
    payload: ByteWindow,
    target: SocketAddr,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut session = SystemUdpSession::new(tunnel, None)?;
    session.prepare_send(metadata)?;
    session.send_to(payload, target)?;
    session.recv_once()
}

#[cfg(test)]
pub(crate) fn exercise_sudoku_udp_write_back_for_tests(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    tunnel: Arc<RuntimeTunnel>,
    special_proxy: &str,
    target: &str,
    dns_runtime: Option<DnsRuntime>,
    payload: Vec<u8>,
) -> io::Result<()> {
    let listener = ManagedUdpListenerConfig {
        name: "edge-udp".into(),
        address: "127.0.0.1:0".into(),
        config: TunnelInboundConfig {
            base: BaseInboundConfig {
                name: "edge-udp".into(),
                listen: "127.0.0.1".into(),
                port: "0".into(),
                special_rules: String::new(),
                special_proxy: special_proxy.to_owned(),
            },
            target: target.to_owned(),
            network: vec!["udp".into()],
            extra: BTreeMap::new(),
        },
    };
    handle_udp_packet(socket, peer_addr, payload, tunnel, listener, dns_runtime)
}


fn connect_vless_udp_stream(
    route: &UdpVlessRoute,
    tunnel: &RuntimeTunnel,
    target: SocketAddr,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    let websocket_alpn = vec!["http/1.1".to_owned()];
    let grpc_alpn = vec!["h2".to_owned()];
    let h2_alpn = vec!["h2".to_owned()];
    let websocket = route.websocket.clone();
    let mut tls = route.tls.clone();
    if tls.enabled && tls.sni.trim().is_empty() {
        if let Some((_, host)) = websocket
            .headers
            .iter()
            .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.trim().is_empty())
        {
            tls.sni = host.clone();
        }
    }
    let mut stream: BoxedTcpStream = if route.tls.enabled {
        if route.network == "xhttp" {
            wrap_xhttp_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                &route.alpn,
                &route.xhttp,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            wrap_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                if route.network == "ws" {
                    &websocket_alpn
                } else if route.network == "grpc" {
                    &grpc_alpn
                } else if route.network == "h2" {
                    &h2_alpn
                } else {
                    &route.alpn
                },
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        }
    } else {
        stream
    };
    if route.network == "ws" {
        stream = wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &websocket,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "grpc" {
        stream = wrap_grpc_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.grpc,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "http" {
        stream = wrap_http_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.http,
        );
    } else if route.network == "h2" {
        stream = wrap_h2_proxy_stream(stream, &route.h2)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "xhttp" && !route.tls.enabled {
        stream = wrap_xhttp_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.xhttp,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    }
    if route.xudp {
        open_vless_xudp_stream(stream, &route.uuid)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else if route.packet_addr {
        open_vless_packetaddr_udp_stream(stream, &route.uuid)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else {
        open_vless_udp_stream(stream, &route.uuid, target)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

fn connect_vmess_udp_stream(
    route: &UdpVmessRoute,
    tunnel: &RuntimeTunnel,
    target: SocketAddr,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    let websocket_alpn = vec!["http/1.1".to_owned()];
    let grpc_alpn = vec!["h2".to_owned()];
    let h2_alpn = vec!["h2".to_owned()];
    let websocket = route.websocket.clone();
    let mut tls = route.tls.clone();
    if tls.enabled && tls.sni.trim().is_empty() {
        if let Some((_, host)) = websocket
            .headers
            .iter()
            .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.trim().is_empty())
        {
            tls.sni = host.clone();
        }
    }
    let mut stream: BoxedTcpStream = if route.tls.enabled {
        if route.network == "xhttp" {
            wrap_xhttp_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                &route.alpn,
                &route.xhttp,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        } else {
            wrap_tls_proxy_stream(
                stream,
                TransportTarget::new(route.server.clone(), route.port),
                &tls,
                if route.network == "ws" {
                    &websocket_alpn
                } else if route.network == "grpc" {
                    &grpc_alpn
                } else if route.network == "h2" {
                    &h2_alpn
                } else {
                    &route.alpn
                },
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        }
    } else {
        stream
    };
    if route.network == "ws" {
        stream = wrap_websocket_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &websocket,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "grpc" {
        stream = wrap_grpc_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.grpc,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "http" {
        stream = wrap_http_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.http,
        );
    } else if route.network == "h2" {
        stream = wrap_h2_proxy_stream(stream, &route.h2)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    } else if route.network == "xhttp" && !route.tls.enabled {
        stream = wrap_xhttp_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.xhttp,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    }
    if route.xudp {
        open_vmess_xudp_stream(
            stream,
            &route.uuid,
            route.alter_id,
            &route.cipher,
            route.global_padding,
            route.authenticated_length,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else if route.packet_addr {
        open_vmess_packetaddr_udp_stream(
            stream,
            &route.uuid,
            route.alter_id,
            &route.cipher,
            route.global_padding,
            route.authenticated_length,
        )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    } else {
        open_vmess_udp_stream(
            stream,
            &route.uuid,
            route.alter_id,
            &route.cipher,
            route.global_padding,
            route.authenticated_length,
            target,
        )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

fn connect_gost_relay_udp_stream(
    route: &UdpGostRelayRoute,
    tunnel: &RuntimeTunnel,
    target: SocketAddr,
    dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<BoxedTcpStream> {
    let stream = connect_udp_dialer_proxy_stream(
        tunnel,
        route.dialer_proxy.as_deref(),
        route.server.as_str(),
        route.port,
        dns_runtime,
    )?;
    let stream: BoxedTcpStream = if route.tls.enabled {
        wrap_tls_proxy_stream(
            stream,
            TransportTarget::new(route.server.clone(), route.port),
            &route.tls,
            &[],
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        stream
    };
    let stream = if route.mux {
        wrap_smux_stream(stream)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
    } else {
        stream
    };
    let auth = if route.username.is_empty() {
        None
    } else {
        Some(mihomo_transport::BasicAuth {
            username: route.username.clone(),
            password: route.password.clone(),
        })
    };
    open_gost_relay_udp_stream(stream, auth, route.forward, target)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

fn read_socks5_udp_associate_target(
    stream: &mut dyn Read,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<SocketAddr> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 || header[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks5 udp associate failed",
        ));
    }
    match header[3] {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream.read_exact(&mut addr)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    addr[0], addr[1], addr[2], addr[3],
                )),
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream.read_exact(&mut addr)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                u16::from_be_bytes(port),
            ))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut host = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut host)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port)?;
            let host = String::from_utf8_lossy(&host).into_owned();
            let port = u16::from_be_bytes(port);
            let ip = resolve_proxy_host_to_ipaddr(host.as_str(), dns_runtime.as_deref_mut())?;
            Ok(SocketAddr::new(ip, port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported socks5 udp relay address type",
        )),
    }
}

fn resolve_host_to_ipaddr(
    host: &str,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(runtime) = dns_runtime.as_mut() {
        match runtime.resolve_host_via_system(host) {
            Ok(Some(ip)) => return Ok(ip),
            Ok(None) => {}
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
            }
        }
    }
    let mut addrs = (host, 0).to_socket_addrs()?;
    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host unresolved"))
}

fn resolve_proxy_host_to_ipaddr(
    host: &str,
    mut dns_runtime: Option<&mut DnsRuntime>,
) -> io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(runtime) = dns_runtime.as_mut() {
        match runtime.resolve_proxy_server_host_via_system(host) {
            Ok(Some(ip)) => return Ok(ip),
            Ok(None) => {}
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
            }
        }
    }
    let mut addrs = (host, 0).to_socket_addrs()?;
    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "proxy host unresolved"))
}

fn format_target(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
