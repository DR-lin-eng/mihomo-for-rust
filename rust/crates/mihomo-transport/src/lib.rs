mod anytls;
mod grpc_stream;
mod h2_stream;
mod http_stream;
mod simple_obfs;
mod smux_stream;
mod ssr;
mod ssr_http_obfs;
#[cfg(feature = "ssh-transport")]
mod ssh;
mod shadowsocks;
mod snell;
mod sudoku;
mod sudoku_httpmask;
mod tls_client;
mod trojan;
mod trusttunnel;
mod v2ray_plugin_mux;
mod vless;
mod vmess;
mod websocket;
mod xhttp_stream;

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream as NetTcpStream};
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine;
use mihomo_core::{BoxedTcpStream, Metadata, RewriteStage, SubsystemManifest, TcpStream};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFamily {
    AnyTls,
    Gost,
    Gun,
    Hysteria,
    KcpTun,
    Masque,
    OpenVpn,
    Restls,
    ShadowSocks,
    ShadowTls,
    SimpleObfs,
    SingShadowTls,
    Snell,
    Socks4,
    Socks5,
    Ssr,
    Sudoku,
    Trojan,
    TrustTunnel,
    Tuic,
    V2RayPlugin,
    Vless,
    Vmess,
    XHttp,
}

pub const SUPPORTED_TRANSPORTS: &[TransportFamily] = &[
    TransportFamily::AnyTls,
    TransportFamily::Gost,
    TransportFamily::Gun,
    TransportFamily::Hysteria,
    TransportFamily::KcpTun,
    TransportFamily::Masque,
    TransportFamily::OpenVpn,
    TransportFamily::Restls,
    TransportFamily::ShadowSocks,
    TransportFamily::ShadowTls,
    TransportFamily::SimpleObfs,
    TransportFamily::SingShadowTls,
    TransportFamily::Snell,
    TransportFamily::Socks4,
    TransportFamily::Socks5,
    TransportFamily::Ssr,
    TransportFamily::Sudoku,
    TransportFamily::Trojan,
    TransportFamily::TrustTunnel,
    TransportFamily::Tuic,
    TransportFamily::V2RayPlugin,
    TransportFamily::Vless,
    TransportFamily::Vmess,
    TransportFamily::XHttp,
];

impl TransportFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnyTls => "anytls",
            Self::Gost => "gost",
            Self::Gun => "gun",
            Self::Hysteria => "hysteria",
            Self::KcpTun => "kcptun",
            Self::Masque => "masque",
            Self::OpenVpn => "openvpn",
            Self::Restls => "restls",
            Self::ShadowSocks => "shadowsocks",
            Self::ShadowTls => "shadowtls",
            Self::SimpleObfs => "simple-obfs",
            Self::SingShadowTls => "sing-shadowtls",
            Self::Snell => "snell",
            Self::Socks4 => "socks4",
            Self::Socks5 => "socks5",
            Self::Ssr => "ssr",
            Self::Sudoku => "sudoku",
            Self::Trojan => "trojan",
            Self::TrustTunnel => "trusttunnel",
            Self::Tuic => "tuic",
            Self::V2RayPlugin => "v2ray-plugin",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::XHttp => "xhttp",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SocketOptions {
    pub tfo: bool,
    pub mptcp: bool,
    pub interface_name: String,
    pub routing_mark: i32,
    pub ip_version: String,
    pub smux_enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsOptions {
    pub enabled: bool,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
}

pub use websocket::WebsocketOptions;
pub use http_stream::HttpStreamOptions;
pub use xhttp_stream::XHttpOptions;
pub use h2_stream::Http2Options;
pub use grpc_stream::GrpcOptions;
pub use sudoku_httpmask::{
    HttpMaskAcceptResult as SudokuHttpMaskAcceptResult,
    HttpMaskServerAcceptor as SudokuHttpMaskServerAcceptor,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportTarget {
    pub host: String,
    pub port: u16,
}

pub const PACKETADDR_MAGIC_HOST: &str = "sp.packet-addr.v2fly.arpa";
pub const PACKETADDR_MAGIC_PORT: u16 = 443;

impl TransportTarget {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn from_metadata(metadata: &Metadata) -> Result<Self, TransportError> {
        let port = metadata
            .dst_port
            .ok_or(TransportError::MissingDestinationPort)?;
        let host = metadata
            .host
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .or_else(|| metadata.dst_ip.map(|ip| ip.to_string()))
            .ok_or(TransportError::MissingDestinationHost)?;
        Ok(Self { host, port })
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub fn packetaddr_magic_target() -> TransportTarget {
    TransportTarget::new(PACKETADDR_MAGIC_HOST, PACKETADDR_MAGIC_PORT)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrojanShadowsocksOptions {
    pub enabled: bool,
    pub method: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportAction {
    Direct {
        socket: SocketOptions,
        target: TransportTarget,
    },
    Reject {
        drop: bool,
    },
    HttpConnect {
        proxy: TransportTarget,
        auth: Option<BasicAuth>,
        tls: TlsOptions,
        headers: BTreeMap<String, String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    Socks5Connect {
        proxy: TransportTarget,
        auth: Option<BasicAuth>,
        tls: TlsOptions,
        udp: bool,
        socket: SocketOptions,
        target: TransportTarget,
    },
    AnyTlsConnect {
        proxy: TransportTarget,
        password: String,
        tls: TlsOptions,
        alpn: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    ShadowsocksConnect {
        proxy: TransportTarget,
        cipher: String,
        password: String,
        plugin: String,
        plugin_mode: String,
        plugin_host: String,
        websocket: WebsocketOptions,
        tls: TlsOptions,
        mux: bool,
        socket: SocketOptions,
        target: TransportTarget,
    },
    SsrConnect {
        proxy: TransportTarget,
        password: String,
        cipher: String,
        obfs: String,
        obfs_param: String,
        protocol: String,
        protocol_param: String,
        udp: bool,
        socket: SocketOptions,
        target: TransportTarget,
    },
    SnellConnect {
        proxy: TransportTarget,
        psk: String,
        version: u8,
        obfs_mode: String,
        obfs_host: String,
        socket: SocketOptions,
        target: TransportTarget,
    },
    TrojanConnect {
        proxy: TransportTarget,
        password: String,
        shadowsocks: TrojanShadowsocksOptions,
        network: String,
        websocket: WebsocketOptions,
        grpc: GrpcOptions,
        http: HttpStreamOptions,
        tls: TlsOptions,
        alpn: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    TrustTunnelConnect {
        proxy: TransportTarget,
        username: String,
        password: String,
        udp: bool,
        quic: bool,
        tls: TlsOptions,
        alpn: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    VlessConnect {
        proxy: TransportTarget,
        uuid: String,
        flow: String,
        udp: bool,
        network: String,
        websocket: WebsocketOptions,
        grpc: GrpcOptions,
        h2: Http2Options,
        http: HttpStreamOptions,
        xhttp: XHttpOptions,
        encryption: String,
        packet_addr: bool,
        xudp: bool,
        tls: TlsOptions,
        alpn: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    VmessConnect {
        proxy: TransportTarget,
        uuid: String,
        alter_id: u16,
        cipher: String,
        udp: bool,
        network: String,
        websocket: WebsocketOptions,
        grpc: GrpcOptions,
        h2: Http2Options,
        http: HttpStreamOptions,
        xhttp: XHttpOptions,
        packet_addr: bool,
        xudp: bool,
        global_padding: bool,
        authenticated_length: bool,
        tls: TlsOptions,
        alpn: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    GostRelay {
        proxy: TransportTarget,
        auth: Option<BasicAuth>,
        forward: bool,
        tls: TlsOptions,
        mux: bool,
        socket: SocketOptions,
        target: TransportTarget,
    },
    SudokuConnect {
        proxy: TransportTarget,
        key: String,
        aead_method: String,
        table_type: String,
        padding_min: i32,
        padding_max: i32,
        enable_pure_downlink: bool,
        http_mask_enabled: bool,
        http_mask_mode: String,
        http_mask_tls: bool,
        http_mask_host: String,
        path_root: String,
        custom_table: String,
        custom_tables: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    SshConnect {
        proxy: TransportTarget,
        username: String,
        password: String,
        private_key: String,
        private_key_passphrase: String,
        host_keys: Vec<String>,
        host_key_algorithms: Vec<String>,
        socket: SocketOptions,
        target: TransportTarget,
    },
    Unsupported {
        name: String,
        kind: Option<String>,
        endpoint: Option<TransportTarget>,
        target: Option<TransportTarget>,
    },
}

impl TransportAction {
    pub fn target(&self) -> Option<&TransportTarget> {
        match self {
            Self::Direct { target, .. }
            | Self::HttpConnect { target, .. }
            | Self::Socks5Connect { target, .. }
            | Self::AnyTlsConnect { target, .. }
            | Self::ShadowsocksConnect { target, .. }
            | Self::SsrConnect { target, .. }
            | Self::SnellConnect { target, .. }
            | Self::TrojanConnect { target, .. }
            | Self::TrustTunnelConnect { target, .. }
            | Self::VlessConnect { target, .. }
            | Self::VmessConnect { target, .. }
            | Self::GostRelay { target, .. }
            | Self::SudokuConnect { target, .. }
            | Self::SshConnect { target, .. } => Some(target),
            Self::Reject { .. } => None,
            Self::Unsupported { target, .. } => target.as_ref(),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Direct { target, .. } => format!("direct->{}", target.authority()),
            Self::Reject { drop } => {
                if *drop {
                    "reject-drop".to_owned()
                } else {
                    "reject".to_owned()
                }
            }
            Self::HttpConnect { proxy, target, .. } => {
                format!("http-connect {} -> {}", proxy.authority(), target.authority())
            }
            Self::Socks5Connect { proxy, target, .. } => {
                format!("socks5-connect {} -> {}", proxy.authority(), target.authority())
            }
            Self::AnyTlsConnect { proxy, target, .. } => {
                format!("anytls {} -> {}", proxy.authority(), target.authority())
            }
            Self::ShadowsocksConnect { proxy, target, .. } => {
                format!("shadowsocks {} -> {}", proxy.authority(), target.authority())
            }
            Self::SsrConnect { proxy, target, .. } => {
                format!("ssr {} -> {}", proxy.authority(), target.authority())
            }
            Self::SnellConnect { proxy, target, .. } => {
                format!("snell {} -> {}", proxy.authority(), target.authority())
            }
            Self::TrojanConnect { proxy, target, .. } => {
                format!("trojan {} -> {}", proxy.authority(), target.authority())
            }
            Self::TrustTunnelConnect { proxy, target, .. } => {
                format!("trusttunnel {} -> {}", proxy.authority(), target.authority())
            }
            Self::VlessConnect { proxy, target, .. } => {
                format!("vless {} -> {}", proxy.authority(), target.authority())
            }
            Self::VmessConnect { proxy, target, .. } => {
                format!("vmess {} -> {}", proxy.authority(), target.authority())
            }
            Self::GostRelay { proxy, target, .. } => {
                format!("gost-relay {} -> {}", proxy.authority(), target.authority())
            }
            Self::SudokuConnect { proxy, target, .. } => {
                format!("sudoku {} -> {}", proxy.authority(), target.authority())
            }
            Self::SshConnect { proxy, target, .. } => {
                format!("ssh {} -> {}", proxy.authority(), target.authority())
            }
            Self::Unsupported {
                name,
                kind,
                endpoint,
                target,
            } => {
                let kind = kind.as_deref().unwrap_or("unknown");
                let endpoint = endpoint
                    .as_ref()
                    .map(|value| value.authority())
                    .unwrap_or_else(|| "<none>".to_owned());
                let target = target
                    .as_ref()
                    .map(|value| value.authority())
                    .unwrap_or_else(|| "<none>".to_owned());
                format!("unsupported {name} kind={kind} endpoint={endpoint} target={target}")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportHop {
    pub name: String,
    pub action: TransportAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportPlan {
    pub requested: String,
    pub selected_path: Vec<String>,
    pub leaf_name: String,
    pub hops: Vec<TransportHop>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    MissingDestinationPort,
    MissingDestinationHost,
    InvalidPlan(String),
    Rejected { drop: bool },
    UnsupportedAction { name: String, kind: Option<String> },
    UnsupportedTls { proxy: String },
    UnsupportedFeature { proxy: String, feature: String },
    InvalidProxyResponse(String),
    Io { kind: io::ErrorKind, message: String },
}

impl TransportError {
    fn invalid_proxy_response(message: impl Into<String>) -> Self {
        Self::InvalidProxyResponse(message.into())
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDestinationPort => write!(f, "missing destination port"),
            Self::MissingDestinationHost => write!(f, "missing destination host"),
            Self::InvalidPlan(message) => write!(f, "invalid transport plan: {message}"),
            Self::Rejected { drop } => {
                if *drop {
                    write!(f, "transport rejected with drop semantics")
                } else {
                    write!(f, "transport rejected")
                }
            }
            Self::UnsupportedAction { name, kind } => {
                let kind = kind.as_deref().unwrap_or("unknown");
                write!(f, "unsupported transport action for {name} kind={kind}")
            }
            Self::UnsupportedTls { proxy } => {
                write!(f, "tls-wrapped proxy transport not implemented for {proxy}")
            }
            Self::UnsupportedFeature { proxy, feature } => {
                write!(f, "transport feature {feature} is not implemented for {proxy}")
            }
            Self::InvalidProxyResponse(message) => write!(f, "invalid proxy response: {message}"),
            Self::Io { message, .. } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Io {
            kind: value.kind(),
            message: value.to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportTraceStep {
    pub name: String,
    pub summary: String,
}

pub trait TransportPlanRunner {
    type Output;

    fn run_plan(&mut self, plan: &TransportPlan) -> Result<Self::Output, TransportError>;
}

#[derive(Default, Debug)]
pub struct RecordingTransportRunner {
    steps: Vec<TransportTraceStep>,
}

impl RecordingTransportRunner {
    pub fn steps(&self) -> &[TransportTraceStep] {
        &self.steps
    }
}

impl TransportPlanRunner for RecordingTransportRunner {
    type Output = Vec<TransportTraceStep>;

    fn run_plan(&mut self, plan: &TransportPlan) -> Result<Self::Output, TransportError> {
        self.steps = plan
            .hops
            .iter()
            .map(|hop| TransportTraceStep {
                name: hop.name.clone(),
                summary: hop.action.summary(),
            })
            .collect();
        Ok(self.steps.clone())
    }
}

pub trait TcpDialer {
    fn connect(
        &mut self,
        target: &TransportTarget,
        socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDialPurpose {
    FinalTarget,
    ProxyServer,
}

#[derive(Default, Debug)]
pub struct SystemTcpDialer;

impl TcpDialer for SystemTcpDialer {
    fn connect(
        &mut self,
        target: &TransportTarget,
        _socket: &SocketOptions,
        _purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        // The socket option surface is kept stable first; platform-specific sockopts
        // will be wired in after the execution layer is no longer a stub.
        let stream = NetTcpStream::connect(target.authority())?;
        Ok(Box::new(stream))
    }
}

pub struct TcpTransportExecutor<D> {
    dialer: D,
    trace: Vec<TransportTraceStep>,
}

struct PrefixedTcpStream {
    prefix: io::Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
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

impl TcpStream for PrefixedTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        self.inner.try_clone_box()
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct HttpResponsePrefixedTcpStream {
    header_sent: bool,
    inner: BoxedTcpStream,
}

impl Read for HttpResponsePrefixedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for HttpResponsePrefixedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.header_sent {
            self.inner.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: keep-alive\r\n\r\n",
            )?;
            self.header_sent = true;
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for HttpResponsePrefixedTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            header_sent: self.header_sent,
            inner: self.inner.try_clone_box()?,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

impl<D> TcpTransportExecutor<D> {
    pub fn new(dialer: D) -> Self {
        Self {
            dialer,
            trace: Vec::new(),
        }
    }

    pub fn trace(&self) -> &[TransportTraceStep] {
        &self.trace
    }

    pub fn dialer(&self) -> &D {
        &self.dialer
    }

    pub fn dialer_mut(&mut self) -> &mut D {
        &mut self.dialer
    }

    pub fn into_dialer(self) -> D {
        self.dialer
    }
}

impl<D: TcpDialer> TransportPlanRunner for TcpTransportExecutor<D> {
    type Output = BoxedTcpStream;

    fn run_plan(&mut self, plan: &TransportPlan) -> Result<Self::Output, TransportError> {
        self.trace.clear();

        let mut stream: Option<BoxedTcpStream> = None;
        for hop in &plan.hops {
            self.trace.push(TransportTraceStep {
                name: hop.name.clone(),
                summary: hop.action.summary(),
            });
            stream = Some(match &hop.action {
                TransportAction::Direct { socket, target } => {
                    execute_direct(&mut self.dialer, stream.take(), socket, target)?
                }
                TransportAction::Reject { drop } => {
                    return Err(TransportError::Rejected { drop: *drop });
                }
                TransportAction::HttpConnect {
                    proxy,
                    auth,
                    tls,
                    headers,
                    socket,
                    target,
                } => execute_http_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    auth,
                    tls,
                    headers,
                    socket,
                    target,
                )?,
                TransportAction::Socks5Connect {
                    proxy,
                    auth,
                    tls,
                    udp,
                    socket,
                    target,
                } => execute_socks5_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    auth,
                    tls,
                    *udp,
                    socket,
                    target,
                )?,
                TransportAction::AnyTlsConnect {
                    proxy,
                    password,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_anytls_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::ShadowsocksConnect {
                    proxy,
                    cipher,
                    password,
                    plugin,
                    plugin_mode,
                    plugin_host,
                    websocket,
                    tls,
                    mux,
                    socket,
                    target,
                } => execute_shadowsocks_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    cipher,
                    password,
                    plugin,
                    plugin_mode,
                    plugin_host,
                    websocket,
                    tls,
                    *mux,
                    socket,
                    target,
                )?,
                TransportAction::SsrConnect {
                    proxy,
                    password,
                    cipher,
                    obfs,
                    obfs_param,
                    protocol,
                    protocol_param,
                    udp,
                    socket,
                    target,
                } => execute_ssr_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    cipher,
                    obfs,
                    obfs_param,
                    protocol,
                    protocol_param,
                    *udp,
                    socket,
                    target,
                )?,
                TransportAction::SnellConnect {
                    proxy,
                    psk,
                    version,
                    obfs_mode,
                    obfs_host,
                    socket,
                    target,
                } => execute_snell_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    psk,
                    *version,
                    obfs_mode,
                    obfs_host,
                    socket,
                    target,
                )?,
                TransportAction::TrojanConnect {
                    proxy,
                    password,
                    shadowsocks,
                    network,
                    websocket,
                    grpc,
                    http,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_trojan_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    shadowsocks,
                    network,
                    websocket,
                    grpc,
                    http,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::TrustTunnelConnect {
                    proxy,
                    username,
                    password,
                    udp,
                    quic,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_trusttunnel_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    username,
                    password,
                    *udp,
                    *quic,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::VlessConnect {
                    proxy,
                    uuid,
                    flow,
                    udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    encryption,
                    packet_addr,
                    xudp,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_vless_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    uuid,
                    flow,
                    *udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    encryption,
                    *packet_addr,
                    *xudp,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::VmessConnect {
                    proxy,
                    uuid,
                    alter_id,
                    cipher,
                    udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    packet_addr,
                    xudp,
                    global_padding,
                    authenticated_length,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_vmess_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    uuid,
                    *alter_id,
                    cipher,
                    *udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    *packet_addr,
                    *xudp,
                    *global_padding,
                    *authenticated_length,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::GostRelay {
                    proxy,
                    auth,
                    forward,
                    tls,
                    mux,
                    socket,
                    target,
                } => execute_gost_relay_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    auth,
                    *forward,
                    tls,
                    *mux,
                    socket,
                    target,
                )?,
                TransportAction::SudokuConnect {
                    proxy,
                    key,
                    aead_method,
                    table_type,
                    padding_min,
                    padding_max,
                    enable_pure_downlink,
                    http_mask_enabled,
                    http_mask_mode,
                    http_mask_tls,
                    http_mask_host,
                    path_root,
                    custom_table,
                    custom_tables,
                    socket,
                    target,
                } => execute_sudoku_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    key,
                    aead_method,
                    table_type,
                    *padding_min,
                    *padding_max,
                    *enable_pure_downlink,
                    *http_mask_enabled,
                    http_mask_mode,
                    *http_mask_tls,
                    http_mask_host,
                    path_root,
                    custom_table,
                    custom_tables,
                    socket,
                    target,
                )?,
                TransportAction::SshConnect {
                    proxy,
                    username,
                    password,
                    private_key,
                    private_key_passphrase,
                    host_keys,
                    host_key_algorithms,
                    socket,
                    target,
                } => execute_ssh_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    username,
                    password,
                    private_key,
                    private_key_passphrase,
                    host_keys,
                    host_key_algorithms,
                    socket,
                    target,
                )?,
                TransportAction::Unsupported { name, kind, .. } => {
                    return Err(TransportError::UnsupportedAction {
                        name: name.clone(),
                        kind: kind.clone(),
                    });
                }
            });
        }

        stream.ok_or_else(|| TransportError::InvalidPlan("no executable hops".to_owned()))
    }
}

fn execute_direct<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if let Some(stream) = existing {
        Ok(stream)
    } else {
        dialer.connect(target, socket, TcpDialPurpose::FinalTarget)
    }
}

fn execute_http_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    auth: &Option<BasicAuth>,
    tls: &TlsOptions,
    headers: &BTreeMap<String, String>,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream =
        open_proxy_stream(dialer, existing, proxy, tls, &[], socket)?;

    let request = build_http_connect_request(target, auth, headers);
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let buffered = read_http_connect_response(&mut *stream)?;
    Ok(prepend_bytes(stream, buffered))
}

fn execute_socks5_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    auth: &Option<BasicAuth>,
    tls: &TlsOptions,
    _udp: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream =
        open_proxy_stream(dialer, existing, proxy, tls, &[], socket)?;

    write_socks5_greeting(&mut *stream, auth.is_some())?;
    read_socks5_method_selection(&mut *stream, auth)?;
    if let Some(auth) = auth {
        write_socks5_auth(&mut *stream, auth)?;
        read_socks5_auth_result(&mut *stream)?;
    }
    write_socks5_connect_request(&mut *stream, target)?;
    read_socks5_connect_response(&mut *stream)?;
    Ok(stream)
}

fn execute_anytls_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let tls = tls
        .enabled
        .then_some(tls)
        .ok_or_else(|| TransportError::InvalidPlan("anytls transport requires tls".to_owned()))?;
    let resolved_alpn = if alpn.is_empty() {
        vec!["h2".to_owned(), "http/1.1".to_owned()]
    } else {
        alpn.to_vec()
    };
    let stream = open_proxy_stream(dialer, existing, proxy, tls, &resolved_alpn, socket)?;
    anytls::wrap_stream(stream, password, target)
}

fn execute_shadowsocks_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    cipher: &str,
    password: &str,
    plugin: &str,
    plugin_mode: &str,
    plugin_host: &str,
    websocket: &WebsocketOptions,
    tls: &TlsOptions,
    mux: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let plugin = plugin.trim();
    let plugin_lower = plugin.to_ascii_lowercase();
    match plugin_lower.as_str() {
        "" => {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            shadowsocks::wrap_stream(stream, cipher, password, target)
        }
        "obfs" => {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            let host = if plugin_host.trim().is_empty() {
                "bing.com"
            } else {
                plugin_host
            };
            let stream = match plugin_mode.trim() {
                "tls" => simple_obfs::wrap_tls_stream(stream, host),
                "http" => simple_obfs::wrap_http_stream(stream, host, &proxy.port.to_string()),
                other => {
                    return Err(TransportError::UnsupportedFeature {
                        proxy: proxy.authority(),
                        feature: format!("plugin={plugin} mode={other}"),
                    })
                }
            };
            shadowsocks::wrap_stream(stream, cipher, password, target)
        }
        "v2ray-plugin" | "gost-plugin" => {
            let mut stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            if tls.enabled {
                stream = tls_client::wrap_stream(
                    stream,
                    proxy,
                    tls,
                    &resolved_websocket_alpn(&[]),
                )?;
            }
            stream = websocket::wrap_stream(stream, proxy, websocket)?;
            if mux {
                stream = if plugin_lower == "v2ray-plugin" {
                    v2ray_plugin_mux::wrap_stream(stream).map_err(TransportError::from)?
                } else {
                    smux_stream::wrap_stream(stream).map_err(TransportError::from)?
                };
            }
            shadowsocks::wrap_stream(stream, cipher, password, target)
        }
        _ => Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("plugin={plugin}"),
        }),
    }
}

fn execute_ssr_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    cipher: &str,
    obfs: &str,
    obfs_param: &str,
    protocol: &str,
    protocol_param: &str,
    _udp: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    ssr::wrap_stream(
        stream,
        proxy,
        cipher,
        password,
        obfs,
        obfs_param,
        protocol,
        protocol_param,
        target,
    )
}

fn execute_snell_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    psk: &str,
    version: u8,
    obfs_mode: &str,
    obfs_host: &str,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    match obfs_mode.trim() {
        "" | "http" | "tls" => {}
        other => {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: format!("obfs={other}"),
            })
        }
    }
    let mut stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    let host = if obfs_host.trim().is_empty() {
        "bing.com"
    } else {
        obfs_host
    };
    stream = match obfs_mode.trim() {
        "" => stream,
        "tls" => simple_obfs::wrap_tls_stream(stream, host),
        "http" => simple_obfs::wrap_http_stream(stream, host, &proxy.port.to_string()),
        _ => unreachable!("unsupported snell obfs prevalidated"),
    };
    snell::wrap_stream(stream, psk, version, "", target)
}

fn execute_trojan_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    shadowsocks: &TrojanShadowsocksOptions,
    network: &str,
    websocket: &WebsocketOptions,
    grpc: &GrpcOptions,
    http: &HttpStreamOptions,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !network.trim().is_empty()
        && network != "tcp"
        && network != "ws"
        && network != "http"
        && network != "grpc"
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("network={network}"),
        });
    }
    let tls = tls
        .enabled
        .then_some(tls)
        .ok_or_else(|| TransportError::InvalidPlan("trojan transport requires tls".to_owned()))?;
    let resolved_alpn = if alpn.is_empty() {
        trojan::DEFAULT_ALPN
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    } else {
        alpn.to_vec()
    };
    let websocket_alpn = resolved_websocket_alpn(alpn);
    let (websocket, tls) = if network == "ws" {
        prepare_websocket_options(websocket, tls, true)
    } else {
        (websocket.clone(), tls.clone())
    };
    if network == "grpc" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = grpc_stream::wrap_tls_stream(stream, proxy, &tls, grpc)?;
        let stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
        return trojan::wrap_stream(stream, password, target);
    }
    let mut stream = open_proxy_stream(
        dialer,
        existing,
        proxy,
        &tls,
        if network == "ws" {
            &websocket_alpn
        } else {
            &resolved_alpn
        },
        socket,
    )?;
    if network == "ws" {
        stream = websocket::wrap_stream(stream, proxy, &websocket)?;
    } else if network == "http" {
        stream = http_stream::wrap_stream(stream, proxy, http);
    }
    stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
    trojan::wrap_stream(stream, password, target)
}

fn apply_trojan_shadowsocks(
    stream: BoxedTcpStream,
    shadowsocks: &TrojanShadowsocksOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if !shadowsocks.enabled {
        return Ok(stream);
    }
    shadowsocks::wrap_accepted_stream(stream, &shadowsocks.method, &shadowsocks.password)
}

fn execute_trusttunnel_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    username: &str,
    password: &str,
    _udp: bool,
    quic: bool,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if quic {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "quic".to_owned(),
        });
    }
    let tls = tls
        .enabled
        .then_some(tls)
        .ok_or_else(|| TransportError::InvalidPlan("trusttunnel transport requires tls".to_owned()))?;
    let resolved_alpn = if alpn.is_empty() {
        vec!["h2".to_owned()]
    } else {
        alpn.to_vec()
    };
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    trusttunnel::wrap_tls_stream(
        stream,
        proxy,
        tls,
        &resolved_alpn,
        username,
        password,
        target,
    )
}

fn execute_vless_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    uuid: &str,
    flow: &str,
    _udp: bool,
    network: &str,
    websocket: &WebsocketOptions,
    grpc: &GrpcOptions,
    h2: &Http2Options,
    http: &HttpStreamOptions,
    xhttp: &XHttpOptions,
    encryption: &str,
    _packet_addr: bool,
    _xudp: bool,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !network.trim().is_empty()
        && network != "tcp"
        && network != "ws"
        && network != "grpc"
        && network != "http"
        && network != "h2"
        && network != "xhttp"
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("network={network}"),
        });
    }
    if !flow.trim().is_empty() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("flow={flow}"),
        });
    }
    if !encryption.trim().is_empty() && encryption != "none" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("encryption={encryption}"),
        });
    }
    let websocket_alpn = resolved_websocket_alpn(alpn);
    let h2_alpn = vec!["h2".to_owned()];
    let (websocket, tls) = if network == "ws" {
        prepare_websocket_options(websocket, tls, false)
    } else {
        (websocket.clone(), tls.clone())
    };
    if network == "xhttp" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = if tls.enabled {
            xhttp_stream::wrap_tls_stream(stream, proxy, &tls, alpn, xhttp)?
        } else {
            xhttp_stream::wrap_stream(stream, proxy, xhttp)?
        };
        return vless::wrap_stream(stream, uuid, target);
    }
    let mut stream = if network == "grpc" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        grpc_stream::wrap_tls_stream(stream, proxy, &tls, grpc)?
    } else if network == "h2" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        h2_stream::wrap_tls_stream_with_request(
            stream,
            proxy,
            &tls,
            &h2_alpn,
            h2_stream::H2RequestOptions {
                authority: h2
                    .host
                    .iter()
                    .find(|value| !value.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| proxy.host.clone()),
                path: if h2.path.trim().is_empty() {
                    "/".to_owned()
                } else if h2.path.starts_with('/') {
                    h2.path.clone()
                } else {
                    format!("/{}", h2.path)
                },
                method: "PUT".to_owned(),
                headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
            },
        )?
    } else {
        open_proxy_stream(
            dialer,
            existing,
            proxy,
            &tls,
            if network == "ws" {
                &websocket_alpn
            } else {
                alpn
            },
            socket,
        )?
    };
    if network == "ws" {
        stream = websocket::wrap_stream(stream, proxy, &websocket)?;
    } else if network == "grpc" && !tls.enabled {
        stream = grpc_stream::wrap_stream(stream, proxy, grpc)?;
    } else if network == "h2" && !tls.enabled {
        stream = h2_stream::wrap_stream(stream, h2)?;
    } else if network == "http" {
        stream = http_stream::wrap_stream(stream, proxy, http);
    }
    vless::wrap_stream(stream, uuid, target)
}

fn execute_vmess_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    _udp: bool,
    network: &str,
    websocket: &WebsocketOptions,
    grpc: &GrpcOptions,
    h2: &Http2Options,
    http: &HttpStreamOptions,
    xhttp: &XHttpOptions,
    _packet_addr: bool,
    _xudp: bool,
    global_padding: bool,
    authenticated_length: bool,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !network.trim().is_empty()
        && network != "tcp"
        && network != "ws"
        && network != "grpc"
        && network != "http"
        && network != "h2"
        && network != "xhttp"
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("network={network}"),
        });
    }
    let websocket_alpn = resolved_websocket_alpn(alpn);
    let h2_alpn = vec!["h2".to_owned()];
    let (websocket, tls) = if network == "ws" {
        prepare_websocket_options(websocket, tls, false)
    } else {
        (websocket.clone(), tls.clone())
    };
    if network == "xhttp" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = if tls.enabled {
            xhttp_stream::wrap_tls_stream(stream, proxy, &tls, alpn, xhttp)?
        } else {
            xhttp_stream::wrap_stream(stream, proxy, xhttp)?
        };
        return vmess::wrap_stream(
            stream,
            uuid,
            alter_id,
            cipher,
            global_padding,
            authenticated_length,
            target,
        );
    }
    let mut stream = if network == "grpc" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        grpc_stream::wrap_tls_stream(stream, proxy, &tls, grpc)?
    } else if network == "h2" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        h2_stream::wrap_tls_stream_with_request(
            stream,
            proxy,
            &tls,
            &h2_alpn,
            h2_stream::H2RequestOptions {
                authority: h2
                    .host
                    .iter()
                    .find(|value| !value.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| proxy.host.clone()),
                path: if h2.path.trim().is_empty() {
                    "/".to_owned()
                } else if h2.path.starts_with('/') {
                    h2.path.clone()
                } else {
                    format!("/{}", h2.path)
                },
                method: "PUT".to_owned(),
                headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
            },
        )?
    } else {
        open_proxy_stream(
            dialer,
            existing,
            proxy,
            &tls,
            if network == "ws" {
                &websocket_alpn
            } else {
                alpn
            },
            socket,
        )?
    };
    if network == "ws" {
        stream = websocket::wrap_stream(stream, proxy, &websocket)?;
    } else if network == "grpc" && !tls.enabled {
        stream = grpc_stream::wrap_stream(stream, proxy, grpc)?;
    } else if network == "h2" && !tls.enabled {
        stream = h2_stream::wrap_stream(stream, h2)?;
    } else if network == "http" {
        stream = http_stream::wrap_stream(stream, proxy, http);
    }
    vmess::wrap_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
        target,
    )
}

fn execute_gost_relay_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    auth: &Option<BasicAuth>,
    forward: bool,
    tls: &TlsOptions,
    mux: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream = open_proxy_stream(dialer, existing, proxy, tls, &[], socket)?;
    if mux {
        stream = smux_stream::wrap_stream(stream)?;
    }

    write_gost_relay_connect_request(&mut *stream, auth, forward, target)?;
    read_gost_relay_connect_response(&mut *stream)?;
    Ok(stream)
}

fn execute_sudoku_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let normalized_mode = if http_mask_enabled {
        let trimmed = http_mask_mode.trim();
        if trimmed.is_empty() { "legacy" } else { trimmed }
    } else {
        ""
    };
    if existing.is_some()
        && matches!(normalized_mode, "stream" | "poll" | "auto")
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("http-mask-mode={normalized_mode} over chained stream"),
        });
    }
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    let stream = maybe_wrap_sudoku_ws_http_mask_tls(
        stream,
        proxy,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
    )?;
    sudoku::wrap_stream(
        stream,
        proxy,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
        path_root,
        custom_table,
        custom_tables,
        target,
    )
}

fn execute_ssh_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    username: &str,
    password: &str,
    private_key: &str,
    private_key_passphrase: &str,
    host_keys: &[String],
    host_key_algorithms: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    #[cfg(not(feature = "ssh-transport"))]
    {
        let _ = dialer;
        let _ = existing;
        let _ = proxy;
        let _ = username;
        let _ = password;
        let _ = private_key;
        let _ = private_key_passphrase;
        let _ = host_keys;
        let _ = host_key_algorithms;
        let _ = socket;
        let _ = target;
        return Err(TransportError::UnsupportedFeature {
            proxy: "<ssh>".to_owned(),
            feature: "ssh transport support is disabled in the default Rust build".to_owned(),
        });
    }
    #[cfg(feature = "ssh-transport")]
    {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    ssh::wrap_stream(
        stream,
        username,
        password,
        private_key,
        private_key_passphrase,
        host_keys,
        host_key_algorithms,
        target,
    )
    }
}

fn open_proxy_stream<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };

    if tls.enabled {
        tls_client::wrap_stream(stream, proxy, tls, alpn)
    } else {
        Ok(stream)
    }
}

fn resolved_websocket_alpn(alpn: &[String]) -> Vec<String> {
    if alpn.is_empty() {
        vec!["http/1.1".to_owned()]
    } else {
        alpn.to_vec()
    }
}

fn maybe_wrap_sudoku_ws_http_mask_tls(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
) -> Result<BoxedTcpStream, TransportError> {
    if !http_mask_enabled || !http_mask_tls || http_mask_mode.trim() != "ws" {
        return Ok(stream);
    }
    let sni = if http_mask_host.trim().is_empty() {
        proxy.host.clone()
    } else {
        sudoku_http_mask_sni(http_mask_host)
    };
    tls_client::wrap_stream(
        stream,
        proxy,
        &TlsOptions {
            enabled: true,
            sni,
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &resolved_websocket_alpn(&[]),
    )
}

fn sudoku_http_mask_sni(host: &str) -> String {
    let trimmed = host.trim();
    if let Ok((name, _)) = split_host_port(trimmed) {
        return name.to_owned();
    }
    trimmed.trim_start_matches('[').trim_end_matches(']').to_owned()
}

fn split_host_port(value: &str) -> Result<(&str, &str), ()> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(());
        };
        let host = &rest[..end];
        let remainder = &rest[end + 1..];
        let Some(port) = remainder.strip_prefix(':') else {
            return Err(());
        };
        return Ok((host, port));
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(());
    };
    if host.contains(':') {
        return Err(());
    }
    Ok((host, port))
}

fn prepare_websocket_options(
    websocket: &WebsocketOptions,
    tls: &TlsOptions,
    use_sni_as_host: bool,
) -> (WebsocketOptions, TlsOptions) {
    let mut websocket = websocket.clone();
    let mut tls = tls.clone();
    let has_host = websocket
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("host"));
    if use_sni_as_host && !tls.sni.trim().is_empty() && !has_host {
        websocket.headers.insert("Host".to_owned(), tls.sni.clone());
    }
    if tls.enabled && tls.sni.trim().is_empty() {
        if let Some((_, host)) = websocket
            .headers
            .iter()
            .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.trim().is_empty())
        {
            tls.sni = host.clone();
        }
    }
    (websocket, tls)
}

fn build_http_connect_request(
    target: &TransportTarget,
    auth: &Option<BasicAuth>,
    headers: &BTreeMap<String, String>,
) -> String {
    let authority = target.authority();
    let mut request = String::new();
    request.push_str(&format!("CONNECT {authority} HTTP/1.1\r\n"));
    request.push_str(&format!("Host: {authority}\r\n"));
    request.push_str("Proxy-Connection: Keep-Alive\r\n");
    if let Some(auth) = auth {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

fn read_http_connect_response(stream: &mut dyn Read) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(TransportError::invalid_proxy_response(
                "proxy closed before CONNECT response completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return validate_http_connect_response(&buffer, header_end);
        }
        if buffer.len() > 64 * 1024 {
            return Err(TransportError::invalid_proxy_response(
                "CONNECT response headers exceeded 64KiB",
            ));
        }
    }
}

fn validate_http_connect_response(
    buffer: &[u8],
    header_end: usize,
) -> Result<Vec<u8>, TransportError> {
    let text = String::from_utf8_lossy(&buffer[..header_end]);
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response(format!("missing HTTP status in {status_line:?}"))
        })?;
    if !version.starts_with("HTTP/") {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected HTTP version in {status_line:?}"
        )));
    }
    if !(200..300).contains(&status) {
        return Err(TransportError::invalid_proxy_response(format!(
            "CONNECT failed with status {status}"
        )));
    }
    Ok(buffer[header_end..].to_vec())
}

pub(crate) fn prepend_bytes(stream: BoxedTcpStream, prefix: Vec<u8>) -> BoxedTcpStream {
    if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: stream,
        })
    }
}

fn write_socks5_greeting(stream: &mut dyn Write, wants_auth: bool) -> Result<(), TransportError> {
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;
    Ok(())
}

fn read_socks5_method_selection(
    stream: &mut dyn Read,
    auth: &Option<BasicAuth>,
) -> Result<(), TransportError> {
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected SOCKS version {}",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => Ok(()),
        0x02 if auth.is_some() => Ok(()),
        0x02 => Err(TransportError::invalid_proxy_response(
            "proxy requested username/password auth but none was configured",
        )),
        0xff => Err(TransportError::invalid_proxy_response(
            "proxy rejected all advertised SOCKS5 auth methods",
        )),
        method => Err(TransportError::invalid_proxy_response(format!(
            "unsupported SOCKS5 auth method {method}"
        ))),
    }
}

fn write_socks5_auth(stream: &mut dyn Write, auth: &BasicAuth) -> Result<(), TransportError> {
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "SOCKS5 username/password must fit within 255 bytes".to_owned(),
        ));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request)?;
    stream.flush()?;
    Ok(())
}

fn read_socks5_auth_result(stream: &mut dyn Read) -> Result<(), TransportError> {
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x01 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected SOCKS5 auth version {}",
            reply[0]
        )));
    }
    if reply[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(format!(
            "SOCKS5 auth failed with status {}",
            reply[1]
        )));
    }
    Ok(())
}

fn write_socks5_connect_request(
    stream: &mut dyn Write,
    target: &TransportTarget,
) -> Result<(), TransportError> {
    let mut request = vec![0x05, 0x01, 0x00];
    request.extend_from_slice(&encode_socks5_target(target)?);
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request)?;
    stream.flush()?;
    Ok(())
}

fn encode_socks5_target(target: &TransportTarget) -> Result<Vec<u8>, TransportError> {
    if let Ok(ip) = IpAddr::from_str(&target.host) {
        match ip {
            IpAddr::V4(ip) => Ok([vec![0x01], ip.octets().to_vec()].concat()),
            IpAddr::V6(ip) => Ok([vec![0x04], ip.octets().to_vec()].concat()),
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(TransportError::InvalidPlan(
                "SOCKS5 domain target must fit within 255 bytes".to_owned(),
            ));
        }
        let mut encoded = Vec::with_capacity(2 + host.len());
        encoded.push(0x03);
        encoded.push(host.len() as u8);
        encoded.extend_from_slice(host);
        Ok(encoded)
    }
}

fn write_gost_relay_connect_request(
    stream: &mut dyn Write,
    auth: &Option<BasicAuth>,
    forward: bool,
    target: &TransportTarget,
) -> Result<(), TransportError> {
    const RELAY_VERSION_1: u8 = 0x01;
    const RELAY_CMD_CONNECT: u8 = 0x01;
    const RELAY_FEATURE_USER_AUTH: u8 = 0x01;
    const RELAY_FEATURE_ADDR: u8 = 0x02;
    const RELAY_FEATURE_NETWORK: u8 = 0x04;
    const RELAY_NETWORK_TCP: u16 = 0x0000;

    let mut features = Vec::new();
    if let Some(auth) = auth {
        let auth_feature = encode_gost_relay_feature(
            RELAY_FEATURE_USER_AUTH,
            encode_gost_relay_user_auth(auth)?,
        )?;
        features.push(auth_feature);
    }
    if !forward {
        let addr_feature =
            encode_gost_relay_feature(RELAY_FEATURE_ADDR, encode_gost_relay_addr(target)?)?;
        features.push(addr_feature);
    }
    let network_feature = encode_gost_relay_feature(
        RELAY_FEATURE_NETWORK,
        RELAY_NETWORK_TCP.to_be_bytes().to_vec(),
    )?;
    features.push(network_feature);

    let feature_len = features.iter().map(Vec::len).sum::<usize>();
    if feature_len > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay feature list too large".to_owned(),
        ));
    }

    stream.write_all(&[
        RELAY_VERSION_1,
        RELAY_CMD_CONNECT,
        (feature_len >> 8) as u8,
        feature_len as u8,
    ])?;
    for feature in features {
        stream.write_all(&feature)?;
    }
    stream.flush()?;
    Ok(())
}

fn write_gost_relay_udp_associate_request(
    stream: &mut dyn Write,
    auth: &Option<BasicAuth>,
    forward: bool,
    target: std::net::SocketAddr,
) -> Result<(), TransportError> {
    const RELAY_VERSION_1: u8 = 0x01;
    const RELAY_CMD_CONNECT: u8 = 0x01;
    const RELAY_FLAG_UDP: u8 = 0x80;
    const RELAY_FEATURE_USER_AUTH: u8 = 0x01;
    const RELAY_FEATURE_ADDR: u8 = 0x02;
    const RELAY_FEATURE_NETWORK: u8 = 0x04;
    const RELAY_NETWORK_UDP: u16 = 0x0001;

    let mut features = Vec::new();
    if let Some(auth) = auth {
        let auth_feature = encode_gost_relay_feature(
            RELAY_FEATURE_USER_AUTH,
            encode_gost_relay_user_auth(auth)?,
        )?;
        features.push(auth_feature);
    }
    if !forward {
        let addr_feature = encode_gost_relay_feature(
            RELAY_FEATURE_ADDR,
            encode_gost_relay_addr(&TransportTarget::new(target.ip().to_string(), target.port()))?,
        )?;
        features.push(addr_feature);
    }
    let network_feature = encode_gost_relay_feature(
        RELAY_FEATURE_NETWORK,
        RELAY_NETWORK_UDP.to_be_bytes().to_vec(),
    )?;
    features.push(network_feature);

    let feature_len = features.iter().map(Vec::len).sum::<usize>();
    if feature_len > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay feature list too large".to_owned(),
        ));
    }

    stream.write_all(&[
        RELAY_VERSION_1,
        RELAY_CMD_CONNECT | RELAY_FLAG_UDP,
        (feature_len >> 8) as u8,
        feature_len as u8,
    ])?;
    for feature in features {
        stream.write_all(&feature)?;
    }
    stream.flush()?;
    Ok(())
}

fn encode_gost_relay_feature(feature_type: u8, payload: Vec<u8>) -> Result<Vec<u8>, TransportError> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay feature payload too large".to_owned(),
        ));
    }
    let mut encoded = Vec::with_capacity(3 + payload.len());
    encoded.push(feature_type);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

fn encode_gost_relay_user_auth(auth: &BasicAuth) -> Result<Vec<u8>, TransportError> {
    if auth.username.len() > u8::MAX as usize || auth.password.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay username or password too long".to_owned(),
        ));
    }
    let mut encoded = Vec::with_capacity(2 + auth.username.len() + auth.password.len());
    encoded.push(auth.username.len() as u8);
    encoded.extend_from_slice(auth.username.as_bytes());
    encoded.push(auth.password.len() as u8);
    encoded.extend_from_slice(auth.password.as_bytes());
    Ok(encoded)
}

fn encode_gost_relay_addr(target: &TransportTarget) -> Result<Vec<u8>, TransportError> {
    const RELAY_ADDR_IPV4: u8 = 0x01;
    const RELAY_ADDR_DOMAIN: u8 = 0x03;
    const RELAY_ADDR_IPV6: u8 = 0x04;

    let mut encoded = Vec::new();
    if let Ok(ip) = IpAddr::from_str(&target.host) {
        match ip {
            IpAddr::V4(ip) => {
                encoded.push(RELAY_ADDR_IPV4);
                encoded.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                encoded.push(RELAY_ADDR_IPV6);
                encoded.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(TransportError::InvalidPlan(
                "gost relay target host too long".to_owned(),
            ));
        }
        encoded.push(RELAY_ADDR_DOMAIN);
        encoded.push(host.len() as u8);
        encoded.extend_from_slice(host);
    }
    encoded.extend_from_slice(&target.port.to_be_bytes());
    Ok(encoded)
}

fn read_gost_relay_connect_response(stream: &mut dyn Read) -> Result<(), TransportError> {
    const RELAY_VERSION_1: u8 = 0x01;
    const RELAY_STATUS_OK: u8 = 0x00;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != RELAY_VERSION_1 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected gost relay version {}",
            header[0]
        )));
    }
    if header[1] != RELAY_STATUS_OK {
        return Err(TransportError::invalid_proxy_response(format!(
            "gost relay connect failed with status 0x{:02x}",
            header[1]
        )));
    }
    let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if feature_len == 0 {
        return Ok(());
    }
    let mut discard = vec![0_u8; feature_len];
    stream.read_exact(&mut discard)?;
    Ok(())
}

fn read_socks5_connect_response(stream: &mut dyn Read) -> Result<(), TransportError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected SOCKS5 reply version {}",
            header[0]
        )));
    }
    if header[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(format!(
            "SOCKS5 connect failed with status {}",
            header[1]
        )));
    }
    consume_socks5_bound_address(stream, header[3])?;
    Ok(())
}

fn consume_socks5_bound_address(
    stream: &mut dyn Read,
    atyp: u8,
) -> Result<(), TransportError> {
    let length = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            length[0] as usize
        }
        _ => {
            return Err(TransportError::invalid_proxy_response(format!(
                "unsupported SOCKS5 bound address type {atyp}"
            )));
        }
    };
    let mut address = vec![0_u8; length];
    stream.read_exact(&mut address)?;
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok(())
}

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-transport",
    go_areas: &["transport"],
    contracts: &[
        "stream transports",
        "packet transports",
        "encapsulation layers",
        "normalized transport plan execution",
    ],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

pub fn encode_shadowsocks_udp_packet(
    cipher: &str,
    password: &str,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    shadowsocks::encode_udp_packet(cipher, password, target, payload)
}

pub fn encode_shadowsocks_udp_packet_for_target(
    cipher: &str,
    password: &str,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    shadowsocks::encode_udp_packet_for_target(cipher, password, target, payload)
}

pub fn decode_shadowsocks_udp_packet(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> Result<(std::net::SocketAddr, Vec<u8>), TransportError> {
    shadowsocks::decode_udp_packet(cipher, password, packet)
}

#[doc(hidden)]
pub fn accept_simple_obfs_tls_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    simple_obfs::wrap_tls_server_stream(stream)
}

#[doc(hidden)]
pub fn accept_simple_obfs_http_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    simple_obfs::wrap_http_server_stream(stream)
}

#[doc(hidden)]
pub fn accept_shadowsocks_test_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    shadowsocks::wrap_accepted_stream(stream, cipher, password)
}

#[doc(hidden)]
pub fn accept_ssr_test_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    ssr::wrap_accepted_stream(stream, cipher, password)
}

#[doc(hidden)]
pub fn accept_v2ray_plugin_mux_test_stream(stream: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    v2ray_plugin_mux::accept_test_stream(stream)
}

#[doc(hidden)]
pub fn accept_ssr_http_obfs_test_stream(
    mut stream: BoxedTcpStream,
) -> io::Result<(String, BoxedTcpStream)> {
    let (request, tail) = read_http_headers_with_tail(&mut *stream)?;
    let encoded_path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = encoded_path.strip_prefix('/').unwrap_or(encoded_path);
    let mut prefix = decode_percent_path(path)?;
    prefix.extend_from_slice(&tail);
    Ok((
        request,
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: Box::new(HttpResponsePrefixedTcpStream {
                header_sent: false,
                inner: stream,
            }),
        }),
    ))
}

#[doc(hidden)]
pub fn accept_smux_test_stream(stream: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    smux_stream::accept_test_stream(stream)
}

#[doc(hidden)]
pub fn wrap_smux_stream(stream: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    smux_stream::wrap_stream(stream)
}

pub fn encode_ssr_udp_packet(
    cipher: &str,
    password: &str,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    ssr::encode_udp_packet(cipher, password, target, payload)
}

pub fn decode_ssr_udp_packet(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    ssr::decode_udp_packet(cipher, password, packet)
}

fn read_http_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http headers ended before terminator",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let request = String::from_utf8(buffer[..position + 4].to_vec())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            let tail = buffer[position + 4..].to_vec();
            return Ok((request, tail));
        }
    }
}

fn decode_percent_path(path: &str) -> io::Result<Vec<u8>> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated percent-encoded path",
                ));
            }
            let value = u8::from_str_radix(&path[index + 1..index + 3], 16)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            out.push(value);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(out)
}

pub fn wrap_snell_udp_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
    obfs_mode: &str,
    obfs_host: &str,
    port: u16,
) -> Result<BoxedTcpStream, TransportError> {
    let host = if obfs_host.trim().is_empty() {
        "bing.com"
    } else {
        obfs_host
    };
    let stream = match obfs_mode.trim() {
        "" => stream,
        "tls" => simple_obfs::wrap_tls_stream(stream, host),
        "http" => simple_obfs::wrap_http_stream(stream, host, &port.to_string()),
        other => {
            return Err(TransportError::UnsupportedFeature {
                proxy: "<snell>".to_owned(),
                feature: format!("obfs={other}"),
            })
        }
    };
    snell::open_udp_stream(stream, psk, version, "")
}

pub fn accept_snell_udp_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
) -> Result<BoxedTcpStream, TransportError> {
    snell::wrap_accepted_stream(stream, psk, version)
}

pub fn write_snell_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    snell::write_udp_packet(stream, target, payload)
}

pub fn read_snell_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    snell::read_udp_packet(stream)
}

pub fn open_vless_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    vless::open_udp_stream(stream, uuid, target)
}

pub fn open_vless_packetaddr_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<BoxedTcpStream, TransportError> {
    vless::open_packetaddr_udp_stream(stream, uuid)
}

pub fn open_vless_xudp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<BoxedTcpStream, TransportError> {
    vless::open_xudp_stream(stream, uuid)
}

pub fn open_vmess_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    vmess::open_udp_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
        target,
    )
}

pub fn open_vmess_packetaddr_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
) -> Result<BoxedTcpStream, TransportError> {
    vmess::open_packetaddr_udp_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
    )
}

pub fn open_vmess_xudp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
) -> Result<BoxedTcpStream, TransportError> {
    vmess::open_xudp_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
    )
}

pub fn write_vmess_xudp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    vmess::write_xudp_packet(stream, target, payload)
}

pub fn read_vmess_xudp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    vmess::read_xudp_packet(stream)
}

pub fn write_vless_udp_packet(stream: &mut dyn Write, payload: &[u8]) -> io::Result<usize> {
    vless::write_udp_packet(stream, payload)
}

pub fn read_vless_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    vless::read_udp_packet(stream)
}

pub fn write_vless_xudp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    vless::write_xudp_packet(stream, target, payload)
}

pub fn read_vless_xudp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    vless::read_xudp_packet(stream)
}

pub fn write_vmess_udp_packet(stream: &mut dyn Write, payload: &[u8]) -> io::Result<usize> {
    vmess::write_udp_packet(stream, payload)
}

pub fn read_vmess_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    vmess::read_udp_packet(stream)
}

pub fn encode_packetaddr_udp_packet(
    destination: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 16 + payload.len());
    match destination {
        std::net::SocketAddr::V4(addr) => {
            packet.push(0x01);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(addr) => {
            packet.push(0x02);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}

pub fn decode_packetaddr_udp_packet(
    payload: &[u8],
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet-addr payload is empty",
        ));
    }
    let atyp = payload[0];
    let (ip, offset) = match atyp {
        0x01 => {
            if payload.len() < 1 + 4 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet-addr ipv4 payload is truncated",
                ));
            }
            let octets = [payload[1], payload[2], payload[3], payload[4]];
            (std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), 5)
        }
        0x02 => {
            if payload.len() < 1 + 16 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet-addr ipv6 payload is truncated",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[1..17]);
            (std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), 17)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported packet-addr family {other}"),
            ))
        }
    };
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    Ok((
        std::net::SocketAddr::new(ip, port),
        payload[offset + 2..].to_vec(),
    ))
}

pub fn open_sudoku_udp_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    let stream = maybe_wrap_sudoku_ws_http_mask_tls(
        stream,
        proxy,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
    )?;
    sudoku::open_udp_stream(
        stream,
        proxy,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
        path_root,
        custom_table,
        custom_tables,
    )
}

#[doc(hidden)]
pub fn open_sudoku_test_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = maybe_wrap_sudoku_ws_http_mask_tls(
        stream,
        proxy,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
    )?;
    sudoku::wrap_stream(
        stream,
        proxy,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
        path_root,
        custom_table,
        custom_tables,
        target,
    )
}

#[doc(hidden)]
pub fn open_sudoku_multiplex_test_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    sudoku::open_multiplex_client_stream(
        stream,
        proxy,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
        path_root,
        custom_table,
        custom_tables,
        target,
    )
}

pub fn write_sudoku_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    sudoku::write_udp_packet(stream, target, payload)
}

pub fn read_sudoku_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    sudoku::read_udp_packet(stream)
}

pub enum SudokuAcceptedStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Multiplex {
        server: sudoku::SudokuMultiplexServer,
    },
    Udp {
        stream: BoxedTcpStream,
    },
}

pub enum SudokuInboundAccept {
    Session(SudokuAcceptedStream),
    PassThrough(BoxedTcpStream),
    Rejected(BoxedTcpStream),
}

pub fn accept_sudoku_stream(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<SudokuAcceptedStream, TransportError> {
    match sudoku::accept_server_stream_for_tests(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
    )? {
        sudoku::SudokuServerSession::Tcp { target, stream } => {
            Ok(SudokuAcceptedStream::Tcp { target, stream })
        }
        sudoku::SudokuServerSession::Multiplex { stream } => {
            Ok(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            })
        }
        sudoku::SudokuServerSession::Udp { stream } => Ok(SudokuAcceptedStream::Udp { stream }),
    }
}

pub fn accept_sudoku_stream_allow_suspicious(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<SudokuInboundAccept, TransportError> {
    match sudoku::accept_server_stream_for_tests_with_custom_tables_allow_suspicious(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        "",
        &[],
    )? {
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Tcp { target, stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Tcp { target, stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Multiplex { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Udp { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Udp { stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Suspicious(stream) => {
            Ok(SudokuInboundAccept::PassThrough(stream))
        }
    }
}

pub fn accept_sudoku_stream_with_custom_tables_allow_suspicious(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuInboundAccept, TransportError> {
    match sudoku::accept_server_stream_for_tests_with_custom_tables_allow_suspicious(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        custom_table,
        custom_tables,
    )? {
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Tcp { target, stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Tcp { target, stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Multiplex { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Udp { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Udp { stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Suspicious(stream) => {
            Ok(SudokuInboundAccept::PassThrough(stream))
        }
    }
}

pub fn accept_sudoku_stream_with_http_mask(
    stream: BoxedTcpStream,
    acceptor: &sudoku_httpmask::HttpMaskServerAcceptor,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<Option<SudokuInboundAccept>, TransportError> {
    let Some(result) = acceptor.accept(stream)? else {
        return Ok(None);
    };
    match result {
        sudoku_httpmask::HttpMaskAcceptResult::Tunnel(stream) => {
            Ok(Some(SudokuInboundAccept::Session(accept_sudoku_stream(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
            )?)))
        }
        sudoku_httpmask::HttpMaskAcceptResult::PassThrough(stream) => {
            Ok(Some(accept_sudoku_stream_allow_suspicious(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
            )?))
        }
        sudoku_httpmask::HttpMaskAcceptResult::Rejected(stream) => {
            Ok(Some(SudokuInboundAccept::Rejected(stream)))
        }
    }
}

pub fn accept_sudoku_stream_with_custom_tables(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuAcceptedStream, TransportError> {
    match sudoku::accept_server_stream_for_tests_with_custom_tables(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        custom_table,
        custom_tables,
    )? {
        sudoku::SudokuServerSession::Tcp { target, stream } => {
            Ok(SudokuAcceptedStream::Tcp { target, stream })
        }
        sudoku::SudokuServerSession::Multiplex { stream } => {
            Ok(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            })
        }
        sudoku::SudokuServerSession::Udp { stream } => Ok(SudokuAcceptedStream::Udp { stream }),
    }
}

pub fn accept_sudoku_stream_with_custom_tables_and_http_mask(
    stream: BoxedTcpStream,
    acceptor: &sudoku_httpmask::HttpMaskServerAcceptor,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Option<SudokuInboundAccept>, TransportError> {
    let Some(result) = acceptor.accept(stream)? else {
        return Ok(None);
    };
    match result {
        sudoku_httpmask::HttpMaskAcceptResult::Tunnel(stream) => Ok(Some(
            SudokuInboundAccept::Session(accept_sudoku_stream_with_custom_tables(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
                custom_table,
                custom_tables,
            )?),
        )),
        sudoku_httpmask::HttpMaskAcceptResult::PassThrough(stream) => Ok(Some(
            accept_sudoku_stream_with_custom_tables_allow_suspicious(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
                custom_table,
                custom_tables,
            )?,
        )),
        sudoku_httpmask::HttpMaskAcceptResult::Rejected(stream) => {
            Ok(Some(SudokuInboundAccept::Rejected(stream)))
        }
    }
}

#[doc(hidden)]
pub use accept_sudoku_stream as accept_sudoku_test_stream;

#[doc(hidden)]
pub use accept_sudoku_stream_with_custom_tables as accept_sudoku_test_stream_with_custom_tables;

#[doc(hidden)]
pub use SudokuAcceptedStream as SudokuAcceptedTestStream;

pub enum VmessAcceptedStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Udp {
        target: String,
        stream: BoxedTcpStream,
    },
    Xudp {
        target: String,
        stream: BoxedTcpStream,
    },
}

pub fn accept_vmess_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<VmessAcceptedStream, TransportError> {
    match vmess::accept_server_stream(stream, uuid)? {
        vmess::VmessAcceptedStream::Tcp { target, stream } => {
            Ok(VmessAcceptedStream::Tcp { target, stream })
        }
        vmess::VmessAcceptedStream::Udp { target, stream } => {
            Ok(VmessAcceptedStream::Udp { target, stream })
        }
        vmess::VmessAcceptedStream::Xudp { target, stream } => {
            Ok(VmessAcceptedStream::Xudp { target, stream })
        }
    }
}

#[doc(hidden)]
pub enum VmessAcceptedTestStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Udp {
        target: String,
        stream: BoxedTcpStream,
    },
    Xudp {
        target: String,
        stream: BoxedTcpStream,
    },
}

#[doc(hidden)]
pub fn accept_vmess_test_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    cipher: &str,
) -> Result<VmessAcceptedTestStream, TransportError> {
    match vmess::accept_server_stream_for_tests(stream, uuid, cipher)? {
        vmess::VmessAcceptedStream::Tcp { target, stream } => {
            Ok(VmessAcceptedTestStream::Tcp { target, stream })
        }
        vmess::VmessAcceptedStream::Udp { target, stream } => {
            Ok(VmessAcceptedTestStream::Udp { target, stream })
        }
        vmess::VmessAcceptedStream::Xudp { target, stream } => {
            Ok(VmessAcceptedTestStream::Xudp { target, stream })
        }
    }
}

pub fn open_trojan_udp_stream(
    stream: BoxedTcpStream,
    password: &str,
    shadowsocks: &TrojanShadowsocksOptions,
    proxy: TransportTarget,
    target: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if tls.enabled {
        let resolved_alpn = if alpn.is_empty() {
            trojan::DEFAULT_ALPN
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        } else {
            alpn.to_vec()
        };
        tls_client::wrap_stream(stream, &proxy, tls, &resolved_alpn)?
    } else {
        stream
    };
    let stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
    trojan::open_udp_stream(stream, password, &target)
}

pub fn wrap_trusttunnel_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
    target: TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    trusttunnel::wrap_tls_stream(
        stream,
        &proxy,
        tls,
        alpn,
        username,
        password,
        &target,
    )
}

pub fn open_trusttunnel_udp_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    trusttunnel::open_udp_stream(stream, &proxy, tls, alpn, username, password)
}

pub fn write_trusttunnel_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    trusttunnel::write_udp_packet(stream, target, payload)
}

pub fn read_trusttunnel_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    trusttunnel::read_udp_packet(stream)
}

pub fn wrap_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    tls_client::wrap_stream(stream, &proxy, tls, alpn)
}

#[doc(hidden)]
pub fn register_test_root_certificate(pem: &str) -> Result<(), TransportError> {
    tls_client::register_test_root_certificate(pem)
}

pub fn wrap_websocket_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    websocket: &WebsocketOptions,
) -> Result<BoxedTcpStream, TransportError> {
    websocket::wrap_stream(stream, &proxy, websocket)
}

pub fn wrap_http_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    http: &HttpStreamOptions,
) -> BoxedTcpStream {
    http_stream::wrap_stream(stream, &proxy, http)
}

pub fn wrap_xhttp_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    xhttp: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    xhttp_stream::wrap_tls_stream(stream, &proxy, tls, alpn, xhttp)
}

pub fn wrap_xhttp_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    xhttp: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    xhttp_stream::wrap_stream(stream, &proxy, xhttp)
}

pub fn wrap_grpc_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    grpc: &GrpcOptions,
) -> Result<BoxedTcpStream, TransportError> {
    grpc_stream::wrap_stream(stream, &proxy, grpc)
}

pub fn wrap_grpc_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    grpc: &GrpcOptions,
) -> Result<BoxedTcpStream, TransportError> {
    grpc_stream::wrap_tls_stream(stream, &proxy, tls, grpc)
}

pub fn wrap_h2_proxy_stream(
    stream: BoxedTcpStream,
    h2: &Http2Options,
) -> Result<BoxedTcpStream, TransportError> {
    h2_stream::wrap_stream(stream, h2)
}

pub fn wrap_h2_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    h2: &Http2Options,
) -> Result<BoxedTcpStream, TransportError> {
    h2_stream::wrap_tls_stream_with_request(
        stream,
        &proxy,
        tls,
        &["h2".to_owned()],
        h2_stream::H2RequestOptions {
            authority: h2
                .host
                .iter()
                .find(|value| !value.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| proxy.host.clone()),
            path: if h2.path.trim().is_empty() {
                "/".to_owned()
            } else if h2.path.starts_with('/') {
                h2.path.clone()
            } else {
                format!("/{}", h2.path)
            },
            method: "PUT".to_owned(),
            headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
        },
    )
}

#[doc(hidden)]
pub fn accept_grpc_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    grpc_stream::accept_test_stream(stream)
}

#[doc(hidden)]
pub fn accept_h2_test_stream(
    stream: BoxedTcpStream,
) -> io::Result<(h2_stream::H2AcceptedTestRequest, BoxedTcpStream)> {
    h2_stream::accept_server_stream(stream)
}

#[doc(hidden)]
pub fn accept_h2_tls_test_stream(
    stream: BoxedTcpStream,
    tls_config: Arc<rustls::ServerConfig>,
) -> io::Result<(h2_stream::H2AcceptedTestRequest, BoxedTcpStream)> {
    h2_stream::accept_tls_server_stream(stream, tls_config)
}

pub fn open_anytls_udp_stream(
    stream: BoxedTcpStream,
    password: &str,
    destination: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    anytls::open_udp_stream(stream, password, destination)
}

pub fn write_anytls_udp_packet(
    stream: &mut dyn Write,
    destination: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    anytls::write_udp_packet(stream, destination, payload)
}

pub fn read_anytls_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    anytls::read_udp_packet(stream)
}

pub fn write_trojan_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    trojan::write_udp_packet(stream, target, payload)
}

pub fn read_trojan_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    trojan::read_udp_packet(stream)
}

pub fn open_gost_relay_udp_stream(
    mut stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
    forward: bool,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    write_gost_relay_udp_associate_request(&mut *stream, &auth, forward, target)?;
    read_gost_relay_connect_response(&mut *stream)?;
    Ok(stream)
}

pub fn write_gost_relay_udp_packet(
    stream: &mut dyn Write,
    payload: &[u8],
) -> io::Result<usize> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("gost relay udp packet too large: {}", payload.len()),
        ));
    }
    stream.write_all(&(payload.len() as u16).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

pub fn read_gost_relay_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{self, Cursor, Read, Write};
    use std::net::{TcpListener, ToSocketAddrs};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use base64::Engine as _;
    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    use sha1::{Digest as Sha1Digest, Sha1};
    use sha2::{Sha224, Sha256};

    use super::{
        accept_grpc_test_stream, accept_h2_test_stream, accept_h2_tls_test_stream,
        accept_shadowsocks_test_stream, accept_simple_obfs_http_test_stream,
        accept_sudoku_test_stream,
        accept_smux_test_stream, accept_v2ray_plugin_mux_test_stream,
        accept_vmess_test_stream, decode_shadowsocks_udp_packet,
        encode_shadowsocks_udp_packet, encode_shadowsocks_udp_packet_for_target,
        open_anytls_udp_stream, open_gost_relay_udp_stream,
        open_trojan_udp_stream, read_anytls_udp_packet,
        register_test_root_certificate,
        read_gost_relay_udp_packet, read_snell_udp_packet, read_trojan_udp_packet, shadowsocks,
        snell, wrap_grpc_tls_proxy_stream, wrap_tls_proxy_stream, write_anytls_udp_packet, write_gost_relay_udp_packet,
        write_snell_udp_packet, write_trojan_udp_packet, BasicAuth, RecordingTransportRunner,
        SocketOptions, SystemTcpDialer, TcpDialPurpose, TcpDialer, TcpTransportExecutor,
        TlsOptions, TransportAction, TransportFamily, TransportHop, TransportPlan,
        TransportPlanRunner, TransportTarget, TrojanShadowsocksOptions, wrap_smux_stream,
        SudokuAcceptedTestStream,
        VmessAcceptedTestStream, SUPPORTED_TRANSPORTS,
        WebsocketOptions,
    };
    use crate::{accept_simple_obfs_tls_test_stream, simple_obfs};
    use mihomo_core::{BoxedTcpStream, Metadata};

    #[derive(Default)]
    struct ScriptedState {
        reader: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    #[derive(Clone)]
    struct ScriptedStreamHandle(Arc<Mutex<ScriptedState>>);

    impl ScriptedStreamHandle {
        fn new(readable: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(ScriptedState {
                reader: Cursor::new(readable),
                writes: Vec::new(),
            })))
        }

        fn stream(&self) -> ScriptedStream {
            ScriptedStream(Arc::clone(&self.0))
        }

        fn writes(&self) -> Vec<u8> {
            self.0.lock().unwrap().writes.clone()
        }
    }

    struct ScriptedStream(Arc<Mutex<ScriptedState>>);

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().reader.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for ScriptedStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(ScriptedStream(Arc::clone(&self.0))))
        }
    }

    struct ServerWebsocketStream {
        inner: BoxedTcpStream,
        pending: Vec<u8>,
        offset: usize,
    }

    struct TestRustlsServerStream(StreamOwned<ServerConnection, std::net::TcpStream>);

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
            self.inner.read_exact(&mut header)?;
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
                    assert!(fin, "fragmented websocket frames are unsupported");
                    Ok(Some(payload))
                }
                0x8 => Ok(None),
                0x9 => {
                    self.write_frame(0xA, &payload)?;
                    Ok(Some(Vec::new()))
                }
                0xA => Ok(Some(Vec::new())),
                other => panic!("unexpected websocket opcode {other}"),
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

    impl Read for TestRustlsServerStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for TestRustlsServerStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl mihomo_core::TcpStream for TestRustlsServerStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "test rustls server stream does not support cloning",
            ))
        }

        fn shutdown_write(&mut self) -> io::Result<()> {
            self.0.sock.shutdown(std::net::Shutdown::Write)
        }

        fn shutdown_all(&mut self) -> io::Result<()> {
            self.0.sock.shutdown(std::net::Shutdown::Both)
        }
    }

    struct FakeDialer {
        expected: VecDeque<(String, ScriptedStreamHandle)>,
        calls: Vec<String>,
    }

    impl FakeDialer {
        fn new() -> Self {
            Self {
                expected: VecDeque::new(),
                calls: Vec::new(),
            }
        }

        fn push_connection(
            &mut self,
            authority: impl Into<String>,
            readable: Vec<u8>,
        ) -> ScriptedStreamHandle {
            let handle = ScriptedStreamHandle::new(readable);
            self.expected
                .push_back((authority.into(), handle.clone()));
            handle
        }
    }

    impl TcpDialer for FakeDialer {
        fn connect(
            &mut self,
            target: &TransportTarget,
            _socket: &SocketOptions,
            _purpose: TcpDialPurpose,
        ) -> Result<mihomo_core::BoxedTcpStream, super::TransportError> {
            self.calls.push(target.authority());
            let Some((expected, handle)) = self.expected.pop_front() else {
                return Err(super::TransportError::InvalidPlan(
                    "unexpected dial attempt".to_owned(),
                ));
            };
            if expected != target.authority() {
                return Err(super::TransportError::InvalidPlan(format!(
                    "expected dial {expected} but got {}",
                    target.authority()
                )));
            }
            Ok(Box::new(handle.stream()))
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ParsedGostRelayRequest {
        command: u8,
        username: Option<String>,
        password: Option<String>,
        target: Option<TransportTarget>,
        network: u16,
    }

    fn parse_gost_relay_request(frame: &[u8]) -> ParsedGostRelayRequest {
        assert!(frame.len() >= 4);
        assert_eq!(frame[0], 0x01);
        let command = frame[1];
        let feature_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(frame.len(), feature_len + 4);

        let mut offset = 4;
        let mut username = None;
        let mut password = None;
        let mut target = None;
        let mut network = u16::MAX;
        while offset < frame.len() {
            let feature_type = frame[offset];
            let payload_len = u16::from_be_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
            offset += 3;
            let payload = &frame[offset..offset + payload_len];
            offset += payload_len;

            match feature_type {
                0x01 => {
                    let user_len = payload[0] as usize;
                    let user_end = 1 + user_len;
                    username = Some(String::from_utf8(payload[1..user_end].to_vec()).unwrap());
                    let pass_len = payload[user_end] as usize;
                    let pass_start = user_end + 1;
                    password = Some(
                        String::from_utf8(payload[pass_start..pass_start + pass_len].to_vec())
                            .unwrap(),
                    );
                }
                0x02 => {
                    let atyp = payload[0];
                    let mut payload_offset = 1;
                    let host = match atyp {
                        0x01 => {
                            let ip = std::net::Ipv4Addr::new(
                                payload[payload_offset],
                                payload[payload_offset + 1],
                                payload[payload_offset + 2],
                                payload[payload_offset + 3],
                            );
                            payload_offset += 4;
                            ip.to_string()
                        }
                        0x04 => {
                            let mut octets = [0_u8; 16];
                            octets.copy_from_slice(&payload[payload_offset..payload_offset + 16]);
                            payload_offset += 16;
                            std::net::Ipv6Addr::from(octets).to_string()
                        }
                        0x03 => {
                            let len = payload[payload_offset] as usize;
                            payload_offset += 1;
                            let host = String::from_utf8(
                                payload[payload_offset..payload_offset + len].to_vec(),
                            )
                            .unwrap();
                            payload_offset += len;
                            host
                        }
                        other => panic!("unexpected gost relay atyp {other}"),
                    };
                    let port = u16::from_be_bytes([
                        payload[payload_offset],
                        payload[payload_offset + 1],
                    ]);
                    target = Some(TransportTarget::new(host, port));
                }
                0x04 => {
                    network = u16::from_be_bytes([payload[0], payload[1]]);
                }
                other => panic!("unexpected gost relay feature {other}"),
            }
        }

        ParsedGostRelayRequest {
            command,
            username,
            password,
            target,
            network,
        }
    }

    fn read_gost_relay_request_frame(stream: &mut dyn Read) -> Vec<u8> {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut frame = header.to_vec();
        let mut features = vec![0_u8; feature_len];
        stream.read_exact(&mut features).unwrap();
        frame.extend_from_slice(&features);
        frame
    }

    fn read_shadowsocks_target(stream: &mut dyn Read) -> TransportTarget {
        let mut atyp = [0_u8; 1];
        stream.read_exact(&mut atyp).unwrap();
        let host = match atyp[0] {
            0x01 => {
                let mut addr = [0_u8; 4];
                stream.read_exact(&mut addr).unwrap();
                std::net::Ipv4Addr::from(addr).to_string()
            }
            0x04 => {
                let mut addr = [0_u8; 16];
                stream.read_exact(&mut addr).unwrap();
                std::net::Ipv6Addr::from(addr).to_string()
            }
            0x03 => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                stream.read_exact(&mut host).unwrap();
                String::from_utf8(host).unwrap()
            }
            other => panic!("unexpected shadowsocks atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        TransportTarget::new(host, u16::from_be_bytes(port))
    }

    fn read_snell_target(stream: &mut dyn Read, expected_version: u8) -> TransportTarget {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 1);
        assert_eq!(
            header[1],
            if expected_version == 2 { 5 } else { 1 }
        );
        assert_eq!(header[2], 0);
        let host_len = header[3] as usize;
        let mut host = vec![0_u8; host_len];
        stream.read_exact(&mut host).unwrap();
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        TransportTarget::new(String::from_utf8(host).unwrap(), u16::from_be_bytes(port))
    }

    fn read_trojan_request(stream: &mut dyn Read) -> (String, u8, TransportTarget) {
        let mut password = [0_u8; 56];
        stream.read_exact(&mut password).unwrap();
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).unwrap();
        let target = read_shadowsocks_target(stream);
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        (
            String::from_utf8(password.to_vec()).unwrap(),
            command[0],
            target,
        )
    }


    fn read_http_headers(stream: &mut dyn Read) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read != 0, "http headers ended before terminator");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                return String::from_utf8(buffer[..position + 4].to_vec()).unwrap();
            }
        }
    }

    fn websocket_accept_key(key: &str) -> String {
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
    }

    fn accept_websocket_test_stream(mut stream: BoxedTcpStream) -> (String, BoxedTcpStream) {
        let request = read_http_headers(&mut *stream);
        let key = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                    Some(value.trim().to_owned())
                } else {
                    None
                }
            })
            .expect("missing Sec-WebSocket-Key");
        let accept = websocket_accept_key(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (request, Box::new(ServerWebsocketStream::new(stream)))
    }

    fn build_tls_server_config_with_pem() -> (Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let cert_pem = cert.cert.pem();
        let key_der = cert.key_pair.serialize_der();
        (
            Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            cert_pem,
        )
    }

    fn build_tls_server_config() -> Arc<ServerConfig> {
        build_tls_server_config_with_pem().0
    }

    fn build_tls_server_config_with_fingerprint() -> (Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let fingerprint = hex::encode(Sha256::digest(&cert_der));
        (
            Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            fingerprint,
        )
    }

    fn read_anytls_auth_prelude(stream: &mut dyn Read) -> (Vec<u8>, u16) {
        let mut password = vec![0_u8; 32];
        stream.read_exact(&mut password).unwrap();
        let mut padding_len = [0_u8; 2];
        stream.read_exact(&mut padding_len).unwrap();
        let padding_len = u16::from_be_bytes(padding_len);
        if padding_len > 0 {
            let mut padding = vec![0_u8; padding_len as usize];
            stream.read_exact(&mut padding).unwrap();
        }
        (password, padding_len)
    }

    fn read_anytls_frame(stream: &mut dyn Read) -> (u8, u32, Vec<u8>) {
        let mut header = [0_u8; 7];
        stream.read_exact(&mut header).unwrap();
        let command = header[0];
        let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).unwrap();
        (command, stream_id, payload)
    }

    fn write_anytls_frame(stream: &mut dyn Write, command: u8, stream_id: u32, payload: &[u8]) {
        stream.write_all(&[command]).unwrap();
        stream.write_all(&stream_id.to_be_bytes()).unwrap();
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(payload).unwrap();
    }

    fn read_anytls_uot_request(payload: &[u8]) -> (bool, std::net::SocketAddr) {
        let mut cursor = io::Cursor::new(payload);
        let mut is_connect = [0_u8; 1];
        cursor.read_exact(&mut is_connect).unwrap();
        let mut atyp = [0_u8; 1];
        cursor.read_exact(&mut atyp).unwrap();
        let target = match atyp[0] {
            0x00 => {
                let mut octets = [0_u8; 4];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x01 => {
                let mut octets = [0_u8; 16];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x02 => {
                let mut len = [0_u8; 1];
                cursor.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                cursor.read_exact(&mut host).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                let host = String::from_utf8_lossy(&host).into_owned();
                (host.as_str(), u16::from_be_bytes(port))
                    .to_socket_addrs()
                    .unwrap()
                    .next()
                    .unwrap()
            }
            other => panic!("unexpected anytls uot atyp {other}"),
        };
        (is_connect[0] != 0, target)
    }

    fn read_anytls_uot_packet(payload: &[u8]) -> (std::net::SocketAddr, Vec<u8>) {
        let mut cursor = io::Cursor::new(payload);
        let mut atyp = [0_u8; 1];
        cursor.read_exact(&mut atyp).unwrap();
        let target = match atyp[0] {
            0x00 => {
                let mut octets = [0_u8; 4];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x01 => {
                let mut octets = [0_u8; 16];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x02 => {
                let mut len = [0_u8; 1];
                cursor.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                cursor.read_exact(&mut host).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                let host = String::from_utf8_lossy(&host).into_owned();
                (host.as_str(), u16::from_be_bytes(port))
                    .to_socket_addrs()
                    .unwrap()
                    .next()
                    .unwrap()
            }
            other => panic!("unexpected anytls uot packet atyp {other}"),
        };
        let mut length = [0_u8; 2];
        cursor.read_exact(&mut length).unwrap();
        let length = u16::from_be_bytes(length) as usize;
        let mut packet = vec![0_u8; length];
        cursor.read_exact(&mut packet).unwrap();
        (target, packet)
    }

    #[test]
    fn inventory_tracks_transport_dirs() {
        assert!(SUPPORTED_TRANSPORTS.len() >= 20);
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::Sudoku));
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::TrustTunnel));
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::XHttp));
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::ShadowSocks));
    }

    #[test]
    fn target_from_metadata_prefers_host_when_available() {
        let metadata = Metadata {
            host: Some("example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let target = TransportTarget::from_metadata(&metadata).unwrap();
        assert_eq!(target.authority(), "example.com:443");
    }

    #[test]
    fn recording_runner_keeps_hop_order_and_summary() {
        let plan = TransportPlan {
            requested: "proxy".into(),
            selected_path: vec!["proxy".into()],
            leaf_name: "proxy".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("proxy.example", 443),
                    },
                },
                TransportHop {
                    name: "leaf".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example", 8443),
                    },
                },
            ],
        };
        let mut runner = RecordingTransportRunner::default();
        let steps = runner.run_plan(&plan).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].name, "outer");
        assert_eq!(steps[0].summary, "direct->proxy.example:443");
        assert_eq!(steps[1].summary, "direct->final.example:8443");
        assert_eq!(runner.steps(), steps.as_slice());
    }

    #[test]
    fn tcp_executor_runs_http_connect_handshake() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "proxy.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );
        let plan = TransportPlan {
            requested: "http-hop".into(),
            selected_path: vec!["http-hop".into()],
            leaf_name: "http-hop".into(),
            hops: vec![TransportHop {
                name: "http-hop".into(),
                action: TransportAction::HttpConnect {
                    proxy: TransportTarget::new("proxy.example.com", 8080),
                    auth: Some(BasicAuth {
                        username: "user".into(),
                        password: "pass".into(),
                    }),
                    tls: TlsOptions::default(),
                    headers: BTreeMap::from([("User-Agent".into(), "mihomo-rust".into())]),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        let mut stream = executor.run_plan(&plan).unwrap();

        let written = String::from_utf8(handle.writes()).unwrap();
        assert!(written.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert!(written.contains("Host: final.example.com:443\r\n"));
        assert!(written.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(written.contains("User-Agent: mihomo-rust\r\n"));
        assert_eq!(executor.dialer().calls, vec!["proxy.example.com:8080"]);
        let mut remainder = Vec::new();
        stream.read_to_end(&mut remainder).unwrap();
        assert_eq!(remainder, b"server-data".to_vec());
    }

    #[test]
    fn tcp_executor_runs_http_connect_handshake_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data")
                .unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "http-hop".into(),
            selected_path: vec!["http-hop".into()],
            leaf_name: "http-hop".into(),
            hops: vec![TransportHop {
                name: "http-hop".into(),
                action: TransportAction::HttpConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    auth: None,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    headers: BTreeMap::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        let mut remainder = Vec::new();
        stream.read_to_end(&mut remainder).unwrap();
        assert_eq!(remainder, b"server-data".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_socks5_auth_and_connect_handshake() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "proxy.example.com:1080",
            vec![
                0x05, 0x02, // method selection
                0x01, 0x00, // auth success
                0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90, // connect reply
            ],
        );
        let plan = TransportPlan {
            requested: "socks-hop".into(),
            selected_path: vec!["socks-hop".into()],
            leaf_name: "socks-hop".into(),
            hops: vec![TransportHop {
                name: "socks-hop".into(),
                action: TransportAction::Socks5Connect {
                    proxy: TransportTarget::new("proxy.example.com", 1080),
                    auth: Some(BasicAuth {
                        username: "user".into(),
                        password: "pass".into(),
                    }),
                    tls: TlsOptions::default(),
                    udp: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let writes = handle.writes();
        assert_eq!(&writes[0..4], &[0x05, 0x02, 0x00, 0x02]);
        assert_eq!(writes[4], 0x01);
        assert_eq!(writes[5], 4);
        assert_eq!(&writes[6..10], b"user");
        assert_eq!(writes[10], 4);
        assert_eq!(&writes[11..15], b"pass");
        assert_eq!(&writes[15..19], &[0x05, 0x01, 0x00, 0x03]);
        assert_eq!(writes[19] as usize, "example.com".len());
        assert_eq!(&writes[20..31], b"example.com");
        assert_eq!(&writes[31..33], &443_u16.to_be_bytes());
    }

    #[test]
    fn tcp_executor_runs_gost_relay_handshake() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection("relay.example.com:8443", vec![0x01, 0x00, 0x00, 0x00]);
        let plan = TransportPlan {
            requested: "relay-hop".into(),
            selected_path: vec!["relay-hop".into()],
            leaf_name: "relay-hop".into(),
            hops: vec![TransportHop {
                name: "relay-hop".into(),
                action: TransportAction::GostRelay {
                    proxy: TransportTarget::new("relay.example.com", 8443),
                    auth: Some(BasicAuth {
                        username: "relay-user".into(),
                        password: "relay-pass".into(),
                    }),
                    forward: false,
                    tls: TlsOptions::default(),
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let request = parse_gost_relay_request(&handle.writes());
        assert_eq!(request.command, 0x01);
        assert_eq!(request.username.as_deref(), Some("relay-user"));
        assert_eq!(request.password.as_deref(), Some("relay-pass"));
        assert_eq!(
            request.target,
            Some(TransportTarget::new("final.example.com", 443))
        );
        assert_eq!(request.network, 0x0000);
        assert_eq!(executor.dialer().calls, vec!["relay.example.com:8443"]);
    }

    #[test]
    fn tcp_executor_runs_gost_relay_handshake_over_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let request = parse_gost_relay_request(&read_gost_relay_request_frame(&mut *stream));
            assert_eq!(request.command, 0x01);
            assert_eq!(
                request.target,
                Some(TransportTarget::new("final.example.com", 443))
            );
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "relay-hop-mux".into(),
            selected_path: vec!["relay-hop-mux".into()],
            leaf_name: "relay-hop-mux".into(),
            hops: vec![TransportHop {
                name: "relay-hop-mux".into(),
                action: TransportAction::GostRelay {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    auth: None,
                    forward: false,
                    tls: TlsOptions::default(),
                    mux: true,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_sudoku_websocket_http_mask_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.contains("GET /mask/ws HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost:8443\r\n"));
            assert!(request.contains("X-Sudoku-Tunnel: ws\r\n"));
            assert!(request.contains("X-Sudoku-Version: 1\r\n"));
            let session = accept_sudoku_test_stream(
                stream,
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-wss").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: true,
                    http_mask_mode: "ws".into(),
                    http_mask_tls: true,
                    http_mask_host: "localhost:8443".into(),
                    path_root: "mask".into(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku-wss");
        worker.join().unwrap();
    }

    #[test]
    fn gost_relay_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = parse_gost_relay_request(&read_gost_relay_request_frame(&mut stream));
            assert_eq!(request.command, 0x81);
            assert_eq!(
                request.target,
                Some(TransportTarget::new("127.0.0.1", 5353))
            );
            assert_eq!(request.network, 0x0001);
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"udp-ping".to_vec());
            write_gost_relay_udp_packet(&mut stream, b"udp-pong").unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let auth = Some(BasicAuth {
            username: "user".into(),
            password: "pass".into(),
        });
        let mut stream = open_gost_relay_udp_stream(
            Box::new(stream),
            auth,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_gost_relay_udp_packet(&mut *stream, b"udp-ping").unwrap();
        let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn gost_relay_udp_stream_round_trip_preserves_target_and_payload_over_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let request = parse_gost_relay_request(&read_gost_relay_request_frame(&mut *stream));
            assert_eq!(request.command, 0x81);
            assert_eq!(
                request.target,
                Some(TransportTarget::new("127.0.0.1", 5353))
            );
            assert_eq!(request.network, 0x0001);
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"udp-ping".to_vec());
            write_gost_relay_udp_packet(&mut *stream, b"udp-pong").unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let auth = Some(BasicAuth {
            username: "user".into(),
            password: "pass".into(),
        });
        let stream = wrap_smux_stream(Box::new(stream)).unwrap();
        let mut stream = open_gost_relay_udp_stream(
            stream,
            auth,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_gost_relay_udp_packet(&mut *stream, b"udp-ping").unwrap();
        let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream =
                shadowsocks::wrap_accepted_stream(Box::new(stream), "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: String::new(),
                    plugin_mode: String::new(),
                    plugin_host: String::new(),
                    websocket: WebsocketOptions::default(),
                    tls: TlsOptions::default(),
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_anytls_handshake_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);
            assert!(String::from_utf8(payload).unwrap().contains("v=2"));

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);
            assert!(payload.is_empty());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = io::Cursor::new(payload);
            let target = read_shadowsocks_target(&mut payload_reader);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            assert_eq!(payload, b"ping".to_vec());

            write_anytls_frame(&mut stream, 0x02, 1, b"pong-anytls");
            write_anytls_frame(&mut stream, 0x03, 1, &[]);
            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x03);
            assert_eq!(stream_id, 1);
            assert!(payload.is_empty());
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-anytls".into(),
            selected_path: vec!["edge-anytls".into()],
            leaf_name: "edge-anytls".into(),
            hops: vec![TransportHop {
                name: "edge-anytls".into(),
                action: TransportAction::AnyTlsConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-anytls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn anytls_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = io::Cursor::new(payload);
            let target = read_shadowsocks_target(&mut payload_reader);
            assert_eq!(target, TransportTarget::new("sp.v2.udp-over-tcp.arpa", 0));

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (is_connect, destination) = read_anytls_uot_request(&payload);
            assert!(!is_connect);
            assert_eq!(destination, "127.0.0.1:5353".parse().unwrap());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (target, packet) = read_anytls_uot_packet(&payload);
            assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
            assert_eq!(packet, b"udp-ping".to_vec());

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);
            let mut response = Vec::new();
            response.push(0x00);
            response.extend_from_slice(&[127, 0, 0, 1]);
            response.extend_from_slice(&5353_u16.to_be_bytes());
            response.extend_from_slice(&(8_u16).to_be_bytes());
            response.extend_from_slice(b"udp-pong");
            write_anytls_frame(&mut stream, 0x02, 1, &response);
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let stream = wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into(), "http/1.1".into()],
        )
        .unwrap();
        let mut stream = open_anytls_udp_stream(Box::new(stream), "secret", "127.0.0.1:5353".parse().unwrap()).unwrap();
        write_anytls_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping").unwrap();
        let (target, payload) = read_anytls_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn anytls_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.push(0x02);
        packet.push(9);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_anytls_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_v2ray_plugin_over_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));
            assert!(request.contains("\r\nX-Proxy: enabled\r\n"));

            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-ws").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "v2ray-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "ws.example.com".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow".into(),
                        headers: BTreeMap::from([
                            ("Host".into(), "ws.example.com".into()),
                            ("X-Proxy".into(), "enabled".into()),
                        ]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions::default(),
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss-ws".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_gost_plugin_over_websocket_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-tls HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: localhost\r\n"));

            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-wss").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "gost-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "localhost".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow-tls".into(),
                        headers: BTreeMap::from([("Host".into(), "localhost".into())]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss-wss".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_obfs_http_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-obfs").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "obfs".into(),
                    plugin_mode: "http".into(),
                    plugin_host: "bing.com".into(),
                    websocket: WebsocketOptions::default(),
                    tls: TlsOptions::default(),
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss-obfs".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_obfs_tls_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-obfs-tls").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "obfs".into(),
                    plugin_mode: "tls".into(),
                    plugin_host: "bing.com".into(),
                    websocket: WebsocketOptions::default(),
                    tls: TlsOptions::default(),
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss-obfs-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_v2ray_plugin_mux_over_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-mux HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));

            let stream = accept_v2ray_plugin_mux_test_stream(stream).unwrap();
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-mux").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "v2ray-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "ws.example.com".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow-mux".into(),
                        headers: BTreeMap::from([("Host".into(), "ws.example.com".into())]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions::default(),
                    mux: true,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss-mux".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_gost_plugin_mux_over_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-gost-mux HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));

            let stream = accept_smux_test_stream(stream).unwrap();
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-gost-mux").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "gost-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "ws.example.com".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow-gost-mux".into(),
                        headers: BTreeMap::from([("Host".into(), "ws.example.com".into())]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions::default(),
                    mux: true,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ss-gost-mux".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = snell::wrap_accepted_stream(Box::new(stream), "secret-psk", 3).unwrap();
            let target = read_snell_target(&mut *stream, 3);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: String::new(),
                    obfs_host: String::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-snell".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_v2_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = snell::wrap_accepted_stream(Box::new(stream), "secret-psk", 2).unwrap();
            let target = read_snell_target(&mut *stream, 2);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-v2").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell-v2".into(),
            selected_path: vec!["edge-snell-v2".into()],
            leaf_name: "edge-snell-v2".into(),
            hops: vec![TransportHop {
                name: "edge-snell-v2".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 2,
                    obfs_mode: String::new(),
                    obfs_host: String::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-snell-v2".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_http_obfs_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream = snell::wrap_accepted_stream(stream, "secret-psk", 3).unwrap();
            let target = read_snell_target(&mut *stream, 3);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-obfs").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: "http".into(),
                    obfs_host: "bing.com".into(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-snell-obfs".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_tls_obfs_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream = snell::wrap_accepted_stream(stream, "secret-psk", 3).unwrap();
            let target = read_snell_target(&mut *stream, 3);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-obfs-tls").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: "tls".into(),
                    obfs_host: "bing.com".into(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-snell-obfs-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, command, target) = read_trojan_request(&mut stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions::default(),
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    http: crate::HttpStreamOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-trojan".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_tls_with_shadowsocks_stream_cipher() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream =
                accept_shadowsocks_test_stream(Box::new(stream), "aes-128-gcm", "inner").unwrap();
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-ss").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions {
                        enabled: true,
                        method: "aes-128-gcm".into(),
                        password: "inner".into(),
                    },
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    http: crate::HttpStreamOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; b"pong-trojan-ss".len()];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..], b"pong-trojan-ss");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_grpc_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", listen_addr.port()));
            assert_eq!(request.path, "/GunService/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-grpc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions::default(),
                    network: "grpc".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    http: crate::HttpStreamOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-trojan-grpc".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn trojan_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (_password, command, target) = read_trojan_request(&mut stream);
            assert_eq!(command, 0x03);
            assert_eq!(target, TransportTarget::new("127.0.0.1", 5353));
            let (packet_target, payload) = read_trojan_udp_packet(&mut stream).unwrap();
            assert_eq!(packet_target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            write_trojan_udp_packet(&mut stream, "127.0.0.1:5353".parse().unwrap(), b"udp-pong")
                .unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_trojan_udp_stream(
            Box::new(stream),
            "secret",
            &TrojanShadowsocksOptions::default(),
            TransportTarget::new("localhost", listen_addr.port()),
            TransportTarget::new("127.0.0.1", 5353),
            &tls,
            &[],
        )
        .unwrap();
        write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping")
            .unwrap();
        let (target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn trojan_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.push(0x03);
        packet.push(9);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_trojan_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn trojan_udp_stream_round_trip_with_shadowsocks_stream_cipher_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream =
                accept_shadowsocks_test_stream(Box::new(stream), "aes-128-gcm", "inner").unwrap();
            let (_password, command, target) = read_trojan_request(&mut *stream);
            assert_eq!(command, 0x03);
            assert_eq!(target, TransportTarget::new("127.0.0.1", 5353));
            let (packet_target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
            assert_eq!(packet_target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-pong")
                .unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_trojan_udp_stream(
            Box::new(stream),
            "secret",
            &TrojanShadowsocksOptions {
                enabled: true,
                method: "aes-128-gcm".into(),
                password: "inner".into(),
            },
            TransportTarget::new("localhost", listen_addr.port()),
            TransportTarget::new("127.0.0.1", 5353),
            &tls,
            &[],
        )
        .unwrap();
        write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping")
            .unwrap();
        let (target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn trojan_udp_stream_over_grpc_tls_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", listen_addr.port()));
            assert_eq!(request.path, "/GunService/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (_password, command, target) = read_trojan_request(&mut *stream);
            assert_eq!(command, 0x03);
            assert_eq!(target, TransportTarget::new("127.0.0.1", 5353));
            let (packet_target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
            assert_eq!(packet_target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-pong")
                .unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let grpc = crate::GrpcOptions::default();
        let stream = wrap_grpc_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &grpc,
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &TrojanShadowsocksOptions::default(),
            TransportTarget::new("localhost", listen_addr.port()),
            TransportTarget::new("127.0.0.1", 5353),
            &TlsOptions::default(),
            &[],
        )
        .unwrap();
        write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping")
            .unwrap();
        let (target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn shadowsocks_udp_packet_round_trip_preserves_target_and_payload() {
        let target: std::net::SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let packet = encode_shadowsocks_udp_packet(
            "chacha20-ietf-poly1305",
            "secret",
            target,
            b"udp-ping",
        )
        .unwrap();
        let (decoded_target, decoded_payload) =
            decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &packet).unwrap();
        assert_eq!(decoded_target, target);
        assert_eq!(decoded_payload, b"udp-ping".to_vec());
    }

    #[test]
    fn shadowsocks_udp_packet_supports_fqdn_targets() {
        let packet = encode_shadowsocks_udp_packet_for_target(
            "chacha20-ietf-poly1305",
            "secret",
            &TransportTarget::new("localhost", 5353),
            b"udp-fqdn",
        )
        .unwrap();
        let (decoded_target, decoded_payload) =
            decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &packet).unwrap();
        assert_eq!(decoded_target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(decoded_payload, b"udp-fqdn".to_vec());
    }

    #[test]
    fn snell_udp_packet_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = snell::wrap_accepted_stream(Box::new(stream), "secret-psk", 3).unwrap();
            let mut header = [0_u8; 3];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 6, 0]);
            let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            stream.write_all(&[0x00]).unwrap();
            write_snell_udp_packet(
                &mut *stream,
                "127.0.0.1:5353".parse().unwrap(),
                b"udp-pong",
            )
            .unwrap();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let mut stream =
            super::wrap_snell_udp_stream(Box::new(stream), "secret-psk", 3, "", "", 443)
                .unwrap();
        write_snell_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping").unwrap();
        let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn snell_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.push(0x01);
        packet.push(0x09);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_snell_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn simple_obfs_tls_round_trip_preserves_payloads() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut first = [0_u8; 5];
            stream.read_exact(&mut first).unwrap();
            assert_eq!(&first, b"hello");
            stream.write_all(b"world").unwrap();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let mut stream = simple_obfs::wrap_tls_stream(Box::new(stream), "bing.com");
        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        let mut reply = [0_u8; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"world");
        worker.join().unwrap();
    }

    #[test]
    fn wrap_tls_proxy_stream_accepts_matching_fingerprint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (tls_config, fingerprint) = build_tls_server_config_with_fingerprint();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint,
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &[],
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn wrap_tls_proxy_stream_rejects_mismatched_fingerprint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (tls_config, _) = build_tls_server_config_with_fingerprint();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let mut discard = [0_u8; 64];
            let _ = stream.read(&mut discard);
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: "00".repeat(32),
            certificate: String::new(),
            private_key: String::new(),
        };
        let err = match wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &[],
        ) {
            Ok(_) => panic!("expected mismatched fingerprint to fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("certificate")
                || err.to_string().contains("application verification failure"),
            "unexpected error: {err}"
        );
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vmess_h2_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmess-h2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-h2".into(),
            selected_path: vec!["edge-vmess-h2".into()],
            leaf_name: "edge-vmess-h2".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-h2".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "h2".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vmess-h2".into(),
                    },
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions::default(),
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-h2".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vmess_grpc_over_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/example/Tun");
            let stream = accept_grpc_test_stream(stream);
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc-tls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-grpc-tls".into(),
            selected_path: vec!["edge-vmess-grpc-tls".into()],
            leaf_name: "edge-vmess-grpc-tls".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-grpc-tls".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "grpc".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions {
                        service_name: "example".into(),
                        ..Default::default()
                    },
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-grpc-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vmess_h2_over_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmess-h2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2-tls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-h2-tls".into(),
            selected_path: vec!["edge-vmess-h2-tls".into()],
            leaf_name: "edge-vmess-h2-tls".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-h2-tls".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "h2".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vmess-h2".into(),
                    },
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-h2-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn vmess_wrap_stream_over_h2_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/vmess-h2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2-tls-direct").unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let tls = crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let stream = crate::h2_stream::wrap_tls_stream_with_request(
            Box::new(stream),
            &TransportTarget::new("localhost", addr.port()),
            &tls,
            &["h2".to_owned()],
            crate::h2_stream::H2RequestOptions {
                authority: format!("localhost:{}", addr.port()),
                path: "/vmess-h2".into(),
                method: "PUT".into(),
                headers: vec![("accept-encoding".into(), "identity".into())],
            },
        )
        .unwrap();
        let mut stream = crate::vmess::wrap_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            &TransportTarget::new("final.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-h2-tls-direct".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn vmess_wrap_stream_over_grpc_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/example/Tun");
            let stream = accept_grpc_test_stream(stream);
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc-tls-direct").unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let tls = crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let grpc = crate::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
        };
        let stream = wrap_grpc_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", addr.port()),
            &tls,
            &grpc,
        )
        .unwrap();
        let mut stream = crate::vmess::wrap_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            &TransportTarget::new("final.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-grpc-tls-direct".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_rejects_unknown_snell_obfs_mode() {
        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", 8443),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: "quic".into(),
                    obfs_host: "bing.com".into(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        match executor.run_plan(&plan) {
            Err(err) => assert_eq!(
                err,
                super::TransportError::UnsupportedFeature {
                    proxy: "127.0.0.1:8443".into(),
                    feature: "obfs=quic".into(),
                }
            ),
            Ok(_) => panic!("expected snell obfs to be rejected"),
        }
    }

    #[test]
    fn tcp_executor_chains_outer_socks5_and_gost_relay() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "outer.example.com:1080",
            [
                vec![
                    0x05, 0x00, // socks no-auth
                    0x05, 0x00, 0x00, 0x03, 17,
                ],
                b"relay.example.com".to_vec(),
                vec![0x20, 0xfb], // 8443
                vec![0x01, 0x00, 0x00, 0x00],
            ]
            .concat(),
        );
        let plan = TransportPlan {
            requested: "relay".into(),
            selected_path: vec!["relay".into()],
            leaf_name: "relay".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Socks5Connect {
                        proxy: TransportTarget::new("outer.example.com", 1080),
                        auth: None,
                        tls: TlsOptions::default(),
                        udp: false,
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("relay.example.com", 8443),
                    },
                },
                TransportHop {
                    name: "relay".into(),
                    action: TransportAction::GostRelay {
                        proxy: TransportTarget::new("relay.example.com", 8443),
                        auth: None,
                        forward: false,
                        tls: TlsOptions::default(),
                        mux: false,
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
            ],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let writes = handle.writes();
        assert_eq!(&writes[0..3], &[0x05, 0x01, 0x00]);
        let relay_start = writes
            .windows(2)
            .position(|window| window == [0x01, 0x01])
            .unwrap();
        let request = parse_gost_relay_request(&writes[relay_start..]);
        assert_eq!(
            request.target,
            Some(TransportTarget::new("final.example.com", 443))
        );
        assert_eq!(executor.dialer().calls, vec!["outer.example.com:1080"]);
    }

    #[test]
    fn tcp_executor_chains_outer_socks5_and_inner_http() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "outer.example.com:1080",
            [
                vec![
                    0x05, 0x00, // socks no-auth
                    0x05, 0x00, 0x00, 0x03, 16,
                ],
                b"leaf.example.com".to_vec(),
                vec![0x20, 0xfb], // 8443
                b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
            ]
            .concat(),
        );
        let plan = TransportPlan {
            requested: "leaf".into(),
            selected_path: vec!["leaf".into()],
            leaf_name: "leaf".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Socks5Connect {
                        proxy: TransportTarget::new("outer.example.com", 1080),
                        auth: None,
                        tls: TlsOptions::default(),
                        udp: false,
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("leaf.example.com", 8443),
                    },
                },
                TransportHop {
                    name: "leaf".into(),
                    action: TransportAction::HttpConnect {
                        proxy: TransportTarget::new("leaf.example.com", 8443),
                        auth: None,
                        tls: TlsOptions::default(),
                        headers: BTreeMap::new(),
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
            ],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let written = handle.writes();
        assert_eq!(&written[0..3], &[0x05, 0x01, 0x00]);
        let http_start = written
            .windows("CONNECT ".len())
            .position(|window| window == b"CONNECT ")
            .unwrap();
        let request = String::from_utf8(written[http_start..].to_vec()).unwrap();
        assert!(request.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert_eq!(executor.dialer().calls, vec!["outer.example.com:1080"]);
        assert_eq!(executor.trace().len(), 2);
    }

    #[test]
    fn tcp_executor_direct_chain_only_dials_once() {
        let mut dialer = FakeDialer::new();
        dialer.push_connection("final.example.com:443", Vec::new());
        let plan = TransportPlan {
            requested: "leaf".into(),
            selected_path: vec!["leaf".into()],
            leaf_name: "leaf".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
                TransportHop {
                    name: "leaf".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
            ],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();
        assert_eq!(executor.dialer().calls, vec!["final.example.com:443"]);
    }
}
