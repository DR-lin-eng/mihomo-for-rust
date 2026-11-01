use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream as NetTcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};

use mihomo_core::{BoxedTcpStream, Metadata, TcpStream};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use crate::{
    grpc_stream::GrpcOptions, h2_stream::Http2Options, http_stream::HttpStreamOptions,
    websocket::WebsocketOptions, xhttp_stream::XHttpOptions,
};

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
pub struct WireGuardPeerTransportOptions {
    pub server: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterSocks5UdpPlan {
    pub proxy: TransportTarget,
    pub auth: Option<BasicAuth>,
    pub prefix_plan: Option<Box<TransportPlan>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelDnsOptions {
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasqueConnectOptions {
    pub private_key: String,
    pub public_key: String,
    pub ip: String,
    pub ipv6: String,
    pub uri: String,
    pub mtu: usize,
    pub network: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
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
    HysteriaConnect {
        proxy: TransportTarget,
        ports: String,
        protocol: String,
        auth: String,
        auth_str: String,
        obfs: String,
        sni: String,
        alpn: Vec<String>,
        up: String,
        down: String,
        up_speed: u32,
        down_speed: u32,
        disable_mtu_discovery: bool,
        fast_open: bool,
        hop_interval: u32,
        skip_cert_verify: bool,
        socket: SocketOptions,
        target: TransportTarget,
    },
    Hy2Connect {
        proxy: TransportTarget,
        password: String,
        sni: String,
        certificate: String,
        private_key: String,
        obfs: String,
        obfs_password: String,
        realm_enabled: bool,
        realm_server_url: String,
        realm_token: String,
        realm_id: String,
        realm_stun_servers: Vec<String>,
        realm_sni: String,
        realm_skip_cert_verify: bool,
        realm_fingerprint: String,
        realm_certificate: String,
        realm_private_key: String,
        realm_alpn: Vec<String>,
        realm_proxy: String,
        realm_proxy_plan: Option<Box<TransportPlan>>,
        skip_cert_verify: bool,
        socket: SocketOptions,
        target: TransportTarget,
    },
    TuicConnect {
        proxy: TransportTarget,
        uuid: String,
        password: String,
        token: String,
        udp: bool,
        sni: String,
        certificate: String,
        private_key: String,
        alpn: Vec<String>,
        disable_sni: bool,
        request_timeout_ms: u64,
        heartbeat_interval_ms: u64,
        congestion_controller: String,
        max_open_streams: u32,
        max_udp_relay_packet_size: u32,
        tls: TlsOptions,
        socket: SocketOptions,
        target: TransportTarget,
    },
    WireGuardConnect {
        proxy: TransportTarget,
        private_key: String,
        ip: String,
        ipv6: String,
        workers: usize,
        tunnel_dns: TunnelDnsOptions,
        peers: Vec<WireGuardPeerTransportOptions>,
        outer_socks5: Option<OuterSocks5UdpPlan>,
        mtu: usize,
        socket: SocketOptions,
        target: TransportTarget,
    },
    OpenVpnConnect {
        proxy: TransportTarget,
        proto: String,
        dev: String,
        cipher: String,
        auth: String,
        ca: String,
        cert: String,
        key: String,
        tls_crypt: String,
        username: String,
        password: String,
        tunnel_dns: TunnelDnsOptions,
        outer_socks5: Option<OuterSocks5UdpPlan>,
        mtu: usize,
        socket: SocketOptions,
        target: TransportTarget,
    },
    MasqueConnect {
        proxy: TransportTarget,
        options: MasqueConnectOptions,
        tls: TlsOptions,
        outer_socks5: Option<OuterSocks5UdpPlan>,
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
        h2: Http2Options,
        http: HttpStreamOptions,
        xhttp: XHttpOptions,
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
        reality_public_key: String,
        reality_short_id: String,
        reality_support_x25519mlkem768: bool,
        client_fingerprint: String,
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
            | Self::HysteriaConnect { target, .. }
            | Self::Hy2Connect { target, .. }
            | Self::TuicConnect { target, .. }
            | Self::WireGuardConnect { target, .. }
            | Self::OpenVpnConnect { target, .. }
            | Self::MasqueConnect { target, .. }
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
            Self::HysteriaConnect { proxy, target, .. } => {
                format!("hysteria {} -> {}", proxy.authority(), target.authority())
            }
            Self::Hy2Connect { proxy, target, .. } => {
                format!("hysteria2 {} -> {}", proxy.authority(), target.authority())
            }
            Self::TuicConnect { proxy, target, .. } => {
                format!("tuic {} -> {}", proxy.authority(), target.authority())
            }
            Self::WireGuardConnect { proxy, target, .. } => {
                format!("wireguard {} -> {}", proxy.authority(), target.authority())
            }
            Self::OpenVpnConnect { proxy, target, .. } => {
                format!("openvpn {} -> {}", proxy.authority(), target.authority())
            }
            Self::MasqueConnect { proxy, target, .. } => {
                format!("masque {} -> {}", proxy.authority(), target.authority())
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
    pub(crate) fn invalid_proxy_response(message: impl Into<String>) -> Self {
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
    /// Independent bounded dialer for Smart races. Custom dialers can opt in;
    /// callers retain sequential behavior when this capability is unavailable.
    fn fork(&self,_timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{None}

    fn resolve_addrs(
        &mut self,
        target: &TransportTarget,
        _socket: &SocketOptions,
        _purpose: TcpDialPurpose,
    ) -> Result<Vec<NetTcpStreamAddr>, TransportError> {
        let addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(TransportError::from)?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(TransportError::Io {
                kind: io::ErrorKind::NotFound,
                message: format!("failed to resolve tcp target: {}", target.authority()),
            });
        }
        Ok(addrs.into_iter().map(NetTcpStreamAddr).collect())
    }

    fn connect(
        &mut self,
        target: &TransportTarget,
        socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetTcpStreamAddr(pub std::net::SocketAddr);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDialPurpose {
    FinalTarget,
    ProxyServer,
}

#[derive(Default, Debug)]
pub struct SystemTcpDialer;

impl TcpDialer for SystemTcpDialer {
    fn fork(&self,timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{Some(Box::new(BoundedSystemDialer(timeout_ms)))}

    fn connect(
        &mut self,
        target: &TransportTarget,
        socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        let addrs = self.resolve_addrs(target, socket, purpose)?;
        let mut last_err = None;
        for addr in addrs {
            match connect_tcp_with_socket_options(addr.0, socket) {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err
            .map(TransportError::from)
            .unwrap_or_else(|| TransportError::Io {
                kind: io::ErrorKind::NotFound,
                message: format!("failed to connect to any address for {}", target.authority()),
            }))
    }
}

static DEFAULT_INTERFACE_NAME: OnceLock<Mutex<String>> = OnceLock::new();
static DEFAULT_ROUTING_MARK: OnceLock<Mutex<i32>> = OnceLock::new();

pub fn set_default_interface_name(name: impl Into<String>) {
    let lock = DEFAULT_INTERFACE_NAME.get_or_init(|| Mutex::new(String::new()));
    if let Ok(mut value) = lock.lock() {
        *value = name.into();
    }
}

pub fn clear_default_interface_name() {
    set_default_interface_name(String::new());
}

pub fn set_default_routing_mark(mark: i32) {
    mihomo_core::set_outbound_mark(mark as u32);
    let lock = DEFAULT_ROUTING_MARK.get_or_init(|| Mutex::new(0));
    if let Ok(mut value) = lock.lock() {
        *value = mark;
    }
}

pub fn clear_default_routing_mark() {
    set_default_routing_mark(0);
}

struct BoundedSystemDialer(u64);
impl TcpDialer for BoundedSystemDialer {
    fn fork(&self,timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{Some(Box::new(Self(timeout_ms.min(self.0))))}
    fn connect(&mut self,target:&TransportTarget,options:&SocketOptions,purpose:TcpDialPurpose)->Result<BoxedTcpStream,TransportError>{
        let mut last=None;for addr in self.resolve_addrs(target,options,purpose)?{
            match connect_tcp_addr_with_options(addr.0,options,Some(self.0)){Ok(stream)=>{stream.set_timeouts(Some(std::time::Duration::from_millis(self.0)),Some(std::time::Duration::from_millis(self.0)))?;return Ok(Box::new(stream));},Err(error)=>last=Some(error)}
        }Err(last.unwrap_or_else(||io::Error::new(io::ErrorKind::NotFound,"no dial addresses")).into())
    }
}
impl<T:TcpDialer+?Sized> TcpDialer for Box<T>{
    fn fork(&self,timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{(**self).fork(timeout_ms)}
    fn connect(&mut self,target:&TransportTarget,socket:&SocketOptions,purpose:TcpDialPurpose)->Result<BoxedTcpStream,TransportError>{(**self).connect(target,socket,purpose)}
    fn resolve_addrs(&mut self,target:&TransportTarget,socket:&SocketOptions,purpose:TcpDialPurpose)->Result<Vec<NetTcpStreamAddr>,TransportError>{(**self).resolve_addrs(target,socket,purpose)}
}

fn connect_tcp_with_socket_options(
    addr: SocketAddr,
    socket: &SocketOptions,
) -> io::Result<NetTcpStream> {
    connect_tcp_addr_with_options(addr,socket,None)
}

pub fn connect_tcp_addr_with_options(addr:SocketAddr,options:&SocketOptions,timeout_ms:Option<u64>)->io::Result<NetTcpStream> {
    let domain = Domain::for_address(addr);
    let stream_socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    configure_tcp_socket(&stream_socket, options, addr)?;
    if let Some(timeout)=timeout_ms{stream_socket.connect_timeout(&SockAddr::from(addr),std::time::Duration::from_millis(timeout.max(1)))?;}
    else{stream_socket.connect(&SockAddr::from(addr))?;}
    Ok(stream_socket.into())
}

fn configure_tcp_socket(
    _socket: &Socket,
    options: &SocketOptions,
    addr: SocketAddr,
) -> io::Result<()> {
    let interface_name = effective_interface_name(options);
    let routing_mark = effective_routing_mark(options);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if !interface_name.trim().is_empty() {
            _socket.bind_device(Some(interface_name.as_bytes()))?;
        }
        if routing_mark != 0 {
            _socket.set_mark(routing_mark as u32)?;
        }
    }

    apply_ip_version_hint(_socket, options, addr)?;
    Ok(())
}

fn effective_interface_name(options: &SocketOptions) -> String {
    if !options.interface_name.trim().is_empty() {
        return options.interface_name.clone();
    }
    DEFAULT_INTERFACE_NAME
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .map(|value| value.clone())
        .unwrap_or_default()
}

fn effective_routing_mark(options: &SocketOptions) -> i32 {
    if options.routing_mark != 0 {
        return options.routing_mark;
    }
    DEFAULT_ROUTING_MARK
        .get_or_init(|| Mutex::new(0))
        .lock()
        .map(|value| *value)
        .unwrap_or(0)
}

fn apply_ip_version_hint(
    _socket: &Socket,
    options: &SocketOptions,
    addr: SocketAddr,
) -> io::Result<()> {
    let version = options.ip_version.trim().to_ascii_lowercase();
    if version.is_empty() || version == "dual" {
        return Ok(());
    }

    match addr {
        SocketAddr::V4(_) => {
            if matches!(version.as_str(), "ipv6" | "ipv6-prefer") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("ip-version `{}` does not allow IPv4 target {}", options.ip_version, addr),
                ));
            }
        }
        SocketAddr::V6(_) => {
            if matches!(version.as_str(), "ipv4" | "ipv4-prefer") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("ip-version `{}` does not allow IPv6 target {}", options.ip_version, addr),
                ));
            }
        }
    }
    Ok(())
}

pub struct TcpTransportExecutor<D> {
    pub(crate) dialer: D,
    pub(crate) trace: Vec<TransportTraceStep>,
}
