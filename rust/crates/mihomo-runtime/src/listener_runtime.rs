use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use mihomo_config::RuntimeConfigDocument;
use mihomo_core::{
    BoxedTcpStream, ConnectionContext, Metadata, NetworkKind, ParseMetadataError, SessionKind,
    TcpStream,
};
use mihomo_inbound::{
    AuthUser, HttpInboundConfig, InboundDefinition, RedirInboundConfig, TProxyInboundConfig,
    TlsInboundConfig, TunnelInboundConfig,
};
use mihomo_transport::TcpDialer;

use crate::{ExecutionError, RuntimeTunnel, TcpForwardError, TcpRelayStats};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelListenerRuntimeSpec {
    pub name: String,
    pub addresses: Vec<String>,
    pub target: String,
    pub supports_tcp: bool,
    pub supports_udp: bool,
    pub special_proxy: String,
    pub special_rules: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirListenerRuntimeSpec {
    pub name: String,
    pub addresses: Vec<String>,
    pub special_proxy: String,
    pub special_rules: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TProxyListenerRuntimeSpec {
    pub name: String,
    pub addresses: Vec<String>,
    pub supports_udp: bool,
    pub special_proxy: String,
    pub special_rules: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksListenerRuntimeSpec {
    pub name: String,
    pub addresses: Vec<String>,
    pub supports_udp: bool,
    pub user_count: usize,
    pub special_proxy: String,
    pub special_rules: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpListenerRuntimeSpec {
    pub name: String,
    pub addresses: Vec<String>,
    pub user_count: usize,
    pub special_proxy: String,
    pub special_rules: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedListenerRuntimeSpec {
    pub name: String,
    pub addresses: Vec<String>,
    pub supports_udp: bool,
    pub user_count: usize,
    pub special_proxy: String,
    pub special_rules: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpProxyMode {
    Connect,
    Forward,
}

pub struct PreparedHttpProxyContext {
    pub context: ConnectionContext,
    pub mode: HttpProxyMode,
}

pub struct PreparedSocks5UdpAssociate {
    pub stream: BoxedTcpStream,
    pub inbound_name: String,
    pub inbound_user: String,
    pub special_proxy: String,
    pub special_rules: String,
    pub requested_target: String,
}

pub enum PreparedSocks5Dispatch {
    Connect(ConnectionContext),
    UdpAssociate(PreparedSocks5UdpAssociate),
}

#[derive(Debug)]
pub enum ListenerRuntimeError {
    UnsupportedNetwork(String),
    InvalidTarget(ParseMetadataError),
    Connect(ExecutionError),
    TcpForward(TcpForwardError),
    Io(io::Error),
    Relay(io::Error),
    SocksProtocol(String),
    SocksUnsupportedCommand(u8),
    SocksAuthenticationFailed,
    HttpProtocol(String),
    HttpAuthenticationFailed,
    HttpUnsupportedTarget(String),
}

impl std::fmt::Display for ListenerRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedNetwork(name) => {
                write!(f, "tunnel listener does not support tcp: {name}")
            }
            Self::InvalidTarget(err) => write!(f, "{err}"),
            Self::Connect(err) => write!(f, "{err}"),
            Self::TcpForward(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Relay(err) => write!(f, "{err}"),
            Self::SocksProtocol(message) => write!(f, "invalid socks5 request: {message}"),
            Self::SocksUnsupportedCommand(command) => {
                write!(f, "unsupported socks5 command: {command}")
            }
            Self::SocksAuthenticationFailed => write!(f, "socks5 authentication failed"),
            Self::HttpProtocol(message) => write!(f, "invalid http proxy request: {message}"),
            Self::HttpAuthenticationFailed => write!(f, "http proxy authentication failed"),
            Self::HttpUnsupportedTarget(target) => {
                write!(f, "unsupported http proxy target: {target}")
            }
        }
    }
}

impl std::error::Error for ListenerRuntimeError {}

impl From<ParseMetadataError> for ListenerRuntimeError {
    fn from(value: ParseMetadataError) -> Self {
        Self::InvalidTarget(value)
    }
}

impl From<TcpForwardError> for ListenerRuntimeError {
    fn from(value: TcpForwardError) -> Self {
        Self::TcpForward(value)
    }
}

impl From<ExecutionError> for ListenerRuntimeError {
    fn from(value: ExecutionError) -> Self {
        Self::Connect(value)
    }
}

impl From<io::Error> for ListenerRuntimeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct PrefixedStream {
    prefix: Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
}

impl Read for PrefixedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.inner.read(buf)
    }
}

impl Write for PrefixedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for PrefixedStream {
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

pub fn build_tunnel_listener_specs(document: &RuntimeConfigDocument) -> Vec<TunnelListenerRuntimeSpec> {
    document
        .listeners
        .iter()
        .filter_map(|listener| match listener {
            InboundDefinition::Tunnel(config) => Some(TunnelListenerRuntimeSpec {
                name: config.base.name.clone(),
                addresses: config.base.raw_addresses(),
                target: config.target.clone(),
                supports_tcp: tunnel_network_supports(&config.network, "tcp"),
                supports_udp: tunnel_network_supports(&config.network, "udp"),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
            }),
            _ => None,
        })
        .collect()
}

pub fn build_redir_listener_specs(document: &RuntimeConfigDocument) -> Vec<RedirListenerRuntimeSpec> {
    document
        .listeners
        .iter()
        .filter_map(|listener| match listener {
            InboundDefinition::Redir(config) => Some(RedirListenerRuntimeSpec {
                name: config.base.name.clone(),
                addresses: config.base.raw_addresses(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
            }),
            _ => None,
        })
        .collect()
}

pub fn build_tproxy_listener_specs(document: &RuntimeConfigDocument) -> Vec<TProxyListenerRuntimeSpec> {
    document
        .listeners
        .iter()
        .filter_map(|listener| match listener {
            InboundDefinition::TProxy(config) => Some(TProxyListenerRuntimeSpec {
                name: config.base.name.clone(),
                addresses: config.base.raw_addresses(),
                supports_udp: config.udp,
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
            }),
            _ => None,
        })
        .collect()
}

pub fn build_socks_listener_specs(document: &RuntimeConfigDocument) -> Vec<SocksListenerRuntimeSpec> {
    document
        .listeners
        .iter()
        .filter_map(|listener| match listener {
            InboundDefinition::Socks(config) => Some(SocksListenerRuntimeSpec {
                name: config.base.name.clone(),
                addresses: config.base.raw_addresses(),
                supports_udp: config.udp,
                user_count: config.users.len(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
            }),
            _ => None,
        })
        .collect()
}

pub fn build_http_listener_specs(document: &RuntimeConfigDocument) -> Vec<HttpListenerRuntimeSpec> {
    document
        .listeners
        .iter()
        .filter_map(|listener| match listener {
            InboundDefinition::Http(config) => Some(HttpListenerRuntimeSpec {
                name: config.base.name.clone(),
                addresses: config.base.raw_addresses(),
                user_count: config.users.len(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
            }),
            _ => None,
        })
        .collect()
}

pub fn build_mixed_listener_specs(document: &RuntimeConfigDocument) -> Vec<MixedListenerRuntimeSpec> {
    document
        .listeners
        .iter()
        .filter_map(|listener| match listener {
            InboundDefinition::Mixed(config) => Some(MixedListenerRuntimeSpec {
                name: config.base.name.clone(),
                addresses: config.base.raw_addresses(),
                supports_udp: config.udp,
                user_count: config.users.len(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
            }),
            _ => None,
        })
        .collect()
}

pub fn prepare_tunnel_tcp_context(
    config: &TunnelInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<ConnectionContext, ListenerRuntimeError> {
    if !tunnel_network_supports(&config.network, "tcp") {
        let name = if config.base.name.is_empty() {
            "<unnamed>".to_owned()
        } else {
            config.base.name.clone()
        };
        return Err(ListenerRuntimeError::UnsupportedNetwork(name));
    }

    let mut metadata = Metadata::default();
    metadata.inbound_name = config.base.name.clone();
    metadata.special_proxy = config.base.special_proxy.clone();
    metadata.special_rules = config.base.special_rules.clone();
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata.set_remote_address(&config.target)?;
    Ok(ConnectionContext::new(stream, metadata))
}

pub fn prepare_redir_tcp_context(
    config: &RedirInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
) -> Result<ConnectionContext, ListenerRuntimeError> {
    Ok(prepare_transparent_tcp_context(
        SessionKind::Redir,
        &config.base.name,
        &config.base.special_proxy,
        &config.base.special_rules,
        stream,
        peer_addr,
        original_dst,
    ))
}

pub fn prepare_tproxy_tcp_context(
    config: &TProxyInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
) -> Result<ConnectionContext, ListenerRuntimeError> {
    Ok(prepare_transparent_tcp_context(
        SessionKind::TProxy,
        &config.base.name,
        &config.base.special_proxy,
        &config.base.special_rules,
        stream,
        peer_addr,
        original_dst,
    ))
}

pub fn prepare_http_proxy_tcp_context(
    config: &HttpInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<PreparedHttpProxyContext, ListenerRuntimeError> {
    let mut stream: BoxedTcpStream = Box::new(stream);
    let parsed = match read_http_proxy_request(&mut *stream) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = write_http_response(&mut *stream, "400 Bad Request", None);
            return Err(err);
        }
    };
    if let Err(err) = validate_http_proxy_auth(&parsed.headers, &config.users) {
        let _ = write_http_response(
            &mut *stream,
            "407 Proxy Authentication Required",
            Some("Proxy-Authenticate: Basic realm=\"mihomo-rust\""),
        );
        return Err(err);
    }

    let (target, mode, prefix, kind) = match build_http_proxy_route(&parsed) {
        Ok(route) => route,
        Err(err) => {
            let status = match err {
                ListenerRuntimeError::HttpUnsupportedTarget(_) => "400 Bad Request",
                _ => "400 Bad Request",
            };
            let _ = write_http_response(&mut *stream, status, None);
            return Err(err);
        }
    };

    let wrapped: BoxedTcpStream = if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedStream {
            prefix: Cursor::new(prefix),
            inner: stream,
        })
    };

    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind,
        inbound_name: config.base.name.clone(),
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata.set_remote_address(&target)?;
    Ok(PreparedHttpProxyContext {
        context: ConnectionContext::new(wrapped, metadata),
        mode,
    })
}

pub fn prepare_socks5_tcp_context(
    config: &TlsInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<ConnectionContext, ListenerRuntimeError> {
    match prepare_socks5_dispatch(config, stream, peer_addr)? {
        PreparedSocks5Dispatch::Connect(context) => Ok(context),
        PreparedSocks5Dispatch::UdpAssociate(_) => {
            Err(ListenerRuntimeError::SocksUnsupportedCommand(0x03))
        }
    }
}

pub fn prepare_socks5_udp_associate(
    config: &TlsInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<PreparedSocks5UdpAssociate, ListenerRuntimeError> {
    match prepare_socks5_dispatch(config, stream, peer_addr)? {
        PreparedSocks5Dispatch::UdpAssociate(associate) => Ok(associate),
        PreparedSocks5Dispatch::Connect(_) => {
            Err(ListenerRuntimeError::SocksUnsupportedCommand(0x01))
        }
    }
}

pub fn prepare_socks5_dispatch(
    config: &TlsInboundConfig,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<PreparedSocks5Dispatch, ListenerRuntimeError> {
    match prepare_socks5_request(config, stream)? {
        PreparedSocks5Request::Connect {
            stream,
            inbound_user,
            target,
        } => {
            let mut metadata = Metadata {
                network: NetworkKind::Tcp,
                kind: SessionKind::Socks5,
                inbound_name: config.base.name.clone(),
                inbound_user: inbound_user.unwrap_or_default(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                ..Metadata::default()
            };
            if let Some(peer) = peer_addr {
                metadata.src_ip = Some(peer.ip());
                metadata.src_port = Some(peer.port());
            }
            metadata.set_remote_address(&target)?;
            Ok(PreparedSocks5Dispatch::Connect(ConnectionContext::new(
                stream, metadata,
            )))
        }
        PreparedSocks5Request::UdpAssociate {
            stream,
            inbound_user,
            target,
        } => Ok(PreparedSocks5Dispatch::UdpAssociate(
            PreparedSocks5UdpAssociate {
                stream: Box::new(stream),
                inbound_name: config.base.name.clone(),
                inbound_user: inbound_user.unwrap_or_default(),
                special_proxy: config.base.special_proxy.clone(),
                special_rules: config.base.special_rules.clone(),
                requested_target: target,
            },
        )),
    }
}

pub fn dispatch_tunnel_tcp_stream(
    config: &TunnelInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    let mut context = prepare_tunnel_tcp_context(config, stream, peer_addr)?;
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)
}

pub fn dispatch_redir_tcp_stream(
    config: &RedirInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    dispatch_redir_tcp_stream_with_dialer(
        config,
        tunnel,
        stream,
        peer_addr,
        original_dst,
        mihomo_transport::SystemTcpDialer,
    )
}

pub fn dispatch_redir_tcp_stream_with_dialer<D>(
    config: &RedirInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let mut context = prepare_redir_tcp_context(config, stream, peer_addr, original_dst)?;
    tunnel
        .forward_tcp_context_with_dialer(&mut context, dialer)
        .map_err(ListenerRuntimeError::from)
}

pub fn dispatch_tproxy_tcp_stream(
    config: &TProxyInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    dispatch_tproxy_tcp_stream_with_dialer(
        config,
        tunnel,
        stream,
        peer_addr,
        original_dst,
        mihomo_transport::SystemTcpDialer,
    )
}

pub fn dispatch_tproxy_tcp_stream_with_dialer<D>(
    config: &TProxyInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let mut context = prepare_tproxy_tcp_context(config, stream, peer_addr, original_dst)?;
    tunnel
        .forward_tcp_context_with_dialer(&mut context, dialer)
        .map_err(ListenerRuntimeError::from)
}

pub fn dispatch_http_proxy_tcp_stream(
    config: &HttpInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    dispatch_http_proxy_tcp_stream_with_dialer(
        config,
        tunnel,
        stream,
        peer_addr,
        mihomo_transport::SystemTcpDialer,
    )
}

pub fn dispatch_http_proxy_tcp_stream_with_dialer<D>(
    config: &HttpInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let PreparedHttpProxyContext { mut context, mode } =
        prepare_http_proxy_tcp_context(config, stream, peer_addr)?;
    let (mut upstream, plan) = match tunnel.connect_tcp_with_dialer(context.metadata(), dialer) {
        Ok(result) => result,
        Err(err) => {
            let _ = write_http_response(&mut *context.stream_mut(), "502 Bad Gateway", None);
            return Err(ListenerRuntimeError::Connect(err));
        }
    };
    if mode == HttpProxyMode::Connect {
        write_http_response(
            &mut *context.stream_mut(),
            "200 Connection Established",
            Some("Proxy-Agent: mihomo-rust"),
        )?;
    }
    tunnel
        .relay_tcp_stream(&mut context, &mut *upstream, Some(&plan))
        .map_err(ListenerRuntimeError::Relay)
}

pub fn dispatch_mixed_tcp_stream(
    config: &TlsInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    dispatch_mixed_tcp_stream_with_dialer(
        config,
        tunnel,
        stream,
        peer_addr,
        mihomo_transport::SystemTcpDialer,
    )
}

pub fn dispatch_mixed_tcp_stream_with_dialer<D>(
    config: &TlsInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let mut stream: BoxedTcpStream = Box::new(stream);
    let first = read_u8(&mut *stream)?;
    let stream = prepend_stream(stream, vec![first]);

    if first == 0x05 {
        dispatch_socks5_tcp_stream_with_dialer(config, tunnel, stream, peer_addr, dialer)
    } else {
        let http_config = http_config_from_tls_config(config);
        dispatch_http_proxy_tcp_stream_with_dialer(&http_config, tunnel, stream, peer_addr, dialer)
    }
}

pub fn dispatch_socks5_tcp_stream(
    config: &TlsInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    dispatch_socks5_tcp_stream_with_dialer(
        config,
        tunnel,
        stream,
        peer_addr,
        mihomo_transport::SystemTcpDialer,
    )
}

pub fn dispatch_socks5_tcp_stream_with_dialer<D>(
    config: &TlsInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let mut context = prepare_socks5_tcp_context(config, stream, peer_addr)?;
    dispatch_prepared_socks5_tcp_context_with_dialer(tunnel, &mut context, dialer)
}

pub fn dispatch_prepared_socks5_tcp_context(
    tunnel: &RuntimeTunnel,
    context: &mut ConnectionContext,
) -> Result<TcpRelayStats, ListenerRuntimeError> {
    dispatch_prepared_socks5_tcp_context_with_dialer(
        tunnel,
        context,
        mihomo_transport::SystemTcpDialer,
    )
}

pub fn dispatch_prepared_socks5_tcp_context_with_dialer<D>(
    tunnel: &RuntimeTunnel,
    context: &mut ConnectionContext,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let (mut upstream, plan) = match tunnel.connect_tcp_with_dialer(context.metadata(), dialer) {
        Ok(result) => result,
        Err(err) => {
            let _ = write_socks5_connect_reply(context.stream_mut(), 0x01);
            return Err(ListenerRuntimeError::Connect(err));
        }
    };
    write_socks5_connect_reply(context.stream_mut(), 0x00)?;
    tunnel
        .relay_tcp_stream(context, &mut *upstream, Some(&plan))
        .map_err(ListenerRuntimeError::Relay)
}

pub fn dispatch_tunnel_tcp_stream_with_dialer<D>(
    config: &TunnelInboundConfig,
    tunnel: &RuntimeTunnel,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    dialer: D,
) -> Result<TcpRelayStats, ListenerRuntimeError>
where
    D: TcpDialer,
{
    let mut context = prepare_tunnel_tcp_context(config, stream, peer_addr)?;
    tunnel
        .forward_tcp_context_with_dialer(&mut context, dialer)
        .map_err(ListenerRuntimeError::from)
}

fn tunnel_network_supports(networks: &[String], wanted: &str) -> bool {
    if networks.is_empty() {
        return true;
    }
    networks.iter().any(|network| {
        let network = network.trim().to_ascii_lowercase();
        network == wanted || network == "all"
    })
}

fn prepare_transparent_tcp_context(
    kind: SessionKind,
    inbound_name: &str,
    special_proxy: &str,
    special_rules: &str,
    stream: impl TcpStream + 'static,
    peer_addr: Option<SocketAddr>,
    original_dst: SocketAddr,
) -> ConnectionContext {
    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind,
        inbound_name: inbound_name.to_owned(),
        special_proxy: special_proxy.to_owned(),
        special_rules: special_rules.to_owned(),
        dst_ip: Some(original_dst.ip()),
        dst_port: Some(original_dst.port()),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    ConnectionContext::new(stream, metadata)
}

fn read_http_proxy_request(
    stream: &mut (impl Read + Write + ?Sized),
) -> Result<ParsedHttpProxyRequest, ListenerRuntimeError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(ListenerRuntimeError::HttpProtocol(
                "client closed before request headers completed".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            return parse_http_proxy_request(&buffer, position + 4);
        }
        if buffer.len() > 64 * 1024 {
            return Err(ListenerRuntimeError::HttpProtocol(
                "request headers exceeded 64KiB".to_owned(),
            ));
        }
    }
}

fn parse_http_proxy_request(
    buffer: &[u8],
    header_end: usize,
) -> Result<ParsedHttpProxyRequest, ListenerRuntimeError> {
    let text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ListenerRuntimeError::HttpProtocol("missing request line".to_owned()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ListenerRuntimeError::HttpProtocol("missing method".to_owned()))?;
    let target = parts
        .next()
        .ok_or_else(|| ListenerRuntimeError::HttpProtocol("missing request target".to_owned()))?;
    let version = parts
        .next()
        .ok_or_else(|| ListenerRuntimeError::HttpProtocol("missing http version".to_owned()))?;
    if !version.starts_with("HTTP/") {
        return Err(ListenerRuntimeError::HttpProtocol(format!(
            "unexpected http version {version}"
        )));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ListenerRuntimeError::HttpProtocol(format!(
                "invalid header line {line:?}"
            )));
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    Ok(ParsedHttpProxyRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        remainder: buffer[header_end..].to_vec(),
    })
}

fn validate_http_proxy_auth(
    headers: &[(String, String)],
    users: &[AuthUser],
) -> Result<Option<String>, ListenerRuntimeError> {
    if users.is_empty() {
        return Ok(None);
    }
    let Some(value) = header_value(headers, "Proxy-Authorization") else {
        return Err(ListenerRuntimeError::HttpAuthenticationFailed);
    };
    let Some(raw_basic) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return Err(ListenerRuntimeError::HttpAuthenticationFailed);
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_basic)
        .map_err(|_| ListenerRuntimeError::HttpAuthenticationFailed)?;
    let decoded = String::from_utf8_lossy(&decoded);
    let Some((username, password)) = decoded.split_once(':') else {
        return Err(ListenerRuntimeError::HttpAuthenticationFailed);
    };
    if users
        .iter()
        .any(|user| user.username == username && user.password == password)
    {
        Ok(Some(username.to_owned()))
    } else {
        Err(ListenerRuntimeError::HttpAuthenticationFailed)
    }
}

fn build_http_proxy_route(
    request: &ParsedHttpProxyRequest,
) -> Result<(String, HttpProxyMode, Vec<u8>, SessionKind), ListenerRuntimeError> {
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return Ok((
            request.target.clone(),
            HttpProxyMode::Connect,
            request.remainder.clone(),
            SessionKind::Https,
        ));
    }

    let (target, path) = if let Some(rest) = request.target.strip_prefix("http://") {
        parse_http_absolute_target(rest)?
    } else if request.target.starts_with('/') || request.target == "*" {
        let host = header_value(&request.headers, "Host").ok_or_else(|| {
            ListenerRuntimeError::HttpProtocol("missing Host header".to_owned())
        })?;
        (
            format_target_address_from_authority(host, 80)?,
            request.target.clone(),
        )
    } else {
        return Err(ListenerRuntimeError::HttpUnsupportedTarget(
            request.target.clone(),
        ));
    };

    Ok((
        target,
        HttpProxyMode::Forward,
        build_forward_http_request(request, &path),
        SessionKind::Http,
    ))
}

fn parse_http_absolute_target(rest: &str) -> Result<(String, String), ListenerRuntimeError> {
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let target = format_target_address_from_authority(authority, 80)?;
    Ok((target, path.to_owned()))
}

fn format_target_address_from_authority(
    authority: &str,
    default_port: u16,
) -> Result<String, ListenerRuntimeError> {
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some((host, port)) = stripped.split_once("]:") {
            return Ok(format!("[{host}]:{port}"));
        }
        return Ok(format!("[{stripped}]:{default_port}"));
    }
    if authority.rsplit_once(':').is_some() {
        Ok(authority.to_owned())
    } else {
        Ok(format!("{authority}:{default_port}"))
    }
}

fn build_forward_http_request(request: &ParsedHttpProxyRequest, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(
        format!("{} {} {}\r\n", request.method, path, request.version).as_bytes(),
    );
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        payload.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    payload.extend_from_slice(b"\r\n");
    payload.extend_from_slice(&request.remainder);
    payload
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
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

fn prepend_stream(stream: BoxedTcpStream, prefix: Vec<u8>) -> BoxedTcpStream {
    if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedStream {
            prefix: Cursor::new(prefix),
            inner: stream,
        })
    }
}

fn write_http_response(
    stream: &mut dyn Write,
    status: &str,
    extra_header: Option<&str>,
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\n")?;
    if let Some(header) = extra_header {
        write!(stream, "{header}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.flush()
}

fn negotiate_socks5(
    stream: &mut (impl Read + Write),
    users: &[AuthUser],
) -> Result<Option<String>, ListenerRuntimeError> {
    let version = read_u8(stream)?;
    if version != 0x05 {
        return Err(ListenerRuntimeError::SocksProtocol(format!(
            "unexpected version {version}"
        )));
    }
    let method_count = read_u8(stream)? as usize;
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods)?;

    if users.is_empty() {
        if methods.contains(&0x00) {
            stream.write_all(&[0x05, 0x00])?;
            stream.flush()?;
            Ok(None)
        } else {
            stream.write_all(&[0x05, 0xff])?;
            stream.flush()?;
            Err(ListenerRuntimeError::SocksProtocol(
                "client did not offer no-auth method".to_owned(),
            ))
        }
    } else if methods.contains(&0x02) {
        stream.write_all(&[0x05, 0x02])?;
        stream.flush()?;
        authenticate_socks5_user(stream, users)
    } else {
        stream.write_all(&[0x05, 0xff])?;
        stream.flush()?;
        Err(ListenerRuntimeError::SocksAuthenticationFailed)
    }
}

fn authenticate_socks5_user(
    stream: &mut (impl Read + Write),
    users: &[AuthUser],
) -> Result<Option<String>, ListenerRuntimeError> {
    let version = read_u8(stream)?;
    if version != 0x01 {
        return Err(ListenerRuntimeError::SocksProtocol(format!(
            "unexpected auth version {version}"
        )));
    }
    let username_len = read_u8(stream)? as usize;
    let username = read_string(stream, username_len)?;
    let password_len = read_u8(stream)? as usize;
    let password = read_string(stream, password_len)?;

    if users
        .iter()
        .any(|user| user.username == username && user.password == password)
    {
        stream.write_all(&[0x01, 0x00])?;
        stream.flush()?;
        Ok(Some(username))
    } else {
        stream.write_all(&[0x01, 0x01])?;
        stream.flush()?;
        Err(ListenerRuntimeError::SocksAuthenticationFailed)
    }
}

pub fn write_socks5_udp_associate_reply(
    stream: &mut (impl Write + ?Sized),
    bind_addr: SocketAddr,
) -> io::Result<()> {
    write_socks5_reply(stream, 0x00, Some(bind_addr))
}

struct Socks5Request {
    command: u8,
    target: String,
}

enum PreparedSocks5Request<S> {
    Connect {
        stream: S,
        inbound_user: Option<String>,
        target: String,
    },
    UdpAssociate {
        stream: S,
        inbound_user: Option<String>,
        target: String,
    },
}

fn prepare_socks5_request<S>(
    config: &TlsInboundConfig,
    mut stream: S,
) -> Result<PreparedSocks5Request<S>, ListenerRuntimeError>
where
    S: TcpStream + 'static,
{
    let inbound_user = negotiate_socks5(&mut stream, &config.users)?;
    let request = read_socks5_request(&mut stream)?;
    match request.command {
        0x01 => Ok(PreparedSocks5Request::Connect {
            stream,
            inbound_user,
            target: request.target,
        }),
        0x03 => Ok(PreparedSocks5Request::UdpAssociate {
            stream,
            inbound_user,
            target: request.target,
        }),
        other => {
            let _ = write_socks5_reply(&mut stream, 0x07, None);
            Err(ListenerRuntimeError::SocksUnsupportedCommand(other))
        }
    }
}

fn read_socks5_request(
    stream: &mut (impl Read + Write),
) -> Result<Socks5Request, ListenerRuntimeError> {
    let version = read_u8(stream)?;
    let command = read_u8(stream)?;
    let _reserved = read_u8(stream)?;
    let atyp = read_u8(stream)?;

    if version != 0x05 {
        return Err(ListenerRuntimeError::SocksProtocol(format!(
            "unexpected request version {version}"
        )));
    }

    let host = match atyp {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets)?;
            IpAddr::from(octets).to_string()
        }
        0x03 => {
            let length = read_u8(stream)? as usize;
            read_string(stream, length)?
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets)?;
            IpAddr::from(octets).to_string()
        }
        other => {
            let _ = write_socks5_connect_reply(stream, 0x08);
            return Err(ListenerRuntimeError::SocksProtocol(format!(
                "unsupported address type {other}"
            )));
        }
    };
    let port = read_u16(stream)?;
    Ok(Socks5Request {
        command,
        target: format_target_address(&host, port),
    })
}

fn write_socks5_connect_reply(stream: &mut (impl Write + ?Sized), status: u8) -> io::Result<()> {
    write_socks5_reply(stream, status, None)
}

fn write_socks5_reply(
    stream: &mut (impl Write + ?Sized),
    status: u8,
    bind_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let mut payload = Vec::with_capacity(32);
    payload.extend_from_slice(&[0x05, status, 0x00]);
    match bind_addr {
        Some(SocketAddr::V4(addr)) => {
            payload.push(0x01);
            payload.extend_from_slice(&addr.ip().octets());
            payload.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            payload.push(0x04);
            payload.extend_from_slice(&addr.ip().octets());
            payload.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => payload.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]),
    }
    stream.write_all(&payload)?;
    stream.flush()
}

fn read_u8(stream: &mut (impl Read + ?Sized)) -> io::Result<u8> {
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_u16(stream: &mut (impl Read + ?Sized)) -> io::Result<u16> {
    let mut bytes = [0_u8; 2];
    stream.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_string(stream: &mut (impl Read + ?Sized), length: usize) -> io::Result<String> {
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn format_target_address(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

struct ParsedHttpProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    remainder: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{BoxedTcpStream, SessionKind};
    use mihomo_inbound::InboundDefinition;
    use mihomo_transport::{SocketOptions, TcpDialPurpose, TcpDialer, TransportError, TransportTarget};

    use crate::build_runtime_registry;

    use super::{
        build_http_listener_specs, build_mixed_listener_specs, build_socks_listener_specs,
        build_redir_listener_specs, build_tproxy_listener_specs, build_tunnel_listener_specs,
        dispatch_http_proxy_tcp_stream_with_dialer, dispatch_redir_tcp_stream_with_dialer,
        dispatch_mixed_tcp_stream_with_dialer, dispatch_socks5_tcp_stream_with_dialer,
        dispatch_tproxy_tcp_stream_with_dialer, dispatch_tunnel_tcp_stream_with_dialer,
        prepare_http_proxy_tcp_context, prepare_redir_tcp_context, prepare_socks5_tcp_context,
        prepare_tproxy_tcp_context, prepare_tunnel_tcp_context, HttpProxyMode,
        ListenerRuntimeError,
    };

    #[derive(Default)]
    struct SharedStreamState {
        reader: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    #[derive(Clone)]
    struct SharedStreamHandle(Arc<Mutex<SharedStreamState>>);

    impl SharedStreamHandle {
        fn new(readable: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(SharedStreamState {
                reader: Cursor::new(readable),
                written: Vec::new(),
            })))
        }

        fn stream(&self) -> SharedStream {
            SharedStream(Arc::clone(&self.0))
        }

        fn written(&self) -> Vec<u8> {
            self.0.lock().unwrap().written.clone()
        }
    }

    struct SharedStream(Arc<Mutex<SharedStreamState>>);

    impl Read for SharedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().reader.read(buf)
        }
    }

    impl Write for SharedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for SharedStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(SharedStream(Arc::clone(&self.0))))
        }
    }

    struct FakeDialer {
        expected: VecDeque<(String, SharedStreamHandle)>,
    }

    impl FakeDialer {
        fn new() -> Self {
            Self {
                expected: VecDeque::new(),
            }
        }

        fn push_connection(
            &mut self,
            authority: impl Into<String>,
            readable: Vec<u8>,
        ) -> SharedStreamHandle {
            let handle = SharedStreamHandle::new(readable);
            self.expected.push_back((authority.into(), handle.clone()));
            handle
        }
    }

    impl TcpDialer for FakeDialer {
        fn connect(
            &mut self,
            target: &TransportTarget,
            _socket: &SocketOptions,
            _purpose: TcpDialPurpose,
        ) -> Result<BoxedTcpStream, TransportError> {
            let Some((expected, handle)) = self.expected.pop_front() else {
                return Err(TransportError::InvalidPlan(
                    "unexpected listener runtime dial".to_owned(),
                ));
            };
            if expected != target.authority() {
                return Err(TransportError::InvalidPlan(format!(
                    "expected dial {expected} but got {}",
                    target.authority()
                )));
            }
            Ok(Box::new(handle.stream()))
        }
    }

    #[test]
    fn build_tunnel_specs_extracts_runtime_surface() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: tunnel
    name: edge
    listen: 127.0.0.1
    port: "7000-7001"
    target: example.com:443
    network: [tcp, udp]
    proxy: selector
    rule: custom
"#,
        )
        .unwrap();
        let specs = build_tunnel_listener_specs(&document);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "edge");
        assert_eq!(specs[0].addresses, vec!["127.0.0.1:7000", "127.0.0.1:7001"]);
        assert!(specs[0].supports_tcp);
        assert!(specs[0].supports_udp);
        assert_eq!(specs[0].special_proxy, "selector");
        assert_eq!(specs[0].special_rules, "custom");
    }

    #[test]
    fn build_redir_specs_extract_runtime_surface() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: redir
    name: edge
    listen: 127.0.0.1
    port: "7892"
    proxy: selector
    rule: custom
"#,
        )
        .unwrap();
        let specs = build_redir_listener_specs(&document);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "edge");
        assert_eq!(specs[0].addresses, vec!["127.0.0.1:7892"]);
        assert_eq!(specs[0].special_proxy, "selector");
        assert_eq!(specs[0].special_rules, "custom");
    }

    #[test]
    fn build_tproxy_specs_extract_runtime_surface() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: tproxy
    name: edge
    listen: 0.0.0.0
    port: "7893"
    proxy: selector
"#,
        )
        .unwrap();
        let specs = build_tproxy_listener_specs(&document);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "edge");
        assert_eq!(specs[0].addresses, vec!["0.0.0.0:7893"]);
        assert!(specs[0].supports_udp);
        assert_eq!(specs[0].special_proxy, "selector");
    }

    #[test]
    fn build_socks_specs_extract_runtime_surface() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: socks
    name: edge
    listen: 127.0.0.1
    port: "1080"
    proxy: selector
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let specs = build_socks_listener_specs(&document);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "edge");
        assert_eq!(specs[0].addresses, vec!["127.0.0.1:1080"]);
        assert!(specs[0].supports_udp);
        assert_eq!(specs[0].user_count, 1);
        assert_eq!(specs[0].special_proxy, "selector");
    }

    #[test]
    fn build_http_specs_extract_runtime_surface() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: http
    name: edge
    listen: 127.0.0.1
    port: "8080"
    proxy: selector
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let specs = build_http_listener_specs(&document);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "edge");
        assert_eq!(specs[0].addresses, vec!["127.0.0.1:8080"]);
        assert_eq!(specs[0].user_count, 1);
        assert_eq!(specs[0].special_proxy, "selector");
    }

    #[test]
    fn build_mixed_specs_extract_runtime_surface() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: mixed
    name: edge
    listen: 127.0.0.1
    port: "7890"
    proxy: selector
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let specs = build_mixed_listener_specs(&document);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "edge");
        assert_eq!(specs[0].addresses, vec!["127.0.0.1:7890"]);
        assert!(specs[0].supports_udp);
        assert_eq!(specs[0].user_count, 1);
        assert_eq!(specs[0].special_proxy, "selector");
    }

    #[test]
    fn prepare_tunnel_context_maps_listener_target_and_source() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: tunnel
    name: edge
    target: example.com:443
    proxy: selector
"#,
        )
        .unwrap();
        let InboundDefinition::Tunnel(config) = &document.listeners[0] else {
            panic!("expected tunnel listener");
        };
        let peer: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let context =
            prepare_tunnel_tcp_context(config, SharedStreamHandle::new(Vec::new()).stream(), Some(peer))
                .unwrap();
        assert_eq!(context.metadata().host.as_deref(), Some("example.com"));
        assert_eq!(context.metadata().dst_port, Some(443));
        assert_eq!(context.metadata().src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(context.metadata().src_port, Some(50000));
        assert_eq!(context.metadata().special_proxy, "selector");
    }

    #[test]
    fn prepare_redir_context_maps_original_destination() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: redir
    name: edge
    proxy: selector
"#,
        )
        .unwrap();
        let InboundDefinition::Redir(config) = &document.listeners[0] else {
            panic!("expected redir listener");
        };
        let peer: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let original_dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let context = prepare_redir_tcp_context(
            config,
            SharedStreamHandle::new(Vec::new()).stream(),
            Some(peer),
            original_dst,
        )
        .unwrap();
        assert_eq!(context.metadata().kind, SessionKind::Redir);
        assert_eq!(context.metadata().dst_ip, Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert_eq!(context.metadata().dst_port, Some(443));
        assert_eq!(context.metadata().src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(context.metadata().special_proxy, "selector");
    }

    #[test]
    fn prepare_tproxy_context_maps_original_destination() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: tproxy
    name: edge
    proxy: selector
"#,
        )
        .unwrap();
        let InboundDefinition::TProxy(config) = &document.listeners[0] else {
            panic!("expected tproxy listener");
        };
        let original_dst: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let context = prepare_tproxy_tcp_context(
            config,
            SharedStreamHandle::new(Vec::new()).stream(),
            None,
            original_dst,
        )
        .unwrap();
        assert_eq!(context.metadata().kind, SessionKind::TProxy);
        assert_eq!(context.metadata().dst_ip, Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert_eq!(context.metadata().dst_port, Some(80));
    }

    #[test]
    fn prepare_socks5_context_maps_request_without_auth() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: socks
    name: edge
    port: "1080"
"#,
        )
        .unwrap();
        let InboundDefinition::Socks(config) = &document.listeners[0] else {
            panic!("expected socks listener");
        };
        let inbound = SharedStreamHandle::new(
            [
                vec![0x05, 0x01, 0x00], // greeting
                vec![
                    0x05, 0x01, 0x00, 0x03, 11, // request + domain len
                ],
                b"example.com".to_vec(),
                443_u16.to_be_bytes().to_vec(),
            ]
            .concat(),
        );
        let context = prepare_socks5_tcp_context(
            config,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(context.metadata().kind, SessionKind::Socks5);
        assert_eq!(context.metadata().host.as_deref(), Some("example.com"));
        assert_eq!(context.metadata().dst_port, Some(443));
        assert_eq!(context.metadata().src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(inbound.written(), vec![0x05, 0x00]);
    }

    #[test]
    fn prepare_socks5_context_authenticates_user() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: socks
    name: edge
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let InboundDefinition::Socks(config) = &document.listeners[0] else {
            panic!("expected socks listener");
        };
        let inbound = SharedStreamHandle::new(
            [
                vec![0x05, 0x02, 0x00, 0x02], // greeting with no-auth + user/pass
                vec![0x01, 0x04],
                b"user".to_vec(),
                vec![0x04],
                b"pass".to_vec(),
                vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4],
                8080_u16.to_be_bytes().to_vec(),
            ]
            .concat(),
        );
        let context = prepare_socks5_tcp_context(config, inbound.stream(), None).unwrap();
        assert_eq!(context.metadata().dst_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(context.metadata().dst_port, Some(8080));
        assert_eq!(context.metadata().inbound_user, "user");
        assert_eq!(inbound.written(), vec![0x05, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn prepare_http_proxy_context_maps_connect_request() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: http
    name: edge
    port: "8080"
"#,
        )
        .unwrap();
        let InboundDefinition::Http(config) = &document.listeners[0] else {
            panic!("expected http listener");
        };
        let inbound = SharedStreamHandle::new(
            b"CONNECT final.example.com:443 HTTP/1.1\r\nHost: final.example.com:443\r\n\r\n"
                .to_vec(),
        );
        let prepared = prepare_http_proxy_tcp_context(
            config,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(prepared.mode, HttpProxyMode::Connect);
        assert_eq!(prepared.context.metadata().kind, SessionKind::Https);
        assert_eq!(prepared.context.metadata().host.as_deref(), Some("final.example.com"));
        assert_eq!(prepared.context.metadata().dst_port, Some(443));
        assert_eq!(prepared.context.metadata().src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn prepare_http_proxy_context_rewrites_absolute_uri_and_strips_proxy_auth() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: http
    name: edge
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let InboundDefinition::Http(config) = &document.listeners[0] else {
            panic!("expected http listener");
        };
        let inbound = SharedStreamHandle::new(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Connection: keep-alive\r\n\r\nbody"
                .to_vec(),
        );
        let mut prepared = prepare_http_proxy_tcp_context(config, inbound.stream(), None).unwrap();
        assert_eq!(prepared.mode, HttpProxyMode::Forward);
        assert_eq!(prepared.context.metadata().kind, SessionKind::Http);
        assert_eq!(prepared.context.metadata().host.as_deref(), Some("example.com"));
        assert_eq!(prepared.context.metadata().dst_port, Some(80));
        let mut replay = Vec::new();
        prepared.context.stream_mut().read_to_end(&mut replay).unwrap();
        let replay = String::from_utf8(replay).unwrap();
        assert!(replay.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(replay.contains("Host: example.com\r\n"));
        assert!(!replay.contains("Proxy-Authorization"));
        assert!(!replay.contains("Proxy-Connection"));
        assert!(replay.ends_with("body"));
    }

    #[test]
    fn dispatch_tunnel_stream_forwards_via_runtime_tunnel() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: tunnel
    name: edge
    target: final.example.com:443
    proxy: special
    network: [tcp]
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Tunnel(config) = &document.listeners[0] else {
            panic!("expected tunnel listener");
        };
        let inbound = SharedStreamHandle::new(b"client-data".to_vec());
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_tunnel_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        assert_eq!(stats.right_to_left, b"server-data".len() as u64);
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert!(inbound.written().ends_with(b"server-data"));
    }

    #[test]
    fn dispatch_redir_stream_forwards_via_runtime_tunnel() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: redir
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Redir(config) = &document.listeners[0] else {
            panic!("expected redir listener");
        };
        let inbound = SharedStreamHandle::new(b"client-data".to_vec());
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_redir_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            "93.184.216.34:443".parse().unwrap(),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
        assert!(inbound.written().ends_with(b"server-data"));
    }

    #[test]
    fn dispatch_tproxy_stream_forwards_via_runtime_tunnel() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: tproxy
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::TProxy(config) = &document.listeners[0] else {
            panic!("expected tproxy listener");
        };
        let inbound = SharedStreamHandle::new(b"client-data".to_vec());
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_tproxy_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            "93.184.216.34:80".parse().unwrap(),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT 93.184.216.34:80 HTTP/1.1\r\n"));
        assert!(inbound.written().ends_with(b"server-data"));
    }

    #[test]
    fn dispatch_socks5_stream_forwards_after_connect_reply() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: socks
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Socks(config) = &document.listeners[0] else {
            panic!("expected socks listener");
        };
        let inbound = SharedStreamHandle::new(
            [
                vec![0x05, 0x01, 0x00],
                vec![0x05, 0x01, 0x00, 0x03, 17],
                b"final.example.com".to_vec(),
                443_u16.to_be_bytes().to_vec(),
                b"client-data".to_vec(),
            ]
            .concat(),
        );
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_socks5_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        assert_eq!(stats.right_to_left, b"server-data".len() as u64);
        assert_eq!(
            &inbound.written()[..12],
            &[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert!(upstream_writes.ends_with("client-data"));
        assert!(inbound.written().ends_with(b"server-data"));
    }

    #[test]
    fn dispatch_http_connect_stream_forwards_after_success_response() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: http
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Http(config) = &document.listeners[0] else {
            panic!("expected http listener");
        };
        let inbound = SharedStreamHandle::new(
            b"CONNECT final.example.com:443 HTTP/1.1\r\nHost: final.example.com:443\r\n\r\nclient-data"
                .to_vec(),
        );
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_http_proxy_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        assert_eq!(stats.right_to_left, b"server-data".len() as u64);
        assert!(String::from_utf8(inbound.written()).unwrap().starts_with(
            "HTTP/1.1 200 Connection Established\r\nProxy-Agent: mihomo-rust\r\n\r\n"
        ));
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert!(upstream_writes.ends_with("client-data"));
    }

    #[test]
    fn dispatch_http_forward_stream_rewrites_request_before_relay() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: http
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Http(config) = &document.listeners[0] else {
            panic!("expected http listener");
        };
        let inbound = SharedStreamHandle::new(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\nclient-body"
                .to_vec(),
        );
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_http_proxy_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            None,
            dialer,
        )
        .unwrap();

        assert_eq!(stats.right_to_left, b"server-data".len() as u64);
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT example.com:80 HTTP/1.1\r\n"));
        assert!(upstream_writes.contains("GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\nclient-body"));
    }

    #[test]
    fn dispatch_mixed_stream_routes_socks5_by_first_byte() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: mixed
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Mixed(config) = &document.listeners[0] else {
            panic!("expected mixed listener");
        };
        let inbound = SharedStreamHandle::new(
            [
                vec![0x05, 0x01, 0x00],
                vec![0x05, 0x01, 0x00, 0x03, 17],
                b"final.example.com".to_vec(),
                443_u16.to_be_bytes().to_vec(),
                b"client-data".to_vec(),
            ]
            .concat(),
        );
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_mixed_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        assert_eq!(
            &inbound.written()[..12],
            &[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT final.example.com:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn dispatch_mixed_stream_routes_http_when_not_socks5() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
listeners:
  - type: mixed
    name: edge
    proxy: special
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = crate::RuntimeTunnel::new(document.mode.clone(), registry);
        let InboundDefinition::Mixed(config) = &document.listeners[0] else {
            panic!("expected mixed listener");
        };
        let inbound = SharedStreamHandle::new(
            b"CONNECT final.example.com:443 HTTP/1.1\r\nHost: final.example.com:443\r\n\r\nclient-data"
                .to_vec(),
        );
        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );

        let stats = dispatch_mixed_tcp_stream_with_dialer(
            config,
            &tunnel,
            inbound.stream(),
            Some("10.0.0.2:50000".parse().unwrap()),
            dialer,
        )
        .unwrap();

        assert_eq!(stats.left_to_right, b"client-data".len() as u64);
        assert!(String::from_utf8(inbound.written()).unwrap().starts_with(
            "HTTP/1.1 200 Connection Established\r\nProxy-Agent: mihomo-rust\r\n\r\n"
        ));
        let upstream_writes = String::from_utf8(upstream.written()).unwrap();
        assert!(upstream_writes.contains("CONNECT final.example.com:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn prepare_tunnel_context_rejects_tcp_when_network_excludes_it() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: tunnel
    name: udp-only
    target: example.com:53
    network: [udp]
"#,
        )
        .unwrap();
        let InboundDefinition::Tunnel(config) = &document.listeners[0] else {
            panic!("expected tunnel listener");
        };
        let err = match prepare_tunnel_tcp_context(
            config,
            SharedStreamHandle::new(Vec::new()).stream(),
            None,
        ) {
            Ok(_) => panic!("expected unsupported tcp network"),
            Err(err) => err,
        };
        assert!(matches!(err, ListenerRuntimeError::UnsupportedNetwork(_)));
    }

    #[test]
    fn prepare_socks5_context_rejects_when_auth_method_is_missing() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: socks
    name: edge
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let InboundDefinition::Socks(config) = &document.listeners[0] else {
            panic!("expected socks listener");
        };
        let inbound = SharedStreamHandle::new(vec![0x05, 0x01, 0x00]);
        let err = match prepare_socks5_tcp_context(config, inbound.stream(), None) {
            Ok(_) => panic!("expected socks auth failure"),
            Err(err) => err,
        };
        assert!(matches!(err, ListenerRuntimeError::SocksAuthenticationFailed));
        assert_eq!(inbound.written(), vec![0x05, 0xff]);
    }

    #[test]
    fn prepare_http_proxy_context_rejects_missing_auth() {
        let document = parse_runtime_config_document(
            r#"
listeners:
  - type: http
    name: edge
    users:
      - username: user
        password: pass
"#,
        )
        .unwrap();
        let InboundDefinition::Http(config) = &document.listeners[0] else {
            panic!("expected http listener");
        };
        let inbound = SharedStreamHandle::new(
            b"CONNECT final.example.com:443 HTTP/1.1\r\nHost: final.example.com:443\r\n\r\n"
                .to_vec(),
        );
        let err = match prepare_http_proxy_tcp_context(config, inbound.stream(), None) {
            Ok(_) => panic!("expected http auth failure"),
            Err(err) => err,
        };
        assert!(matches!(err, ListenerRuntimeError::HttpAuthenticationFailed));
        let written = String::from_utf8(inbound.written()).unwrap();
        assert!(written.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(written.contains("Proxy-Authenticate: Basic realm=\"mihomo-rust\"\r\n"));
    }
}
