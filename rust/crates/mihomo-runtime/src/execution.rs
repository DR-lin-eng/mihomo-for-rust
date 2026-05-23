use std::collections::BTreeMap;

use mihomo_core::{BoxedTcpStream, Metadata};
use mihomo_outbound::{OutboundDefinition, OutboundKind, ProxyBaseConfig};
use mihomo_transport::{
    BasicAuth as TransportBasicAuth, SocketOptions as TransportSocketOptions,
    GrpcOptions as TransportGrpcOptions,
    Http2Options as TransportHttp2Options,
    HttpStreamOptions as TransportHttpStreamOptions,
    TcpDialer, TcpTransportExecutor, TlsOptions as TransportTlsOptions,
    TransportAction, TransportError, TransportHop, TransportPlan, TransportPlanRunner,
    TransportTarget, TrojanShadowsocksOptions as TransportTrojanShadowsocksOptions,
    WebsocketOptions as TransportWebsocketOptions,
    XHttpOptions as TransportXHttpOptions,
};
use serde_yaml::Value;

use crate::{resolve_proxy_path, CandidateState, ProxySource, ResolveError, RuntimeRegistry};

const DEFAULT_TROJAN_ALPN: &[&str] = &["h2", "http/1.1"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketOptions {
    pub tfo: bool,
    pub mptcp: bool,
    pub interface_name: String,
    pub routing_mark: i32,
    pub ip_version: String,
    pub smux_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsOptions {
    pub enabled: bool,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectHopSpec {
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectHopSpec {
    pub drop: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHopSpec {
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub auth: Option<BasicAuth>,
    pub tls: TlsOptions,
    pub headers: BTreeMap<String, String>,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5ConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub auth: Option<BasicAuth>,
    pub tls: TlsOptions,
    pub udp: bool,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    pub alpn: Vec<String>,
    pub tls: TlsOptions,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowSocksConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub plugin: String,
    pub plugin_mode: String,
    pub plugin_host: String,
    pub websocket: TransportWebsocketOptions,
    pub tls: TlsOptions,
    pub mux: bool,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsrConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub obfs: String,
    pub obfs_param: String,
    pub protocol: String,
    pub protocol_param: String,
    pub udp: bool,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnellConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub version: u8,
    pub obfs_mode: String,
    pub obfs_host: String,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub shadowsocks: TransportTrojanShadowsocksOptions,
    pub udp: bool,
    pub network: String,
    pub websocket: TransportWebsocketOptions,
    pub grpc: TransportGrpcOptions,
    pub http: TransportHttpStreamOptions,
    pub alpn: Vec<String>,
    pub tls: TlsOptions,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustTunnelConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub udp: bool,
    pub quic: bool,
    pub alpn: Vec<String>,
    pub tls: TlsOptions,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub flow: String,
    pub udp: bool,
    pub network: String,
    pub websocket: TransportWebsocketOptions,
    pub grpc: TransportGrpcOptions,
    pub h2: TransportHttp2Options,
    pub http: TransportHttpStreamOptions,
    pub xhttp: TransportXHttpOptions,
    pub encryption: String,
    pub packet_addr: bool,
    pub xudp: bool,
    pub tls: TlsOptions,
    pub alpn: Vec<String>,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u16,
    pub cipher: String,
    pub udp: bool,
    pub network: String,
    pub websocket: TransportWebsocketOptions,
    pub grpc: TransportGrpcOptions,
    pub h2: TransportHttp2Options,
    pub http: TransportHttpStreamOptions,
    pub xhttp: TransportXHttpOptions,
    pub packet_addr: bool,
    pub xudp: bool,
    pub global_padding: bool,
    pub authenticated_length: bool,
    pub tls: TlsOptions,
    pub alpn: Vec<String>,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GostRelayHopSpec {
    pub server: String,
    pub port: u16,
    pub auth: Option<BasicAuth>,
    pub forward: bool,
    pub tls: TlsOptions,
    pub mux: bool,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub private_key: String,
    pub private_key_passphrase: String,
    pub host_keys: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SudokuConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub key: String,
    pub aead_method: String,
    pub table_type: String,
    pub padding_min: i32,
    pub padding_max: i32,
    pub enable_pure_downlink: bool,
    pub http_mask_enabled: bool,
    pub http_mask_mode: String,
    pub http_mask_tls: bool,
    pub http_mask_host: String,
    pub path_root: String,
    pub custom_table: String,
    pub custom_tables: Vec<String>,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedHopSpec {
    pub name: String,
    pub kind: Option<OutboundKind>,
    pub endpoint: Option<TransportTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionHopSpec {
    Direct(DirectHopSpec),
    Reject(RejectHopSpec),
    Dns(DnsHopSpec),
    HttpConnect(HttpConnectHopSpec),
    Socks5Connect(Socks5ConnectHopSpec),
    AnyTls(AnyTlsConnectHopSpec),
    ShadowSocks(ShadowSocksConnectHopSpec),
    Ssr(SsrConnectHopSpec),
    Snell(SnellConnectHopSpec),
    Trojan(TrojanConnectHopSpec),
    TrustTunnel(TrustTunnelConnectHopSpec),
    Vless(VlessConnectHopSpec),
    Vmess(VmessConnectHopSpec),
    GostRelay(GostRelayHopSpec),
    Sudoku(SudokuConnectHopSpec),
    Ssh(SshConnectHopSpec),
    Unsupported(UnsupportedHopSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionHop {
    pub name: String,
    pub kind: Option<OutboundKind>,
    pub source: ProxySource,
    pub spec: ExecutionHopSpec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPlan {
    pub requested: String,
    pub selected_path: Vec<String>,
    pub leaf_name: String,
    pub dial_chain: Vec<String>,
    pub hops: Vec<ExecutionHop>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    Resolve(ResolveError),
    MissingProxyDefinition(String),
    Transport(TransportError),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(err) => write!(f, "{err}"),
            Self::MissingProxyDefinition(name) => {
                write!(f, "missing proxy definition for execution: {name}")
            }
            Self::Transport(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<ResolveError> for ExecutionError {
    fn from(value: ResolveError) -> Self {
        Self::Resolve(value)
    }
}

impl From<TransportError> for ExecutionError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

pub fn build_execution_plan(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: Option<&Metadata>,
    states: &BTreeMap<String, CandidateState>,
) -> Result<ExecutionPlan, ExecutionError> {
    let resolved = resolve_proxy_path(registry, target, metadata, states)?;
    let mut chain = resolved.dialer_path.clone();
    chain.reverse();
    chain.push(resolved.leaf_name.clone());

    let hops = chain
        .iter()
        .map(|name| build_execution_hop(registry, name))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ExecutionPlan {
        requested: resolved.requested,
        selected_path: resolved.selected_path,
        leaf_name: resolved.leaf_name,
        dial_chain: chain,
        hops,
    })
}

pub fn build_transport_plan(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: &Metadata,
    states: &BTreeMap<String, CandidateState>,
) -> Result<TransportPlan, ExecutionError> {
    let plan = build_execution_plan(registry, target, Some(metadata), states)?;
    materialize_transport_plan(&plan, metadata)
}

pub fn materialize_transport_plan(
    plan: &ExecutionPlan,
    metadata: &Metadata,
) -> Result<TransportPlan, ExecutionError> {
    let final_target = TransportTarget::from_metadata(metadata)?;
    let hops = plan
        .hops
        .iter()
        .enumerate()
        .map(|(index, hop)| {
            let downstream = downstream_target(&plan.hops, index, &final_target);
            Ok(TransportHop {
                name: hop.name.clone(),
                action: transport_action(&hop.spec, downstream),
            })
        })
        .collect::<Result<Vec<_>, ExecutionError>>()?;

    Ok(TransportPlan {
        requested: plan.requested.clone(),
        selected_path: plan.selected_path.clone(),
        leaf_name: plan.leaf_name.clone(),
        hops,
    })
}

pub fn truncate_execution_plan(
    plan: &ExecutionPlan,
    hop_count: usize,
) -> Result<ExecutionPlan, ExecutionError> {
    if hop_count == 0 || hop_count > plan.hops.len() {
        return Err(ExecutionError::Transport(TransportError::InvalidPlan(format!(
            "invalid truncated execution plan hop_count={} total={}",
            hop_count,
            plan.hops.len()
        ))));
    }

    Ok(ExecutionPlan {
        requested: plan.requested.clone(),
        selected_path: plan.selected_path.clone(),
        leaf_name: plan.leaf_name.clone(),
        dial_chain: plan.dial_chain.iter().take(hop_count).cloned().collect(),
        hops: plan.hops.iter().take(hop_count).cloned().collect(),
    })
}

pub fn build_transport_plan_from_execution_plan(
    plan: &ExecutionPlan,
    metadata: &Metadata,
) -> Result<TransportPlan, ExecutionError> {
    materialize_transport_plan(plan, metadata)
}

pub fn run_transport_plan<R>(
    runner: &mut R,
    plan: &TransportPlan,
) -> Result<BoxedTcpStream, ExecutionError>
where
    R: TransportPlanRunner<Output = BoxedTcpStream>,
{
    runner.run_plan(plan).map_err(ExecutionError::from)
}

pub fn connect_target<R>(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: &Metadata,
    states: &BTreeMap<String, CandidateState>,
    runner: &mut R,
) -> Result<BoxedTcpStream, ExecutionError>
where
    R: TransportPlanRunner<Output = BoxedTcpStream>,
{
    let plan = build_transport_plan(registry, target, metadata, states)?;
    run_transport_plan(runner, &plan)
}

pub fn connect_target_with_dialer<D>(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: &Metadata,
    states: &BTreeMap<String, CandidateState>,
    dialer: D,
) -> Result<BoxedTcpStream, ExecutionError>
where
    D: TcpDialer,
{
    let mut executor = TcpTransportExecutor::new(dialer);
    connect_target(registry, target, metadata, states, &mut executor)
}

fn build_execution_hop(
    registry: &RuntimeRegistry,
    name: &str,
) -> Result<ExecutionHop, ExecutionError> {
    let registration = registry
        .proxies
        .get(name)
        .ok_or_else(|| ExecutionError::MissingProxyDefinition(name.to_owned()))?;

    let spec = match &registration.source {
        ProxySource::Builtin => builtin_spec(&registration.name),
        _ => {
            let definition = registry
                .proxy_definitions
                .get(name)
                .cloned()
                .ok_or_else(|| ExecutionError::MissingProxyDefinition(name.to_owned()))?;
            spec_from_definition(definition)
        }
    };

    Ok(ExecutionHop {
        name: registration.name.clone(),
        kind: registration.kind,
        source: registration.source.clone(),
        spec,
    })
}

fn builtin_spec(name: &str) -> ExecutionHopSpec {
    match name {
        "DIRECT" | "COMPATIBLE" => ExecutionHopSpec::Direct(DirectHopSpec {
            socket: SocketOptions {
                tfo: false,
                mptcp: false,
                interface_name: String::new(),
                routing_mark: 0,
                ip_version: String::new(),
                smux_enabled: false,
            },
        }),
        "REJECT" => ExecutionHopSpec::Reject(RejectHopSpec { drop: false }),
        "REJECT-DROP" => ExecutionHopSpec::Reject(RejectHopSpec { drop: true }),
        other => ExecutionHopSpec::Unsupported(UnsupportedHopSpec {
            name: other.to_owned(),
            kind: None,
            endpoint: None,
        }),
    }
}

fn spec_from_definition(definition: OutboundDefinition) -> ExecutionHopSpec {
    match definition {
        OutboundDefinition::Direct(config) => ExecutionHopSpec::Direct(DirectHopSpec {
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Dns(config) => ExecutionHopSpec::Dns(DnsHopSpec {
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Reject(_) => ExecutionHopSpec::Reject(RejectHopSpec { drop: false }),
        OutboundDefinition::Http(config) => ExecutionHopSpec::HttpConnect(HttpConnectHopSpec {
            server: config.server,
            port: config.port,
            auth: basic_auth(&config.extra, "username", "password"),
            tls: tls_options(&config.extra, "sni"),
            headers: string_map(&config.extra, "headers"),
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Socks5(config) => {
            ExecutionHopSpec::Socks5Connect(Socks5ConnectHopSpec {
                server: config.server,
                port: config.port,
                auth: basic_auth(&config.extra, "username", "password"),
                tls: tls_options(&config.extra, "server"),
                udp: value_as_bool(&config.extra, "udp"),
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::AnyTls(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            ExecutionHopSpec::AnyTls(AnyTlsConnectHopSpec {
                server: config.server,
                port: config.port,
                password: value_as_string(&config.extra, "password").unwrap_or_default(),
                udp: value_as_bool(&config.extra, "udp"),
                alpn: string_list(&config.extra, "alpn"),
                tls,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::ShadowSocks(config) => ExecutionHopSpec::ShadowSocks(
            ShadowSocksConnectHopSpec {
                plugin: value_as_string(&config.extra, "plugin").unwrap_or_default(),
                server: config.server,
                port: config.port,
                cipher: config.cipher,
                password: config.password,
                plugin_mode: nested_value_as_string(&config.extra, "plugin-opts", "mode")
                    .unwrap_or_default(),
                plugin_host: nested_value_as_string(&config.extra, "plugin-opts", "host")
                    .unwrap_or_default(),
                websocket: shadowsocks_plugin_websocket_options(
                    value_as_string(&config.extra, "plugin").as_deref().unwrap_or_default(),
                    &config.extra,
                ),
                tls: shadowsocks_plugin_tls_options(
                    value_as_string(&config.extra, "plugin").as_deref().unwrap_or_default(),
                    &config.extra,
                ),
                mux: shadowsocks_plugin_mux(
                    value_as_string(&config.extra, "plugin").as_deref().unwrap_or_default(),
                    &config.extra,
                ),
                socket: socket_options(&config.base),
            },
        ),
        OutboundDefinition::ShadowSocksR(config) => ExecutionHopSpec::Ssr(SsrConnectHopSpec {
            server: config.server,
            port: config.port,
            cipher: value_as_string(&config.extra, "cipher").unwrap_or_default(),
            password: value_as_string(&config.extra, "password").unwrap_or_default(),
            obfs: value_as_string(&config.extra, "obfs").unwrap_or_default(),
            obfs_param: value_as_string(&config.extra, "obfs-param").unwrap_or_default(),
            protocol: value_as_string(&config.extra, "protocol").unwrap_or_default(),
            protocol_param: value_as_string(&config.extra, "protocol-param").unwrap_or_default(),
            udp: value_as_bool(&config.extra, "udp"),
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Snell(config) => ExecutionHopSpec::Snell(SnellConnectHopSpec {
            server: config.server,
            port: config.port,
            psk: value_as_string(&config.extra, "psk").unwrap_or_default(),
            version: value_as_u8(&config.extra, "version").unwrap_or(1),
            obfs_mode: nested_value_as_string(&config.extra, "obfs-opts", "mode").unwrap_or_default(),
            obfs_host: nested_value_as_string(&config.extra, "obfs-opts", "host").unwrap_or_default(),
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Trojan(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            let default_host = config.server.clone();
            ExecutionHopSpec::Trojan(TrojanConnectHopSpec {
                server: config.server,
                port: config.port,
                password: value_as_string(&config.extra, "password").unwrap_or_default(),
                shadowsocks: trojan_shadowsocks_options(&config.extra),
                udp: value_as_bool(&config.extra, "udp"),
                network: value_as_string(&config.extra, "network").unwrap_or_default(),
                websocket: websocket_options(&config.extra),
                grpc: grpc_options(&config.extra),
                http: http_options(&config.extra, &default_host),
                alpn: string_list(&config.extra, "alpn"),
                tls,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::TrustTunnel(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            ExecutionHopSpec::TrustTunnel(TrustTunnelConnectHopSpec {
                server: config.server,
                port: config.port,
                username: value_as_string(&config.extra, "username").unwrap_or_default(),
                password: value_as_string(&config.extra, "password").unwrap_or_default(),
                udp: value_as_bool(&config.extra, "udp"),
                quic: value_as_bool(&config.extra, "quic"),
                alpn: string_list(&config.extra, "alpn"),
                tls,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::Vless(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            if tls.enabled && tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            let default_host = config.server.clone();
            ExecutionHopSpec::Vless(VlessConnectHopSpec {
                server: config.server,
                port: config.port,
                uuid: value_as_string(&config.extra, "uuid").unwrap_or_default(),
                flow: value_as_string(&config.extra, "flow").unwrap_or_default(),
                udp: value_as_bool(&config.extra, "udp"),
                network: value_as_string(&config.extra, "network").unwrap_or_default(),
                websocket: websocket_options(&config.extra),
                grpc: grpc_options(&config.extra),
                h2: h2_options(&config.extra, &default_host),
                http: http_options(&config.extra, &default_host),
                xhttp: xhttp_options(
                    &config.extra,
                    &value_as_string(&config.extra, "servername").unwrap_or(default_host),
                ),
                encryption: value_as_string(&config.extra, "encryption").unwrap_or_default(),
                packet_addr: value_as_bool(&config.extra, "packet-addr"),
                xudp: value_as_bool(&config.extra, "xudp"),
                tls,
                alpn: string_list(&config.extra, "alpn"),
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::Vmess(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            if tls.enabled && tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            let default_host = config.server.clone();
            ExecutionHopSpec::Vmess(VmessConnectHopSpec {
                server: config.server,
                port: config.port,
                uuid: value_as_string(&config.extra, "uuid").unwrap_or_default(),
                alter_id: value_as_u16(&config.extra, "alterId").unwrap_or(0),
                cipher: value_as_string(&config.extra, "cipher")
                    .unwrap_or_else(|| "auto".to_owned()),
                udp: value_as_bool(&config.extra, "udp"),
                network: value_as_string(&config.extra, "network").unwrap_or_default(),
                websocket: websocket_options(&config.extra),
                grpc: grpc_options(&config.extra),
                h2: h2_options(&config.extra, &default_host),
                http: http_options(&config.extra, &default_host),
                xhttp: xhttp_options(
                    &config.extra,
                    &value_as_string(&config.extra, "servername").unwrap_or(default_host),
                ),
                packet_addr: value_as_bool(&config.extra, "packet-addr")
                    || matches!(
                        value_as_string(&config.extra, "packet-encoding").as_deref(),
                        Some("packetaddr" | "packet")
                    ),
                xudp: value_as_bool(&config.extra, "xudp")
                    || matches!(
                        value_as_string(&config.extra, "packet-encoding").as_deref(),
                        Some("xudp")
                    ),
                global_padding: value_as_bool(&config.extra, "global-padding"),
                authenticated_length: value_as_bool(&config.extra, "authenticated-length"),
                tls,
                alpn: string_list(&config.extra, "alpn"),
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::GostRelay(config) => ExecutionHopSpec::GostRelay(GostRelayHopSpec {
            server: config.server,
            port: config.port,
            auth: basic_auth(&config.extra, "username", "password"),
            forward: value_as_bool(&config.extra, "forward"),
            tls: tls_options(&config.extra, "sni"),
            mux: value_as_bool(&config.extra, "mux"),
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Ssh(config) => ExecutionHopSpec::Ssh(SshConnectHopSpec {
            server: config.server,
            port: config.port,
            username: value_as_string(&config.extra, "username").unwrap_or_default(),
            password: value_as_string(&config.extra, "password").unwrap_or_default(),
            private_key: value_as_string(&config.extra, "private-key").unwrap_or_default(),
            private_key_passphrase: value_as_string(&config.extra, "private-key-passphrase")
                .unwrap_or_default(),
            host_keys: string_list(&config.extra, "host-key"),
            host_key_algorithms: string_list(&config.extra, "host-key-algorithms"),
            socket: socket_options(&config.base),
        }),
        OutboundDefinition::Sudoku(config) => ExecutionHopSpec::Sudoku(SudokuConnectHopSpec {
            server: config.server,
            port: config.port,
            key: value_as_string(&config.extra, "key").unwrap_or_default(),
            aead_method: value_as_string(&config.extra, "aead-method")
                .unwrap_or_else(|| "chacha20-poly1305".to_owned()),
            table_type: value_as_string(&config.extra, "table-type")
                .unwrap_or_else(|| "prefer_entropy".to_owned()),
            padding_min: resolve_padding_min(&config.extra, 10, 30),
            padding_max: resolve_padding_max(&config.extra, 10, 30),
            enable_pure_downlink: value_as_bool_with_default(
                &config.extra,
                "enable-pure-downlink",
                true,
            ),
            http_mask_enabled: sudoku_http_mask_enabled(&config.extra),
            http_mask_mode: sudoku_http_mask_mode(&config.extra)
                .unwrap_or_else(|| "legacy".to_owned()),
            http_mask_tls: sudoku_http_mask_tls(&config.extra),
            http_mask_host: sudoku_http_mask_host(&config.extra).unwrap_or_default(),
            path_root: sudoku_http_mask_path_root(&config.extra).unwrap_or_default(),
            custom_table: value_as_string(&config.extra, "custom-table").unwrap_or_default(),
            custom_tables: string_list(&config.extra, "custom-tables"),
            socket: socket_options(&config.base),
        }),
        other => {
            let name = other.name().to_owned();
            let kind = other.kind();
            let endpoint = other
                .remote_endpoint()
                .map(|(server, port)| TransportTarget::new(server, port));
            ExecutionHopSpec::Unsupported(UnsupportedHopSpec {
                name,
                kind: Some(kind),
                endpoint,
            })
        }
    }
}

fn socket_options(base: &ProxyBaseConfig) -> SocketOptions {
    SocketOptions {
        tfo: base.tfo,
        mptcp: base.mptcp,
        interface_name: base.interface_name.clone(),
        routing_mark: base.routing_mark,
        ip_version: base.ip_version.clone(),
        smux_enabled: base.smux.enabled,
    }
}

fn transport_socket_options(socket: &SocketOptions) -> TransportSocketOptions {
    TransportSocketOptions {
        tfo: socket.tfo,
        mptcp: socket.mptcp,
        interface_name: socket.interface_name.clone(),
        routing_mark: socket.routing_mark,
        ip_version: socket.ip_version.clone(),
        smux_enabled: socket.smux_enabled,
    }
}

fn tls_options(extra: &BTreeMap<String, Value>, sni_key: &str) -> TlsOptions {
    TlsOptions {
        enabled: value_as_bool(extra, "tls"),
        sni: value_as_string(extra, sni_key)
            .or_else(|| value_as_string(extra, "servername"))
            .unwrap_or_default(),
        skip_cert_verify: value_as_bool(extra, "skip-cert-verify"),
        fingerprint: value_as_string(extra, "fingerprint").unwrap_or_default(),
        certificate: value_as_string(extra, "certificate").unwrap_or_default(),
        private_key: value_as_string(extra, "private-key").unwrap_or_default(),
    }
}

fn transport_tls_options(tls: &TlsOptions) -> TransportTlsOptions {
    TransportTlsOptions {
        enabled: tls.enabled,
        sni: tls.sni.clone(),
        skip_cert_verify: tls.skip_cert_verify,
        fingerprint: tls.fingerprint.clone(),
        certificate: tls.certificate.clone(),
        private_key: tls.private_key.clone(),
    }
}

fn basic_auth(
    extra: &BTreeMap<String, Value>,
    user_key: &str,
    pass_key: &str,
) -> Option<BasicAuth> {
    let username = value_as_string(extra, user_key)?;
    let password = value_as_string(extra, pass_key).unwrap_or_default();
    Some(BasicAuth { username, password })
}

fn transport_basic_auth(auth: &Option<BasicAuth>) -> Option<TransportBasicAuth> {
    auth.as_ref().map(|auth| TransportBasicAuth {
        username: auth.username.clone(),
        password: auth.password.clone(),
    })
}

fn downstream_target(
    hops: &[ExecutionHop],
    index: usize,
    final_target: &TransportTarget,
) -> TransportTarget {
    hops.iter()
        .skip(index + 1)
        .find_map(|hop| proxy_endpoint(&hop.spec))
        .unwrap_or_else(|| final_target.clone())
}

fn proxy_endpoint(spec: &ExecutionHopSpec) -> Option<TransportTarget> {
    match spec {
        ExecutionHopSpec::HttpConnect(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Socks5Connect(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::AnyTls(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::ShadowSocks(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Ssr(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Snell(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Trojan(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::TrustTunnel(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Vless(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Vmess(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::GostRelay(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Sudoku(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Ssh(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Unsupported(spec) => spec.endpoint.clone(),
        ExecutionHopSpec::Direct(_) | ExecutionHopSpec::Reject(_) | ExecutionHopSpec::Dns(_) => None,
    }
}

fn transport_action(spec: &ExecutionHopSpec, target: TransportTarget) -> TransportAction {
    match spec {
        ExecutionHopSpec::Direct(spec) => TransportAction::Direct {
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Dns(_) => TransportAction::Unsupported {
            name: "dns".to_owned(),
            kind: Some("dns".to_owned()),
            endpoint: None,
            target: Some(target),
        },
        ExecutionHopSpec::Reject(spec) => TransportAction::Reject { drop: spec.drop },
        ExecutionHopSpec::HttpConnect(spec) => TransportAction::HttpConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            auth: transport_basic_auth(&spec.auth),
            tls: transport_tls_options(&spec.tls),
            headers: spec.headers.clone(),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Socks5Connect(spec) => TransportAction::Socks5Connect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            auth: transport_basic_auth(&spec.auth),
            tls: transport_tls_options(&spec.tls),
            udp: spec.udp,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::AnyTls(spec) => TransportAction::AnyTlsConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            password: spec.password.clone(),
            tls: transport_tls_options(&spec.tls),
            alpn: if spec.alpn.is_empty() {
                vec!["h2".to_owned(), "http/1.1".to_owned()]
            } else {
                spec.alpn.clone()
            },
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::ShadowSocks(spec) => TransportAction::ShadowsocksConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            cipher: spec.cipher.clone(),
            password: spec.password.clone(),
            plugin: spec.plugin.clone(),
            plugin_mode: spec.plugin_mode.clone(),
            plugin_host: spec.plugin_host.clone(),
            websocket: spec.websocket.clone(),
            tls: transport_tls_options(&spec.tls),
            mux: spec.mux,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Ssr(spec) => TransportAction::SsrConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            password: spec.password.clone(),
            cipher: spec.cipher.clone(),
            obfs: spec.obfs.clone(),
            obfs_param: spec.obfs_param.clone(),
            protocol: spec.protocol.clone(),
            protocol_param: spec.protocol_param.clone(),
            udp: spec.udp,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Snell(spec) => TransportAction::SnellConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            psk: spec.psk.clone(),
            version: spec.version,
            obfs_mode: spec.obfs_mode.clone(),
            obfs_host: spec.obfs_host.clone(),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Trojan(spec) => TransportAction::TrojanConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            password: spec.password.clone(),
            shadowsocks: spec.shadowsocks.clone(),
            network: spec.network.clone(),
            websocket: spec.websocket.clone(),
            grpc: spec.grpc.clone(),
            http: spec.http.clone(),
            tls: transport_tls_options(&spec.tls),
            alpn: if spec.alpn.is_empty() {
                DEFAULT_TROJAN_ALPN
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect()
            } else {
                spec.alpn.clone()
            },
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::TrustTunnel(spec) => TransportAction::TrustTunnelConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            username: spec.username.clone(),
            password: spec.password.clone(),
            udp: spec.udp,
            quic: spec.quic,
            tls: transport_tls_options(&spec.tls),
            alpn: if spec.alpn.is_empty() {
                vec!["h2".to_owned()]
            } else {
                spec.alpn.clone()
            },
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Vless(spec) => TransportAction::VlessConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            uuid: spec.uuid.clone(),
            flow: spec.flow.clone(),
            udp: spec.udp,
            network: spec.network.clone(),
            websocket: spec.websocket.clone(),
            grpc: spec.grpc.clone(),
            h2: spec.h2.clone(),
            http: spec.http.clone(),
            xhttp: spec.xhttp.clone(),
            encryption: spec.encryption.clone(),
            packet_addr: spec.packet_addr,
            xudp: spec.xudp,
            tls: transport_tls_options(&spec.tls),
            alpn: spec.alpn.clone(),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Vmess(spec) => TransportAction::VmessConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            uuid: spec.uuid.clone(),
            alter_id: spec.alter_id,
            cipher: spec.cipher.clone(),
            udp: spec.udp,
            network: spec.network.clone(),
            websocket: spec.websocket.clone(),
            grpc: spec.grpc.clone(),
            h2: spec.h2.clone(),
            http: spec.http.clone(),
            xhttp: spec.xhttp.clone(),
            packet_addr: spec.packet_addr,
            xudp: spec.xudp,
            global_padding: spec.global_padding,
            authenticated_length: spec.authenticated_length,
            tls: transport_tls_options(&spec.tls),
            alpn: spec.alpn.clone(),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::GostRelay(spec) => TransportAction::GostRelay {
            proxy: TransportTarget::new(&spec.server, spec.port),
            auth: transport_basic_auth(&spec.auth),
            forward: spec.forward,
            tls: transport_tls_options(&spec.tls),
            mux: spec.mux,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Sudoku(spec) => TransportAction::SudokuConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            key: spec.key.clone(),
            aead_method: spec.aead_method.clone(),
            table_type: spec.table_type.clone(),
            padding_min: spec.padding_min,
            padding_max: spec.padding_max,
            enable_pure_downlink: spec.enable_pure_downlink,
            http_mask_enabled: spec.http_mask_enabled,
            http_mask_mode: spec.http_mask_mode.clone(),
            http_mask_tls: spec.http_mask_tls,
            http_mask_host: spec.http_mask_host.clone(),
            path_root: spec.path_root.clone(),
            custom_table: spec.custom_table.clone(),
            custom_tables: spec.custom_tables.clone(),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Ssh(spec) => TransportAction::SshConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            username: spec.username.clone(),
            password: spec.password.clone(),
            private_key: spec.private_key.clone(),
            private_key_passphrase: spec.private_key_passphrase.clone(),
            host_keys: spec.host_keys.clone(),
            host_key_algorithms: spec.host_key_algorithms.clone(),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Unsupported(spec) => TransportAction::Unsupported {
            name: spec.name.clone(),
            kind: spec.kind.map(|kind| kind.as_str().to_owned()),
            endpoint: spec.endpoint.clone(),
            target: Some(target),
        },
    }
}

fn string_map(extra: &BTreeMap<String, Value>, key: &str) -> BTreeMap<String, String> {
    let Some(value) = extra.get(key) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_mapping() else {
        return BTreeMap::new();
    };
    map.iter()
        .filter_map(|(key, value)| {
            let key = key.as_str()?.to_owned();
            let value = value.as_str().map(|text| text.to_owned()).or_else(|| {
                value.as_sequence().and_then(|sequence| {
                    sequence
                        .first()
                        .and_then(|first| first.as_str())
                        .map(|text| text.to_owned())
                })
            })?;
            Some((key, value))
        })
        .collect()
}

fn nested_string_map(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> BTreeMap<String, String> {
    let Some(value) = extra.get(outer_key) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_mapping() else {
        return BTreeMap::new();
    };
    let Some(value) = map.get(Value::String(inner_key.to_owned())) else {
        return BTreeMap::new();
    };
    let Some(inner) = value.as_mapping() else {
        return BTreeMap::new();
    };
    inner.iter()
        .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), value.as_str()?.to_owned())))
        .collect()
}

fn value_as_string(extra: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    extra.get(key).and_then(|value| value.as_str()).map(ToOwned::to_owned)
}

fn string_list(extra: &BTreeMap<String, Value>, key: &str) -> Vec<String> {
    extra
        .get(key)
        .and_then(|value| value.as_sequence())
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn value_as_bool(extra: &BTreeMap<String, Value>, key: &str) -> bool {
    extra.get(key).and_then(|value| value.as_bool()).unwrap_or(false)
}

fn value_as_bool_with_default(extra: &BTreeMap<String, Value>, key: &str, default: bool) -> bool {
    extra.get(key).and_then(|value| value.as_bool()).unwrap_or(default)
}

fn nested_optional_bool(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<bool> {
    let value = extra.get(outer_key)?;
    let map = value.as_mapping()?;
    map.get(Value::String(inner_key.to_owned()))
        .and_then(|value| value.as_bool())
}

fn sudoku_http_mask_enabled(extra: &BTreeMap<String, Value>) -> bool {
    if extra.contains_key("http-mask") {
        return value_as_bool_with_default(extra, "http-mask", true);
    }
    if extra.contains_key("httpmask") {
        return !nested_optional_bool(extra, "httpmask", "disable").unwrap_or(false);
    }
    false
}

fn sudoku_http_mask_mode(extra: &BTreeMap<String, Value>) -> Option<String> {
    value_as_string(extra, "http-mask-mode")
        .or_else(|| nested_value_as_string(extra, "httpmask", "mode"))
}

fn sudoku_http_mask_tls(extra: &BTreeMap<String, Value>) -> bool {
    if extra.contains_key("http-mask-tls") {
        return value_as_bool(extra, "http-mask-tls");
    }
    nested_optional_bool(extra, "httpmask", "tls").unwrap_or(false)
}

fn sudoku_http_mask_host(extra: &BTreeMap<String, Value>) -> Option<String> {
    value_as_string(extra, "http-mask-host")
        .or_else(|| nested_value_as_string(extra, "httpmask", "host"))
}

fn sudoku_http_mask_path_root(extra: &BTreeMap<String, Value>) -> Option<String> {
    value_as_string(extra, "path-root")
        .or_else(|| nested_value_as_string(extra, "httpmask", "path-root"))
}

fn value_as_i32(extra: &BTreeMap<String, Value>, key: &str) -> Option<i32> {
    extra
        .get(key)
        .and_then(|value| value.as_i64())
        .and_then(|value| i32::try_from(value).ok())
}

fn value_as_u16(extra: &BTreeMap<String, Value>, key: &str) -> Option<u16> {
    extra
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
}

fn resolve_padding_min(extra: &BTreeMap<String, Value>, default_min: i32, default_max: i32) -> i32 {
    let mut min = value_as_i32(extra, "padding-min").unwrap_or(default_min);
    let max = value_as_i32(extra, "padding-max").unwrap_or(default_max);
    if !extra.contains_key("padding-min") && extra.contains_key("padding-max") && max < min {
        min = max;
    }
    min
}

fn resolve_padding_max(extra: &BTreeMap<String, Value>, default_min: i32, default_max: i32) -> i32 {
    let min = value_as_i32(extra, "padding-min").unwrap_or(default_min);
    let mut max = value_as_i32(extra, "padding-max").unwrap_or(default_max);
    if !extra.contains_key("padding-max") && extra.contains_key("padding-min") && max < min {
        max = min;
    }
    max
}

fn value_as_u8(extra: &BTreeMap<String, Value>, key: &str) -> Option<u8> {
    extra
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u8::try_from(value).ok())
}

fn nested_value_as_string(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

fn nested_value_as_bool(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn nested_value_as_bool_with_default(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
    default: bool,
) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_bool())
        .unwrap_or(default)
}

fn nested_value_as_i32(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<i32> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_i64())
        .and_then(|value| i32::try_from(value).ok())
}

fn websocket_options(extra: &BTreeMap<String, Value>) -> TransportWebsocketOptions {
    TransportWebsocketOptions {
        path: nested_value_as_string(extra, "ws-opts", "path").unwrap_or_default(),
        headers: nested_string_map(extra, "ws-opts", "headers"),
        max_early_data: nested_value_as_i32(extra, "ws-opts", "max-early-data").unwrap_or(0),
        early_data_header_name: nested_value_as_string(
            extra,
            "ws-opts",
            "early-data-header-name",
        )
        .unwrap_or_default(),
        v2ray_http_upgrade: nested_value_as_bool(extra, "ws-opts", "v2ray-http-upgrade"),
        v2ray_http_upgrade_fast_open: nested_value_as_bool(
            extra,
            "ws-opts",
            "v2ray-http-upgrade-fast-open",
        ),
    }
}

fn shadowsocks_plugin_websocket_options(
    plugin: &str,
    extra: &BTreeMap<String, Value>,
) -> TransportWebsocketOptions {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin != "v2ray-plugin" && plugin != "gost-plugin" {
        return TransportWebsocketOptions::default();
    }
    let mut headers = nested_string_map(extra, "plugin-opts", "headers");
    let plugin_host = nested_value_as_string(extra, "plugin-opts", "host")
        .unwrap_or_else(|| "bing.com".to_owned());
    if !plugin_host.trim().is_empty()
        && !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("host"))
    {
        headers.insert("Host".to_owned(), plugin_host);
    }
    TransportWebsocketOptions {
        path: nested_value_as_string(extra, "plugin-opts", "path").unwrap_or_default(),
        headers,
        max_early_data: 0,
        early_data_header_name: String::new(),
        v2ray_http_upgrade: nested_value_as_bool(extra, "plugin-opts", "v2ray-http-upgrade"),
        v2ray_http_upgrade_fast_open: nested_value_as_bool(
            extra,
            "plugin-opts",
            "v2ray-http-upgrade-fast-open",
        ),
    }
}

fn shadowsocks_plugin_tls_options(plugin: &str, extra: &BTreeMap<String, Value>) -> TlsOptions {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin != "v2ray-plugin" && plugin != "gost-plugin" {
        return TlsOptions {
            enabled: false,
            sni: String::new(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
    }
    let enabled = nested_value_as_bool(extra, "plugin-opts", "tls");
    let mut sni = String::new();
    if enabled {
        sni = nested_string_map(extra, "plugin-opts", "headers")
            .into_iter()
            .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.trim().is_empty())
            .map(|(_, value)| value)
            .unwrap_or_else(|| {
                nested_value_as_string(extra, "plugin-opts", "host")
                    .unwrap_or_else(|| "bing.com".to_owned())
            });
    }
    TlsOptions {
        enabled,
        sni,
        skip_cert_verify: nested_value_as_bool(extra, "plugin-opts", "skip-cert-verify"),
        fingerprint: nested_value_as_string(extra, "plugin-opts", "fingerprint")
            .unwrap_or_default(),
        certificate: nested_value_as_string(extra, "plugin-opts", "certificate")
            .unwrap_or_default(),
        private_key: nested_value_as_string(extra, "plugin-opts", "private-key")
            .unwrap_or_default(),
    }
}

fn shadowsocks_plugin_mux(plugin: &str, extra: &BTreeMap<String, Value>) -> bool {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin != "v2ray-plugin" && plugin != "gost-plugin" {
        return false;
    }
    nested_value_as_bool_with_default(extra, "plugin-opts", "mux", true)
}

fn nested_string_list(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Vec<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_sequence())
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn nested_string_map_list(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> BTreeMap<String, Vec<String>> {
    let Some(value) = extra.get(outer_key) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_mapping() else {
        return BTreeMap::new();
    };
    let Some(value) = map.get(Value::String(inner_key.to_owned())) else {
        return BTreeMap::new();
    };
    let Some(inner) = value.as_mapping() else {
        return BTreeMap::new();
    };
    inner.iter()
        .filter_map(|(key, value)| {
            let key = key.as_str()?.to_owned();
            let values = if let Some(text) = value.as_str() {
                vec![text.to_owned()]
            } else {
                value
                    .as_sequence()
                    .map(|sequence| {
                        sequence
                            .iter()
                            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            Some((key, values))
        })
        .collect()
}

fn http_options(extra: &BTreeMap<String, Value>, default_host: &str) -> TransportHttpStreamOptions {
    let host = nested_string_list(extra, "http-opts", "host");
    let mut path = nested_string_list(extra, "http-opts", "path");
    if path.is_empty() {
        if let Some(single_path) = nested_value_as_string(extra, "http-opts", "path") {
            path.push(single_path);
        }
    }
    TransportHttpStreamOptions {
        method: nested_value_as_string(extra, "http-opts", "method").unwrap_or_default(),
        host: if host.is_empty() {
            vec![default_host.to_owned()]
        } else {
            host
        },
        path,
        headers: nested_string_map_list(extra, "http-opts", "headers"),
    }
}

fn h2_options(extra: &BTreeMap<String, Value>, default_host: &str) -> TransportHttp2Options {
    let mut host = nested_string_list(extra, "h2-opts", "host");
    if host.is_empty() {
        if let Some(single_host) = nested_value_as_string(extra, "h2-opts", "host") {
            host.push(single_host);
        }
    }
    TransportHttp2Options {
        host: if host.is_empty() {
            vec![default_host.to_owned()]
        } else {
            host
        },
        path: nested_value_as_string(extra, "h2-opts", "path").unwrap_or_default(),
    }
}

fn grpc_options(extra: &BTreeMap<String, Value>) -> TransportGrpcOptions {
    TransportGrpcOptions {
        service_name: nested_value_as_string(extra, "grpc-opts", "grpc-service-name")
            .unwrap_or_default(),
        user_agent: nested_value_as_string(extra, "grpc-opts", "grpc-user-agent")
            .unwrap_or_default(),
        ping_interval: nested_value_as_i32(extra, "grpc-opts", "ping-interval").unwrap_or(0),
        max_connections: nested_value_as_i32(extra, "grpc-opts", "max-connections")
            .unwrap_or(0),
        min_streams: nested_value_as_i32(extra, "grpc-opts", "min-streams").unwrap_or(0),
        max_streams: nested_value_as_i32(extra, "grpc-opts", "max-streams").unwrap_or(0),
    }
}

fn trojan_shadowsocks_options(
    extra: &BTreeMap<String, Value>,
) -> TransportTrojanShadowsocksOptions {
    TransportTrojanShadowsocksOptions {
        enabled: nested_value_as_bool(extra, "ss-opts", "enabled"),
        method: nested_value_as_string(extra, "ss-opts", "method").unwrap_or_default(),
        password: nested_value_as_string(extra, "ss-opts", "password").unwrap_or_default(),
    }
}

fn xhttp_options(extra: &BTreeMap<String, Value>, default_host: &str) -> TransportXHttpOptions {
    TransportXHttpOptions {
        host: nested_value_as_string(extra, "xhttp-opts", "host")
            .unwrap_or_else(|| default_host.to_owned()),
        path: nested_value_as_string(extra, "xhttp-opts", "path").unwrap_or_default(),
        mode: nested_value_as_string(extra, "xhttp-opts", "mode").unwrap_or_default(),
        headers: nested_string_map(extra, "xhttp-opts", "headers"),
        uplink_http_method: nested_value_as_string(extra, "xhttp-opts", "uplink-http-method")
            .unwrap_or_default(),
        session_placement: nested_value_as_string(extra, "xhttp-opts", "session-placement")
            .unwrap_or_default(),
        session_key: nested_value_as_string(extra, "xhttp-opts", "session-key")
            .unwrap_or_default(),
        seq_placement: nested_value_as_string(extra, "xhttp-opts", "seq-placement")
            .unwrap_or_default(),
        seq_key: nested_value_as_string(extra, "xhttp-opts", "seq-key").unwrap_or_default(),
        uplink_data_placement: nested_value_as_string(
            extra,
            "xhttp-opts",
            "uplink-data-placement",
        )
        .unwrap_or_default(),
        uplink_data_key: nested_value_as_string(extra, "xhttp-opts", "uplink-data-key")
            .unwrap_or_default(),
        uplink_chunk_size: nested_value_as_string(extra, "xhttp-opts", "uplink-chunk-size")
            .unwrap_or_default(),
        sc_max_each_post_bytes: nested_value_as_string(
            extra,
            "xhttp-opts",
            "sc-max-each-post-bytes",
        )
        .unwrap_or_default(),
        sc_min_posts_interval_ms: nested_value_as_string(
            extra,
            "xhttp-opts",
            "sc-min-posts-interval-ms",
        )
        .unwrap_or_default(),
        no_grpc_header: nested_value_as_bool(extra, "xhttp-opts", "no-grpc-header"),
        xpadding_bytes: nested_value_as_string(extra, "xhttp-opts", "x-padding-bytes")
            .unwrap_or_default(),
        xpadding_obfs_mode: nested_value_as_bool(extra, "xhttp-opts", "x-padding-obfs-mode"),
        xpadding_key: nested_value_as_string(extra, "xhttp-opts", "x-padding-key")
            .unwrap_or_default(),
        xpadding_header: nested_value_as_string(extra, "xhttp-opts", "x-padding-header")
            .unwrap_or_default(),
        xpadding_placement: nested_value_as_string(extra, "xhttp-opts", "x-padding-placement")
            .unwrap_or_default(),
        xpadding_method: nested_value_as_string(extra, "xhttp-opts", "x-padding-method")
            .unwrap_or_default(),
        has_reuse_settings: nested_value_exists(extra, "xhttp-opts", "reuse-settings"),
        has_download_settings: nested_value_exists(extra, "xhttp-opts", "download-settings"),
        download_host: doubly_nested_value_as_string(extra, "xhttp-opts", "download-settings", "host")
            .unwrap_or_default(),
        download_path: doubly_nested_value_as_string(extra, "xhttp-opts", "download-settings", "path")
            .unwrap_or_default(),
        download_headers: doubly_nested_string_map(extra, "xhttp-opts", "download-settings", "headers"),
        download_server: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "server",
        )
        .unwrap_or_default(),
        download_port: doubly_nested_value_as_u16(extra, "xhttp-opts", "download-settings", "port")
            .unwrap_or(0),
        has_download_port: doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", "port"),
        download_tls: doubly_nested_value_as_bool(extra, "xhttp-opts", "download-settings", "tls")
            .unwrap_or(false),
        has_download_tls: doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", "tls"),
        download_sni: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "servername",
        )
        .unwrap_or_default(),
        download_skip_cert_verify: doubly_nested_value_as_bool(
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
        download_fingerprint: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "fingerprint",
        )
        .unwrap_or_default(),
        download_certificate: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "certificate",
        )
        .unwrap_or_default(),
        download_private_key: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "private-key",
        )
        .unwrap_or_default(),
        has_download_reuse_settings: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "reuse-settings",
        ),
        has_download_transport_overrides: [
            "ech-opts",
            "reality-opts",
            "client-fingerprint",
        ]
        .iter()
        .any(|key| doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", key)),
    }
}

fn nested_value_exists(extra: &BTreeMap<String, Value>, outer_key: &str, inner_key: &str) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .is_some_and(|mapping| mapping.contains_key(Value::String(inner_key.to_owned())))
}

fn doubly_nested_value_as_string(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Option<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
}

fn doubly_nested_value_as_u16(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Option<u16> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_i64())
        .and_then(|value| u16::try_from(value).ok())
}

fn doubly_nested_value_as_bool(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Option<bool> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_bool())
}

fn doubly_nested_string_map(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> BTreeMap<String, String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(key, value)| {
                    Some((key.as_str()?.to_owned(), value.as_str()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_string_list(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Vec<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_sequence())
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_value_exists(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .is_some_and(|mapping| mapping.contains_key(Value::String(inner_key.to_owned())))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{self, Cursor, Read, Write};
    use std::sync::{Arc, Mutex};

    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{BoxedTcpStream, Metadata};
    use mihomo_transport::{
        RecordingTransportRunner, TcpDialPurpose, TcpDialer, TcpTransportExecutor,
        TransportAction, TransportPlanRunner, TransportTarget,
    };

    use super::{build_execution_plan, build_transport_plan, connect_target, ExecutionHopSpec};
    use crate::{build_runtime_registry, CandidateState};

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
            self.expected.push_back((authority.into(), handle.clone()));
            handle
        }
    }

    impl TcpDialer for FakeDialer {
        fn connect(
            &mut self,
            target: &TransportTarget,
            _socket: &mihomo_transport::SocketOptions,
            _purpose: TcpDialPurpose,
        ) -> Result<BoxedTcpStream, mihomo_transport::TransportError> {
            self.calls.push(target.authority());
            let Some((expected, handle)) = self.expected.pop_front() else {
                return Err(mihomo_transport::TransportError::InvalidPlan(
                    "unexpected runtime dial".to_owned(),
                ));
            };
            if expected != target.authority() {
                return Err(mihomo_transport::TransportError::InvalidPlan(format!(
                    "expected dial {expected} but got {}",
                    target.authority()
                )));
            }
            Ok(Box::new(handle.stream()))
        }
    }

    #[test]
    fn execution_plan_resolves_direct_proxy_to_single_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: local
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "local", None, &BTreeMap::new()).unwrap();
        assert_eq!(plan.leaf_name, "local");
        assert_eq!(plan.dial_chain, vec!["local"]);
        match &plan.hops[0].spec {
            ExecutionHopSpec::Direct(spec) => {
                assert!(!spec.socket.tfo);
            }
            _ => panic!("expected configured hop"),
        }
    }

    #[test]
    fn execution_plan_resolves_nested_group_and_reverses_dialer_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: leaf
    dialer-proxy: mid
  - type: direct
    name: mid
    dialer-proxy: outer
  - type: direct
    name: outer
proxy-groups:
  - name: selector
    type: select
    proxies: [leaf]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "selector", None, &BTreeMap::new()).unwrap();
        assert_eq!(plan.selected_path, vec!["selector", "leaf"]);
        assert_eq!(plan.dial_chain, vec!["outer", "mid", "leaf"]);
        assert_eq!(plan.hops.len(), 3);
    }

    #[test]
    fn execution_plan_uses_runtime_group_choice() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: a
  - type: direct
    name: b
proxy-groups:
  - name: auto
    type: url-test
    proxies: [a, b]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let states = BTreeMap::from([
            (
                "a".into(),
                CandidateState {
                    name: "a".into(),
                    alive: true,
                    last_delay_ms: 80,
                    supports_udp: true,
                },
            ),
            (
                "b".into(),
                CandidateState {
                    name: "b".into(),
                    alive: true,
                    last_delay_ms: 20,
                    supports_udp: true,
                },
            ),
        ]);
        let plan = build_execution_plan(&mut registry, "auto", None, &states).unwrap();
        assert_eq!(plan.leaf_name, "b");
    }

    #[test]
    fn execution_plan_supports_provider_leaf_definition() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: socks5
        name: p1
        server: 1.2.3.4
        port: 1080
proxy-groups:
  - name: selector
    type: select
    use: [provider1]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "selector", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Socks5Connect(spec) => {
                assert_eq!(spec.server, "1.2.3.4");
                assert_eq!(spec.port, 1080);
            }
            _ => panic!("expected configured provider hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_http_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: http
    name: http-hop
    server: proxy.example.com
    port: 8443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
    skip-cert-verify: true
    headers:
      Host: override.example.com
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "http-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::HttpConnect(spec) => {
                assert_eq!(spec.server, "proxy.example.com");
                assert_eq!(spec.port, 8443);
                assert_eq!(spec.auth.as_ref().unwrap().username, "user");
                assert!(spec.tls.enabled);
                assert_eq!(spec.tls.sni, "edge.example.com");
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.headers["Host"], "override.example.com");
            }
            _ => panic!("expected http hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_shadowsocks_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: edge-ss
    server: ss.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-ss", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::ShadowSocks(spec) => {
                assert_eq!(spec.server, "ss.example.com");
                assert_eq!(spec.port, 8388);
                assert_eq!(spec.cipher, "chacha20-ietf-poly1305");
                assert_eq!(spec.password, "secret");
                assert!(spec.plugin.is_empty());
                assert!(spec.plugin_mode.is_empty());
                assert!(spec.plugin_host.is_empty());
                assert!(spec.websocket.path.is_empty());
                assert!(spec.websocket.headers.is_empty());
                assert!(!spec.tls.enabled);
                assert!(!spec.mux);
            }
            _ => panic!("expected shadowsocks hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_shadowsocks_plugin_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: edge-ss
    server: ss.example.com
    port: 443
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /shadow
      tls: true
      skip-cert-verify: true
      mux: false
      headers:
        X-Test: enabled
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-ss", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::ShadowSocks(spec) => {
                assert_eq!(spec.plugin, "v2ray-plugin");
                assert_eq!(spec.plugin_mode, "websocket");
                assert_eq!(spec.plugin_host, "ws.example.com");
                assert_eq!(spec.websocket.path, "/shadow");
                assert_eq!(spec.websocket.headers["Host"], "ws.example.com");
                assert_eq!(spec.websocket.headers["X-Test"], "enabled");
                assert!(spec.tls.enabled);
                assert_eq!(spec.tls.sni, "ws.example.com");
                assert!(spec.tls.skip_cert_verify);
                assert!(!spec.mux);
            }
            _ => panic!("expected shadowsocks hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_ssr_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: ssr.example.com
    port: 8389
    cipher: dummy
    password: secret
    obfs: plain
    protocol: origin
    udp: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-ssr", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Ssr(spec) => {
                assert_eq!(spec.server, "ssr.example.com");
                assert_eq!(spec.port, 8389);
                assert_eq!(spec.cipher, "dummy");
                assert_eq!(spec.password, "secret");
                assert_eq!(spec.obfs, "plain");
                assert_eq!(spec.protocol, "origin");
                assert!(spec.udp);
            }
            _ => panic!("expected ssr hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_snell_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: snell.example.com
    port: 8443
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: tls
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "edge-snell", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Snell(spec) => {
                assert_eq!(spec.server, "snell.example.com");
                assert_eq!(spec.port, 8443);
                assert_eq!(spec.psk, "secret-psk");
                assert_eq!(spec.version, 3);
                assert_eq!(spec.obfs_mode, "tls");
                assert!(spec.obfs_host.is_empty());
            }
            _ => panic!("expected snell hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_snell_v2_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: snell.example.com
    port: 8443
    psk: secret-psk
    version: 2
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "edge-snell", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Snell(spec) => {
                assert_eq!(spec.server, "snell.example.com");
                assert_eq!(spec.port, 8443);
                assert_eq!(spec.psk, "secret-psk");
                assert_eq!(spec.version, 2);
                assert!(spec.obfs_mode.is_empty());
                assert!(spec.obfs_host.is_empty());
            }
            _ => panic!("expected snell hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_gost_relay_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: gost-relay
    name: relay-hop
    server: relay.example.com
    port: 8443
    username: user
    password: pass
    forward: true
    mux: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "relay-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::GostRelay(spec) => {
                assert_eq!(spec.server, "relay.example.com");
                assert_eq!(spec.port, 8443);
                assert_eq!(spec.auth.as_ref().unwrap().username, "user");
                assert_eq!(spec.auth.as_ref().unwrap().password, "pass");
                assert!(spec.forward);
                assert!(spec.mux);
            }
            _ => panic!("expected gost relay hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_ssh_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssh
    name: ssh-hop
    server: ssh.example.com
    port: 22
    username: user
    password: pass
    private-key: /tmp/id_ed25519
    private-key-passphrase: secret
    host-key:
      - AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ
    host-key-algorithms: [ssh-ed25519, rsa-sha2-256]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "ssh-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Ssh(spec) => {
                assert_eq!(spec.server, "ssh.example.com");
                assert_eq!(spec.port, 22);
                assert_eq!(spec.username, "user");
                assert_eq!(spec.password, "pass");
                assert_eq!(spec.private_key, "/tmp/id_ed25519");
                assert_eq!(spec.private_key_passphrase, "secret");
                assert_eq!(
                    spec.host_keys,
                    vec!["AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ".to_owned()]
                );
                assert_eq!(
                    spec.host_key_algorithms,
                    vec!["ssh-ed25519".to_owned(), "rsa-sha2-256".to_owned()]
                );
            }
            _ => panic!("expected ssh hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    http-mask: true
    http-mask-mode: ws
    http-mask-tls: true
    http-mask-host: cdn.example.com
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert_eq!(spec.server, "sudoku.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.key, "secret-seed");
                assert_eq!(spec.aead_method, "aes-128-gcm");
                assert_eq!(spec.table_type, "prefer_ascii");
                assert_eq!(spec.padding_min, 12);
                assert_eq!(spec.padding_max, 30);
                assert!(spec.enable_pure_downlink);
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "ws");
                assert!(spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "cdn.example.com");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_stream_http_mask_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: stream
    http-mask-host: cdn.example.com:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "stream");
                assert!(!spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "cdn.example.com:8443");
                assert_eq!(spec.path_root, "mask");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_stream_http_mask_tls_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: stream
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "stream");
                assert!(spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "localhost:8443");
                assert_eq!(spec.path_root, "mask");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_auto_http_mask_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: auto
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "auto");
                assert!(!spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "");
                assert_eq!(spec.path_root, "mask");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_auto_http_mask_tls_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: auto
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "auto");
                assert!(spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "localhost:8443");
                assert_eq!(spec.path_root, "mask");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_nested_httpmask_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    padding-min: 12
    padding-max: 24
    httpmask:
      disable: false
      mode: auto
      tls: true
      host: localhost:8443
      path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "auto");
                assert!(spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "localhost:8443");
                assert_eq!(spec.path_root, "mask");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_trojan_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: trojan-hop
    server: trojan.example.com
    port: 443
    password: secret
    sni: edge.example.com
    skip-cert-verify: true
    alpn: [h2, http/1.1]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "trojan-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Trojan(spec) => {
                assert_eq!(spec.server, "trojan.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.password, "secret");
                assert!(!spec.shadowsocks.enabled);
                assert_eq!(spec.network, "");
                assert_eq!(spec.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
                assert!(spec.tls.enabled);
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.tls.sni, "edge.example.com");
            }
            _ => panic!("expected trojan hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_trojan_grpc_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: trojan-hop
    server: trojan.example.com
    port: 443
    password: secret
    ss-opts:
      enabled: true
      method: aes-128-gcm
      password: inner
    network: grpc
    sni: edge.example.com
    skip-cert-verify: true
    grpc-opts:
      grpc-service-name: example
      grpc-user-agent: grpc-go/1.36.0
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "trojan-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Trojan(spec) => {
                assert_eq!(spec.network, "grpc");
                assert!(spec.shadowsocks.enabled);
                assert_eq!(spec.shadowsocks.method, "aes-128-gcm");
                assert_eq!(spec.shadowsocks.password, "inner");
                assert_eq!(spec.grpc.service_name, "example");
                assert_eq!(spec.grpc.user_agent, "grpc-go/1.36.0");
            }
            _ => panic!("expected trojan hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_trojan_http_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: trojan-hop
    server: trojan.example.com
    port: 443
    password: secret
    network: http
    sni: edge.example.com
    skip-cert-verify: true
    http-opts:
      method: PUT
      path: [/tr]
      host: [localhost]
      headers:
        X-Test: [yes]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "trojan-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Trojan(spec) => {
                assert_eq!(spec.network, "http");
                assert_eq!(spec.http.method, "PUT");
                assert_eq!(spec.http.path, vec!["/tr".to_owned()]);
                assert_eq!(spec.http.host, vec!["localhost".to_owned()]);
                assert_eq!(
                    spec.http.headers.get("X-Test"),
                    Some(&vec!["yes".to_owned()])
                );
            }
            _ => panic!("expected trojan hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_trusttunnel_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trusttunnel
    name: trust-hop
    server: trust.example.com
    port: 443
    username: alice
    password: secret
    udp: true
    quic: false
    sni: edge.example.com
    skip-cert-verify: true
    alpn: [h2]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "trust-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::TrustTunnel(spec) => {
                assert_eq!(spec.server, "trust.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.username, "alice");
                assert_eq!(spec.password, "secret");
                assert!(spec.udp);
                assert!(!spec.quic);
                assert_eq!(spec.alpn, vec!["h2".to_owned()]);
                assert!(spec.tls.enabled);
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.tls.sni, "edge.example.com");
            }
            _ => panic!("expected trusttunnel hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_anytls_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: anytls
    name: anytls-hop
    server: anytls.example.com
    port: 443
    password: secret
    udp: true
    sni: edge.example.com
    skip-cert-verify: true
    alpn: [h2, http/1.1]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "anytls-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::AnyTls(spec) => {
                assert_eq!(spec.server, "anytls.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.password, "secret");
                assert!(spec.udp);
                assert_eq!(spec.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
                assert!(spec.tls.enabled);
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.tls.sni, "edge.example.com");
            }
            _ => panic!("expected anytls hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vless_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vless-hop
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    servername: edge.example.com
    alpn: [h2, http/1.1]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vless-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vless(spec) => {
                assert_eq!(spec.server, "vless.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert!(spec.udp);
                assert!(spec.tls.enabled);
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.tls.sni, "edge.example.com");
                assert_eq!(spec.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
                assert_eq!(spec.h2.host, vec!["vless.example.com".to_owned()]);
                assert!(spec.h2.path.is_empty());
            }
            _ => panic!("expected vless hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vless_h2_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vless-hop
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: h2
    h2-opts:
      host: [edge.example.com, backup.example.com]
      path: /vless-h2
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vless-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vless(spec) => {
                assert_eq!(spec.network, "h2");
                assert_eq!(
                    spec.h2.host,
                    vec!["edge.example.com".to_owned(), "backup.example.com".to_owned()]
                );
                assert_eq!(spec.h2.path, "/vless-h2");
            }
            _ => panic!("expected vless hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vless_grpc_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vless-hop
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: grpc
    grpc-opts:
      grpc-service-name: example
      grpc-user-agent: grpc-go/1.36.0
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vless-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vless(spec) => {
                assert_eq!(spec.network, "grpc");
                assert_eq!(spec.grpc.service_name, "example");
                assert_eq!(spec.grpc.user_agent, "grpc-go/1.36.0");
            }
            _ => panic!("expected vless hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vless_xhttp_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    servername: x.example.com
    network: xhttp
    xhttp-opts:
      path: /vx
      mode: stream-one
      uplink-http-method: PUT
      session-placement: path
      seq-placement: path
      uplink-data-placement: body
      no-grpc-header: true
      x-padding-bytes: 100-1000
      x-padding-obfs-mode: true
      x-padding-key: x_padding
      x-padding-header: Referer
      x-padding-placement: header
      x-padding-method: repeat-x
      sc-max-each-post-bytes: "4096"
      sc-min-posts-interval-ms: "30"
      reuse-settings:
        max-concurrency: "8"
      download-settings:
        reuse-settings: true
        server: download.example.com
        port: 8443
        tls: false
        servername: download-sni.example.com
        skip-cert-verify: true
        alpn: [h2]
        fingerprint: DOWNLOAD FINGERPRINT
        certificate: DOWNLOAD CERT
        private-key: DOWNLOAD KEY
        host: download.example.com
        path: /download
        headers:
          X-Download: yes
      headers:
        X-Test: yes
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-vless", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vless(spec) => {
                assert_eq!(spec.network, "xhttp");
                assert_eq!(spec.xhttp.host, "x.example.com");
                assert_eq!(spec.xhttp.path, "/vx");
                assert_eq!(spec.xhttp.mode, "stream-one");
                assert_eq!(spec.xhttp.uplink_http_method, "PUT");
                assert_eq!(spec.xhttp.session_placement, "path");
                assert_eq!(spec.xhttp.seq_placement, "path");
                assert_eq!(spec.xhttp.uplink_data_placement, "body");
                assert!(spec.xhttp.no_grpc_header);
                assert_eq!(spec.xhttp.xpadding_bytes, "100-1000");
                assert!(spec.xhttp.xpadding_obfs_mode);
                assert_eq!(spec.xhttp.xpadding_key, "x_padding");
                assert_eq!(spec.xhttp.xpadding_header, "Referer");
                assert_eq!(spec.xhttp.xpadding_placement, "header");
                assert_eq!(spec.xhttp.xpadding_method, "repeat-x");
                assert_eq!(spec.xhttp.sc_max_each_post_bytes, "4096");
                assert_eq!(spec.xhttp.sc_min_posts_interval_ms, "30");
                assert!(spec.xhttp.has_reuse_settings);
                assert!(spec.xhttp.has_download_settings);
                assert!(spec.xhttp.has_download_reuse_settings);
                assert_eq!(spec.xhttp.download_server, "download.example.com");
                assert_eq!(spec.xhttp.download_port, 8443);
                assert!(spec.xhttp.has_download_port);
                assert!(!spec.xhttp.download_tls);
                assert!(spec.xhttp.has_download_tls);
                assert_eq!(spec.xhttp.download_sni, "download-sni.example.com");
                assert!(spec.xhttp.download_skip_cert_verify);
                assert!(spec.xhttp.has_download_skip_cert_verify);
                assert_eq!(spec.xhttp.download_alpn, vec!["h2".to_owned()]);
                assert_eq!(spec.xhttp.download_fingerprint, "DOWNLOAD FINGERPRINT");
                assert_eq!(spec.xhttp.download_certificate, "DOWNLOAD CERT");
                assert_eq!(spec.xhttp.download_private_key, "DOWNLOAD KEY");
                assert_eq!(spec.xhttp.download_host, "download.example.com");
                assert_eq!(spec.xhttp.download_path, "/download");
                assert_eq!(
                    spec.xhttp.download_headers.get("X-Download").map(String::as_str),
                    Some("yes")
                );
                assert_eq!(spec.xhttp.headers.get("X-Test").map(String::as_str), Some("yes"));
            }
            _ => panic!("expected vless hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vmess_hop_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: vmess-hop
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    tls: true
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vmess-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vmess(spec) => {
                assert_eq!(spec.server, "vmess.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(spec.alter_id, 0);
                assert_eq!(spec.cipher, "none");
                assert!(spec.tls.enabled);
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.tls.sni, "vmess.example.com");
                assert_eq!(spec.h2.host, vec!["vmess.example.com".to_owned()]);
                assert!(spec.h2.path.is_empty());
            }
            _ => panic!("expected vmess hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vmess_h2_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: vmess-hop
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: h2
    h2-opts:
      host: edge.example.com
      path: /vmess-h2
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vmess-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vmess(spec) => {
                assert_eq!(spec.network, "h2");
                assert_eq!(spec.h2.host, vec!["edge.example.com".to_owned()]);
                assert_eq!(spec.h2.path, "/vmess-h2");
            }
            _ => panic!("expected vmess hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vmess_grpc_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: vmess-hop
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: grpc
    grpc-opts:
      grpc-service-name: example
      grpc-user-agent: grpc-go/1.36.0
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vmess-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vmess(spec) => {
                assert_eq!(spec.network, "grpc");
                assert_eq!(spec.grpc.service_name, "example");
                assert_eq!(spec.grpc.user_agent, "grpc-go/1.36.0");
            }
            _ => panic!("expected vmess hop"),
        }
    }

    #[test]
    fn execution_plan_normalizes_vmess_xhttp_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    tls: true
    servername: x.example.com
    network: xhttp
    xhttp-opts:
      path: /vmx
      mode: stream-one
      uplink-http-method: PUT
      session-placement: path
      seq-placement: path
      uplink-data-placement: body
      no-grpc-header: true
      x-padding-bytes: 100-1000
      x-padding-obfs-mode: true
      x-padding-key: x_padding
      x-padding-header: Referer
      x-padding-placement: header
      x-padding-method: repeat-x
      sc-max-each-post-bytes: "4096"
      sc-min-posts-interval-ms: "30"
      reuse-settings:
        max-concurrency: "8"
      download-settings:
        reuse-settings: true
        server: download.example.com
        port: 8443
        tls: false
        servername: download-sni.example.com
        skip-cert-verify: true
        alpn: [h2]
        fingerprint: DOWNLOAD FINGERPRINT
        certificate: DOWNLOAD CERT
        private-key: DOWNLOAD KEY
        host: download.example.com
        path: /download
        headers:
          X-Download: yes
      headers:
        X-Test: yes
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-vmess", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vmess(spec) => {
                assert_eq!(spec.network, "xhttp");
                assert_eq!(spec.xhttp.host, "x.example.com");
                assert_eq!(spec.xhttp.path, "/vmx");
                assert_eq!(spec.xhttp.mode, "stream-one");
                assert_eq!(spec.xhttp.uplink_http_method, "PUT");
                assert_eq!(spec.xhttp.session_placement, "path");
                assert_eq!(spec.xhttp.seq_placement, "path");
                assert_eq!(spec.xhttp.uplink_data_placement, "body");
                assert!(spec.xhttp.no_grpc_header);
                assert_eq!(spec.xhttp.xpadding_bytes, "100-1000");
                assert!(spec.xhttp.xpadding_obfs_mode);
                assert_eq!(spec.xhttp.xpadding_key, "x_padding");
                assert_eq!(spec.xhttp.xpadding_header, "Referer");
                assert_eq!(spec.xhttp.xpadding_placement, "header");
                assert_eq!(spec.xhttp.xpadding_method, "repeat-x");
                assert_eq!(spec.xhttp.sc_max_each_post_bytes, "4096");
                assert_eq!(spec.xhttp.sc_min_posts_interval_ms, "30");
                assert!(spec.xhttp.has_reuse_settings);
                assert!(spec.xhttp.has_download_settings);
                assert!(spec.xhttp.has_download_reuse_settings);
                assert_eq!(spec.xhttp.download_server, "download.example.com");
                assert_eq!(spec.xhttp.download_port, 8443);
                assert!(spec.xhttp.has_download_port);
                assert!(!spec.xhttp.download_tls);
                assert!(spec.xhttp.has_download_tls);
                assert_eq!(spec.xhttp.download_sni, "download-sni.example.com");
                assert!(spec.xhttp.download_skip_cert_verify);
                assert!(spec.xhttp.has_download_skip_cert_verify);
                assert_eq!(spec.xhttp.download_alpn, vec!["h2".to_owned()]);
                assert_eq!(spec.xhttp.download_fingerprint, "DOWNLOAD FINGERPRINT");
                assert_eq!(spec.xhttp.download_certificate, "DOWNLOAD CERT");
                assert_eq!(spec.xhttp.download_private_key, "DOWNLOAD KEY");
                assert_eq!(spec.xhttp.download_host, "download.example.com");
                assert_eq!(spec.xhttp.download_path, "/download");
                assert_eq!(
                    spec.xhttp.download_headers.get("X-Download").map(String::as_str),
                    Some("yes")
                );
                assert_eq!(spec.xhttp.headers.get("X-Test").map(String::as_str), Some("yes"));
            }
            _ => panic!("expected vmess hop"),
        }
    }

    #[test]
    fn execution_plan_marks_unimplemented_outbounds_as_unsupported() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: mieru
    name: mieru-hop
    server: 1.2.3.4
    port: 443
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "mieru-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Unsupported(spec) => {
                assert_eq!(spec.name, "mieru-hop");
                assert_eq!(spec.kind, Some(mihomo_outbound::OutboundKind::Mieru));
                assert_eq!(spec.endpoint.as_ref().unwrap().authority(), "1.2.3.4:443");
            }
            _ => panic!("expected unsupported hop"),
        }
    }

    #[test]
    fn transport_plan_routes_outer_proxy_to_next_hop_endpoint() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: http
    name: leaf
    server: leaf.example.com
    port: 8443
    dialer-proxy: outer
  - type: socks5
    name: outer
    server: outer.example.com
    port: 1080
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan = build_transport_plan(&mut registry, "leaf", &metadata, &BTreeMap::new()).unwrap();
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[0].action {
            TransportAction::Socks5Connect { proxy, target, .. } => {
                assert_eq!(proxy.authority(), "outer.example.com:1080");
                assert_eq!(target.authority(), "leaf.example.com:8443");
            }
            _ => panic!("expected outer socks5 transport action"),
        }
        match &plan.hops[1].action {
            TransportAction::HttpConnect { proxy, target, .. } => {
                assert_eq!(proxy.authority(), "leaf.example.com:8443");
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected leaf http transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_shadowsocks_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: edge-ss
    server: ss.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-ss", &metadata, &BTreeMap::new()).unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
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
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "ss.example.com:8388");
                assert_eq!(cipher, "chacha20-ietf-poly1305");
                assert_eq!(password, "secret");
                assert!(plugin.is_empty());
                assert!(plugin_mode.is_empty());
                assert!(plugin_host.is_empty());
                assert!(websocket.path.is_empty());
                assert!(!tls.enabled);
                assert!(!*mux);
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected shadowsocks transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_shadowsocks_plugin_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: edge-ss
    server: ss.example.com
    port: 443
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: gost-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /relay
      tls: true
      skip-cert-verify: true
      mux: false
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-ss", &metadata, &BTreeMap::new()).unwrap();
        match &plan.hops[0].action {
            TransportAction::ShadowsocksConnect {
                plugin,
                plugin_mode,
                plugin_host,
                websocket,
                tls,
                mux,
                ..
            } => {
                assert_eq!(plugin, "gost-plugin");
                assert_eq!(plugin_mode, "websocket");
                assert_eq!(plugin_host, "ws.example.com");
                assert_eq!(websocket.path, "/relay");
                assert_eq!(websocket.headers["Host"], "ws.example.com");
                assert!(tls.enabled);
                assert_eq!(tls.sni, "ws.example.com");
                assert!(!*mux);
            }
            _ => panic!("expected shadowsocks transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_snell_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: snell.example.com
    port: 8443
    psk: secret-psk
    version: 3
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-snell", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::SnellConnect {
                proxy,
                psk,
                version,
                obfs_mode,
                obfs_host,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "snell.example.com:8443");
                assert_eq!(psk, "secret-psk");
                assert_eq!(*version, 3);
                assert!(obfs_mode.is_empty());
                assert!(obfs_host.is_empty());
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected snell transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_snell_v2_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: snell.example.com
    port: 8443
    psk: secret-psk
    version: 2
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-snell", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::SnellConnect {
                proxy,
                psk,
                version,
                obfs_mode,
                obfs_host,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "snell.example.com:8443");
                assert_eq!(psk, "secret-psk");
                assert_eq!(*version, 2);
                assert!(obfs_mode.is_empty());
                assert!(obfs_host.is_empty());
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected snell transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_trojan_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-trojan", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::TrojanConnect {
                proxy,
                password,
                shadowsocks,
                tls,
                alpn,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "trojan.example.com:443");
                assert_eq!(password, "secret");
                assert!(!shadowsocks.enabled);
                assert!(tls.enabled);
                assert!(tls.skip_cert_verify);
                assert_eq!(alpn, &vec!["h2".to_owned(), "http/1.1".to_owned()]);
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected trojan transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_trojan_grpc_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    ss-opts:
      enabled: true
      method: aes-128-gcm
      password: inner
    network: grpc
    skip-cert-verify: true
    grpc-opts:
      grpc-service-name: example
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-trojan", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::TrojanConnect {
                network,
                shadowsocks,
                grpc,
                target,
                ..
            } => {
                assert_eq!(network, "grpc");
                assert!(shadowsocks.enabled);
                assert_eq!(shadowsocks.method, "aes-128-gcm");
                assert_eq!(shadowsocks.password, "inner");
                assert_eq!(grpc.service_name, "example");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected trojan transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_trojan_http_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    network: http
    skip-cert-verify: true
    http-opts:
      method: PUT
      path: [/tr]
      host: [localhost]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-trojan", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::TrojanConnect {
                network,
                http,
                target,
                ..
            } => {
                assert_eq!(network, "http");
                assert_eq!(http.method, "PUT");
                assert_eq!(http.path, vec!["/tr".to_owned()]);
                assert_eq!(http.host, vec!["localhost".to_owned()]);
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected trojan transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_trusttunnel_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trusttunnel
    name: edge-trust
    server: trust.example.com
    port: 443
    username: alice
    password: secret
    udp: true
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-trust", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::TrustTunnelConnect {
                proxy,
                username,
                password,
                udp,
                quic,
                alpn,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "trust.example.com:443");
                assert_eq!(username, "alice");
                assert_eq!(password, "secret");
                assert!(*udp);
                assert!(!quic);
                assert_eq!(alpn, &vec!["h2".to_owned()]);
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected trusttunnel transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_anytls_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: anytls
    name: edge-anytls
    server: anytls.example.com
    port: 443
    password: secret
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-anytls", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::AnyTlsConnect {
                proxy,
                password,
                tls,
                alpn,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "anytls.example.com:443");
                assert_eq!(password, "secret");
                assert!(tls.enabled);
                assert!(tls.skip_cert_verify);
                assert_eq!(alpn, &vec!["h2".to_owned(), "http/1.1".to_owned()]);
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected anytls transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vless_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vless", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::VlessConnect {
                proxy,
                uuid,
                udp,
                tls,
                h2,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "vless.example.com:443");
                assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert!(*udp);
                assert!(tls.enabled);
                assert!(tls.skip_cert_verify);
                assert_eq!(h2.host, vec!["vless.example.com".to_owned()]);
                assert!(h2.path.is_empty());
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vless transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vless_h2_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: h2
    h2-opts:
      host: [localhost]
      path: /vless-h2
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vless", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::VlessConnect {
                network,
                h2,
                target,
                ..
            } => {
                assert_eq!(network, "h2");
                assert_eq!(h2.host, vec!["localhost".to_owned()]);
                assert_eq!(h2.path, "/vless-h2");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vless transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vless_grpc_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: grpc
    grpc-opts:
      grpc-service-name: example
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vless", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::VlessConnect {
                network,
                grpc,
                target,
                ..
            } => {
                assert_eq!(network, "grpc");
                assert_eq!(grpc.service_name, "example");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vless transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vless_xhttp_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    servername: x.example.com
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vx
      mode: stream-one
      headers:
        X-Test: yes
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vless", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::VlessConnect {
                network,
                xhttp,
                target,
                ..
            } => {
                assert_eq!(network, "xhttp");
                assert_eq!(xhttp.host, "x.example.com");
                assert_eq!(xhttp.path, "/vx");
                assert_eq!(xhttp.mode, "stream-one");
                assert_eq!(xhttp.headers.get("X-Test").map(String::as_str), Some("yes"));
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vless transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vmess_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vmess", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::VmessConnect {
                proxy,
                uuid,
                alter_id,
                cipher,
                h2,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "vmess.example.com:443");
                assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(*alter_id, 0);
                assert_eq!(cipher, "none");
                assert_eq!(h2.host, vec!["vmess.example.com".to_owned()]);
                assert!(h2.path.is_empty());
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vmess transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vmess_h2_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmess-h2
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vmess", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::VmessConnect {
                network,
                h2,
                target,
                ..
            } => {
                assert_eq!(network, "h2");
                assert_eq!(h2.host, vec!["localhost".to_owned()]);
                assert_eq!(h2.path, "/vmess-h2");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vmess transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vmess_grpc_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    network: grpc
    grpc-opts:
      grpc-service-name: example
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vmess", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::VmessConnect {
                network,
                grpc,
                target,
                ..
            } => {
                assert_eq!(network, "grpc");
                assert_eq!(grpc.service_name, "example");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vmess transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_vmess_xhttp_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    tls: true
    servername: x.example.com
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmx
      mode: stream-one
      headers:
        X-Test: yes
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-vmess", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::VmessConnect {
                network,
                xhttp,
                target,
                ..
            } => {
                assert_eq!(network, "xhttp");
                assert_eq!(xhttp.host, "x.example.com");
                assert_eq!(xhttp.path, "/vmx");
                assert_eq!(xhttp.mode, "stream-one");
                assert_eq!(xhttp.headers.get("X-Test").map(String::as_str), Some("yes"));
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected vmess transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_gost_relay_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: gost-relay
    name: relay
    server: relay.example.com
    port: 8443
    username: user
    password: pass
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan = build_transport_plan(&mut registry, "relay", &metadata, &BTreeMap::new()).unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::GostRelay {
                proxy,
                auth,
                forward,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "relay.example.com:8443");
                assert_eq!(auth.as_ref().unwrap().username, "user");
                assert!(!forward);
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected gost relay transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    http-mask: true
    http-mask-mode: ws
    http-mask-tls: true
    http-mask-host: cdn.example.com
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                proxy,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "sudoku.example.com:443");
                assert_eq!(key, "secret-seed");
                assert_eq!(aead_method, "aes-128-gcm");
                assert_eq!(table_type, "prefer_ascii");
                assert_eq!(*padding_min, 12);
                assert_eq!(*padding_max, 30);
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "ws");
                assert!(*http_mask_tls);
                assert_eq!(http_mask_host, "cdn.example.com");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_poll_http_mask_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: poll
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                path_root,
                target,
                ..
            } => {
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "poll");
                assert!(!http_mask_tls);
                assert_eq!(path_root, "mask");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn execution_plan_normalizes_sudoku_poll_http_mask_tls_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: sudoku-hop
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: poll
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "sudoku-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Sudoku(spec) => {
                assert!(spec.http_mask_enabled);
                assert_eq!(spec.http_mask_mode, "poll");
                assert!(spec.http_mask_tls);
                assert_eq!(spec.http_mask_host, "localhost:8443");
                assert_eq!(spec.path_root, "mask");
            }
            _ => panic!("expected sudoku hop"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_poll_http_mask_tls_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: poll
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
                target,
                ..
            } => {
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "poll");
                assert!(*http_mask_tls);
                assert_eq!(http_mask_host, "localhost:8443");
                assert_eq!(path_root, "mask");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_stream_http_mask_tls_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: stream
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
                target,
                ..
            } => {
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "stream");
                assert!(*http_mask_tls);
                assert_eq!(http_mask_host, "localhost:8443");
                assert_eq!(path_root, "mask");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_auto_http_mask_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: auto
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                path_root,
                target,
                ..
            } => {
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "auto");
                assert!(!*http_mask_tls);
                assert_eq!(path_root, "mask");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_auto_http_mask_tls_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: true
    http-mask-mode: auto
    http-mask-tls: true
    http-mask-host: localhost:8443
    path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
                target,
                ..
            } => {
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "auto");
                assert!(*http_mask_tls);
                assert_eq!(http_mask_host, "localhost:8443");
                assert_eq!(path_root, "mask");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_sudoku_nested_httpmask_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    httpmask:
      disable: false
      mode: auto
      tls: true
      host: localhost:8443
      path-root: mask
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan =
            build_transport_plan(&mut registry, "edge-sudoku", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::SudokuConnect {
                http_mask_enabled,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
                target,
                ..
            } => {
                assert!(*http_mask_enabled);
                assert_eq!(http_mask_mode, "auto");
                assert!(*http_mask_tls);
                assert_eq!(http_mask_host, "localhost:8443");
                assert_eq!(path_root, "mask");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected sudoku transport action"),
        }
    }

    #[test]
    fn transport_plan_keeps_unsupported_leaf_endpoint_for_dialer_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: mieru
    name: leaf
    server: leaf.example.com
    port: 443
    dialer-proxy: outer
  - type: socks5
    name: outer
    server: outer.example.com
    port: 1080
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(8443),
            ..Metadata::default()
        };
        let plan = build_transport_plan(&mut registry, "leaf", &metadata, &BTreeMap::new()).unwrap();
        match &plan.hops[0].action {
            TransportAction::Socks5Connect { target, .. } => {
                assert_eq!(target.authority(), "leaf.example.com:443");
            }
            _ => panic!("expected outer socks5 action"),
        }
        match &plan.hops[1].action {
            TransportAction::Unsupported {
                endpoint, target, ..
            } => {
                assert_eq!(endpoint.as_ref().unwrap().authority(), "leaf.example.com:443");
                assert_eq!(target.as_ref().unwrap().authority(), "final.example.com:8443");
            }
            _ => panic!("expected unsupported transport action"),
        }
    }

    #[test]
    fn transport_plan_runner_records_materialized_order() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: leaf
    dialer-proxy: outer
  - type: direct
    name: outer
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let plan = build_transport_plan(&mut registry, "leaf", &metadata, &BTreeMap::new()).unwrap();
        let mut runner = RecordingTransportRunner::default();
        let steps = runner.run_plan(&plan).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].summary, "direct->final.example.com:443");
        assert_eq!(steps[1].summary, "direct->final.example.com:443");
    }

    #[test]
    fn connect_target_executes_runtime_transport_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: http
    name: leaf
    server: leaf.example.com
    port: 8443
    dialer-proxy: outer
  - type: socks5
    name: outer
    server: outer.example.com
    port: 1080
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let metadata = Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
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
        let mut executor = TcpTransportExecutor::new(dialer);

        connect_target(
            &mut registry,
            "leaf",
            &metadata,
            &BTreeMap::new(),
            &mut executor,
        )
        .unwrap();

        let written = handle.writes();
        let request_offset = written
            .windows("CONNECT ".len())
            .position(|window| window == b"CONNECT ")
            .unwrap();
        let request = String::from_utf8(written[request_offset..].to_vec()).unwrap();
        assert!(request.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert_eq!(executor.dialer().calls, vec!["outer.example.com:1080"]);
        assert_eq!(executor.trace().len(), 2);
    }
}
