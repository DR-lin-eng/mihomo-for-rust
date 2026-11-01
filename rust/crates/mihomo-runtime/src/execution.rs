use std::collections::BTreeMap;

use mihomo_core::{BoxedTcpStream, Metadata};
use mihomo_outbound::{OutboundDefinition, OutboundKind};
use mihomo_transport::{
    GrpcOptions as TransportGrpcOptions,
    Http2Options as TransportHttp2Options,
    HttpStreamOptions as TransportHttpStreamOptions,
    OuterSocks5UdpPlan,
    TcpDialer, TcpTransportExecutor,
    TransportAction, TransportError, TransportHop, TransportPlan, TransportPlanRunner,
    TransportTarget,
    TrojanShadowsocksOptions as TransportTrojanShadowsocksOptions,
    WebsocketOptions as TransportWebsocketOptions,
    XHttpOptions as TransportXHttpOptions,
};
use serde_yaml::Value;

use crate::execution_helpers::{
    basic_auth, grpc_options, h2_options, http_options, nested_value_as_bool,
    nested_value_as_string, nested_value_as_u64, resolve_padding_max,
    resolve_padding_min, shadowsocks_plugin_mux,
    shadowsocks_plugin_tls_options, shadowsocks_plugin_websocket_options, socket_options,
    string_list, string_map, sudoku_http_mask_enabled, sudoku_http_mask_host,
    sudoku_http_mask_mode, sudoku_http_mask_path_root, sudoku_http_mask_tls, tls_options,
    transport_basic_auth, transport_socket_options, transport_tls_options,
    transport_wireguard_peers, trojan_shadowsocks_options, value_as_bool,
    value_as_bool_with_default, value_as_string, value_as_u16, value_as_u32, value_as_u64,
    value_as_u8, websocket_options, wireguard_peer_specs, xhttp_options,
};
use crate::{resolve_proxy_path, CandidateState, ProxySource, ResolveError, RuntimeRegistry};
use crate::support_helpers::{nested_map, nested_mapping_bool, nested_mapping_string};

const DEFAULT_TROJAN_ALPN: &[&str] = &["h2", "http/1.1"];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
pub struct HysteriaConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub ports: String,
    pub protocol: String,
    pub auth: String,
    pub auth_str: String,
    pub obfs: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    pub up: String,
    pub down: String,
    pub up_speed: u32,
    pub down_speed: u32,
    pub disable_mtu_discovery: bool,
    pub fast_open: bool,
    pub hop_interval: u32,
    pub tls: TlsOptions,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hy2ConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub obfs: String,
    pub obfs_password: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub realm_enabled: bool,
    pub realm_server_url: String,
    pub realm_token: String,
    pub realm_id: String,
    pub realm_stun_servers: Vec<String>,
    pub realm_sni: String,
    pub realm_skip_cert_verify: bool,
    pub realm_fingerprint: String,
    pub realm_certificate: String,
    pub realm_private_key: String,
    pub realm_alpn: Vec<String>,
    pub realm_proxy: String,
    pub tls: TlsOptions,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    pub token: String,
    pub udp: bool,
    pub sni: String,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub request_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub congestion_controller: String,
    pub max_open_streams: u32,
    pub max_udp_relay_packet_size: u32,
    pub tls: TlsOptions,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPeerHopSpec {
    pub server: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardConnectHopSpec {
    pub private_key: String,
    pub ip: String,
    pub ipv6: String,
    pub udp: bool,
    pub mtu: usize,
    pub workers: usize,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub peers: Vec<WireGuardPeerHopSpec>,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVpnConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub proto: String,
    pub dev: String,
    pub cipher: String,
    pub auth: String,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub tls_crypt: String,
    pub username: String,
    pub password: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub udp: bool,
    pub mtu: usize,
    pub socket: SocketOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasqueConnectHopSpec {
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub ip: String,
    pub ipv6: String,
    pub uri: String,
    pub sni: String,
    pub udp: bool,
    pub mtu: usize,
    pub network: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
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
    pub h2: TransportHttp2Options,
    pub http: TransportHttpStreamOptions,
    pub xhttp: TransportXHttpOptions,
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
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub reality_support_x25519mlkem768: bool,
    pub client_fingerprint: String,
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
    Hysteria(HysteriaConnectHopSpec),
    Hy2(Hy2ConnectHopSpec),
    Tuic(TuicConnectHopSpec),
    WireGuard(WireGuardConnectHopSpec),
    OpenVpn(OpenVpnConnectHopSpec),
    Masque(MasqueConnectHopSpec),
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

impl ExecutionError {
    pub(crate) fn with_dial_context(self,plan:&ExecutionPlan,metadata:&Metadata)->Self {
        let context=format!("proxy={} chain={} target={}",plan.leaf_name,plan.selected_path.join(" -> "),metadata.remote_address().unwrap_or_default());
        match self {
            Self::Transport(TransportError::Io{kind,message})=>Self::Transport(TransportError::Io{kind,message:format!("{message} ({context})")}),
            Self::Transport(TransportError::InvalidProxyResponse(message))=>Self::Transport(TransportError::InvalidProxyResponse(format!("{message} ({context})"))),
            error=>error,
        }
    }
}

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
    if let Some((leaf_index, leaf_hop)) = plan.hops.iter().enumerate().next_back() {
        if matches!(leaf_hop.spec, ExecutionHopSpec::WireGuard(_)) {
            let mut action = transport_action(&leaf_hop.spec, final_target.clone());
            if leaf_index > 0 {
                let TransportAction::WireGuardConnect { outer_socks5, .. } = &mut action else {
                    unreachable!("wireguard transport action shape changed unexpectedly");
                };
                *outer_socks5 = Some(build_outer_socks5_udp_plan(plan, leaf_index)?);
            }
            return Ok(TransportPlan {
                requested: plan.requested.clone(),
                selected_path: plan.selected_path.clone(),
                leaf_name: plan.leaf_name.clone(),
                hops: vec![TransportHop {
                    name: leaf_hop.name.clone(),
                    action,
                }],
            });
        }
        if let ExecutionHopSpec::OpenVpn(spec) = &leaf_hop.spec {
            let mut action = transport_action(&leaf_hop.spec, final_target.clone());
            if leaf_index > 0 && normalize_openvpn_leaf_proto(&spec.proto) == "udp" {
                let TransportAction::OpenVpnConnect { outer_socks5, .. } = &mut action else {
                    unreachable!("openvpn transport action shape changed unexpectedly");
                };
                *outer_socks5 = Some(build_outer_socks5_udp_plan(plan, leaf_index)?);
                return Ok(TransportPlan {
                    requested: plan.requested.clone(),
                    selected_path: plan.selected_path.clone(),
                    leaf_name: plan.leaf_name.clone(),
                    hops: vec![TransportHop {
                        name: leaf_hop.name.clone(),
                        action,
                    }],
                });
            }
        }
    }
    let mut hops = Vec::new();
    for (index, hop) in plan.hops.iter().enumerate() {
        let downstream = downstream_target(&plan.hops, index, &final_target);
        let mut action = transport_action(&hop.spec, downstream.clone());
        if let (
            ExecutionHopSpec::Hy2(spec),
            TransportAction::Hy2Connect { realm_proxy_plan, .. },
        ) = (&hop.spec, &mut action)
        {
            if hy2_realm_proxy_uses_named_proxy(&spec.realm_proxy) {
                let nested =
                    build_transport_plan_for_named_hy2_realm_proxy(plan, index, spec)?;
                *realm_proxy_plan = Some(Box::new(nested));
            }
        }
        hops.push(TransportHop {
            name: hop.name.clone(),
            action,
        });
    }

    Ok(TransportPlan {
        requested: plan.requested.clone(),
        selected_path: plan.selected_path.clone(),
        leaf_name: plan.leaf_name.clone(),
        hops,
    })
}

fn hy2_realm_proxy_uses_named_proxy(realm_proxy: &str) -> bool {
    let value = realm_proxy.trim();
    !value.is_empty() && !value.eq_ignore_ascii_case("DIRECT") && !value.contains("://")
}

fn build_transport_plan_for_named_hy2_realm_proxy(
    plan: &ExecutionPlan,
    hy2_index: usize,
    spec: &Hy2ConnectHopSpec,
) -> Result<TransportPlan, ExecutionError> {
    if hy2_index == 0 {
        return Err(ExecutionError::Transport(TransportError::InvalidPlan(
            "hysteria2 realm proxy name requires at least one proxy hop".to_owned(),
        )));
    }
    let target = realm_control_target(&spec.realm_server_url)?;

    let mut nested = build_transport_plan_for_prefix(plan, hy2_index, &target)?;
    nested.requested = spec.realm_proxy.clone();
    nested.leaf_name = spec.realm_proxy.clone();
    Ok(nested)
}

fn build_outer_socks5_udp_plan(
    plan: &ExecutionPlan,
    leaf_index: usize,
) -> Result<OuterSocks5UdpPlan, ExecutionError> {
    let outer_index = leaf_index.checked_sub(1).ok_or_else(|| {
        ExecutionError::Transport(TransportError::InvalidPlan(
            "outer socks5 udp plan requires at least one proxy hop".to_owned(),
        ))
    })?;
    let outer_hop = plan.hops.get(outer_index).ok_or_else(|| {
        ExecutionError::Transport(TransportError::InvalidPlan(
            "outer socks5 udp hop is missing".to_owned(),
        ))
    })?;
    let ExecutionHopSpec::Socks5Connect(spec) = &outer_hop.spec else {
        return Err(ExecutionError::Transport(TransportError::InvalidPlan(
            "wireguard outer udp plan currently requires an outer socks5 proxy".to_owned(),
        )));
    };
    if !spec.udp {
        return Err(ExecutionError::Transport(TransportError::InvalidPlan(
            "wireguard outer udp plan requires socks5 udp support on the outer proxy".to_owned(),
        )));
    }
    let prefix_plan = if outer_index == 0 {
        None
    } else {
        Some(Box::new(build_transport_plan_for_prefix(
            plan,
            outer_index,
            &TransportTarget::new(&spec.server, spec.port),
        )?))
    };
    Ok(OuterSocks5UdpPlan {
        proxy: TransportTarget::new(&spec.server, spec.port),
        auth: transport_basic_auth(&spec.auth),
        prefix_plan,
    })
}

fn normalize_openvpn_leaf_proto(proto: &str) -> &'static str {
    match proto.trim().to_ascii_lowercase().as_str() {
        "" | "udp" | "udp4" => "udp",
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => "tcp",
        _ => "other",
    }
}

fn realm_control_target(server_url: &str) -> Result<TransportTarget, ExecutionError> {
    let url = server_url.trim();
    let (_, rest) = url.split_once("://").ok_or_else(|| {
        ExecutionError::Transport(TransportError::InvalidPlan(format!(
            "invalid hysteria2 realm server-url: {server_url}"
        )))
    })?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(ExecutionError::Transport(TransportError::InvalidPlan(format!(
            "invalid hysteria2 realm server-url authority: {server_url}"
        ))));
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']').ok_or_else(|| {
            ExecutionError::Transport(TransportError::InvalidPlan(format!(
                "invalid hysteria2 realm ipv6 authority: {server_url}"
            )))
        })?;
        let port = rest
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_else(|| if url.starts_with("https://") { 443 } else { 80 });
        return Ok(TransportTarget::new(host, port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.chars().all(|ch| ch.is_ascii_digit()) {
            let port = port.parse::<u16>().map_err(|err| {
                ExecutionError::Transport(TransportError::InvalidPlan(format!(
                    "invalid hysteria2 realm server-url port {port:?}: {err}"
                )))
            })?;
            return Ok(TransportTarget::new(host, port));
        }
    }
    Ok(TransportTarget::new(
        authority,
        if url.starts_with("https://") { 443 } else { 80 },
    ))
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

pub fn build_transport_plan_for_prefix(
    plan: &ExecutionPlan,
    hop_count: usize,
    target: &TransportTarget,
) -> Result<TransportPlan, ExecutionError> {
    if hop_count == 0 || hop_count > plan.hops.len() {
        return Err(ExecutionError::Transport(TransportError::InvalidPlan(format!(
            "invalid prefix transport plan hop_count={} total={}",
            hop_count,
            plan.hops.len()
        ))));
    }

    let nested_hops = plan.hops[..hop_count]
        .iter()
        .enumerate()
        .map(|(index, hop)| {
            let downstream = if index + 1 == hop_count {
                target.clone()
            } else {
                proxy_endpoint(&plan.hops[index + 1].spec).unwrap_or_else(|| target.clone())
            };
            TransportHop {
                name: hop.name.clone(),
                action: transport_action(&hop.spec, downstream),
            }
        })
        .collect::<Vec<_>>();

    Ok(TransportPlan {
        requested: plan.requested.clone(),
        selected_path: plan.selected_path.iter().take(hop_count).cloned().collect(),
        leaf_name: plan.hops[hop_count - 1].name.clone(),
        hops: nested_hops,
    })
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
            build_execution_hop_spec(definition)
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

pub fn build_execution_hop_spec(definition: OutboundDefinition) -> ExecutionHopSpec {
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
        OutboundDefinition::Hysteria(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            ExecutionHopSpec::Hysteria(HysteriaConnectHopSpec {
                server: config.server,
                port: config.port,
                ports: value_as_string(&config.extra, "ports").unwrap_or_default(),
                protocol: value_as_string(&config.extra, "protocol")
                    .or_else(|| value_as_string(&config.extra, "obfs-protocol"))
                    .unwrap_or_default(),
                auth: value_as_string(&config.extra, "auth").unwrap_or_default(),
                auth_str: value_as_string(&config.extra, "auth-str").unwrap_or_default(),
                obfs: value_as_string(&config.extra, "obfs").unwrap_or_default(),
                sni: tls.sni.clone(),
                alpn: string_list(&config.extra, "alpn"),
                skip_cert_verify: tls.skip_cert_verify,
                up: value_as_string(&config.extra, "up").unwrap_or_default(),
                down: value_as_string(&config.extra, "down").unwrap_or_default(),
                up_speed: value_as_u32(&config.extra, "up-speed").unwrap_or_default(),
                down_speed: value_as_u32(&config.extra, "down-speed").unwrap_or_default(),
                disable_mtu_discovery: value_as_bool(&config.extra, "disable-mtu-discovery"),
                fast_open: value_as_bool(&config.extra, "fast-open"),
                hop_interval: value_as_u32(&config.extra, "hop-interval").unwrap_or_default(),
                tls,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::Hysteria2(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            let realm = nested_map(&config.extra, "realm-opts");
            ExecutionHopSpec::Hy2(Hy2ConnectHopSpec {
                server: config.server,
                port: config.port,
                password: value_as_string(&config.extra, "password").unwrap_or_default(),
                obfs: value_as_string(&config.extra, "obfs").unwrap_or_default(),
                obfs_password: value_as_string(&config.extra, "obfs-password").unwrap_or_default(),
                up_mbps: value_as_u32(&config.extra, "up").unwrap_or_default(),
                down_mbps: value_as_u32(&config.extra, "down").unwrap_or_default(),
                realm_enabled: nested_mapping_bool(realm, "enable"),
                realm_server_url: nested_mapping_string(realm, "server-url"),
                realm_token: nested_mapping_string(realm, "token"),
                realm_id: nested_mapping_string(realm, "realm-id"),
                realm_stun_servers: realm
                    .and_then(|mapping| mapping.get(Value::String("stun-servers".to_owned())))
                    .and_then(Value::as_sequence)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(ToOwned::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                realm_sni: nested_mapping_string(realm, "sni"),
                realm_skip_cert_verify: nested_mapping_bool(realm, "skip-cert-verify"),
                realm_fingerprint: nested_mapping_string(realm, "fingerprint"),
                realm_certificate: nested_mapping_string(realm, "certificate"),
                realm_private_key: nested_mapping_string(realm, "private-key"),
                realm_alpn: realm
                    .and_then(|mapping| mapping.get(Value::String("alpn".to_owned())))
                    .and_then(Value::as_sequence)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(ToOwned::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                realm_proxy: nested_mapping_string(realm, "proxy"),
                tls,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::Tuic(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            ExecutionHopSpec::Tuic(TuicConnectHopSpec {
                server: config.server,
                port: config.port,
                uuid: value_as_string(&config.extra, "uuid").unwrap_or_default(),
                password: value_as_string(&config.extra, "password").unwrap_or_default(),
                token: value_as_string(&config.extra, "token").unwrap_or_default(),
                udp: value_as_bool(&config.extra, "udp"),
                sni: tls.sni.clone(),
                alpn: string_list(&config.extra, "alpn"),
                disable_sni: value_as_bool(&config.extra, "disable-sni"),
                request_timeout_ms: value_as_u64(&config.extra, "request-timeout").unwrap_or(8_000),
                heartbeat_interval_ms: value_as_u64(&config.extra, "heartbeat-interval").unwrap_or(10_000),
                congestion_controller: value_as_string(&config.extra, "congestion-controller")
                    .unwrap_or_default(),
                max_open_streams: value_as_u32(&config.extra, "max-open-streams").unwrap_or(100),
                max_udp_relay_packet_size: value_as_u32(&config.extra, "max-udp-relay-packet-size")
                    .unwrap_or(1_252),
                tls,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::WireGuard(config) => {
            let peers = wireguard_peer_specs(&config);
            ExecutionHopSpec::WireGuard(WireGuardConnectHopSpec {
                private_key: config.private_key,
                ip: config.ip,
                ipv6: config.ipv6,
                udp: value_as_bool_with_default(&config.extra, "udp", true),
                mtu: value_as_u32(&config.extra, "mtu").unwrap_or(1420) as usize,
                workers: value_as_u32(&config.extra, "workers").unwrap_or(0) as usize,
                remote_dns_resolve: value_as_bool(&config.extra, "remote-dns-resolve"),
                dns: string_list(&config.extra, "dns"),
                peers,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::OpenVpn(config) => {
            ExecutionHopSpec::OpenVpn(OpenVpnConnectHopSpec {
                server: config.server,
                port: config.port,
                proto: value_as_string(&config.extra, "proto")
                    .unwrap_or_else(|| "udp".to_owned()),
                dev: value_as_string(&config.extra, "dev")
                    .unwrap_or_else(|| "tun".to_owned()),
                cipher: value_as_string(&config.extra, "cipher")
                    .unwrap_or_else(|| "AES-128-GCM".to_owned()),
                auth: value_as_string(&config.extra, "auth")
                    .unwrap_or_else(|| "SHA256".to_owned()),
                ca: value_as_string(&config.extra, "ca").unwrap_or_default(),
                cert: value_as_string(&config.extra, "cert").unwrap_or_default(),
                key: value_as_string(&config.extra, "key").unwrap_or_default(),
                tls_crypt: value_as_string(&config.extra, "tls-crypt").unwrap_or_default(),
                username: value_as_string(&config.extra, "username").unwrap_or_default(),
                password: value_as_string(&config.extra, "password").unwrap_or_default(),
                remote_dns_resolve: value_as_bool(&config.extra, "remote-dns-resolve"),
                dns: string_list(&config.extra, "dns"),
                udp: value_as_bool_with_default(&config.extra, "udp", true),
                mtu: value_as_u32(&config.extra, "mtu").unwrap_or(1500) as usize,
                socket: socket_options(&config.base),
            })
        }
        OutboundDefinition::Masque(config) => {
            let mut tls = tls_options(&config.extra, "sni");
            tls.enabled = true;
            if tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            ExecutionHopSpec::Masque(MasqueConnectHopSpec {
                server: config.server,
                port: config.port,
                private_key: value_as_string(&config.extra, "private-key").unwrap_or_default(),
                public_key: value_as_string(&config.extra, "public-key").unwrap_or_default(),
                ip: value_as_string(&config.extra, "ip").unwrap_or_default(),
                ipv6: value_as_string(&config.extra, "ipv6").unwrap_or_default(),
                uri: value_as_string(&config.extra, "uri")
                    .unwrap_or_else(|| "https://cloudflareaccess.com".to_owned()),
                sni: tls.sni.clone(),
                udp: value_as_bool_with_default(&config.extra, "udp", true),
                mtu: value_as_u32(&config.extra, "mtu").unwrap_or(1280) as usize,
                network: value_as_string(&config.extra, "network").unwrap_or_default(),
                remote_dns_resolve: value_as_bool(&config.extra, "remote-dns-resolve"),
                dns: string_list(&config.extra, "dns"),
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
                h2: h2_options(&config.extra, &default_host),
                http: http_options(&config.extra, &default_host),
                xhttp: xhttp_options(&config.extra, &default_host),
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
            // Go reads `servername` for vless; also accept `server-name`.
            let mut tls = tls_options(&config.extra, "server-name");
            if tls.enabled && tls.sni.trim().is_empty() {
                tls.sni = config.server.clone();
            }
            if !config.extra.contains_key("reality-opts")
                && tls.enabled
                && tls.sni.trim().is_empty()
            {
                tls.sni = value_as_string(&config.extra, "servername").unwrap_or_default();
            }
            let default_host = config.server.clone();
            let flow = value_as_string(&config.extra, "flow").unwrap_or_default();
            let packet_addr = value_as_bool(&config.extra, "packet-addr")
                || matches!(value_as_string(&config.extra, "packet-encoding").as_deref(), Some("packetaddr" | "packet"));
            // Vision UDP uses XUDP by default, as in the Go client. sing-box
            // rejects the ordinary UDP command when the account requires flow.
            let xudp = value_as_bool(&config.extra, "xudp")
                || (flow == "xtls-rprx-vision" && !packet_addr);
            ExecutionHopSpec::Vless(VlessConnectHopSpec {
                server: config.server,
                port: config.port,
                uuid: value_as_string(&config.extra, "uuid").unwrap_or_default(),
                flow,
                reality_public_key: nested_value_as_string(&config.extra, "reality-opts", "public-key")
                    .unwrap_or_default(),
                reality_short_id: nested_value_as_string(&config.extra, "reality-opts", "short-id")
                    .or_else(|| nested_value_as_u64(&config.extra, "reality-opts", "short-id").map(|value| value.to_string()))
                    .unwrap_or_default(),
                reality_support_x25519mlkem768: nested_value_as_bool(
                    &config.extra,
                    "reality-opts",
                    "support-x25519mlkem768",
                ),
                client_fingerprint: value_as_string(&config.extra, "client-fingerprint")
                    .unwrap_or_default(),
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
                packet_addr,
                xudp,
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

pub fn execution_hop_udp_gap(spec: &ExecutionHopSpec) -> Option<String> {
    match spec {
        ExecutionHopSpec::Direct(_)
        | ExecutionHopSpec::Dns(_)
        | ExecutionHopSpec::ShadowSocks(_)
        | ExecutionHopSpec::Hysteria(_)
        | ExecutionHopSpec::Hy2(_)
        | ExecutionHopSpec::GostRelay(_)
        | ExecutionHopSpec::Sudoku(_) => None,
        ExecutionHopSpec::Socks5Connect(spec) if spec.udp => None,
        ExecutionHopSpec::Socks5Connect(_) => Some("selected socks5 outbound does not enable udp".to_owned()),
        ExecutionHopSpec::Ssr(spec)
            if spec.udp
                && (spec.cipher.trim().is_empty()
                    || spec.cipher == "dummy"
                    || spec.cipher == "none"
                    || spec.cipher == "aes-128-cfb"
                    || spec.cipher == "aes-192-cfb"
                    || spec.cipher == "aes-256-cfb")
                && (spec.obfs.trim().is_empty()
                    || spec.obfs == "plain"
                    || spec.obfs == "http_simple"
                    || spec.obfs == "http_post")
                && (spec.protocol.trim().is_empty() || spec.protocol == "origin")
                && (spec.obfs_param.trim().is_empty()
                    || spec.obfs == "plain"
                    || spec.obfs == "http_simple"
                    || spec.obfs == "http_post")
                && (spec.protocol_param.trim().is_empty() || spec.protocol == "origin") =>
        {
            None
        }
        ExecutionHopSpec::Ssr(spec) if !spec.udp => Some("selected ssr outbound does not enable udp".to_owned()),
        ExecutionHopSpec::Ssr(spec) if !spec.cipher.trim().is_empty() && spec.cipher != "dummy" && spec.cipher != "none" => {
            Some(format!("selected ssr cipher is not implemented for udp: {}", spec.cipher))
        }
        ExecutionHopSpec::Ssr(spec) if !spec.obfs.trim().is_empty() && spec.obfs != "plain" => {
            Some(format!("selected ssr obfs is not implemented for udp: {}", spec.obfs))
        }
        ExecutionHopSpec::Ssr(spec)
            if !spec.obfs_param.trim().is_empty()
                && spec.obfs != "plain"
                && spec.obfs != "http_simple"
                && spec.obfs != "http_post" =>
        {
            Some("selected ssr obfs-param is not implemented for udp".to_owned())
        }
        ExecutionHopSpec::Ssr(spec)
            if !spec.protocol.trim().is_empty() && spec.protocol != "origin" =>
        {
            Some(format!("selected ssr protocol is not implemented for udp: {}", spec.protocol))
        }
        ExecutionHopSpec::Ssr(spec)
            if !spec.protocol_param.trim().is_empty() && spec.protocol != "origin" =>
        {
            Some("selected ssr protocol-param is not implemented for udp".to_owned())
        }
        ExecutionHopSpec::AnyTls(spec) if spec.udp => None,
        ExecutionHopSpec::AnyTls(_) => Some("selected anytls outbound does not enable udp".to_owned()),
        ExecutionHopSpec::Tuic(spec) if spec.udp => None,
        ExecutionHopSpec::Tuic(_) => Some("selected tuic outbound does not enable udp".to_owned()),
        ExecutionHopSpec::WireGuard(spec) if spec.udp => None,
        ExecutionHopSpec::WireGuard(_) => Some("selected wireguard outbound does not enable udp".to_owned()),
        ExecutionHopSpec::OpenVpn(spec) if spec.udp => None,
        ExecutionHopSpec::OpenVpn(_) => Some("selected openvpn outbound does not enable udp".to_owned()),
        ExecutionHopSpec::Masque(spec)
            if spec.udp
                && spec.network == "h2"
                && (!spec.remote_dns_resolve || !spec.dns.is_empty()) =>
        {
            None
        }
        ExecutionHopSpec::Masque(spec) if !spec.udp => {
            Some("selected masque outbound does not enable udp".to_owned())
        }
        ExecutionHopSpec::Masque(spec) if spec.network != "h2" =>
        {
            Some(format!(
                "selected masque outbound network is not implemented for udp: {}",
                if spec.network.trim().is_empty() {
                    "<default>"
                } else {
                    spec.network.as_str()
                }
            ))
        }
        ExecutionHopSpec::Masque(spec) if spec.remote_dns_resolve && spec.dns.is_empty() => {
            Some(
                "selected masque outbound remote dns resolution requires explicit dns servers for udp"
                    .to_owned(),
            )
        }
        ExecutionHopSpec::Masque(_) => None,
        ExecutionHopSpec::Snell(spec)
            if spec.version >= 3
                && (spec.obfs_mode.trim().is_empty()
                    || spec.obfs_mode == "tls"
                    || spec.obfs_mode == "http") =>
        {
            None
        }
        ExecutionHopSpec::Snell(spec) if spec.version < 3 => {
            Some(format!("selected snell outbound version {} does not support udp", spec.version))
        }
        ExecutionHopSpec::Snell(spec) => {
            Some(format!("selected snell outbound obfs is not implemented for udp: {}", spec.obfs_mode))
        }
        ExecutionHopSpec::Trojan(spec)
            if spec.udp
                && (spec.network.trim().is_empty()
                    || spec.network == "tcp"
                    || spec.network == "ws"
                    || spec.network == "http"
                    || spec.network == "grpc"
                    || spec.network == "h2"
                    || spec.network == "xhttp") =>
        {
            None
        }
        ExecutionHopSpec::Trojan(spec) if !spec.udp => {
            Some("selected trojan outbound does not enable udp".to_owned())
        }
        ExecutionHopSpec::Trojan(spec) => {
            Some(format!("selected trojan outbound network is not implemented for udp: {}", spec.network))
        }
        ExecutionHopSpec::TrustTunnel(spec) if spec.udp => None,
        ExecutionHopSpec::TrustTunnel(_) => Some("selected trusttunnel outbound does not enable udp".to_owned()),
        ExecutionHopSpec::Vless(spec)
            if spec.udp
                && (spec.network.trim().is_empty()
                    || spec.network == "tcp"
                    || spec.network == "grpc"
                    || spec.network == "h2"
                    || spec.network == "http"
                    || spec.network == "xhttp"
                    || spec.network == "ws")
                && (spec.flow.trim().is_empty()
                    || (spec.flow == "xtls-rprx-vision"
                        && spec.tls.enabled
                        && (spec.network.is_empty() || spec.network == "tcp")))
                && (spec.encryption.trim().is_empty() || spec.encryption == "none") =>
        {
            None
        }
        ExecutionHopSpec::Vless(spec) if !spec.udp => {
            Some("selected vless outbound does not enable udp".to_owned())
        }
        ExecutionHopSpec::Vless(spec) if !spec.flow.trim().is_empty() => {
            Some(format!("selected vless outbound flow is not implemented for udp: {}", spec.flow))
        }
        ExecutionHopSpec::Vless(spec)
            if !spec.encryption.trim().is_empty() && spec.encryption != "none" =>
        {
            Some(format!("selected vless encryption is not implemented for udp: {}", spec.encryption))
        }
        ExecutionHopSpec::Vless(spec) => {
            Some(format!("selected vless outbound network is not implemented for udp: {}", spec.network))
        }
        ExecutionHopSpec::Vmess(spec)
            if spec.udp
                && (spec.network.trim().is_empty()
                    || spec.network == "tcp"
                    || spec.network == "grpc"
                    || spec.network == "h2"
                    || spec.network == "http"
                    || spec.network == "xhttp"
                    || spec.network == "ws") =>
        {
            None
        }
        ExecutionHopSpec::Vmess(spec) if !spec.udp => {
            Some("selected vmess outbound does not enable udp".to_owned())
        }
        ExecutionHopSpec::Vmess(spec) => {
            Some(format!("selected vmess outbound network is not implemented for udp: {}", spec.network))
        }
        other => Some(format!("udp outbound is not implemented for {other:?}")),
    }
}

pub fn outbound_udp_support_gap(definition: &OutboundDefinition) -> Option<String> {
    let spec = build_execution_hop_spec(definition.clone());
    execution_hop_udp_gap(&spec)
}

pub fn outbound_supports_udp(definition: &OutboundDefinition) -> bool {
    outbound_udp_support_gap(definition).is_none()
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
        ExecutionHopSpec::Hysteria(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Hy2(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Tuic(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::WireGuard(spec) => spec
            .peers
            .first()
            .map(|peer| TransportTarget::new(&peer.server, peer.port)),
        ExecutionHopSpec::OpenVpn(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
        ExecutionHopSpec::Masque(spec) => Some(TransportTarget::new(&spec.server, spec.port)),
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
        ExecutionHopSpec::Hysteria(spec) => TransportAction::HysteriaConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            ports: spec.ports.clone(),
            protocol: spec.protocol.clone(),
            auth: spec.auth.clone(),
            auth_str: spec.auth_str.clone(),
            obfs: spec.obfs.clone(),
            sni: spec.sni.clone(),
            alpn: if spec.alpn.is_empty() {
                vec!["hysteria".to_owned()]
            } else {
                spec.alpn.clone()
            },
            up: spec.up.clone(),
            down: spec.down.clone(),
            up_speed: spec.up_speed,
            down_speed: spec.down_speed,
            disable_mtu_discovery: spec.disable_mtu_discovery,
            fast_open: spec.fast_open,
            hop_interval: spec.hop_interval,
            skip_cert_verify: spec.skip_cert_verify,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Hy2(spec) => TransportAction::Hy2Connect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            password: spec.password.clone(),
            sni: spec.tls.sni.clone(),
            certificate: spec.tls.certificate.clone(),
            private_key: spec.tls.private_key.clone(),
            obfs: spec.obfs.clone(),
            obfs_password: spec.obfs_password.clone(),
            realm_enabled: spec.realm_enabled,
            realm_server_url: spec.realm_server_url.clone(),
            realm_token: spec.realm_token.clone(),
            realm_id: spec.realm_id.clone(),
            realm_stun_servers: spec.realm_stun_servers.clone(),
            realm_sni: spec.realm_sni.clone(),
            realm_skip_cert_verify: spec.realm_skip_cert_verify,
            realm_fingerprint: spec.realm_fingerprint.clone(),
            realm_certificate: spec.realm_certificate.clone(),
            realm_private_key: spec.realm_private_key.clone(),
            realm_alpn: spec.realm_alpn.clone(),
            realm_proxy: spec.realm_proxy.clone(),
            realm_proxy_plan: None,
            skip_cert_verify: spec.tls.skip_cert_verify,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Tuic(spec) => TransportAction::TuicConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            uuid: spec.uuid.clone(),
            password: spec.password.clone(),
            token: spec.token.clone(),
            udp: spec.udp,
            sni: spec.sni.clone(),
            certificate: spec.tls.certificate.clone(),
            private_key: spec.tls.private_key.clone(),
            alpn: if spec.alpn.is_empty() {
                vec!["h3".to_owned()]
            } else {
                spec.alpn.clone()
            },
            disable_sni: spec.disable_sni,
            request_timeout_ms: spec.request_timeout_ms,
            heartbeat_interval_ms: spec.heartbeat_interval_ms,
            congestion_controller: spec.congestion_controller.clone(),
            max_open_streams: spec.max_open_streams,
            max_udp_relay_packet_size: spec.max_udp_relay_packet_size,
            tls: transport_tls_options(&spec.tls),
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::WireGuard(spec) => TransportAction::WireGuardConnect {
            proxy: TransportTarget::new(
                spec.peers
                    .first()
                    .map(|peer| peer.server.as_str())
                    .unwrap_or_default(),
                spec.peers.first().map(|peer| peer.port).unwrap_or(0),
            ),
            private_key: spec.private_key.clone(),
            ip: spec.ip.clone(),
            ipv6: spec.ipv6.clone(),
            workers: spec.workers,
            tunnel_dns: mihomo_transport::TunnelDnsOptions {
                remote_dns_resolve: spec.remote_dns_resolve,
                dns: spec.dns.clone(),
            },
            peers: transport_wireguard_peers(&spec.peers),
            outer_socks5: None,
            mtu: spec.mtu,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::OpenVpn(spec) => TransportAction::OpenVpnConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            proto: spec.proto.clone(),
            dev: spec.dev.clone(),
            cipher: spec.cipher.clone(),
            auth: spec.auth.clone(),
            ca: spec.ca.clone(),
            cert: spec.cert.clone(),
            key: spec.key.clone(),
            tls_crypt: spec.tls_crypt.clone(),
            username: spec.username.clone(),
            password: spec.password.clone(),
            tunnel_dns: mihomo_transport::TunnelDnsOptions {
                remote_dns_resolve: spec.remote_dns_resolve,
                dns: spec.dns.clone(),
            },
            outer_socks5: None,
            mtu: spec.mtu,
            socket: transport_socket_options(&spec.socket),
            target,
        },
        ExecutionHopSpec::Masque(spec) => TransportAction::MasqueConnect {
            proxy: TransportTarget::new(&spec.server, spec.port),
            options: mihomo_transport::MasqueConnectOptions {
                private_key: spec.private_key.clone(),
                public_key: spec.public_key.clone(),
                ip: spec.ip.clone(),
                ipv6: spec.ipv6.clone(),
                uri: spec.uri.clone(),
                mtu: spec.mtu,
                network: spec.network.clone(),
                remote_dns_resolve: spec.remote_dns_resolve,
                dns: spec.dns.clone(),
            },
            tls: transport_tls_options(&spec.tls),
            outer_socks5: None,
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
            h2: spec.h2.clone(),
            http: spec.http.clone(),
            xhttp: spec.xhttp.clone(),
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
                vec![if spec.quic { "h3" } else { "h2" }.to_owned()]
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
            reality_public_key: spec.reality_public_key.clone(),
            reality_short_id: spec.reality_short_id.clone(),
            reality_support_x25519mlkem768: spec.reality_support_x25519mlkem768,
            client_fingerprint: spec.client_fingerprint.clone(),
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
    use crate::{
        build_runtime_registry, outbound_supports_udp, outbound_udp_support_gap, CandidateState,
    };

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
    fn outbound_udp_support_gap_allows_ssr_http_obfs_with_obfs_param() {
        for (obfs, cipher) in [("http_simple", "dummy"), ("http_post", "aes-128-cfb")] {
            let definition = parse_runtime_config_document(
                &format!(
                    r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: ssr.example.com
    port: 8389
    cipher: {cipher}
    password: secret
    protocol: origin
    obfs: {obfs}
    obfs-param: obfs.example.com
    udp: true
"#
                ),
            )
            .unwrap()
            .proxies
            .into_iter()
            .next()
            .unwrap();
            assert_eq!(outbound_udp_support_gap(&definition), None, "{obfs}");
            assert!(outbound_supports_udp(&definition), "{obfs}");
        }
    }

    #[test]
    fn outbound_udp_support_gap_allows_ssr_origin_plain_with_ignored_params() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: ssr.example.com
    port: 8389
    cipher: dummy
    password: secret
    protocol: origin
    protocol-param: ignored-user
    obfs: plain
    obfs-param: ignored-host
    udp: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert_eq!(outbound_udp_support_gap(&definition), None);
        assert!(outbound_supports_udp(&definition));
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
                assert!(spec.reality_public_key.is_empty());
                assert!(spec.reality_short_id.is_empty());
                assert!(!spec.reality_support_x25519mlkem768);
                assert!(spec.client_fingerprint.is_empty());
            }
            _ => panic!("expected vless hop"),
        }
    }

    #[test]
    fn execution_plan_vision_udp_defaults_to_xudp_and_preserves_packetaddr_choice() {
        for (extra, expected_xudp, expected_packetaddr) in [
            ("", true, false),
            ("    packet-addr: true\n", false, true),
            ("    packet-encoding: packetaddr\n", false, true),
        ] {
            let document = parse_runtime_config_document(&format!(
                "proxies:\n  - type: vless\n    name: vision\n    server: 127.0.0.1\n    port: 443\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n{extra}"
            )).unwrap();
            let mut registry = build_runtime_registry(&document).unwrap();
            let plan = build_execution_plan(&mut registry, "vision", None, &BTreeMap::new()).unwrap();
            let ExecutionHopSpec::Vless(spec) = &plan.hops[0].spec else { panic!("expected VLESS"); };
            assert_eq!(spec.xudp, expected_xudp);
            assert_eq!(spec.packet_addr, expected_packetaddr);
        }
    }

    #[test]
    fn execution_plan_preserves_vless_reality_and_client_fingerprint_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vless-hop
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: abcdef
      short-id: 1234
      support-x25519mlkem768: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "vless-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Vless(spec) => {
                assert_eq!(spec.flow, "xtls-rprx-vision");
                assert_eq!(spec.reality_public_key, "abcdef");
                assert_eq!(spec.reality_short_id, "1234");
                assert!(spec.reality_support_x25519mlkem768);
                assert_eq!(spec.client_fingerprint, "chrome");
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
    fn execution_plan_materializes_plain_hysteria2_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2-hop
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "hy2-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Hy2(spec) => {
                assert_eq!(spec.server, "1.2.3.4");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.password, "secret");
                assert_eq!(spec.tls.sni, "edge.example");
                assert!(spec.tls.skip_cert_verify);
                assert!(spec.obfs.is_empty());
            }
            _ => panic!("expected hysteria2 hop"),
        }
    }

    #[test]
    fn execution_plan_materializes_plain_hysteria_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria
    name: hy-hop
    server: 1.2.3.4
    port: 443
    auth-str: secret
    sni: edge.example
    skip-cert-verify: true
    up: 10 Mbps
    down: 50 Mbps
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "hy-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Hysteria(spec) => {
                assert_eq!(spec.server, "1.2.3.4");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.auth_str, "secret");
                assert_eq!(spec.tls.sni, "edge.example");
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.up, "10 Mbps");
                assert_eq!(spec.down, "50 Mbps");
            }
            _ => panic!("expected hysteria hop"),
        }
    }

    #[test]
    fn execution_plan_materializes_plain_tuic_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: tuic-hop
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    sni: edge.example
    skip-cert-verify: true
    alpn: [h3]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "tuic-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Tuic(spec) => {
                assert_eq!(spec.server, "1.2.3.4");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(spec.password, "secret");
                assert_eq!(spec.sni, "edge.example");
                assert!(spec.tls.skip_cert_verify);
                assert_eq!(spec.alpn, vec!["h3".to_owned()]);
                assert!(!spec.udp);
                assert!(spec.token.is_empty());
            }
            _ => panic!("expected tuic hop"),
        }
    }

    #[test]
    fn execution_plan_materializes_wireguard_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips:
      - 0.0.0.0/0
    persistent-keepalive: 15
    mtu: 1380
    workers: 4
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-wg", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::WireGuard(spec) => {
                assert_eq!(spec.ip, "10.0.0.2/32");
                assert!(spec.udp);
                assert_eq!(spec.peers.len(), 1);
                assert_eq!(spec.peers[0].server, "1.2.3.4");
                assert_eq!(spec.peers[0].port, 51820);
                assert_eq!(spec.peers[0].allowed_ips, vec!["0.0.0.0/0"]);
                assert_eq!(spec.peers[0].persistent_keepalive, 15);
                assert_eq!(spec.mtu, 1380);
                assert_eq!(spec.workers, 4);
            }
            _ => panic!("expected wireguard hop"),
        }
    }

    #[test]
    fn execution_plan_materializes_wireguard_multi_peer_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        allowed-ips: [0.0.0.0/0]
        persistent-keepalive: 15
      - server: 5.6.7.8
        port: 51821
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        allowed-ips: [10.0.0.0/8]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-wg", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::WireGuard(spec) => {
                assert_eq!(spec.ip, "10.0.0.2/32");
                assert!(spec.udp);
                assert_eq!(spec.peers.len(), 2);
                assert_eq!(spec.peers[0].server, "1.2.3.4");
                assert_eq!(spec.peers[0].port, 51820);
                assert_eq!(spec.peers[0].allowed_ips, vec!["0.0.0.0/0"]);
                assert_eq!(spec.peers[0].persistent_keepalive, 15);
                assert_eq!(spec.peers[1].server, "5.6.7.8");
                assert_eq!(spec.peers[1].port, 51821);
                assert_eq!(spec.peers[1].allowed_ips, vec!["10.0.0.0/8"]);
                assert_eq!(spec.peers[1].persistent_keepalive, 0);
            }
            _ => panic!("expected wireguard hop"),
        }
    }

    #[test]
    fn execution_plan_materializes_openvpn_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
      -----BEGIN CERTIFICATE-----
      MIIBhTCCASugAwIBAgIUJfQ1G3QW9W5JmM6z7Q9M9Q0Y0KowCgYIKoZIzj0EAwIw
      EzERMA8GA1UEAwwIb3Zwbi10ZXN0MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAw
      MDAwMFowEzERMA8GA1UEAwwIb3Zwbi10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
      AQcDQgAEw2P9GQHk8r2m2mG4Xv8Jw6fD3F2rM4bJ2GQzj1f5aH3m3M5Q0n+uC2oVv
      lB3w0dQ4G9F1sY4E6oQhXg4nW8v+9qNTMFEwHQYDVR0OBBYEFDs6x9h1gY0fD7kL
      8K1kzv6dY8hGMB8GA1UdIwQYMBaAFDs6x9h1gY0fD7kL8K1kzv6dY8hGMA8GA1Ud
      EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKZ9ZpD5jN7s3QXcY5z9V4sL
      pG7bXz1wGx9K2V8nM2mTAiA4r0v9dZ7g6Y8Eo4Jt2kP7Z8M6dX1qZ3cN5uV1bH6g
      -----END CERTIFICATE-----
    tls-crypt: |
      -----BEGIN OpenVPN Static key V1-----
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      -----END OpenVPN Static key V1-----
    username: demo
    password: secret
    mtu: 1500
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "edge-ovpn", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::OpenVpn(spec) => {
                assert_eq!(spec.server, "1.2.3.4");
                assert_eq!(spec.port, 1194);
                assert_eq!(spec.proto, "udp");
                assert_eq!(spec.dev, "tun");
                assert_eq!(spec.cipher, "AES-128-GCM");
                assert_eq!(spec.auth, "SHA256");
                assert!(spec.ca.contains("BEGIN CERTIFICATE"));
                assert!(spec.tls_crypt.contains("BEGIN OpenVPN Static key V1"));
                assert_eq!(spec.username, "demo");
                assert_eq!(spec.password, "secret");
                assert_eq!(spec.mtu, 1500);
            }
            _ => panic!("expected openvpn hop"),
        }
    }

    #[test]
    fn execution_plan_materializes_masque_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    mtu: 1300
    sni: edge.example.com
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan =
            build_execution_plan(&mut registry, "edge-masque", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Masque(spec) => {
                assert_eq!(spec.server, "masque.example.com");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.private_key, "key");
                assert_eq!(spec.public_key, "pub");
                assert_eq!(spec.ip, "10.10.0.2/32");
                assert_eq!(spec.network, "h2");
                assert_eq!(spec.mtu, 1300);
                assert_eq!(spec.sni, "edge.example.com");
                assert!(spec.udp);
            }
            other => panic!("expected masque hop, got {other:?}"),
        }
    }

    #[test]
    fn execution_plan_materializes_tuic_v4_token_outbound() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: tuic-hop
    server: 1.2.3.4
    port: 443
    token: secret
    alpn: [h3]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "tuic-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Tuic(spec) => {
                assert_eq!(spec.server, "1.2.3.4");
                assert_eq!(spec.port, 443);
                assert_eq!(spec.token, "secret");
                assert!(spec.uuid.is_empty());
                assert!(spec.password.is_empty());
                assert!(!spec.udp);
            }
            _ => panic!("expected tuic hop"),
        }
    }

    #[test]
    fn execution_plan_preserves_hysteria2_obfs_fields_for_runtime_gating() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2-hop
    server: 1.2.3.4
    port: 443
    password: secret
    obfs: salamander
    obfs-password: hidden
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "hy2-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Hy2(spec) => {
                assert_eq!(spec.obfs, "salamander");
                assert_eq!(spec.obfs_password, "hidden");
            }
            _ => panic!("expected hysteria2 hop"),
        }
    }

    #[test]
    fn execution_plan_preserves_hysteria2_realm_opts_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2-hop
    server: 1.2.3.4
    port: 443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - stun.nextcloud.com:3478
      sni: realm-sni.example.com
      skip-cert-verify: true
      fingerprint: sha256:demo
      certificate: cert-pem
      private-key: key-pem
      alpn: [h2, http/1.1]
      proxy: DIRECT
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let plan = build_execution_plan(&mut registry, "hy2-hop", None, &BTreeMap::new()).unwrap();
        match &plan.hops[0].spec {
            ExecutionHopSpec::Hy2(spec) => {
                assert!(spec.realm_enabled);
                assert_eq!(spec.realm_server_url, "https://realm.example.com");
                assert_eq!(spec.realm_token, "public");
                assert_eq!(spec.realm_id, "my-cabin-1f3a8c2e9b");
                assert_eq!(spec.realm_stun_servers, vec!["stun.nextcloud.com:3478"]);
                assert_eq!(spec.realm_sni, "realm-sni.example.com");
                assert!(spec.realm_skip_cert_verify);
                assert_eq!(spec.realm_fingerprint, "sha256:demo");
                assert_eq!(spec.realm_certificate, "cert-pem");
                assert_eq!(spec.realm_private_key, "key-pem");
                assert_eq!(spec.realm_alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
                assert_eq!(spec.realm_proxy, "DIRECT");
            }
            _ => panic!("expected hysteria2 hop"),
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
    fn transport_plan_materializes_trojan_h2_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    network: h2
    skip-cert-verify: true
    h2-opts:
      host: [localhost]
      path: /trh2
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
                h2,
                target,
                ..
            } => {
                assert_eq!(network, "h2");
                assert_eq!(h2.host, vec!["localhost".to_owned()]);
                assert_eq!(h2.path, "/trh2");
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected trojan transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_trojan_xhttp_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    network: xhttp
    skip-cert-verify: true
    xhttp-opts:
      host: localhost
      path: /trx
      mode: stream-one
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
                xhttp,
                target,
                ..
            } => {
                assert_eq!(network, "xhttp");
                assert_eq!(xhttp.host, "localhost");
                assert_eq!(xhttp.path, "/trx");
                assert_eq!(xhttp.mode, "stream-one");
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
    fn transport_plan_materializes_trusttunnel_quic_hop() {
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
    quic: true
    sni: edge.example.com
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
                assert!(*quic);
                assert_eq!(alpn, &vec!["h3".to_owned()]);
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
    fn transport_plan_materializes_tuic_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: edge-tuic
    server: tuic.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    sni: edge.example.com
    skip-cert-verify: true
    alpn: [h3]
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
            build_transport_plan(&mut registry, "edge-tuic", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::TuicConnect {
                proxy,
                uuid,
                password,
                sni,
                udp,
                alpn,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "tuic.example.com:443");
                assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(password, "secret");
                assert_eq!(sni, "edge.example.com");
                assert!(!udp);
                assert_eq!(alpn, &vec!["h3".to_owned()]);
                assert_eq!(target.authority(), "final.example.com:8443");
            }
            _ => panic!("expected tuic transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_wireguard_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips:
      - 0.0.0.0/0
    persistent-keepalive: 15
    mtu: 1380
    workers: 4
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
            build_transport_plan(&mut registry, "edge-wg", &metadata, &BTreeMap::new()).unwrap();
        match &plan.hops[0].action {
            TransportAction::WireGuardConnect {
                proxy,
                ip,
                workers,
                peers,
                mtu,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "1.2.3.4:51820");
                assert_eq!(ip, "10.0.0.2/32");
                assert_eq!(*workers, 4);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].allowed_ips, vec!["0.0.0.0/0"]);
                assert_eq!(peers[0].persistent_keepalive, 15);
                assert_eq!(*mtu, 1380);
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected wireguard transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_wireguard_remote_dns_options() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
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
            build_transport_plan(&mut registry, "edge-wg", &metadata, &BTreeMap::new()).unwrap();
        match &plan.hops[0].action {
            TransportAction::WireGuardConnect { tunnel_dns, .. } => {
                assert!(tunnel_dns.remote_dns_resolve);
                assert_eq!(tunnel_dns.dns, vec!["udp://1.1.1.1".to_owned()]);
            }
            _ => panic!("expected wireguard transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_wireguard_multi_peer_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        allowed-ips: [0.0.0.0/0]
        persistent-keepalive: 15
      - server: 5.6.7.8
        port: 51821
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        allowed-ips: [10.0.0.0/8]
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
            build_transport_plan(&mut registry, "edge-wg", &metadata, &BTreeMap::new()).unwrap();
        match &plan.hops[0].action {
            TransportAction::WireGuardConnect {
                proxy,
                ip,
                peers,
                mtu,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "1.2.3.4:51820");
                assert_eq!(ip, "10.0.0.2/32");
                assert_eq!(peers.len(), 2);
                assert_eq!(peers[0].server, "1.2.3.4");
                assert_eq!(peers[0].port, 51820);
                assert_eq!(peers[0].allowed_ips, vec!["0.0.0.0/0"]);
                assert_eq!(peers[0].persistent_keepalive, 15);
                assert_eq!(peers[1].server, "5.6.7.8");
                assert_eq!(peers[1].port, 51821);
                assert_eq!(peers[1].allowed_ips, vec!["10.0.0.0/8"]);
                assert_eq!(peers[1].persistent_keepalive, 0);
                assert_eq!(*mtu, 1420);
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected wireguard transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_wireguard_outer_socks5_udp_subplan() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips:
      - 0.0.0.0/0
    dialer-proxy: outer-socks
  - type: socks5
    name: outer-socks
    server: outer.example.com
    port: 1080
    udp: true
    username: demo
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
            build_transport_plan(&mut registry, "edge-wg", &metadata, &BTreeMap::new()).unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::WireGuardConnect {
                proxy,
                outer_socks5,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "1.2.3.4:51820");
                assert_eq!(target.authority(), "final.example.com:443");
                let outer = outer_socks5.as_ref().expect("expected wireguard outer socks5 plan");
                assert_eq!(outer.proxy.authority(), "outer.example.com:1080");
                let auth = outer.auth.as_ref().expect("expected socks5 auth");
                assert_eq!(auth.username, "demo");
                assert_eq!(auth.password, "secret");
                assert!(outer.prefix_plan.is_none());
            }
            other => panic!("expected wireguard transport action, got {other:?}"),
        }
    }

    #[test]
    fn transport_plan_materializes_openvpn_connect_action() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
      -----BEGIN CERTIFICATE-----
      MIIBhTCCASugAwIBAgIUJfQ1G3QW9W5JmM6z7Q9M9Q0Y0KowCgYIKoZIzj0EAwIw
      EzERMA8GA1UEAwwIb3Zwbi10ZXN0MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAw
      MDAwMFowEzERMA8GA1UEAwwIb3Zwbi10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
      AQcDQgAEw2P9GQHk8r2m2mG4Xv8Jw6fD3F2rM4bJ2GQzj1f5aH3m3M5Q0n+uC2oVv
      lB3w0dQ4G9F1sY4E6oQhXg4nW8v+9qNTMFEwHQYDVR0OBBYEFDs6x9h1gY0fD7kL
      8K1kzv6dY8hGMB8GA1UdIwQYMBaAFDs6x9h1gY0fD7kL8K1kzv6dY8hGMA8GA1Ud
      EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKZ9ZpD5jN7s3QXcY5z9V4sL
      pG7bXz1wGx9K2V8nM2mTAiA4r0v9dZ7g6Y8Eo4Jt2kP7Z8M6dX1qZ3cN5uV1bH6g
      -----END CERTIFICATE-----
    tls-crypt: |
      -----BEGIN OpenVPN Static key V1-----
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      -----END OpenVPN Static key V1-----
    username: demo
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
            build_transport_plan(&mut registry, "edge-ovpn", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::OpenVpnConnect {
                proxy,
                proto,
                dev,
                cipher,
                auth,
                ca,
                tls_crypt,
                username,
                password,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "1.2.3.4:1194");
                assert_eq!(proto, "udp");
                assert_eq!(dev, "tun");
                assert_eq!(cipher, "AES-128-GCM");
                assert_eq!(auth, "SHA256");
                assert!(ca.contains("BEGIN CERTIFICATE"));
                assert!(tls_crypt.contains("BEGIN OpenVPN Static key V1"));
                assert_eq!(username, "demo");
                assert_eq!(password, "secret");
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected openvpn transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_openvpn_remote_dns_options() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
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
            build_transport_plan(&mut registry, "edge-ovpn", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::OpenVpnConnect { tunnel_dns, .. } => {
                assert!(tunnel_dns.remote_dns_resolve);
                assert_eq!(tunnel_dns.dns, vec!["udp://1.1.1.1".to_owned()]);
            }
            _ => panic!("expected openvpn transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_openvpn_udp_outer_socks5_subplan() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    dialer-proxy: outer-socks
  - type: socks5
    name: outer-socks
    server: outer.example.com
    port: 1080
    udp: true
    username: alice
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
            build_transport_plan(&mut registry, "edge-ovpn", &metadata, &BTreeMap::new()).unwrap();
        assert_eq!(plan.hops.len(), 1);
        match &plan.hops[0].action {
            TransportAction::OpenVpnConnect {
                proxy,
                outer_socks5,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "1.2.3.4:1194");
                assert_eq!(target.authority(), "final.example.com:443");
                let outer = outer_socks5.as_ref().expect("expected openvpn outer socks5 plan");
                assert_eq!(outer.proxy.authority(), "outer.example.com:1080");
                let auth = outer.auth.as_ref().expect("expected socks5 auth");
                assert_eq!(auth.username, "alice");
                assert_eq!(auth.password, "secret");
                assert!(outer.prefix_plan.is_none());
            }
            other => panic!("expected openvpn transport action, got {other:?}"),
        }
    }

    #[test]
    fn transport_plan_materializes_hysteria2_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: edge-hy2
    server: hy2.example.com
    port: 8443
    password: secret
    sni: edge.example.com
    skip-cert-verify: true
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
            build_transport_plan(&mut registry, "edge-hy2", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::Hy2Connect {
                proxy,
                password,
                sni,
                skip_cert_verify,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "hy2.example.com:8443");
                assert_eq!(password, "secret");
                assert_eq!(sni, "edge.example.com");
                assert!(*skip_cert_verify);
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected hysteria2 transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_hysteria2_realm_opts() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: edge-hy2
    server: hy2.example.com
    port: 8443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - stun.nextcloud.com:3478
      sni: realm.example.com
      skip-cert-verify: true
      alpn: [h2]
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
            build_transport_plan(&mut registry, "edge-hy2", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::Hy2Connect {
                realm_enabled,
                realm_server_url,
                realm_token,
                realm_id,
                realm_stun_servers,
                realm_sni,
                realm_skip_cert_verify,
                realm_alpn,
                ..
            } => {
                assert!(*realm_enabled);
                assert_eq!(realm_server_url, "https://realm.example.com");
                assert_eq!(realm_token, "public");
                assert_eq!(realm_id, "my-cabin-1f3a8c2e9b");
                assert_eq!(realm_stun_servers, &vec!["stun.nextcloud.com:3478".to_owned()]);
                assert_eq!(realm_sni, "realm.example.com");
                assert!(*realm_skip_cert_verify);
                assert_eq!(realm_alpn, &vec!["h2".to_owned()]);
            }
            _ => panic!("expected hysteria2 transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_hysteria2_realm_proxy_name_subplan() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: edge-hy2
    server: hy2.example.com
    port: 8443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      token: public
      realm-id: my-cabin-1f3a8c2e9b
      stun-servers:
        - stun.nextcloud.com:3478
      proxy: outer-socks
    dialer-proxy: outer-socks
  - type: socks5
    name: outer-socks
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
        let plan =
            build_transport_plan(&mut registry, "edge-hy2", &metadata, &BTreeMap::new()).unwrap();
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[1].action {
            TransportAction::Hy2Connect {
                realm_proxy,
                realm_proxy_plan,
                ..
            } => {
                assert_eq!(realm_proxy, "outer-socks");
                let nested = realm_proxy_plan.as_ref().expect("expected hy2 realm proxy subplan");
                assert_eq!(nested.hops.len(), 1);
                match &nested.hops[0].action {
                    TransportAction::Socks5Connect { proxy, target, .. } => {
                        assert_eq!(proxy.authority(), "outer.example.com:1080");
                        assert_eq!(target.authority(), "realm.example.com:443");
                    }
                    _ => panic!("expected nested socks5 transport action"),
                }
            }
            _ => panic!("expected hysteria2 transport action"),
        }
    }

    #[test]
    fn transport_plan_materializes_hysteria_hop() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria
    name: edge-hy
    server: hy.example.com
    port: 8443
    auth-str: secret
    sni: edge.example.com
    skip-cert-verify: true
    up: 10 Mbps
    down: 50 Mbps
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
            build_transport_plan(&mut registry, "edge-hy", &metadata, &BTreeMap::new())
                .unwrap();
        match &plan.hops[0].action {
            TransportAction::HysteriaConnect {
                proxy,
                auth_str,
                sni,
                up,
                down,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "hy.example.com:8443");
                assert_eq!(auth_str, "secret");
                assert_eq!(sni, "edge.example.com");
                assert_eq!(up, "10 Mbps");
                assert_eq!(down, "50 Mbps");
                assert_eq!(target.authority(), "final.example.com:443");
            }
            _ => panic!("expected hysteria action"),
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
                flow,
                reality_public_key,
                reality_short_id,
                reality_support_x25519mlkem768,
                client_fingerprint,
                udp,
                tls,
                h2,
                target,
                ..
            } => {
                assert_eq!(proxy.authority(), "vless.example.com:443");
                assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert!(flow.is_empty());
                assert!(reality_public_key.is_empty());
                assert!(reality_short_id.is_empty());
                assert!(!reality_support_x25519mlkem768);
                assert!(client_fingerprint.is_empty());
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
    fn transport_plan_materializes_vless_reality_and_client_fingerprint_fields() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: abcdef
      short-id: 1234
      support-x25519mlkem768: true
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
                flow,
                reality_public_key,
                reality_short_id,
                reality_support_x25519mlkem768,
                client_fingerprint,
                ..
            } => {
                assert_eq!(flow, "xtls-rprx-vision");
                assert_eq!(reality_public_key, "abcdef");
                assert_eq!(reality_short_id, "1234");
                assert!(*reality_support_x25519mlkem768);
                assert_eq!(client_fingerprint, "chrome");
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
