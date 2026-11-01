use std::collections::BTreeMap;
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream as NetTcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, ConnectionContext, DnsMode, Metadata, PacketEnvelope, TcpStream, Tunnel, UdpSession};
use mihomo_dns::DnsRuntime;
use mihomo_rules::{RuleSet, RuntimeRuleSnapshot};
use mihomo_transport::{
    GrpcOptions as TransportGrpcOptions,
    Http2Options as TransportHttp2Options,
    HttpStreamOptions as TransportHttpStreamOptions,
    NetTcpStreamAddr, SocketOptions as TransportSocketOptions, TcpDialPurpose, TcpDialer,
    TlsOptions as TransportTlsOptions, TransportError, TransportTarget,
    TrojanShadowsocksOptions as TransportTrojanShadowsocksOptions,
    WebsocketOptions as TransportWebsocketOptions, XHttpOptions as TransportXHttpOptions,
};

use crate::{
    build_execution_plan, tcp::relay_bidirectional_with_counters,
    resolve_proxy_path, CandidateState, ExecutionError, ExecutionHopSpec, ExecutionPlan, QueuedUdpRelay,
    RuntimeRegistry,
    TcpForwardError, TcpRelayStats, TcpRelayStrategy,
};
use crate::healthcheck::{record_health_state, ProxyHealthSnapshot, ProxyHealthState};

const RULE_FALLBACK_TARGET: &str = "COMPATIBLE";
const DNS_RULES_PROXY: &str = "RULES";

pub struct RuntimeTunnel {
    mode: Mutex<String>,
    pub(crate) registry: Arc<Mutex<RuntimeRegistry>>,
    pub(crate) smart_context: Mutex<Option<crate::smart::SmartContext>>,
    pub(crate) smart_advanced: Arc<crate::smart::AdvancedRuntime>,
    ebpf: RwLock<Option<Arc<mihomo_ebpf::EbpfRuntime>>>,
    rules: RwLock<Arc<RuleSet>>,
    dns_runtime: RwLock<Option<Arc<Mutex<DnsRuntime>>>>,
    pub(crate) candidate_states: Mutex<BTreeMap<String, CandidateState>>,
    udp_relay: Mutex<QueuedUdpRelay>,
    last_error: Mutex<Option<String>>,
    tcp_strategy: TcpRelayStrategy,
    up_total: AtomicU64,
    down_total: AtomicU64,
    active_connections: Mutex<BTreeMap<u64, Arc<TrackedConnection>>>,
    proxy_health: Mutex<BTreeMap<String, ProxyHealthState>>,
}

impl std::fmt::Debug for RuntimeTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeTunnel")
            .field("mode", &self.current_mode())
            .field("pending_udp_packets", &self.pending_udp_packets())
            .field("tcp_strategy", &self.tcp_strategy)
            .field("traffic", &self.traffic_snapshot())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficSnapshot {
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSocks5Route {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpShadowSocksRoute {
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSsrRoute {
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub obfs: String,
    pub obfs_param: String,
    pub protocol: String,
    pub protocol_param: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpAnyTlsRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub alpn: Vec<String>,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHysteriaRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub ports: String,
    pub protocol: String,
    pub auth: String,
    pub auth_str: String,
    pub obfs: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub up: String,
    pub down: String,
    pub up_speed: u32,
    pub down_speed: u32,
    pub disable_mtu_discovery: bool,
    pub fast_open: bool,
    pub hop_interval: u32,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHy2Route {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub certificate: String,
    pub private_key: String,
    pub obfs: String,
    pub obfs_password: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSnellRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub version: u8,
    pub obfs_mode: String,
    pub obfs_host: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpGostRelayRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub forward: bool,
    pub mux: bool,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTrojanRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub shadowsocks: TransportTrojanShadowsocksOptions,
    pub network: String,
    pub websocket: TransportWebsocketOptions,
    pub grpc: TransportGrpcOptions,
    pub h2: mihomo_transport::Http2Options,
    pub http: TransportHttpStreamOptions,
    pub xhttp: mihomo_transport::XHttpOptions,
    pub alpn: Vec<String>,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTrustTunnelRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub quic: bool,
    pub alpn: Vec<String>,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTuicRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    pub token: String,
    pub udp: bool,
    pub sni: String,
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub request_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub congestion_controller: String,
    pub max_open_streams: u32,
    pub max_udp_relay_packet_size: u32,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpWireGuardPeerRoute {
    pub server: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpWireGuardRoute {
    pub private_key: String,
    pub ip: String,
    pub ipv6: String,
    pub udp: bool,
    pub workers: usize,
    pub mtu: usize,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub peers: Vec<UdpWireGuardPeerRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOpenVpnRoute {
    pub dialer_proxy: Option<String>,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpMasqueRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub ip: String,
    pub ipv6: String,
    pub uri: String,
    pub network: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub udp: bool,
    pub mtu: usize,
    pub tls: TransportTlsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpVlessRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub flow: String,
    pub network: String,
    pub websocket: TransportWebsocketOptions,
    pub grpc: TransportGrpcOptions,
    pub h2: TransportHttp2Options,
    pub http: TransportHttpStreamOptions,
    pub xhttp: TransportXHttpOptions,
    pub encryption: String,
    pub packet_addr: bool,
    pub xudp: bool,
    pub tls: TransportTlsOptions,
    pub alpn: Vec<String>,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub reality_support_x25519mlkem768: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpVmessRoute {
    pub dialer_proxy: Option<String>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u16,
    pub cipher: String,
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
    pub tls: TransportTlsOptions,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSudokuRoute {
    pub dialer_proxy: Option<String>,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UdpOutboundRoute {
    Direct,
    Dns,
    Socks5(UdpSocks5Route),
    ShadowSocks(UdpShadowSocksRoute),
    Ssr(UdpSsrRoute),
    AnyTls(UdpAnyTlsRoute),
    Hysteria(UdpHysteriaRoute),
    Hy2(UdpHy2Route),
    Snell(UdpSnellRoute),
    Trojan(UdpTrojanRoute),
    TrustTunnel(UdpTrustTunnelRoute),
    Tuic(UdpTuicRoute),
    WireGuard(UdpWireGuardRoute),
    OpenVpn(UdpOpenVpnRoute),
    Masque(UdpMasqueRoute),
    Vless(UdpVlessRoute),
    Vmess(UdpVmessRoute),
    GostRelay(UdpGostRelayRoute),
    Sudoku(UdpSudokuRoute),
    Unsupported(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveConnectionSnapshot {
    pub id: u64,
    pub metadata: Metadata,
    pub upload: u64,
    pub download: u64,
    pub start_unix_ms: u64,
    pub chains: Vec<String>,
    pub provider_chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

struct TrackedConnection {
    id: u64,
    metadata: Metadata,
    start_unix_ms: u64,
    upload: AtomicU64,
    download: AtomicU64,
    chains: Vec<String>,
    provider_chains: Vec<String>,
    rule: String,
    rule_payload: String,
    handles: Mutex<Vec<BoxedTcpStream>>,
}

impl std::fmt::Debug for TrackedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedConnection")
            .field("id", &self.id)
            .field("metadata", &self.metadata)
            .field("start_unix_ms", &self.start_unix_ms)
            .field("upload", &self.upload.load(Ordering::Relaxed))
            .field("download", &self.download.load(Ordering::Relaxed))
            .field("chains", &self.chains)
            .field("provider_chains", &self.provider_chains)
            .field("rule", &self.rule)
            .field("rule_payload", &self.rule_payload)
            .field("handle_count", &self.handles.lock().unwrap().len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeControlError {
    InvalidMode(String),
    GroupNotFound(String),
    ProxyNotFound(String),
    GroupCandidateNotFound { group: String, candidate: String },
}

impl std::fmt::Display for RuntimeControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMode(mode) => write!(f, "invalid mode: {mode}"),
            Self::GroupNotFound(group) => write!(f, "group not found: {group}"),
            Self::ProxyNotFound(proxy) => write!(f, "proxy not found: {proxy}"),
            Self::GroupCandidateNotFound { group, candidate } => {
                write!(f, "group {group} does not contain candidate {candidate}")
            }
        }
    }
}

impl std::error::Error for RuntimeControlError {}

impl RuntimeTunnel {
    pub fn new(mode: impl Into<String>, registry: RuntimeRegistry) -> Self {
        Self {
            mode: Mutex::new(mode.into()),
            registry: Arc::new(Mutex::new(registry)),
            smart_context: Mutex::new(None),
            smart_advanced: Arc::new(crate::smart::AdvancedRuntime::default()),
            ebpf: RwLock::new(None),
            rules: RwLock::new(Arc::new(RuleSet::default())),
            dns_runtime: RwLock::new(None),
            candidate_states: Mutex::new(BTreeMap::new()),
            udp_relay: Mutex::new(QueuedUdpRelay::default()),
            last_error: Mutex::new(None),
            tcp_strategy: TcpRelayStrategy::for_current_platform(),
            up_total: AtomicU64::new(0),
            down_total: AtomicU64::new(0),
            active_connections: Mutex::new(BTreeMap::new()),
            proxy_health: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn set_ebpf_runtime(&self,runtime:Option<Arc<mihomo_ebpf::EbpfRuntime>>) {
        *self.ebpf.write().unwrap()=runtime;
    }
    pub fn ebpf_status(&self)->mihomo_ebpf::EbpfStatus {
        self.ebpf.read().unwrap().as_ref().map(|runtime|runtime.status()).unwrap_or_else(||mihomo_ebpf::EbpfStatus{supported:cfg!(target_os="linux"),..Default::default()})
    }
    pub fn ebpf_original_destination(&self,peer:SocketAddr,local:SocketAddr)->io::Result<Option<SocketAddr>> {
        match self.ebpf.read().unwrap().as_ref(){Some(runtime)=>runtime.original_destination(peer,local),None=>Ok(None)}
    }

    pub fn with_tcp_strategy(mut self, strategy: TcpRelayStrategy) -> Self {
        self.tcp_strategy = strategy;
        self
    }

    pub fn with_rule_set(mut self, rules: RuleSet) -> Self {
        *self.rules.get_mut().unwrap() = Arc::new(rules);
        self
    }

    pub fn with_dns_runtime(mut self, dns_runtime: DnsRuntime) -> Self {
        *self.dns_runtime.get_mut().unwrap() = Some(Arc::new(Mutex::new(dns_runtime)));
        self
    }

    pub fn dns_runtime(&self) -> Option<Arc<Mutex<DnsRuntime>>> {
        self.dns_runtime.read().unwrap().as_ref().map(Arc::clone)
    }

    pub fn current_mode(&self) -> String {
        self.mode.lock().unwrap().clone()
    }

    pub fn set_mode(&self, mode: &str) -> Result<(), RuntimeControlError> {
        if !matches!(mode, "direct" | "global" | "rule") {
            return Err(RuntimeControlError::InvalidMode(mode.to_owned()));
        }
        *self.mode.lock().unwrap() = mode.to_owned();
        Ok(())
    }

    pub fn set_candidate_state(&self, state: CandidateState) {
        self.candidate_states
            .lock()
            .unwrap()
            .insert(state.name.clone(), state);
    }

    pub fn replace_candidate_states(&self, states: BTreeMap<String, CandidateState>) {
        *self.candidate_states.lock().unwrap() = states;
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    pub fn clear_last_error(&self) {
        *self.last_error.lock().unwrap() = None;
    }

    pub fn runtime_rules_snapshot(&self) -> Vec<RuntimeRuleSnapshot> {
        self.rules.read().unwrap().runtime_snapshots()
    }

    pub(crate) fn smart_rule_for(&self, metadata: &Metadata) -> Option<(String, usize)> {
        self.rules.read().unwrap().smart_rule_identity(metadata)
    }

    pub fn set_rule_disabled(&self, index: usize, disabled: bool) -> bool {
        self.rules.read().unwrap().set_rule_disabled(index, disabled)
    }

    pub fn replace_rule_set(&self, rules: RuleSet) {
        *self.rules.write().unwrap() = Arc::new(rules);
    }

    pub fn replace_dns_runtime(&self, dns_runtime: Option<DnsRuntime>) {
        let previous = self.dns_runtime();
        *self.dns_runtime.write().unwrap() = dns_runtime.map(|mut runtime| {
            if let Some(previous) = previous.as_ref() {
                let previous = previous.lock().unwrap();
                runtime.clone_fake_ip_state_from(&previous);
            }
            Arc::new(Mutex::new(runtime))
        });
    }

    pub fn seed_dns_fake_ip_state(&self, runtime: &mut DnsRuntime) {
        if let Some(shared) = self.dns_runtime() {
            let shared = shared.lock().unwrap();
            runtime.clone_fake_ip_state_from(&shared);
        }
    }

    pub fn capture_dns_fake_ip_state(&self, runtime: &DnsRuntime) {
        if let Some(shared) = self.dns_runtime() {
            let mut shared = shared.lock().unwrap();
            shared.clone_fake_ip_state_from(runtime);
        }
    }

    pub fn replace_registry(&self, mut registry: RuntimeRegistry) {
        self.smart_advanced.invalidate();
        {
            let current = self.registry.lock().unwrap();
            for (name, view) in &mut registry.groups {
                if let (Some(smart), Some(previous)) = (&mut view.runtime.smart, current.groups.get(name).and_then(|view|view.runtime.smart.as_ref())) { smart.adopt_state(previous); }
            }
        }
        let selected = {
            let current = self.registry.lock().unwrap();
            current
                .groups
                .iter()
                .filter_map(|(name, view)| {
                    view.runtime.selected().map(|selected| (name.clone(), selected.to_owned()))
                })
                .collect::<Vec<_>>()
        };
        for (group_name, candidate) in selected {
            if let Some(view) = registry.groups.get_mut(&group_name) {
                if view.candidate_names.iter().any(|name| name == &candidate) {
                    view.runtime.set_selected(candidate);
                }
            }
        }
        *self.registry.lock().unwrap() = registry;
    }

    pub fn registry_snapshot(&self) -> RuntimeRegistry {
        self.registry.lock().unwrap().clone()
    }

    pub fn record_proxy_health(
        &self,
        name: &str,
        url: &str,
        alive: bool,
        delay_ms: u16,
        last_error: &str,
    ) {
        let mut states = self.proxy_health.lock().unwrap();
        record_health_state(&mut states, name, url, alive, delay_ms, last_error);
    }

    pub fn proxy_health_snapshot(&self, name: &str) -> Option<ProxyHealthSnapshot> {
        self.proxy_health.lock().unwrap().get(name).map(|state| ProxyHealthSnapshot {
            alive: state.alive,
            history: state.history.clone(),
            extra: state.extra.clone(),
        })
    }

    pub fn pending_udp_packets(&self) -> usize {
        self.udp_relay.lock().unwrap().len()
    }

    pub fn traffic_snapshot(&self) -> TrafficSnapshot {
        let up_total = self.up_total.load(Ordering::Relaxed);
        let down_total = self.down_total.load(Ordering::Relaxed);
        TrafficSnapshot {
            up: up_total,
            down: down_total,
            up_total,
            down_total,
        }
    }

    pub fn connections_snapshot(&self) -> Vec<ActiveConnectionSnapshot> {
        self.active_connections
            .lock()
            .unwrap()
            .values()
            .map(|tracked| ActiveConnectionSnapshot {
                id: tracked.id,
                metadata: tracked.metadata.clone(),
                upload: tracked.upload.load(Ordering::Relaxed),
                download: tracked.download.load(Ordering::Relaxed),
                start_unix_ms: tracked.start_unix_ms,
                chains: tracked.chains.clone(),
                provider_chains: tracked.provider_chains.clone(),
                rule: tracked.rule.clone(),
                rule_payload: tracked.rule_payload.clone(),
            })
            .collect()
    }

    pub fn selected_target_for_metadata(
        &self,
        metadata: &Metadata,
    ) -> Result<(String, crate::ResolvedProxyPath), ExecutionError> {
        let mut metadata = metadata.clone();
        self.preprocess_metadata_for_routing(&mut metadata)?;
        if metadata.smart_rule.is_none() {
            metadata.smart_rule=self.rules.read().unwrap().smart_rule_identity(&metadata);
        }
        let mode = self.mode.lock().unwrap().clone();
        let states = self.candidate_states.lock().unwrap().clone();
        let rules = Arc::clone(&self.rules.read().unwrap());
        let mut registry = self.registry.lock().unwrap();
        let target = select_target_name(&mode, &metadata, &registry, rules.as_ref());
        let resolved = resolve_proxy_path(&mut registry, &target, Some(&metadata), &states)?;
        Ok((target, resolved))
    }

    pub fn resolve_udp_outbound(
        &self,
        metadata: &Metadata,
    ) -> Result<UdpOutboundRoute, ExecutionError> {
        let (route, _) = self.resolve_udp_outbound_with_plan(metadata)?;
        Ok(route)
    }

    pub fn resolve_udp_outbound_with_plan(
        &self,
        metadata: &Metadata,
    ) -> Result<(UdpOutboundRoute, ExecutionPlan), ExecutionError> {
        let mut metadata = metadata.clone();
        self.preprocess_metadata_for_routing(&mut metadata)?;
        let mode = self.mode.lock().unwrap().clone();
        if mode == "direct" && metadata.special_proxy.trim().is_empty() {
            let _ = metadata
                .dst_port
                .ok_or_else(|| ExecutionError::Transport(mihomo_transport::TransportError::MissingDestinationPort))?;
            let _ = metadata
                .host
                .as_ref()
                .filter(|value| !value.is_empty())
                .cloned()
                .or_else(|| metadata.dst_ip.map(|ip| ip.to_string()))
                .ok_or_else(|| ExecutionError::Transport(mihomo_transport::TransportError::MissingDestinationHost))?;
            let plan = ExecutionPlan {
                requested: "DIRECT".to_owned(),
                selected_path: vec!["DIRECT".to_owned()],
                leaf_name: "DIRECT".to_owned(),
                dial_chain: vec!["DIRECT".to_owned()],
                hops: vec![crate::ExecutionHop {
                name: "DIRECT".to_owned(),
                kind: None,
                source: crate::ProxySource::Builtin,
                spec: crate::ExecutionHopSpec::Direct(crate::execution::DirectHopSpec {
                    socket: crate::execution::SocketOptions::default(),
                }),
            }],
        };
            return Ok((UdpOutboundRoute::Direct, plan));
        }
        let states = self.candidate_states.lock().unwrap().clone();
        let rules = Arc::clone(&self.rules.read().unwrap());
        let mut registry = self.registry.lock().unwrap();
        let target = select_target_name(&mode, &metadata, &registry, rules.as_ref());
        let plan = build_execution_plan(&mut registry, &target, Some(&metadata), &states)?;
        let route = self.resolve_udp_outbound_from_plan(&plan)?;
        Ok((route, plan))
    }

    fn resolve_udp_outbound_from_plan(
        &self,
        plan: &ExecutionPlan,
    ) -> Result<UdpOutboundRoute, ExecutionError> {
        let Some((leaf_index, leaf_hop)) = plan.hops.iter().enumerate().next_back() else {
            return Ok(UdpOutboundRoute::Unsupported(
                "udp execution plan is empty".to_owned(),
            ));
        };
        let dialer_proxy = if leaf_index > 0 {
            Some(plan.hops[leaf_index - 1].name.clone())
        } else {
            None
        };
        if dialer_proxy.is_some() && !udp_leaf_supports_dialer_chain(&leaf_hop.spec) {
            return Ok(UdpOutboundRoute::Unsupported(
                "udp dialer chain is not implemented".to_owned(),
            ));
        }
        match &leaf_hop.spec {
            ExecutionHopSpec::Direct(_) => Ok(UdpOutboundRoute::Direct),
            ExecutionHopSpec::Dns(_) => Ok(UdpOutboundRoute::Dns),
            ExecutionHopSpec::Socks5Connect(spec) if spec.udp => Ok(UdpOutboundRoute::Socks5(
                UdpSocks5Route {
                    server: spec.server.clone(),
                    port: spec.port,
                    username: spec
                        .auth
                        .as_ref()
                        .map(|auth| auth.username.clone())
                        .unwrap_or_default(),
                    password: spec
                        .auth
                        .as_ref()
                        .map(|auth| auth.password.clone())
                        .unwrap_or_default(),
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                },
            )),
            ExecutionHopSpec::ShadowSocks(spec) => {
                Ok(UdpOutboundRoute::ShadowSocks(UdpShadowSocksRoute {
                    server: spec.server.clone(),
                    port: spec.port,
                    cipher: spec.cipher.clone(),
                    password: spec.password.clone(),
                }))
            }
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
                    && (spec.protocol_param.trim().is_empty() || spec.protocol == "origin")
                    =>
            {
                Ok(UdpOutboundRoute::Ssr(UdpSsrRoute {
                    server: spec.server.clone(),
                    port: spec.port,
                    cipher: spec.cipher.clone(),
                    password: spec.password.clone(),
                    obfs: spec.obfs.clone(),
                    obfs_param: spec.obfs_param.clone(),
                    protocol: spec.protocol.clone(),
                    protocol_param: spec.protocol_param.clone(),
                }))
            }
            ExecutionHopSpec::Ssr(spec) if !spec.udp => Ok(UdpOutboundRoute::Unsupported(
                "selected ssr outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Ssr(spec)
                if !spec.cipher.trim().is_empty()
                    && spec.cipher != "dummy"
                    && spec.cipher != "none" =>
            {
                Ok(UdpOutboundRoute::Unsupported(format!(
                    "selected ssr cipher is not implemented for udp: {}",
                    spec.cipher
                )))
            }
            ExecutionHopSpec::Ssr(spec)
                if !spec.obfs.trim().is_empty() && spec.obfs != "plain" =>
            {
                Ok(UdpOutboundRoute::Unsupported(format!(
                    "selected ssr obfs is not implemented for udp: {}",
                    spec.obfs
                )))
            }
            ExecutionHopSpec::Ssr(spec)
                if !spec.obfs_param.trim().is_empty()
                    && spec.obfs != "plain"
                    && spec.obfs != "http_simple"
                    && spec.obfs != "http_post" =>
            {
                Ok(UdpOutboundRoute::Unsupported(
                    "selected ssr obfs-param is not implemented for udp".to_owned(),
                ))
            }
            ExecutionHopSpec::Ssr(spec)
                if !spec.protocol.trim().is_empty() && spec.protocol != "origin" =>
            {
                Ok(UdpOutboundRoute::Unsupported(format!(
                    "selected ssr protocol is not implemented for udp: {}",
                    spec.protocol
                )))
            }
            ExecutionHopSpec::Ssr(spec)
                if !spec.protocol_param.trim().is_empty() && spec.protocol != "origin" =>
            {
                Ok(UdpOutboundRoute::Unsupported(
                    "selected ssr protocol-param is not implemented for udp".to_owned(),
                ))
            }
            ExecutionHopSpec::AnyTls(spec) if spec.udp => Ok(UdpOutboundRoute::AnyTls(UdpAnyTlsRoute {
                dialer_proxy,
                server: spec.server.clone(),
                port: spec.port,
                password: spec.password.clone(),
                alpn: if spec.alpn.is_empty() {
                    vec!["h2".to_owned(), "http/1.1".to_owned()]
                } else {
                    spec.alpn.clone()
                },
                tls: TransportTlsOptions {
                    enabled: spec.tls.enabled,
                    sni: spec.tls.sni.clone(),
                    skip_cert_verify: spec.tls.skip_cert_verify,
                    fingerprint: spec.tls.fingerprint.clone(),
                    certificate: spec.tls.certificate.clone(),
                    private_key: spec.tls.private_key.clone(),
                },
            })),
            ExecutionHopSpec::AnyTls(_) => Ok(UdpOutboundRoute::Unsupported(
                "selected anytls outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Hysteria(spec) => Ok(UdpOutboundRoute::Hysteria(UdpHysteriaRoute {
                dialer_proxy,
                server: spec.server.clone(),
                port: spec.port,
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
                tls: TransportTlsOptions {
                    enabled: spec.tls.enabled,
                    sni: spec.tls.sni.clone(),
                    skip_cert_verify: spec.tls.skip_cert_verify,
                    fingerprint: spec.tls.fingerprint.clone(),
                    certificate: spec.tls.certificate.clone(),
                    private_key: spec.tls.private_key.clone(),
                },
            })),
            ExecutionHopSpec::Hy2(spec) => Ok(UdpOutboundRoute::Hy2(UdpHy2Route {
                dialer_proxy,
                server: spec.server.clone(),
                port: spec.port,
                password: spec.password.clone(),
                certificate: spec.tls.certificate.clone(),
                private_key: spec.tls.private_key.clone(),
                obfs: spec.obfs.clone(),
                obfs_password: spec.obfs_password.clone(),
                up_mbps: spec.up_mbps,
                down_mbps: spec.down_mbps,
                tls: TransportTlsOptions {
                    enabled: spec.tls.enabled,
                    sni: spec.tls.sni.clone(),
                    skip_cert_verify: spec.tls.skip_cert_verify,
                    fingerprint: spec.tls.fingerprint.clone(),
                    certificate: spec.tls.certificate.clone(),
                    private_key: spec.tls.private_key.clone(),
                },
            })),
            ExecutionHopSpec::Tuic(spec) if spec.udp => {
                Ok(UdpOutboundRoute::Tuic(UdpTuicRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
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
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                }))
            }
            ExecutionHopSpec::Tuic(_) => Ok(UdpOutboundRoute::Unsupported(
                "selected tuic outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::WireGuard(spec) if spec.udp => Ok(UdpOutboundRoute::WireGuard(
                UdpWireGuardRoute {
                    private_key: spec.private_key.clone(),
                    ip: spec.ip.clone(),
                    ipv6: spec.ipv6.clone(),
                    udp: spec.udp,
                    workers: spec.workers,
                    mtu: spec.mtu,
                    remote_dns_resolve: spec.remote_dns_resolve,
                    dns: spec.dns.clone(),
                    peers: spec
                        .peers
                        .iter()
                        .map(|peer| UdpWireGuardPeerRoute {
                            server: peer.server.clone(),
                            port: peer.port,
                            public_key: peer.public_key.clone(),
                            allowed_ips: peer.allowed_ips.clone(),
                            persistent_keepalive: peer.persistent_keepalive,
                        })
                        .collect(),
                },
            )),
            ExecutionHopSpec::WireGuard(_) => Ok(UdpOutboundRoute::Unsupported(
                "selected wireguard outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::OpenVpn(spec) if spec.udp => Ok(UdpOutboundRoute::OpenVpn(
                UdpOpenVpnRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
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
                    remote_dns_resolve: spec.remote_dns_resolve,
                    dns: spec.dns.clone(),
                    udp: spec.udp,
                    mtu: spec.mtu,
                },
            )),
            ExecutionHopSpec::OpenVpn(_) => Ok(UdpOutboundRoute::Unsupported(
                "selected openvpn outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Masque(spec) if spec.udp => Ok(UdpOutboundRoute::Masque(
                UdpMasqueRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    private_key: spec.private_key.clone(),
                    public_key: spec.public_key.clone(),
                    ip: spec.ip.clone(),
                    ipv6: spec.ipv6.clone(),
                    uri: spec.uri.clone(),
                    network: spec.network.clone(),
                    remote_dns_resolve: spec.remote_dns_resolve,
                    dns: spec.dns.clone(),
                    udp: spec.udp,
                    mtu: spec.mtu,
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                },
            )),
            ExecutionHopSpec::Masque(_) => Ok(UdpOutboundRoute::Unsupported(
                "selected masque outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Snell(spec)
                if spec.version >= 3
                    && (spec.obfs_mode.trim().is_empty()
                        || spec.obfs_mode == "tls"
                        || spec.obfs_mode == "http") =>
            {
                Ok(UdpOutboundRoute::Snell(UdpSnellRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    psk: spec.psk.clone(),
                    version: spec.version,
                    obfs_mode: spec.obfs_mode.clone(),
                    obfs_host: spec.obfs_host.clone(),
                }))
            }
            ExecutionHopSpec::Snell(spec) if spec.version < 3 => Ok(UdpOutboundRoute::Unsupported(
                format!("selected snell outbound version {} does not support udp", spec.version),
            )),
            ExecutionHopSpec::Snell(spec) => Ok(UdpOutboundRoute::Unsupported(format!(
                "selected snell outbound obfs is not implemented for udp: {}",
                spec.obfs_mode
            ))),
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
                Ok(UdpOutboundRoute::Trojan(UdpTrojanRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    password: spec.password.clone(),
                    shadowsocks: spec.shadowsocks.clone(),
                    network: spec.network.clone(),
                    websocket: spec.websocket.clone(),
                    grpc: spec.grpc.clone(),
                    h2: spec.h2.clone(),
                    http: spec.http.clone(),
                    xhttp: spec.xhttp.clone(),
                    alpn: if spec.alpn.is_empty() {
                        vec!["h2".to_owned(), "http/1.1".to_owned()]
                    } else {
                        spec.alpn.clone()
                    },
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                }))
            }
            ExecutionHopSpec::TrustTunnel(spec) if spec.udp => {
                Ok(UdpOutboundRoute::TrustTunnel(UdpTrustTunnelRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    username: spec.username.clone(),
                    password: spec.password.clone(),
                    quic: spec.quic,
                    alpn: if spec.alpn.is_empty() {
                        vec![if spec.quic { "h3" } else { "h2" }.to_owned()]
                    } else {
                        spec.alpn.clone()
                    },
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                }))
            }
            ExecutionHopSpec::TrustTunnel(spec) if !spec.udp => Ok(UdpOutboundRoute::Unsupported(
                "selected trusttunnel outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Trojan(spec)
                if spec.udp
                    && (spec.network.trim().is_empty()
                        || spec.network == "tcp"
                        || spec.network == "ws"
                        || spec.network == "http"
                        || spec.network == "grpc") =>
            {
                Ok(UdpOutboundRoute::Trojan(UdpTrojanRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    password: spec.password.clone(),
                    shadowsocks: TransportTrojanShadowsocksOptions {
                        enabled: spec.shadowsocks.enabled,
                        method: spec.shadowsocks.method.clone(),
                        password: spec.shadowsocks.password.clone(),
                    },
                    network: spec.network.clone(),
                    websocket: spec.websocket.clone(),
                    grpc: spec.grpc.clone(),
                    h2: spec.h2.clone(),
                    http: spec.http.clone(),
                    xhttp: spec.xhttp.clone(),
                    alpn: spec.alpn.clone(),
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                }))
            }
            ExecutionHopSpec::Trojan(spec) if !spec.udp => Ok(UdpOutboundRoute::Unsupported(
                "selected trojan outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Trojan(spec) => Ok(UdpOutboundRoute::Unsupported(format!(
                "selected trojan outbound network is not implemented for udp: {}",
                spec.network
            ))),
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
                Ok(UdpOutboundRoute::Vless(UdpVlessRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    uuid: spec.uuid.clone(),
                    flow: spec.flow.clone(),
                    reality_public_key: spec.reality_public_key.clone(),
                    reality_short_id: spec.reality_short_id.clone(),
                    reality_support_x25519mlkem768: spec.reality_support_x25519mlkem768,
                    network: spec.network.clone(),
                    websocket: spec.websocket.clone(),
                    grpc: spec.grpc.clone(),
                    h2: spec.h2.clone(),
                    http: spec.http.clone(),
                    xhttp: spec.xhttp.clone(),
                    encryption: spec.encryption.clone(),
                    packet_addr: spec.packet_addr,
                    xudp: spec.xudp,
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                    alpn: spec.alpn.clone(),
                }))
            }
            ExecutionHopSpec::Vless(spec) if !spec.udp => Ok(UdpOutboundRoute::Unsupported(
                "selected vless outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Vless(spec) if !spec.flow.trim().is_empty() => {
                Ok(UdpOutboundRoute::Unsupported(format!(
                    "selected vless outbound flow is not implemented for udp: {}",
                    spec.flow
                )))
            }
            ExecutionHopSpec::Vless(spec)
                if !spec.encryption.trim().is_empty() && spec.encryption != "none" =>
            {
                Ok(UdpOutboundRoute::Unsupported(format!(
                    "selected vless encryption is not implemented for udp: {}",
                    spec.encryption
                )))
            }
            ExecutionHopSpec::Vless(spec) => Ok(UdpOutboundRoute::Unsupported(format!(
                "selected vless outbound network is not implemented for udp: {}",
                spec.network
            ))),
            ExecutionHopSpec::Vmess(spec)
                if spec.udp
                    && (spec.network.trim().is_empty()
                        || spec.network == "tcp"
                        || spec.network == "grpc"
                        || spec.network == "h2"
                        || spec.network == "http"
                        || spec.network == "xhttp"
                        || spec.network == "ws")
                    =>
            {
                Ok(UdpOutboundRoute::Vmess(UdpVmessRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    uuid: spec.uuid.clone(),
                    alter_id: spec.alter_id,
                    cipher: spec.cipher.clone(),
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
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                    alpn: spec.alpn.clone(),
                }))
            }
            ExecutionHopSpec::Vmess(spec) if !spec.udp => Ok(UdpOutboundRoute::Unsupported(
                "selected vmess outbound does not enable udp".to_owned(),
            )),
            ExecutionHopSpec::Vmess(spec) => Ok(UdpOutboundRoute::Unsupported(format!(
                "selected vmess outbound network is not implemented for udp: {}",
                spec.network
            ))),
            ExecutionHopSpec::GostRelay(spec) => {
                Ok(UdpOutboundRoute::GostRelay(UdpGostRelayRoute {
                    dialer_proxy,
                    server: spec.server.clone(),
                    port: spec.port,
                    username: spec
                        .auth
                        .as_ref()
                        .map(|auth| auth.username.clone())
                        .unwrap_or_default(),
                    password: spec
                        .auth
                        .as_ref()
                        .map(|auth| auth.password.clone())
                        .unwrap_or_default(),
                    forward: spec.forward,
                    mux: spec.mux,
                    tls: TransportTlsOptions {
                        enabled: spec.tls.enabled,
                        sni: spec.tls.sni.clone(),
                        skip_cert_verify: spec.tls.skip_cert_verify,
                        fingerprint: spec.tls.fingerprint.clone(),
                        certificate: spec.tls.certificate.clone(),
                        private_key: spec.tls.private_key.clone(),
                    },
                }))
            }
            ExecutionHopSpec::Sudoku(spec) => Ok(UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy,
                server: spec.server.clone(),
                port: spec.port,
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
            })),
            ExecutionHopSpec::Socks5Connect(_) => Ok(UdpOutboundRoute::Unsupported(
                "selected socks5 outbound does not enable udp".to_owned(),
            )),
            other => Ok(UdpOutboundRoute::Unsupported(format!(
                "udp outbound is not implemented for {other:?}"
            ))),
        }
    }

    pub fn close_connection(&self, id: u64) -> bool {
        let Some(connection) = self.active_connections.lock().unwrap().get(&id).cloned() else {
            return false;
        };
        let mut handles = connection.handles.lock().unwrap();
        for handle in handles.iter_mut() {
            let _ = handle.shutdown_all();
        }
        true
    }

    pub fn close_all_connections(&self) -> usize {
        let connections = self
            .active_connections
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for connection in &connections {
            let mut handles = connection.handles.lock().unwrap();
            for handle in handles.iter_mut() {
                let _ = handle.shutdown_all();
            }
        }
        connections.len()
    }

    pub fn has_proxy(&self, name: &str) -> bool {
        self.registry.lock().unwrap().proxies.contains_key(name)
    }

    pub fn group_selected(&self, group: &str) -> Option<String> {
        self.registry
            .lock()
            .unwrap()
            .groups
            .get(group)
            .and_then(|view| view.runtime.selected().map(ToOwned::to_owned))
    }

    pub fn effective_group_selected(
        &self,
        group: &str,
        metadata: Option<&Metadata>,
    ) -> Option<String> {
        let mut registry = self.registry.lock().unwrap();
        let states = self.candidate_states.lock().unwrap().clone();
        resolve_proxy_path(&mut registry, group, metadata, &states)
            .ok()
            .and_then(|path| path.selected_path.into_iter().nth(1))
    }

    pub fn set_group_selected(
        &self,
        group: &str,
        candidate: &str,
    ) -> Result<(), RuntimeControlError> {
        let mut registry = self.registry.lock().unwrap();
        if !registry.proxies.contains_key(group) {
            return Err(RuntimeControlError::ProxyNotFound(group.to_owned()));
        }
        let Some(view) = registry.groups.get_mut(group) else {
            return Err(RuntimeControlError::GroupNotFound(group.to_owned()));
        };
        if !view.candidate_names.iter().any(|name| name == candidate) {
            return Err(RuntimeControlError::GroupCandidateNotFound {
                group: group.to_owned(),
                candidate: candidate.to_owned(),
            });
        }
        view.runtime.set_selected(candidate.to_owned());
        Ok(())
    }

    pub fn clear_group_selected(&self, group: &str) -> Result<(), RuntimeControlError> {
        let mut registry = self.registry.lock().unwrap();
        if !registry.proxies.contains_key(group) {
            return Err(RuntimeControlError::ProxyNotFound(group.to_owned()));
        }
        let Some(view) = registry.groups.get_mut(group) else {
            return Err(RuntimeControlError::GroupNotFound(group.to_owned()));
        };
        view.runtime.clear_selected();
        Ok(())
    }

    pub fn enqueue_udp_packet(&self, packet: PacketEnvelope) {
        self.udp_relay.lock().unwrap().enqueue(packet);
    }

    pub fn send_udp_packet(
        &self,
        packet: &PacketEnvelope,
        session: &mut impl UdpSession,
    ) -> io::Result<SocketAddr> {
        let target = self.udp_relay.lock().unwrap().send_packet(session, packet)?;
        self.record_up(packet.payload().len() as u64);
        Ok(target)
    }

    pub fn write_back_udp(
        &self,
        packet: &PacketEnvelope,
        payload: ByteWindow,
        remote: SocketAddr,
    ) -> io::Result<usize> {
        let len = payload.len() as u64;
        let written = self.udp_relay.lock().unwrap().write_back(packet, payload, remote)?;
        self.record_down(len.min(written as u64));
        Ok(written)
    }

    pub fn selected_target(&self, metadata: &Metadata) -> String {
        let mut metadata = metadata.clone();
        let _ = self.preprocess_metadata_for_routing(&mut metadata);
        let mode = self.mode.lock().unwrap().clone();
        let registry = self.registry.lock().unwrap();
        let rules = Arc::clone(&self.rules.read().unwrap());
        select_target_name(&mode, &metadata, &registry, rules.as_ref())
    }

    pub fn tcp_strategy(&self) -> TcpRelayStrategy {
        self.tcp_strategy
    }

    pub fn connect_tcp_with_dialer<D>(
        &self,
        metadata: &Metadata,
        mut dialer: D,
    ) -> Result<(BoxedTcpStream, ExecutionPlan), ExecutionError>
    where
        D: TcpDialer,
    {
        let mut metadata = metadata.clone();
        self.preprocess_metadata_for_routing(&mut metadata)?;
        if let Some(result) = self.try_connect_direct_tcp(&metadata, &mut dialer)? {
            return Ok(result);
        }
        metadata.smart_rule=self.rules.read().unwrap().smart_rule_identity(&metadata);
        let mut executor = mihomo_transport::TcpTransportExecutor::new(dialer);
        let mut attempts = 0;
        loop {
            let states = self.candidate_states.lock().unwrap().clone();
            let mode = self.mode.lock().unwrap().clone();
            let rules = Arc::clone(&self.rules.read().unwrap());
            let (plan, transport, smart_route, pinned) = {
                let mut registry = self.registry.lock().unwrap();
                let target = select_target_name(&mode, &metadata, &registry, rules.as_ref());
                let plan = build_execution_plan(&mut registry, &target, Some(&metadata), &states)?;
                if plan.hops.len() == 1 && matches!(plan.hops[0].spec, ExecutionHopSpec::Dns(_)) {
                    drop(registry);
                    return self.connect_dns_tcp().map(|stream| (stream, plan));
                }
                let transport = crate::build_transport_plan_from_execution_plan(&plan, &metadata)?;
                let smart_route = plan.selected_path.iter().any(|name| registry.groups.get(name).is_some_and(|view|view.runtime.smart.is_some()));
                let pinned = plan.selected_path.iter().any(|name| registry.groups.get(name).is_some_and(|view|view.runtime.smart.is_some() && view.runtime.selected().is_some()));
                (plan, transport, smart_route, pinned)
            };
            if smart_route && metadata.kind != mihomo_core::SessionKind::Inner {
                if let Some(result)=self.connect_smart_race(&metadata,&plan,executor.dialer()) {return result;}
            }
            let started = std::time::Instant::now();
            match crate::run_transport_plan(&mut executor, &transport) {
                Ok(stream) => {
                    let stream = if let Some(tracker) = self.smart_tracker(&metadata, &plan, started.elapsed().as_millis().min(u64::MAX as u128) as u64) { crate::smart::SmartStream::wrap(stream, tracker) } else { stream };
                    return Ok((stream, plan));
                }
                Err(error) => {
                    if !smart_route { return Err(error); }
                    self.record_smart_dial_failure(&metadata, &plan, started.elapsed().as_millis().min(u64::MAX as u128) as u64);
                    attempts += 1;
                    if pinned || attempts >= 5 { return Err(error); }
                }
            }
        }
    }

    pub fn connect_tcp_with_system_dialer(
        &self,
        metadata: &Metadata,
    ) -> Result<(BoxedTcpStream, ExecutionPlan), ExecutionError> {
        let dialer = DnsAwareSystemTcpDialer::new(self.dns_runtime(), None);
        self.connect_tcp_with_dialer(metadata, dialer)
    }

    pub fn connect_tcp_with_system_dialer_with_timeout(
        &self,
        metadata: &Metadata,
        timeout_ms: Option<u64>,
    ) -> Result<(BoxedTcpStream, ExecutionPlan), ExecutionError> {
        let dialer = DnsAwareSystemTcpDialer::new(self.dns_runtime(), timeout_ms);
        self.connect_tcp_with_dialer(metadata, dialer)
    }

    fn try_connect_direct_tcp<D>(
        &self,
        metadata: &Metadata,
        dialer: &mut D,
    ) -> Result<Option<(BoxedTcpStream, ExecutionPlan)>, ExecutionError>
    where
        D: TcpDialer,
    {
        if self.current_mode() != "direct" || !metadata.special_proxy.trim().is_empty() {
            return Ok(None);
        }
        let port = match metadata.dst_port {
            Some(port) => port,
            None => return Ok(None),
        };
        let host = metadata
            .host
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .or_else(|| metadata.dst_ip.map(|ip| ip.to_string()));
        let target = match host {
            Some(host) => TransportTarget::new(host, port),
            None => return Ok(None),
        };
        let plan = ExecutionPlan {
            requested: "DIRECT".to_owned(),
            selected_path: vec!["DIRECT".to_owned()],
            leaf_name: "DIRECT".to_owned(),
            dial_chain: vec!["DIRECT".to_owned()],
            hops: vec![crate::ExecutionHop {
                name: "DIRECT".to_owned(),
                kind: None,
                source: crate::ProxySource::Builtin,
                spec: crate::ExecutionHopSpec::Direct(crate::execution::DirectHopSpec {
                    socket: crate::execution::SocketOptions::default(),
                }),
            }],
        };
        let stream = dialer
            .connect(&target, &TransportSocketOptions::default(), TcpDialPurpose::FinalTarget)
            .map_err(ExecutionError::from)?;
        Ok(Some((stream, plan)))
    }

    pub fn relay_tcp_stream(
        &self,
        context: &mut ConnectionContext,
        upstream: &mut dyn TcpStream,
        plan: Option<&ExecutionPlan>,
    ) -> io::Result<TcpRelayStats> {
        let tracked = {
            let mut handles = Vec::new();
            if let Ok(handle) = context.stream_mut().try_clone_box() {
                handles.push(handle);
            }
            if let Ok(handle) = upstream.try_clone_box() {
                handles.push(handle);
            }
            self.register_connection(
                context.id(),
                context.metadata().clone(),
                plan,
                handles,
            )
        };
        let result = relay_bidirectional_with_counters(
            context.stream_mut(),
            upstream,
            self.tcp_strategy,
            Some(&tracked.upload),
            Some(&tracked.download),
        );
        self.unregister_connection(context.id());
        let stats = result?;
        self.record_up(stats.left_to_right);
        self.record_down(stats.right_to_left);
        Ok(stats)
    }

    pub fn forward_tcp_context_with_dialer<D>(
        &self,
        context: &mut ConnectionContext,
        dialer: D,
    ) -> Result<TcpRelayStats, TcpForwardError>
    where
        D: TcpDialer,
    {
        let (mut upstream, plan) = self.connect_tcp_with_dialer(context.metadata(), dialer)?;
        let stats = self.relay_tcp_stream(context, &mut *upstream, Some(&plan))?;
        Ok(stats)
    }

    pub fn forward_tcp_context_with_system_dialer(
        &self,
        context: &mut ConnectionContext,
    ) -> Result<TcpRelayStats, TcpForwardError> {
        let (mut upstream, plan) = self.connect_tcp_with_system_dialer(context.metadata())?;
        let stats = self.relay_tcp_stream(context, &mut *upstream, Some(&plan))?;
        Ok(stats)
    }

    pub fn process_udp_queue(
        &self,
        session: &mut impl UdpSession,
    ) -> io::Result<Option<SocketAddr>> {
        self.udp_relay.lock().unwrap().process_next(session)
    }

    fn remember_error(&self, error: impl ToString) {
        *self.last_error.lock().unwrap() = Some(error.to_string());
    }

    pub fn preprocess_metadata_for_routing(
        &self,
        metadata: &mut Metadata,
    ) -> Result<(), ExecutionError> {
        self.enrich_smart_metadata(metadata);
        if metadata
            .host
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Ok(());
        }
        let Some(dst_ip) = metadata.dst_ip else {
            return Ok(());
        };
        let Some(runtime) = self.dns_runtime() else {
            return Ok(());
        };
        let runtime = runtime.lock().unwrap();
        if let Some(host) = runtime.reverse_lookup(dst_ip).map(ToOwned::to_owned) {
            metadata.host = Some(host);
            metadata.dst_ip = None;
            metadata.dns_mode = DnsMode::FakeIp;
            return Ok(());
        }
        if runtime.is_fake_ip_addr(dst_ip) {
            return Err(ExecutionError::Transport(TransportError::Io {
                kind: io::ErrorKind::NotFound,
                message: format!("fake DNS record {dst_ip} missing"),
            }));
        }
        Ok(())
    }

    fn record_up(&self, bytes: u64) {
        self.up_total.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_down(&self, bytes: u64) {
        self.down_total.fetch_add(bytes, Ordering::Relaxed);
    }

    fn connect_dns_tcp(&self) -> Result<BoxedTcpStream, ExecutionError> {
        let Some(runtime) = self.dns_runtime.read().unwrap().as_ref().map(Arc::clone) else {
            return Err(ExecutionError::Transport(TransportError::InvalidPlan(
                "dns runtime is unavailable for dns outbound".to_owned(),
            )));
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(TransportError::from)
            .map_err(ExecutionError::from)?;
        let addr = listener
            .local_addr()
            .map_err(TransportError::from)
            .map_err(ExecutionError::from)?;
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut header = [0_u8; 2];
            loop {
                if stream.read_exact(&mut header).is_err() {
                    break;
                }
                let length = u16::from_be_bytes(header) as usize;
                let mut payload = vec![0_u8; length];
                if stream.read_exact(&mut payload).is_err() {
                    break;
                }
                let response = {
                    let mut runtime = runtime.lock().unwrap();
                    runtime.relay_query_packet_via_system(&payload)
                };
                let Ok(Some(response)) = response else {
                    continue;
                };
                let Ok(length) = u16::try_from(response.len()) else {
                    break;
                };
                if stream.write_all(&length.to_be_bytes()).is_err() {
                    break;
                }
                if stream.write_all(&response).is_err() {
                    break;
                }
                if stream.flush().is_err() {
                    break;
                }
            }
        });

        let stream = NetTcpStream::connect(addr)
            .map_err(TransportError::from)
            .map_err(ExecutionError::from)?;
        Ok(Box::new(stream))
    }

    fn register_connection(
        &self,
        id: u64,
        metadata: Metadata,
        plan: Option<&ExecutionPlan>,
        handles: Vec<BoxedTcpStream>,
    ) -> Arc<TrackedConnection> {
        let current_mode = self.current_mode();
        let chains = plan
            .map(|plan| plan.selected_path.iter().rev().cloned().collect())
            .unwrap_or_default();
        let provider_chains = plan
            .map(|plan| connection_provider_chains(&self.registry.lock().unwrap(), plan))
            .unwrap_or_default();
        let matched_rule = if plan.is_some()
            && current_mode == "rule"
            && metadata.special_proxy.trim().is_empty()
        {
            self.rules
                .read()
                .unwrap()
                .matched_rule_definition(&metadata)
        } else {
            None
        };
        let tracked = Arc::new(TrackedConnection {
            id,
            metadata,
            start_unix_ms: now_unix_ms(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            chains,
            provider_chains,
            rule: matched_rule
                .as_ref()
                .map(|rule| rule.rule_type.as_str().to_owned())
                .unwrap_or_default(),
            rule_payload: matched_rule
                .map(|rule| rule.payload)
                .unwrap_or_default(),
            handles: Mutex::new(handles),
        });
        self.active_connections
            .lock()
            .unwrap()
            .insert(id, Arc::clone(&tracked));
        tracked
    }

    fn unregister_connection(&self, id: u64) {
        self.active_connections.lock().unwrap().remove(&id);
    }
}

pub(crate) struct DnsAwareSystemTcpDialer {
    dns_runtime: Option<Arc<Mutex<DnsRuntime>>>,
    timeout_ms: Option<u64>,
}

impl DnsAwareSystemTcpDialer {
    pub(crate) fn new(dns_runtime: Option<Arc<Mutex<DnsRuntime>>>, timeout_ms: Option<u64>) -> Self {
        Self { dns_runtime, timeout_ms }
    }

    fn resolve_target(
        &mut self,
        target: &TransportTarget,
        purpose: TcpDialPurpose,
    ) -> Result<Vec<SocketAddr>, TransportError> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }

        if let Some(runtime) = self.dns_runtime.as_ref() {
            let resolved = {
                let mut runtime = runtime.lock().unwrap();
                match purpose {
                    TcpDialPurpose::FinalTarget => {
                        runtime.resolve_direct_server_host_addrs_via_system(&target.host)
                    }
                    TcpDialPurpose::ProxyServer => {
                        runtime.resolve_proxy_server_host_addrs_via_system(&target.host)
                    }
                }
            }
            .map_err(|err| TransportError::Io {
                kind: io::ErrorKind::Other,
                message: err.to_string(),
            })?;
            if !resolved.is_empty() {
                return Ok(resolved
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .collect());
            }
        }

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
        Ok(addrs)
    }
}

impl TcpDialer for DnsAwareSystemTcpDialer {
    fn fork(&self,timeout_ms:u64)->Option<Box<dyn TcpDialer+Send>>{Some(Box::new(Self::new(self.dns_runtime.clone(),Some(self.timeout_ms.map(|limit|limit.min(timeout_ms)).unwrap_or(timeout_ms)))))}

    fn resolve_addrs(
        &mut self,
        target: &TransportTarget,
        _socket: &TransportSocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<Vec<NetTcpStreamAddr>, TransportError> {
        self.resolve_target(target, purpose)
            .map(|addrs| addrs.into_iter().map(NetTcpStreamAddr).collect())
    }

    fn connect(
        &mut self,
        target: &TransportTarget,
        socket: &TransportSocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        let addrs = <Self as TcpDialer>::resolve_addrs(self, target, socket, purpose)?
            .into_iter()
            .map(|addr| addr.0)
            .collect::<Vec<_>>();
        let mut last_err = None;
        for addr in addrs {
            let stream = mihomo_transport::connect_tcp_addr_with_options(addr,socket,self.timeout_ms);
            match stream {
                Ok(stream) => {
                    if let Some(timeout_ms) = self.timeout_ms {
                        let timeout = std::time::Duration::from_millis(timeout_ms.max(1));
                        let _ = stream.set_read_timeout(Some(timeout));
                        let _ = stream.set_write_timeout(Some(timeout));
                    }
                    return Ok(Box::new(stream));
                }
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

fn connection_provider_chains(registry: &RuntimeRegistry, plan: &ExecutionPlan) -> Vec<String> {
    plan.selected_path
        .iter()
        .rev()
        .map(|name| {
            registry
                .proxies
                .get(name)
                .and_then(|registration| match &registration.source {
                    crate::ProxySource::ProviderInline { provider } => Some(provider.clone()),
                    _ => None,
                })
                .unwrap_or_default()
        })
        .collect()
}

fn udp_leaf_supports_dialer_chain(spec: &ExecutionHopSpec) -> bool {
    matches!(
        spec,
        ExecutionHopSpec::AnyTls(_)
            | ExecutionHopSpec::Hysteria(_)
            | ExecutionHopSpec::Hy2(_)
            | ExecutionHopSpec::Tuic(_)
            | ExecutionHopSpec::WireGuard(_)
            | ExecutionHopSpec::OpenVpn(_)
            | ExecutionHopSpec::Masque(_)
            | ExecutionHopSpec::Snell(_)
            | ExecutionHopSpec::Trojan(_)
            | ExecutionHopSpec::TrustTunnel(_)
            | ExecutionHopSpec::Vless(_)
            | ExecutionHopSpec::Vmess(_)
            | ExecutionHopSpec::GostRelay(_)
            | ExecutionHopSpec::Sudoku(_)
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Tunnel for RuntimeTunnel {
    fn handle_tcp(&self, mut context: ConnectionContext) {
        if let Err(err) = self.forward_tcp_context_with_system_dialer(&mut context) {
            self.remember_error(err);
        }
    }

    fn handle_udp(&self, packet: PacketEnvelope) {
        self.enqueue_udp_packet(packet);
    }
}

fn select_target_name(
    mode: &str,
    metadata: &Metadata,
    registry: &RuntimeRegistry,
    rules: &RuleSet,
) -> String {
    if !metadata.special_proxy.trim().is_empty() {
        if metadata.special_proxy == DNS_RULES_PROXY {
            return select_rule_target(metadata, registry, rules);
        }
        return metadata.special_proxy.clone();
    }

    match mode {
        "direct" => "DIRECT".to_owned(),
        "global" => select_global_target(registry),
        "rule" => select_rule_target(metadata, registry, rules),
        _ => RULE_FALLBACK_TARGET.to_owned(),
    }
}

fn select_global_target(registry: &RuntimeRegistry) -> String {
    if registry.groups.contains_key("GLOBAL") || registry.proxies.contains_key("GLOBAL") {
        "GLOBAL".to_owned()
    } else {
        RULE_FALLBACK_TARGET.to_owned()
    }
}

fn select_rule_target(metadata: &Metadata, registry: &RuntimeRegistry, rules: &RuleSet) -> String {
    let Some(target) = rules.matched_rule_definition_and_record(metadata).map(|rule| rule.target) else {
        return RULE_FALLBACK_TARGET.to_owned();
    };
    if registry.proxies.contains_key(&target) || registry.groups.contains_key(&target) {
        target
    } else {
        RULE_FALLBACK_TARGET.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};

    use mihomo_buf::ByteWindow;
    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{
        BoxedTcpStream, DnsMode, Metadata, PacketEnvelope, Tunnel, UdpPacket, UdpSession,
        WriteBack,
    };
    use mihomo_rules::compile_rule_set;
    use mihomo_transport::{SocketOptions, TcpDialPurpose, TcpDialer, TransportError, TransportTarget};

    use crate::{build_runtime_registry, ExecutionHopSpec, RuntimeGroupView};

    use super::{
        DNS_RULES_PROXY, RuntimeTunnel, TcpRelayStrategy, UdpAnyTlsRoute, UdpGostRelayRoute, UdpHy2Route, UdpMasqueRoute, UdpOpenVpnRoute, UdpOutboundRoute,
        UdpShadowSocksRoute, UdpSnellRoute, UdpSsrRoute, UdpSudokuRoute, UdpTrojanRoute,
        UdpTrustTunnelRoute, UdpTuicRoute, UdpWireGuardRoute,
        UdpVlessRoute, UdpVmessRoute,
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
            self.calls.push(target.authority());
            let Some((expected, handle)) = self.expected.pop_front() else {
                return Err(TransportError::InvalidPlan(
                    "unexpected tunnel dial".to_owned(),
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

    #[derive(Default)]
    struct RecordingSink {
        writes: Mutex<Vec<(Vec<u8>, Option<SocketAddr>)>>,
    }

    struct TestPacket {
        payload: ByteWindow,
        local_addr: SocketAddr,
        sink: Arc<RecordingSink>,
    }

    impl WriteBack for TestPacket {
        fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
            let len = payload.len();
            self.sink
                .writes
                .lock()
                .unwrap()
                .push((payload.as_slice().to_vec(), source));
            Ok(len)
        }
    }

    impl UdpPacket for TestPacket {
        fn payload(&self) -> ByteWindow {
            self.payload.clone()
        }

        fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }
    }

    #[derive(Default)]
    struct FakeUdpSession {
        writes: Vec<(Vec<u8>, SocketAddr)>,
    }

    impl UdpSession for FakeUdpSession {
        fn resolve_udp(&mut self, metadata: &mut Metadata) -> io::Result<()> {
            if metadata.host.as_deref() == Some("example.com") {
                metadata.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
                return Ok(());
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "missing resolver result"))
        }

        fn send_to(&mut self, payload: ByteWindow, target: SocketAddr) -> io::Result<usize> {
            let len = payload.len();
            self.writes.push((payload.as_slice().to_vec(), target));
            Ok(len)
        }
    }

    #[test]
    fn tunnel_special_proxy_overrides_mode_selection() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let inbound = SharedStreamHandle::new(Vec::new());
        let mut context = mihomo_core::ConnectionContext::new(
            inbound.stream(),
            Metadata {
                host: Some("final.example.com".into()),
                dst_port: Some(443),
                special_proxy: "special".into(),
                ..Metadata::default()
            },
        );
        let mut dialer = FakeDialer::new();
        dialer.push_connection(
            "special.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
        );
        tunnel
            .forward_tcp_context_with_dialer(&mut context, dialer)
            .unwrap();
    }

    #[test]
    fn tunnel_special_proxy_rules_uses_rule_mode_selection() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: http
    name: matched
    server: matched.example.com
    port: 8080
rules:
  - MATCH,matched
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let rules = compile_rule_set(&["MATCH,matched".into()]).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_rule_set(rules)
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let selected = tunnel.selected_target(&Metadata {
            host: Some("final.example.com".into()),
            dst_port: Some(443),
            special_proxy: DNS_RULES_PROXY.into(),
            ..Metadata::default()
        });
        assert_eq!(selected, "matched");
    }

    #[test]
    fn selected_target_recovers_host_from_fake_ip_before_rule_match() {
        let document = parse_runtime_config_document(
            r#"
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
proxies:
  - type: http
    name: matched
    server: matched.example.com
    port: 8080
rules:
  - DOMAIN-SUFFIX,example.com,matched
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let rules = compile_rule_set(&[
            "DOMAIN-SUFFIX,example.com,matched".into(),
            "MATCH,DIRECT".into(),
        ])
        .unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_rule_set(rules)
            .with_dns_runtime(mihomo_dns::DnsRuntime::from_document(&document).unwrap())
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let fake = {
            let runtime = tunnel.dns_runtime().unwrap();
            let mut runtime = runtime.lock().unwrap();
            runtime.resolve_host("edge.example.com").unwrap().unwrap()
        };
        let selected = tunnel.selected_target(&Metadata {
            dst_ip: Some(fake),
            dst_port: Some(443),
            ..Metadata::default()
        });
        assert_eq!(selected, "matched");
    }

    #[test]
    fn selected_target_rejects_missing_fake_ip_record() {
        let document = parse_runtime_config_document(
            r#"
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let rules = compile_rule_set(&["MATCH,DIRECT".into()]).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_rule_set(rules)
            .with_dns_runtime(mihomo_dns::DnsRuntime::from_document(&document).unwrap())
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let err = tunnel
            .selected_target_for_metadata(&Metadata {
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 88))),
                dst_port: Some(443),
                ..Metadata::default()
            })
            .unwrap_err();
        assert!(err.to_string().contains("fake DNS record"));
    }

    #[test]
    fn tunnel_global_mode_uses_global_group_selection() {
        let document = parse_runtime_config_document(
            r#"
mode: global
proxies:
  - type: http
    name: leaf
    server: leaf.example.com
    port: 8443
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let RuntimeGroupView { runtime, .. } = registry.groups.get_mut("GLOBAL").unwrap();
        runtime.set_selected("leaf");
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let inbound = SharedStreamHandle::new(Vec::new());
        let mut context = mihomo_core::ConnectionContext::new(
            inbound.stream(),
            Metadata {
                host: Some("final.example.com".into()),
                dst_port: Some(443),
                ..Metadata::default()
            },
        );
        let mut dialer = FakeDialer::new();
        dialer.push_connection(
            "leaf.example.com:8443",
            b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
        );
        tunnel
            .forward_tcp_context_with_dialer(&mut context, dialer)
            .unwrap();
    }

    #[test]
    fn tunnel_handle_udp_enqueues_and_processes_packets() {
        let document = parse_runtime_config_document("mode: direct").unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let sink = Arc::new(RecordingSink::default());
        let packet = Arc::new(TestPacket {
            payload: ByteWindow::freeze(b"hello".to_vec()),
            local_addr: "127.0.0.1:5300".parse().unwrap(),
            sink,
        });
        let envelope = PacketEnvelope::new(
            packet,
            Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                dns_mode: DnsMode::Normal,
                ..Metadata::default()
            },
        );

        tunnel.handle_udp(envelope);
        assert_eq!(tunnel.pending_udp_packets(), 1);

        let mut session = FakeUdpSession::default();
        let target = tunnel.process_udp_queue(&mut session).unwrap().unwrap();
        assert_eq!(target, "1.1.1.1:53".parse().unwrap());
        assert_eq!(tunnel.pending_udp_packets(), 0);
        assert_eq!(session.writes, vec![(b"hello".to_vec(), target)]);
    }

    #[test]
    fn tunnel_direct_mode_short_circuits_tcp_planning() {
        let document = parse_runtime_config_document("mode: direct").unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let mut dialer = FakeDialer::new();
        dialer.push_connection("1.1.1.1:443", b"server-data".to_vec());
        let (stream, plan) = tunnel
            .connect_tcp_with_dialer(
                &Metadata {
                    dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                    dst_port: Some(443),
                    ..Metadata::default()
                },
                dialer,
            )
            .unwrap();
        let _ = stream;
        assert_eq!(plan.requested, "DIRECT");
        assert_eq!(plan.leaf_name, "DIRECT");
        assert_eq!(plan.selected_path, vec!["DIRECT".to_owned()]);
        assert!(matches!(plan.hops[0].spec, ExecutionHopSpec::Direct(_)));
    }

    #[test]
    fn tunnel_direct_mode_short_circuits_tcp_planning_for_domain_targets() {
        let document = parse_runtime_config_document("mode: direct").unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);
        let mut dialer = FakeDialer::new();
        dialer.push_connection("example.com:443", b"server-data".to_vec());
        let (stream, plan) = tunnel
            .connect_tcp_with_dialer(
                &Metadata {
                    host: Some("example.com".into()),
                    dst_port: Some(443),
                    ..Metadata::default()
                },
                dialer,
            )
            .unwrap();
        let _ = stream;
        assert_eq!(plan.requested, "DIRECT");
        assert_eq!(plan.leaf_name, "DIRECT");
        assert_eq!(plan.selected_path, vec!["DIRECT".to_owned()]);
        assert!(matches!(plan.hops[0].spec, ExecutionHopSpec::Direct(_)));
    }

    #[test]
    fn connect_tcp_with_system_dialer_uses_dns_runtime_for_direct_domain_targets() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
hosts:
  direct-fallback.local:
    - "::1"
    - "127.0.0.1"
dns:
  enable: true
  use-hosts: true
  use-system-hosts: false
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_dns_runtime(mihomo_dns::DnsRuntime::from_document(&document).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let (_stream, plan) = tunnel
            .connect_tcp_with_system_dialer(&Metadata {
                host: Some("direct-fallback.local".into()),
                dst_port: Some(addr.port()),
                ..Metadata::default()
            })
            .unwrap();

        assert_eq!(plan.requested, "DIRECT");
        worker.join().unwrap();
    }

    #[test]
    fn connect_tcp_with_system_dialer_uses_dns_runtime_for_proxy_server_targets() {
        let document = parse_runtime_config_document(
            r#"
mode: global
hosts:
  proxy-fallback.local:
    - "::1"
    - "127.0.0.1"
dns:
  enable: true
  use-hosts: true
  use-system-hosts: false
proxies:
  - type: http
    name: relay
    server: proxy-fallback.local
    port: 0
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        if let Some(mihomo_outbound::OutboundDefinition::Http(config)) =
            registry.proxy_definitions.get_mut("relay")
        {
            config.port = addr.port();
        } else {
            panic!("missing relay proxy definition");
        }
        let RuntimeGroupView { runtime, .. } = registry.groups.get_mut("GLOBAL").unwrap();
        runtime.set_selected("relay");

        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_dns_runtime(mihomo_dns::DnsRuntime::from_document(&document).unwrap());

        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 64];
            let _ = stream.read(&mut buf).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
        });

        let (_stream, plan) = tunnel
            .connect_tcp_with_system_dialer(&Metadata {
                host: Some("final.example.com".into()),
                dst_port: Some(443),
                ..Metadata::default()
            })
            .unwrap();

        assert_eq!(plan.leaf_name, "relay");
        worker.join().unwrap();
    }

    #[test]
    fn failed_healthcheck_marks_proxy_snapshot_unhealthy() {
        let document = parse_runtime_config_document(
            r#"
mode: rule
proxies:
  - type: direct
    name: edge-http
rules:
  - MATCH,edge-http
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let err = crate::run_proxy_health_check_with_timeout(
            &tunnel,
            "edge-http",
            &format!("http://127.0.0.1:{}/delay", addr.port()),
            "204",
            Some(5_000),
        )
        .unwrap_err();
        assert!(matches!(err, crate::HealthCheckError::Request(_, _)));

        let health = tunnel.proxy_health_snapshot("edge-http").unwrap();
        assert!(!health.alive);
        assert!(health.history.last().is_some_and(|entry| entry.delay_ms == 0));
        let url_state = health.extra.values().next().unwrap();
        assert!(url_state.last_error.contains("unexpected http status"));
        worker.join().unwrap();
    }

    #[test]
    fn healthcheck_timeout_marks_proxy_unhealthy_when_peer_stalls() {
        let document = parse_runtime_config_document(
            r#"
mode: rule
proxies:
  - type: direct
    name: edge-http
rules:
  - MATCH,edge-http
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(400));
        });

        let err = crate::run_proxy_health_check_with_timeout(
            &tunnel,
            "edge-http",
            &format!("http://127.0.0.1:{}/delay", addr.port()),
            "204",
            Some(100),
        )
        .unwrap_err();
        assert!(matches!(err, crate::HealthCheckError::Request(_, _)));

        let health = tunnel.proxy_health_snapshot("edge-http").unwrap();
        assert!(!health.alive);
        assert!(health.history.last().is_some_and(|entry| entry.delay_ms == 0));
        worker.join().unwrap();
    }

    #[test]
    fn tunnel_direct_mode_short_circuits_udp_planning() {
        let document = parse_runtime_config_document("mode: direct").unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let (route, plan) = tunnel
            .resolve_udp_outbound_with_plan(&Metadata {
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                dst_port: Some(53),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(route, UdpOutboundRoute::Direct);
        assert_eq!(plan.requested, "DIRECT");
        assert_eq!(plan.leaf_name, "DIRECT");
        assert_eq!(plan.selected_path, vec!["DIRECT".to_owned()]);
        assert!(matches!(plan.hops[0].spec, ExecutionHopSpec::Direct(_)));
    }

    #[test]
    fn resolve_udp_outbound_supports_shadowsocks_without_plugin() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: edge-ss
    server: 1.2.3.4
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ss".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::ShadowSocks(UdpShadowSocksRoute {
                server: "1.2.3.4".into(),
                port: 8388,
                cipher: "chacha20-ietf-poly1305".into(),
                password: "secret".into(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_origin_plain_dummy() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
    port: 8389
    cipher: dummy
    password: secret
    protocol: origin
    obfs: plain
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "dummy".into(),
                password: "secret".into(),
                obfs: "plain".into(),
                obfs_param: String::new(),
                protocol: "origin".into(),
                protocol_param: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_origin_plain_aes_128_cfb() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
    port: 8389
    cipher: aes-128-cfb
    password: secret
    protocol: origin
    obfs: plain
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "aes-128-cfb".into(),
                password: "secret".into(),
                obfs: "plain".into(),
                obfs_param: String::new(),
                protocol: "origin".into(),
                protocol_param: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_origin_plain_with_ignored_params() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
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
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "dummy".into(),
                password: "secret".into(),
                obfs: "plain".into(),
                obfs_param: "ignored-host".into(),
                protocol: "origin".into(),
                protocol_param: "ignored-user".into(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_origin_plain_aes_256_cfb() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
    port: 8389
    cipher: aes-256-cfb
    password: secret
    protocol: origin
    obfs: plain
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "aes-256-cfb".into(),
                password: "secret".into(),
                obfs: "plain".into(),
                obfs_param: String::new(),
                protocol: "origin".into(),
                protocol_param: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_origin_plain_aes_192_cfb() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
    port: 8389
    cipher: aes-192-cfb
    password: secret
    protocol: origin
    obfs: plain
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "aes-192-cfb".into(),
                password: "secret".into(),
                obfs: "plain".into(),
                obfs_param: String::new(),
                protocol: "origin".into(),
                protocol_param: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_http_simple_obfs() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
    port: 8389
    cipher: dummy
    password: secret
    protocol: origin
    obfs: http_simple
    obfs-param: obfs.example.com
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "dummy".into(),
                password: "secret".into(),
                obfs: "http_simple".into(),
                obfs_param: "obfs.example.com".into(),
                protocol: "origin".into(),
                protocol_param: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_ssr_http_post_obfs() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ssr
    name: edge-ssr
    server: 1.2.3.4
    port: 8389
    cipher: aes-128-cfb
    password: secret
    protocol: origin
    obfs: http_post
    obfs-param: obfs.example.com
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ssr".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Ssr(UdpSsrRoute {
                server: "1.2.3.4".into(),
                port: 8389,
                cipher: "aes-128-cfb".into(),
                password: "secret".into(),
                obfs: "http_post".into(),
                obfs_param: "obfs.example.com".into(),
                protocol: "origin".into(),
                protocol_param: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_anytls_with_udp_enabled() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: anytls
    name: edge-anytls
    server: anytls.example.com
    port: 443
    password: secret
    udp: true
    sni: edge.example.com
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-anytls".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::AnyTls(UdpAnyTlsRoute {
                dialer_proxy: None,
                server: "anytls.example.com".into(),
                port: 443,
                password: "secret".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "edge.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_anytls_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: anytls
    name: edge-anytls
    server: anytls.example.com
    port: 443
    password: secret
    udp: true
    sni: edge.example.com
    skip-cert-verify: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-anytls".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::AnyTls(UdpAnyTlsRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "anytls.example.com".into(),
                port: 443,
                password: "secret".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "edge.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_snell_v3_without_obfs() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: 1.2.3.4
    port: 8443
    psk: secret-psk
    version: 3
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-snell".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Snell(UdpSnellRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 8443,
                psk: "secret-psk".into(),
                version: 3,
                obfs_mode: String::new(),
                obfs_host: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_snell_v3_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: snell
    name: edge-snell
    server: 1.2.3.4
    port: 8443
    psk: secret-psk
    version: 3
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-snell".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Snell(UdpSnellRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "1.2.3.4".into(),
                port: 8443,
                psk: "secret-psk".into(),
                version: 3,
                obfs_mode: String::new(),
                obfs_host: String::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_snell_v3_with_http_obfs() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: 1.2.3.4
    port: 8443
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: http
      host: bing.com
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-snell".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Snell(UdpSnellRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 8443,
                psk: "secret-psk".into(),
                version: 3,
                obfs_mode: "http".into(),
                obfs_host: "bing.com".into(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_snell_v3_with_tls_obfs() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: snell
    name: edge-snell
    server: 1.2.3.4
    port: 8443
    psk: secret-psk
    version: 3
    obfs-opts:
      mode: tls
      host: bing.com
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-snell".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Snell(UdpSnellRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 8443,
                psk: "secret-psk".into(),
                version: 3,
                obfs_mode: "tls".into(),
                obfs_host: "bing.com".into(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_dns_proxy() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: dns
    name: edge-dns
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.test".into()),
                dst_port: Some(53),
                special_proxy: "edge-dns".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(route, UdpOutboundRoute::Dns);
    }

    #[test]
    fn resolve_udp_outbound_supports_gost_relay_without_tls_or_mux() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: gost-relay
    name: edge-gost
    server: 1.2.3.4
    port: 8443
    username: user
    password: pass
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-gost".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::GostRelay(UdpGostRelayRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 8443,
                username: "user".into(),
                password: "pass".into(),
                forward: false,
                mux: false,
                tls: mihomo_transport::TlsOptions::default(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_gost_relay_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: gost-relay
    name: edge-gost
    server: 1.2.3.4
    port: 8443
    username: user
    password: pass
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-gost".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::GostRelay(UdpGostRelayRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "1.2.3.4".into(),
                port: 8443,
                username: "user".into(),
                password: "pass".into(),
                forward: false,
                mux: false,
                tls: mihomo_transport::TlsOptions::default(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_gost_relay_with_mux() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: gost-relay
    name: edge-gost
    server: 1.2.3.4
    port: 8443
    mux: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-gost".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::GostRelay(UdpGostRelayRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 8443,
                username: String::new(),
                password: String::new(),
                forward: false,
                mux: true,
                tls: mihomo_transport::TlsOptions::default(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_gost_relay_with_mux_and_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: gost-relay
    name: edge-gost
    server: 1.2.3.4
    port: 8443
    mux: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-gost".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::GostRelay(UdpGostRelayRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "1.2.3.4".into(),
                port: 8443,
                username: String::new(),
                password: String::new(),
                forward: false,
                mux: true,
                tls: mihomo_transport::TlsOptions::default(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_shadowsocks_with_plugin_ignored() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: edge-ss
    server: 1.2.3.4
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: obfs
    plugin-opts:
      mode: http
      host: bing.com
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ss".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::ShadowSocks(UdpShadowSocksRoute {
                server: "1.2.3.4".into(),
                port: 8388,
                cipher: "chacha20-ietf-poly1305".into(),
                password: "secret".into(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_with_udp_enabled() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    udp: true
    sni: edge.example.com
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Trojan(UdpTrojanRoute {
                dialer_proxy: None,
                server: "trojan.example.com".into(),
                port: 443,
                password: "secret".into(),
                shadowsocks: mihomo_transport::TrojanShadowsocksOptions::default(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["trojan.example.com".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["trojan.example.com".into()],
                    path: Vec::new(),
                    headers: std::collections::BTreeMap::new(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "trojan.example.com".into(),
                    ..mihomo_transport::XHttpOptions::default()
                },
                alpn: vec!["h2".into(), "http/1.1".into()],
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "edge.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    udp: true
    sni: edge.example.com
    skip-cert-verify: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Trojan(UdpTrojanRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "trojan.example.com".into(),
                port: 443,
                password: "secret".into(),
                shadowsocks: mihomo_transport::TrojanShadowsocksOptions::default(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["trojan.example.com".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["trojan.example.com".into()],
                    path: Vec::new(),
                    headers: std::collections::BTreeMap::new(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "trojan.example.com".into(),
                    ..mihomo_transport::XHttpOptions::default()
                },
                alpn: vec!["h2".into(), "http/1.1".into()],
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "edge.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_trusttunnel_with_udp_enabled() {
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
    sni: edge.example.com
    skip-cert-verify: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trust".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::TrustTunnel(UdpTrustTunnelRoute {
                dialer_proxy: None,
                server: "trust.example.com".into(),
                port: 443,
                username: "alice".into(),
                password: "secret".into(),
                quic: false,
                alpn: vec!["h2".into()],
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "edge.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_trusttunnel_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: trusttunnel
    name: edge-trust
    server: trust.example.com
    port: 443
    username: alice
    password: secret
    udp: true
    sni: edge.example.com
    skip-cert-verify: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trust".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::TrustTunnel(UdpTrustTunnelRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "trust.example.com".into(),
                port: 443,
                username: "alice".into(),
                password: "secret".into(),
                quic: false,
                alpn: vec!["h2".into()],
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "edge.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_with_plan_keeps_outer_socks5_for_trusttunnel_quic_udp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: trusttunnel
    name: edge-trust
    server: trust.example.com
    port: 443
    username: alice
    password: secret
    udp: true
    quic: true
    tls: true
    sni: edge.example.com
    skip-cert-verify: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let (route, plan) = tunnel
            .resolve_udp_outbound_with_plan(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trust".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::TrustTunnel(UdpTrustTunnelRoute {
                server,
                port,
                quic,
                ..
            }) => {
                assert_eq!(server, "trust.example.com");
                assert_eq!(port, 443);
                assert!(quic);
            }
            other => panic!("expected trusttunnel udp route, got {other:?}"),
        }
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[0].spec {
            crate::ExecutionHopSpec::Socks5Connect(spec) => {
                assert_eq!(spec.server, "127.0.0.1");
                assert_eq!(spec.port, 1080);
                assert!(spec.udp);
            }
            other => panic!("expected outer socks5 hop, got {other:?}"),
        }
        match &plan.hops[1].spec {
            crate::ExecutionHopSpec::TrustTunnel(spec) => {
                assert!(spec.quic);
            }
            other => panic!("expected trusttunnel leaf hop, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_with_udp_enabled() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vless(UdpVlessRoute {
                dialer_proxy: None,
                server: "vless.example.com".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: String::new(),
                reality_public_key: String::new(),
                reality_short_id: String::new(),
                reality_support_x25519mlkem768: false,
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["vless.example.com".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["vless.example.com".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "vless.example.com".into(),
                    ..Default::default()
                },
                encryption: String::new(),
                packet_addr: false,
                xudp: false,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "vless.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    skip-cert-verify: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vless(UdpVlessRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "vless.example.com".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: String::new(),
                reality_public_key: String::new(),
                reality_short_id: String::new(),
                reality_support_x25519mlkem768: false,
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["vless.example.com".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["vless.example.com".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "vless.example.com".into(),
                    ..Default::default()
                },
                encryption: String::new(),
                packet_addr: false,
                xudp: false,
                tls: mihomo_transport::TlsOptions {
                    enabled: true,
                    sni: "vless.example.com".into(),
                    skip_cert_verify: true,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_packet_addr() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: vless.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    packet-addr: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vless(route) => assert!(route.packet_addr),
            other => panic!("expected vless packet-addr route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_tuic_with_udp_enabled() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: proxy-tuic
    server: tuic.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
    alpn: [h3]
rules:
  - MATCH,proxy-tuic
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "proxy-tuic".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Tuic(UdpTuicRoute {
                server,
                port,
                uuid,
                password,
                token,
                udp,
                alpn,
                ..
            }) => {
                assert_eq!(server, "tuic.example.com");
                assert_eq!(port, 443);
                assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(password, "secret");
                assert!(token.is_empty());
                assert!(udp);
                assert_eq!(alpn, vec!["h3".to_owned()]);
            }
            other => panic!("expected tuic udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_with_plan_keeps_outer_socks5_for_tuic_udp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: tuic
    name: proxy-tuic
    server: tuic.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
    alpn: [h3]
    dialer-proxy: outer-socks
rules:
  - MATCH,proxy-tuic
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let (route, plan) = tunnel
            .resolve_udp_outbound_with_plan(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "proxy-tuic".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Tuic(UdpTuicRoute { server, port, .. }) => {
                assert_eq!(server, "tuic.example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected tuic udp route, got {other:?}"),
        }
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[0].spec {
            crate::ExecutionHopSpec::Socks5Connect(spec) => {
                assert_eq!(spec.server, "127.0.0.1");
                assert_eq!(spec.port, 1080);
                assert!(spec.udp);
            }
            other => panic!("expected outer socks5 hop, got {other:?}"),
        }
        match &plan.hops[1].spec {
            crate::ExecutionHopSpec::Tuic(spec) => {
                assert_eq!(spec.server, "tuic.example.com");
                assert!(spec.udp);
            }
            other => panic!("expected tuic leaf hop, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_wireguard() {
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
rules:
  - MATCH,edge-wg
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-wg".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::WireGuard(UdpWireGuardRoute {
                ip,
                workers,
                peers,
                mtu,
                ..
            }) => {
                assert_eq!(ip, "10.0.0.2/32");
                assert_eq!(workers, 4);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].server, "1.2.3.4");
                assert_eq!(peers[0].port, 51820);
                assert_eq!(peers[0].allowed_ips, vec!["0.0.0.0/0"]);
                assert_eq!(peers[0].persistent_keepalive, 15);
                assert_eq!(mtu, 1380);
            }
            other => panic!("expected wireguard udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_wireguard_multi_peer() {
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
rules:
  - MATCH,edge-wg
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-wg".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::WireGuard(UdpWireGuardRoute { ip, peers, .. }) => {
                assert_eq!(ip, "10.0.0.2/32");
                assert_eq!(peers.len(), 2);
                assert_eq!(peers[0].server, "1.2.3.4");
                assert_eq!(peers[0].port, 51820);
                assert_eq!(peers[0].allowed_ips, vec!["0.0.0.0/0"]);
                assert_eq!(peers[1].server, "5.6.7.8");
                assert_eq!(peers[1].port, 51821);
                assert_eq!(peers[1].allowed_ips, vec!["10.0.0.0/8"]);
            }
            other => panic!("expected wireguard udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_rejects_wireguard_with_udp_disabled() {
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
    udp: false
    allowed-ips:
      - 0.0.0.0/0
rules:
  - MATCH,edge-wg
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-wg".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Unsupported(reason) => {
                assert!(reason.contains("wireguard"));
                assert!(reason.contains("does not enable udp"));
            }
            other => panic!("expected unsupported wireguard udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_openvpn() {
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
rules:
  - MATCH,edge-ovpn
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ovpn".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::OpenVpn(UdpOpenVpnRoute {
                server,
                port,
                proto,
                dev,
                cipher,
                auth,
                username,
                password,
                ..
            }) => {
                assert_eq!(server, "1.2.3.4");
                assert_eq!(port, 1194);
                assert_eq!(proto, "udp");
                assert_eq!(dev, "tun");
                assert_eq!(cipher, "AES-128-GCM");
                assert_eq!(auth, "SHA256");
                assert_eq!(username, "demo");
                assert_eq!(password, "secret");
            }
            other => panic!("expected openvpn udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_rejects_openvpn_with_udp_disabled() {
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
    udp: false
    ca: demo
    tls-crypt: demo
    username: demo
    password: secret
rules:
  - MATCH,edge-ovpn
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-ovpn".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Unsupported(reason) => {
                assert!(reason.contains("openvpn"));
                assert!(reason.contains("does not enable udp"));
            }
            other => panic!("expected unsupported openvpn udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_masque_h2_subset() {
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
rules:
  - MATCH,edge-masque
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-masque".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Masque(UdpMasqueRoute {
                server,
                port,
                ip,
                network,
                mtu,
                ..
            }) => {
                assert_eq!(server, "masque.example.com");
                assert_eq!(port, 443);
                assert_eq!(ip, "10.10.0.2/32");
                assert_eq!(network, "h2");
                assert_eq!(mtu, 1300);
            }
            other => panic!("expected masque udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_masque_h2_remote_dns_subset() {
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
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
rules:
  - MATCH,edge-masque
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-masque".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Masque(UdpMasqueRoute {
                remote_dns_resolve,
                dns,
                network,
                ..
            }) => {
                assert!(remote_dns_resolve);
                assert_eq!(network, "h2");
                assert_eq!(dns, vec!["udp://1.1.1.1".to_owned()]);
            }
            other => panic!("expected masque udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_with_plan_keeps_outer_hop_for_masque_h2() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: 8080
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    dialer-proxy: outer-http
rules:
  - MATCH,edge-masque
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let (route, plan) = tunnel
            .resolve_udp_outbound_with_plan(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-masque".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Masque(UdpMasqueRoute { server, port, .. }) => {
                assert_eq!(server, "masque.example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected masque udp route, got {other:?}"),
        }
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[0].spec {
            crate::ExecutionHopSpec::HttpConnect(spec) => {
                assert_eq!(spec.server, "127.0.0.1");
                assert_eq!(spec.port, 8080);
            }
            other => panic!("expected outer http hop, got {other:?}"),
        }
        match &plan.hops[1].spec {
            crate::ExecutionHopSpec::Masque(spec) => {
                assert_eq!(spec.server, "masque.example.com");
                assert_eq!(spec.network, "h2");
            }
            other => panic!("expected masque leaf hop, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_hy2() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: proxy-hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: edge.example.com
    skip-cert-verify: true
rules:
  - MATCH,proxy-hy2
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "proxy-hy2".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Hy2(UdpHy2Route {
                server,
                port,
                password,
                obfs,
                obfs_password,
                tls,
                ..
            }) => {
                assert_eq!(server, "hy2.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "secret");
                assert!(obfs.is_empty());
                assert!(obfs_password.is_empty());
                assert_eq!(tls.sni, "edge.example.com");
                assert!(tls.skip_cert_verify);
            }
            other => panic!("expected hy2 udp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_with_plan_keeps_outer_socks5_for_hysteria_udp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: hysteria
    name: proxy-hy
    server: hy.example.com
    port: 443
    auth-str: secret
    up: 10 Mbps
    down: 50 Mbps
    dialer-proxy: outer-socks
rules:
  - MATCH,proxy-hy
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let (route, plan) = tunnel
            .resolve_udp_outbound_with_plan(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "proxy-hy".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Hysteria(crate::UdpHysteriaRoute { server, port, .. }) => {
                assert_eq!(server, "hy.example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected hysteria udp route, got {other:?}"),
        }
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[0].spec {
            crate::ExecutionHopSpec::Socks5Connect(spec) => {
                assert_eq!(spec.server, "127.0.0.1");
                assert_eq!(spec.port, 1080);
                assert!(spec.udp);
            }
            other => panic!("expected outer socks5 hop, got {other:?}"),
        }
        match &plan.hops[1].spec {
            crate::ExecutionHopSpec::Hysteria(spec) => {
                assert_eq!(spec.server, "hy.example.com");
            }
            other => panic!("expected hysteria leaf hop, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_with_plan_keeps_outer_socks5_for_hy2_udp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: hysteria2
    name: proxy-hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: edge.example.com
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - MATCH,proxy-hy2
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let (route, plan) = tunnel
            .resolve_udp_outbound_with_plan(&Metadata {
                host: Some("target.example.com".into()),
                dst_port: Some(53),
                special_proxy: "proxy-hy2".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Hy2(UdpHy2Route { server, port, .. }) => {
                assert_eq!(server, "hy2.example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected hy2 udp route, got {other:?}"),
        }
        assert_eq!(plan.hops.len(), 2);
        match &plan.hops[0].spec {
            crate::ExecutionHopSpec::Socks5Connect(spec) => {
                assert_eq!(spec.server, "127.0.0.1");
                assert_eq!(spec.port, 1080);
                assert!(spec.udp);
            }
            other => panic!("expected outer socks5 hop, got {other:?}"),
        }
        match &plan.hops[1].spec {
            crate::ExecutionHopSpec::Hy2(spec) => {
                assert_eq!(spec.server, "hy2.example.com");
            }
            other => panic!("expected hy2 leaf hop, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_xudp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    xudp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vless(UdpVlessRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: String::new(),
                reality_public_key: String::new(),
                reality_short_id: String::new(),
                reality_support_x25519mlkem768: false,
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["1.2.3.4".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["1.2.3.4".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "1.2.3.4".into(),
                    ..Default::default()
                },
                encryption: String::new(),
                packet_addr: false,
                xudp: true,
                tls: mihomo_transport::TlsOptions::default(),
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_h2() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: h2
    h2-opts:
      host: [localhost]
      path: /vuh2
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vless(route) => {
                assert_eq!(route.network, "h2");
                assert_eq!(route.h2.host, vec!["localhost".to_owned()]);
                assert_eq!(route.h2.path, "/vuh2");
            }
            other => panic!("expected vless h2 route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_grpc() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    network: grpc
    grpc-opts:
      grpc-service-name: example
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vless(route) => {
                assert_eq!(route.network, "grpc");
                assert_eq!(route.grpc.service_name, "example");
            }
            other => panic!("expected vless grpc route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vless_xhttp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: edge-vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    servername: x.example.com
    network: xhttp
    xhttp-opts:
      path: /vx
      mode: stream-one
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vless".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vless(route) => {
                assert_eq!(route.network, "xhttp");
                assert_eq!(route.xhttp.host, "x.example.com");
                assert_eq!(route.xhttp.path, "/vx");
                assert_eq!(route.xhttp.mode, "stream-one");
            }
            other => panic!("expected vless xhttp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_with_udp_enabled() {
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
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vmess(UdpVmessRoute {
                dialer_proxy: None,
                server: "vmess.example.com".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 0,
                cipher: "none".into(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["vmess.example.com".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["vmess.example.com".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "vmess.example.com".into(),
                    ..Default::default()
                },
                packet_addr: false,
                xudp: false,
                global_padding: false,
                authenticated_length: false,
                tls: mihomo_transport::TlsOptions::default(),
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: vmess
    name: edge-vmess
    server: vmess.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vmess(UdpVmessRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "vmess.example.com".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 0,
                cipher: "none".into(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["vmess.example.com".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["vmess.example.com".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "vmess.example.com".into(),
                    ..Default::default()
                },
                packet_addr: false,
                xudp: false,
                global_padding: false,
                authenticated_length: false,
                tls: mihomo_transport::TlsOptions::default(),
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_h2() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: h2
    h2-opts:
      host: [localhost]
      path: /vmuh2
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vmess(route) => {
                assert_eq!(route.network, "h2");
                assert_eq!(route.h2.host, vec!["localhost".to_owned()]);
                assert_eq!(route.h2.path, "/vmuh2");
            }
            other => panic!("expected vmess h2 route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_grpc() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
    udp: true
    network: grpc
    grpc-opts:
      grpc-service-name: example
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vmess(route) => {
                assert_eq!(route.network, "grpc");
                assert_eq!(route.grpc.service_name, "example");
            }
            other => panic!("expected vmess grpc route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_xhttp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
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
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vmess(route) => {
                assert_eq!(route.network, "xhttp");
                assert_eq!(route.xhttp.host, "x.example.com");
                assert_eq!(route.xhttp.path, "/vmx");
                assert_eq!(route.xhttp.mode, "stream-one");
            }
            other => panic!("expected vmess xhttp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_grpc() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: trojan.example.com
    port: 443
    password: secret
    udp: true
    network: grpc
    skip-cert-verify: true
    grpc-opts:
      grpc-service-name: example
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Trojan(route) => {
                assert_eq!(route.network, "grpc");
                assert_eq!(route.grpc.service_name, "example");
            }
            other => panic!("expected trojan grpc route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_http() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: 1.2.3.4
    port: 443
    password: secret
    udp: true
    network: http
    skip-cert-verify: true
    http-opts:
      method: GET
      path: [/th]
      host: [localhost]
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Trojan(route) => {
                assert_eq!(route.network, "http");
                assert_eq!(route.http.method, "GET");
                assert_eq!(route.http.path, vec!["/th".to_owned()]);
                assert_eq!(route.http.host, vec!["localhost".to_owned()]);
            }
            other => panic!("expected trojan http route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_ws() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: 1.2.3.4
    port: 443
    password: secret
    udp: true
    network: ws
    skip-cert-verify: true
    ws-opts:
      path: /tws
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Trojan(route) => {
                assert_eq!(route.network, "ws");
                assert_eq!(route.websocket.path, "/tws");
            }
            other => panic!("expected trojan ws route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_h2() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: 1.2.3.4
    port: 443
    password: secret
    udp: true
    network: h2
    skip-cert-verify: true
    h2-opts:
      host: [localhost]
      path: /th2
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Trojan(route) => {
                assert_eq!(route.network, "h2");
                assert_eq!(route.h2.host, vec!["localhost".to_owned()]);
                assert_eq!(route.h2.path, "/th2");
            }
            other => panic!("expected trojan h2 route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_trojan_xhttp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: edge-trojan
    server: 1.2.3.4
    port: 443
    password: secret
    udp: true
    network: xhttp
    skip-cert-verify: true
    xhttp-opts:
      host: localhost
      path: /trx
      mode: stream-one
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-trojan".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Trojan(route) => {
                assert_eq!(route.network, "xhttp");
                assert_eq!(route.xhttp.host, "localhost");
                assert_eq!(route.xhttp.path, "/trx");
                assert_eq!(route.xhttp.mode, "stream-one");
            }
            other => panic!("expected trojan xhttp route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_with_authenticated_length_and_global_padding() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    udp: true
    global-padding: true
    authenticated-length: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vmess(UdpVmessRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 0,
                cipher: "aes-128-gcm".into(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["1.2.3.4".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["1.2.3.4".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "1.2.3.4".into(),
                    ..Default::default()
                },
                packet_addr: false,
                xudp: false,
                global_padding: true,
                authenticated_length: true,
                tls: mihomo_transport::TlsOptions::default(),
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_xudp() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    udp: true
    xudp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vmess(UdpVmessRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 0,
                cipher: "aes-128-gcm".into(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["1.2.3.4".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["1.2.3.4".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "1.2.3.4".into(),
                    ..Default::default()
                },
                packet_addr: false,
                xudp: true,
                global_padding: false,
                authenticated_length: false,
                tls: mihomo_transport::TlsOptions::default(),
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_with_legacy_alter_id() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 16
    cipher: none
    udp: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Vmess(UdpVmessRoute {
                dialer_proxy: None,
                server: "1.2.3.4".into(),
                port: 443,
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                alter_id: 16,
                cipher: "none".into(),
                network: String::new(),
                websocket: mihomo_transport::WebsocketOptions::default(),
                grpc: mihomo_transport::GrpcOptions::default(),
                h2: mihomo_transport::Http2Options {
                    host: vec!["1.2.3.4".into()],
                    path: String::new(),
                },
                http: mihomo_transport::HttpStreamOptions {
                    method: String::new(),
                    host: vec!["1.2.3.4".into()],
                    path: Vec::new(),
                    headers: Default::default(),
                },
                xhttp: mihomo_transport::XHttpOptions {
                    host: "1.2.3.4".into(),
                    ..Default::default()
                },
                packet_addr: false,
                xudp: false,
                global_padding: false,
                authenticated_length: false,
                tls: mihomo_transport::TlsOptions::default(),
                alpn: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_vmess_packet_addr() {
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
    packet-addr: true
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-vmess".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Vmess(route) => assert!(route.packet_addr),
            other => panic!("expected vmess packet-addr route, got {other:?}"),
        }
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku() {
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
    http-mask: false
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: false,
                http_mask_mode: "legacy".into(),
                http_mask_tls: false,
                http_mask_host: String::new(),
                path_root: String::new(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_with_dialer_proxy_chain() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    padding-max: 24
    http-mask: false
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: Some("outer-socks".into()),
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: false,
                http_mask_mode: "legacy".into(),
                http_mask_tls: false,
                http_mask_host: String::new(),
                path_root: String::new(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_packed_downlink() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: chacha20-poly1305
    table-type: up_ascii_down_entropy
    padding-min: 12
    padding-max: 24
    enable-pure-downlink: false
    http-mask: false
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "chacha20-poly1305".into(),
                table_type: "up_ascii_down_entropy".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: false,
                http_mask_enabled: false,
                http_mask_mode: "legacy".into(),
                http_mask_tls: false,
                http_mask_host: String::new(),
                path_root: String::new(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_poll_http_mask() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: true,
                http_mask_mode: "poll".into(),
                http_mask_tls: false,
                http_mask_host: String::new(),
                path_root: "mask".into(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_poll_http_mask_tls() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: true,
                http_mask_mode: "poll".into(),
                http_mask_tls: true,
                http_mask_host: "localhost:8443".into(),
                path_root: "mask".into(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_stream_http_mask_tls() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: true,
                http_mask_mode: "stream".into(),
                http_mask_tls: true,
                http_mask_host: "localhost:8443".into(),
                path_root: "mask".into(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_auto_http_mask() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: true,
                http_mask_mode: "auto".into(),
                http_mask_tls: false,
                http_mask_host: String::new(),
                path_root: "mask".into(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_auto_http_mask_tls() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: true,
                http_mask_mode: "auto".into(),
                http_mask_tls: true,
                http_mask_host: "localhost:8443".into(),
                path_root: "mask".into(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_nested_httpmask() {
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
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        assert_eq!(
            route,
            UdpOutboundRoute::Sudoku(UdpSudokuRoute {
                dialer_proxy: None,
                server: "sudoku.example.com".into(),
                port: 443,
                key: "secret-seed".into(),
                aead_method: "aes-128-gcm".into(),
                table_type: "prefer_ascii".into(),
                padding_min: 12,
                padding_max: 24,
                enable_pure_downlink: true,
                http_mask_enabled: true,
                http_mask_mode: "auto".into(),
                http_mask_tls: true,
                http_mask_host: "localhost:8443".into(),
                path_root: "mask".into(),
                custom_table: String::new(),
                custom_tables: Vec::new(),
            })
        );
    }

    #[test]
    fn resolve_udp_outbound_supports_sudoku_custom_table_rotation() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_entropy
    custom-tables:
      - xpxvvpvv
      - vxpvxvvp
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let route = tunnel
            .resolve_udp_outbound(&Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                special_proxy: "edge-sudoku".into(),
                ..Metadata::default()
            })
            .unwrap();
        match route {
            UdpOutboundRoute::Sudoku(route) => {
                assert_eq!(route.custom_table, "");
                assert_eq!(route.custom_tables, vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()]);
            }
            other => panic!("expected sudoku route, got {other:?}"),
        }
    }

    #[test]
    fn tunnel_traffic_snapshot_tracks_tcp_and_udp_bytes() {
        let document = parse_runtime_config_document("mode: direct").unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry)
            .with_tcp_strategy(TcpRelayStrategy::BufferedCopy);

        let inbound = SharedStreamHandle::new(b"ping".to_vec());
        let mut upstream = SharedStreamHandle::new(b"pong".to_vec()).stream();
        let mut context = mihomo_core::ConnectionContext::new(
            inbound.stream(),
            Metadata {
                host: Some("example.com".into()),
                dst_port: Some(443),
                ..Metadata::default()
            },
        );
        let stats = tunnel.relay_tcp_stream(&mut context, &mut upstream, None).unwrap();
        assert_eq!(stats.left_to_right, 4);
        assert_eq!(stats.right_to_left, 4);

        let sink = Arc::new(RecordingSink::default());
        let packet = Arc::new(TestPacket {
            payload: ByteWindow::freeze(b"udp".to_vec()),
            local_addr: "127.0.0.1:5301".parse().unwrap(),
            sink: Arc::clone(&sink),
        });
        let envelope = PacketEnvelope::new(
            packet,
            Metadata {
                host: Some("example.com".into()),
                dst_port: Some(53),
                dns_mode: DnsMode::Normal,
                ..Metadata::default()
            },
        );
        let mut session = FakeUdpSession::default();
        let remote = tunnel.send_udp_packet(&envelope, &mut session).unwrap();
        tunnel
            .write_back_udp(&envelope, ByteWindow::freeze(b"ok".to_vec()), remote)
            .unwrap();

        let traffic = tunnel.traffic_snapshot();
        assert_eq!(traffic.up_total, 7);
        assert_eq!(traffic.down_total, 6);
    }

    #[test]
    fn tunnel_handle_tcp_records_last_error() {
        let document = parse_runtime_config_document(
            r#"
mode: direct
proxies:
  - type: mieru
    name: bad
    server: bad.example.com
    port: 443
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let context = mihomo_core::ConnectionContext::new(
            SharedStreamHandle::new(Vec::new()).stream(),
            Metadata {
                host: Some("final.example.com".into()),
                dst_port: Some(443),
                special_proxy: "bad".into(),
                ..Metadata::default()
            },
        );

        tunnel.handle_tcp(context);
        let error = tunnel.last_error().unwrap();
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn tunnel_rule_mode_falls_back_to_compatible_target_name() {
        let document = parse_runtime_config_document("mode: rule").unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry);
        let selected = tunnel.selected_target(&Metadata::default());
        assert_eq!(selected, "COMPATIBLE");
    }

    #[test]
    fn tunnel_rule_mode_uses_compiled_rules_when_available() {
        let document = parse_runtime_config_document(
            r#"
mode: rule
proxies:
  - type: direct
    name: direct-a
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let rules = compile_rule_set(&[
            "DOMAIN-SUFFIX,example.com,direct-a".into(),
            "MATCH,COMPATIBLE".into(),
        ])
        .unwrap();
        let tunnel = RuntimeTunnel::new(document.mode.clone(), registry).with_rule_set(rules);
        let selected = tunnel.selected_target(&Metadata {
            host: Some("www.example.com".into()),
            ..Metadata::default()
        });
        assert_eq!(selected, "direct-a");
    }
}
