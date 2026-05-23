mod bootstrap;
mod execution;
mod group;
mod inbound_surface;
mod listener_runtime;
mod registry;
mod resolver;
mod topology;
mod tcp;
mod tun_surface;
mod tunnel_runtime;
mod udp;

pub use bootstrap::{
    bootstrap_from_boot_options, bootstrap_from_boot_options_with_stdin, bootstrap_from_yaml,
    load_provider_content_sources_from_home, BootstrapError, BootstrapState,
};
pub use execution::{
    build_execution_plan, build_transport_plan, build_transport_plan_from_execution_plan,
    connect_target, connect_target_with_dialer, materialize_transport_plan, run_transport_plan,
    truncate_execution_plan, ExecutionError, ExecutionHop, ExecutionHopSpec, ExecutionPlan,
};
pub use group::{build_runtime_groups, LoadBalanceStrategy, ProxyCandidate, RuntimeGroup};
pub use inbound_surface::{build_effective_listeners, EffectiveListener, ListenerOrigin};
pub use listener_runtime::{
    build_http_listener_specs, build_mixed_listener_specs, build_redir_listener_specs,
    build_socks_listener_specs, build_tproxy_listener_specs, build_tunnel_listener_specs,
    dispatch_http_proxy_tcp_stream, dispatch_http_proxy_tcp_stream_with_dialer,
    dispatch_mixed_tcp_stream, dispatch_mixed_tcp_stream_with_dialer,
    dispatch_prepared_socks5_tcp_context, dispatch_prepared_socks5_tcp_context_with_dialer,
    dispatch_redir_tcp_stream, dispatch_redir_tcp_stream_with_dialer,
    dispatch_socks5_tcp_stream, dispatch_socks5_tcp_stream_with_dialer,
    dispatch_tproxy_tcp_stream, dispatch_tproxy_tcp_stream_with_dialer,
    dispatch_tunnel_tcp_stream, dispatch_tunnel_tcp_stream_with_dialer,
    prepare_http_proxy_tcp_context, prepare_redir_tcp_context, prepare_socks5_dispatch,
    prepare_socks5_tcp_context, prepare_socks5_udp_associate, prepare_tproxy_tcp_context,
    prepare_tunnel_tcp_context, write_socks5_udp_associate_reply, HttpListenerRuntimeSpec,
    HttpProxyMode, ListenerRuntimeError, MixedListenerRuntimeSpec, PreparedHttpProxyContext,
    PreparedSocks5Dispatch, PreparedSocks5UdpAssociate, RedirListenerRuntimeSpec,
    SocksListenerRuntimeSpec, TProxyListenerRuntimeSpec, TunnelListenerRuntimeSpec,
};
pub use registry::{
    build_runtime_registry, build_runtime_registry_with_sources, ProviderContentSources,
    ProviderHealthCheckRuntime, ProviderMember, ProviderRuntime, ProxyRegistration, ProxySource,
    RegistryError, RuntimeGroupView, RuntimeRegistry,
};
pub use resolver::{resolve_proxy_path, CandidateState, ResolveError, ResolvedProxyPath};
pub use topology::{assemble_proxy_topology, AssembledProxyTopology, ResolvedGroup, TopologyError};
pub use tcp::{
    forward_tcp_context, forward_tcp_context_with_dialer, forward_tcp_context_with_system_dialer,
    relay_bidirectional, TcpForwardError, TcpRelayStats, TcpRelayStrategy,
};
pub use tun_surface::{
    build_tun_runtime_specs, dispatch_tun_tcp_stream, dispatch_tun_tcp_stream_with_dialer,
    dispatch_tun_udp_packet, prepare_tun_tcp_context, prepare_tun_udp_metadata,
    prepare_tun_udp_packet, PreparedTunUdpPacket,
};
pub use tunnel_runtime::{
    ActiveConnectionSnapshot, RuntimeControlError, RuntimeTunnel, TrafficSnapshot,
    UdpAnyTlsRoute, UdpGostRelayRoute, UdpOutboundRoute, UdpShadowSocksRoute, UdpSnellRoute,
    UdpSocks5Route, UdpSsrRoute, UdpSudokuRoute, UdpTrojanRoute, UdpTrustTunnelRoute, UdpVlessRoute,
    UdpVmessRoute,
};
pub use udp::{NatMappings, QueuedUdpRelay};

use mihomo_config::BootOptions;
use mihomo_core::{RewriteStage, SubsystemManifest, GLOBAL_INVARIANTS};
use mihomo_platform::{current_capabilities, TargetProfile, SUPPORTED_TARGETS};

pub struct RuntimePlan {
    pub command: &'static str,
    pub current_family: &'static str,
    pub invariant_count: usize,
    pub subsystem_count: usize,
    pub openwrt_friendly_targets: usize,
}

pub fn runtime_subsystems() -> Vec<&'static SubsystemManifest> {
    static API_MANIFEST: SubsystemManifest = SubsystemManifest {
        crate_name: "mihomo-api",
        go_areas: &["hub/route"],
        contracts: &["external controller", "external UI", "API-facing runtime state"],
        stage: RewriteStage::Verified,
    };
    vec![
        &API_MANIFEST,
        mihomo_dns::manifest(),
        mihomo_inbound::manifest(),
        mihomo_outbound::manifest(),
        mihomo_rules::manifest(),
        mihomo_transport::manifest(),
        mihomo_tun::manifest(),
    ]
}

pub fn supported_targets() -> &'static [TargetProfile] {
    SUPPORTED_TARGETS
}

pub fn build_runtime_plan(options: &BootOptions) -> RuntimePlan {
    let caps = current_capabilities();
    RuntimePlan {
        command: options.command.name(),
        current_family: caps.family,
        invariant_count: GLOBAL_INVARIANTS.len(),
        subsystem_count: runtime_subsystems().len(),
        openwrt_friendly_targets: supported_targets()
            .iter()
            .filter(|target| target.openwrt_friendly)
            .count(),
    }
}

impl RuntimePlan {
    pub fn render_human_summary(&self) -> String {
        format!(
            "command={} platform={} invariants={} subsystems={} openwrt_profiles={}",
            self.command,
            self.current_family,
            self.invariant_count,
            self.subsystem_count,
            self.openwrt_friendly_targets
        )
    }
}

#[cfg(test)]
mod tests {
    use mihomo_config::BootOptions;

    use super::build_runtime_plan;

    #[test]
    fn runtime_plan_covers_embedded_targets() {
        let plan = build_runtime_plan(&BootOptions::default());
        assert!(plan.openwrt_friendly_targets >= 4);
        assert!(plan.subsystem_count >= 7);
    }
}
