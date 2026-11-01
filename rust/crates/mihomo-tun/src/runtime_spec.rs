use std::net::{IpAddr, SocketAddr};

use mihomo_core::{Metadata, NetworkKind, SessionKind};
use mihomo_inbound::{TunInboundConfig, TunStack};

use crate::filters::{allows_value, dns_hijack_matches, uid_in_range};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunUdpRuntimeMode {
    DirectRelay,
    MixedLikeRelay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunRuntimeSpec {
    pub name: String,
    pub config: TunInboundConfig,
}

impl TunRuntimeSpec {
    pub fn new(name: impl Into<String>, config: TunInboundConfig) -> Self {
        Self {
            name: name.into(),
            config,
        }
    }

    pub fn stack(&self) -> TunStack {
        self.config.stack.clone()
    }

    pub fn uses_mixed_tun_stack(&self) -> bool {
        matches!(self.config.stack, TunStack::Mixed)
    }

    pub fn uses_system_or_mixed_tun_stack(&self) -> bool {
        matches!(self.config.stack, TunStack::System | TunStack::Mixed)
    }

    pub fn supports_mixed_runtime_path(&self) -> bool {
        cfg!(any(target_os = "linux", target_os = "android"))
            && self.uses_mixed_tun_stack()
            && self.config.auto_route
            && self.config.auto_redirect
    }

    pub fn udp_runtime_mode(&self) -> TunUdpRuntimeMode {
        if self.supports_mixed_runtime_path() {
            TunUdpRuntimeMode::MixedLikeRelay
        } else {
            TunUdpRuntimeMode::DirectRelay
        }
    }

    pub fn uses_source_reuse_udp_runtime_path(&self) -> bool {
        self.config.endpoint_independent_nat
            || matches!(self.udp_runtime_mode(), TunUdpRuntimeMode::MixedLikeRelay)
    }

    pub fn supports_transparent_tcp_runtime_path(&self) -> bool {
        cfg!(any(target_os = "linux", target_os = "android"))
            && self.uses_system_or_mixed_tun_stack()
            && self.config.auto_route
            && self.config.auto_redirect
            && self.config.loopback_address.is_empty()
    }

    pub fn should_hijack_dns(&self, destination: SocketAddr) -> bool {
        self.config
            .dns_hijack
            .iter()
            .any(|entry| dns_hijack_matches(entry, destination))
    }

    pub fn allows_interface(&self, name: &str) -> bool {
        allows_value(&self.config.include_interface, &self.config.exclude_interface, name)
    }

    pub fn allows_package(&self, package: &str) -> bool {
        allows_value(&self.config.include_package, &self.config.exclude_package, package)
    }

    pub fn allows_uid(&self, uid: u32) -> bool {
        let include_matches = self.config.include_uid.contains(&uid)
            || self
                .config
                .include_uid_range
                .iter()
                .any(|range| uid_in_range(uid, range));
        let exclude_matches = self.config.exclude_uid.contains(&uid)
            || self
                .config
                .exclude_uid_range
                .iter()
                .any(|range| uid_in_range(uid, range));

        if !self.config.include_uid.is_empty() || !self.config.include_uid_range.is_empty() {
            include_matches && !exclude_matches
        } else {
            !exclude_matches
        }
    }

    pub fn loopback_redirect_address(&self, destination: IpAddr) -> Option<IpAddr> {
        self.config
            .loopback_address
            .iter()
            .filter_map(|value| value.trim().parse::<IpAddr>().ok())
            .find(|candidate| *candidate == destination)
    }

    pub fn prepare_tcp_metadata(
        &self,
        source: Option<SocketAddr>,
        destination: SocketAddr,
    ) -> Metadata {
        self.prepare_metadata(NetworkKind::Tcp, source, destination)
    }

    pub fn prepare_udp_metadata(
        &self,
        source: Option<SocketAddr>,
        destination: SocketAddr,
    ) -> Metadata {
        self.prepare_metadata(NetworkKind::Udp, source, destination)
    }

    fn prepare_metadata(
        &self,
        network: NetworkKind,
        source: Option<SocketAddr>,
        destination: SocketAddr,
    ) -> Metadata {
        let mut metadata = Metadata {
            network,
            kind: SessionKind::Tun,
            inbound_name: self.name.clone(),
            dst_ip: Some(destination.ip()),
            dst_port: Some(destination.port()),
            special_proxy: self.config.base.special_proxy.clone(),
            special_rules: self.config.base.special_rules.clone(),
            ..Metadata::default()
        };
        if let Some(source) = source {
            metadata.src_ip = Some(source.ip());
            metadata.src_port = Some(source.port());
        }
        metadata
    }
}
