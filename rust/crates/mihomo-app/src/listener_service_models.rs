use mihomo_inbound::{HttpInboundConfig, TlsInboundConfig, TunnelInboundConfig};

use super::listener_service_configs::{
    AnyTlsListenerConfig, ShadowSocksListenerConfig, SudokuInboundConfig,
    TrustTunnelListenerConfig, TrojanListenerConfig, VlessInboundConfig, VmessInboundConfig,
};
use super::hy2_realm_inbound;

#[derive(Clone, Debug)]
pub(crate) struct ListenerAuthUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedUdpListenerConfig {
    pub name: String,
    pub address: String,
    pub handler: ManagedUdpListenerHandler,
}

impl ManagedUdpListenerConfig {
    pub const fn kind_name(&self) -> &'static str {
        self.handler.kind_name()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ManagedUdpListenerHandler {
    Tunnel(TunnelInboundConfig),
    ShadowSocks(ShadowSocksListenerConfig),
    Redir(mihomo_inbound::RedirInboundConfig),
    TProxy(mihomo_inbound::TProxyInboundConfig),
}

impl ManagedUdpListenerHandler {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Tunnel(_) => "tunnel/udp",
            Self::ShadowSocks(_) => "shadowsocks/udp",
            Self::Redir(_) => "redir/udp",
            Self::TProxy(_) => "tproxy/udp",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedQuicListenerConfig {
    pub name: String,
    pub address: String,
    pub handler: ManagedQuicListenerHandler,
}

impl ManagedQuicListenerConfig {
    pub const fn kind_name(&self) -> &'static str {
        self.handler.kind_name()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ManagedQuicListenerHandler {
    Tuic(super::tuic_inbound::TuicListenerConfig),
    Hy2(super::hy2_inbound::Hy2ListenerConfig),
}

impl ManagedQuicListenerHandler {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Tuic(_) => "tuic",
            Self::Hy2(_) => "hysteria2",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedTcpListenerConfig {
    pub name: String,
    pub address: String,
    pub handler: ManagedTcpListenerHandler,
}

#[derive(Clone, Debug)]
pub(crate) enum ManagedTcpListenerHandler {
    Http(HttpInboundConfig),
    Socks(TlsInboundConfig),
    Mixed(TlsInboundConfig),
    Tunnel(TunnelInboundConfig),
    Redir(mihomo_inbound::RedirInboundConfig),
    TProxy(mihomo_inbound::TProxyInboundConfig),
    ShadowSocks(ShadowSocksListenerConfig),
    Trojan(TrojanListenerConfig),
    AnyTls(AnyTlsListenerConfig),
    Hy2Realm(
        hy2_realm_inbound::Hy2RealmListenerConfig,
        hy2_realm_inbound::Hy2RealmServer,
    ),
    TrustTunnel(TrustTunnelListenerConfig),
    Sudoku(SudokuInboundConfig),
    Vless(VlessInboundConfig),
    Vmess(VmessInboundConfig),
}

impl ManagedTcpListenerHandler {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Socks(_) => "socks",
            Self::Mixed(_) => "mixed",
            Self::Tunnel(_) => "tunnel",
            Self::Redir(_) => "redir",
            Self::TProxy(_) => "tproxy",
            Self::ShadowSocks(_) => "shadowsocks",
            Self::Trojan(_) => "trojan",
            Self::AnyTls(_) => "anytls",
            Self::Hy2Realm(_, _) => "hysteria2-realm",
            Self::TrustTunnel(_) => "trusttunnel",
            Self::Sudoku(_) => "sudoku",
            Self::Vless(_) => "vless",
            Self::Vmess(_) => "vmess",
        }
    }
}
