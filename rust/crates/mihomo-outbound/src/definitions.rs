use serde::{Deserialize, Serialize};

use crate::{
    kinds::OutboundKind,
    models::{
        NamedOutboundConfig, ProxyBaseConfig, ServerPortOutboundConfig, ShadowSocksOutboundConfig,
        WireGuardOutboundConfig,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum OutboundDefinition {
    #[serde(rename = "direct")]
    Direct(NamedOutboundConfig),
    #[serde(rename = "dns")]
    Dns(NamedOutboundConfig),
    #[serde(rename = "reject")]
    Reject(NamedOutboundConfig),
    #[serde(rename = "http")]
    Http(ServerPortOutboundConfig),
    #[serde(rename = "socks5")]
    Socks5(ServerPortOutboundConfig),
    #[serde(rename = "ss")]
    ShadowSocks(ShadowSocksOutboundConfig),
    #[serde(rename = "ssr")]
    ShadowSocksR(ServerPortOutboundConfig),
    #[serde(rename = "snell")]
    Snell(ServerPortOutboundConfig),
    #[serde(rename = "vmess")]
    Vmess(ServerPortOutboundConfig),
    #[serde(rename = "vless")]
    Vless(ServerPortOutboundConfig),
    #[serde(rename = "trojan")]
    Trojan(ServerPortOutboundConfig),
    #[serde(rename = "hysteria")]
    Hysteria(ServerPortOutboundConfig),
    #[serde(rename = "hysteria2")]
    Hysteria2(ServerPortOutboundConfig),
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardOutboundConfig),
    #[serde(rename = "tuic")]
    Tuic(ServerPortOutboundConfig),
    #[serde(rename = "gost-relay")]
    GostRelay(ServerPortOutboundConfig),
    #[serde(rename = "ssh")]
    Ssh(ServerPortOutboundConfig),
    #[serde(rename = "mieru")]
    Mieru(ServerPortOutboundConfig),
    #[serde(rename = "anytls")]
    AnyTls(ServerPortOutboundConfig),
    #[serde(rename = "sudoku")]
    Sudoku(ServerPortOutboundConfig),
    #[serde(rename = "masque")]
    Masque(ServerPortOutboundConfig),
    #[serde(rename = "trusttunnel")]
    TrustTunnel(ServerPortOutboundConfig),
    #[serde(rename = "openvpn")]
    OpenVpn(ServerPortOutboundConfig),
    #[serde(rename = "tailscale")]
    Tailscale(NamedOutboundConfig),
}

impl OutboundDefinition {
    pub fn kind(&self) -> OutboundKind {
        match self {
            Self::Direct(_) => OutboundKind::Direct,
            Self::Dns(_) => OutboundKind::Dns,
            Self::Reject(_) => OutboundKind::Reject,
            Self::Http(_) => OutboundKind::Http,
            Self::Socks5(_) => OutboundKind::Socks5,
            Self::ShadowSocks(_) => OutboundKind::ShadowSocks,
            Self::ShadowSocksR(_) => OutboundKind::ShadowSocksR,
            Self::Snell(_) => OutboundKind::Snell,
            Self::Vmess(_) => OutboundKind::Vmess,
            Self::Vless(_) => OutboundKind::Vless,
            Self::Trojan(_) => OutboundKind::Trojan,
            Self::Hysteria(_) => OutboundKind::Hysteria,
            Self::Hysteria2(_) => OutboundKind::Hysteria2,
            Self::WireGuard(_) => OutboundKind::WireGuard,
            Self::Tuic(_) => OutboundKind::Tuic,
            Self::GostRelay(_) => OutboundKind::GostRelay,
            Self::Ssh(_) => OutboundKind::Ssh,
            Self::Mieru(_) => OutboundKind::Mieru,
            Self::AnyTls(_) => OutboundKind::AnyTls,
            Self::Sudoku(_) => OutboundKind::Sudoku,
            Self::Masque(_) => OutboundKind::Masque,
            Self::TrustTunnel(_) => OutboundKind::TrustTunnel,
            Self::OpenVpn(_) => OutboundKind::OpenVpn,
            Self::Tailscale(_) => OutboundKind::Tailscale,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Direct(config) => &config.base.name,
            Self::Dns(config) => &config.base.name,
            Self::Reject(config) => &config.base.name,
            Self::Http(config) => &config.base.name,
            Self::Socks5(config) => &config.base.name,
            Self::ShadowSocks(config) => &config.base.name,
            Self::ShadowSocksR(config) => &config.base.name,
            Self::Snell(config) => &config.base.name,
            Self::Vmess(config) => &config.base.name,
            Self::Vless(config) => &config.base.name,
            Self::Trojan(config) => &config.base.name,
            Self::Hysteria(config) => &config.base.name,
            Self::Hysteria2(config) => &config.base.name,
            Self::WireGuard(config) => &config.base.name,
            Self::Tuic(config) => &config.base.name,
            Self::GostRelay(config) => &config.base.name,
            Self::Ssh(config) => &config.base.name,
            Self::Mieru(config) => &config.base.name,
            Self::AnyTls(config) => &config.base.name,
            Self::Sudoku(config) => &config.base.name,
            Self::Masque(config) => &config.base.name,
            Self::TrustTunnel(config) => &config.base.name,
            Self::OpenVpn(config) => &config.base.name,
            Self::Tailscale(config) => &config.base.name,
        }
    }

    pub fn dialer_proxy(&self) -> &str {
        match self {
            Self::Direct(config) => &config.base.dialer_proxy,
            Self::Dns(config) => &config.base.dialer_proxy,
            Self::Reject(config) => &config.base.dialer_proxy,
            Self::Http(config) => &config.base.dialer_proxy,
            Self::Socks5(config) => &config.base.dialer_proxy,
            Self::ShadowSocks(config) => &config.base.dialer_proxy,
            Self::ShadowSocksR(config) => &config.base.dialer_proxy,
            Self::Snell(config) => &config.base.dialer_proxy,
            Self::Vmess(config) => &config.base.dialer_proxy,
            Self::Vless(config) => &config.base.dialer_proxy,
            Self::Trojan(config) => &config.base.dialer_proxy,
            Self::Hysteria(config) => &config.base.dialer_proxy,
            Self::Hysteria2(config) => &config.base.dialer_proxy,
            Self::WireGuard(config) => &config.base.dialer_proxy,
            Self::Tuic(config) => &config.base.dialer_proxy,
            Self::GostRelay(config) => &config.base.dialer_proxy,
            Self::Ssh(config) => &config.base.dialer_proxy,
            Self::Mieru(config) => &config.base.dialer_proxy,
            Self::AnyTls(config) => &config.base.dialer_proxy,
            Self::Sudoku(config) => &config.base.dialer_proxy,
            Self::Masque(config) => &config.base.dialer_proxy,
            Self::TrustTunnel(config) => &config.base.dialer_proxy,
            Self::OpenVpn(config) => &config.base.dialer_proxy,
            Self::Tailscale(config) => &config.base.dialer_proxy,
        }
    }

    pub fn base(&self) -> &ProxyBaseConfig {
        match self {
            Self::Direct(config) => &config.base,
            Self::Dns(config) => &config.base,
            Self::Reject(config) => &config.base,
            Self::Http(config) => &config.base,
            Self::Socks5(config) => &config.base,
            Self::ShadowSocks(config) => &config.base,
            Self::ShadowSocksR(config) => &config.base,
            Self::Snell(config) => &config.base,
            Self::Vmess(config) => &config.base,
            Self::Vless(config) => &config.base,
            Self::Trojan(config) => &config.base,
            Self::Hysteria(config) => &config.base,
            Self::Hysteria2(config) => &config.base,
            Self::WireGuard(config) => &config.base,
            Self::Tuic(config) => &config.base,
            Self::GostRelay(config) => &config.base,
            Self::Ssh(config) => &config.base,
            Self::Mieru(config) => &config.base,
            Self::AnyTls(config) => &config.base,
            Self::Sudoku(config) => &config.base,
            Self::Masque(config) => &config.base,
            Self::TrustTunnel(config) => &config.base,
            Self::OpenVpn(config) => &config.base,
            Self::Tailscale(config) => &config.base,
        }
    }

    pub fn base_mut(&mut self) -> &mut ProxyBaseConfig {
        match self {
            Self::Direct(config) => &mut config.base,
            Self::Dns(config) => &mut config.base,
            Self::Reject(config) => &mut config.base,
            Self::Http(config) => &mut config.base,
            Self::Socks5(config) => &mut config.base,
            Self::ShadowSocks(config) => &mut config.base,
            Self::ShadowSocksR(config) => &mut config.base,
            Self::Snell(config) => &mut config.base,
            Self::Vmess(config) => &mut config.base,
            Self::Vless(config) => &mut config.base,
            Self::Trojan(config) => &mut config.base,
            Self::Hysteria(config) => &mut config.base,
            Self::Hysteria2(config) => &mut config.base,
            Self::WireGuard(config) => &mut config.base,
            Self::Tuic(config) => &mut config.base,
            Self::GostRelay(config) => &mut config.base,
            Self::Ssh(config) => &mut config.base,
            Self::Mieru(config) => &mut config.base,
            Self::AnyTls(config) => &mut config.base,
            Self::Sudoku(config) => &mut config.base,
            Self::Masque(config) => &mut config.base,
            Self::TrustTunnel(config) => &mut config.base,
            Self::OpenVpn(config) => &mut config.base,
            Self::Tailscale(config) => &mut config.base,
        }
    }

    pub fn remote_endpoint(&self) -> Option<(&str, u16)> {
        match self {
            Self::Http(config) => Some((&config.server, config.port)),
            Self::Socks5(config) => Some((&config.server, config.port)),
            Self::ShadowSocks(config) => Some((&config.server, config.port)),
            Self::ShadowSocksR(config) => Some((&config.server, config.port)),
            Self::Snell(config) => Some((&config.server, config.port)),
            Self::Vmess(config) => Some((&config.server, config.port)),
            Self::Vless(config) => Some((&config.server, config.port)),
            Self::Trojan(config) => Some((&config.server, config.port)),
            Self::Hysteria(config) => Some((&config.server, config.port)),
            Self::Hysteria2(config) => Some((&config.server, config.port)),
            Self::WireGuard(config) => Some((&config.server, config.port)),
            Self::Tuic(config) => Some((&config.server, config.port)),
            Self::GostRelay(config) => Some((&config.server, config.port)),
            Self::Ssh(config) => Some((&config.server, config.port)),
            Self::Mieru(config) => Some((&config.server, config.port)),
            Self::AnyTls(config) => Some((&config.server, config.port)),
            Self::Sudoku(config) => Some((&config.server, config.port)),
            Self::Masque(config) => Some((&config.server, config.port)),
            Self::TrustTunnel(config) => Some((&config.server, config.port)),
            Self::OpenVpn(config) => Some((&config.server, config.port)),
            Self::Direct(_) | Self::Dns(_) | Self::Reject(_) | Self::Tailscale(_) => None,
        }
    }

    pub fn set_name(&mut self, name: String) {
        self.base_mut().name = name;
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPayloadDocument {
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<OutboundDefinition>,
}
