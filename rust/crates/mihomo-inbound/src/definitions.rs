use serde::{Deserialize, Serialize};

use crate::kinds::InboundKind;
use crate::models::{
    BaseInboundConfig, GenericInboundConfig, HttpInboundConfig, RedirInboundConfig,
    ShadowSocksInboundConfig, TlsInboundConfig, TProxyInboundConfig, TunnelInboundConfig,
    TunInboundConfig,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum InboundDefinition {
    #[serde(rename = "socks")]
    Socks(TlsInboundConfig),
    #[serde(rename = "http")]
    Http(HttpInboundConfig),
    #[serde(rename = "tproxy")]
    TProxy(TProxyInboundConfig),
    #[serde(rename = "redir")]
    Redir(RedirInboundConfig),
    #[serde(rename = "mixed")]
    Mixed(TlsInboundConfig),
    #[serde(rename = "tunnel")]
    Tunnel(TunnelInboundConfig),
    #[serde(rename = "tun")]
    Tun(TunInboundConfig),
    #[serde(rename = "shadowsocks")]
    ShadowSocks(ShadowSocksInboundConfig),
    #[serde(rename = "vmess")]
    Vmess(GenericInboundConfig),
    #[serde(rename = "vless")]
    Vless(GenericInboundConfig),
    #[serde(rename = "trojan")]
    Trojan(GenericInboundConfig),
    #[serde(rename = "hysteria2")]
    Hysteria2(GenericInboundConfig),
    #[serde(rename = "hysteria2-realm")]
    Hysteria2Realm(GenericInboundConfig),
    #[serde(rename = "tuic")]
    Tuic(GenericInboundConfig),
    #[serde(rename = "anytls")]
    AnyTls(GenericInboundConfig),
    #[serde(rename = "mieru")]
    Mieru(GenericInboundConfig),
    #[serde(rename = "sudoku")]
    Sudoku(GenericInboundConfig),
    #[serde(rename = "trusttunnel")]
    TrustTunnel(GenericInboundConfig),
}

impl InboundDefinition {
    pub fn kind(&self) -> InboundKind {
        match self {
            Self::Socks(_) => InboundKind::Socks,
            Self::Http(_) => InboundKind::Http,
            Self::TProxy(_) => InboundKind::TProxy,
            Self::Redir(_) => InboundKind::Redir,
            Self::Mixed(_) => InboundKind::Mixed,
            Self::Tunnel(_) => InboundKind::Tunnel,
            Self::Tun(_) => InboundKind::Tun,
            Self::ShadowSocks(_) => InboundKind::ShadowSocks,
            Self::Vmess(_) => InboundKind::Vmess,
            Self::Vless(_) => InboundKind::Vless,
            Self::Trojan(_) => InboundKind::Trojan,
            Self::Hysteria2(_) => InboundKind::Hysteria2,
            Self::Hysteria2Realm(_) => InboundKind::Hysteria2Realm,
            Self::Tuic(_) => InboundKind::Tuic,
            Self::AnyTls(_) => InboundKind::AnyTls,
            Self::Mieru(_) => InboundKind::Mieru,
            Self::Sudoku(_) => InboundKind::Sudoku,
            Self::TrustTunnel(_) => InboundKind::TrustTunnel,
        }
    }

    pub fn base(&self) -> &BaseInboundConfig {
        match self {
            Self::Socks(config) => &config.base,
            Self::Http(config) => &config.base,
            Self::TProxy(config) => &config.base,
            Self::Redir(config) => &config.base,
            Self::Mixed(config) => &config.base,
            Self::Tunnel(config) => &config.base,
            Self::Tun(config) => &config.base,
            Self::ShadowSocks(config) => &config.base,
            Self::Vmess(config) => &config.base,
            Self::Vless(config) => &config.base,
            Self::Trojan(config) => &config.base,
            Self::Hysteria2(config) => &config.base,
            Self::Hysteria2Realm(config) => &config.base,
            Self::Tuic(config) => &config.base,
            Self::AnyTls(config) => &config.base,
            Self::Mieru(config) => &config.base,
            Self::Sudoku(config) => &config.base,
            Self::TrustTunnel(config) => &config.base,
        }
    }

    pub fn raw_addresses(&self) -> Vec<String> {
        self.base().raw_addresses()
    }
}
