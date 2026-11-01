#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundKind {
    Socks,
    Http,
    TProxy,
    Redir,
    Mixed,
    Tunnel,
    Tun,
    ShadowSocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Hysteria2Realm,
    Tuic,
    AnyTls,
    Mieru,
    Sudoku,
    TrustTunnel,
}

pub const SUPPORTED_INBOUNDS: &[InboundKind] = &[
    InboundKind::Socks,
    InboundKind::Http,
    InboundKind::TProxy,
    InboundKind::Redir,
    InboundKind::Mixed,
    InboundKind::Tunnel,
    InboundKind::Tun,
    InboundKind::ShadowSocks,
    InboundKind::Vmess,
    InboundKind::Vless,
    InboundKind::Trojan,
    InboundKind::Hysteria2,
    InboundKind::Hysteria2Realm,
    InboundKind::Tuic,
    InboundKind::AnyTls,
    InboundKind::Mieru,
    InboundKind::Sudoku,
    InboundKind::TrustTunnel,
];

impl InboundKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Socks => "socks",
            Self::Http => "http",
            Self::TProxy => "tproxy",
            Self::Redir => "redir",
            Self::Mixed => "mixed",
            Self::Tunnel => "tunnel",
            Self::Tun => "tun",
            Self::ShadowSocks => "shadowsocks",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria2 => "hysteria2",
            Self::Hysteria2Realm => "hysteria2-realm",
            Self::Tuic => "tuic",
            Self::AnyTls => "anytls",
            Self::Mieru => "mieru",
            Self::Sudoku => "sudoku",
            Self::TrustTunnel => "trusttunnel",
        }
    }
}
