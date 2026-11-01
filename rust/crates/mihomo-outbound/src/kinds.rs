#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundKind {
    Direct,
    Reject,
    Dns,
    Http,
    Socks5,
    ShadowSocks,
    ShadowSocksR,
    Snell,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Hysteria2,
    WireGuard,
    Tuic,
    GostRelay,
    Ssh,
    Mieru,
    AnyTls,
    Sudoku,
    Masque,
    TrustTunnel,
    OpenVpn,
    Tailscale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundGroupKind {
    Selector,
    UrlTest,
    Fallback,
    LoadBalance,
    Smart,
}

pub const SUPPORTED_OUTBOUNDS: &[OutboundKind] = &[
    OutboundKind::Direct,
    OutboundKind::Reject,
    OutboundKind::Dns,
    OutboundKind::Http,
    OutboundKind::Socks5,
    OutboundKind::ShadowSocks,
    OutboundKind::ShadowSocksR,
    OutboundKind::Snell,
    OutboundKind::Vmess,
    OutboundKind::Vless,
    OutboundKind::Trojan,
    OutboundKind::Hysteria,
    OutboundKind::Hysteria2,
    OutboundKind::WireGuard,
    OutboundKind::Tuic,
    OutboundKind::GostRelay,
    OutboundKind::Ssh,
    OutboundKind::Mieru,
    OutboundKind::AnyTls,
    OutboundKind::Sudoku,
    OutboundKind::Masque,
    OutboundKind::TrustTunnel,
    OutboundKind::OpenVpn,
    OutboundKind::Tailscale,
];

pub const SUPPORTED_OUTBOUND_GROUPS: &[OutboundGroupKind] = &[
    OutboundGroupKind::Selector,
    OutboundGroupKind::UrlTest,
    OutboundGroupKind::Fallback,
    OutboundGroupKind::LoadBalance,
    OutboundGroupKind::Smart,
];

impl OutboundKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reject => "reject",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::ShadowSocks => "ss",
            Self::ShadowSocksR => "ssr",
            Self::Snell => "snell",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria => "hysteria",
            Self::Hysteria2 => "hysteria2",
            Self::WireGuard => "wireguard",
            Self::Tuic => "tuic",
            Self::GostRelay => "gost-relay",
            Self::Ssh => "ssh",
            Self::Mieru => "mieru",
            Self::AnyTls => "anytls",
            Self::Sudoku => "sudoku",
            Self::Masque => "masque",
            Self::TrustTunnel => "trusttunnel",
            Self::OpenVpn => "openvpn",
            Self::Tailscale => "tailscale",
        }
    }
}

impl OutboundGroupKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Selector => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
            Self::Smart => "smart",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProviderVehicleType {
    File,
    Http,
    Inline,
}

impl ProxyProviderVehicleType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Http => "http",
            Self::Inline => "inline",
        }
    }
}
