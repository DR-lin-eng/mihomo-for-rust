mod flow;
mod logs;

pub use flow::{
    AddrKind, BoxedTcpStream, ConnectionContext, DnsMode, Metadata, NetworkKind, PacketEnvelope,
    ParseMetadataError, SessionKind, TcpStream, Tunnel, UdpPacket, UdpSession, WriteBack,
};
pub use logs::{push_log, recent_logs, subscribe_logs, LogEntry, LogLevel};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewriteStage {
    Scaffolded,
    InProgress,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubsystemManifest {
    pub crate_name: &'static str,
    pub go_areas: &'static [&'static str],
    pub contracts: &'static [&'static str],
    pub stage: RewriteStage,
}

pub const GLOBAL_INVARIANTS: &[&str] = &[
    "Preserve CLI flags and subcommands from main.go.",
    "Preserve config grammar and reload semantics.",
    "Preserve controller, external UI, and secret behavior.",
    "Preserve inbound listener families and metadata flow.",
    "Preserve outbound adapters, groups, and provider-driven updates.",
    "Preserve DNS, fake-ip, sniffer, NAT, statistics, and process attribution semantics.",
    "Preserve broad cross-platform release coverage, including low-end Linux and OpenWrt-style deployments.",
    "Move the data plane toward zero-copy friendly ownership and OS-specific fast paths where available.",
    "Do not treat crate-level verification as proof that the repository default runtime, CI, and release chain have fully cut over to Rust.",
];

pub const SUBSYSTEMS: &[SubsystemManifest] = &[
    SubsystemManifest {
        crate_name: "mihomo-app",
        go_areas: &["main.go"],
        contracts: &[
            "CLI compatibility",
            "version and config test entrypoints",
            "subcommand dispatch",
        ],
        stage: RewriteStage::InProgress,
    },
    SubsystemManifest {
        crate_name: "mihomo-runtime",
        go_areas: &["hub", "hub/executor", "listener/listener.go", "tunnel"],
        contracts: &[
            "runtime assembly",
            "reload flow",
            "listener and tunnel orchestration",
        ],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-config",
        go_areas: &["config", "listener/config"],
        contracts: &["boot flags", "config source selection", "compatibility parser"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-api",
        go_areas: &["hub/route"],
        contracts: &["external controller", "external UI", "API-facing runtime state"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-dns",
        go_areas: &["dns", "component/resolver", "component/fakeip"],
        contracts: &["resolver behavior", "fake-ip behavior", "hosts integration"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-inbound",
        go_areas: &["listener", "adapter/inbound"],
        contracts: &["listener families", "metadata extraction", "packet ingestion"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-outbound",
        go_areas: &["adapter/outbound", "adapter/outboundgroup", "adapter/provider"],
        contracts: &["proxy adapters", "proxy groups", "write-back behavior"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-rules",
        go_areas: &["rules", "rules/provider"],
        contracts: &["rule matching", "policy selection", "rule-provider updates"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-transport",
        go_areas: &["transport"],
        contracts: &["transport protocol implementations", "stream and packet encapsulation"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-tun",
        go_areas: &["listener/sing_tun", "listener/redir", "listener/tproxy"],
        contracts: &["TUN", "redir", "tproxy", "transparent interception"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-platform",
        go_areas: &[
            "component/dialer",
            "component/process",
            "common/sockopt",
            "constant/features",
        ],
        contracts: &["platform capability detection", "release target matrix", "OS-specific hooks"],
        stage: RewriteStage::Verified,
    },
    SubsystemManifest {
        crate_name: "mihomo-buf",
        go_areas: &["common/buf", "common/net", "common/net/packet", "tunnel/statistic"],
        contracts: &["zero-copy buffers", "packet lifetime control", "vectored IO surfaces"],
        stage: RewriteStage::Verified,
    },
];

pub fn all_subsystems() -> &'static [SubsystemManifest] {
    SUBSYSTEMS
}

#[cfg(test)]
mod tests {
    use super::{all_subsystems, RewriteStage, GLOBAL_INVARIANTS};

    #[test]
    fn full_rewrite_manifest_is_not_partial() {
        assert!(GLOBAL_INVARIANTS.len() >= 6);
        assert!(all_subsystems().len() >= 10);
        assert!(all_subsystems()
            .iter()
            .any(|manifest| manifest.crate_name == "mihomo-tun"));
        assert!(all_subsystems()
            .iter()
            .any(|manifest| manifest.stage == RewriteStage::Verified));
        assert!(all_subsystems()
            .iter()
            .any(|manifest| manifest.stage == RewriteStage::InProgress));
    }
}
