mod definitions;
mod kinds;
mod models;
mod parse;

use mihomo_core::{RewriteStage, SubsystemManifest};

pub use definitions::InboundDefinition;
pub use kinds::{InboundKind, SUPPORTED_INBOUNDS};
pub use models::{
    AuthUser, BaseInboundConfig, GenericInboundConfig, HttpInboundConfig, RealityConfig,
    RealityLimitFallback, RedirInboundConfig, ShadowSocksInboundConfig, SimpleObfsConfig,
    TlsInboundConfig, TProxyInboundConfig, TunnelInboundConfig, TunInboundConfig, TunStack,
};
pub use parse::parse_inbound_yaml;

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-inbound",
    go_areas: &["listener", "adapter/inbound"],
    contracts: &["listener families", "metadata extraction", "packet ingestion"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests;
