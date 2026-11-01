mod definitions;
mod kinds;
mod models;
mod parse;
mod serde_support;

use mihomo_core::{RewriteStage, SubsystemManifest};

pub use definitions::{OutboundDefinition, ProviderPayloadDocument};
pub use kinds::{
    OutboundGroupKind, OutboundKind, ProxyProviderVehicleType, SUPPORTED_OUTBOUND_GROUPS,
    SUPPORTED_OUTBOUNDS,
};
pub use models::{
    GroupDefinition, NamedOutboundConfig, ProviderHealthCheckConfig, ProxyBaseConfig,
    ProxyProviderDefinition, ProxyProviderOverride, ServerPortOutboundConfig,
    ShadowSocksOutboundConfig, SmuxConfig, WireGuardOutboundConfig,
};
pub use parse::{
    parse_group_yaml, parse_outbound_yaml, parse_provider_payload_document, parse_provider_yaml,
};

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-outbound",
    go_areas: &["adapter/outbound", "adapter/outboundgroup", "adapter/provider"],
    contracts: &["proxy adapters", "proxy groups", "provider compatibility"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests;
