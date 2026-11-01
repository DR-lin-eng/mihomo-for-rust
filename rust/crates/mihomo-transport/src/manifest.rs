use mihomo_core::{RewriteStage, SubsystemManifest};

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-transport",
    go_areas: &["transport"],
    contracts: &[
        "stream transports",
        "packet transports",
        "encapsulation layers",
        "normalized transport plan execution",
    ],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}
