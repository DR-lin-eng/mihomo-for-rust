use mihomo_core::{RewriteStage, SubsystemManifest};

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-api",
    go_areas: &["hub/route"],
    contracts: &["external controller compatibility", "external UI exposure"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}
