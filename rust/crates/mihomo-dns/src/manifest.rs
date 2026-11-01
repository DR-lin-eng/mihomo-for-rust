use mihomo_core::{RewriteStage, SubsystemManifest};

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-dns",
    go_areas: &["dns", "component/resolver", "component/fakeip"],
    contracts: &["resolver flow", "fake-ip", "hosts and system DNS compatibility"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}
