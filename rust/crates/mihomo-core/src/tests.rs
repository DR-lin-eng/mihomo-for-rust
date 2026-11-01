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
