mod capabilities;
mod optimization;
mod targets;

pub use capabilities::{current_capabilities, current_family, PlatformCapabilities};
pub use optimization::{supported_optimization_variants, OptimizationVariant};
pub use targets::{TargetProfile, SUPPORTED_TARGETS};

#[cfg(test)]
mod tests {
    use super::{current_capabilities, SUPPORTED_TARGETS};

    #[test]
    fn keeps_embedded_linux_targets_in_scope() {
        assert!(SUPPORTED_TARGETS
            .iter()
            .any(|target| target.openwrt_friendly && target.family == "linux"));
    }

    #[test]
    fn keeps_non_linux_desktop_targets_in_scope() {
        assert!(SUPPORTED_TARGETS.iter().any(|target| target.family == "windows"));
        assert!(SUPPORTED_TARGETS.iter().any(|target| target.family == "darwin"));
    }

    #[test]
    fn current_capabilities_are_self_consistent() {
        let caps = current_capabilities();
        assert!(!caps.family.is_empty());
    }
}
