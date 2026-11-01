mod filters;
#[cfg(target_os = "linux")]
mod linux;
mod runtime_spec;

use mihomo_core::{RewriteStage, SubsystemManifest};

#[cfg(test)]
mod tests;

#[cfg(target_os = "linux")]
pub use linux::{
    cleanup_linux_tun_interface, linux_tun_setup_commands, open_linux_tun_device,
    requested_linux_tun_name,
};
pub use runtime_spec::{TunRuntimeSpec, TunUdpRuntimeMode};

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-tun",
    go_areas: &["listener/sing_tun"],
    contracts: &[
        "linux tun device lifecycle",
        "policy-routing command generation",
        "tun runtime metadata filters",
    ],
    stage: RewriteStage::InProgress,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}
