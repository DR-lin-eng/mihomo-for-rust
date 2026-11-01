use crate::{PlatformCapabilities, TargetProfile};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptimizationVariant {
    Standard,
    ZeroCopyTcp,
    ZeroCopyTcpUdp,
    OpenWrtSoftwareOffload,
    OpenWrtHardwareOffload,
}

impl OptimizationVariant {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::ZeroCopyTcp => "zero-copy-tcp",
            Self::ZeroCopyTcpUdp => "zero-copy-tcp-udp",
            Self::OpenWrtSoftwareOffload => "openwrt-software-offload",
            Self::OpenWrtHardwareOffload => "openwrt-hardware-offload",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::Standard => "portable buffered forwarding baseline",
            Self::ZeroCopyTcp => "platform-tuned tcp forwarding fast path",
            Self::ZeroCopyTcpUdp => "platform-tuned tcp and udp forwarding fast path",
            Self::OpenWrtSoftwareOffload => "openwrt-oriented software flow offload integration",
            Self::OpenWrtHardwareOffload => "openwrt-oriented hardware flow offload integration",
        }
    }
}

pub fn supported_optimization_variants(
    target: &TargetProfile,
    caps: &PlatformCapabilities,
) -> Vec<OptimizationVariant> {
    let mut variants = vec![OptimizationVariant::Standard];
    if caps.supports_zero_copy_tcp {
        variants.push(OptimizationVariant::ZeroCopyTcp);
    }
    if caps.supports_zero_copy_tcp && caps.supports_zero_copy_udp {
        variants.push(OptimizationVariant::ZeroCopyTcpUdp);
    }
    if target.openwrt_friendly && caps.supports_openwrt_flow_offload {
        variants.push(OptimizationVariant::OpenWrtSoftwareOffload);
    }
    if target.openwrt_friendly && caps.supports_openwrt_hardware_offload {
        variants.push(OptimizationVariant::OpenWrtHardwareOffload);
    }
    variants
}
