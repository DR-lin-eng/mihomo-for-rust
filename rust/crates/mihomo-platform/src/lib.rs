#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetProfile {
    pub family: &'static str,
    pub output: &'static str,
    pub preferred_rust_target: Option<&'static str>,
    pub cpu_profile: &'static str,
    pub openwrt_friendly: bool,
    pub notes: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformCapabilities {
    pub family: &'static str,
    pub supports_redir: bool,
    pub supports_tproxy: bool,
    pub supports_tun: bool,
    pub supports_socket_mark: bool,
    pub supports_process_lookup: bool,
    pub supports_tcp_fast_open: bool,
    pub supports_zero_copy_tcp: bool,
    pub supports_zero_copy_udp: bool,
}

pub const SUPPORTED_TARGETS: &[TargetProfile] = &[
    TargetProfile {
        family: "linux",
        output: "386",
        preferred_rust_target: Some("i686-unknown-linux-musl"),
        cpu_profile: "baseline",
        openwrt_friendly: false,
        notes: &["Keep legacy 32-bit Linux builds in scope."],
    },
    TargetProfile {
        family: "linux",
        output: "amd64-v1",
        preferred_rust_target: Some("x86_64-unknown-linux-musl"),
        cpu_profile: "x86-64-v1",
        openwrt_friendly: false,
        notes: &["Separate CPU profile from target triple."],
    },
    TargetProfile {
        family: "linux",
        output: "amd64-v2",
        preferred_rust_target: Some("x86_64-unknown-linux-musl"),
        cpu_profile: "x86-64-v2",
        openwrt_friendly: false,
        notes: &["Needs a dedicated release profile, not a different crate graph."],
    },
    TargetProfile {
        family: "linux",
        output: "amd64-v3",
        preferred_rust_target: Some("x86_64-unknown-linux-musl"),
        cpu_profile: "x86-64-v3",
        openwrt_friendly: false,
        notes: &["Primary high-performance Linux desktop/server profile."],
    },
    TargetProfile {
        family: "linux",
        output: "armv5",
        preferred_rust_target: Some("armv5te-unknown-linux-musleabi"),
        cpu_profile: "armv5 soft-float",
        openwrt_friendly: true,
        notes: &["Old embedded targets remain in scope."],
    },
    TargetProfile {
        family: "linux",
        output: "armv6",
        preferred_rust_target: Some("arm-unknown-linux-musleabi"),
        cpu_profile: "armv6",
        openwrt_friendly: true,
        notes: &["Raspberry Pi Zero class devices and similar boards."],
    },
    TargetProfile {
        family: "linux",
        output: "armv7",
        preferred_rust_target: Some("armv7-unknown-linux-musleabihf"),
        cpu_profile: "armv7 hard-float",
        openwrt_friendly: true,
        notes: &["Common OpenWrt-class target."],
    },
    TargetProfile {
        family: "linux",
        output: "arm64",
        preferred_rust_target: Some("aarch64-unknown-linux-musl"),
        cpu_profile: "arm64",
        openwrt_friendly: true,
        notes: &["Primary ARM64 Linux target."],
    },
    TargetProfile {
        family: "linux",
        output: "mips-softfloat",
        preferred_rust_target: None,
        cpu_profile: "mips soft-float",
        openwrt_friendly: true,
        notes: &["Likely requires custom target JSON or a separate toolchain policy."],
    },
    TargetProfile {
        family: "linux",
        output: "mipsle-softfloat",
        preferred_rust_target: None,
        cpu_profile: "mipsel soft-float",
        openwrt_friendly: true,
        notes: &["Embedded OpenWrt compatibility target."],
    },
    TargetProfile {
        family: "linux",
        output: "mips64le",
        preferred_rust_target: Some("mips64el-unknown-linux-muslabi64"),
        cpu_profile: "mips64le",
        openwrt_friendly: false,
        notes: &["64-bit MIPS release target."],
    },
    TargetProfile {
        family: "linux",
        output: "riscv64",
        preferred_rust_target: Some("riscv64gc-unknown-linux-musl"),
        cpu_profile: "riscv64",
        openwrt_friendly: true,
        notes: &["Increasingly relevant for routers and SBCs."],
    },
    TargetProfile {
        family: "linux",
        output: "loong64-abi1",
        preferred_rust_target: None,
        cpu_profile: "loongarch64 abi1",
        openwrt_friendly: false,
        notes: &["Needs explicit ABI handling in the Rust build policy."],
    },
    TargetProfile {
        family: "linux",
        output: "s390x",
        preferred_rust_target: Some("s390x-unknown-linux-musl"),
        cpu_profile: "s390x",
        openwrt_friendly: false,
        notes: &["Keep parity with the current release matrix."],
    },
    TargetProfile {
        family: "linux",
        output: "ppc64le",
        preferred_rust_target: Some("powerpc64le-unknown-linux-gnu"),
        cpu_profile: "ppc64le",
        openwrt_friendly: false,
        notes: &["Server-side parity target."],
    },
    TargetProfile {
        family: "darwin",
        output: "amd64-v1",
        preferred_rust_target: Some("x86_64-apple-darwin"),
        cpu_profile: "x86-64-v1",
        openwrt_friendly: false,
        notes: &["Legacy macOS compatibility needs a separate policy."],
    },
    TargetProfile {
        family: "darwin",
        output: "arm64",
        preferred_rust_target: Some("aarch64-apple-darwin"),
        cpu_profile: "arm64",
        openwrt_friendly: false,
        notes: &["Apple Silicon baseline."],
    },
    TargetProfile {
        family: "windows",
        output: "386",
        preferred_rust_target: Some("i686-pc-windows-msvc"),
        cpu_profile: "baseline",
        openwrt_friendly: false,
        notes: &["Legacy Windows coverage is part of the current contract."],
    },
    TargetProfile {
        family: "windows",
        output: "amd64-v3",
        preferred_rust_target: Some("x86_64-pc-windows-msvc"),
        cpu_profile: "x86-64-v3",
        openwrt_friendly: false,
        notes: &["Primary modern Windows profile."],
    },
    TargetProfile {
        family: "windows",
        output: "arm64",
        preferred_rust_target: Some("aarch64-pc-windows-msvc"),
        cpu_profile: "arm64",
        openwrt_friendly: false,
        notes: &["Windows on ARM remains in scope."],
    },
    TargetProfile {
        family: "freebsd",
        output: "amd64-v3",
        preferred_rust_target: Some("x86_64-unknown-freebsd"),
        cpu_profile: "x86-64-v3",
        openwrt_friendly: false,
        notes: &["Keep parity with the current FreeBSD builds."],
    },
    TargetProfile {
        family: "freebsd",
        output: "arm64",
        preferred_rust_target: Some("aarch64-unknown-freebsd"),
        cpu_profile: "arm64",
        openwrt_friendly: false,
        notes: &["FreeBSD ARM64 stays supported."],
    },
    TargetProfile {
        family: "android",
        output: "arm64-v8",
        preferred_rust_target: Some("aarch64-linux-android"),
        cpu_profile: "arm64",
        openwrt_friendly: false,
        notes: &["Android-specific hooks and protect APIs remain in scope."],
    },
];

pub fn current_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        family: current_family(),
        supports_redir: cfg!(any(target_os = "linux", target_os = "freebsd", target_os = "macos")),
        supports_tproxy: cfg!(target_os = "linux"),
        supports_tun: cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd"
        )),
        supports_socket_mark: cfg!(target_os = "linux"),
        supports_process_lookup: cfg!(any(target_os = "linux", target_os = "macos")),
        supports_tcp_fast_open: cfg!(any(target_os = "linux", target_os = "windows", target_os = "macos")),
        supports_zero_copy_tcp: cfg!(any(target_os = "linux", target_os = "macos", target_os = "freebsd")),
        supports_zero_copy_udp: cfg!(target_os = "linux"),
    }
}

pub fn current_family() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else {
        "other"
    }
}

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
