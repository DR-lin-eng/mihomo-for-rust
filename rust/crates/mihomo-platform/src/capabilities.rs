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
    pub supports_openwrt_flow_offload: bool,
    pub supports_openwrt_hardware_offload: bool,
}

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
        supports_tcp_fast_open: cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        )),
        supports_zero_copy_tcp: cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd"
        )),
        supports_zero_copy_udp: cfg!(target_os = "linux"),
        supports_openwrt_flow_offload: cfg!(target_os = "linux"),
        supports_openwrt_hardware_offload: cfg!(target_os = "linux"),
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
