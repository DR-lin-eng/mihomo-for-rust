#[derive(Clone, Copy, Debug, Default)]
pub struct TcpStats {
    pub segments_out: u64,
    pub retransmissions: u64,
    pub rtt_us: u64,
}
impl TcpStats {
    pub fn loss_rate(self) -> f64 {
        if self.segments_out == 0 {
            0.0
        } else {
            (self.retransmissions as f64 / self.segments_out as f64).min(1.0)
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn read(socket: &std::net::TcpStream) -> Option<TcpStats> {
    use std::os::fd::AsRawFd;
    // TCP_INFO grows by appending fields. Read only stable UAPI offsets and
    // check the returned length, so older OpenWrt kernels remain supported.
    let mut bytes = [0u8; 256];
    let mut length = bytes.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            bytes.as_mut_ptr() as *mut _,
            &mut length,
        )
    };
    if result != 0 || length < 140 {
        return None;
    }
    let u32_at = |offset| u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64;
    Some(TcpStats {
        segments_out: u32_at(136),
        retransmissions: u32_at(100),
        rtt_us: u32_at(68),
    })
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn read(_: &std::net::TcpStream) -> Option<TcpStats> {
    None
}
