use mihomo_config::RuntimeConfigDocument;
use serde::Serialize;
use std::io;
use std::net::SocketAddr;

mod direct_types;
pub use direct_types::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::EbpfRuntime;

#[derive(Clone, Debug, Default, Serialize)]
pub struct EbpfStatus {
    pub supported: bool,
    pub running: bool,
    pub interfaces: Vec<InterfaceStatus>,
    pub direct_offload: DirectOffloadStatus,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub mode: String,
    pub ingress: bool,
    pub egress: bool,
    pub program_ids: Vec<u32>,
    pub counters: Counters,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Counters {
    pub processed: u64,
    pub redirected: u64,
    pub bypassed: u64,
    pub dropped: u64,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct EbpfRuntime;
#[cfg(not(target_os = "linux"))]
impl EbpfRuntime {
    pub fn direct_ready(&self) -> bool { false }
    pub fn direct_pending(&self, _key: &DirectFlowKey) -> bool { false }
    pub fn direct_fragment(&self, _key: &DirectFragmentKey) -> Option<DirectFlowKey> { None }
    pub fn direct_remember_fragment(&self, _fragment: DirectFragmentKey, _key: DirectFlowKey) {}
    pub fn direct_contains(&self, _key: &DirectFlowKey) -> bool { false }
    pub fn direct_install(&self, _key: DirectFlowKey, _target: SocketAddr, _id: u64, _timeout_secs: u64) -> io::Result<bool> { Ok(false) }
    pub fn direct_samples(&self) -> Vec<DirectFlowSample> { Vec::new() }
    pub fn direct_close(&self, _key: &DirectFlowKey) {}
    pub fn direct_forget(&self, _key: &DirectFlowKey) {}
    pub fn direct_invalidate_udp(&self) {}
    pub fn install(document: &RuntimeConfigDocument) -> io::Result<Option<Self>> {
        if document.ebpf.enabled() {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "eBPF is only available on Linux",
            ))
        } else {
            Ok(None)
        }
    }
    pub fn shutdown(&self) {}
    pub fn original_destination(
        &self,
        _peer: SocketAddr,
        _local: SocketAddr,
    ) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    pub fn status(&self) -> EbpfStatus {
        EbpfStatus::default()
    }
}
