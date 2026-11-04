use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::io::{self, Read, Write};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mihomo_core::{push_log, LogLevel};
use mihomo_dns::DnsRuntime;
use mihomo_runtime::{dispatch_tun_tcp_stream, RuntimeTunnel};
use mihomo_tun::{TunRuntimeSpec, TunUdpRuntimeMode};
#[cfg(target_os = "linux")]
use mihomo_tun::open_linux_tun_device;
#[cfg(target_os = "linux")]
type TunRouteGuard = mihomo_tun::LinuxTunRouteGuard;
#[cfg(not(target_os = "linux"))]
type TunRouteGuard = ();

use crate::listener_udp_support::udp_worker_threads;
use crate::tun_icmp_packet::parse_tun_icmp_packet;
use crate::tun_packet::{parse_tun_udp_packet, relay_tun_udp_packet, TunUdpSessionPool};
use crate::tun_tcp_packet::{parse_tun_tcp_packet, ParsedTunTcpPacket, TunTcpFlowKey};
use crate::tun_tcp_stack::{TunTcpPassiveStack, TunTcpStreamHandle};

const TUN_PACKET_BUFFER_SIZE: usize = 64 * 1024;
#[path="tun_kernel_direct.rs"]
mod kernel_direct;
#[cfg(unix)]
const TUN_WORKER_POLL_TIMEOUT_MS: i32 = 20;
const TUN_UDP_QUEUE_DEPTH_PER_WORKER: usize = 64;

struct TunUdpDispatchTask {
    spec: TunRuntimeSpec,
    tunnel: Arc<RuntimeTunnel>,
    dns_runtime: Option<DnsRuntime>,
    parsed: crate::tun_packet::ParsedTunUdpPacket,
    writer: Arc<Mutex<File>>,
    session_pool: Arc<TunUdpSessionPool>,
}

impl TunUdpDispatchTask {
    fn run(self) {
        let writer = Arc::clone(&self.writer);
        let session_result = self.session_pool.send_live(
            &self.spec,
            self.tunnel,
            self.parsed,
            self.dns_runtime,
            Arc::new(move |frame| write_frame(&writer, frame)),
        );
        match session_result {
            Ok(()) => {}
            Err(err) => {
                push_log(
                    LogLevel::Warn,
                    format!("tun worker relay error inbound={}: {err}", self.spec.name),
                );
            }
        }
    }
}

struct TunUdpDispatchQueue {
    runtime_mode: TunUdpRuntimeMode,
    shards: Vec<Arc<TunUdpDispatchQueueShard>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum TunUdpDispatchShardKey {
    Source(SocketAddr),
    SourceAndDestination {
        source: SocketAddr,
        destination: SocketAddr,
    },
}

struct TunUdpDispatchQueueShard {
    state: Mutex<TunUdpDispatchQueueState>,
    ready: Condvar,
    drained: Condvar,
    max_tasks: usize,
}

struct TunUdpDispatchQueueState {
    closed: bool,
    tasks: std::collections::VecDeque<TunUdpDispatchTask>,
}

impl TunUdpDispatchQueue {
    fn new(runtime_mode: TunUdpRuntimeMode, worker_count: usize) -> Self {
        let shard_count = worker_count.max(1);
        Self {
            runtime_mode,
            shards: (0..shard_count)
                .map(|_| {
                    Arc::new(TunUdpDispatchQueueShard {
                        state: Mutex::new(TunUdpDispatchQueueState {
                            closed: false,
                            tasks: std::collections::VecDeque::new(),
                        }),
                        ready: Condvar::new(),
                        drained: Condvar::new(),
                        max_tasks: TUN_UDP_QUEUE_DEPTH_PER_WORKER,
                    })
                })
                .collect(),
        }
    }

    fn push(&self, task: TunUdpDispatchTask) {
        let shard = self.shard_for_packet(task.parsed.source, task.parsed.destination);
        shard.push(task);
    }

    fn close(&self) {
        for shard in &self.shards {
            shard.close();
        }
    }

    fn shard_key_for_packet(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> TunUdpDispatchShardKey {
        match self.runtime_mode {
            TunUdpRuntimeMode::DirectRelay => TunUdpDispatchShardKey::SourceAndDestination {
                source,
                destination,
            },
            TunUdpRuntimeMode::MixedLikeRelay => TunUdpDispatchShardKey::Source(source),
        }
    }

    fn shard_for_packet(
        &self,
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
    ) -> Arc<TunUdpDispatchQueueShard> {
        let mut hasher = DefaultHasher::new();
        self.shard_key_for_packet(source, destination)
            .hash(&mut hasher);
        Arc::clone(&self.shards[hasher.finish() as usize % self.shards.len()])
    }

    #[cfg(test)]
    fn shard_key_for_packet_for_tests(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> TunUdpDispatchShardKey {
        self.shard_key_for_packet(source, destination)
    }
}

impl TunUdpDispatchQueueShard {
    fn push(&self, task: TunUdpDispatchTask) {
        let mut state = self.state.lock().unwrap();
        while !state.closed && state.tasks.len() >= self.max_tasks {
            state = self.drained.wait(state).unwrap();
        }
        if state.closed {
            return;
        }
        state.tasks.push_back(task);
        self.ready.notify_one();
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.ready.notify_all();
        self.drained.notify_all();
    }

    fn pop(&self) -> Option<TunUdpDispatchTask> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(task) = state.tasks.pop_front() {
                self.drained.notify_one();
                return Some(task);
            }
            if state.closed {
                return None;
            }
            state = self.ready.wait(state).unwrap();
        }
    }
}

fn spawn_tun_udp_workers(queue: Arc<TunUdpDispatchQueue>) -> Vec<JoinHandle<()>> {
    queue
        .shards
        .iter()
        .map(|shard| {
            let shard = Arc::clone(shard);
            thread::spawn(move || {
                while let Some(task) = shard.pop() {
                    task.run();
                }
            })
        })
        .collect()
}

include!("tun_worker_tcp.rs");
include!("tun_worker_tcp_dispatch.rs");
include!("tun_worker_loop.rs");
include!("tun_worker_io.rs");

#[cfg(all(test, unix))]
mod tests {
    include!("tun_worker_tests.rs");
}
