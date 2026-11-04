// Each flow stays on one worker, preserving TCP order while unrelated flows
// perform stack/ACK/timer work concurrently. The TUN reader only dispatches.
struct TunTcpDispatch {
    senders: Vec<std::sync::mpsc::SyncSender<TcpDispatchTask>>,
    workers: Vec<JoinHandle<()>>,
    inline_flows: HashMap<TunTcpFlowKey, CurrentTcpFlow>,
    parallel: bool,
    last_inline_poll: std::time::Instant,
}

enum TcpDispatchTask {
    Packet(ParsedTunTcpPacket),
    Adopt(TunTcpFlowKey, CurrentTcpFlow),
}

fn tun_tcp_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, 8)
}

fn tcp_flow_shard(key: &TunTcpFlowKey, count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as usize % count
}

impl TunTcpDispatch {
    fn new(
        spec: &TunRuntimeSpec,
        tunnel: &Arc<RuntimeTunnel>,
        writer: &Arc<Mutex<File>>,
    ) -> io::Result<Self> {
        let mut dispatch = Self {
            senders: Vec::new(),
            workers: Vec::new(),
            inline_flows: HashMap::new(),
            parallel: false,
            last_inline_poll: std::time::Instant::now(),
        };
        if spec.supports_transparent_tcp_runtime_path() {
            return Ok(dispatch);
        }
        for index in 0..tun_tcp_worker_count() {
            let (tx, rx) = std::sync::mpsc::sync_channel(128);
            let spec = spec.clone();
            let tunnel = tunnel.clone();
            let writer = writer.clone();
            let worker = thread::Builder::new()
                .name(format!("tun-tcp-{index}"))
                .stack_size(512 * 1024)
                .spawn(move || {
                    let mut flows: HashMap<TunTcpFlowKey, CurrentTcpFlow> = HashMap::new();
                    let mut last_poll = std::time::Instant::now();
                    loop {
                        if last_poll.elapsed() >= Duration::from_millis(20) {
                            for flow in flows.values() {
                                if let Err(err) = flow.poll_timers(&writer) {
                                    push_log(
                                        LogLevel::Warn,
                                        format!("tun tcp timer inbound={}: {err}", spec.name),
                                    );
                                }
                            }
                            flows.retain(|_, flow| !flow.finished());
                            last_poll = std::time::Instant::now();
                        }
                        let wait = if flows.is_empty() {
                            Duration::from_secs(1)
                        } else {
                            Duration::from_millis(20).saturating_sub(last_poll.elapsed())
                        };
                        match rx.recv_timeout(wait) {
                            Ok(TcpDispatchTask::Packet(packet)) => {
                                Self::ingest(&mut flows, &spec, &tunnel, &writer, packet)
                            }
                            Ok(TcpDispatchTask::Adopt(key, flow)) => {
                                flows.insert(key, flow);
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    for (_, mut flow) in flows {
                        let _ = mihomo_core::TcpStream::shutdown_all(&mut flow.handle);
                    }
                })?;
            dispatch.senders.push(tx);
            dispatch.workers.push(worker);
        }
        Ok(dispatch)
    }

    fn ingest(
        flows: &mut HashMap<TunTcpFlowKey, CurrentTcpFlow>,
        spec: &TunRuntimeSpec,
        tunnel: &Arc<RuntimeTunnel>,
        writer: &Arc<Mutex<File>>,
        packet: ParsedTunTcpPacket,
    ) {
        let key = packet.flow_key();
        if flows.get(&key).is_some_and(CurrentTcpFlow::finished) {
            flows.remove(&key);
        }
        if let Some(flow) = flows.get_mut(&key) {
            if let Err(err) = flow.ingest(&packet, writer) {
                push_log(
                    LogLevel::Warn,
                    format!("tun tcp ingest inbound={}: {err}", spec.name),
                );
                return;
            }
            flow.maybe_start_bridge(spec, tunnel, &packet, writer);
        } else {
            // Out-of-window late ACKs must not allocate orphaned TCP stacks.
            if packet.tcp_repr.control != smoltcp::wire::TcpControl::Syn {
                return;
            }
            match CurrentTcpFlow::new(spec, &packet, writer) {
                Ok(flow) => {
                    flows.insert(key, flow);
                }
                Err(err) => push_log(
                    LogLevel::Warn,
                    format!("tun tcp init inbound={}: {err}", spec.name),
                ),
            }
        }
    }

    fn poll_inline(&mut self, writer: &Arc<Mutex<File>>) -> io::Result<()> {
        if self.parallel || self.last_inline_poll.elapsed() < Duration::from_millis(20) {
            return Ok(());
        }
        for flow in self.inline_flows.values() {
            flow.poll_timers(writer)?;
        }
        self.inline_flows.retain(|_, flow| !flow.finished());
        self.last_inline_poll = std::time::Instant::now();
        Ok(())
    }

    fn push(
        &mut self,
        spec: &TunRuntimeSpec,
        tunnel: &Arc<RuntimeTunnel>,
        writer: &Arc<Mutex<File>>,
        packet: ParsedTunTcpPacket,
    ) -> io::Result<()> {
        if !self.parallel {
            self.inline_flows.retain(|_, flow| !flow.finished());
            if self.inline_flows.is_empty() || self.inline_flows.contains_key(&packet.flow_key()) {
                Self::ingest(&mut self.inline_flows, spec, tunnel, writer, packet);
                return Ok(());
            }
            if packet.tcp_repr.control != smoltcp::wire::TcpControl::Syn {
                return Ok(());
            }
            // Transfer the existing stack before queueing any later packet for
            // its flow. Application stream handles keep the same shared state.
            for (key, flow) in self.inline_flows.drain() {
                let index = tcp_flow_shard(&key, self.senders.len());
                self.senders[index]
                    .send(TcpDispatchTask::Adopt(key, flow))
                    .map_err(|_| io::Error::other("TUN TCP worker stopped"))?;
            }
            self.parallel = true;
        }
        let index = tcp_flow_shard(&packet.flow_key(), self.senders.len());
        self.senders[index]
            .send(TcpDispatchTask::Packet(packet))
            .map_err(|_| io::Error::other("TUN TCP worker stopped"))
    }
}

impl Drop for TunTcpDispatch {
    fn drop(&mut self) {
        for (_, mut flow) in self.inline_flows.drain() {
            let _ = mihomo_core::TcpStream::shutdown_all(&mut flow.handle);
        }
        self.senders.clear();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl CurrentTcpFlow {
    fn finished(&self) -> bool {
        self.bridge_done.load(Ordering::Relaxed)
            && self
                .handle
                .stack()
                .lock()
                .map(|stack| stack.is_finished())
                .unwrap_or(true)
    }
}

#[cfg(test)]
mod tcp_dispatch_tests {
    use super::*;

    #[test]
    fn tcp_flows_preserve_worker_affinity_and_spread_across_workers() {
        let mut counts = [0; 8];
        for port in 10000..11000 {
            let key = TunTcpFlowKey {
                source: SocketAddr::from(([192, 0, 2, 1], port)),
                destination: "203.0.113.10:443".parse().unwrap(),
            };
            let shard = tcp_flow_shard(&key, 8);
            assert_eq!(shard, tcp_flow_shard(&key.clone(), 8));
            counts[shard] += 1;
        }
        assert!(counts.iter().all(|count| *count > 50));
    }
}
