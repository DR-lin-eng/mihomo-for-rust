struct CurrentTcpFlow {
    handle: TunTcpStreamHandle,
    bridge_done: Arc<AtomicBool>,
    bridge_started: bool,
}

impl CurrentTcpFlow {
    fn poll_timers(&self, writer: &Arc<Mutex<File>>) -> io::Result<()> {
        let stack = self.handle.stack();
        let mut stack = stack.lock()
            .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
        if stack.poll_due() {
            write_frames(writer, &stack.drain_outgoing())?;
        }
        Ok(())
    }

    fn new(
        spec: &TunRuntimeSpec,
        parsed_tcp: &ParsedTunTcpPacket,
        writer: &Arc<Mutex<File>>,
    ) -> io::Result<Self> {
        let mut stack = TunTcpPassiveStack::new(parsed_tcp, spec.config.mtu as usize)?;
        stack.ingest_packet(parsed_tcp)?;
        stack.poll();
        write_frames(writer, &stack.drain_outgoing())?;
        let writer = Arc::clone(writer);
        Ok(Self {
            handle: TunTcpStreamHandle::with_egress(
                stack,
                Arc::new(move |packets| write_frames(&writer, &packets)),
            ),
            bridge_done: Arc::new(AtomicBool::new(false)),
            bridge_started: false,
        })
    }

    fn ingest(&self, parsed_tcp: &ParsedTunTcpPacket, writer: &Arc<Mutex<File>>) -> io::Result<()> {
        let stack_ref = self.handle.stack();
        let mut locked = stack_ref
            .lock()
            .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
        locked.ingest_packet(parsed_tcp)?;
        locked.poll();
        write_frames(writer, &locked.drain_outgoing())?;
        Ok(())
    }

    fn maybe_start_bridge(
        &mut self,
        spec: &TunRuntimeSpec,
        tunnel: &Arc<RuntimeTunnel>,
        parsed_tcp: &ParsedTunTcpPacket,
        writer: &Arc<Mutex<File>>,
    ) {
        if self.bridge_started {
            return;
        }
        let should_start = match self.handle.stack().lock() {
            Ok(locked) => locked.is_established(),
            Err(_) => false,
        };
        if !should_start {
            return;
        }
        self.bridge_started = true;
        trace_tun_tcp_event(&spec.name, "bridge-start");
        let done = Arc::clone(&self.bridge_done);
        let spec = spec.clone();
        let tunnel = Arc::clone(tunnel);
        let peer = parsed_tcp.source;
        let destination = parsed_tcp.destination;
        let writer = Arc::clone(writer);
        if crate::blocking_executor::blocking_workers_under_pressure() {
            tunnel.age_connection_under_pressure();
        }
        let bridge = TunTcpStreamHandle::with_egress_from_handle(
            &self.handle,
            Arc::new(move |packets| write_frames(&writer, &packets)),
        );
        crate::blocking_executor::spawn_blocking(move || {
            match dispatch_tun_tcp_stream(
                &spec,
                &tunnel,
                bridge,
                Some(peer),
                destination,
            ) {
                Ok(stats) => {
                    trace_tun_tcp_event(
                        &spec.name,
                        &format!(
                            "bridge-finished left_to_right={} right_to_left={}",
                            stats.left_to_right, stats.right_to_left
                        ),
                    );
                }
                Err(err) => {
                    push_log(
                        LogLevel::Warn,
                        format!("tun worker tcp bridge error inbound={}: {err}", spec.name),
                    );
                    trace_tun_tcp_event(&spec.name, &format!("bridge-error {err}"));
                }
            }
            done.store(true, Ordering::Relaxed);
        });
    }
}
