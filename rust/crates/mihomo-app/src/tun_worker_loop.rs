pub(crate) fn spawn_tun_workers(
    specs: &[TunRuntimeSpec],
    tunnel: Arc<RuntimeTunnel>,
    dns_runtime: Option<DnsRuntime>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for spec in specs {
        let Some((reader, writer)) = open_tun_reader_writer(spec)? else {
            continue;
        };
        let spec = spec.clone();
        let tunnel = Arc::clone(&tunnel);
        let dns_runtime = dns_runtime.clone();
        let shutdown_flag = Arc::clone(&shutdown);
        handles.push(thread::spawn(move || {
            tun_fd_udp_loop(spec, tunnel, dns_runtime, shutdown_flag, reader, writer);
        }));
    }
    Ok(handles)
}

pub(crate) fn tun_fd_udp_loop(
    spec: TunRuntimeSpec,
    tunnel: Arc<RuntimeTunnel>,
    dns_runtime: Option<DnsRuntime>,
    shutdown: Arc<AtomicBool>,
    mut reader: File,
    writer: Arc<Mutex<File>>,
) {
    let cleanup_name = linux_tun_cleanup_name(&spec);
    let mut buffer = vec![0_u8; TUN_PACKET_BUFFER_SIZE];
    let mut tcp_flows: HashMap<TunTcpFlowKey, CurrentTcpFlow> = HashMap::new();
    let udp_session_pool = Arc::new(TunUdpSessionPool::from_tun_spec(&spec));
    let udp_runtime_mode = spec.udp_runtime_mode();
    let udp_queue = Arc::new(TunUdpDispatchQueue::new(
        udp_runtime_mode,
        udp_worker_threads(),
    ));
    let udp_workers = spawn_tun_udp_workers(Arc::clone(&udp_queue));
    while !shutdown.load(Ordering::Relaxed) {
        for flow in tcp_flows.values() {
            if let Err(err) = flow.poll_timers(&writer) {
                push_log(LogLevel::Warn, format!("tun worker tcp timer error inbound={}: {err}", spec.name));
            }
        }
        tcp_flows.retain(|_, flow| {
            !flow
                .handle
                .stack()
                .lock()
                .map(|locked| locked.is_finished() && flow.bridge_done.load(Ordering::Relaxed))
                .unwrap_or(true)
        });

        match wait_for_frame(&reader) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                push_log(
                    LogLevel::Warn,
                    format!("tun worker wait error inbound={}: {err}", spec.name),
                );
                break;
            }
        }

        match reader.read(&mut buffer) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(read) => match parse_tun_udp_packet(&buffer[..read]) {
                Ok(parsed) => {
                    udp_queue.push(TunUdpDispatchTask {
                        spec: spec.clone(),
                        tunnel: Arc::clone(&tunnel),
                        dns_runtime: dns_runtime.clone(),
                        parsed,
                        writer: Arc::clone(&writer),
                        session_pool: Arc::clone(&udp_session_pool),
                    });
                }
                Err(_) => {
                    match parse_tun_tcp_packet(&buffer[..read]) {
                        Ok(parsed_tcp) => {
                            trace_tun_tcp_packet("ingress", &spec.name, &parsed_tcp);
                            if spec.supports_transparent_tcp_runtime_path() {
                                continue;
                            }
                            if let Some(loopback_source) =
                                spec.loopback_redirect_address(parsed_tcp.destination.ip())
                            {
                                match crate::tun_tcp_packet::encode_loopback_rewritten_tun_tcp_packet(
                                    &parsed_tcp,
                                    loopback_source,
                                    parsed_tcp.source.ip(),
                                ) {
                                    Ok(frame) => {
                                        if let Err(err) = write_frame(&writer, &frame) {
                                            push_log(
                                                LogLevel::Warn,
                                                format!(
                                                    "tun worker loopback write-back error inbound={}: {err}",
                                                    spec.name
                                                ),
                                            );
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        push_log(
                                            LogLevel::Warn,
                                            format!(
                                                "tun worker loopback rewrite error inbound={}: {err}",
                                                spec.name
                                            ),
                                        );
                                    }
                                }
                                continue;
                            }
                            let key = parsed_tcp.flow_key();
                            if !tcp_flows.contains_key(&key) {
                                match CurrentTcpFlow::new(&spec, &parsed_tcp, &writer) {
                                    Ok(flow) => {
                                        trace_tun_tcp_event(
                                            &spec.name,
                                            "flow-created",
                                        );
                                        tcp_flows.insert(key.clone(), flow);
                                    }
                                    Err(err) => {
                                        push_log(
                                            LogLevel::Warn,
                                            format!("tun worker tcp flow init error inbound={}: {err}", spec.name),
                                        );
                                        continue;
                                    }
                                }
                                continue;
                            }

                            let Some(flow) = tcp_flows.get_mut(&key) else {
                                continue;
                            };
                            if let Err(err) = flow.ingest(&parsed_tcp, &writer) {
                                push_log(
                                    LogLevel::Warn,
                                    format!("tun worker tcp ingest error inbound={}: {err}", spec.name),
                                );
                                continue;
                            }
                            flow.maybe_start_bridge(&spec, &tunnel, &parsed_tcp, &writer);
                        }
                        Err(_) => {
                            match parse_tun_icmp_packet(&spec, &buffer[..read]) {
                                Ok(Some(parsed_icmp)) => {
                                    if let Err(err) = write_frame(&writer, &parsed_icmp.response_frame) {
                                        push_log(
                                            LogLevel::Warn,
                                            format!(
                                                "tun worker icmp write-back error inbound={}: {err}",
                                                spec.name
                                            ),
                                        );
                                        break;
                                    }
                                }
                                Ok(None) => {
                                    // Ignore non-UDP/non-TCP or currently-unsupported packets for now.
                                }
                                Err(err) => {
                                    push_log(
                                        LogLevel::Warn,
                                        format!(
                                            "tun worker icmp parse error inbound={}: {err}",
                                            spec.name
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            },
            Err(err) if matches!(err.kind(), io::ErrorKind::Interrupted) => continue,
            Err(err) => {
                push_log(
                    LogLevel::Warn,
                    format!("tun worker read error inbound={}: {err}", spec.name),
                );
                break;
            }
        }
    }
    udp_queue.close();
    for worker in udp_workers {
        let _ = worker.join();
    }
    udp_session_pool.shutdown();
    cleanup_linux_tun_worker(&spec, cleanup_name.as_deref());
}

#[cfg(target_os = "linux")]
fn linux_tun_cleanup_name(spec: &TunRuntimeSpec) -> Option<String> {
    mihomo_tun::requested_linux_tun_name(spec)
        .ok()
        .filter(|name| !name.trim().is_empty())
}

#[cfg(not(target_os = "linux"))]
fn linux_tun_cleanup_name(_spec: &TunRuntimeSpec) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn cleanup_linux_tun_worker(spec: &TunRuntimeSpec, device_name: Option<&str>) {
    let Some(device_name) = device_name else {
        return;
    };
    if let Err(err) = mihomo_tun::cleanup_linux_tun_interface(spec, device_name) {
        push_log(
            LogLevel::Warn,
            format!(
                "tun worker cleanup error inbound={} device={device_name}: {err}",
                spec.name
            ),
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn cleanup_linux_tun_worker(_spec: &TunRuntimeSpec, _device_name: Option<&str>) {}
