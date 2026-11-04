pub(crate) fn spawn_tun_workers(
    specs: &[TunRuntimeSpec],
    tunnel: Arc<RuntimeTunnel>,
    dns_runtime: Option<DnsRuntime>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let mut opened = Vec::new();
    for spec in specs {
        let Some((reader, writer, routes)) = open_tun_reader_writer(spec)? else {
            continue;
        };
        opened.push((spec.clone(), reader, writer, routes));
    }
    // Prepare every device before spawning workers. If a later device fails,
    // the earlier route guards roll back synchronously before startup returns.
    let mut handles = Vec::new();
    for (spec, reader, writer, routes) in opened {
        let tunnel = Arc::clone(&tunnel);
        let dns_runtime = dns_runtime.clone();
        let shutdown_flag = Arc::clone(&shutdown);
        handles.push(thread::spawn(move || {
            let _routes = routes;
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
    let mut buffer = vec![0_u8; TUN_PACKET_BUFFER_SIZE];
    let mut tcp_dispatch = match TunTcpDispatch::new(&spec, &tunnel, &writer) {
        Ok(dispatch) => dispatch,
        Err(err) => {
            push_log(LogLevel::Error, format!("TUN TCP worker startup: {err}"));
            return;
        }
    };
    let udp_session_pool = Arc::new(TunUdpSessionPool::from_tun_spec(&spec));
    let udp_runtime_mode = spec.udp_runtime_mode();
    let udp_queue = Arc::new(TunUdpDispatchQueue::new(
        udp_runtime_mode,
        udp_worker_threads(),
    ));
    let udp_workers = spawn_tun_udp_workers(Arc::clone(&udp_queue));
    while !shutdown.load(Ordering::Relaxed) {
        if let Err(err) = tcp_dispatch.poll_inline(&writer) {
            push_log(LogLevel::Warn, format!("TUN TCP timer: {err}"));
        }
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
            Ok(read) => {
                match kernel_direct::try_kernel_direct(&spec,&tunnel,&buffer[..read],&writer) {
                    Ok(true)=>continue,
                    Ok(false)=>{},
                    Err(error)=>{push_log(LogLevel::Warn,format!("kernel DIRECT first packet: {error}"));continue;}
                }
                match parse_tun_udp_packet(&buffer[..read]) {
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
                            if let Err(err) = tcp_dispatch.push(&spec, &tunnel, &writer, parsed_tcp) {
                                push_log(LogLevel::Warn, format!("TUN TCP dispatch: {err}"));
                                break;
                            }
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
    drop(tcp_dispatch);
    udp_queue.close();
    for worker in udp_workers {
        let _ = worker.join();
    }
    udp_session_pool.shutdown();
}
