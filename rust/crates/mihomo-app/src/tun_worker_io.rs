fn write_frame(writer: &Arc<Mutex<File>>, frame: &[u8]) -> io::Result<()> {
    trace_tun_tcp_frame("egress", frame);
    let mut file = writer
        .lock()
        .map_err(|_| io::Error::other("tun worker write mutex poisoned"))?;
    file.write_all(frame)?;
    file.flush()
}

fn write_frames(writer: &Arc<Mutex<File>>, frames: &[Vec<u8>]) -> io::Result<()> {
    if frames.is_empty() { return Ok(()); }
    let mut file = writer.lock().map_err(|_| io::Error::other("tun worker write mutex poisoned"))?;
    for frame in frames {
        trace_tun_tcp_frame("egress", frame);
        file.write_all(frame)?;
    }
    file.flush()
}

fn tun_tcp_trace_enabled() -> bool {
    use std::sync::OnceLock;

    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("MIHOMO_TUN_TCP_TRACE").is_some())
}

fn trace_tun_tcp_packet(label: &str, inbound_name: &str, packet: &ParsedTunTcpPacket) {
    if !tun_tcp_trace_enabled() {
        return;
    }
    eprintln!(
        "[tun-tcp-trace] {label} inbound={inbound_name} src={} dst={} ctrl={:?} seq={:?} ack={:?} payload_len={}",
        packet.source,
        packet.destination,
        packet.tcp_repr.control,
        packet.tcp_repr.seq_number,
        packet.tcp_repr.ack_number,
        packet.tcp_repr.payload.len(),
    );
}

fn trace_tun_tcp_frame(label: &str, frame: &[u8]) {
    if !tun_tcp_trace_enabled() {
        return;
    }
    if let Ok(packet) = parse_tun_tcp_packet(frame) {
        trace_tun_tcp_packet(label, "<frame>", &packet);
    }
}

fn trace_tun_tcp_event(inbound_name: &str, event: &str) {
    if !tun_tcp_trace_enabled() {
        return;
    }
    eprintln!("[tun-tcp-trace] event inbound={inbound_name} {event}");
}

fn open_tun_reader_writer(
    spec: &TunRuntimeSpec,
) -> io::Result<Option<(File, Arc<Mutex<File>>, Option<TunRouteGuard>)>> {
    if spec.config.file_descriptor > 0 {
        let fd = spec.config.file_descriptor;
        let reader = clone_fd_as_file(fd)?;
        let writer = Arc::new(Mutex::new(clone_fd_as_file(fd)?));
        return Ok(Some((reader, writer, None)));
    }

    #[cfg(target_os = "linux")]
    {
        let (reader, routes) = open_linux_tun_device(spec)?.into_parts();
        let writer = Arc::new(Mutex::new(reader.try_clone()?));
        return Ok(Some((reader, writer, routes)));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(None)
    }
}

#[cfg(unix)]
fn wait_for_frame(reader: &File) -> io::Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let polled = unsafe { libc::poll(&mut poll_fd, 1, TUN_WORKER_POLL_TIMEOUT_MS) };
        if polled > 0 {
            return Ok(true);
        }
        if polled == 0 {
            return Ok(false);
        }
        let err = io::Error::last_os_error();
        if matches!(err.kind(), io::ErrorKind::Interrupted) {
            continue;
        }
        return Err(err);
    }
}

#[cfg(not(unix))]
fn wait_for_frame(_reader: &File) -> io::Result<bool> {
    Ok(true)
}

#[cfg(unix)]
fn clone_fd_as_file(fd: i32) -> io::Result<File> {
    let cloned = unsafe { libc::dup(fd) };
    if cloned < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(cloned) };
    Ok(file)
}

#[cfg(not(unix))]
fn clone_fd_as_file(_fd: i32) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tun file descriptor workers require unix file descriptors",
    ))
}
