//! Active, unauthenticated reachability checks through the exact selected node.
//! Redirects are evidence only; they are never followed by this module.
use super::{
    advanced::{self, ExitInfo, ProbeJob, ProbeKind},
    now_seconds,
    race::{ControlledDialer, DialControl},
    response::{self, Headers, Verdict},
};
use crate::{tunnel_runtime::DnsAwareSystemTcpDialer, RuntimeTunnel};
use mihomo_core::{BoxedTcpStream, Metadata};
use mihomo_transport::{TcpDialer, TcpTransportExecutor, TlsOptions, TransportTarget};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};
const EXIT_URLS: [&str; 3] = [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ip.sb/geoip",
    "https://ipwho.is/",
];

#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Headers,
    body: Vec<u8>,
}
enum Outcome {
    Status(u16, Verdict),
    Exit(Option<ExitInfo>),
}
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl RuntimeTunnel {
    /// Two callers are used by the application. A deadline closes raw sockets
    /// even while a TLS/proxy handshake or a slow HTTP reader is blocked.
    pub fn run_smart_probe_once(&self) -> bool {
        if self.smart_advanced.closed.load(Ordering::Acquire) {
            return false;
        }
        let slots = &self.smart_advanced.probe_slots;
        if slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 2).then_some(n + 1)
            })
            .is_err()
        {
            return false;
        }
        let slot = Slot(slots.clone());
        let Some(job) = self.smart_advanced.jobs.lock().unwrap().pop_front() else {
            return false;
        };
        if job.generation != self.smart_advanced.generation.load(Ordering::Acquire) {
            return true;
        }
        let control = Arc::new(DialControl::default());
        {
            let mut active = self.smart_advanced.controls.lock().unwrap();
            active.retain(|c| c.strong_count() > 0);
            active.push(Arc::downgrade(&control));
        }
        let dialer = DnsAwareSystemTcpDialer::new(self.dns_runtime(), Some(8000));
        let geo = self
            .smart_context
            .lock()
            .unwrap()
            .as_ref()
            .map(|ctx| ctx.geo.clone());
        let (send, recv) = mpsc::channel();
        let cloned = job.clone();
        let worker_control = control.clone();
        let spawned = std::thread::Builder::new()
            .name("smart-probe-io".into())
            .spawn(move || {
                let _slot = slot;
                let outcome = execute(
                    &cloned,
                    Box::new(dialer),
                    worker_control.clone(),
                    geo.as_deref(),
                );
                worker_control.cancel();
                let _ = send.send(outcome);
            });
        if spawned.is_err() {
            return true;
        }
        let start = Instant::now();
        let outcome = loop {
            if job.generation != self.smart_advanced.generation.load(Ordering::Acquire)
                || self.smart_advanced.closed.load(Ordering::Acquire)
            {
                control.cancel();
                return true;
            }
            match recv.recv_timeout(Duration::from_millis(50)) {
                Ok(answer) => break answer,
                Err(mpsc::RecvTimeoutError::Disconnected) => return true,
                Err(_) if start.elapsed() >= Duration::from_secs(8) => {
                    control.cancel();
                    break match job.kind {
                        ProbeKind::Status => {
                            Outcome::Status(0, response::classify_error("deadline", true))
                        }
                        _ => Outcome::Exit(None),
                    };
                }
                Err(_) => {}
            }
        };
        // Check under the registry lock too: flush invalidates before clearing
        // state, so an in-flight result cannot recreate cleared evidence.
        let mut registry = self.registry.lock().unwrap();
        if job.generation != self.smart_advanced.generation.load(Ordering::Acquire) {
            return true;
        }
        let Some(smart) = registry
            .groups
            .get_mut(&job.group)
            .and_then(|view| view.runtime.smart.as_mut())
        else {
            return true;
        };
        let host = advanced::host(&job.metadata);
        let now = now_seconds();
        match outcome {
            Outcome::Status(status, verdict) => {
                if verdict.action == response::Action::Record {
                    mihomo_core::push_log(
                        mihomo_core::LogLevel::Debug,
                        format!(
                            "[Smart] {} via {}: {} (HTTP {status})",
                            host, job.node, verdict.reason
                        ),
                    );
                }
                smart.state.advanced.apply_verdict(
                    &host,
                    &job.node,
                    status,
                    verdict,
                    smart.options.prefer_asn,
                    now,
                );
            }
            Outcome::Exit(exit) => {
                let key = if matches!(job.kind, ProbeKind::TargetExit) {
                    advanced::pair(&host, &job.node)
                } else {
                    job.node.clone()
                };
                let map = if matches!(job.kind, ProbeKind::TargetExit) {
                    &mut smart.state.advanced.target_exits
                } else {
                    &mut smart.state.advanced.exits
                };
                if let Some(exit) = exit {
                    map.insert(key, exit);
                } else {
                    map.entry(key).or_default().failed = now;
                }
                smart
                    .state
                    .advanced
                    .confirm(&host, smart.options.prefer_asn, now);
            }
        }
        smart.state.advanced.trim();
        true
    }
    pub fn run_smart_probe_worker(&self, shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Acquire)
            && !self.smart_advanced.closed.load(Ordering::Acquire)
        {
            if !self.run_smart_probe_once() {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        self.stop_smart_probes();
    }
    pub fn stop_smart_probes(&self) {
        self.smart_advanced.closed.store(true, Ordering::Release);
        self.smart_advanced.invalidate();
    }
    pub fn start_smart_probes(&self) {
        self.smart_advanced.closed.store(false, Ordering::Release);
    }
    pub fn smart_diagnostics(&self, group: &str) -> Option<serde_json::Value> {
        let registry = self.registry.lock().unwrap();
        let smart = registry.groups.get(group)?.runtime.smart.as_ref()?;
        Some(
            serde_json::json!({"advanced":smart.state.advanced,"pending":self.smart_advanced.jobs.lock().unwrap().len(),"active":self.smart_advanced.probe_slots.load(Ordering::Relaxed)}),
        )
    }
}

fn execute(
    job: &ProbeJob,
    mut dialer: Box<dyn TcpDialer + Send>,
    control: Arc<DialControl>,
    geo: Option<&super::geodata::SmartGeoData>,
) -> Outcome {
    let host = advanced::host(&job.metadata);
    if matches!(job.kind, ProbeKind::Status) {
        let url = format!("https://{host}/robots.txt");
        return match fetch(job, &url, &mut dialer, control, 4096) {
            Ok(answer) => Outcome::Status(
                answer.status,
                response::classify(answer.status, &answer.headers, &answer.body, now_seconds()),
            ),
            Err(error) => Outcome::Status(
                0,
                response::classify_error(
                    &error.to_string(),
                    matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ),
                ),
            ),
        };
    }
    let urls = if matches!(job.kind, ProbeKind::TargetExit) {
        vec![format!("https://{host}/cdn-cgi/trace")]
    } else {
        EXIT_URLS.iter().map(|url| (*url).into()).collect()
    };
    for raw in urls {
        if control.is_cancelled() {
            break;
        }
        if let Ok(answer) = fetch(job, &raw, &mut dialer, control.clone(), 2048) {
            if answer.status == 200 {
                if let Some(exit) = parse_exit(&answer.body, geo, now_seconds()) {
                    return Outcome::Exit(Some(exit));
                }
            }
        }
    }
    Outcome::Exit(None)
}

fn fetch(
    job: &ProbeJob,
    raw: &str,
    dialer: &mut Box<dyn TcpDialer + Send>,
    control: Arc<DialControl>,
    limit: usize,
) -> io::Result<Answer> {
    let url = url::Url::parse(raw).map_err(io::Error::other)?;
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::other("probe URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::other("probe URL scheme"))?;
    let mut metadata = job.metadata.clone();
    metadata.host = Some(host.into());
    metadata.dst_ip = None;
    metadata.dst_port = Some(port);
    metadata.kind = mihomo_core::SessionKind::Inner;
    let transport = crate::build_transport_plan_from_execution_plan(&job.plan, &metadata)
        .map_err(io::Error::other)?;
    let fork = dialer
        .fork(8000)
        .ok_or_else(|| io::Error::other("probe requires a bounded dialer"))?;
    let mut executor = TcpTransportExecutor::new(ControlledDialer {
        inner: fork,
        control: control.clone(),
    });
    let mut stream =
        crate::run_transport_plan(&mut executor, &transport).map_err(io::Error::other)?;
    if url.scheme() == "https" {
        stream = mihomo_transport::wrap_tls_proxy_stream(
            stream,
            TransportTarget::new(host, port),
            &TlsOptions {
                enabled: true,
                sni: host.into(),
                ..Default::default()
            },
            &["http/1.1".into()],
        )
        .map_err(io::Error::other)?;
    } else {
        return Err(io::Error::other("Smart probes require HTTPS"));
    }
    let authority = if port == 443 {
        host.into()
    } else {
        format!("{host}:{port}")
    };
    // URLs are fixed or constructed from Url-validated hostnames. No cookies,
    // origin authorization, or request data from the user stream is reused.
    write!(stream,"GET {} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: mihomo-smart-probe\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",url.path())?;
    stream.flush()?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.len() > 32768 {
            return Err(io::Error::other("probe headers exceed 32 KiB"));
        }
    }
    let text = std::str::from_utf8(&head).map_err(io::Error::other)?;
    let mut lines = text.split("\r\n");
    let mut status_line = lines.next().unwrap_or("").split_whitespace();
    let protocol = status_line.next().unwrap_or("");
    let status = status_line
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|status| (100..600).contains(status))
        .ok_or_else(|| io::Error::other("invalid probe status"))?;
    if !matches!(protocol, "HTTP/1.0" | "HTTP/1.1") {
        return Err(io::Error::other("invalid probe HTTP version"));
    }
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().into()))
        .collect::<Headers>();
    control.timeouts(Duration::from_secs(1));
    let _ = stream.set_timeouts(Some(Duration::from_secs(1)), Some(Duration::from_secs(1)));
    let mut body = Vec::with_capacity(limit);
    // An uncooperative body must not discard already valid status/headers.
    // The outer deadline also caps slow trickles, independently of SO_RCVTIMEO.
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        let _ = read_chunked(&mut stream, &mut body, limit);
    } else {
        let expected = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(limit)
            .min(limit);
        let _ = stream.take(expected as u64).read_to_end(&mut body);
    }
    Ok(Answer {
        status,
        headers,
        body,
    })
}
fn read_chunked(stream: &mut BoxedTcpStream, body: &mut Vec<u8>, limit: usize) -> io::Result<()> {
    while body.len() < limit {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            stream.read_exact(&mut byte)?;
            line.push(byte[0]);
            if line.len() > 128 {
                return Err(io::Error::other("invalid probe chunk"));
            }
        }
        let size = usize::from_str_radix(
            std::str::from_utf8(&line)
                .map_err(io::Error::other)?
                .trim()
                .split(';')
                .next()
                .unwrap_or(""),
            16,
        )
        .map_err(io::Error::other)?;
        if size == 0 {
            return Ok(());
        }
        let take = size.min(limit - body.len());
        let start = body.len();
        body.resize(start + take, 0);
        stream.read_exact(&mut body[start..])?;
        if take < size {
            return Ok(());
        }
        let mut end = [0u8; 2];
        stream.read_exact(&mut end)?;
        if end != *b"\r\n" {
            return Err(io::Error::other("invalid probe chunk ending"));
        }
    }
    Ok(())
}
pub(super) fn parse_exit(
    body: &[u8],
    geo: Option<&super::geodata::SmartGeoData>,
    now: u64,
) -> Option<ExitInfo> {
    let text = std::str::from_utf8(body).ok()?;
    let mut region = String::new();
    let mut asn = String::new();
    let mut ip = None;
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
        region = json
            .get("country_code")
            .or_else(|| json.get("countryCode"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();
        ip = json
            .get("ip")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<std::net::IpAddr>().ok());
        let network = json
            .get("asn")
            .or_else(|| json.get("connection").and_then(|v| v.get("asn")));
        if let Some(value) = network {
            asn = value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_u64().map(|v| v.to_string()))
                .unwrap_or_default();
        }
    } else {
        for line in text.lines() {
            if let Some((k, v)) = line.trim().split_once('=') {
                match k {
                    "loc" => region = v.into(),
                    "ip" => ip = v.parse().ok(),
                    _ => {}
                }
            }
        }
    }
    let ip = ip?;
    let mut meta = Metadata {
        dst_ip: Some(ip),
        ..Default::default()
    };
    if let Some(geo) = geo {
        geo.enrich(&mut meta);
    }
    if region.is_empty() {
        region = meta
            .dst_geoip
            .as_ref()
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
    }
    if asn.is_empty() {
        asn = super::target::asn(&meta).into();
    }
    asn = asn
        .trim()
        .trim_start_matches("AS")
        .trim_start_matches("as")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .into();
    if !asn.bytes().all(|b| b.is_ascii_digit()) {
        asn.clear();
    }
    region = region.to_ascii_uppercase();
    if region.len() != 2 || !region.bytes().all(|b| b.is_ascii_alphabetic()) {
        region.clear();
    }
    if region.is_empty() && asn.is_empty() {
        return None;
    }
    let bytes = match ip {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    };
    let hash = Sha256::digest(&bytes);
    let key = hash[..6].iter().map(|byte| format!("{byte:02x}")).collect();
    Some(ExitInfo {
        region,
        asn,
        key,
        updated: now,
        failed: 0,
    })
}
