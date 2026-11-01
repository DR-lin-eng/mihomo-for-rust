use super::Observation;
use crate::{ExecutionPlan, RuntimeRegistry};
use mihomo_core::{BoxedTcpStream, Metadata, TcpStream};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone)]
pub struct SmartTracker {
    inner: Arc<Metrics>,
}
impl std::fmt::Debug for SmartTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartTracker")
            .field("groups", &self.inner.groups)
            .finish()
    }
}
struct Metrics {
    registry: Arc<Mutex<RuntimeRegistry>>,
    groups: Vec<(String, String)>,
    metadata: Metadata,
    start: Instant,
    connect_ms: u64,
    upload: AtomicU64,
    download: AtomicU64,
    first_byte_ms: AtomicU64,
    failed: AtomicBool,
    rates: Mutex<RateWindow>,
    loss: Mutex<super::loss::LossSampler>,
    advanced: Arc<super::advanced::AdvancedRuntime>,
    generation: u64,
    plan: ExecutionPlan,
}
struct RateWindow {
    start: Instant,
    up: u64,
    down: u64,
    peak_up: f64,
    peak_down: f64,
}
impl SmartTracker {
    pub(crate) fn new(
        registry: Arc<Mutex<RuntimeRegistry>>,
        metadata: &Metadata,
        plan: &ExecutionPlan,
        connect_ms: u64,
        advanced: Arc<super::advanced::AdvancedRuntime>,
    ) -> Option<Self> {
        let mut groups = Vec::new();
        {
            let locked = registry.lock().unwrap();
            for path in plan.selected_path.windows(2) {
                if let Some(view) = locked.groups.get(&path[0]) {
                    if view.runtime.smart.is_some() {
                        let probe = url::Url::parse(&view.runtime.test_url)
                            .ok()
                            .and_then(|url| url.host_str().map(str::to_owned));
                        if metadata.kind == mihomo_core::SessionKind::Inner
                            && metadata
                                .host
                                .as_deref()
                                .zip(probe.as_deref())
                                .is_some_and(|(host, probe)| host.eq_ignore_ascii_case(probe))
                        {
                            continue;
                        }
                        groups.push((path[0].clone(), path[1].clone()));
                    }
                }
            }
        }
        if groups.is_empty() {
            return None;
        }
        Some(Self {
            inner: Arc::new(Metrics {
                registry,
                groups,
                metadata: metadata.clone(),
                start: Instant::now(),
                connect_ms,
                generation: advanced.generation.load(Ordering::Acquire),
                advanced,
                plan: plan.clone(),
                loss: Mutex::new(super::loss::LossSampler::default()),
                upload: AtomicU64::new(0),
                download: AtomicU64::new(0),
                first_byte_ms: AtomicU64::new(0),
                failed: AtomicBool::new(false),
                rates: Mutex::new(RateWindow {
                    start: Instant::now(),
                    up: 0,
                    down: 0,
                    peak_up: 0.0,
                    peak_down: 0.0,
                }),
            }),
        })
    }
    pub fn record_upload(&self, bytes: usize) {
        self.inner.upload.fetch_add(bytes as u64, Ordering::Relaxed);
        self.record_rate(bytes as u64, 0);
    }
    pub fn record_download(&self, bytes: usize) {
        self.inner
            .download
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if bytes > 0 {
            let value = self
                .inner
                .connect_ms
                .saturating_add(self.inner.start.elapsed().as_millis() as u64)
                .max(1);
            let _ = self.inner.first_byte_ms.compare_exchange(
                0,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        self.record_rate(0, bytes as u64);
    }
    pub fn record_failure(&self) {
        self.inner.failed.store(true, Ordering::Relaxed);
    }
    fn record_rate(&self, upload: u64, download: u64) {
        let mut rates = self.inner.rates.lock().unwrap();
        rates.up = rates.up.saturating_add(upload);
        rates.down = rates.down.saturating_add(download);
        if rates.start.elapsed().as_millis() >= 500 {
            rates.flush();
        }
    }
}
impl RateWindow {
    fn flush(&mut self) {
        let seconds = self.start.elapsed().as_secs_f64().max(0.05);
        self.peak_up = self.peak_up.max(self.up as f64 / 1024.0 / seconds);
        self.peak_down = self.peak_down.max(self.down as f64 / 1024.0 / seconds);
        self.up = 0;
        self.down = 0;
        self.start = Instant::now();
    }
}
impl Drop for Metrics {
    fn drop(&mut self) {
        if self.generation != self.advanced.generation.load(Ordering::Acquire) {
            return;
        }
        let rates = self.rates.get_mut().unwrap();
        rates.flush();
        let observation = Observation {
            success: !self.failed.load(Ordering::Relaxed)
                && (self.metadata.network != mihomo_core::NetworkKind::Udp
                    || self.download.load(Ordering::Relaxed) > 0),
            connect_ms: self.connect_ms,
            latency_ms: self.first_byte_ms.load(Ordering::Relaxed),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            duration_ms: self.start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            max_upload_kb: rates.peak_up,
            max_download_kb: rates.peak_down,
            tcp_segments: self.loss.get_mut().unwrap().segments,
            tcp_retransmissions: self.loss.get_mut().unwrap().retransmissions,
            tcp_loss_windows: self.loss.get_mut().unwrap().windows,
            tcp_loss_ema: self.loss.get_mut().unwrap().ema,
            tcp_loss_strikes: self.loss.get_mut().unwrap().strikes,
            tcp_loss_last: self.loss.get_mut().unwrap().last_rate,
        };
        let Ok(mut registry) = self.registry.lock() else {
            return;
        };
        if self.generation != self.advanced.generation.load(Ordering::Acquire) {
            return;
        }
        for (group, node) in &self.groups {
            if let Some(smart) = registry
                .groups
                .get_mut(group)
                .and_then(|view| view.runtime.smart.as_mut())
            {
                smart.observe(group, node, &self.metadata, &observation);
            }
        }
        self.advanced.schedule(
            &mut registry,
            &self.metadata,
            &self.plan,
            observation.download,
        );
    }
}

pub(crate) struct SmartStream {
    stream: BoxedTcpStream,
    tracker: SmartTracker,
}
impl SmartStream {
    pub(crate) fn wrap(stream: BoxedTcpStream, tracker: SmartTracker) -> BoxedTcpStream {
        tracker
            .inner
            .loss
            .lock()
            .unwrap()
            .sample(stream.tcp_stats());
        Box::new(Self { stream, tracker })
    }
}
impl Read for SmartStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = self.stream.read(buffer);
        self.tracker
            .inner
            .loss
            .lock()
            .unwrap()
            .sample(self.stream.tcp_stats());
        match &result {
            Ok(size) => self.tracker.record_download(*size),
            Err(error) if feedback_error(error) => self.tracker.record_failure(),
            _ => {}
        }
        result
    }
}
impl Write for SmartStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let result = self.stream.write(buffer);
        self.tracker
            .inner
            .loss
            .lock()
            .unwrap()
            .sample(self.stream.tcp_stats());
        match &result {
            Ok(size) => self.tracker.record_upload(*size),
            Err(error) if feedback_error(error) => self.tracker.record_failure(),
            _ => {}
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn feedback_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::BrokenPipe
    )
}
impl TcpStream for SmartStream {
    fn tcp_stats(&self) -> Option<mihomo_core::TcpStats> {
        self.stream.tcp_stats()
    }
    fn set_timeouts(
        &self,
        read: Option<std::time::Duration>,
        write: Option<std::time::Duration>,
    ) -> io::Result<()> {
        self.stream.set_timeouts(read, write)
    }
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            stream: self.stream.try_clone_box()?,
            tracker: self.tracker.clone(),
        }))
    }
    fn supports_tls_passthrough(&self) -> bool {
        self.stream.supports_tls_passthrough()
    }
    fn start_tls_passthrough_read(&mut self) -> io::Result<()> {
        self.stream.start_tls_passthrough_read()
    }
    fn start_tls_passthrough_write(&mut self) -> io::Result<()> {
        self.stream.start_tls_passthrough_write()
    }
    fn shutdown_write(&mut self) -> io::Result<()> {
        self.stream.shutdown_write()
    }
    fn shutdown_all(&mut self) -> io::Result<()> {
        self.stream.shutdown_all()
    }
}
impl Drop for SmartStream {
    fn drop(&mut self) {
        self.tracker
            .inner
            .loss
            .lock()
            .unwrap()
            .sample(self.stream.tcp_stats());
    }
}
