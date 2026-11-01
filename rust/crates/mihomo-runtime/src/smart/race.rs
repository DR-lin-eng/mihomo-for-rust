//! Bounded first-success protocol dials, following Smart Alpha's 3 + 5 schedule.
use super::{advanced, now_seconds};
use crate::{
    build_execution_plan, build_transport_plan_from_execution_plan, run_transport_plan,
    ExecutionError, ExecutionPlan, ProxyCandidate, RuntimeTunnel,
};
use mihomo_core::{BoxedTcpStream, Metadata};
use mihomo_transport::{
    NetTcpStreamAddr, SocketOptions, TcpDialPurpose, TcpDialer, TcpTransportExecutor,
    TransportError, TransportTarget,
};
use std::io;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct DialControl {
    cancelled: AtomicBool,
    sockets: Mutex<Vec<BoxedTcpStream>>,
}
impl std::fmt::Debug for DialControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialControl")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}
impl DialControl {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        for mut socket in self.sockets.lock().unwrap().drain(..) {
            let _ = socket.shutdown_all();
        }
    }
    pub fn release(&self) {
        for socket in self.sockets.lock().unwrap().drain(..) {
            let _ = socket.set_timeouts(None, None);
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    pub fn timeouts(&self, timeout: Duration) {
        for socket in self.sockets.lock().unwrap().iter() {
            let _ = socket.set_timeouts(Some(timeout), Some(timeout));
        }
    }
}
pub(super) struct ControlledDialer {
    pub inner: Box<dyn TcpDialer + Send>,
    pub control: Arc<DialControl>,
}
impl TcpDialer for ControlledDialer {
    fn resolve_addrs(
        &mut self,
        target: &TransportTarget,
        socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<Vec<NetTcpStreamAddr>, TransportError> {
        self.inner.resolve_addrs(target, socket, purpose)
    }
    fn connect(
        &mut self,
        target: &TransportTarget,
        socket: &SocketOptions,
        purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        if self.control.is_cancelled() {
            return Err(cancelled());
        }
        let mut stream = self.inner.connect(target, socket, purpose)?;
        let mut handles = self.control.sockets.lock().unwrap();
        if self.control.is_cancelled() {
            let _ = stream.shutdown_all();
            return Err(cancelled());
        }
        // These are raw underlays, before TLS/proxy wrappers are installed.
        handles.push(stream.try_clone_box()?);
        Ok(stream)
    }
}
fn cancelled() -> TransportError {
    TransportError::Io {
        kind: io::ErrorKind::Interrupted,
        message: "Smart dial cancelled".into(),
    }
}
fn timed_out() -> ExecutionError {
    TransportError::Io {
        kind: io::ErrorKind::TimedOut,
        message: "Smart protocol dial deadline exceeded".into(),
    }
    .into()
}

struct Slot(Arc<AtomicUsize>);
impl Slot {
    fn acquire(slots: &Arc<AtomicUsize>) -> Option<Self> {
        slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 16).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(slots.clone()))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl RuntimeTunnel {
    /// None means a custom dialer has not opted into independent bounded forks.
    pub(crate) fn connect_smart_race<D: TcpDialer>(
        &self,
        metadata: &Metadata,
        first: &ExecutionPlan,
        dialer: &D,
    ) -> Option<Result<(BoxedTcpStream, ExecutionPlan), ExecutionError>> {
        dialer.fork(10000)?;
        if self.smart_advanced.dial_slots.load(Ordering::Acquire) >= 16 {
            // Existing listener threads can still dial sequentially when the
            // extra race-worker budget is occupied by other connections.
            return None;
        }
        let states = self.candidate_states.lock().unwrap().clone();
        let (plans, pinned, sequential) = {
            let mut registry = self.registry.lock().unwrap();
            let group = first
                .selected_path
                .windows(2)
                .find(|pair| {
                    registry
                        .groups
                        .get(&pair[0])
                        .is_some_and(|view| view.runtime.smart.is_some())
                })?
                .to_vec();
            let view = registry.groups.get(&group[0])?;
            let smart = view.runtime.smart.as_ref()?;
            let now = now_seconds();
            let pinned = first.selected_path.iter().any(|name| {
                registry.groups.get(name).is_some_and(|view| {
                    view.runtime.smart.is_some() && view.runtime.selected().is_some()
                })
            });
            let auto_pin = smart
                .state
                .advanced
                .pins
                .get(&smart.target_key(metadata))
                .is_some_and(|pin| pin.until > now && pin.node == group[1]);
            let mut candidates = view
                .candidate_names
                .iter()
                .map(|name| {
                    let state = states.get(name);
                    ProxyCandidate {
                        name: name.clone(),
                        alive: state.is_none_or(|s| s.alive),
                        last_delay_ms: state.map_or(0, |s| s.last_delay_ms),
                        supports_udp: true,
                    }
                })
                .filter(|c| {
                    c.alive
                        && !smart.state.advanced.blocked(
                            metadata,
                            &c.name,
                            smart.options.prefer_asn,
                            now,
                        )
                })
                .filter(|c| {
                    smart
                        .state
                        .records
                        .get(&smart.record_key(metadata, &c.name))
                        .is_none_or(|s| {
                            (s.failed_at == 0 || now.saturating_sub(s.failed_at) >= 30)
                                && s.loss_block_until <= now
                        })
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|a, b| {
                smart
                    .score(b, Some(metadata), now)
                    .total_cmp(&smart.score(a, Some(metadata), now))
            });
            candidates.retain(|c| c.name != group[1]);
            candidates.insert(
                0,
                ProxyCandidate {
                    name: group[1].clone(),
                    alive: true,
                    last_delay_ms: 0,
                    supports_udp: true,
                },
            );
            // A manual selection is a strict exit contract. A cached selection
            // is tried first and uses sequential fallback if it fails.
            candidates.truncate(if pinned { 1 } else { 10 });
            let saved = registry
                .groups
                .get(&group[0])
                .and_then(|v| v.runtime.selected())
                .map(str::to_owned);
            let mut plans = Vec::new();
            for candidate in candidates {
                registry
                    .groups
                    .get_mut(&group[0])
                    .unwrap()
                    .runtime
                    .set_selected(&candidate.name);
                if let Ok(plan) =
                    build_execution_plan(&mut registry, &first.requested, Some(metadata), &states)
                {
                    if plans
                        .iter()
                        .any(|(old, _): &(ExecutionPlan, u64)| old.hops == plan.hops)
                    {
                        continue;
                    }
                    let smart = registry
                        .groups
                        .get(&group[0])
                        .unwrap()
                        .runtime
                        .smart
                        .as_ref()
                        .unwrap();
                    let timeout = smart
                        .stats_for(Some(metadata), &candidate.name)
                        .map(|s| s.input.connect_time * 5.0)
                        .filter(|ms| ms.is_finite() && *ms > 0.0)
                        .unwrap_or(10000.0)
                        .clamp(250.0, 10000.0) as u64;
                    plans.push((plan, timeout));
                }
            }
            let runtime = &mut registry.groups.get_mut(&group[0]).unwrap().runtime;
            if let Some(saved) = saved {
                runtime.set_selected(saved);
            } else {
                runtime.clear_selected();
            }
            (plans, pinned, auto_pin)
        };
        if plans.is_empty() {
            return Some(Err(timed_out()));
        }
        let mut remaining = plans.into_iter();
        let mut last = timed_out();
        // Successful protocol setup (CONNECT/SOCKS/TLS/etc.), never mere TCP
        // accept, wins. No application bytes are duplicated onto race losers.
        let batches = if sequential {
            vec![1; 10]
        } else {
            vec![1, 1, 1, 5, 2]
        };
        for batch_size in batches {
            let batch = remaining.by_ref().take(batch_size).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            let (sender, receiver) = mpsc::channel();
            let mut controls = Vec::new();
            let mut expected = 0;
            let mut deadline = Duration::from_millis(1);
            for (plan, timeout) in batch {
                let Some(slot) = Slot::acquire(&self.smart_advanced.dial_slots) else {
                    if expected == 0 {
                        return None;
                    }
                    continue;
                };
                let Some(fork) = dialer.fork(timeout) else {
                    continue;
                };
                let transport = match build_transport_plan_from_execution_plan(&plan, metadata) {
                    Ok(p) => p,
                    Err(e) => {
                        last = e;
                        continue;
                    }
                };
                let control = Arc::new(DialControl::default());
                controls.push((plan.clone(), control.clone()));
                let sender = sender.clone();
                let start = Instant::now();
                deadline = deadline.max(Duration::from_millis(timeout));
                let result =
                    std::thread::Builder::new()
                        .name("smart-dial".into())
                        .spawn(move || {
                            let _slot = slot;
                            let mut executor = TcpTransportExecutor::new(ControlledDialer {
                                inner: fork,
                                control: control.clone(),
                            });
                            let result = run_transport_plan(&mut executor, &transport);
                            if control.is_cancelled() {
                                if let Ok(mut stream) = result {
                                    let _ = stream.shutdown_all();
                                }
                                return;
                            }
                            // A disconnected receiver drops and closes a late winner.
                            let _ = sender.send((plan, result, start.elapsed().as_millis() as u64));
                        });
                if result.is_ok() {
                    expected += 1;
                }
            }
            drop(sender);
            if expected > 1 {
                let mut registry = self.registry.lock().unwrap();
                for path in first.selected_path.windows(2) {
                    if let Some(smart) = registry
                        .groups
                        .get_mut(&path[0])
                        .and_then(|view| view.runtime.smart.as_mut())
                    {
                        smart.state.advanced.races = smart.state.advanced.races.saturating_add(1);
                    }
                }
            }
            let started = Instant::now();
            let mut finished = std::collections::BTreeSet::new();
            while expected > 0 {
                let result = receiver.recv_timeout(deadline.saturating_sub(started.elapsed()));
                let (plan, result, elapsed) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                expected -= 1;
                finished.insert(plan.selected_path.clone());
                match result {
                    Ok(stream) => {
                        let _ = stream.set_timeouts(None, None);
                        for (other, control) in &controls {
                            if other.selected_path == plan.selected_path {
                                control.release();
                            } else {
                                control.cancel();
                            }
                        }
                        self.note_smart_winner(
                            metadata,
                            &plan,
                            controls.len().saturating_sub(finished.len()) as u64,
                        );
                        let stream =
                            if let Some(tracker) = self.smart_tracker(metadata, &plan, elapsed) {
                                super::SmartStream::wrap(stream, tracker)
                            } else {
                                stream
                            };
                        return Some(Ok((stream, plan)));
                    }
                    Err(error) => {
                        self.record_smart_dial_failure(metadata, &plan, elapsed);
                        last = error.with_dial_context(&plan,metadata);
                    }
                }
            }
            for (plan, control) in controls {
                control.cancel();
                if !finished.contains(&plan.selected_path) {
                    self.record_smart_dial_failure(metadata, &plan, deadline.as_millis() as u64);
                }
            }
            if pinned {
                break;
            }
        }
        Some(Err(last))
    }
    pub(super) fn note_smart_winner(
        &self,
        metadata: &Metadata,
        plan: &ExecutionPlan,
        cancelled: u64,
    ) {
        let now = now_seconds();
        let mut registry = self.registry.lock().unwrap();
        for pair in plan.selected_path.windows(2) {
            if let Some(smart) = registry
                .groups
                .get_mut(&pair[0])
                .and_then(|v| v.runtime.smart.as_mut())
            {
                smart.state.advanced.pins.insert(
                    smart.target_key(metadata),
                    advanced::Pin {
                        node: pair[1].clone(),
                        until: now + 600,
                    },
                );
                smart.state.advanced.cancelled =
                    smart.state.advanced.cancelled.saturating_add(cancelled);
                smart.state.last_used = now;
                smart.state.advanced.trim();
            }
        }
    }
}
