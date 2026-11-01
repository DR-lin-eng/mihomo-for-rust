use super::{
    now_seconds,
    response::{self, Action, Verdict},
    target,
};
use crate::ExecutionPlan;
use mihomo_core::Metadata;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

pub const MAX_ADVANCED_ENTRIES: usize = 2048;
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExitInfo {
    pub region: String,
    pub asn: String,
    pub key: String,
    pub updated: u64,
    pub failed: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeRecord {
    pub verdict: Verdict,
    pub status: u16,
    pub updated: u64,
    pub until: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pin {
    pub node: String,
    pub until: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Prefetch {
    pub nodes: Vec<String>,
    pub updated: u64,
    pub fingerprint: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedState {
    pub probes: BTreeMap<String, ProbeRecord>,
    pub exits: BTreeMap<String, ExitInfo>,
    pub target_exits: BTreeMap<String, ExitInfo>,
    pub evidence: BTreeMap<String, BTreeMap<String, u32>>,
    pub pins: BTreeMap<String, Pin>,
    pub suspects: BTreeMap<String, u64>,
    pub half_open: BTreeMap<String, Pin>,
    #[serde(skip)]
    pub last_probe: BTreeMap<String, u64>,
    #[serde(skip)]
    pub target_windows: BTreeMap<String, (u64, u32)>,
    pub races: u64,
    pub cancelled: u64,
    pub probes_completed: u64,
    pub probes_dropped: u64,
    #[serde(skip)]
    pub prefetch: BTreeMap<String, Prefetch>,
}
pub fn host(metadata: &Metadata) -> String {
    metadata
        .host
        .as_deref()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_lowercase()
}
pub fn pair(host: &str, node: &str) -> String {
    format!("{host}\u{1f}{node}")
}
impl AdvancedState {
    pub fn half_open_candidate(
        &mut self,
        metadata: &Metadata,
        candidates: &[crate::ProxyCandidate],
        now: u64,
    ) -> Option<String> {
        let host = host(metadata);
        if self
            .half_open
            .get(&host)
            .is_some_and(|lease| lease.until > now)
        {
            return None;
        }
        let node = candidates
            .iter()
            .filter(|c| c.alive)
            .min_by_key(|c| {
                self.probes
                    .get(&pair(&host, &c.name))
                    .map_or(0, |record| record.updated)
            })?
            .name
            .clone();
        self.half_open.insert(
            host,
            Pin {
                node: node.clone(),
                until: now + 30,
            },
        );
        Some(node)
    }
    pub fn trim(&mut self) {
        let now = now_seconds();
        self.probes
            .retain(|_, entry| now.saturating_sub(entry.updated) < 3600);
        self.suspects.retain(|_, until| *until > now);
        self.pins.retain(|_, pin| pin.until > now);
        self.half_open.retain(|_, pin| pin.until > now);
        while self.probes.len() >= MAX_ADVANCED_ENTRIES {
            if let Some(key) = self
                .probes
                .iter()
                .min_by_key(|(_, record)| record.updated)
                .map(|(key, _)| key.clone())
            {
                self.probes.remove(&key);
            } else {
                break;
            }
        }
        for map in [&mut self.exits, &mut self.target_exits] {
            while map.len() >= MAX_ADVANCED_ENTRIES {
                if let Some(key) = map
                    .iter()
                    .min_by_key(|(_, record)| record.updated.max(record.failed))
                    .map(|(key, _)| key.clone())
                {
                    map.remove(&key);
                } else {
                    break;
                }
            }
        }
        for map in [&mut self.last_probe] {
            while map.len() > MAX_ADVANCED_ENTRIES {
                map.pop_first();
            }
        }
        while self.target_windows.len() > MAX_ADVANCED_ENTRIES {
            self.target_windows.pop_first();
        }
        while self.evidence.len() > MAX_ADVANCED_ENTRIES {
            self.evidence.pop_first();
        }
        while self.suspects.len() > MAX_ADVANCED_ENTRIES {
            self.suspects.pop_first();
        }
        while self.pins.len() > MAX_ADVANCED_ENTRIES {
            self.pins.pop_first();
        }
        while self.half_open.len() > MAX_ADVANCED_ENTRIES {
            self.half_open.pop_first();
        }
        while self.prefetch.len() > 128 {
            if let Some(key) = self
                .prefetch
                .iter()
                .min_by_key(|(_, entry)| entry.updated)
                .map(|(key, _)| key.clone())
            {
                self.prefetch.remove(&key);
            } else {
                break;
            }
        }
    }
    pub fn exit(&self, host: &str, node: &str, now: u64) -> Option<&ExitInfo> {
        self.target_exits
            .get(&pair(host, node))
            .filter(|entry| {
                (!entry.region.is_empty() || !entry.asn.is_empty())
                    && now.saturating_sub(entry.updated) < 21600
            })
            .or_else(|| {
                self.exits.get(node).filter(|entry| {
                    (!entry.region.is_empty() || !entry.asn.is_empty())
                        && now.saturating_sub(entry.updated) < 21600
                })
            })
    }
    pub fn suspected(&self, host: &str, node: &str, prefer_asn: bool, now: u64) -> bool {
        let Some(exit) = self.exit(host, node, now) else {
            return false;
        };
        self.suspects
            .get(&format!("{host}\u{1f}region:{}", exit.region))
            .is_some_and(|until| *until > now)
            || prefer_asn
                && self
                    .suspects
                    .get(&format!("{host}\u{1f}asn:{}", exit.asn))
                    .is_some_and(|until| *until > now)
    }
    pub fn blocked(&self, metadata: &Metadata, node: &str, prefer_asn: bool, now: u64) -> bool {
        let host = host(metadata);
        self.probes
            .get(&pair(&host, node))
            .is_some_and(|record| record.verdict.action == Action::Record && record.until > now)
            || self.suspected(&host, node, prefer_asn, now)
    }
    pub fn apply_verdict(
        &mut self,
        host: &str,
        node: &str,
        status: u16,
        verdict: Verdict,
        prefer_asn: bool,
        now: u64,
    ) {
        self.trim();
        if verdict.action != Action::Ignore {
            self.probes.insert(
                pair(host, node),
                ProbeRecord {
                    until: now.saturating_add(verdict.ttl),
                    status,
                    updated: now,
                    verdict: verdict.clone(),
                },
            );
        }
        if verdict.action == Action::Record {
            self.pins.clear();
            self.prefetch.clear();
        }
        if verdict.control_success {
            self.half_open.remove(host);
            if let Some(exit) = self.exit(host, node, now).cloned() {
                self.suspects
                    .remove(&format!("{host}\u{1f}region:{}", exit.region));
                self.suspects
                    .remove(&format!("{host}\u{1f}asn:{}", exit.asn));
            }
        }
        self.probes_completed = self.probes_completed.saturating_add(1);
        self.confirm(host, prefer_asn, now);
    }
    pub fn confirm(&mut self, host: &str, prefer_asn: bool, now: u64) {
        let prefix = format!("{host}\u{1f}");
        let mut refusals = BTreeMap::<String, std::collections::BTreeSet<String>>::new();
        let mut controls = Vec::<(String, String)>::new();
        for (key, record) in &self.probes {
            let Some(node) = key.strip_prefix(&prefix) else {
                continue;
            };
            if now.saturating_sub(record.updated) > 600 {
                continue;
            }
            let Some(exit) = self.exit(host, node, now) else {
                continue;
            };
            let identity = if exit.key.is_empty() { node } else { &exit.key };
            if record.verdict.control_success {
                if !exit.region.is_empty() {
                    controls.push((format!("region:{}", exit.region), identity.into()));
                }
                if prefer_asn && !exit.asn.is_empty() {
                    controls.push((format!("asn:{}", exit.asn), identity.into()));
                }
            }
            if record.verdict.action == Action::Record
                && response::regional_reason(&record.verdict.reason)
            {
                if !exit.region.is_empty() {
                    refusals
                        .entry(format!("region:{}", exit.region))
                        .or_default()
                        .insert(identity.into());
                }
                if prefer_asn && !exit.asn.is_empty() {
                    refusals
                        .entry(format!("asn:{}", exit.asn))
                        .or_default()
                        .insert(identity.into());
                }
            }
        }
        for (key, identities) in refusals {
            let kind = key.split(':').next().unwrap();
            if identities.len() >= 2
                && !controls.iter().any(|(other, _)| *other == key)
                && controls.iter().any(|(other, identity)| {
                    other.starts_with(kind) && *other != key && !identities.contains(identity)
                })
            {
                self.suspects
                    .insert(format!("{host}\u{1f}{key}"), now + 1800);
                self.pins.clear();
            }
        }
    }
    pub fn allow_probe(&mut self, host: &str, node: &str, now: u64) -> bool {
        self.trim();
        let key = pair(host, node);
        let record = self.probes.get(&key);
        let failed = record.is_some_and(|record| {
            record.verdict.action == Action::Record && now.saturating_sub(record.updated) < 600
        });
        let gap = if failed { 30 } else { 120 };
        if self
            .last_probe
            .get(&key)
            .is_some_and(|last| now.saturating_sub(*last) < gap)
        {
            return false;
        }
        let window = self.target_windows.entry(host.into()).or_insert((now, 0));
        if now.saturating_sub(window.0) >= 60 {
            *window = (now, 0);
        }
        if window.1 >= 6 {
            return false;
        }
        // Three independent refusals without any control answer mean the host is
        // probably down. Avoid repeatedly probing every exit until the hold expires.
        let prefix = format!("{host}\u{1f}");
        let mut failures = 0;
        let mut control = false;
        for (key, record) in &self.probes {
            if key.starts_with(&prefix) && now.saturating_sub(record.updated) < 1800 {
                if record.verdict.control_success {
                    control = true;
                } else if [
                    "region unavailable",
                    "forbidden",
                    "origin error",
                    "unknown certificate authority",
                    "certificate hostname mismatch",
                ]
                .contains(&record.verdict.reason.as_str())
                {
                    failures += 1;
                }
            }
        }
        if failures >= 3 && !control {
            return false;
        }
        self.last_probe.insert(key, now);
        window.1 += 1;
        true
    }
    pub fn note_evidence(&mut self, metadata: &Metadata) {
        let Some((rule, count)) = &metadata.smart_rule else {
            return;
        };
        let network = target::asn(metadata);
        if rule.is_empty()
            || *count >= 10000
            || network.is_empty()
            || super::features::shared_asn(network)
        {
            return;
        }
        let entries = self.evidence.entry(rule.clone()).or_default();
        if entries.len() < 32 || entries.contains_key(network) {
            let hits = entries.entry(network.into()).or_default();
            *hits = hits.saturating_add(1);
        }
        self.trim();
    }
}
#[derive(Clone, Debug)]
pub enum ProbeKind {
    Status,
    Exit,
    TargetExit,
}
#[derive(Clone, Debug)]
pub struct ProbeJob {
    pub group: String,
    pub node: String,
    pub metadata: Metadata,
    pub plan: ExecutionPlan,
    pub kind: ProbeKind,
    pub generation: u64,
}
#[derive(Debug)]
pub struct AdvancedRuntime {
    pub jobs: Mutex<VecDeque<ProbeJob>>,
    pub closed: AtomicBool,
    pub generation: std::sync::atomic::AtomicU64,
    tokens: Mutex<(u64, f64)>,
    pub dial_slots: Arc<AtomicUsize>,
    pub probe_slots: Arc<AtomicUsize>,
    pub controls: Mutex<Vec<std::sync::Weak<super::race::DialControl>>>,
}
impl Default for AdvancedRuntime {
    fn default() -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            generation: std::sync::atomic::AtomicU64::new(1),
            tokens: Mutex::new((now_seconds(), 10.0)),
            dial_slots: Arc::new(AtomicUsize::new(0)),
            probe_slots: Arc::new(AtomicUsize::new(0)),
            controls: Mutex::new(Vec::new()),
        }
    }
}
impl AdvancedRuntime {
    pub fn enqueue(&self, job: ProbeJob) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let mut jobs = self.jobs.lock().unwrap();
        if jobs.len() >= 128 {
            return false;
        }
        if matches!(job.kind, ProbeKind::Status) {
            let mut bucket = self.tokens.lock().unwrap();
            let now = now_seconds();
            bucket.1 = (bucket.1 + now.saturating_sub(bucket.0) as f64 * 2.0).min(10.0);
            bucket.0 = now;
            if bucket.1 < 1.0 {
                return false;
            }
            bucket.1 -= 1.0;
            jobs.push_front(job);
        } else {
            jobs.push_back(job);
        }
        true
    }
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.jobs.lock().unwrap().clear();
        for control in self
            .controls
            .lock()
            .unwrap()
            .drain(..)
            .filter_map(|control| control.upgrade())
        {
            control.cancel();
        }
    }
    pub fn schedule(
        &self,
        registry: &mut crate::RuntimeRegistry,
        metadata: &Metadata,
        plan: &ExecutionPlan,
        download: u64,
    ) {
        if self.closed.load(Ordering::Acquire)
            || metadata.network != mihomo_core::NetworkKind::Tcp
            || metadata.kind == mihomo_core::SessionKind::Inner
        {
            return;
        }
        let now = now_seconds();
        let host = host(metadata);
        let eligible = !host.is_empty()
            && host.parse::<std::net::IpAddr>().is_err()
            && metadata.dst_port == Some(443)
            && download < 31457;
        let generation = self.generation.load(Ordering::Acquire);
        for names in plan.selected_path.windows(2) {
            let Some(smart) = registry
                .groups
                .get_mut(&names[0])
                .and_then(|view| view.runtime.smart.as_mut())
            else {
                continue;
            };
            let job = |kind| ProbeJob {
                group: names[0].clone(),
                node: names[1].clone(),
                metadata: metadata.clone(),
                plan: plan.clone(),
                kind,
                generation,
            };
            if eligible
                && smart.state.advanced.allow_probe(&host, &names[1], now)
                && !self.enqueue(job(ProbeKind::Status))
            {
                smart.state.advanced.probes_dropped += 1;
            }
            let exit = smart
                .state
                .advanced
                .exits
                .entry(names[1].clone())
                .or_default();
            if (exit.updated == 0 || now.saturating_sub(exit.updated) >= 21600)
                && (exit.failed == 0 || now.saturating_sub(exit.failed) >= 900)
            {
                exit.failed = now;
                if !self.enqueue(job(ProbeKind::Exit)) {
                    smart.state.advanced.probes_dropped += 1;
                }
            }
            if eligible {
                let exit = smart
                    .state
                    .advanced
                    .target_exits
                    .entry(pair(&host, &names[1]))
                    .or_default();
                if (exit.updated == 0 || now.saturating_sub(exit.updated) >= 21600)
                    && (exit.failed == 0 || now.saturating_sub(exit.failed) >= 900)
                {
                    exit.failed = now;
                    if !self.enqueue(job(ProbeKind::TargetExit)) {
                        smart.state.advanced.probes_dropped += 1;
                    }
                }
            }
            smart.state.advanced.trim();
        }
    }
}
