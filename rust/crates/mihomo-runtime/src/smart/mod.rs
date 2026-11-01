pub mod features;
pub mod model;
mod runtime;
mod stream;
pub(crate) use runtime::SmartContext;
mod advanced;
mod download;
mod geodata;
mod loss;
mod probe;
mod race;
pub mod response;
pub mod target;
mod weight;
pub(crate) use advanced::AdvancedRuntime;

use crate::ProxyCandidate;
use features::ModelInput;
use mihomo_core::{Metadata, NetworkKind};
use mihomo_outbound::GroupDefinition;
use model::LightGbmModel;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use stream::SmartStream;
pub use stream::SmartTracker;
pub const DEFAULT_MODEL_URL: &str =
    "https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model.bin";
const MAX_RECORDS: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmartOptions {
    pub use_lightgbm: bool,
    pub collect_data: bool,
    pub sample_rate_ppm: u32,
    pub prefer_asn: bool,
    pub policy_priority: String,
    pub tolerance_ms: u16,
}
impl SmartOptions {
    pub fn from_definition(definition: &GroupDefinition) -> Self {
        let get = |key: &str| definition.extra.get(key);
        let rate = get("sample-rate")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value > 0.0 && *value <= 1.0)
            .unwrap_or(1.0);
        Self {
            use_lightgbm: get("uselightgbm").and_then(Value::as_bool).unwrap_or(false),
            collect_data: get("collectdata").and_then(Value::as_bool).unwrap_or(false),
            sample_rate_ppm: (rate * 1_000_000.0).round().max(1.0) as u32,
            prefer_asn: get("prefer-asn").and_then(Value::as_bool).unwrap_or(false),
            policy_priority: get("policy-priority")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            tolerance_ms: definition.tolerance.clamp(0, 65535) as u16,
        }
    }
    pub fn sample_rate(&self) -> f64 {
        self.sample_rate_ppm as f64 / 1_000_000.0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NodeStats {
    pub input: ModelInput,
    pub weight: f64,
    pub model_predicted: bool,
    pub failed_at: u64,
    pub consecutive_failures: u32,
    pub tcp_segments: u64,
    pub tcp_retransmissions: u64,
    pub loss_strikes: u32,
    pub loss_strike_at: u64,
    pub loss_block_until: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct SmartState {
    pub nodes: BTreeMap<String, NodeStats>,
    pub records: BTreeMap<String, NodeStats>,
    pub selections: u64,
    pub observations: u64,
    pub last_used: u64,
    #[serde(default)]
    pub advanced: advanced::AdvancedState,
}

#[derive(Clone, Debug)]
pub struct SmartGroup {
    pub options: SmartOptions,
    pub model: Option<Arc<LightGbmModel>>,
    pub(crate) state: SmartState,
    priorities: Vec<PriorityRule>,
    pub(crate) collector: Option<Arc<Collector>>,
}
impl PartialEq for SmartGroup {
    fn eq(&self, other: &Self) -> bool {
        self.options == other.options && self.state == other.state && self.model == other.model
    }
}
impl Eq for SmartGroup {}
#[derive(Clone, Debug)]
struct PriorityRule {
    pattern: String,
    factor: f64,
    regex: Option<Arc<fancy_regex::Regex>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SmartNodeRank {
    pub name: String,
    pub rank: String,
    pub weight: f64,
}

impl SmartGroup {
    pub fn new(definition: &GroupDefinition) -> Self {
        let options = SmartOptions::from_definition(definition);
        let mut priorities = Vec::new();
        for pair in options
            .policy_priority
            .split(';')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let split = pair
                .char_indices()
                .rev()
                .find(|(index, ch)| {
                    *ch == ':'
                        && pair[..*index]
                            .chars()
                            .rev()
                            .take_while(|c| *c == '\\')
                            .count()
                            % 2
                            == 0
                })
                .map(|v| v.0);
            let Some(index) = split else {
                continue;
            };
            let (pattern, number) = pair.split_at(index);
            let Ok(factor) = number[1..].trim().parse::<f64>() else {
                continue;
            };
            if !factor.is_finite() || factor <= 0.0 {
                continue;
            }
            let mut pattern_chars = pattern.trim().chars();
            let mut pattern = String::new();
            while let Some(ch) = pattern_chars.next() {
                pattern.push(if ch == '\\' {
                    pattern_chars.next().unwrap_or(ch)
                } else {
                    ch
                });
            }
            let regex = fancy_regex::Regex::new(&pattern).ok().map(Arc::new);
            priorities.push(PriorityRule {
                pattern,
                factor,
                regex,
            });
        }
        Self {
            options,
            model: None,
            state: SmartState::default(),
            priorities,
            collector: None,
        }
    }
    pub fn priority(&self, name: &str) -> f64 {
        self.priorities
            .iter()
            .find(|rule| {
                rule.regex
                    .as_ref()
                    .map(|regex| regex.is_match(name).unwrap_or(false))
                    .unwrap_or_else(|| name.contains(&rule.pattern))
            })
            .map(|rule| rule.factor)
            .unwrap_or(1.0)
    }
    pub fn normalized_priority(&self) -> String {
        self.priorities
            .iter()
            .map(|rule| format!("{}:{:.2}", rule.pattern, rule.factor))
            .collect::<Vec<_>>()
            .join(";")
    }
    pub fn last_used(&self) -> u64 {
        self.state.last_used
    }
    pub fn target_key(&self, metadata: &Metadata) -> String {
        let site = target::key(
            self.options.prefer_asn,
            metadata,
            &self.state.advanced.evidence,
        );
        format!(
            "{}|{site}",
            if metadata.network == NetworkKind::Udp {
                "udp"
            } else {
                "tcp"
            }
        )
    }
    fn record_key(&self, metadata: &Metadata, node: &str) -> String {
        format!("{}\u{1f}{node}", self.target_key(metadata))
    }
    fn stats_for(&self, metadata: Option<&Metadata>, node: &str) -> Option<&NodeStats> {
        metadata
            .and_then(|meta| self.state.records.get(&self.record_key(meta, node)))
            .or_else(|| self.state.nodes.get(node))
    }
    fn score(&self, candidate: &ProxyCandidate, metadata: Option<&Metadata>, now: u64) -> f64 {
        let priority = self.priority(&candidate.name);
        if let Some(record) = self.stats_for(metadata, &candidate.name) {
            if record.weight > 0.0 && record.weight.is_finite() {
                let age = now.saturating_sub(record.input.last_used) as f64;
                return record.weight * priority * (1.0 / (1.0 + age / 604800.0));
            }
        }
        let delay = if candidate.last_delay_ms == 0 {
            2000.0
        } else {
            candidate.last_delay_ms as f64
        };
        (-delay / 1500.0).exp().clamp(0.05, 1.0) * priority
    }
    fn prefetch(
        &mut self,
        candidates: &[ProxyCandidate],
        metadata: &Metadata,
        now: u64,
    ) -> Vec<String> {
        let key = self.target_key(metadata);
        let fingerprint = candidates
            .iter()
            .fold(0xcbf29ce484222325u64, |mut value, candidate| {
                for byte in candidate
                    .name
                    .bytes()
                    .chain(candidate.last_delay_ms.to_le_bytes())
                    .chain([candidate.alive as u8, candidate.supports_udp as u8])
                {
                    value = (value ^ u64::from(byte)).wrapping_mul(0x100000001b3);
                }
                value
            });
        if let Some(cache) = self.state.advanced.prefetch.get(&key).filter(|cache| {
            cache.fingerprint == fingerprint && now.saturating_sub(cache.updated) < 60
        }) {
            return cache.nodes.clone();
        }
        let mut ranked = candidates.iter().collect::<Vec<_>>();
        ranked.sort_by(|a, b| {
            self.score(b, Some(metadata), now)
                .total_cmp(&self.score(a, Some(metadata), now))
        });
        let nodes = ranked
            .into_iter()
            .take(10)
            .map(|c| c.name.clone())
            .collect::<Vec<_>>();
        self.state.advanced.prefetch.insert(
            key,
            advanced::Prefetch {
                nodes: nodes.clone(),
                updated: now,
                fingerprint,
            },
        );
        self.state.advanced.trim();
        nodes
    }
    pub fn choose<'a>(
        &mut self,
        candidates: &'a [ProxyCandidate],
        metadata: Option<&Metadata>,
        selected: Option<&str>,
    ) -> Option<&'a ProxyCandidate> {
        let udp = metadata.is_some_and(|meta| meta.network == NetworkKind::Udp);
        let now = now_seconds();
        if metadata.is_some() {
            self.state.last_used = now;
            self.state.selections = self.state.selections.saturating_add(1);
        }
        let usable =
            |candidate: &&ProxyCandidate| candidate.alive && (!udp || candidate.supports_udp);
        if let Some(selected) = selected {
            if let Some(candidate) = candidates
                .iter()
                .filter(|candidate| !udp || candidate.supports_udp)
                .find(|candidate| candidate.name == selected)
            {
                return Some(candidate);
            }
        }
        let mut eligible = candidates
            .iter()
            .filter(usable)
            .filter(|candidate| {
                metadata.is_none_or(|meta| {
                    !self.state.advanced.blocked(
                        meta,
                        &candidate.name,
                        self.options.prefer_asn,
                        now,
                    )
                })
            })
            .filter(|candidate| {
                metadata
                    .and_then(|metadata| {
                        self.state
                            .records
                            .get(&self.record_key(metadata, &candidate.name))
                    })
                    .is_none_or(|record| {
                        (record.failed_at == 0 || now.saturating_sub(record.failed_at) >= 30)
                            && record.loss_block_until <= now
                    })
            })
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            // Half-open a single node after all exits were excluded. Keep the
            // lease per host so a burst cannot retry every blocked exit.
            let fallback = candidates
                .iter()
                .filter(usable)
                .filter(|candidate| {
                    metadata.is_none_or(|meta| {
                        !self.state.advanced.blocked(
                            meta,
                            &candidate.name,
                            self.options.prefer_asn,
                            now,
                        )
                    })
                })
                .collect::<Vec<_>>();
            eligible = fallback;
            if eligible.is_empty() {
                if let Some(meta) = metadata {
                    if let Some(node) = self
                        .state
                        .advanced
                        .half_open_candidate(meta, candidates, now)
                    {
                        eligible = candidates
                            .iter()
                            .filter(usable)
                            .filter(|candidate| candidate.name == node)
                            .collect();
                    }
                }
            }
        }
        if eligible.is_empty() {
            return None;
        }
        if let Some(meta) = metadata {
            let ranked = self.prefetch(candidates, meta, now);
            if self.options.tolerance_ms == 0
                || eligible
                    .iter()
                    .any(|candidate| self.stats_for(Some(meta), &candidate.name).is_some())
            {
                eligible.sort_by_key(|candidate| {
                    ranked
                        .iter()
                        .position(|name| *name == candidate.name)
                        .unwrap_or(usize::MAX)
                });
            }
        }
        if let Some(meta) = metadata {
            let key = self.target_key(meta);
            if let Some(pin) = self
                .state
                .advanced
                .pins
                .get(&key)
                .filter(|pin| pin.until > now)
            {
                if let Some(candidate) =
                    eligible.iter().find(|candidate| candidate.name == pin.node)
                {
                    return Some(*candidate);
                }
            }
        }
        let mut best = eligible[0];
        let mut best_score = self.score(best, metadata, now);
        for candidate in eligible.into_iter().skip(1) {
            let score = self.score(candidate, metadata, now);
            let within =
                best.last_delay_ms.abs_diff(candidate.last_delay_ms) <= self.options.tolerance_ms;
            let unknown = self.stats_for(metadata, &best.name).is_none()
                && self.stats_for(metadata, &candidate.name).is_none();
            if score > best_score
                && !(within
                    && unknown
                    && self.priority(&best.name) == self.priority(&candidate.name))
            {
                best = candidate;
                best_score = score;
            }
        }
        Some(best)
    }
    pub fn ranking(&self, candidates: &[ProxyCandidate]) -> Vec<SmartNodeRank> {
        if self
            .state
            .nodes
            .values()
            .all(|stats| stats.input.success + stats.input.failure < 2)
        {
            return vec![];
        }
        let now = now_seconds();
        let mut scores = candidates
            .iter()
            .map(|candidate| (candidate, self.score(candidate, None, now)))
            .collect::<Vec<_>>();
        scores.sort_by(|(left, lw), (right, rw)| {
            right
                .alive
                .cmp(&left.alive)
                .then_with(|| rw.total_cmp(lw))
                .then_with(|| left.name.cmp(&right.name))
        });
        let max = scores
            .iter()
            .filter(|(candidate, _)| candidate.alive)
            .map(|(_, score)| *score)
            .fold(0.0, f64::max);
        let positive = scores
            .iter()
            .filter(|(candidate, score)| candidate.alive && *score > 0.0)
            .count();
        let top = (positive / 5).max(1);
        let middle = top + positive / 2;
        scores
            .into_iter()
            .enumerate()
            .map(|(index, (candidate, score))| SmartNodeRank {
                name: candidate.name.clone(),
                weight: if max > 0.0 && candidate.alive {
                    (score / max * 10000.0).round() / 100.0
                } else {
                    0.0
                },
                rank: if !candidate.alive || index >= middle {
                    "RarelyUsed"
                } else if index < top {
                    "MostUsed"
                } else {
                    "OccasionalUsed"
                }
                .into(),
            })
            .collect()
    }
    pub fn observe(
        &mut self,
        group: &str,
        node: &str,
        metadata: &Metadata,
        observation: &Observation,
    ) {
        let now = now_seconds();
        self.state.advanced.trim();
        self.state.advanced.prefetch.clear();
        if observation.success {
            self.state.advanced.note_evidence(metadata);
        } else {
            let key = self.target_key(metadata);
            self.state.advanced.pins.remove(&key);
        }
        let key = self.record_key(metadata, node);
        if !self.state.records.contains_key(&key) && self.state.records.len() >= MAX_RECORDS {
            if let Some(oldest) = self
                .state
                .records
                .iter()
                .min_by_key(|(_, record)| record.input.last_used)
                .map(|(key, _)| key.clone())
            {
                self.state.records.remove(&oldest);
            }
        }
        let model = if self.options.use_lightgbm {
            self.model.as_deref()
        } else {
            None
        };
        let exit = self
            .state
            .advanced
            .exit(&advanced::host(metadata), node, now)
            .cloned();
        let aggregate = self.state.nodes.entry(node.into()).or_default();
        aggregate.input.exit_region = exit
            .as_ref()
            .map(|exit| exit.region.clone())
            .unwrap_or_default();
        aggregate.input.exit_asn = exit
            .as_ref()
            .map(|exit| exit.asn.clone())
            .unwrap_or_default();
        update_stats(aggregate, metadata, observation, model, now);
        let stats = self.state.records.entry(key).or_default();
        stats.input.exit_region = exit
            .as_ref()
            .map(|exit| exit.region.clone())
            .unwrap_or_default();
        stats.input.exit_asn = exit
            .as_ref()
            .map(|exit| exit.asn.clone())
            .unwrap_or_default();
        update_stats(stats, metadata, observation, model, now);
        self.state.observations = self.state.observations.saturating_add(1);
        if self.options.collect_data
            && sample(
                self.state.observations,
                &metadata.display_host(),
                self.options.sample_rate_ppm,
            )
        {
            if let Some(collector) = &self.collector {
                if let Err(err) = collector.write(
                    group,
                    node,
                    &stats.input,
                    stats.weight,
                    stats.model_predicted,
                    now,
                ) {
                    mihomo_core::push_log(
                        mihomo_core::LogLevel::Warn,
                        format!("[Smart] data collection: {err}"),
                    );
                }
            }
        }
    }
    pub fn flush(&mut self) {
        self.state = SmartState::default();
    }
    pub fn adopt_state(&mut self, previous: &Self) {
        self.state = previous.state.clone();
        self.model = previous.model.clone();
        self.collector = previous.collector.clone();
    }
    pub fn set_model(&mut self, model: Option<Arc<LightGbmModel>>) {
        self.model = model;
        self.state.advanced.prefetch.clear();
        let now = now_seconds();
        for stats in self
            .state
            .nodes
            .values_mut()
            .chain(self.state.records.values_mut())
        {
            let (weight, predicted) = predict(
                &stats.input,
                if self.options.use_lightgbm {
                    self.model.as_deref()
                } else {
                    None
                },
                now,
            );
            stats.weight = weight;
            stats.model_predicted = predicted;
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Observation {
    pub success: bool,
    pub connect_ms: u64,
    pub latency_ms: u64,
    pub upload: u64,
    pub download: u64,
    pub duration_ms: u64,
    pub max_upload_kb: f64,
    pub max_download_kb: f64,
    pub tcp_segments: u64,
    pub tcp_retransmissions: u64,
    pub tcp_loss_windows: u32,
    pub tcp_loss_ema: f64,
    pub tcp_loss_strikes: u32,
    pub tcp_loss_last: f64,
}
fn update_stats(
    stats: &mut NodeStats,
    metadata: &Metadata,
    event: &Observation,
    model: Option<&LightGbmModel>,
    now: u64,
) {
    let previous = &stats.input;
    let duration = event.duration_ms as f64 / 60000.0;
    let samples = previous.success + previous.failure;
    stats.tcp_segments = stats.tcp_segments.saturating_add(event.tcp_segments);
    stats.tcp_retransmissions = stats
        .tcp_retransmissions
        .saturating_add(event.tcp_retransmissions);
    let measured = event.tcp_segments >= 64 && event.tcp_loss_windows > 0;
    let loss = if measured {
        event.tcp_retransmissions as f64 / event.tcp_segments as f64
    } else {
        previous.loss_rate
    };
    let ema = if measured {
        event.tcp_loss_ema
    } else {
        previous.ema_loss_rate
    };
    if measured {
        if event.tcp_loss_strikes > 0
            && (event.tcp_loss_last >= 0.1 || (event.tcp_loss_last >= 0.05 && ema >= 0.05))
        {
            if now.saturating_sub(stats.loss_strike_at) > 300 {
                stats.loss_strikes = 0;
            }
            stats.loss_strikes = stats.loss_strikes.saturating_add(event.tcp_loss_strikes);
            stats.loss_strike_at = now;
            if stats.loss_strikes >= 2 {
                stats.loss_block_until = now + 300;
            }
        } else {
            stats.loss_strikes = 0;
            stats.loss_block_until = 0;
        }
    }
    let mut input = ModelInput {
        success: previous.success.saturating_add(u64::from(event.success)),
        failure: previous.failure.saturating_add(u64::from(!event.success)),
        connect_time: event.connect_ms as f64,
        latency: if event.latency_ms == 0 {
            event.connect_ms as f64
        } else {
            event.latency_ms as f64
        },
        upload_mb: event.upload as f64 / 1048576.0,
        download_mb: event.download as f64 / 1048576.0,
        history_upload_mb: previous.history_upload_mb + event.upload as f64 / 1048576.0,
        history_download_mb: previous.history_download_mb + event.download as f64 / 1048576.0,
        max_upload_kb: event.max_upload_kb,
        max_download_kb: event.max_download_kb,
        history_max_upload_kb: previous.history_max_upload_kb.max(event.max_upload_kb),
        history_max_download_kb: previous.history_max_download_kb.max(event.max_download_kb),
        duration_minutes: duration,
        history_duration_minutes: (previous.history_duration_minutes * samples as f64 + duration)
            / (samples as f64 + 1.0),
        last_used: now,
        is_udp: metadata.network == NetworkKind::Udp,
        asn: if metadata.dst_ip_asn == "unknown" {
            String::new()
        } else {
            metadata.dst_ip_asn.clone()
        },
        host: metadata.host.clone().unwrap_or_default().to_lowercase(),
        ip: metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        port: metadata.dst_port.unwrap_or_default(),
        geoip: metadata.dst_geoip.clone().unwrap_or_default(),
        connection_failed: !event.success,
        loss_rate: loss,
        cumul_loss_rate: if stats.tcp_segments > 0 {
            (stats.tcp_retransmissions as f64 / stats.tcp_segments as f64).min(1.0)
        } else {
            previous.cumul_loss_rate
        },
        ema_loss_rate: ema,
        exit_region: previous.exit_region.clone(),
        exit_asn: previous.exit_asn.clone(),
        ..Default::default()
    };
    if !event.success {
        input.connect_time = input.connect_time.max(2000.0);
        input.latency = input.latency.max(2000.0);
        stats.failed_at = now;
        stats.consecutive_failures = stats.consecutive_failures.saturating_add(1);
    } else {
        stats.failed_at = 0;
        stats.consecutive_failures = 0;
    }
    let (score, predicted) = predict(&input, model, now);
    stats.input = input;
    stats.weight = score;
    stats.model_predicted = predicted;
}
fn predict(input: &ModelInput, model: Option<&LightGbmModel>, now: u64) -> (f64, bool) {
    if input.success + input.failure < 2 {
        return (0.0, false);
    }
    if let Some(model) = model {
        let base = input.features(now);
        let mut raw = base.to_vec();
        raw.resize(model.feature_names.len().max(raw.len()), 0.0);
        let compatible = model
            .feature_names
            .iter()
            .take(features::FEATURE_NAMES.len())
            .zip(features::FEATURE_NAMES)
            .all(|(left, right)| left == right);
        if compatible {
            if let Ok(score) = model.predict(&raw) {
                if score > 0.0 {
                    return (score, true);
                }
            }
        }
    }
    (weight::calculate(input, 1.0, now), false)
}
fn sample(sequence: u64, host: &str, rate: u32) -> bool {
    let mut hash = sequence.wrapping_mul(0x9e3779b97f4a7c15);
    for byte in host.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    hash % 1_000_000 < u64::from(rate)
}
/// The deterministic Smart scoring fallback, also useful for model validation.
pub fn adaptive_weight(input: &ModelInput, priority: f64, now: u64) -> f64 {
    weight::calculate(input, priority, now)
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
pub(crate) struct Collector {
    path: PathBuf,
    limit: u64,
    lock: Mutex<()>,
}
impl Collector {
    pub fn new(home: &Path, limit_mb: f64) -> Self {
        Self {
            path: home.join("smart_weight_data.csv"),
            limit: (limit_mb.clamp(0.01, 4096.0) * 1048576.0) as u64,
            lock: Mutex::new(()),
        }
    }
    fn write(
        &self,
        group: &str,
        node: &str,
        input: &ModelInput,
        weight: f64,
        predicted: bool,
        now: u64,
    ) -> Result<(), String> {
        let _lock = self.lock.lock().unwrap();
        let exists = fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let mut row = input
            .features(now)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        row.extend([
            group.into(),
            node.into(),
            input.asn.clone(),
            input.host.clone(),
            input.ip.clone(),
            input.port.to_string(),
            input.geoip.join(";"),
            weight.to_string(),
            if predicted { "lightgbm" } else { "formula" }.into(),
            now.to_string(),
        ]);
        let row = row
            .iter()
            .map(|value| csv_escape(value))
            .collect::<Vec<_>>()
            .join(",")
            + "\n";
        let mut header = features::FEATURE_NAMES
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        header.extend(
            [
                "group_name",
                "node_name",
                "asn_raw",
                "host_raw",
                "ip_raw",
                "port_raw",
                "geoip_raw",
                "weight",
                "weight_source",
                "timestamp",
            ]
            .map(str::to_owned),
        );
        let header = header.join(",") + "\n";
        let size = row.len() as u64 + if exists == 0 { header.len() as u64 } else { 0 };
        if exists.saturating_add(size) > self.limit {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        if exists == 0 {
            file.write_all(header.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        file.write_all(row.as_bytes()).map_err(|e| e.to_string())
    }
}
fn csv_escape(raw: &str) -> String {
    if raw.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", raw.replace('"', "\"\""))
    } else {
        raw.into()
    }
}

#[cfg(test)]
mod advanced_tests;
#[cfg(test)]
mod tests;
