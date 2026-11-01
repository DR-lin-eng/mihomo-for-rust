//! Each tracker is one source identity, shared by all clones of its stream.
//! Small windows accumulate; consumed increments are never counted twice.
use mihomo_core::TcpStats;
use std::time::Instant;
#[derive(Debug)]
pub(super) struct LossSampler {
    anchor: TcpStats,
    last: TcpStats,
    updated: Instant,
    pub segments: u64,
    pub retransmissions: u64,
    pub windows: u32,
    pub ema: f64,
    pub strikes: u32,
    pub last_rate: f64,
}
impl Default for LossSampler {
    fn default() -> Self {
        Self {
            anchor: TcpStats::default(),
            last: TcpStats::default(),
            updated: Instant::now(),
            segments: 0,
            retransmissions: 0,
            windows: 0,
            ema: 0.0,
            strikes: 0,
            last_rate: 0.0,
        }
    }
}
impl LossSampler {
    pub fn sample(&mut self, stats: Option<TcpStats>) {
        let Some(stats) = stats else {
            return;
        };
        if stats.segments_out < self.last.segments_out
            || stats.retransmissions < self.last.retransmissions
            || self.updated.elapsed().as_secs() > 1800
        {
            self.anchor = TcpStats::default();
        }
        self.updated = Instant::now();
        self.last = stats;
        let sent = stats.segments_out.saturating_sub(self.anchor.segments_out);
        if sent < 64 {
            return;
        }
        let retrans = stats
            .retransmissions
            .saturating_sub(self.anchor.retransmissions)
            .min(sent);
        self.anchor = stats;
        self.segments = self.segments.saturating_add(sent);
        self.retransmissions = self.retransmissions.saturating_add(retrans);
        let rate = retrans as f64 / sent as f64;
        self.ema = if self.windows == 0 {
            rate
        } else {
            self.ema * 0.7 + rate * 0.3
        };
        self.last_rate = rate;
        if rate >= 0.1 || (rate >= 0.05 && self.ema >= 0.05) {
            self.strikes = self.strikes.saturating_add(1);
        } else {
            self.strikes = 0;
        }
        self.windows = self.windows.saturating_add(1);
    }
}
