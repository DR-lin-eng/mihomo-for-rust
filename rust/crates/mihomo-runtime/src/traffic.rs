//! Live byte totals and a shared one-second throughput sample. Sampling is
//! based on monotonic time, never on how often an API consumer polls.
use crate::TrafficSnapshot;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct TrafficMeter {
    started: Instant,
    windows: Vec<Shard>,
}

// Keep independently updated windows off the same CPU cache line.
#[derive(Debug)]
#[repr(align(128))]
struct Shard(Mutex<Window>);
static NEXT_RECORDER: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static RECORDER: usize = NEXT_RECORDER.fetch_add(1, Ordering::Relaxed);
}
#[derive(Debug, Default)]
struct Window {
    epoch: u64,
    current: [u64; 2],
    previous: [u64; 2],
    total: [u64; 2],
}
impl Default for TrafficMeter {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            windows: (0..std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
                .saturating_mul(4)
                .clamp(4, 64))
                .map(|_| Shard(Mutex::new(Window::default())))
                .collect(),
        }
    }
}
impl Window {
    fn advance(&mut self, epoch: u64) {
        if epoch <= self.epoch {
            return;
        }
        self.previous = if epoch == self.epoch + 1 {
            self.current
        } else {
            [0; 2]
        };
        self.current = [0; 2];
        self.epoch = epoch;
    }
    fn add(&mut self, epoch: u64, upload: bool, bytes: u64) {
        self.advance(epoch);
        let direction = usize::from(!upload);
        self.current[direction] = self.current[direction].saturating_add(bytes);
        self.total[direction] = self.total[direction].saturating_add(bytes);
    }
    fn snapshot(&mut self, epoch: u64) -> TrafficSnapshot {
        self.advance(epoch);
        TrafficSnapshot {
            up: self.previous[0],
            down: self.previous[1],
            up_total: self.total[0],
            down_total: self.total[1],
        }
    }
}
impl TrafficMeter {
    pub(crate) fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    pub(crate) fn record(&self, upload: bool, bytes: u64, counter: Option<&AtomicU64>) {
        if bytes == 0 {
            return;
        }
        let index = RECORDER.with(|index| *index % self.windows.len());
        let mut window = self.windows[index].0.lock().unwrap();
        if let Some(counter) = counter {
            counter.fetch_add(bytes, Ordering::Relaxed);
        }
        window.add(self.started.elapsed().as_secs(), upload, bytes);
    }
    pub(crate) fn snapshot(&self) -> TrafficSnapshot {
        self.with_snapshot(|snapshot| snapshot)
    }

    pub(crate) fn with_snapshot<T>(&self, sample: impl FnOnce(TrafficSnapshot) -> T) -> T {
        // Freeze all recorders through the callback so /connections still sees
        // byte totals and per-flow counters at one consistent point in time.
        let mut windows: Vec<_> = self
            .windows
            .iter()
            .map(|shard| shard.0.lock().unwrap())
            .collect();
        let epoch = self.started.elapsed().as_secs();
        let mut total = TrafficSnapshot {
            up: 0,
            down: 0,
            up_total: 0,
            down_total: 0,
        };
        for window in &mut windows {
            let snapshot = window.snapshot(epoch);
            total.up = total.up.saturating_add(snapshot.up);
            total.down = total.down.saturating_add(snapshot.down);
            total.up_total = total.up_total.saturating_add(snapshot.up_total);
            total.down_total = total.down_total.saturating_add(snapshot.down_total);
        }
        let result = sample(total);
        drop(windows);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_connection_snapshots_keep_global_and_per_connection_bytes_consistent() {
        let meter = TrafficMeter::default();
        let upload = AtomicU64::new(0);
        let download = AtomicU64::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..10_000 {
                    meter.record(true, 31, Some(&upload));
                }
            });
            scope.spawn(|| {
                for _ in 0..10_000 {
                    meter.record(false, 73, Some(&download));
                }
            });
            for _ in 0..10_000 {
                meter.with_snapshot(|snapshot| {
                    assert_eq!(snapshot.up_total, upload.load(Ordering::Relaxed));
                    assert_eq!(snapshot.down_total, download.load(Ordering::Relaxed));
                });
            }
        });
        assert_eq!(meter.snapshot().up_total, 310_000);
        assert_eq!(meter.snapshot().down_total, 730_000);
    }

    #[test]
    fn parallel_recorders_preserve_exact_totals_while_sampling() {
        let meter = TrafficMeter::default();
        let counters: Vec<_> = (0..16).map(|_| AtomicU64::new(0)).collect();
        std::thread::scope(|scope| {
            for counter in &counters {
                let meter = &meter;
                scope.spawn(move || {
                    for _ in 0..2000 {
                        meter.record(false, 16384, Some(counter));
                    }
                });
            }
            for _ in 0..100 {
                meter.with_snapshot(|sample| {
                    assert_eq!(
                        sample.down_total,
                        counters
                            .iter()
                            .map(|counter| counter.load(Ordering::Relaxed))
                            .sum::<u64>()
                    )
                });
            }
        });
        assert_eq!(meter.snapshot().down_total, 16 * 2000 * 16384);
    }

    #[test]
    fn bytes_per_second_is_distinct_from_live_cumulative_bytes() {
        let mut window = Window::default();
        window.add(0, true, 120000);
        window.add(0, false, 90000);
        let live = window.snapshot(0);
        assert_eq!((live.up_total, live.down_total), (120000, 90000));
        assert_eq!((live.up, live.down), (0, 0));
        assert_eq!(
            (window.snapshot(1).up, window.snapshot(1).down),
            (120000, 90000)
        );
        window.add(1, true, 45000);
        assert_eq!(window.snapshot(1).up_total, 165000);
        assert_eq!(window.snapshot(2).up, 45000);
        assert_eq!(window.snapshot(2).down, 0);
    }
    #[test]
    fn subscribers_do_not_consume_the_sample_and_idle_traffic_reaches_zero() {
        let mut window = Window::default();
        window.add(0, true, 1000000);
        window.add(0, false, 2000000);
        let expected = window.snapshot(1);
        for _ in 0..100 {
            assert_eq!(window.snapshot(1), expected);
        }
        assert_eq!(
            window.snapshot(2),
            TrafficSnapshot {
                up: 0,
                down: 0,
                up_total: 1000000,
                down_total: 2000000
            }
        );
        assert_eq!(window.snapshot(60), window.snapshot(2));
    }
    #[test]
    fn delayed_polling_does_not_turn_old_transfers_into_current_speed() {
        let mut window = Window::default();
        window.add(0, true, 4000000);
        assert_eq!(window.snapshot(30).up, 0);
        assert_eq!(window.snapshot(30).up_total, 4000000);
        window.add(30, false, 10000);
        assert_eq!(window.snapshot(31).down, 10000);
    }
}
