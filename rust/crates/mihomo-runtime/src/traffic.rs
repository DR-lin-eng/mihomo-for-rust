//! Live byte totals and a shared one-second throughput sample. Sampling is
//! based on monotonic time, never on how often an API consumer polls.
use crate::TrafficSnapshot;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct TrafficMeter {
    started: Instant,
    window: Mutex<Window>,
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
            window: Mutex::new(Window::default()),
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
        let mut window = self.window.lock().unwrap();
        if let Some(counter) = counter {
            counter.fetch_add(bytes, Ordering::Relaxed);
        }
        window.add(self.started.elapsed().as_secs(), upload, bytes);
    }
    pub(crate) fn snapshot(&self) -> TrafficSnapshot {
        self.with_snapshot(|snapshot| snapshot)
    }

    pub(crate) fn with_snapshot<T>(&self, sample: impl FnOnce(TrafficSnapshot) -> T) -> T {
        let mut window = self.window.lock().unwrap();
        let snapshot = window.snapshot(self.started.elapsed().as_secs());
        sample(snapshot)
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
