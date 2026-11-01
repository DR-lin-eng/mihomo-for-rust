use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

const EXECUTOR_WORKER_THREADS_MIN: usize = 1;
const EXECUTOR_WORKER_THREADS_MAX: usize = 4;
const EXECUTOR_BLOCKING_THREADS_MIN: usize = 32;
const EXECUTOR_BLOCKING_THREADS_MAX: usize = 512;
const EXECUTOR_BLOCKING_THREADS_FACTOR: usize = 32;

fn normalized_worker_threads(parallelism: usize, min: usize, max: usize) -> usize {
    parallelism.clamp(min, max)
}

fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(EXECUTOR_WORKER_THREADS_MIN)
}

fn executor_worker_threads() -> usize {
    normalized_worker_threads(
        available_parallelism(),
        EXECUTOR_WORKER_THREADS_MIN,
        EXECUTOR_WORKER_THREADS_MAX,
    )
}

fn executor_blocking_threads() -> usize {
    let requested = available_parallelism().saturating_mul(EXECUTOR_BLOCKING_THREADS_FACTOR);
    normalized_worker_threads(
        requested,
        EXECUTOR_BLOCKING_THREADS_MIN,
        EXECUTOR_BLOCKING_THREADS_MAX,
    )
}

fn blocking_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(executor_worker_threads())
            .max_blocking_threads(executor_blocking_threads())
            .enable_all()
            .thread_name("mihomo-app-blocking")
            .build()
            .expect("failed to build mihomo blocking runtime")
    })
}

pub(crate) fn spawn_blocking<F, R>(task: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    blocking_runtime().handle().spawn_blocking(task)
}

#[cfg(test)]
mod tests {
    use super::normalized_worker_threads;

    #[test]
    fn normalized_worker_threads_clamps_executor_bounds() {
        assert_eq!(normalized_worker_threads(0, 1, 4), 1);
        assert_eq!(normalized_worker_threads(2, 1, 4), 2);
        assert_eq!(normalized_worker_threads(32, 1, 4), 4);
    }
}
