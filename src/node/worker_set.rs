//! The worker threads behind one crypto worker pool, and what is known about
//! whether each is still running.
//!
//! Both pools (`encrypt_worker`, `decrypt_worker`) are a set of OS threads,
//! each reached through its own bounded channel. A worker that exits, a panic
//! unwinding included, drops its receiver, so its channel closes and every
//! later dispatch to it is refused. Nothing restarts it. This module keeps the
//! thread handles so that loss can be seen, and counts the dispatches it
//! refused.
//!
//! It reports facts only. Whether a loss degrades the node is decided by the
//! driver in `lifecycle`.

use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use tracing::warn;

/// One worker: the sending end of its channel and its thread, `None` when the
/// thread could not be started.
struct Worker<S> {
    sender: S,
    thread: Option<JoinHandle<()>>,
}

/// The workers of one pool. Held behind an `Arc` by the pool so that cloning
/// the pool per packet stays a reference-count bump.
pub(crate) struct WorkerSet<S> {
    workers: Box<[Worker<S>]>,
    /// Dispatches refused because the target worker had exited.
    refused: AtomicU64,
    /// The live-worker count the liveness sweep last reported. Starts at the
    /// number of threads that started, so a worker that never started is
    /// reported once, at spawn, and not again by the sweep. It lives with the
    /// workers so that a pool replaced by another starts from its own count.
    reported_live: AtomicUsize,
}

impl<S> WorkerSet<S> {
    /// Start `n` workers, at least one.
    ///
    /// `channel` builds each worker's sender and receiver. `spawn` starts the
    /// thread that owns the receiver. A worker whose thread cannot be started
    /// is logged and left dead rather than aborting the caller: the receiver
    /// was moved into the failed spawn and is dropped with it, so that
    /// worker's channel is closed and a dispatch to it is refused, not queued.
    pub(crate) fn start<R>(
        pool: &'static str,
        n: usize,
        mut channel: impl FnMut() -> (S, R),
        mut spawn: impl FnMut(usize, R) -> std::io::Result<JoinHandle<()>>,
    ) -> Self {
        let n = n.max(1);
        let mut workers = Vec::with_capacity(n);
        for idx in 0..n {
            let (sender, receiver) = channel();
            let thread = match spawn(idx, receiver) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    warn!(pool, worker = idx, %error, "Failed to start a crypto worker thread");
                    None
                }
            };
            workers.push(Worker { sender, thread });
        }
        let started = workers.iter().filter(|w| w.thread.is_some()).count();
        Self {
            workers: workers.into(),
            refused: AtomicU64::new(0),
            reported_live: AtomicUsize::new(started),
        }
    }

    /// Number of workers, including dead ones. Never zero.
    pub(crate) fn len(&self) -> usize {
        self.workers.len()
    }

    /// The sending end of worker `idx`'s channel.
    pub(crate) fn sender(&self, idx: usize) -> &S {
        &self.workers[idx].sender
    }

    /// Count one dispatch refused by a dead worker, returning the count before
    /// this one.
    pub(crate) fn note_refused(&self) -> u64 {
        self.refused.fetch_add(1, Ordering::Relaxed)
    }
}

/// What the liveness sweep and the tests read from a pool, without naming its
/// channel type.
pub(crate) trait WorkerLiveness {
    /// Number of workers the pool was built with.
    fn worker_count(&self) -> usize;
    /// Workers whose thread started and has not finished. A worker thread
    /// finishes only by unwinding or when every sender to it is dropped, and
    /// the node holds the pool while it runs, so a finished thread is a dead
    /// worker.
    fn live_workers(&self) -> usize;
    /// Indices of the workers that are not live.
    fn dead_workers(&self) -> Vec<usize>;
    /// Dispatches refused because their worker had exited.
    #[cfg(test)]
    fn refused_dispatches(&self) -> u64;
    /// Record `live` as the count last reported, returning the previous one.
    fn swap_reported_live(&self, live: usize) -> usize;
}

impl<S> WorkerLiveness for WorkerSet<S> {
    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    fn live_workers(&self) -> usize {
        self.workers.iter().filter(|w| is_live(w)).count()
    }

    fn dead_workers(&self) -> Vec<usize> {
        self.workers
            .iter()
            .enumerate()
            .filter(|(_, w)| !is_live(w))
            .map(|(idx, _)| idx)
            .collect()
    }

    #[cfg(test)]
    fn refused_dispatches(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    fn swap_reported_live(&self, live: usize) -> usize {
        self.reported_live.swap(live, Ordering::Relaxed)
    }
}

fn is_live<S>(worker: &Worker<S>) -> bool {
    worker.thread.as_ref().is_some_and(|t| !t.is_finished())
}

/// Whether the `n`th event (counting from zero) of a repeating condition is
/// logged: the first eight, then one in ten thousand.
pub(crate) fn worth_logging(n: u64) -> bool {
    n < 8 || n.is_multiple_of(10_000)
}

/// How a test wants one worker of a pool to behave.
#[cfg(test)]
pub(crate) enum TestWorker {
    /// The production worker loop.
    Run,
    /// The thread fails to start.
    FailSpawn,
    /// The thread holds its receiver until signalled, then exits.
    ExitOn(std::sync::mpsc::Receiver<()>),
}

/// A spawner that starts each worker as `plan` says, using `run` for
/// [`TestWorker::Run`].
#[cfg(test)]
pub(crate) fn test_spawner<R: Send + 'static>(
    plan: Vec<TestWorker>,
    run: impl Fn(usize, R) -> std::io::Result<JoinHandle<()>>,
) -> impl FnMut(usize, R) -> std::io::Result<JoinHandle<()>> {
    let mut plan: Vec<Option<TestWorker>> = plan.into_iter().map(Some).collect();
    move |idx, rx| match plan[idx].take().expect("each worker is started once") {
        TestWorker::Run => run(idx, rx),
        TestWorker::FailSpawn => {
            drop(rx);
            Err(std::io::Error::other("worker start refused by the test"))
        }
        TestWorker::ExitOn(signal) => std::thread::Builder::new().spawn(move || {
            let _ = signal.recv();
            drop(rx);
        }),
    }
}

/// Wait up to five seconds for `cond`, returning whether it came true.
#[cfg(test)]
pub(crate) fn wait_for(cond: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !cond() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn a_worker_that_exits_is_no_longer_live_and_is_named_dead() {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let mut stop_rx = Some(stop_rx);
        let set = WorkerSet::start(
            "test",
            2,
            mpsc::channel::<u32>,
            |idx, rx: mpsc::Receiver<u32>| {
                let stop = if idx == 1 { stop_rx.take() } else { None };
                std::thread::Builder::new().spawn(move || match stop {
                    Some(stop) => {
                        let _ = stop.recv();
                        drop(rx);
                    }
                    None => while rx.recv().is_ok() {},
                })
            },
        );
        assert_eq!(set.live_workers(), 2);
        stop_tx.send(()).unwrap();
        assert!(
            wait_for(|| set.live_workers() == 1),
            "worker 1 never exited"
        );
        assert_eq!(set.dead_workers(), vec![1]);
        assert_eq!(set.worker_count(), 2);
    }

    #[test]
    fn the_reported_baseline_starts_at_the_workers_that_started() {
        let set = WorkerSet::start("test", 3, mpsc::channel::<u32>, |idx, rx| {
            if idx == 2 {
                drop(rx);
                return Err(std::io::Error::other("refused by the test"));
            }
            std::thread::Builder::new().spawn(move || while rx.recv().is_ok() {})
        });
        assert_eq!(set.swap_reported_live(2), 2);
        assert_eq!(set.dead_workers(), vec![2]);
    }

    #[test]
    fn worth_logging_keeps_the_first_eight_then_one_in_ten_thousand() {
        let logged: Vec<u64> = (0..20_001).filter(|n| worth_logging(*n)).collect();
        assert_eq!(logged, vec![0, 1, 2, 3, 4, 5, 6, 7, 10_000, 20_000]);
    }
}
