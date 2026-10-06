//! Foreground shutdown on unix: the stop signals, and a stop during start-up.
//!
//! The signals are registered when the shutdown future is built, at the top
//! of `main`, rather than when it is first polled. Until a handler exists a
//! SIGTERM takes the default action, which kills the daemon at once, and when
//! the daemon is PID 1 in a container the kernel discards it, leaving the
//! container to be killed at its stop timeout.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

/// How long a stop received during start-up waits for start-up to finish
/// before the daemon exits without a drain. With the default drain window
/// of 2 s this fits inside Docker's default stop timeout of 10 s.
pub(crate) const STARTUP_STOP_GRACE: Duration = Duration::from_secs(5);

/// Register SIGTERM and SIGINT now, and return a future that completes when
/// either arrives. A signal delivered before the future is first polled is
/// held and reported at that poll.
///
/// The first poll logs `Shutdown signal handler installed` with
/// `since_start_ms`, the time from this call to that poll. The handlers were
/// registered at the start of that span, so the field shows how long the
/// daemon ran before it first looked for a stop, not a registration delay.
pub(crate) fn foreground_signal() -> impl Future<Output = ()> {
    let registered = Instant::now();
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
    async move {
        info!(
            since_start_ms = registered.elapsed().as_millis() as u64,
            "Shutdown signal handler installed"
        );
        let name = tokio::select! {
            _ = sigterm.recv() => "SIGTERM",
            _ = sigint.recv() => "SIGINT",
        };
        info!(signal = %name, "Shutdown signal received");
    }
}

/// How start-up ended when it may have raced a stop.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StartOutcome<E> {
    /// Start-up finished. `signalled` is true when the shutdown future
    /// completed first; it must then not be polled again.
    Started { signalled: bool },
    /// Start-up failed, whether or not a stop had arrived.
    Failed(E),
    /// A stop arrived and start-up did not finish within the grace.
    GraceElapsed,
}

/// Run `start` while watching `shutdown`. Without a stop, this is `start`.
/// After a stop, `start` is given at most `grace` to finish, because a
/// half-run start-up cannot be torn down in an orderly way.
///
/// `start` is borrowed rather than owned so that on `GraceElapsed` the
/// caller can exit the process with the start-up future still in place
/// instead of running its drop part-way through start-up.
pub(crate) async fn start_within_grace<E, F, S>(
    mut start: Pin<&mut F>,
    shutdown: Pin<&mut S>,
    grace: Duration,
) -> StartOutcome<E>
where
    F: Future<Output = Result<(), E>>,
    S: Future<Output = ()>,
{
    tokio::select! {
        biased;
        () = shutdown => {}
        result = start.as_mut() => {
            return match result {
                Ok(()) => StartOutcome::Started { signalled: false },
                Err(e) => StartOutcome::Failed(e),
            };
        }
    }
    info!(
        grace_secs = grace.as_secs(),
        "Stop requested during start-up; waiting for start-up to finish"
    );
    match tokio::time::timeout(grace, start).await {
        Ok(Ok(())) => StartOutcome::Started { signalled: true },
        Ok(Err(e)) => StartOutcome::Failed(e),
        Err(_) => StartOutcome::GraceElapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::pin;
    use tokio::sync::oneshot;
    use tokio::time::{Instant, sleep};

    const GRACE: Duration = Duration::from_secs(5);

    /// A start-up that takes `secs` and then returns `result`.
    async fn start_after(secs: f64, result: Result<(), &'static str>) -> Result<(), &'static str> {
        sleep(Duration::from_secs_f64(secs)).await;
        result
    }

    /// A shutdown future that completes after `secs`.
    async fn signal_after(secs: f64) {
        sleep(Duration::from_secs_f64(secs)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_start_up_waits_for_a_start_up_that_finishes_inside_the_grace() {
        let t0 = Instant::now();
        let start = pin!(start_after(1.5, Ok(())));
        let shutdown = pin!(signal_after(0.5));
        let outcome = start_within_grace(start, shutdown, GRACE).await;
        assert_eq!(outcome, StartOutcome::Started { signalled: true });
        assert_eq!(t0.elapsed(), Duration::from_millis(1500));
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_start_up_gives_up_when_the_grace_elapses_not_when_start_up_ends() {
        let t0 = Instant::now();
        let start = pin!(start_after(60.0, Ok(())));
        let shutdown = pin!(signal_after(0.5));
        let outcome = start_within_grace(start, shutdown, GRACE).await;
        assert_eq!(outcome, StartOutcome::<&str>::GraceElapsed);
        assert_eq!(t0.elapsed(), Duration::from_millis(5500));
    }

    #[tokio::test(start_paused = true)]
    async fn start_up_without_a_stop_leaves_the_shutdown_future_live_for_a_later_stop() {
        let t0 = Instant::now();
        let (tx, rx) = oneshot::channel::<()>();
        let start = pin!(start_after(1.0, Ok(())));
        let mut shutdown = pin!(async {
            let _ = rx.await;
        });
        let outcome = start_within_grace(start, shutdown.as_mut(), GRACE).await;
        assert_eq!(outcome, StartOutcome::Started { signalled: false });
        assert_eq!(t0.elapsed(), Duration::from_secs(1));

        // The same pinned future, already polled once, still reports a stop
        // sent after start-up.
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown future did not complete after a later stop");
    }

    #[tokio::test(start_paused = true)]
    async fn start_up_failure_is_reported_with_or_without_a_stop() {
        let start = pin!(start_after(1.0, Err("boom")));
        let shutdown = pin!(std::future::pending::<()>());
        let outcome = start_within_grace(start, shutdown, GRACE).await;
        assert_eq!(outcome, StartOutcome::Failed("boom"));

        let start = pin!(start_after(1.0, Err("boom")));
        let shutdown = pin!(signal_after(0.5));
        let outcome = start_within_grace(start, shutdown, GRACE).await;
        assert_eq!(outcome, StartOutcome::Failed("boom"));
    }
}
