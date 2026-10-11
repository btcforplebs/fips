use super::super::wait_for_optional_notify_after;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(start_paused = true)]
async fn idle_discovery_wait_does_not_schedule_an_unneeded_timer() {
    let notify = Arc::new(Notify::new());
    for enabled in [false, true] {
        // Real packet arrivals are not aligned to Tokio's millisecond ticks.
        tokio::time::advance(Duration::from_micros(333)).await;
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        let wait = wait_for_optional_notify_after(
            enabled.then_some(&notify),
            Instant::now() - Duration::from_secs(1),
        );
        tokio::pin!(wait);
        assert!(wait.as_mut().poll(&mut context).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            counter.0.load(Ordering::Relaxed),
            0,
            "idle discovery woke without an event"
        );
        if enabled {
            notify.notify_one();
            assert_eq!(counter.0.load(Ordering::Relaxed), 1);
            assert!(wait.as_mut().poll(&mut context).is_ready());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn discovery_event_preserves_its_rate_limit_without_an_expired_delay() {
    let notify = Arc::new(Notify::new());
    let now = tokio::time::Instant::now();
    let wait =
        wait_for_optional_notify_after(Some(&notify), (now + Duration::from_secs(2)).into_std());
    tokio::pin!(wait);
    notify.notify_one();
    assert!(futures::poll!(&mut wait).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(futures::poll!(&mut wait).is_pending());
    tokio::time::advance(Duration::from_secs(2)).await;
    wait.await;

    notify.notify_one();
    let expired =
        wait_for_optional_notify_after(Some(&notify), Instant::now() - Duration::from_secs(1));
    tokio::pin!(expired);
    assert!(
        futures::poll!(&mut expired).is_ready(),
        "ready discovery acquired an extra timer delay"
    );
}
