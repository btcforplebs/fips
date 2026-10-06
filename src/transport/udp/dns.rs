//! Hostname resolution for the UDP transport, kept off the caller's task.
//!
//! Every caller of the UDP send and resolve paths runs on the node's receive
//! loop, so a lookup awaited inline stalls the whole node for as long as the
//! system resolver takes. Here a lookup runs in a spawned task. The caller
//! waits for it only when it is the caller that started it, and then for at
//! most `DNS_COLD_WAIT`. A datagram sent while a lookup for a name with no
//! usable address is still running is held, and the lookup task sends it when
//! the address arrives. A datagram sent to an expired address while its
//! refresh runs goes to that address at once and leaves a copy, which the
//! refresh sends on only if the address has changed.

use super::io::AsyncUdpSocket;
use super::{DNS_CACHE_MAX_ENTRIES, UdpStats, cache_lookup, cache_store};
use crate::transport::{TransportAddr, TransportError};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
#[cfg(test)]
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// How long a caller that starts a lookup waits for it before carrying on.
///
/// A typical recursive lookup finishes well inside it, so first contact with
/// a healthy resolver behaves as an inline lookup would, and a resolver that
/// fails fast still fails the send at once. Smaller, and more first sends are
/// held until the lookup completes; nothing is lost. Larger, and the receive
/// loop stalls for that long once per lookup or refresh started.
pub(super) const DNS_COLD_WAIT: Duration = Duration::from_millis(250);

/// How long an expired entry still serves as its name's address.
///
/// It outlasts an ordinary resolver outage. Past it the name counts as
/// unknown again.
pub(super) const DNS_CACHE_STALE_LIMIT: Duration = Duration::from_secs(3600);

/// The most datagrams held for one name while its lookup runs.
///
/// A dial needs one; the rest cover a link frame or two sent to the same name
/// meanwhile. Beyond it a send is refused, as a full send buffer would refuse
/// it.
pub(super) const DNS_HOLD_MAX: usize = 4;

/// Where a lookup task sends the datagrams held on it: a clone of the
/// transport's socket and the counters the transport's own sends update.
pub(super) struct Sink {
    socket: AsyncUdpSocket,
    stats: Arc<UdpStats>,
}

impl Sink {
    /// Wrap a clone of the transport's socket and its counters.
    pub(super) fn new(socket: AsyncUdpSocket, stats: Arc<UdpStats>) -> Self {
        Self { socket, stats }
    }
}

/// A lookup in flight for one name, and the datagrams waiting on it.
///
/// Each held datagram carries the address it has already been sent to: `None`
/// for one not yet sent anywhere, `Some(stale)` for the copy of one sent to
/// the stale address while the refresh runs.
#[derive(Default)]
pub(super) struct Pending {
    held: Vec<(Vec<u8>, Option<SocketAddr>)>,
    sink: Option<Sink>,
}

/// A stand-in for the system resolver, so tests can drive a real transport
/// through a lookup that hangs, fails or answers on cue.
#[cfg(test)]
pub(crate) type TestResolver = Arc<
    dyn Fn(
            TransportAddr,
        ) -> Pin<Box<dyn Future<Output = Result<SocketAddr, TransportError>> + Send>>
        + Send
        + Sync,
>;

/// One transport's resolution cache and its lookups in flight.
#[derive(Default)]
pub(super) struct DnsState {
    /// Each name's last address and when it was stored.
    pub(super) entries: HashMap<TransportAddr, (SocketAddr, Instant)>,
    /// One record per name whose lookup is running. The record's presence is
    /// the in-flight marker.
    inflight: HashMap<TransportAddr, Pending>,
    /// Used in place of the system resolver when set.
    #[cfg(test)]
    pub(super) test_resolver: Option<TestResolver>,
}

/// What resolving a hostname gave.
#[derive(Debug)]
pub(super) enum Resolve {
    /// A current address.
    Addr(SocketAddr),
    /// The stale address, with its refresh still running.
    Stale(SocketAddr),
    /// No usable address yet; a lookup is running.
    Pending,
    /// The lookup failed and there is no stale address to fall back on.
    Failed(TransportError),
}

/// What `hold` did with a datagram.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Hold {
    /// The lookup finished in the meantime; send to this address directly.
    Resolved(SocketAddr),
    /// Held; the lookup task sends it.
    Held,
    /// The same bytes are already held, so nothing changed.
    Duplicate,
    /// The name already has `DNS_HOLD_MAX` datagrams held.
    Full,
    /// The lookup failed in the meantime.
    Gone,
}

/// Clears a name's in-flight record when its lookup task ends without
/// clearing it itself.
///
/// The task disarms it under the lock when it takes the record. A panic, a
/// runtime shutdown or a task that is never polled drops it armed instead,
/// and without it the name would stay marked in flight for the life of the
/// transport.
struct Guard {
    state: Arc<StdMutex<DnsState>>,
    key: TransportAddr,
    armed: bool,
}

impl Drop for Guard {
    /// Remove the record, and with it any held datagrams and the sink.
    fn drop(&mut self) {
        if self.armed {
            lock(&self.state).inflight.remove(&self.key);
        }
    }
}

/// Lock the state, carrying on through a poisoned lock as the cache always
/// has: no code path leaves the maps half-updated across a panic.
pub(super) fn lock(state: &StdMutex<DnsState>) -> MutexGuard<'_, DnsState> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// The error for a send whose name has no address yet.
pub(super) fn pending_error(addr: &TransportAddr) -> TransportError {
    TransportError::SendFailed(format!("DNS resolution of {addr} still pending"))
}

/// The error for a send whose name failed to resolve.
pub(super) fn failed_error(addr: &TransportAddr) -> TransportError {
    TransportError::SendFailed(format!("DNS resolution of {addr} failed"))
}

/// An entry for `key` at `now`, fresh or expired, that is still inside
/// `DNS_CACHE_STALE_LIMIT`.
fn cache_stale(
    entries: &HashMap<TransportAddr, (SocketAddr, Instant)>,
    key: &TransportAddr,
    now: Instant,
) -> Option<SocketAddr> {
    entries
        .get(key)
        .filter(|(_, cached_at)| now.duration_since(*cached_at) < DNS_CACHE_STALE_LIMIT)
        .map(|(resolved, _)| *resolved)
}

/// Resolve a hostname at `now` without waiting on DNS for longer than
/// `DNS_COLD_WAIT`.
///
/// A fresh entry answers at once. Otherwise, if a lookup for the name is
/// already running, the answer is the stale address or `Pending`, without
/// waiting. If none is running, this starts one through `resolver` and waits
/// for it for at most `DNS_COLD_WAIT`: an address in time is returned; a
/// failure in time gives the stale address if there is one and the error if
/// not; and if the wait runs out the lookup carries on detached, and the
/// answer is the stale address marked `Stale`, or `Pending`.
pub(super) async fn resolve_with<F, Fut>(
    state: &Arc<StdMutex<DnsState>>,
    addr: &TransportAddr,
    now: Instant,
    resolver: F,
) -> Resolve
where
    F: FnOnce(TransportAddr) -> Fut + Send + 'static,
    Fut: Future<Output = Result<SocketAddr, TransportError>> + Send + 'static,
{
    // The guard is built under the lock, and the lock is released before the
    // spawn: a guard dropped inside `spawn` on a runtime that is shutting
    // down then locks a free mutex instead of deadlocking on this thread.
    let (stale, guard) = {
        let mut st = lock(state);
        if let Some(resolved) = cache_lookup(&st.entries, addr, now) {
            return Resolve::Addr(resolved);
        }
        let stale = cache_stale(&st.entries, addr, now);
        if st.inflight.contains_key(addr) {
            return match stale {
                Some(stale) => Resolve::Stale(stale),
                None => Resolve::Pending,
            };
        }
        st.inflight.insert(addr.clone(), Pending::default());
        let guard = Guard {
            state: state.clone(),
            key: addr.clone(),
            armed: true,
        };
        (stale, guard)
    };

    let key = addr.clone();
    let mut handle = tokio::spawn(async move {
        let mut guard = guard;
        // Called here, inside the task, so a panic in the resolver becomes
        // this task's `JoinError` and never poisons the lock.
        let result = resolver(key.clone()).await;
        // The store, the record's removal and the take of its datagrams share
        // one lock hold, so a concurrent `hold` either finds the record and
        // its datagram is taken here, or finds the outcome.
        let taken = {
            let mut st = lock(&guard.state);
            if let Ok(resolved) = &result {
                cache_store(
                    &mut st.entries,
                    key.clone(),
                    *resolved,
                    Instant::now(),
                    DNS_CACHE_MAX_ENTRIES,
                );
            }
            guard.armed = false;
            st.inflight.remove(&key)
        };
        if let Some(pending) = taken {
            flush(&key, &result, pending).await;
        }
        result
    });

    match tokio::time::timeout(DNS_COLD_WAIT, &mut handle).await {
        Ok(Ok(Ok(resolved))) => Resolve::Addr(resolved),
        Ok(Ok(Err(e))) => match stale {
            Some(stale) => Resolve::Addr(stale),
            None => Resolve::Failed(e),
        },
        Ok(Err(_)) => match stale {
            Some(stale) => Resolve::Addr(stale),
            None => Resolve::Failed(failed_error(addr)),
        },
        // Dropping the handle detaches the lookup without cancelling it.
        Err(_) => match stale {
            Some(stale) => Resolve::Stale(stale),
            None => Resolve::Pending,
        },
    }
}

/// Send, or count as dropped, the datagrams held on a finished lookup.
///
/// On success every held datagram goes to the new address, except a copy
/// already sent to that same address. On failure each datagram never sent is
/// counted as a send error; a copy is dropped uncounted, because it went to
/// the stale address the entry keeps.
async fn flush(key: &TransportAddr, result: &Result<SocketAddr, TransportError>, pending: Pending) {
    let Some(sink) = pending.sink else {
        return;
    };
    match result {
        Ok(resolved) => {
            for (bytes, sent_to) in pending.held {
                if sent_to == Some(*resolved) {
                    continue;
                }
                match sink.socket.send_to(&bytes, resolved).await {
                    Ok(sent) => {
                        sink.stats.record_send(sent);
                        trace!(
                            addr = %key,
                            remote_addr = %resolved,
                            bytes = sent,
                            "UDP packet sent after DNS lookup"
                        );
                    }
                    Err(e) => {
                        sink.stats.record_send_error();
                        debug!(
                            addr = %key,
                            remote_addr = %resolved,
                            error = %e,
                            "UDP send after DNS lookup failed"
                        );
                    }
                }
            }
        }
        Err(e) => {
            let dropped = pending.held.iter().filter(|(_, s)| s.is_none()).count();
            for _ in 0..dropped {
                sink.stats.record_send_error();
            }
            if dropped > 0 {
                warn!(
                    addr = %key,
                    dropped,
                    error = %e,
                    "DNS lookup failed; dropped the datagrams waiting on it"
                );
            }
        }
    }
}

/// Hold `data` for the lookup running for `addr`, judging freshness at `now`.
///
/// `sent_to` is `None` for a datagram not yet sent anywhere and `Some(stale)`
/// for the copy of one already sent to the stale address. A repeat of bytes
/// already held is refused as `Duplicate` before the cap is checked, so a
/// handshake resend during a lookup is not counted as sent.
pub(super) fn hold(
    state: &StdMutex<DnsState>,
    addr: &TransportAddr,
    now: Instant,
    data: &[u8],
    sink: Sink,
    sent_to: Option<SocketAddr>,
) -> Hold {
    let mut st = lock(state);
    if let Some(resolved) = cache_lookup(&st.entries, addr, now) {
        return Hold::Resolved(resolved);
    }
    let Some(pending) = st.inflight.get_mut(addr) else {
        return Hold::Gone;
    };
    if pending
        .held
        .iter()
        .any(|(bytes, _)| bytes.as_slice() == data)
    {
        return Hold::Duplicate;
    }
    if pending.held.len() >= DNS_HOLD_MAX {
        return Hold::Full;
    }
    pending.held.push((data.to_vec(), sent_to));
    if pending.sink.is_none() {
        pending.sink = Some(sink);
    }
    Hold::Held
}

/// Pick the address for a send whose name has a stale entry with its refresh
/// running, leaving a copy for the refresh to send on if the address changes.
///
/// The send goes to the stale address unless the refresh finished in the
/// meantime. A repeat of bytes already held is refused with the pending
/// error, so a handshake resend during the refresh is not counted as sent.
pub(super) fn hold_stale(
    state: &StdMutex<DnsState>,
    addr: &TransportAddr,
    now: Instant,
    data: &[u8],
    sink: Sink,
    stale: SocketAddr,
) -> Result<SocketAddr, TransportError> {
    match hold(state, addr, now, data, sink, Some(stale)) {
        Hold::Resolved(resolved) => Ok(resolved),
        Hold::Held | Hold::Full | Hold::Gone => Ok(stale),
        Hold::Duplicate => Err(pending_error(addr)),
    }
}

/// Discard every held datagram and sink, so nothing is sent after the
/// transport stops. The in-flight records stay until their lookups end.
pub(super) fn drop_held(state: &StdMutex<DnsState>) {
    let mut st = lock(state);
    for pending in st.inflight.values_mut() {
        pending.held.clear();
        pending.sink = None;
    }
}

#[cfg(test)]
impl super::UdpTransport {
    /// Resolve every hostname through `r` instead of the system resolver.
    pub(crate) fn hook_resolver(&self, r: TestResolver) {
        lock(&self.dns_cache).test_resolver = Some(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    use crate::transport::udp::io::UdpRawSocket;
    use crate::transport::{TransportId, packet_channel};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use tokio::time::timeout;

    /// The future a gated test resolver returns.
    type BoxFuture = Pin<Box<dyn Future<Output = Result<SocketAddr, TransportError>> + Send>>;

    /// Bound on every call under test; reaching it is a failure, not a pass.
    const OUTER: Duration = Duration::from_secs(30);

    /// Bound on every wait for a datagram or a lookup to finish in the
    /// real-socket tests; only a failure reaches it.
    const RECV_BOUND: Duration = Duration::from_secs(5);

    /// What glibc reports for an authoritative NXDOMAIN, as
    /// `resolve_socket_addrs` wraps it.
    const NXDOMAIN: &str = "DNS resolution failed for x: Name or service not known";

    /// A hostname key for test `n`.
    fn name(n: usize) -> TransportAddr {
        TransportAddr::from(format!("host{n}.invalid:2121"))
    }

    /// The address a healthy lookup answers in most tests.
    fn addr_a() -> SocketAddr {
        "198.51.100.1:2121".parse().unwrap()
    }

    /// A second address, for an answer that changes.
    fn addr_b() -> SocketAddr {
        "198.51.100.2:2121".parse().unwrap()
    }

    /// An empty cache with nothing in flight.
    fn new_state() -> Arc<StdMutex<DnsState>> {
        Arc::new(StdMutex::new(DnsState::default()))
    }

    /// Await `fut`, failing the test if the outer bound fires first.
    async fn bounded<T>(fut: impl Future<Output = T>) -> T {
        timeout(OUTER, fut)
            .await
            .expect("call under test hit the outer timeout: it waited on DNS")
    }

    /// Whether a lookup for `key` still has its in-flight record.
    fn inflight(state: &Arc<StdMutex<DnsState>>, key: &TransportAddr) -> bool {
        lock(state).inflight.contains_key(key)
    }

    /// How many datagrams are held on the lookup for `key`.
    fn held_len(state: &Arc<StdMutex<DnsState>>, key: &TransportAddr) -> usize {
        lock(state).inflight.get(key).map_or(0, |p| p.held.len())
    }

    /// A resolver that never answers, counting its calls.
    fn hung(
        calls: &Arc<AtomicUsize>,
    ) -> impl FnOnce(TransportAddr) -> std::future::Pending<Result<SocketAddr, TransportError>>
    + Send
    + 'static {
        let calls = calls.clone();
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending()
        }
    }

    /// A resolver that answers `answer` at once, counting its calls.
    fn instant(
        calls: &Arc<AtomicUsize>,
        answer: Result<SocketAddr, TransportError>,
    ) -> impl FnOnce(TransportAddr) -> std::future::Ready<Result<SocketAddr, TransportError>>
    + Send
    + 'static {
        let calls = calls.clone();
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(answer)
        }
    }

    /// A resolver that answers `answer` once `gate` is released.
    fn gated(
        gate: &Arc<Notify>,
        answer: Result<SocketAddr, TransportError>,
    ) -> impl FnOnce(TransportAddr) -> BoxFuture + Send + 'static {
        let gate = gate.clone();
        move |_| {
            Box::pin(async move {
                gate.notified().await;
                answer
            })
        }
    }

    /// The body of a resolver future that panics when polled.
    fn boom() -> Result<SocketAddr, TransportError> {
        panic!("test resolver panicked")
    }

    /// Let every spawned lookup task run, so a call count read next includes
    /// any lookup a call started without waiting for it.
    async fn run_spawned() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    // ---- Paused-time tests: no real resolver and no wall-clock timing ----

    /// A resolver that never answers must cost the caller at most one cold wait.
    #[tokio::test(start_paused = true)]
    async fn cold_miss_with_a_hung_resolver_returns_pending_within_the_cold_wait() {
        let st = new_state();
        let calls = Arc::new(AtomicUsize::new(0));
        let start = tokio::time::Instant::now();
        let got = bounded(resolve_with(&st, &name(1), Instant::now(), hung(&calls))).await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");
        assert!(start.elapsed() <= DNS_COLD_WAIT);
        assert!(
            inflight(&st, &name(1)),
            "the name should be marked in flight"
        );
    }

    /// An expired address stays usable while its refresh hangs, and a second
    /// caller neither waits nor starts another lookup.
    #[tokio::test(start_paused = true)]
    async fn stale_entry_is_served_within_the_cold_wait_while_its_refresh_hangs() {
        let st = new_state();
        let t0 = Instant::now();
        lock(&st).entries.insert(name(2), (addr_a(), t0));
        let now = t0 + super::super::DNS_CACHE_TTL + Duration::from_secs(1);
        let calls = Arc::new(AtomicUsize::new(0));

        let start = tokio::time::Instant::now();
        let got = bounded(resolve_with(&st, &name(2), now, hung(&calls))).await;
        assert!(
            matches!(got, Resolve::Stale(a) if a == addr_a()),
            "got {got:?}"
        );
        assert!(start.elapsed() <= DNS_COLD_WAIT);
        assert!(inflight(&st, &name(2)), "the refresh should be in flight");

        let start = tokio::time::Instant::now();
        let again = bounded(resolve_with(&st, &name(2), now, hung(&calls))).await;
        assert!(
            matches!(again, Resolve::Stale(a) if a == addr_a()),
            "got {again:?}"
        );
        assert_eq!(start.elapsed(), Duration::ZERO);
        run_spawned().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Only the caller that starts a lookup waits on it; later callers return at once.
    #[tokio::test(start_paused = true)]
    async fn second_cold_miss_while_a_lookup_is_in_flight_returns_pending_without_waiting() {
        let st = new_state();
        let calls = Arc::new(AtomicUsize::new(0));
        let first = bounded(resolve_with(&st, &name(3), Instant::now(), hung(&calls))).await;
        assert!(matches!(first, Resolve::Pending), "got {first:?}");

        let start = tokio::time::Instant::now();
        let second = bounded(resolve_with(&st, &name(3), Instant::now(), hung(&calls))).await;
        assert!(matches!(second, Resolve::Pending), "got {second:?}");
        assert_eq!(start.elapsed(), Duration::ZERO);
        run_spawned().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A lookup the caller stopped waiting on still runs to the end and caches
    /// its answer.
    #[tokio::test(start_paused = true)]
    async fn lookup_that_outlasts_the_cold_wait_fills_the_cache_for_the_next_send() {
        let st = new_state();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let slow = move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move {
                tokio::time::sleep(DNS_COLD_WAIT * 2).await;
                Ok(addr_a())
            }
        };
        let first = bounded(resolve_with(&st, &name(4), Instant::now(), slow)).await;
        assert!(matches!(first, Resolve::Pending), "got {first:?}");

        tokio::time::sleep(DNS_COLD_WAIT * 2).await;
        run_spawned().await;

        let next = bounded(resolve_with(&st, &name(4), Instant::now(), hung(&calls))).await;
        assert!(
            matches!(next, Resolve::Addr(a) if a == addr_a()),
            "got {next:?}"
        );
        run_spawned().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A fast resolver answers inside the cold wait, as the inline lookup did.
    #[tokio::test(start_paused = true)]
    async fn healthy_resolver_answers_the_first_send_and_is_cached() {
        let st = new_state();
        let calls = Arc::new(AtomicUsize::new(0));
        let first = bounded(resolve_with(
            &st,
            &name(5),
            Instant::now(),
            instant(&calls, Ok(addr_a())),
        ))
        .await;
        assert!(
            matches!(first, Resolve::Addr(a) if a == addr_a()),
            "got {first:?}"
        );
        let second = bounded(resolve_with(&st, &name(5), Instant::now(), hung(&calls))).await;
        assert!(
            matches!(second, Resolve::Addr(a) if a == addr_a()),
            "got {second:?}"
        );
        run_spawned().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A negative or failed refresh must not discard a working address.
    #[tokio::test(start_paused = true)]
    async fn failed_refresh_keeps_serving_the_stale_address() {
        let st = new_state();
        let t0 = Instant::now();
        lock(&st).entries.insert(name(6), (addr_a(), t0));
        let now = t0 + super::super::DNS_CACHE_TTL + Duration::from_secs(1);
        let calls = Arc::new(AtomicUsize::new(0));

        let start = tokio::time::Instant::now();
        let got = bounded(resolve_with(
            &st,
            &name(6),
            now,
            instant(&calls, Err(TransportError::InvalidAddress(NXDOMAIN.into()))),
        ))
        .await;
        assert!(
            matches!(got, Resolve::Addr(a) if a == addr_a()),
            "got {got:?}"
        );
        assert!(start.elapsed() < DNS_COLD_WAIT);
        assert!(!inflight(&st, &name(6)), "no record should remain");
        assert_eq!(
            lock(&st).entries.get(&name(6)),
            Some(&(addr_a(), t0)),
            "the stale entry should be kept with its old stamp"
        );
    }

    /// A panicking resolver must not leave the name marked in flight forever.
    #[tokio::test(start_paused = true)]
    async fn inflight_marker_is_cleared_when_the_resolver_panics() {
        let st = new_state();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let panicking = move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move { boom() }
        };
        let got = bounded(resolve_with(&st, &name(7), Instant::now(), panicking)).await;
        match got {
            Resolve::Failed(TransportError::SendFailed(m)) => {
                assert!(m.ends_with(" failed"), "message was {m:?}")
            }
            other => panic!("expected the JoinError's SendFailed, got {other:?}"),
        }
        assert!(!inflight(&st, &name(7)), "the marker should be cleared");

        let failure = Err(TransportError::InvalidAddress(NXDOMAIN.into()));
        let _ = bounded(resolve_with(
            &st,
            &name(7),
            Instant::now(),
            instant(&calls, failure),
        ))
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "a new lookup should start");
    }

    /// The cache sweep must not remove an expired entry that is still a fallback.
    #[tokio::test(start_paused = true)]
    async fn dns_cache_store_keeps_entries_inside_the_stale_limit() {
        let t0 = Instant::now();
        let mut entries = HashMap::new();
        entries.insert(name(80), (addr_a(), t0));
        cache_store(
            &mut entries,
            name(81),
            addr_b(),
            t0 + super::super::DNS_CACHE_TTL * 2,
            DNS_CACHE_MAX_ENTRIES,
        );
        assert!(
            entries.contains_key(&name(80)),
            "an entry inside the stale limit is a fallback and must not be swept"
        );
    }

    /// A fast failure reaches the caller unchanged and caches nothing, so the
    /// next send tries again.
    #[tokio::test(start_paused = true)]
    async fn cold_miss_whose_lookup_fails_inside_the_cold_wait_returns_the_resolver_error() {
        let st = new_state();
        let calls = Arc::new(AtomicUsize::new(0));
        let start = tokio::time::Instant::now();
        let got = bounded(resolve_with(
            &st,
            &name(9),
            Instant::now(),
            instant(&calls, Err(TransportError::InvalidAddress(NXDOMAIN.into()))),
        ))
        .await;
        match got {
            Resolve::Failed(TransportError::InvalidAddress(m)) => assert_eq!(m, NXDOMAIN),
            other => panic!("expected the resolver's own error, got {other:?}"),
        }
        assert!(start.elapsed() < DNS_COLD_WAIT);
        assert!(!inflight(&st, &name(9)), "no record should remain");
        assert!(!lock(&st).entries.contains_key(&name(9)), "nothing cached");

        let failure = Err(TransportError::InvalidAddress(NXDOMAIN.into()));
        let _ = bounded(resolve_with(
            &st,
            &name(9),
            Instant::now(),
            instant(&calls, failure),
        ))
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "a new lookup should start");
    }

    /// The public off-task resolve shares the bound and holds no datagrams.
    #[tokio::test(start_paused = true)]
    async fn resolve_for_off_task_returns_the_pending_error_within_the_cold_wait_and_does_not_wait_again()
     {
        let cfg = UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        };
        let (tx, _rx) = packet_channel(100);
        let transport = UdpTransport::new(TransportId::new(1), None, cfg, tx);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        transport.hook_resolver(Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }));
        let key = TransportAddr::from("peer.invalid:1".to_string());

        for (round, bound) in [(1, DNS_COLD_WAIT), (2, Duration::ZERO)] {
            let start = tokio::time::Instant::now();
            match bounded(transport.resolve_for_off_task(&key)).await {
                Err(TransportError::SendFailed(m)) => {
                    assert!(
                        m.contains("still pending"),
                        "call {round}: message was {m:?}"
                    )
                }
                other => panic!("call {round}: expected the pending error, got {other:?}"),
            }
            assert!(
                start.elapsed() <= bound,
                "call {round} waited {:?}",
                start.elapsed()
            );
        }
        run_spawned().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            lock(&transport.dns_cache)
                .inflight
                .get(&key)
                .is_none_or(|p| p.held.is_empty()),
            "an off-task resolve must not hold anything"
        );
    }

    /// A refresh that answers inside the cold wait is used at once, not on the
    /// next send.
    #[tokio::test(start_paused = true)]
    async fn stale_entry_with_a_healthy_resolver_returns_the_new_address_on_the_first_call() {
        let st = new_state();
        let t0 = Instant::now();
        lock(&st).entries.insert(name(20), (addr_a(), t0));
        let now = t0 + super::super::DNS_CACHE_TTL + Duration::from_secs(1);
        let calls = Arc::new(AtomicUsize::new(0));

        let start = tokio::time::Instant::now();
        let got = bounded(resolve_with(
            &st,
            &name(20),
            now,
            instant(&calls, Ok(addr_b())),
        ))
        .await;
        assert!(
            matches!(got, Resolve::Addr(a) if a == addr_b()),
            "got {got:?}"
        );
        assert!(start.elapsed() < DNS_COLD_WAIT);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!inflight(&st, &name(20)), "no record should remain");
        assert_eq!(
            lock(&st).entries.get(&name(20)).map(|(a, _)| *a),
            Some(addr_b()),
            "the entry should now hold the new address"
        );
    }

    // ---- Real-socket tests: a gated resolver, so nothing races the wait ----

    /// A bound sender socket as the transport would hold it, its address, and
    /// fresh counters.
    fn sender() -> (AsyncUdpSocket, SocketAddr, Arc<UdpStats>) {
        let cfg = UdpConfig::default();
        let raw = UdpRawSocket::open(
            "127.0.0.1:0".parse().unwrap(),
            cfg.recv_buf_size(),
            cfg.send_buf_size(),
        )
        .expect("bind sender");
        let local = raw.local_addr();
        (
            raw.into_async().expect("register sender"),
            local,
            Arc::new(UdpStats::new()),
        )
    }

    /// A non-blocking receiver, so "nothing arrived" reads the kernel buffer
    /// itself rather than a readiness flag that may not have been set yet.
    fn receiver() -> (std::net::UdpSocket, SocketAddr) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        sock.set_nonblocking(true).unwrap();
        let local = sock.local_addr().unwrap();
        (sock, local)
    }

    /// The next datagram on `sock`, waiting up to `RECV_BOUND` while letting
    /// the lookup task run.
    async fn recv(sock: &std::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 2048];
        timeout(RECV_BOUND, async {
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => return (buf[..n].to_vec(), from),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(5)).await
                    }
                    Err(e) => panic!("receive failed: {e}"),
                }
            }
        })
        .await
        .expect("no datagram arrived")
    }

    /// Whether `sock` has nothing waiting.
    fn empty(sock: &std::net::UdpSocket) -> bool {
        let mut buf = [0u8; 2048];
        matches!(sock.recv_from(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    }

    /// Wait until the lookup for `key` has taken its record, then long enough
    /// for its flush to have sent anything it was going to send.
    async fn finished(state: &Arc<StdMutex<DnsState>>, key: &TransportAddr) {
        timeout(RECV_BOUND, async {
            while inflight(state, key) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the lookup never finished");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// Await a call under test on real time, failing the test if it runs
    /// past `RECV_BOUND`. A gated resolver is released only after the call
    /// returns, so a caller that awaits the lookup inline would otherwise
    /// hang the test instead of failing it.
    async fn capped<T>(fut: impl Future<Output = T>) -> T {
        timeout(RECV_BOUND, fut)
            .await
            .expect("call under test did not return: it waited on DNS inline")
    }

    /// Datagrams the sink counted as sent.
    fn sent(stats: &UdpStats) -> u64 {
        stats.snapshot().packets_sent
    }

    /// Datagrams the sink counted as dropped.
    fn send_errors(stats: &UdpStats) -> u64 {
        stats.snapshot().send_errors
    }

    /// A datagram held on a lookup leaves from the transport socket once the
    /// address arrives.
    #[tokio::test]
    async fn datagram_held_during_a_pending_lookup_is_sent_when_the_lookup_completes() {
        let st = new_state();
        let (socket, from, stats) = sender();
        let (rx, rx_addr) = receiver();
        let gate = Arc::new(Notify::new());
        let got = capped(resolve_with(
            &st,
            &name(10),
            Instant::now(),
            gated(&gate, Ok(rx_addr)),
        ))
        .await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");

        let sink = Sink::new(socket, stats.clone());
        assert_eq!(
            hold(&st, &name(10), Instant::now(), b"held", sink, None),
            Hold::Held
        );
        assert!(
            empty(&rx),
            "nothing may be sent before the lookup completes"
        );

        gate.notify_one();
        let (bytes, src) = recv(&rx).await;
        assert_eq!(bytes, b"held");
        assert_eq!(src, from);
        finished(&st, &name(10)).await;
        assert_eq!(sent(&stats), 1);
    }

    /// A failed lookup counts its held datagrams as send errors and sends nothing.
    #[tokio::test]
    async fn held_datagrams_are_dropped_and_counted_when_the_lookup_fails() {
        let st = new_state();
        let (socket, _, stats) = sender();
        let (rx, _) = receiver();
        let gate = Arc::new(Notify::new());
        let failure = Err(TransportError::InvalidAddress(NXDOMAIN.into()));
        let got = capped(resolve_with(
            &st,
            &name(11),
            Instant::now(),
            gated(&gate, failure),
        ))
        .await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");
        for data in [&b"one"[..], &b"two"[..]] {
            let sink = Sink::new(socket.clone(), stats.clone());
            assert_eq!(
                hold(&st, &name(11), Instant::now(), data, sink, None),
                Hold::Held
            );
        }

        gate.notify_one();
        timeout(RECV_BOUND, async {
            while send_errors(&stats) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the two dropped datagrams were never counted");
        assert!(!inflight(&st, &name(11)), "the record should be gone");
        assert!(empty(&rx));
        assert_eq!(sent(&stats), 0);
    }

    /// The per-name cap bounds memory held for a name that never resolves.
    #[tokio::test]
    async fn hold_refuses_past_the_per_name_cap() {
        let st = new_state();
        let (socket, _, stats) = sender();
        let (_rx, rx_addr) = receiver();
        let gate = Arc::new(Notify::new());
        let got = capped(resolve_with(
            &st,
            &name(12),
            Instant::now(),
            gated(&gate, Ok(rx_addr)),
        ))
        .await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");

        for n in 0..DNS_HOLD_MAX {
            let sink = Sink::new(socket.clone(), stats.clone());
            assert_eq!(
                hold(&st, &name(12), Instant::now(), &[n as u8], sink, None),
                Hold::Held,
                "datagram {n}"
            );
        }
        let sink = Sink::new(socket.clone(), stats.clone());
        assert_eq!(
            hold(&st, &name(12), Instant::now(), b"one too many", sink, None),
            Hold::Full
        );
        assert_eq!(held_len(&st, &name(12)), DNS_HOLD_MAX);
        gate.notify_one();
    }

    /// A hold that loses the race with the lookup gets its outcome instead.
    #[tokio::test]
    async fn hold_after_the_lookup_has_finished_returns_the_address_or_gone() {
        let st = new_state();
        let (socket, _, stats) = sender();
        let calls = Arc::new(AtomicUsize::new(0));

        let got = capped(resolve_with(
            &st,
            &name(13),
            Instant::now(),
            instant(&calls, Ok(addr_a())),
        ))
        .await;
        assert!(matches!(got, Resolve::Addr(_)), "got {got:?}");
        let sink = Sink::new(socket.clone(), stats.clone());
        assert_eq!(
            hold(&st, &name(13), Instant::now(), b"x", sink, None),
            Hold::Resolved(addr_a())
        );

        let failure = Err(TransportError::InvalidAddress(NXDOMAIN.into()));
        let got = capped(resolve_with(
            &st,
            &name(130),
            Instant::now(),
            instant(&calls, failure),
        ))
        .await;
        assert!(matches!(got, Resolve::Failed(_)), "got {got:?}");
        let sink = Sink::new(socket, stats);
        assert_eq!(
            hold(&st, &name(130), Instant::now(), b"x", sink, None),
            Hold::Gone
        );
    }

    /// Nothing held is sent after the transport stops.
    #[tokio::test]
    async fn drop_held_discards_datagrams_so_the_completed_lookup_sends_nothing() {
        let st = new_state();
        let (socket, _, stats) = sender();
        let (rx, rx_addr) = receiver();
        let gate = Arc::new(Notify::new());
        let got = capped(resolve_with(
            &st,
            &name(14),
            Instant::now(),
            gated(&gate, Ok(rx_addr)),
        ))
        .await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");
        let sink = Sink::new(socket, stats.clone());
        assert_eq!(
            hold(&st, &name(14), Instant::now(), b"held", sink, None),
            Hold::Held
        );

        drop_held(&st);
        gate.notify_one();
        finished(&st, &name(14)).await;
        assert!(empty(&rx), "a datagram dropped at stop must not be sent");
        assert_eq!(sent(&stats), 0);
    }

    /// A handshake resend during a lookup is refused rather than queued twice.
    #[tokio::test]
    async fn hold_refuses_a_repeat_of_held_bytes_as_pending_and_does_not_grow_the_list() {
        let st = new_state();
        let (socket, _, stats) = sender();
        let (rx, rx_addr) = receiver();

        // A repeat of the one held datagram.
        let gate = Arc::new(Notify::new());
        let got = capped(resolve_with(
            &st,
            &name(18),
            Instant::now(),
            gated(&gate, Ok(rx_addr)),
        ))
        .await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");
        let sink = Sink::new(socket.clone(), stats.clone());
        assert_eq!(
            hold(&st, &name(18), Instant::now(), b"msg1", sink, None),
            Hold::Held
        );
        let sink = Sink::new(socket.clone(), stats.clone());
        assert_eq!(
            hold(&st, &name(18), Instant::now(), b"msg1", sink, None),
            Hold::Duplicate
        );
        assert_eq!(held_len(&st, &name(18)), 1);
        gate.notify_one();
        let (bytes, _) = recv(&rx).await;
        assert_eq!(bytes, b"msg1");
        finished(&st, &name(18)).await;
        assert!(empty(&rx), "the repeat must not be sent");
        assert_eq!(sent(&stats), 1);

        // At the cap, a repeat is still a duplicate, not a refusal for space.
        let (_other, other_addr) = receiver();
        let other_stats = Arc::new(UdpStats::new());
        let gate = Arc::new(Notify::new());
        let got = capped(resolve_with(
            &st,
            &name(180),
            Instant::now(),
            gated(&gate, Ok(other_addr)),
        ))
        .await;
        assert!(matches!(got, Resolve::Pending), "got {got:?}");
        for n in 0..DNS_HOLD_MAX {
            let sink = Sink::new(socket.clone(), other_stats.clone());
            assert_eq!(
                hold(&st, &name(180), Instant::now(), &[n as u8], sink, None),
                Hold::Held
            );
        }
        let sink = Sink::new(socket, other_stats);
        assert_eq!(
            hold(&st, &name(180), Instant::now(), &[0u8], sink, None),
            Hold::Duplicate
        );
        assert_eq!(held_len(&st, &name(180)), DNS_HOLD_MAX);
        gate.notify_one();
    }

    /// One part of the stale-copy test: a stale entry at `old`, a refresh
    /// held at the gate, and the `now` every call in the part uses.
    async fn stale_part(
        st: &Arc<StdMutex<DnsState>>,
        key: &TransportAddr,
        old: SocketAddr,
        gate: &Arc<Notify>,
        answer: Result<SocketAddr, TransportError>,
    ) -> (Instant, Instant) {
        let t0 = Instant::now();
        lock(st).entries.insert(key.clone(), (old, t0));
        let now = t0 + super::super::DNS_CACHE_TTL + Duration::from_secs(1);
        let got = capped(resolve_with(st, key, now, gated(gate, answer))).await;
        assert!(matches!(got, Resolve::Stale(a) if a == old), "got {got:?}");
        (t0, now)
    }

    /// A send to a stale address is copied to the new one when the refresh
    /// changes it, and a repeat during the refresh is refused.
    #[tokio::test]
    async fn stale_send_leaves_a_copy_that_goes_only_to_a_changed_address() {
        let (socket, from, _) = sender();
        let (old, old_addr) = receiver();
        let (new, new_addr) = receiver();
        let st = new_state();
        let stats = Arc::new(UdpStats::new());
        let gate = Arc::new(Notify::new());
        let (_, now) = stale_part(&st, &name(210), old_addr, &gate, Ok(new_addr)).await;
        let sink = Sink::new(socket.clone(), stats.clone());
        let first = hold_stale(&st, &name(210), now, b"A", sink, old_addr);
        assert_eq!(first.ok(), Some(old_addr));
        assert_eq!(
            held_len(&st, &name(210)),
            1,
            "the stale send should leave a copy"
        );
        let sink = Sink::new(socket.clone(), stats.clone());
        match hold_stale(&st, &name(210), now, b"A", sink, old_addr) {
            Err(TransportError::SendFailed(m)) => {
                assert!(m.contains("still pending"), "message was {m:?}")
            }
            other => panic!("a repeat should be refused as pending, got {other:?}"),
        }
        gate.notify_one();
        let (bytes, src) = recv(&new).await;
        assert_eq!(bytes, b"A");
        assert_eq!(src, from);
        finished(&st, &name(210)).await;
        assert!(empty(&new), "the copy should arrive once");
        assert!(empty(&old), "the flush must not send to the old address");
        assert_eq!(sent(&stats), 1);
    }

    /// A copy is not sent twice to an address that already got it.
    #[tokio::test]
    async fn stale_send_copy_is_not_sent_again_when_the_refresh_returns_the_same_address() {
        let (socket, _, _) = sender();
        let (old, old_addr) = receiver();
        let st = new_state();
        let stats = Arc::new(UdpStats::new());
        let gate = Arc::new(Notify::new());
        let (_, now) = stale_part(&st, &name(211), old_addr, &gate, Ok(old_addr)).await;
        let sink = Sink::new(socket.clone(), stats.clone());
        let first = hold_stale(&st, &name(211), now, b"A", sink, old_addr);
        assert_eq!(first.ok(), Some(old_addr));
        assert_eq!(
            held_len(&st, &name(211)),
            1,
            "the stale send should leave a copy"
        );
        gate.notify_one();
        finished(&st, &name(211)).await;
        assert!(
            empty(&old),
            "a copy already sent to this address is not sent again"
        );
        assert_eq!(sent(&stats), 0);
    }

    /// When the refresh fails the copy is dropped uncounted: the datagram
    /// itself already went to the old address.
    #[tokio::test]
    async fn stale_send_copy_is_dropped_uncounted_when_the_refresh_fails() {
        let (socket, _, _) = sender();
        let (old, old_addr) = receiver();
        let (new, _) = receiver();
        let st = new_state();
        let stats = Arc::new(UdpStats::new());
        let gate = Arc::new(Notify::new());
        let failure = Err(TransportError::InvalidAddress(NXDOMAIN.into()));
        let (t0, now) = stale_part(&st, &name(212), old_addr, &gate, failure).await;
        let sink = Sink::new(socket.clone(), stats.clone());
        let first = hold_stale(&st, &name(212), now, b"A", sink, old_addr);
        assert_eq!(first.ok(), Some(old_addr));
        assert_eq!(
            held_len(&st, &name(212)),
            1,
            "the stale send should leave a copy"
        );
        gate.notify_one();
        finished(&st, &name(212)).await;
        assert_eq!(send_errors(&stats), 0, "a copy is not a lost datagram");
        assert!(empty(&old));
        assert!(empty(&new));
        assert_eq!(
            lock(&st).entries.get(&name(212)),
            Some(&(old_addr, t0)),
            "the stale entry should be kept with its old stamp"
        );
    }

    // ---- Transport-level tests: the hold wired into a real `UdpTransport` ----

    /// A started transport on loopback whose lookups answer `answer` once
    /// `gate` is released, and the receiver of its inbound packets.
    async fn gated_transport(
        gate: &Arc<Notify>,
        answer: SocketAddr,
    ) -> (UdpTransport, crate::transport::PacketRx) {
        let cfg = UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        };
        let (tx, rx) = packet_channel(100);
        let mut transport = UdpTransport::new(TransportId::new(1), None, cfg, tx);
        let gate = gate.clone();
        transport.hook_resolver(Arc::new(move |_| {
            let gate = gate.clone();
            Box::pin(async move {
                gate.notified().await;
                Ok(answer)
            })
        }));
        transport.start_async().await.expect("start transport");
        (transport, rx)
    }

    /// Stopping the transport must discard a send held on a running lookup,
    /// or the lookup sends it through a socket the transport has given up.
    #[tokio::test]
    async fn transport_stop_discards_a_send_held_on_a_running_lookup() {
        let (rx, rx_addr) = receiver();
        let gate = Arc::new(Notify::new());
        let (mut transport, _packets) = gated_transport(&gate, rx_addr).await;
        let key = name(22);
        let n = capped(transport.send_async(&key, b"held"))
            .await
            .expect("a held send is not an error");
        assert_eq!(n, 4);
        assert_eq!(held_len(&transport.dns_cache, &key), 1);

        transport.stop_async().await.expect("stop transport");
        gate.notify_one();
        finished(&transport.dns_cache, &key).await;
        assert!(empty(&rx), "a datagram held at stop must not be sent");
        assert_eq!(sent(transport.stats()), 0);
    }

    /// The transport sends to a stale address at once, leaves one copy that
    /// the refresh sends to the changed address, and refuses a repeat during
    /// the refresh, so a handshake resend is neither sent nor counted twice.
    #[tokio::test]
    async fn transport_send_to_a_stale_address_leaves_one_copy_for_the_changed_address_and_refuses_a_repeat()
     {
        let (old, old_addr) = receiver();
        let (new, new_addr) = receiver();
        let gate = Arc::new(Notify::new());
        let (transport, _packets) = gated_transport(&gate, new_addr).await;
        let from = transport.local_addr().unwrap();
        let key = name(23);
        let expired = Instant::now()
            .checked_sub(super::super::DNS_CACHE_TTL + Duration::from_secs(1))
            .expect("the clock has run for longer than the cache TTL");
        lock(&transport.dns_cache)
            .entries
            .insert(key.clone(), (old_addr, expired));

        capped(transport.send_async(&key, b"A"))
            .await
            .expect("a stale send goes to the old address");
        let (bytes, src) = recv(&old).await;
        assert_eq!(bytes, b"A");
        assert_eq!(src, from);
        assert_eq!(
            held_len(&transport.dns_cache, &key),
            1,
            "the stale send should leave a copy"
        );
        match capped(transport.send_async(&key, b"A")).await {
            Err(TransportError::SendFailed(m)) => {
                assert!(m.contains("still pending"), "message was {m:?}")
            }
            other => panic!("a repeat should be refused as pending, got {other:?}"),
        }
        assert!(empty(&old), "a repeat during the refresh must not be sent");

        gate.notify_one();
        let (bytes, src) = recv(&new).await;
        assert_eq!(bytes, b"A");
        assert_eq!(src, from);
        finished(&transport.dns_cache, &key).await;
        assert!(empty(&new), "the copy should arrive once");
        assert!(empty(&old), "nothing more may go to the old address");
        assert_eq!(
            sent(transport.stats()),
            2,
            "one send to the old address and one copy"
        );
    }

    /// The transport refuses a send past the per-name cap as still pending,
    /// not as a failed lookup, and sends every held datagram once the lookup
    /// completes.
    #[tokio::test]
    async fn transport_send_past_the_hold_cap_fails_as_still_pending_and_the_held_sends_arrive() {
        let (rx, rx_addr) = receiver();
        let gate = Arc::new(Notify::new());
        let (transport, _packets) = gated_transport(&gate, rx_addr).await;
        let key = name(24);
        for n in 0..DNS_HOLD_MAX {
            capped(transport.send_async(&key, &[n as u8]))
                .await
                .unwrap_or_else(|e| panic!("datagram {n} should be held, got {e:?}"));
        }
        assert_eq!(held_len(&transport.dns_cache, &key), DNS_HOLD_MAX);
        match capped(transport.send_async(&key, b"one too many")).await {
            Err(TransportError::SendFailed(m)) => {
                assert!(m.contains("still pending"), "message was {m:?}")
            }
            other => panic!("a send past the cap should be refused as pending, got {other:?}"),
        }
        assert!(
            empty(&rx),
            "nothing may be sent before the lookup completes"
        );

        gate.notify_one();
        let mut got = Vec::new();
        for _ in 0..DNS_HOLD_MAX {
            got.push(recv(&rx).await.0);
        }
        got.sort();
        let want: Vec<Vec<u8>> = (0..DNS_HOLD_MAX).map(|n| vec![n as u8]).collect();
        assert_eq!(got, want);
        finished(&transport.dns_cache, &key).await;
        assert!(empty(&rx), "each held datagram should arrive once");
        assert_eq!(sent(transport.stats()) as usize, DNS_HOLD_MAX);
    }
}
