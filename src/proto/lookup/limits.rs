//! Mesh lookup protocol rate limiting and backoff.
//!
//! Two complementary mechanisms:
//!
//! - **`LookupBackoff`** (originator-side, optional): Exponential
//!   suppression of fresh lookups after the per-attempt sequence in
//!   `node.lookup.attempt_timeouts_secs` has been exhausted.
//!   **Disabled by default** (base/cap = 0); the per-attempt sequence
//!   is the only retry pacing in the standard configuration, and nothing
//!   is recorded while it is disabled. Reset on topology changes (parent
//!   change, new peer, first RTT, reconnection). The table is bounded at
//!   [`MAX_BACKOFF_ENTRIES`]: an entry is forgotten one maximum backoff
//!   interval after its window ends, and at the bound the entry nearest
//!   expiry is evicted.
//!
//! - **`LookupForwardRateLimiter`** (transit-side): Minimum interval per
//!   link peer and target for forwarded requests. Defense-in-depth against
//!   misbehaving nodes generating fresh request_ids at high rate. Bounded at
//!   [`MAX_FORWARD_ENTRIES`]; at the bound the peer holding the most entries
//!   loses its oldest.

use crate::NodeAddr;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};

// ============================================================================
// Receive-side: Request dedup cache bound
// ============================================================================

/// Maximum number of recent LookupRequests retained for dedup and
/// reverse-path routing before the cache is treated as full.
pub(crate) const MAX_RECENT_LOOKUP_REQUESTS: usize = 4096;

// ============================================================================
// Originator-side: Lookup Backoff
// ============================================================================

/// Default base backoff after first lookup failure. `0` = disabled.
const DEFAULT_BACKOFF_BASE_SECS: u64 = 0;

/// Default maximum backoff cap. `0` = disabled.
const DEFAULT_BACKOFF_MAX_SECS: u64 = 0;

/// Most targets the post-failure backoff table holds at once.
///
/// The legitimate load is the number of distinct targets that failed within
/// one backoff window plus one cap interval, which an ordinary node does not
/// approach; the value has no measured basis and matches
/// [`MAX_RECENT_LOOKUP_REQUESTS`]. At roughly 80 to 100 bytes an entry with
/// its expiry index (estimated) the table stays under about 400 KB. A sender
/// that fails more targets than this only evicts the entries nearest expiry,
/// and eviction fails open: an evicted target can only be retried sooner.
pub(crate) const MAX_BACKOFF_ENTRIES: usize = 4096;

/// Exponential backoff for failed lookups.
///
/// Tracks targets whose lookups have timed out and suppresses
/// re-initiation with increasing delays. Cleared on topology changes.
/// Records nothing while backoff is disabled (a zero base or cap), and
/// holds at most [`MAX_BACKOFF_ENTRIES`] targets.
pub struct LookupBackoff {
    /// Maps target → (suppress_until, consecutive_failures).
    pub(crate) entries: BTreeMap<NodeAddr, BackoffEntry>,
    /// The same targets ordered by when their windows end, so the entry
    /// nearest expiry and the forgettable ones are found without scanning
    /// the table. Holds exactly one `(suppress_until_ms, target)` per entry.
    by_expiry: BTreeSet<(u64, NodeAddr)>,
    /// Base backoff in milliseconds (first failure).
    base_ms: u64,
    /// Maximum backoff cap in milliseconds.
    max_ms: u64,
    /// Entries evicted at the bound since the shell last took the count.
    evicted: u64,
}

pub(crate) struct BackoffEntry {
    /// Don't re-initiate until this time (injected `now_ms`).
    pub(crate) suppress_until_ms: u64,
    /// Consecutive failures (drives exponential backoff).
    failures: u32,
}

impl LookupBackoff {
    /// Create with default parameters (disabled — base/cap = 0).
    pub fn new() -> Self {
        Self::with_params(DEFAULT_BACKOFF_BASE_SECS, DEFAULT_BACKOFF_MAX_SECS)
    }

    /// Create with custom base and max backoff in seconds.
    pub fn with_params(base_secs: u64, max_secs: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            by_expiry: BTreeSet::new(),
            base_ms: base_secs * 1000,
            max_ms: max_secs * 1000,
            evicted: 0,
        }
    }

    /// Whether a failure can suppress anything.
    ///
    /// The window is `base * 2^k` capped at the maximum, so a zero base or a
    /// zero cap both mean no suppression, and nothing is worth recording.
    pub fn is_enabled(&self) -> bool {
        self.base_ms > 0 && self.max_ms > 0
    }

    /// Check if a lookup for this target is suppressed.
    ///
    /// Returns true if the target is in backoff and should not be
    /// looked up yet.
    pub fn is_suppressed(&self, target: &NodeAddr, now_ms: u64) -> bool {
        if let Some(e) = self.entries.get(target) {
            now_ms < e.suppress_until_ms
        } else {
            false
        }
    }

    /// Record a lookup failure (timeout) for a target.
    ///
    /// Increments the failure count and sets the next suppression
    /// window using exponential backoff. Does nothing while backoff is
    /// disabled. A new target arriving at [`MAX_BACKOFF_ENTRIES`] first
    /// prunes forgotten entries and, if the table is still full, evicts the
    /// entry nearest expiry.
    pub fn record_failure(&mut self, target: &NodeAddr, now_ms: u64) {
        if !self.is_enabled() {
            return;
        }
        if !self.entries.contains_key(target) && self.entries.len() >= MAX_BACKOFF_ENTRIES {
            self.prune(now_ms);
            if self.entries.len() >= MAX_BACKOFF_ENTRIES {
                self.evict_nearest_expiry();
            }
        }

        let failures = self.entries.get(target).map_or(0, |e| e.failures) + 1;

        let backoff_ms = crate::proto::rate_limit::backoff_ms(
            failures.saturating_sub(1),
            self.base_ms,
            self.max_ms,
        );

        let suppress_until_ms = now_ms + backoff_ms;
        if let Some(old) = self.entries.insert(
            *target,
            BackoffEntry {
                suppress_until_ms,
                failures,
            },
        ) {
            self.by_expiry.remove(&(old.suppress_until_ms, *target));
        }
        self.by_expiry.insert((suppress_until_ms, *target));
    }

    /// Forget entries whose window ended more than one maximum backoff
    /// interval ago.
    ///
    /// The grace keeps a target that fails again soon after its window
    /// escalating; once it has passed, the target's count starts over,
    /// which can only shorten its next window.
    pub fn prune(&mut self, now_ms: u64) {
        let grace_ms = self.max_ms;
        while let Some(&(until, target)) = self.by_expiry.first() {
            if now_ms < until.saturating_add(grace_ms) {
                break;
            }
            self.by_expiry.pop_first();
            self.entries.remove(&target);
        }
    }

    /// Return and reset the count of entries evicted at the bound.
    pub fn take_evicted(&mut self) -> u64 {
        ::core::mem::take(&mut self.evicted)
    }

    /// Drop the entry whose window ends first; it is the one an eviction
    /// costs least, since it would have been retryable soonest anyway.
    fn evict_nearest_expiry(&mut self) {
        if let Some((_, target)) = self.by_expiry.pop_first() {
            self.entries.remove(&target);
            self.evicted += 1;
        }
    }

    /// Record a successful lookup — remove backoff for this target.
    pub fn record_success(&mut self, target: &NodeAddr) {
        if let Some(old) = self.entries.remove(target) {
            self.by_expiry.remove(&(old.suppress_until_ms, *target));
        }
    }

    /// Clear all backoff entries.
    ///
    /// Called on topology changes that might make previously-unreachable
    /// targets reachable (parent change, new peer, first RTT, reconnection).
    pub fn reset_all(&mut self) {
        self.entries.clear();
        self.by_expiry.clear();
    }

    /// Whether any entries exist.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the failure count for a target (for logging).
    pub fn failure_count(&self, target: &NodeAddr) -> u32 {
        self.entries.get(target).map_or(0, |e| e.failures)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for LookupBackoff {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Transit-side: Lookup Forward Rate Limiter
// ============================================================================

/// Default minimum interval between forwarded lookups for the same target
/// from the same link peer.
const DEFAULT_FORWARD_MIN_INTERVAL_MS: u64 = 2_000;

/// How often the forward limiter's full sweep may run.
///
/// The sweep is a scan of the whole map, so it is kept off the per-request
/// path; between sweeps each recording peer's own expired entries are purged
/// as it records. This is the cadence the shared rate limiter swept this
/// limiter at before it had its own map (a 60 s maximum age, eight sweeps
/// per age).
const FORWARD_SWEEP_INTERVAL_MS: u64 = 7_500;

/// Most `(link peer, target)` pairs the transit forward limiter holds at once.
///
/// An entry lives one interval, so the honest load is the number of distinct
/// targets each link peer asks this node to forward within one interval,
/// summed over peers, which an ordinary node does not approach. A peer that
/// asks for more fresh targets than this only displaces its own oldest
/// entries: at the bound the peer holding the most entries pays, and the
/// newcomer is always recorded, so a full limiter never stops limiting. No
/// measured basis; the value is that of the shared rate limiter bound it
/// replaces. About 80 bytes an entry with its queue element (estimated), so
/// the limiter stays under about 330 KB.
pub(crate) const MAX_FORWARD_ENTRIES: usize = 4096;

/// When an entry was recorded, and its limiter-wide insertion number.
#[derive(Clone, Copy)]
struct Stamp {
    at_ms: u64,
    seq: u64,
}

/// One link peer's entries, in insertion order.
#[derive(Default)]
struct PeerQueue {
    /// How many entries the map holds for this peer. This, not the queue
    /// length, is what makes a peer the heaviest.
    live: usize,
    /// `(seq, target)` per entry, oldest first. An element whose entry has
    /// since been refreshed or removed is stale; stale elements are dropped
    /// from the front as the peer records, and by the sweep.
    order: VecDeque<(u64, NodeAddr)>,
}

/// Rate limiter for forwarded lookup requests, keyed on the link peer the
/// request arrived from and its target.
///
/// A request for a target from a link peer that asked for the same target
/// within the interval is not forwarded. The key is the Noise-authenticated
/// link peer and not the request's origin, which is unsigned and chosen by
/// the sender: keyed on the target alone, one neighbour refreshing a target
/// suppressed every other neighbour's request for it.
///
/// Requests for a target from different link peers within an interval are
/// each forwarded, so what one target can cost is bounded by the peer count.
/// The map is bounded at [`MAX_FORWARD_ENTRIES`] and evicts rather than
/// failing open; a per-peer index in insertion order, kept level with the
/// map, finds the heaviest peer's oldest entry without scanning entries.
pub struct LookupForwardRateLimiter {
    entries: BTreeMap<(NodeAddr, NodeAddr), Stamp>,
    by_peer: BTreeMap<NodeAddr, PeerQueue>,
    min_interval_ms: u64,
    next_seq: u64,
    last_sweep_ms: Option<u64>,
    /// Entries evicted at the bound since the shell last took the count.
    evicted: u64,
}

impl LookupForwardRateLimiter {
    /// Create with default parameters (2s interval).
    pub fn new() -> Self {
        Self::with_interval_ms(DEFAULT_FORWARD_MIN_INTERVAL_MS)
    }

    /// Create with a custom minimum interval in milliseconds.
    pub fn with_interval_ms(min_interval_ms: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            by_peer: BTreeMap::new(),
            min_interval_ms,
            next_seq: 0,
            last_sweep_ms: None,
            evicted: 0,
        }
    }

    /// Check if we should forward a lookup for `target` that arrived from the
    /// link peer `from`.
    ///
    /// Returns false when `from` asked for `target` within the interval.
    /// Otherwise records the pair and returns true; at
    /// [`MAX_FORWARD_ENTRIES`] the recording evicts the oldest entry of the
    /// peer holding the most, and is counted for [`Self::take_evicted`].
    pub fn should_forward(&mut self, from: &NodeAddr, target: &NodeAddr, now_ms: u64) -> bool {
        let key = (*from, *target);
        if let Some(stamp) = self.entries.get(&key)
            && !self.is_expired(stamp, now_ms)
        {
            return false;
        }
        self.prune(now_ms);
        // An expired entry for the same pair is replaced, not kept beside
        // the new one; its queue element goes stale and the purge drops it.
        if self.entries.remove(&key).is_some()
            && let Some(queue) = self.by_peer.get_mut(from)
        {
            queue.live -= 1;
        }
        self.purge_front(from, now_ms);
        if self.entries.len() >= MAX_FORWARD_ENTRIES {
            self.evict_from_heaviest();
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(key, Stamp { at_ms: now_ms, seq });
        let queue = self.by_peer.entry(*from).or_default();
        queue.live += 1;
        queue.order.push_back((seq, *target));
        true
    }

    /// Remove expired entries and rebuild every peer's queue from the map,
    /// at most once per [`FORWARD_SWEEP_INTERVAL_MS`].
    ///
    /// The per-record purge only reaches the recording peer's own queue;
    /// this is what clears entries of peers that have gone quiet. The rebuild
    /// keeps the index level with the map, as the dedup cache's
    /// `purge_recent` does: an element survives only if its entry does.
    ///
    /// A clock that has stepped back makes a sweep due at once. Entries
    /// stamped before the step read as unexpired and stop the front purge,
    /// so without the sweep a peer's queue would grow until the clock caught
    /// up with the last sweep.
    pub fn prune(&mut self, now_ms: u64) {
        if let Some(last) = self.last_sweep_ms
            && now_ms >= last
            && now_ms - last < FORWARD_SWEEP_INTERVAL_MS
        {
            return;
        }
        self.last_sweep_ms = Some(now_ms);
        let interval = self.min_interval_ms;
        self.entries
            .retain(|_, stamp| now_ms.saturating_sub(stamp.at_ms) < interval);
        let entries = &self.entries;
        self.by_peer.retain(|peer, queue| {
            queue.order.retain(|(seq, target)| {
                entries
                    .get(&(*peer, *target))
                    .is_some_and(|s| s.seq == *seq)
            });
            queue.live = queue.order.len();
            !queue.order.is_empty()
        });
    }

    /// Return and reset the count of entries evicted at the bound.
    pub fn take_evicted(&mut self) -> u64 {
        ::core::mem::take(&mut self.evicted)
    }

    /// Current number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// An entry older than the interval cannot suppress anything.
    fn is_expired(&self, stamp: &Stamp, now_ms: u64) -> bool {
        now_ms.saturating_sub(stamp.at_ms) >= self.min_interval_ms
    }

    /// Drop from the front of `peer`'s queue every element that is stale or
    /// whose entry has expired, removing those entries, and forget the peer
    /// once its queue is empty.
    fn purge_front(&mut self, peer: &NodeAddr, now_ms: u64) {
        let Some(queue) = self.by_peer.get_mut(peer) else {
            return;
        };
        while let Some(&(seq, target)) = queue.order.front() {
            match self.entries.get(&(*peer, target)) {
                Some(stamp) if stamp.seq == seq => {
                    if now_ms.saturating_sub(stamp.at_ms) < self.min_interval_ms {
                        break;
                    }
                    self.entries.remove(&(*peer, target));
                    queue.live -= 1;
                }
                _ => {}
            }
            queue.order.pop_front();
        }
        if queue.order.is_empty() {
            self.by_peer.remove(peer);
        }
    }

    /// Evict the oldest entry of the peer holding the most entries.
    ///
    /// Oldest is by insertion number, never by stamp or target, so equal
    /// stamps do not fall back to an order the sender picks. Ties between
    /// equally heavy peers resolve to the highest address, as the dedup
    /// cache's `heaviest_peer` does: deterministic, and nothing in the policy
    /// depends on which of them pays. The scan is over peers, not entries.
    fn evict_from_heaviest(&mut self) {
        let Some(peer) = self
            .by_peer
            .iter()
            .max_by_key(|(_, queue)| queue.live)
            .map(|(peer, _)| *peer)
        else {
            return;
        };
        let Some(queue) = self.by_peer.get_mut(&peer) else {
            return;
        };
        while let Some((seq, target)) = queue.order.pop_front() {
            if self
                .entries
                .get(&(peer, target))
                .is_some_and(|stamp| stamp.seq == seq)
            {
                self.entries.remove(&(peer, target));
                queue.live -= 1;
                self.evicted += 1;
                break;
            }
        }
        if queue.order.is_empty() {
            self.by_peer.remove(&peer);
        }
    }

    /// Replace the minimum interval in milliseconds (e.g., set to zero to disable).
    #[cfg(test)]
    pub fn set_interval_ms(&mut self, interval_ms: u64) {
        self.min_interval_ms = interval_ms;
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether `from`'s request for `target` is recorded.
    #[cfg(test)]
    pub(crate) fn holds(&self, from: &NodeAddr, target: &NodeAddr) -> bool {
        self.entries.contains_key(&(*from, *target))
    }

    /// How many entries `peer` holds.
    #[cfg(test)]
    pub(crate) fn live(&self, peer: &NodeAddr) -> usize {
        self.by_peer.get(peer).map_or(0, |queue| queue.live)
    }

    /// How many elements `peer`'s queue holds, stale ones included.
    #[cfg(test)]
    pub(crate) fn queued(&self, peer: &NodeAddr) -> usize {
        self.by_peer.get(peer).map_or(0, |queue| queue.order.len())
    }
}

impl Default for LookupForwardRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
