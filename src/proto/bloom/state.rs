//! FIPS-specific Bloom filter announcement state management.

use alloc::collections::{BTreeMap, BTreeSet};

use super::BloomFilter;
use crate::NodeAddr;

/// How long an announce the receiver reports cannot check waits before its
/// one unchecked resend, in milliseconds. Equal to the default link dead
/// timeout, so an outage that did not remove the peer has ended by then.
pub const FALLBACK_MS: u64 = 30_000;

/// The largest gap the per-peer resend backoff imposes, in milliseconds.
pub const MAXGAP_MS: u64 = 60_000;

/// A run of resends with no resend for this long, in milliseconds, resets the
/// backoff. It must exceed [`MAXGAP_MS`], or a sustained trigger resending at
/// the largest gap would reset its own backoff every time.
pub const QUIET_MS: u64 = 120_000;

/// Unchecked resends (`Unverified`, `SessionChanged` or `Timeout`) allowed per
/// announce lineage per session.
pub const UNVERIFIED_BUDGET: u8 = 1;

/// Resends on reported loss allowed per announce lineage per session.
pub const LOSS_BUDGET: u8 = 3;

/// Highest backoff level. `gap` at this level is already capped at
/// [`MAXGAP_MS`], so a higher level would add nothing; the cap keeps the
/// shift in range.
const MAX_LEVEL: u8 = 7;

/// The cumulative counters of one ReceiverReport the peer sent about our
/// frames on a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RrCounters {
    /// Highest link counter the peer had received from us.
    pub highest: u64,
    /// Link frames from us the peer had counted, cumulative.
    pub received: u64,
    /// Of those, frames that arrived below the highest counter, cumulative.
    pub reordered: u32,
}

/// What the shell reads from one peer's link at one moment, for deciding
/// whether an announce reached that peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkEvidence {
    /// Identity of the current link session (from its handshake hash). The
    /// send counter restarts at 0 in every session, so counters are compared
    /// only within one epoch.
    pub epoch: u64,
    /// The next send counter the current session will use.
    pub next_counter: u64,
    /// The last ReceiverReport accepted in the current session, if any.
    pub rr: Option<RrCounters>,
}

impl LinkEvidence {
    /// The report, when it can describe the current session.
    ///
    /// The peer cannot have received a counter this session has not used yet,
    /// so a report whose highest counter is at or above `next_counter`
    /// describes another session. That happens briefly around a rekey, when a
    /// report or frame of the old session is counted against the new one, and
    /// such a report is no evidence either way.
    pub fn usable_rr(&self) -> Option<RrCounters> {
        self.rr.filter(|rr| rr.highest < self.next_counter)
    }
}

/// Why an announce is being resent, for the shell's log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResendReason {
    /// A report covering the announce shows fewer frames arrived since its
    /// base than were sent.
    Loss,
    /// The first usable report already covers an announce it cannot check.
    Unverified,
    /// The announce was sent on an earlier session and cannot be checked.
    SessionChanged,
    /// No usable report checked the announce within the fallback interval.
    Timeout,
}

/// What an announce's delivery is measured from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Base {
    /// The last usable report before the announce was sent, and whether it
    /// has no holes: every counter up to its highest had arrived.
    Counted(RrCounters, bool),
    /// Nothing received yet in the peer's first session: every counter from 0
    /// must arrive.
    Zero,
    /// No base: a later report can become one if it does not yet cover the
    /// announce.
    Unknown,
}

/// The one announce to a peer still awaiting confirmation.
#[derive(Clone, Copy, Debug)]
struct SentAnnounce {
    /// Link counter the announce was sent with.
    counter: u64,
    /// Session the counter belongs to (or, once orphaned, the session that
    /// orphaned it).
    epoch: u64,
    /// What delivery is measured from.
    base: Base,
    /// Sent on an earlier session, so it can never be checked.
    orphan: bool,
    /// When it was sent or orphaned, for the fallback.
    at_ms: u64,
}

/// Per-peer delivery tracking for filter announces.
#[derive(Clone, Debug)]
struct AckState {
    /// Session in which this entry was created; only there does a missing
    /// report mean the peer has received nothing yet.
    first_epoch: u64,
    /// The outstanding announce, if one is unconfirmed.
    sent: Option<SentAnnounce>,
    /// Backoff level: the number of resends in the current run, capped.
    level: u8,
    /// When the last resend was triggered.
    resent_ms: Option<u64>,
    /// Session the budgets were last refilled for.
    budget_epoch: u64,
    /// Unchecked resends left for the current lineage in this session.
    unverified_left: u8,
    /// Loss resends left for the current lineage in this session.
    loss_left: u8,
}

impl AckState {
    /// A fresh entry for a peer first sent to in session `epoch`.
    fn new(epoch: u64) -> Self {
        Self {
            first_epoch: epoch,
            sent: None,
            level: 0,
            resent_ms: None,
            budget_epoch: epoch,
            unverified_left: UNVERIFIED_BUDGET,
            loss_left: LOSS_BUDGET,
        }
    }

    /// Refill both budgets for session `epoch`.
    fn refill(&mut self, epoch: u64) {
        self.budget_epoch = epoch;
        self.unverified_left = UNVERIFIED_BUDGET;
        self.loss_left = LOSS_BUDGET;
    }

    /// Whether report `rr`, taken in session `epoch`, shows no holes: every
    /// counter up to its highest had arrived. Only in the peer's first session
    /// does its cumulative count start at 0, so a later session's report is
    /// never known to be whole.
    fn whole(&self, epoch: u64, rr: RrCounters) -> bool {
        epoch == self.first_epoch && rr.highest.checked_add(1) == Some(rr.received)
    }

    /// Whether the backoff allows a resend at `now_ms`, resetting the level
    /// after a quiet period.
    fn backoff_allows(&mut self, now_ms: u64) -> bool {
        let Some(last) = self.resent_ms else {
            return true;
        };
        if now_ms >= last.saturating_add(QUIET_MS) {
            self.level = 0;
        }
        now_ms >= last.saturating_add(gap(self.level))
    }
}

/// Minimum time after a resend before the next one, at backoff `level`.
fn gap(level: u8) -> u64 {
    match level {
        0 => 0,
        n => (1000u64 << (n.min(MAX_LEVEL) - 1)).min(MAXGAP_MS),
    }
}

/// Whether every counter in the report's range since `base` arrived.
///
/// Within one receiver epoch every frame counted between two reports is a
/// distinct counter at or below `h1`. Those in `(h0, h1]` number at most all
/// receipts, `got`, and at least the non-reorder receipts, `sure`: a frame
/// that arrived after a higher counter is a reorder whether its counter lies
/// inside the window or at or below `h0`.
///
/// - `got` below the span is a loss: fewer frames arrived than the window
///   holds.
/// - `sure` equal to the span is delivery.
/// - `got` equal to the span is delivery when the base has no holes, since
///   then no counter at or below `h0` is left to arrive late.
///
/// Anything else is ambiguous and proves nothing, as is an inconsistent pair
/// (a counter went backwards), which means the two reports straddle a
/// receiver reset or another session's frame. Frames reserved but never
/// sent and frames dropped before counting only lower the counts, so a lost
/// frame is confirmed only if the peer overcounts.
fn delivered(base: Base, rr: RrCounters) -> Option<bool> {
    let (r0, o0, span, complete) = match base {
        Base::Counted(b, complete) => (
            b.received,
            b.reordered,
            rr.highest.checked_sub(b.highest)?,
            complete,
        ),
        Base::Zero => (0, 0, rr.highest.checked_add(1)?, true),
        Base::Unknown => return None,
    };
    let got = rr.received.checked_sub(r0)?;
    let sure = got.checked_sub(u64::from(rr.reordered.checked_sub(o0)?))?;
    if got < span {
        Some(false)
    } else if sure == span || (complete && got == span) {
        Some(true)
    } else {
        None
    }
}

/// State for managing Bloom filter announcements.
///
/// Tracks local filter state and what needs to be sent to peers.
#[derive(Clone, Debug)]
pub struct BloomState {
    /// This node's NodeAddr (always included in outgoing filters).
    own_node_addr: NodeAddr,
    /// Leaf-only nodes we speak for (included in our filter).
    leaf_dependents: BTreeSet<NodeAddr>,
    /// Whether this node operates in leaf-only mode.
    is_leaf_only: bool,
    /// Rate limiting: minimum interval between outgoing updates (milliseconds).
    update_debounce_ms: u64,
    /// Timestamp of last update sent (per peer, in milliseconds).
    last_update_sent: BTreeMap<NodeAddr, u64>,
    /// Peers that need a filter update.
    pending_updates: BTreeSet<NodeAddr>,
    /// Current sequence number for outgoing filters.
    sequence: u64,
    /// Last outgoing filter sent to each peer (for change detection).
    last_sent_filters: BTreeMap<NodeAddr, BloomFilter>,
    /// How long an unchecked announce waits for its fallback resend (ms).
    fallback_ms: u64,
    /// Per-peer delivery tracking for sent announces.
    acks: BTreeMap<NodeAddr, AckState>,
}

impl BloomState {
    /// Create new Bloom state for a node.
    pub fn new(own_node_addr: NodeAddr) -> Self {
        Self {
            own_node_addr,
            leaf_dependents: BTreeSet::new(),
            is_leaf_only: false,
            update_debounce_ms: 500,
            last_update_sent: BTreeMap::new(),
            pending_updates: BTreeSet::new(),
            sequence: 0,
            last_sent_filters: BTreeMap::new(),
            fallback_ms: FALLBACK_MS,
            acks: BTreeMap::new(),
        }
    }

    /// Create state for a leaf-only node.
    pub fn leaf_only(own_node_addr: NodeAddr) -> Self {
        let mut state = Self::new(own_node_addr);
        state.is_leaf_only = true;
        state
    }

    /// Get the node's own ID.
    pub fn own_node_addr(&self) -> &NodeAddr {
        &self.own_node_addr
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    /// Get the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Increment and return the next sequence number.
    pub fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Get the update debounce interval in milliseconds.
    pub fn update_debounce_ms(&self) -> u64 {
        self.update_debounce_ms
    }

    /// Set the update debounce interval.
    pub fn set_update_debounce_ms(&mut self, ms: u64) {
        self.update_debounce_ms = ms;
    }

    /// Set how long an announce the receiver reports cannot check waits
    /// before its fallback resend. Defaults to [`FALLBACK_MS`].
    pub fn set_fallback(&mut self, ms: u64) {
        self.fallback_ms = ms;
    }

    /// Add a leaf dependent that we'll include in our filter.
    pub fn add_leaf_dependent(&mut self, node_addr: NodeAddr) {
        self.leaf_dependents.insert(node_addr);
    }

    /// Remove a leaf dependent.
    pub fn remove_leaf_dependent(&mut self, node_addr: &NodeAddr) -> bool {
        self.leaf_dependents.remove(node_addr)
    }

    /// Get the set of leaf dependents.
    pub fn leaf_dependents(&self) -> &BTreeSet<NodeAddr> {
        &self.leaf_dependents
    }

    /// Number of leaf dependents.
    pub fn leaf_dependent_count(&self) -> usize {
        self.leaf_dependents.len()
    }

    /// Mark that a peer needs an update.
    pub fn mark_update_needed(&mut self, peer_id: NodeAddr) {
        self.pending_updates.insert(peer_id);
    }

    /// Mark all peers as needing updates.
    pub fn mark_all_updates_needed(&mut self, peer_ids: impl IntoIterator<Item = NodeAddr>) {
        self.pending_updates.extend(peer_ids);
    }

    /// Check if a peer needs an update.
    pub fn needs_update(&self, peer_id: &NodeAddr) -> bool {
        self.pending_updates.contains(peer_id)
    }

    /// Check if we should send an update to a peer (respecting debounce).
    pub fn should_send_update(&self, peer_id: &NodeAddr, current_time_ms: u64) -> bool {
        if !self.pending_updates.contains(peer_id) {
            return false;
        }

        match self.last_update_sent.get(peer_id) {
            Some(&last_time) => current_time_ms >= last_time + self.update_debounce_ms,
            None => true,
        }
    }

    /// Record that we sent an update to a peer.
    pub fn record_update_sent(&mut self, peer_id: NodeAddr, current_time_ms: u64) {
        self.last_update_sent.insert(peer_id, current_time_ms);
        self.pending_updates.remove(&peer_id);
    }

    /// Clear all pending updates.
    pub fn clear_pending_updates(&mut self) {
        self.pending_updates.clear();
    }

    /// Record the outgoing filter that was sent to a peer.
    pub fn record_sent_filter(&mut self, peer_id: NodeAddr, filter: BloomFilter) {
        self.last_sent_filters.insert(peer_id, filter);
    }

    /// Read back the last outgoing filter actually sent to a peer, if any.
    ///
    /// Returns the filter recorded by [`record_sent_filter`](Self::record_sent_filter)
    /// — i.e. what the peer currently holds for us — or `None` when no announce
    /// has been sent to that peer yet (or the node is root, with no parent to
    /// send to).
    pub fn last_sent_filter(&self, peer_id: &NodeAddr) -> Option<&BloomFilter> {
        self.last_sent_filters.get(peer_id)
    }

    /// Remove stored filter state for a peer that was removed.
    pub fn remove_peer_state(&mut self, peer_id: &NodeAddr) {
        self.last_sent_filters.remove(peer_id);
        self.last_update_sent.remove(peer_id);
        self.pending_updates.remove(peer_id);
        self.acks.remove(peer_id);
    }

    /// Record an announce the transport accepted for `peer`, sent with link
    /// counter `counter`, so it stays outstanding until the peer's receiver
    /// reports show it arrived.
    ///
    /// The transport accepting a frame is not delivery: a datagram can still
    /// be lost, and announces are sent only when a filter changes, so a lost
    /// one would otherwise leave the peer's filter stale indefinitely.
    ///
    /// Call this before [`record_sent_filter`](Self::record_sent_filter) for
    /// the same send: it compares `filter` with the last one sent, and new
    /// content starts a new lineage with fresh resend budgets. The budgets
    /// also refill when the session changes, and never otherwise, so a resend
    /// of the same content spends from its lineage's budget.
    pub fn record_announce(
        &mut self,
        peer: NodeAddr,
        filter: &BloomFilter,
        counter: u64,
        link: &LinkEvidence,
        now_ms: u64,
    ) {
        let new_lineage = self.last_sent_filters.get(&peer) != Some(filter);
        let ack = self
            .acks
            .entry(peer)
            .or_insert_with(|| AckState::new(link.epoch));
        if new_lineage || link.epoch != ack.budget_epoch {
            ack.refill(link.epoch);
        }
        // With no report yet, the zero baseline holds only in the peer's first
        // session: a later session's cumulative count includes earlier ones.
        let base = match link.usable_rr() {
            Some(rr) if rr.highest < counter => Base::Counted(rr, ack.whole(link.epoch, rr)),
            _ if link.rr.is_none() && link.epoch == ack.first_epoch => Base::Zero,
            _ => Base::Unknown,
        };
        ack.sent = Some(SentAnnounce {
            counter,
            epoch: link.epoch,
            base,
            orphan: false,
            at_ms: now_ms,
        });
    }

    /// Decide whether the outstanding announce to `peer` must be resent.
    ///
    /// Confirms the announce when a usable report covering its counter shows
    /// every counter since its base arrived. Resends on a covering report that
    /// shows a loss; once, as soon as a usable report arrives, for an announce
    /// the reports cannot check; and once after the fallback interval when no
    /// usable report checks it. A usable report that does not yet cover an
    /// announce sent in the current session becomes its base instead of
    /// triggering a resend. A report from another session, or a pair of
    /// reports that is inconsistent or cannot tell a late frame from before
    /// the base from one inside the window, is no evidence. Each announce lineage
    /// gets [`UNVERIFIED_BUDGET`] unchecked and [`LOSS_BUDGET`] loss resends
    /// per session, and a per-peer backoff spaces all resends by 1, 2, 4 ...
    /// up to 60 s until [`QUIET_MS`] passes with none.
    ///
    /// On `Some`, the peer has been marked for an update; the ordinary send
    /// path delivers the resend.
    pub fn check_announce(
        &mut self,
        peer: &NodeAddr,
        link: &LinkEvidence,
        now_ms: u64,
    ) -> Option<ResendReason> {
        let fallback_ms = self.fallback_ms;
        let ack = self.acks.get_mut(peer)?;
        let mut sent = ack.sent?;

        if link.epoch != ack.budget_epoch {
            ack.refill(link.epoch);
        }
        if sent.epoch != link.epoch {
            sent.orphan = true;
            sent.epoch = link.epoch;
            sent.base = Base::Unknown;
            sent.at_ms = now_ms;
        }
        ack.sent = Some(sent);

        let rr = link.usable_rr();
        let due = now_ms >= sent.at_ms.saturating_add(fallback_ms);
        let candidate = match (sent.base, rr) {
            (Base::Unknown, Some(rr)) => {
                if !sent.orphan && rr.highest < sent.counter {
                    sent.base = Base::Counted(rr, ack.whole(link.epoch, rr));
                    ack.sent = Some(sent);
                    return None;
                }
                Some(if sent.orphan {
                    ResendReason::SessionChanged
                } else {
                    ResendReason::Unverified
                })
            }
            (Base::Unknown, None) => due.then_some(ResendReason::Timeout),
            (base, rr) => {
                let covering = rr.filter(|rr| rr.highest >= sent.counter);
                let loss = match covering.and_then(|rr| delivered(base, rr)) {
                    Some(true) => {
                        ack.sent = None;
                        return None;
                    }
                    Some(false) if ack.loss_left > 0 => Some(ResendReason::Loss),
                    _ => None,
                };
                loss.or(due.then_some(ResendReason::Timeout))
            }
        }?;

        let loss = candidate == ResendReason::Loss;
        let left = if loss {
            ack.loss_left
        } else {
            ack.unverified_left
        };
        if left == 0 || !ack.backoff_allows(now_ms) {
            return None;
        }
        if loss {
            ack.loss_left -= 1;
        } else {
            ack.unverified_left -= 1;
        }
        ack.level = (ack.level + 1).min(MAX_LEVEL);
        ack.resent_ms = Some(now_ms);
        self.mark_update_needed(*peer);
        Some(candidate)
    }

    /// Whether an announce to `peer` is still awaiting confirmation.
    pub fn announce_outstanding(&self, peer: &NodeAddr) -> bool {
        self.outstanding_counter(peer).is_some()
    }

    /// The link counter of the announce to `peer` awaiting confirmation.
    pub fn outstanding_counter(&self, peer: &NodeAddr) -> Option<u64> {
        self.acks.get(peer)?.sent.map(|sent| sent.counter)
    }

    /// Mark only peers whose outgoing filter has actually changed.
    ///
    /// Computes the outgoing filter for each peer and compares it
    /// against what was last sent. Only marks peers where the filter
    /// differs. This prevents cascading update loops in steady state.
    pub fn mark_changed_peers(
        &mut self,
        exclude_from: &NodeAddr,
        peer_addrs: &[NodeAddr],
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) {
        let targets: Vec<NodeAddr> = peer_addrs
            .iter()
            .filter(|addr| *addr != exclude_from)
            .copied()
            .collect();
        self.mark_changed(&targets, peer_filters);
    }

    /// Mark every target whose outgoing filter differs from what was last sent.
    ///
    /// A target never sent to counts as changed. Unlike
    /// [`mark_changed_peers`](Self::mark_changed_peers), no peer is excluded.
    pub fn mark_changed(
        &mut self,
        targets: &[NodeAddr],
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) {
        for (peer_addr, new_filter) in self.compute_outgoing_filters(targets, peer_filters) {
            let changed = match self.last_sent_filters.get(&peer_addr) {
                Some(last) => *last != new_filter,
                None => true, // never sent → must send
            };
            if changed {
                self.pending_updates.insert(peer_addr);
            }
        }
    }

    /// Compute the outgoing filter for many peers in one pass.
    ///
    /// Equivalent to calling [`compute_outgoing_filter`](Self::compute_outgoing_filter)
    /// once per target, but linear in the number of contributing peer
    /// filters instead of quadratic. The per-peer call rebuilds the whole
    /// union from scratch, so computing it for every peer costs
    /// O(targets × filters) 1 KB merges; announce fan-out on a
    /// large node does exactly that, once per tick and again on every
    /// inbound announce.
    ///
    /// The split-horizon exclusion is the only thing that differs between
    /// targets, so the union of "everything except peer i" is assembled
    /// from a running prefix union and a precomputed suffix union. Merging
    /// is a bytewise OR, which is commutative and associative, so the
    /// result is bit-identical to the per-peer computation.
    pub fn compute_outgoing_filters(
        &self,
        targets: &[NodeAddr],
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) -> BTreeMap<NodeAddr, BloomFilter> {
        let base = self.base_filter();
        let keys: Vec<NodeAddr> = peer_filters.keys().copied().collect();
        let n = keys.len();

        // suffix[i] = union of peer_filters[keys[i..]]; suffix[n] is empty.
        let mut suffix = vec![BloomFilter::new(); n + 1];
        for i in (0..n).rev() {
            let mut acc = suffix[i + 1].clone();
            // Size mismatches are skipped, exactly as in the per-peer path.
            let _ = acc.merge(&peer_filters[&keys[i]]);
            suffix[i] = acc;
        }

        // Filter for a target that contributes nothing: everything merged.
        let mut all = base.clone();
        let _ = all.merge(&suffix[0]);

        let mut per_key: BTreeMap<NodeAddr, BloomFilter> = BTreeMap::new();
        let mut prefix = BloomFilter::new();
        for i in 0..n {
            let mut outgoing = base.clone();
            let _ = outgoing.merge(&prefix);
            let _ = outgoing.merge(&suffix[i + 1]);
            per_key.insert(keys[i], outgoing);
            let _ = prefix.merge(&peer_filters[&keys[i]]);
        }

        targets
            .iter()
            .map(|target| {
                let filter = per_key.get(target).cloned().unwrap_or_else(|| all.clone());
                (*target, filter)
            })
            .collect()
    }

    /// Compute the outgoing filter for a specific peer.
    ///
    /// The filter includes:
    /// - This node's own ID
    /// - All leaf dependents
    /// - Entries from other peers' inbound filters (excluding the destination peer)
    ///
    /// The `peer_filters` map contains inbound filters from each peer.
    /// The filter for `exclude_peer` is excluded to prevent routing loops.
    pub fn compute_outgoing_filter(
        &self,
        exclude_peer: &NodeAddr,
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) -> BloomFilter {
        let mut filter = BloomFilter::new();

        // Always include ourselves
        filter.insert(&self.own_node_addr);

        // Include leaf dependents
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }

        // Merge filters from other peers
        for (peer_id, peer_filter) in peer_filters {
            if peer_id != exclude_peer {
                // Ignore merge errors (size mismatches) - just skip that filter
                let _ = filter.merge(peer_filter);
            }
        }

        filter
    }

    /// Create a base filter containing just this node and its dependents.
    pub fn base_filter(&self) -> BloomFilter {
        let mut filter = BloomFilter::new();
        filter.insert(&self.own_node_addr);
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }
        filter
    }
}
