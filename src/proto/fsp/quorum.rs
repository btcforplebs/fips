//! Distinct-link quorum for `PathBroken` signals.
//!
//! A `PathBroken` carries no end-to-end authentication, so one report is not
//! enough evidence to discard coordinates a lookup verified. This module
//! counts, per destination, the distinct links that delivered a report naming
//! it within a window, and says when enough of them have.
//!
//! The vote is keyed on the authenticated link peer the datagram arrived over,
//! not on the reporter the body names: the reporter is plaintext the sender
//! chooses, so a sender on one link could invent as many reporters as the
//! quorum needs. Every datagram from one neighbour, whether its own or relayed
//! through it, arrives over the same link and is one vote.
//!
//! Sans-IO: the caller passes the time in, and nothing here logs or counts.

use std::collections::BTreeMap;

use crate::NodeAddr;

/// Distinct links that must deliver a report naming a destination within
/// [`QUORUM_WINDOW_MS`] before its verified coordinates are demoted.
///
/// Two is the smallest value that one neighbour cannot reach alone, whether it
/// forges the reports or relays a reflection. No measurement has counted how
/// many links a genuine failure's reports arrive over; a larger value only
/// keeps a genuinely stale verified entry verified for longer, while the
/// lookup every report starts replaces it anyway.
///
/// A node whose reports all arrive over one link, such as a leaf with a
/// single peer, never reaches this. A stale verified entry there lasts until
/// a lookup that a report started answers and replaces it, or at most until
/// its verification ages out after [`crate::cache::VERIFIED_TTL_MS`]; from
/// then on it no longer refuses a hint, and the next report removes it.
pub(crate) const QUORUM_LINKS: usize = 2;

/// Window within which distinct links count toward one quorum, in
/// milliseconds.
///
/// The sum of the default lookup attempt schedule (1 + 2 + 4 + 8 s), so the
/// reports that arrive during one re-validation cycle count together. An
/// anchor, not a measurement.
pub(crate) const QUORUM_WINDOW_MS: u64 = 15_000;

/// What one report did to its destination's quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuorumVerdict {
    /// Not enough distinct links yet; `distinct` counts this one.
    Below { distinct: usize },
    /// This report completed the quorum. The destination's record is cleared,
    /// so the next quorum starts from nothing.
    Reached,
}

/// Distinct links seen per destination, each with the time it was first seen
/// inside the current window.
#[derive(Debug, Default)]
pub(crate) struct LinkQuorum {
    seen: BTreeMap<NodeAddr, Vec<(NodeAddr, u64)>>,
    last_sweep_ms: u64,
}

impl LinkQuorum {
    /// An empty quorum tracker.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record that a report naming `dest` arrived over the link to
    /// `link_peer` at `now_ms`.
    ///
    /// A link already counted for `dest` inside the window does not count
    /// again, and its first-seen time is not refreshed, so one neighbour
    /// repeating itself can neither reach the quorum nor keep a record alive.
    pub(crate) fn record(
        &mut self,
        dest: NodeAddr,
        link_peer: NodeAddr,
        now_ms: u64,
    ) -> QuorumVerdict {
        self.sweep(now_ms);
        let seen = self.seen.entry(dest).or_default();
        seen.retain(|&(_, at)| live(at, now_ms));
        if !seen.iter().any(|&(l, _)| l == link_peer) {
            seen.push((link_peer, now_ms));
        }
        let distinct = seen.len();
        if distinct >= QUORUM_LINKS {
            self.seen.remove(&dest);
            QuorumVerdict::Reached
        } else {
            QuorumVerdict::Below { distinct }
        }
    }

    /// Forget every report about `dest`.
    ///
    /// Called when a lookup verifies `dest` again: reports about the path the
    /// fresh value replaced are not evidence against it.
    pub(crate) fn clear(&mut self, dest: &NodeAddr) {
        self.seen.remove(dest);
    }

    /// Number of destinations with a record.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.seen.len()
    }

    /// Drop destinations with no live link, at most once per window, so
    /// the map holds only destinations reported within the last window or so.
    fn sweep(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_sweep_ms) < QUORUM_WINDOW_MS {
            return;
        }
        self.last_sweep_ms = now_ms;
        self.seen.retain(|_, seen| {
            seen.retain(|&(_, at)| live(at, now_ms));
            !seen.is_empty()
        });
    }
}

/// Whether a report first seen at `at` still counts at `now_ms`.
fn live(at: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(at) <= QUORUM_WINDOW_MS
}
