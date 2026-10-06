//! Shared field vocabulary for diagnostic log lines.
//!
//! Lines about one link at both of its ends use the same field names and the
//! same renderings, so two nodes' logs can be joined on them: the transport
//! and address a message arrived on, the peer's established link and whether
//! the two are the same path, a 4-byte prefix of a msg1's digest, and a
//! 4-byte prefix of a session's handshake hash, which both ends of a session
//! hold. Every value here displays without spaces, and an absent one as
//! `none`.
//!
//! Lines about a frame that failed to decrypt also say which of the peer's
//! sessions its index names and what key state the peer held, and a
//! per-packet line with no peer to suppress on shares one node-wide budget.

use super::rate_limit::TokenBucket;
use crate::noise::NoiseSession;
use crate::peer::ActivePeer;
use crate::proto::fmp::{Msg1Digest, RekeyRole};
use crate::transport::{TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use std::fmt;
use std::time::Instant;

/// A 4-byte prefix of a digest or hash, displayed as 8 lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag4([u8; 4]);

impl fmt::Display for Tag4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// The session's tag: the first four bytes of its handshake hash. Both ends
/// of a session derive the same hash, so both ends' lines carry the same tag.
pub(crate) fn epoch_tag(session: &NoiseSession) -> Tag4 {
    let h = session.handshake_hash();
    Tag4([h[0], h[1], h[2], h[3]])
}

/// The msg1's tag: the first four bytes of its digest.
pub(crate) fn msg1_tag(digest: &Msg1Digest) -> Tag4 {
    Tag4(digest.prefix())
}

/// Displays the value, or `none` when there is none.
pub(crate) struct OrNone<T>(pub(crate) Option<T>);

impl<T: fmt::Display> fmt::Display for OrNone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => v.fmt(f),
            None => f.write_str("none"),
        }
    }
}

/// Where a msg1 arrived, against the peer's established link.
pub(crate) struct Msg1Path {
    link: Option<(TransportId, TransportAddr)>,
    same: bool,
}

impl Msg1Path {
    /// A msg1 that arrived on `tid` from `addr`, for a peer whose
    /// established link is `link` (`None` when it has none).
    pub(crate) fn new(
        tid: TransportId,
        addr: &TransportAddr,
        link: Option<(TransportId, TransportAddr)>,
    ) -> Self {
        let same = link.as_ref().is_some_and(|(t, a)| *t == tid && a == addr);
        Self { link, same }
    }

    /// Whether the msg1 arrived on the established link's own transport and
    /// address. False with no established link.
    pub(crate) fn same_path(&self) -> bool {
        self.same
    }

    /// The established link's transport.
    pub(crate) fn link_tid(&self) -> OrNone<TransportId> {
        OrNone(self.link.as_ref().map(|(t, _)| *t))
    }

    /// The established link's address.
    pub(crate) fn link_addr(&self) -> OrNone<&TransportAddr> {
        OrNone(self.link.as_ref().map(|(_, a)| a))
    }
}

/// Which of a peer's sessions a receiver index names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Slot {
    /// The session the peer sends and receives on.
    Current,
    /// The session a cutover retired, still draining.
    Previous,
    /// A pending session this node produced by answering the peer's rekey.
    PendingResponder,
    /// A pending session from a rekey this node initiated.
    PendingInitiator,
    /// No session the peer holds, such as one whose drain has completed.
    Unknown,
}

impl Slot {
    /// The slot `idx` names among `peer`'s sessions.
    pub(crate) fn of(peer: &ActivePeer, idx: SessionIndex) -> Self {
        if peer.our_index() == Some(idx) {
            Self::Current
        } else if peer.previous_our_index() == Some(idx) {
            Self::Previous
        } else if peer.pending_our_index() == Some(idx) {
            match peer.pending_role() {
                Some(RekeyRole::Responder) => Self::PendingResponder,
                Some(RekeyRole::Initiator) => Self::PendingInitiator,
                None => Self::Unknown,
            }
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Current => "current",
            Self::Previous => "previous",
            Self::PendingResponder => "pending-responder",
            Self::PendingInitiator => "pending-initiator",
            Self::Unknown => "none",
        })
    }
}

/// The key state a decryption line logs, read from the peer as owned values
/// so the caller can release its borrow of the peer before logging.
pub(crate) struct KeyView {
    /// The slot the frame's index names.
    pub(crate) slot: Slot,
    /// This node's current K-bit.
    pub(crate) kbit_ours: OrNone<bool>,
    /// The current session's tag.
    pub(crate) epoch: OrNone<Tag4>,
    /// The draining previous session's tag.
    pub(crate) prev_epoch: OrNone<Tag4>,
    /// The pending session's tag.
    pub(crate) pending_epoch: OrNone<Tag4>,
}

impl KeyView {
    /// The key state of `peer` for a frame naming `idx`. Every field is
    /// `none` without a peer, and the slot is `none` without an index.
    pub(crate) fn of(peer: Option<&ActivePeer>, idx: Option<SessionIndex>) -> Self {
        let Some(p) = peer else {
            return Self {
                slot: Slot::Unknown,
                kbit_ours: OrNone(None),
                epoch: OrNone(None),
                prev_epoch: OrNone(None),
                pending_epoch: OrNone(None),
            };
        };
        Self {
            slot: idx.map_or(Slot::Unknown, |i| Slot::of(p, i)),
            kbit_ours: OrNone(Some(p.current_k_bit())),
            epoch: OrNone(p.noise_session().map(epoch_tag)),
            prev_epoch: OrNone(p.previous_session().map(epoch_tag)),
            pending_epoch: OrNone(p.pending_new_session().map(epoch_tag)),
        }
    }
}

/// Whether a failing frame was tried against the peer's pending session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trial {
    /// The peer held no pending session.
    NotRunNoPending,
    /// A pending session was held, but the frame's K-bit matched ours, so
    /// the gate did not try it.
    NotRunKbitEqual,
    /// The gate tried the pending session and it did not authenticate the
    /// frame.
    Failed,
}

impl Trial {
    /// The trial outcome for a frame that went on to fail: `pending` is
    /// whether a pending session was held, `tried` is the gate's own
    /// decision. A trial that succeeded never reaches a failure line.
    pub(crate) fn of(pending: bool, tried: bool) -> Self {
        match (pending, tried) {
            (false, _) => Self::NotRunNoPending,
            (true, false) => Self::NotRunKbitEqual,
            (true, true) => Self::Failed,
        }
    }
}

impl fmt::Display for Trial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotRunNoPending => "not-run-no-pending",
            Self::NotRunKbitEqual => "not-run-kbit-equal",
            Self::Failed => "failed",
        })
    }
}

/// Lines a [`LogBudget`] admits at once.
const BUDGET_BURST: u32 = 10;
/// Lines per second a [`LogBudget`] admits after its burst.
const BUDGET_RATE: f64 = 1.0;

/// One node-wide budget for a per-packet line that has no authenticated peer
/// to suppress on. It holds no per-source state, so its size does not grow
/// with the number of sources sending, which an unauthenticated sender
/// chooses.
pub(crate) struct LogBudget {
    bucket: TokenBucket,
    withheld: u64,
}

impl LogBudget {
    /// A full budget as of `now`.
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            bucket: TokenBucket::with_params_at(BUDGET_BURST, BUDGET_RATE, now),
            withheld: 0,
        }
    }

    /// Whether to emit one more line at `now`. When admitted, returns how
    /// many lines were withheld since the last admitted one and resets that
    /// count; otherwise counts this line as withheld.
    pub(crate) fn admit(&mut self, now: Instant) -> Option<u64> {
        if self.bucket.try_acquire_at(now) {
            Some(std::mem::take(&mut self.withheld))
        } else {
            self.withheld = self.withheld.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_renders_exactly_the_first_four_bytes_of_a_msg1_digest() {
        let wire = b"a msg1";
        let digest = Msg1Digest::of(wire);
        let full: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(wire).into()
        };
        let want: String = full[..4].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(msg1_tag(&digest).to_string(), want);
        assert_eq!(Tag4([0x00, 0x0a, 0xb0, 0xff]).to_string(), "000ab0ff");
    }

    #[test]
    fn an_absent_value_renders_as_none() {
        assert_eq!(OrNone::<u32>(None).to_string(), "none");
        assert_eq!(OrNone(Some(7u32)).to_string(), "7");
    }

    #[test]
    fn same_path_holds_only_for_the_established_transport_and_address() {
        let addr = TransportAddr::from_string("10.0.0.1:2121");
        let other = TransportAddr::from_string("10.0.0.2:2121");
        let t1 = TransportId::new(1);
        let t2 = TransportId::new(2);
        let link = Some((t1, addr.clone()));

        assert!(Msg1Path::new(t1, &addr, link.clone()).same_path());
        assert!(!Msg1Path::new(t2, &addr, link.clone()).same_path());
        assert!(!Msg1Path::new(t1, &other, link.clone()).same_path());

        let none = Msg1Path::new(t1, &addr, None);
        assert!(!none.same_path());
        assert_eq!(none.link_tid().to_string(), "none");
        assert_eq!(none.link_addr().to_string(), "none");

        let p = Msg1Path::new(t2, &other, link);
        assert_eq!(p.link_tid().to_string(), "transport:1");
        assert_eq!(p.link_addr().to_string(), "10.0.0.1:2121");
    }

    #[test]
    fn the_trial_reads_whether_a_pending_was_held_and_whether_the_gate_tried_it() {
        assert_eq!(Trial::of(false, false).to_string(), "not-run-no-pending");
        assert_eq!(Trial::of(false, true).to_string(), "not-run-no-pending");
        assert_eq!(Trial::of(true, false).to_string(), "not-run-kbit-equal");
        assert_eq!(Trial::of(true, true).to_string(), "failed");
    }

    #[test]
    fn the_log_budget_admits_its_burst_then_one_line_a_second_with_the_withheld_count() {
        let t0 = Instant::now();
        let mut budget = LogBudget::new(t0);
        for _ in 0..BUDGET_BURST {
            assert_eq!(budget.admit(t0), Some(0));
        }
        assert_eq!(budget.admit(t0), None);
        assert_eq!(budget.admit(t0), None);

        let t1 = t0 + std::time::Duration::from_secs(1);
        assert_eq!(budget.admit(t1), Some(2), "the withheld count is reported");
        assert_eq!(budget.admit(t1), None, "and only one line is admitted");
        let t2 = t1 + std::time::Duration::from_secs(1);
        assert_eq!(budget.admit(t2), Some(1), "the count was reset");
    }

    #[test]
    fn a_key_view_without_a_peer_renders_none_for_every_field() {
        let v = KeyView::of(None, None);
        for value in [
            v.slot.to_string(),
            v.kbit_ours.to_string(),
            v.epoch.to_string(),
            v.prev_epoch.to_string(),
            v.pending_epoch.to_string(),
        ] {
            assert_eq!(value, "none");
        }
    }
}
