//! Classification of a same-epoch msg1 by where it arrived: on the existing
//! peer's established link or off it, and whether that link still works; and
//! the record of the link-setup msg1 a peering was promoted from.

use super::util::{establish_snapshot, wire_outcome};
use crate::NodeAddr;
use crate::proto::fmp::core::ENDED_MSG1_RECORD;
use crate::proto::fmp::{
    AnsweredMsg1s, EstablishSnapshot, Fmp, InboundDecision, InboundReject, Msg1Digest, RekeyAnswer,
};

/// The epoch the existing peer and the msg1 share.
const EPOCH: [u8; 8] = [7u8; 8];

/// An existing peer at [`EPOCH`] with a session aged past the 30 s rekey
/// floor and nothing pending: the state in which a same-epoch msg1 is
/// classified as a rekey.
fn aged_snapshot() -> EstablishSnapshot {
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some(EPOCH);
    snap.has_session = true;
    snap.is_healthy = true;
    snap.existing_session_age_secs = 31;
    snap
}

/// All-0xFF NodeAddr: larger than any pubkey-derived peer address, so with
/// it as our own the peer wins the dual-initiation tie-break.
fn max_node_addr() -> NodeAddr {
    NodeAddr::from_bytes([0xFF; 16])
}

#[test]
fn an_off_link_msg1_on_an_aged_session_is_refused_while_the_link_is_reachable() {
    let fmp = Fmp::new();
    let mut snap = aged_snapshot();
    snap.msg1_on_link = false;
    snap.link_reachable = true;
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire_outcome(Some(EPOCH))),
        InboundDecision::Reject {
            reason: InboundReject::OffLink
        }
    ));
}

#[test]
fn an_off_link_msg1_with_the_link_unreachable_is_classified_as_before() {
    // The established connection has gone: the msg1 is a redial and is
    // answered as a rekey, on its own connection if need be.
    let fmp = Fmp::new();
    let mut snap = aged_snapshot();
    snap.msg1_on_link = false;
    snap.link_reachable = false;
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire_outcome(Some(EPOCH))),
        InboundDecision::RekeyRespond {
            abandon_first: false,
            ..
        }
    ));
}

#[test]
fn an_on_link_msg1_is_classified_as_before_whatever_the_link_state() {
    let fmp = Fmp::new();
    for link_reachable in [true, false] {
        let mut snap = aged_snapshot();
        snap.msg1_on_link = true;
        snap.link_reachable = link_reachable;
        let decision = fmp.establish_inbound(&snap, &wire_outcome(Some(EPOCH)));
        assert!(
            matches!(
                decision,
                InboundDecision::RekeyRespond {
                    abandon_first: false,
                    ..
                }
            ),
            "link reachable {link_reachable}: expected RekeyRespond, got {decision:?}"
        );
    }
}

#[test]
fn an_off_link_msg1_is_refused_before_the_held_answer_and_the_tie_break() {
    let fmp = Fmp::new();

    // A held answer whose msg1 matches would otherwise be resent.
    let wire = wire_outcome(Some(EPOCH));
    let mut snap = aged_snapshot();
    snap.pending_new_session = true;
    snap.held_answer = Some(RekeyAnswer {
        msg1: wire.msg1_digest,
        msg2: vec![0x02; 4],
    });
    snap.link_reachable = true;
    snap.msg1_on_link = true;
    assert!(
        matches!(
            fmp.establish_inbound(&snap, &wire),
            InboundDecision::ResendRekeyMsg2 { .. }
        ),
        "precondition: on the link, the held answer is resent"
    );
    snap.msg1_on_link = false;
    let decision = fmp.establish_inbound(&snap, &wire);
    assert!(
        matches!(
            decision,
            InboundDecision::Reject {
                reason: InboundReject::OffLink
            }
        ),
        "off the link, the held answer must not be resent: got {decision:?}"
    );

    // Our own rekey in flight, with the sender winning the tie-break, would
    // otherwise be abandoned.
    let mut snap = aged_snapshot();
    snap.rekey_in_progress = true;
    snap.our_node_addr = max_node_addr();
    snap.link_reachable = true;
    snap.msg1_on_link = true;
    assert!(
        matches!(
            fmp.establish_inbound(&snap, &wire),
            InboundDecision::RekeyRespond {
                abandon_first: true,
                ..
            }
        ),
        "precondition: on the link, the sender wins the tie-break"
    );
    snap.msg1_on_link = false;
    let decision = fmp.establish_inbound(&snap, &wire);
    assert!(
        matches!(
            decision,
            InboundDecision::Reject {
                reason: InboundReject::OffLink
            }
        ),
        "off the link, our own rekey must not be abandoned: got {decision:?}"
    );
}

#[test]
fn an_off_link_msg1_under_30_s_still_gets_the_stored_msg2() {
    let fmp = Fmp::new();
    let mut snap = aged_snapshot();
    snap.existing_session_age_secs = 29;
    snap.existing_msg2 = Some(vec![0x02; 4]);
    snap.msg1_on_link = false;
    snap.link_reachable = true;
    match fmp.establish_inbound(&snap, &wire_outcome(Some(EPOCH))) {
        InboundDecision::ResendMsg2 { msg2 } => assert_eq!(msg2, Some(vec![0x02; 4])),
        other => panic!("expected ResendMsg2, got {other:?}"),
    }
}

#[test]
fn a_link_setup_msg1_recorded_at_promotion_is_answered_before() {
    let mut record = AnsweredMsg1s::default();
    let setup = Msg1Digest::of(b"link setup");
    record.end_setup(setup);
    assert!(record.ended(&setup), "the link-setup msg1 is recorded");
    assert!(record.held().is_none(), "recording it holds no answer");
    assert!(!record.ended(&Msg1Digest::of(b"never seen")));

    // It shares the ended list's bound with the rekey cycles.
    let digest = |i: usize| Msg1Digest::of(&i.to_le_bytes());
    for i in 0..ENDED_MSG1_RECORD {
        record.end_setup(digest(i));
    }
    assert!(
        !record.ended(&setup),
        "the oldest beyond the bound is forgotten"
    );
    assert!(record.ended(&digest(0)));
    assert!(record.ended(&digest(ENDED_MSG1_RECORD - 1)));
}
