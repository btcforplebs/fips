//! Link rekeys between two ends whose K-bits have fallen out of step.
//!
//! The K-bit in an established frame's header says which key epoch the
//! sender is on. A peer restart that our rekey reveals leaves the two ends of
//! a link holding K-bits that do not reflect the same history: the restarted
//! peer promotes our rekey as a fresh link at K-bit 0, while we complete it as
//! a rekey. After that, the peer's frames on a new session can carry a K-bit
//! equal to ours. These tests drive that path over loopback, with the XX
//! rekey's three messages, and assert on promotion of the pending session and
//! on the receiver's consecutive decryption failure count, never on whether
//! the peer survives.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node_with_config,
    process_available_packets, restarted_node,
};
use crate::proto::fmp::wire::{
    CommonPrefix, FLAG_KEY_EPOCH, PHASE_ESTABLISHED, PHASE_MSG2, PHASE_MSG3,
    build_established_header,
};
use crate::proto::link::LinkMessageType;
use rand::Rng;

/// Rekey interval for both ends of the pairs below.
const REKEY_AFTER_SECS: u64 = 60;

/// Frames a test sends after the cutover it is about, well past the 20
/// consecutive failures at which the base code removes a peer.
const FRAMES: usize = 25;

/// A config with rekey on, triggered `after_secs` after the last one and never
/// by message count.
pub(super) fn rekey_config(after_secs: u64) -> crate::config::Config {
    let mut config = crate::config::Config::new();
    config.node.rekey.enabled = true;
    config.node.rekey.after_secs = after_secs;
    config.node.rekey.after_messages = u64::MAX;
    config
}

/// A session age past the jittered rekey trigger.
pub(super) fn trigger_age() -> Duration {
    Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1)
}

/// Send one heartbeat from `from` to its peer `to` on `from`'s current
/// session.
pub(super) async fn heartbeat(from: &mut TestNode, to: &NodeAddr) {
    from.node
        .send_encrypted_link_message(to, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .expect("heartbeat send");
}

/// Process every packet queued at `tn`, and only there.
pub(super) async fn deliver(tn: &mut TestNode) -> usize {
    process_available_packets(std::slice::from_mut(tn)).await
}

/// `tn`'s consecutive decryption failure count for `peer`. A peer that is no
/// longer held panics here, which the caller's test counts as a failure.
pub(super) fn failures(tn: &TestNode, peer: &NodeAddr) -> u32 {
    tn.node
        .get_peer(peer)
        .expect("the receiver still holds the sender as a peer")
        .consecutive_decrypt_failures()
}

/// Age the link session each node holds for the other by `age`.
pub(super) fn age_link(nodes: &mut [TestNode], a: usize, b: usize, age: Duration) {
    let a_addr = *nodes[a].node.node_addr();
    let b_addr = *nodes[b].node.node_addr();
    nodes[a]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_session_established(age);
    nodes[b]
        .node
        .get_peer_mut(&a_addr)
        .unwrap()
        .test_backdate_session_established(age);
}

/// Two loopback nodes peered over FMP, node 0 dialling node 1.
pub(super) async fn linked_pair(
    cfg0: crate::config::Config,
    cfg1: crate::config::Config,
) -> Vec<TestNode> {
    let mut nodes = vec![
        make_test_node_with_config(cfg0, 1280).await,
        make_test_node_with_config(cfg1, 1280).await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr1).is_some() && nodes[1].node.get_peer(&addr0).is_some(),
        "precondition: the pair is peered"
    );
    nodes
}

/// Start `from`'s rekey to `to` and run its three messages: `to` answers the
/// msg1, `from` completes the msg2 and holds an initiator pending, and `to`
/// completes the msg3 and holds a responder pending. Returns the index of the
/// pending `to` holds.
pub(super) async fn rekey_to_pending(
    nodes: &mut [TestNode],
    from: usize,
    to: usize,
) -> SessionIndex {
    let from_addr = *nodes[from].node.node_addr();
    let to_addr = *nodes[to].node.node_addr();
    nodes[from].node.check_rekey().await;
    assert!(
        nodes[from]
            .node
            .get_peer(&to_addr)
            .unwrap()
            .rekey_in_progress(),
        "precondition: the rekey initiator started a rekey"
    );
    assert_eq!(
        deliver(&mut nodes[to]).await,
        1,
        "precondition: only the rekey msg1 is queued at the responder"
    );
    assert_eq!(
        deliver(&mut nodes[from]).await,
        1,
        "precondition: only the msg2 is queued at the rekey initiator"
    );
    assert!(
        nodes[from]
            .node
            .get_peer(&to_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "precondition: the rekey initiator holds its pending after the msg2"
    );
    assert_eq!(
        deliver(&mut nodes[to]).await,
        1,
        "precondition: only the msg3 is queued at the responder"
    );
    let peer = nodes[to].node.get_peer(&from_addr).unwrap();
    assert!(
        peer.pending_new_session().is_some(),
        "precondition: the responder holds its pending after the msg3"
    );
    peer.pending_our_index().unwrap()
}

/// Run `node`'s rekey tick, which cuts over the pending it initiated.
pub(super) async fn cutover(tn: &mut TestNode, peer: &NodeAddr) {
    let expected = tn.node.get_peer(peer).unwrap().pending_our_index();
    tn.node.check_rekey().await;
    let p = tn.node.get_peer(peer).unwrap();
    assert!(
        p.pending_new_session().is_none() && p.our_index() == expected,
        "precondition: the tick cut over to the pending session"
    );
}

/// A link node A dialled to node B, after B restarted and A's rekey msg1
/// revealed it. Built by [`restart_revealed_by_our_rekey`].
struct RestartedPeer {
    /// A at 0, the restarted B at 1.
    nodes: Vec<TestNode>,
    a_addr: NodeAddr,
    b_addr: NodeAddr,
    /// The index of the pending session A's rekey produced.
    pending_index: SessionIndex,
    /// The restarted B's frames to A that arrived after its msg2, held back.
    held: Vec<ReceivedPacket>,
}

/// Peer A and B, restart B, and let A's rekey reach the restarted B.
///
/// B has no peer for A, so it promotes A's rekey msg3 as a fresh link at
/// K-bit 0. A completes B's msg2 as a rekey, sees B's new startup epoch, and
/// holds the session as an initiator pending. B's first frames on the new
/// link, which name A's pending index, are held back from A.
async fn restart_revealed_by_our_rekey() -> RestartedPeer {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();

    let restarted = restarted_node(&nodes[1], rekey_config(REKEY_AFTER_SECS));
    drop(std::mem::replace(&mut nodes[1], restarted));

    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_session_established(trigger_age());
    nodes[0].node.check_rekey().await;
    assert!(
        nodes[0].node.get_peer(&b_addr).unwrap().rekey_in_progress(),
        "precondition: A started a rekey to the restarted B"
    );
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only A's rekey msg1 is queued at the restarted B"
    );

    let mut queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    let at = queued
        .iter()
        .position(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2))
        .expect("precondition: the restarted B's msg2 is queued at A");
    let msg2 = queued.remove(at);
    nodes[0].node.handle_msg2(msg2).await;

    let pending_index = {
        let peer = nodes[0].node.get_peer(&b_addr).unwrap();
        assert!(
            peer.pending_new_session().is_some(),
            "precondition: A holds an initiator pending after the msg2"
        );
        assert_eq!(
            peer.remote_epoch(),
            Some(nodes[1].node.startup_epoch()),
            "precondition: A recorded the restarted B's startup epoch"
        );
        peer.pending_our_index().unwrap()
    };

    let msg3s: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[1].packet_rx.try_recv().ok()).collect();
    assert!(
        msg3s
            .iter()
            .all(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG3)),
        "precondition: only A's msg3 is queued at the restarted B"
    );
    for msg3 in msg3s {
        nodes[1].node.handle_msg3(msg3).await;
    }
    assert!(
        nodes[1].node.get_peer(&a_addr).is_some(),
        "precondition: the restarted B promoted A's rekey as a fresh link"
    );
    assert!(
        !nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
        "precondition: the restarted B is at K-bit 0"
    );

    queued.extend(std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()));
    assert!(
        queued
            .iter()
            .all(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_ESTABLISHED)),
        "precondition: everything else queued at A is an established frame"
    );

    RestartedPeer {
        nodes,
        a_addr,
        b_addr,
        pending_index,
        held: queued,
    }
}

/// Hand each held frame to A, asserting that every one decrypts.
async fn deliver_held(r: &mut RestartedPeer) {
    for packet in std::mem::take(&mut r.held) {
        r.nodes[0].node.handle_encrypted_frame(packet).await;
        assert_eq!(
            failures(&r.nodes[0], &r.b_addr),
            0,
            "precondition: A decrypts the restarted B's first frames on its new session"
        );
    }
}

/// Origin of the split: our rekey reveals a peer restart, we cut over, and
/// then the restarted peer rekeys. Its frames on the new session must be
/// adopted by A without a decryption failure.
#[tokio::test]
async fn a_peer_restart_revealed_by_our_rekey_leaves_the_peers_next_rekey_adopted_without_decrypt_failures()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    cutover(&mut r.nodes[0], &b_addr).await;
    deliver_held(&mut r).await;

    // B rekeys and A answers.
    age_link(&mut r.nodes, 0, 1, trigger_age());
    let a_pending = rekey_to_pending(&mut r.nodes, 1, 0).await;
    cutover(&mut r.nodes[1], &a_addr).await;
    let frame_kbit = r.nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit();

    for n in 1..=FRAMES {
        heartbeat(&mut r.nodes[1], &a_addr).await;
        deliver(&mut r.nodes[0]).await;
        assert_eq!(
            failures(&r.nodes[0], &b_addr),
            0,
            "A's decrypt-failure count after B's frame {n}"
        );
        if n == 1 {
            let peer = r.nodes[0].node.get_peer(&b_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(a_pending),
                "A's pending session is promoted by B's frame 1"
            );
            assert_eq!(
                peer.current_k_bit(),
                frame_kbit,
                "A's K-bit equals the frame's after the promotion"
            );
        }
    }

    cleanup_nodes(&mut r.nodes).await;
}

/// The restarted peer's first frames name our pending index with K-bit 0,
/// equal to ours. They must promote the pending before our own tick does.
#[tokio::test]
async fn a_restarted_peers_first_frames_on_our_pending_index_promote_it_before_our_cutover() {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    let held = std::mem::take(&mut r.held);
    let total = held.len() + 3;
    let mut held = held.into_iter();

    for n in 1..=total {
        match held.next() {
            Some(packet) => r.nodes[0].node.handle_encrypted_frame(packet).await,
            None => {
                heartbeat(&mut r.nodes[1], &a_addr).await;
                deliver(&mut r.nodes[0]).await;
            }
        }
        assert_eq!(
            failures(&r.nodes[0], &b_addr),
            0,
            "A's decrypt-failure count after B's frame {n}"
        );
        if n == 1 {
            let peer = r.nodes[0].node.get_peer(&b_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(r.pending_index),
                "A's pending session is promoted by B's frame 1"
            );
            assert!(
                !peer.current_k_bit(),
                "A's K-bit is the frame's, 0, after the promotion"
            );
        }
    }

    cleanup_nodes(&mut r.nodes).await;
}

/// A peer's frame on our pending index authenticates against the pending
/// session even when its K-bit already equals ours. It must promote the
/// pending, and our K-bit must then be the frame's.
#[tokio::test]
async fn a_peer_rekey_frame_on_our_pending_index_promotes_it_even_when_the_k_bits_already_match() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .force_kbit(true);

    // B rekeys, A answers, B cuts over from K-bit 0 to 1.
    let a_pending = rekey_to_pending(&mut nodes, 1, 0).await;
    cutover(&mut nodes[1], &a_addr).await;
    assert!(
        nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
        "precondition: B sends at K-bit 1 after its cutover"
    );

    for n in 1..=FRAMES {
        heartbeat(&mut nodes[1], &a_addr).await;
        deliver(&mut nodes[0]).await;
        assert_eq!(
            failures(&nodes[0], &b_addr),
            0,
            "A's decrypt-failure count after B's frame {n}"
        );
        if n == 1 {
            let peer = nodes[0].node.get_peer(&b_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(a_pending),
                "A's pending session is promoted by B's frame 1"
            );
            assert!(
                peer.current_k_bit(),
                "A's K-bit is the frame's, 1, after the promotion"
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// After a cutover on a rekey that revealed a peer restart, our K-bit must be
/// 0, the value the restarted peer holds, and a later cutover must toggle it
/// as usual. A peer that only tries its pending on a K-bit that differs from
/// its own must then adopt our next rekey.
#[tokio::test]
async fn our_cutover_after_a_restart_revealing_msg2_takes_k_bit_zero_so_an_old_gate_peer_adopts_our_next_rekey()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    cutover(&mut r.nodes[0], &b_addr).await;
    r.nodes[1].node.get_peer_mut(&a_addr).unwrap().set_oldgate();
    deliver_held(&mut r).await;

    // A rekeys again, B answers, A cuts over.
    age_link(&mut r.nodes, 0, 1, trigger_age());
    let b_pending = rekey_to_pending(&mut r.nodes, 0, 1).await;
    cutover(&mut r.nodes[0], &b_addr).await;

    for n in 1..=FRAMES {
        heartbeat(&mut r.nodes[0], &b_addr).await;
        deliver(&mut r.nodes[1]).await;
        assert_eq!(
            failures(&r.nodes[1], &a_addr),
            0,
            "B's decrypt-failure count after A's frame {n}"
        );
        if n == 1 {
            let peer = r.nodes[1].node.get_peer(&a_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(b_pending),
                "B's pending session is promoted by A's frame 1"
            );
        }
    }
    assert_eq!(
        r.nodes[0].node.get_peer(&b_addr).unwrap().current_k_bit(),
        r.nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
        "A's K-bit equals B's after B adopts A's rekey"
    );

    cleanup_nodes(&mut r.nodes).await;
}

/// A pair caught mid-rekey: node 0 (B) initiated and holds its initiator
/// pending, node 1 (A) completed B's msg3 and holds the responder pending, and
/// neither has cut over. Returns A's pending index.
async fn responder_pending_pair() -> (Vec<TestNode>, SessionIndex) {
    let mut nodes = linked_pair(rekey_config(REKEY_AFTER_SECS), rekey_config(u64::MAX)).await;
    age_link(&mut nodes, 0, 1, trigger_age());
    let index = rekey_to_pending(&mut nodes, 0, 1).await;
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert!(held.is_empty(), "precondition: nothing is queued at B");
    (nodes, index)
}

/// A frame naming the pending index that does not authenticate against any
/// session neither promotes the pending nor escapes the failure count, at
/// either K-bit.
#[tokio::test]
async fn a_frame_on_the_pending_index_that_does_not_authenticate_neither_promotes_nor_escapes_the_failure_count()
 {
    let (mut nodes, pending_index) = responder_pending_pair().await;
    let b_addr = *nodes[0].node.node_addr();
    let (kbit, index) = {
        let peer = nodes[1].node.get_peer(&b_addr).unwrap();
        (peer.current_k_bit(), peer.our_index())
    };
    let failures_before = failures(&nodes[1], &b_addr);

    for (i, frame_kbit) in [kbit, !kbit].into_iter().enumerate() {
        let mut ciphertext = vec![0u8; 48];
        rand::rng().fill_bytes(&mut ciphertext);
        let flags = if frame_kbit { FLAG_KEY_EPOCH } else { 0 };
        let mut data = build_established_header(
            pending_index,
            1000 + i as u64,
            flags,
            ciphertext.len() as u16,
        )
        .to_vec();
        data.extend_from_slice(&ciphertext);
        let packet = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), data);
        nodes[1].node.handle_encrypted_frame(packet).await;
    }

    let peer = nodes[1].node.get_peer(&b_addr).unwrap();
    assert_eq!(
        peer.pending_our_index(),
        Some(pending_index),
        "A keeps its pending session after frames that do not authenticate"
    );
    assert_eq!(peer.current_k_bit(), kbit, "A's K-bit is unchanged");
    assert_eq!(peer.our_index(), index, "A's current index is unchanged");
    assert_eq!(
        failures(&nodes[1], &b_addr),
        failures_before + 2,
        "A counts both frames as decryption failures"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A frame on the current index with a K-bit that differs from ours is tried
/// against the pending session, fails there, and must still decrypt on the
/// current session.
#[tokio::test]
async fn a_k_flipped_frame_on_the_current_index_that_fails_the_trial_still_decrypts_on_the_current_session()
 {
    let (mut nodes, pending_index) = responder_pending_pair().await;
    let a_addr = *nodes[1].node.node_addr();
    let b_addr = *nodes[0].node.node_addr();
    let (kbit, index, recv_before) = {
        let peer = nodes[1].node.get_peer(&b_addr).unwrap();
        (
            peer.current_k_bit(),
            peer.our_index(),
            peer.link_stats().packets_recv,
        )
    };
    nodes[0]
        .node
        .get_peer_mut(&a_addr)
        .unwrap()
        .force_kbit(!kbit);

    heartbeat(&mut nodes[0], &a_addr).await;
    deliver(&mut nodes[1]).await;

    let peer = nodes[1].node.get_peer(&b_addr).unwrap();
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "A's decrypt-failure count after B's K-flipped frame"
    );
    assert_eq!(
        peer.pending_our_index(),
        Some(pending_index),
        "A keeps its pending session"
    );
    assert_eq!(peer.current_k_bit(), kbit, "A's K-bit is unchanged");
    assert_eq!(peer.our_index(), index, "A's current index is unchanged");
    assert_eq!(
        peer.link_stats().packets_recv,
        recv_before + 1,
        "A receives B's frame on its current session"
    );

    cleanup_nodes(&mut nodes).await;
}
