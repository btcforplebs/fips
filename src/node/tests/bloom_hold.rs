//! FilterAnnounce hold for newly promoted peers.
//!
//! A FilterAnnounce to a peer waits until that peer has sent an authenticated
//! frame since it was promoted. These tests drive one side of a handshake at a
//! time over the loopback transport, so the frames each node has heard are
//! exactly the ones the test chose to deliver.

use super::bloom::drain_quiet;
use super::spanning_tree::*;
use super::*;

/// Run node `a`'s handshake to node `b` until `b` promotes `a` on the msg3,
/// without letting `b` hear anything after it: `b` answers the msg1, `a`
/// completes the msg2 and promotes `b`, and `b` handles only the msg3. The
/// frames `a` sent after its msg3 are returned, unheard by `b`.
async fn promote_at_responder_unheard(
    nodes: &mut [TestNode],
    a: usize,
    b: usize,
) -> Vec<ReceivedPacket> {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG3};

    initiate_handshake(nodes, a, b).await;
    assert_eq!(
        process_available_packets(&mut nodes[b..=b]).await,
        1,
        "setup: only the msg1 is queued at the responder"
    );
    assert_eq!(
        process_available_packets(&mut nodes[a..=a]).await,
        1,
        "setup: only the msg2 is queued at the initiator"
    );
    let msg3 = nodes[b]
        .packet_rx
        .try_recv()
        .expect("setup: the msg3 is queued at the responder");
    assert_eq!(
        CommonPrefix::parse(&msg3.data).map(|p| p.phase),
        Some(PHASE_MSG3),
        "setup: the responder's first packet is the msg3"
    );
    nodes[b].node.handle_msg3(msg3).await;
    std::iter::from_fn(|| nodes[b].packet_rx.try_recv().ok()).collect()
}

/// Run the bloom tick on `node` three times.
async fn tick_thrice(node: &mut Node) {
    for _ in 0..3 {
        node.check_bloom_state().await;
    }
}

/// Assert that `node` holds a pending FilterAnnounce to `peer` without having
/// sent one: the send counter is still `sent_before`, no send is recorded for
/// the peer, and the update is still pending rather than dropped.
fn assert_held(node: &Node, peer: &NodeAddr, sent_before: u64, who: &str) {
    assert_eq!(
        node.metrics().bloom.sent.get(),
        sent_before,
        "{who}: no FilterAnnounce may be sent to a peer that has sent no frame"
    );
    assert_eq!(
        node.bloom_state.last_update_sent(peer),
        None,
        "{who}: no send may be recorded for the held peer"
    );
    assert!(
        node.bloom_state.needs_update(peer),
        "{who}: the held update must stay pending"
    );
}

#[tokio::test]
async fn a_responder_holds_the_filter_announce_until_the_new_peer_sends_a_frame() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    nodes[1].node.bloom_state.set_update_debounce_ms(0);

    let unheard = promote_at_responder_unheard(&mut nodes, 0, 1).await;
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "setup: B must promote A on the msg3"
    );
    assert!(
        !unheard.is_empty(),
        "setup: A must have sent B its TreeAnnounce after the msg3"
    );

    let sent = nodes[1].node.metrics().bloom.sent.get();
    tick_thrice(&mut nodes[1].node).await;
    assert_held(&nodes[1].node, &a, sent, "B");

    // B authenticates A's TreeAnnounce.
    for packet in unheard {
        nodes[1].node.handle_encrypted_frame(packet).await;
    }
    nodes[1].node.check_bloom_state().await;
    assert_eq!(
        nodes[1].node.metrics().bloom.sent.get(),
        sent + 1,
        "B must send the held FilterAnnounce on the first tick after A's frame"
    );
    process_available_packets(&mut nodes[..1]).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&b)
            .expect("A must have promoted B")
            .filter_sequence()
            > 0,
        "the filter must reach A"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn an_initiator_holds_the_filter_announce_until_the_responder_sends_a_frame() {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};

    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    nodes[0].node.bloom_state.set_update_debounce_ms(0);
    nodes[1].node.bloom_state.set_update_debounce_ms(0);

    initiate_handshake(&mut nodes, 0, 1).await;
    process_available_packets(&mut nodes[1..]).await;

    let msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("setup: B's msg2 must be queued at A");
    let phase = CommonPrefix::parse(&msg2.data).map(|p| p.phase);
    assert_eq!(
        phase,
        Some(PHASE_MSG2),
        "setup: A's first packet is the msg2"
    );
    nodes[0].node.handle_msg2(msg2).await;
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "setup: A must promote B on the msg2"
    );
    assert!(
        nodes[0].packet_rx.is_empty(),
        "setup: B has sent A nothing after its msg2"
    );

    let sent = nodes[0].node.metrics().bloom.sent.get();
    tick_thrice(&mut nodes[0].node).await;
    assert_held(&nodes[0].node, &b, sent, "A");

    // B completes the msg3, promotes A, authenticates A's TreeAnnounce and
    // sends its own and its filter; A authenticates those, so B is now heard
    // at A.
    process_available_packets(&mut nodes[1..]).await;
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "setup: B must promote A on the msg3"
    );
    process_available_packets(&mut nodes[1..]).await;
    let sent_b = nodes[1].node.metrics().bloom.sent.get();
    nodes[1].node.check_bloom_state().await;
    assert_eq!(
        nodes[1].node.metrics().bloom.sent.get(),
        sent_b + 1,
        "setup: B, having heard A, must send its filter"
    );
    process_available_packets(&mut nodes[..1]).await;
    nodes[0].node.check_bloom_state().await;
    assert_eq!(
        nodes[0].node.metrics().bloom.sent.get(),
        sent + 1,
        "A must send the held FilterAnnounce on the first tick after B's frame"
    );
    process_available_packets(&mut nodes[1..]).await;
    assert!(
        nodes[1]
            .node
            .get_peer(&a)
            .expect("B must still have A")
            .filter_sequence()
            > 0,
        "the filter must reach B"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_peer_heard_on_an_earlier_link_is_held_again_on_a_new_link_that_sends_nothing() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    drain_quiet(&mut nodes).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    assert!(
        nodes[1].node.bloom_state.last_update_sent(&a).is_some(),
        "setup: B must have sent A a filter on the first link"
    );

    nodes[0].node.remove_active_peer(&b);
    nodes[1].node.remove_active_peer(&a);
    drain_quiet(&mut nodes).await;
    nodes[1].node.bloom_state.set_update_debounce_ms(0);
    let sent = nodes[1].node.metrics().bloom.sent.get();

    promote_at_responder_unheard(&mut nodes, 0, 1).await;
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "setup: B must promote A again on the new msg3"
    );

    tick_thrice(&mut nodes[1].node).await;
    assert_held(&nodes[1].node, &a, sent, "B");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn the_filter_announce_hold_applies_only_to_the_peer_that_has_sent_no_frame() {
    // B (node 1) and C (node 2) are peers that have heard each other; A
    // (node 0) is new and B has handled only its handshake messages.
    let mut nodes = run_tree_test(3, &[(1, 2)], false).await;
    drain_quiet(&mut nodes).await;
    let a = *nodes[0].node.node_addr();
    let c = *nodes[2].node.node_addr();

    promote_at_responder_unheard(&mut nodes, 0, 1).await;
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "setup: B must promote A on the msg3"
    );

    let node = &mut nodes[1].node;
    node.bloom_state.set_update_debounce_ms(0);
    node.bloom_state.mark_update_needed(c);
    assert!(
        node.bloom_state.needs_update(&a),
        "setup: A's promotion must leave an update pending"
    );
    let sent = node.metrics().bloom.sent.get();
    let c_stamp = node.bloom_state.last_update_sent(&c);

    node.check_bloom_state().await;

    assert!(
        !node.bloom_state.needs_update(&c),
        "the heard peer C must be sent its update"
    );
    assert_ne!(
        node.bloom_state.last_update_sent(&c),
        c_stamp,
        "a new send to C must be recorded"
    );
    assert_eq!(
        node.bloom_state.last_update_sent(&a),
        None,
        "the unheard peer A must not be sent a filter"
    );
    assert!(
        node.bloom_state.needs_update(&a),
        "A's update must stay pending"
    );
    assert_eq!(
        node.metrics().bloom.sent.get(),
        sent + 1,
        "exactly one FilterAnnounce, to C"
    );

    cleanup_nodes(&mut nodes).await;
}
