//! Tests that a transit forward never goes back to the peer the request came
//! from, while the tree-versus-fallback choice is still made on the full tree
//! set.

use super::util::{MockRoutingView, action_peers, make_request};
use crate::NodeAddr;
use crate::proto::lookup::*;
use crate::testutil::make_node_addr;

/// Build the routing view from `(addr, is_tree, may_reach)` entries.
fn view(peers: Vec<(NodeAddr, bool, bool)>) -> MockRoutingView {
    MockRoutingView { peers }
}

/// Run `plan_forward` from `from` and return `(peers, used_fallback)`, or
/// `None` for `NoPeers`. Panics on `TtlExhausted`, which no test here expects.
fn forward(from: &NodeAddr, rv: &MockRoutingView) -> Option<(Vec<NodeAddr>, bool)> {
    let mut request = make_request(3);
    match plan_forward(&mut request, from, rv) {
        ForwardOutcome::Forward {
            actions,
            used_fallback,
        } => Some((action_peers(&actions), used_fallback)),
        ForwardOutcome::NoPeers => None,
        ForwardOutcome::TtlExhausted => panic!("TTL 3 must not be exhausted"),
    }
}

#[test]
fn forward_never_sends_the_request_back_to_the_tree_peer_it_came_from() {
    let parent = make_node_addr(1);
    let child = make_node_addr(2);
    let rv = view(vec![(parent, true, true), (child, true, true)]);
    assert_eq!(
        forward(&child, &rv),
        Some((vec![parent], false)),
        "a request from tree peer C must go only to the other matching tree peer"
    );
}

#[test]
fn forward_returns_no_peers_when_the_sender_is_the_only_matching_tree_peer_even_with_non_tree_matches()
 {
    let parent = make_node_addr(1);
    let child = make_node_addr(2);
    let rv = view(vec![
        (parent, true, true),
        (child, true, false),
        (make_node_addr(3), false, true),
        (make_node_addr(4), false, true),
        (make_node_addr(5), false, true),
    ]);
    assert_eq!(
        forward(&parent, &rv),
        None,
        "the tree already carried this request; it must neither echo nor fall back"
    );
}

#[test]
fn fallback_never_sends_the_request_back_to_the_non_tree_peer_it_came_from() {
    let a = make_node_addr(3);
    let b = make_node_addr(4);
    let rv = view(vec![
        (make_node_addr(1), true, false),
        (a, false, true),
        (b, false, true),
    ]);
    assert_eq!(
        forward(&a, &rv),
        Some((vec![b], true)),
        "the fallback must exclude the non-tree sender"
    );
}

#[test]
fn fallback_returns_no_peers_when_the_non_tree_sender_is_the_only_match() {
    let a = make_node_addr(3);
    let rv = view(vec![(make_node_addr(1), true, false), (a, false, true)]);
    assert_eq!(
        forward(&a, &rv),
        None,
        "a fallback holding only the sender must yield NoPeers"
    );
}

#[test]
fn forward_from_the_parent_still_reaches_the_child_whose_filter_matches() {
    let parent = make_node_addr(1);
    let child = make_node_addr(2);
    let rv = view(vec![(parent, true, false), (child, true, true)]);
    assert_eq!(forward(&parent, &rv), Some((vec![child], false)));
}

#[test]
fn forward_from_a_non_tree_sender_still_uses_every_matching_tree_peer() {
    let parent = make_node_addr(1);
    let child = make_node_addr(2);
    let a = make_node_addr(3);
    let rv = view(vec![
        (parent, true, true),
        (child, true, true),
        (a, false, true),
    ]);
    assert_eq!(forward(&a, &rv), Some((vec![parent, child], false)));
}

#[test]
fn forward_from_a_tree_peer_still_falls_back_when_no_tree_peer_matches() {
    let parent = make_node_addr(1);
    let child = make_node_addr(2);
    let a = make_node_addr(3);
    let b = make_node_addr(4);
    let rv = view(vec![
        (parent, true, false),
        (child, true, false),
        (a, false, true),
        (b, false, true),
    ]);
    assert_eq!(forward(&parent, &rv), Some((vec![a, b], true)));
}

#[test]
fn fallback_from_a_non_matching_non_tree_sender_still_reaches_the_other_match() {
    let a = make_node_addr(3);
    let b = make_node_addr(4);
    let rv = view(vec![
        (make_node_addr(1), true, false),
        (a, false, false),
        (b, false, true),
    ]);
    assert_eq!(forward(&a, &rv), Some((vec![b], true)));
}
