//! `Stp::classify_announce` tests for an announce from our current parent.
//!
//! Each test builds a `TreeState` for node X (address 5) under parent P
//! (address 4), stores P's new declaration the way the announce path does
//! (`update_peer` first, no `recompute_coords`), then classifies the announce.
//! Costs are cold-start (empty map, every link 1.0) and no peer is skipped.

use alloc::collections::{BTreeMap, BTreeSet};

use super::util::{add_peer, make_coords, make_node_addr, make_tree_state};
use crate::NodeAddr;
use crate::proto::stp::{ParentDeclaration, ParentEval, Stp, TreeDecision, TreeState};

const X: u8 = 5;
const P: u8 = 4;

/// X under P, with each `(addr, path)` added as a peer at sequence 1.
///
/// `hold_down_secs` is set before the parent switch so the hold-down timer is
/// armed by it.
fn under_parent(p_path: &[u8], others: &[(u8, &[u8])], hold_down_secs: u64) -> TreeState {
    let mut tree = make_tree_state(X, &[X]);
    tree.set_hold_down(hold_down_secs);
    add_peer(&mut tree, P, p_path);
    for &(addr, path) in others {
        add_peer(&mut tree, addr, path);
    }
    tree.set_parent(make_node_addr(P), 2, 1000, 1000);
    tree.recompute_coords();
    let mut expected = vec![X];
    expected.extend_from_slice(p_path);
    let path: Vec<NodeAddr> = tree.my_coords().node_addrs().copied().collect();
    let want: Vec<NodeAddr> = expected.iter().map(|&a| make_node_addr(a)).collect();
    assert_eq!(path, want);
    assert_eq!(tree.root(), make_coords(p_path).root_id());
    tree
}

/// Store P's announce that it is now its own root, at sequence 2.
fn parent_self_roots(tree: &mut TreeState) {
    let stored = tree.update_peer(
        ParentDeclaration::self_root(make_node_addr(P), 2, 2000),
        make_coords(&[P]),
    );
    assert!(
        stored,
        "P's self-root announce must be fresher than its first"
    );
}

/// Store P's announce that it now has `parent` and ancestry `path`, at sequence 2.
fn parent_reannounces(tree: &mut TreeState, parent: u8, path: &[u8]) {
    let stored = tree.update_peer(
        ParentDeclaration::new(make_node_addr(P), make_node_addr(parent), 2, 2000),
        make_coords(path),
    );
    assert!(stored, "P's re-announce must be fresher than its first");
}

fn evaluate(tree: &TreeState) -> ParentEval {
    tree.evaluate_parent(&BTreeMap::new(), &BTreeSet::new())
}

fn classify(tree: &TreeState, switch_suppressed: bool) -> TreeDecision {
    Stp::classify_announce(
        tree,
        make_node_addr(P),
        &BTreeMap::new(),
        &BTreeSet::new(),
        switch_suppressed,
    )
}

fn assert_switch(decision: TreeDecision, to: NodeAddr, seq: u64) {
    assert!(
        matches!(
            decision,
            TreeDecision::Switch { new_parent, new_seq } if new_parent == to && new_seq == seq
        ),
        "expected Switch to {to:?} at seq {seq}"
    );
}

fn assert_ancestry_update(decision: TreeDecision, seq: u64) {
    assert!(
        matches!(
            decision,
            TreeDecision::AncestryUpdate { parent, new_seq }
                if parent == make_node_addr(P) && new_seq == seq
        ),
        "expected AncestryUpdate from P at seq {seq}"
    );
}

#[test]
fn parent_moving_to_worse_root_switches_to_peer_still_on_better_root() {
    let q = make_node_addr(2);
    let mut tree = under_parent(&[P, 1], &[(2, &[2, 1])], 0);
    parent_self_roots(&mut tree);

    assert!(matches!(evaluate(&tree), ParentEval::Mandatory(p) if p == q));
    assert_switch(classify(&tree, false), q, 3);
}

#[test]
fn parent_moving_to_worse_root_switches_even_while_hold_down_is_active() {
    let q = make_node_addr(2);
    let mut tree = under_parent(&[P, 1], &[(2, &[2, 1])], 30);
    assert!(tree.is_switch_suppressed(1500), "hold-down must be engaged");
    parent_self_roots(&mut tree);

    assert_switch(classify(&tree, true), q, 3);
}

#[test]
fn parent_ancestry_change_with_no_better_root_yields_ancestry_update() {
    let mut tree = under_parent(&[P, 1], &[(2, &[2, 6, 7, 1])], 0);
    parent_reannounces(&mut tree, 3, &[P, 3, 1]);

    assert!(matches!(evaluate(&tree), ParentEval::None));
    assert_ancestry_update(classify(&tree, false), 3);
}

#[test]
fn parent_moving_to_worse_root_with_no_better_root_visible_yields_ancestry_update() {
    let mut tree = under_parent(&[P, 1], &[], 0);
    parent_self_roots(&mut tree);

    assert!(matches!(evaluate(&tree), ParentEval::None));
    assert_ancestry_update(classify(&tree, false), 3);
}

#[test]
fn parent_moving_to_better_root_yields_ancestry_update() {
    let mut tree = under_parent(&[P, 1], &[(2, &[2, 1])], 0);
    parent_reannounces(&mut tree, 0, &[P, 0]);

    assert!(matches!(evaluate(&tree), ParentEval::None));
    assert_ancestry_update(classify(&tree, false), 3);
}

#[test]
fn parent_moving_to_worse_root_does_not_switch_to_sibling_reached_through_parent() {
    // Q's stored path runs through P, so it is stale once P has moved: Q will
    // follow P and announce, and X re-evaluates then.
    let mut tree = under_parent(&[P, 1], &[(3, &[3, P, 1])], 0);
    parent_self_roots(&mut tree);

    assert!(matches!(evaluate(&tree), ParentEval::None));
    assert_ancestry_update(classify(&tree, false), 3);
}

#[test]
fn parent_moving_to_worse_root_follows_parent_when_best_candidate_is_reached_through_parent() {
    // W is on the better root by a path that avoids P, but the stale Q is the
    // best candidate, so X follows P now and picks W when Q's update arrives.
    let mut tree = under_parent(&[P, 1], &[(3, &[3, P, 1]), (2, &[2, 6, 7, 1])], 0);
    parent_self_roots(&mut tree);

    assert!(matches!(evaluate(&tree), ParentEval::None));
    assert_ancestry_update(classify(&tree, false), 3);
}

#[test]
fn parent_ancestry_change_on_same_root_leaves_better_peer_to_the_hold_down_veto() {
    // Q is a same-root improvement, so the switch stays discretionary and the
    // engaged hold-down keeps X on P.
    let q = make_node_addr(2);
    let mut tree = under_parent(&[P, 6, 7, 1], &[(2, &[2, 1])], 30);
    assert!(tree.is_switch_suppressed(1500), "hold-down must be engaged");
    parent_reannounces(&mut tree, 8, &[P, 8, 7, 1]);

    assert!(matches!(evaluate(&tree), ParentEval::Discretionary(p) if p == q));
    assert_ancestry_update(classify(&tree, true), 3);
}

/// A parent that has joined `skip` with no other candidate left: both
/// classifiers must self-root rather than keep a parent that cannot forward.
#[test]
fn skipped_parent_with_no_alternative_self_roots() {
    let root = make_node_addr(0);
    let p = make_node_addr(P);
    let mut tree = TreeState::new(make_node_addr(X), 1000);
    tree.update_peer(
        ParentDeclaration::new(p, root, 1, 1000),
        make_coords(&[P, 0]),
    );
    tree.set_parent(p, 1, 1000, 1000);
    tree.recompute_coords();
    assert!(!tree.is_root());

    let skip: BTreeSet<NodeAddr> = [p].into_iter().collect();
    assert!(matches!(
        Stp::classify_periodic(&tree, &BTreeMap::new(), &skip, false),
        TreeDecision::SelfRoot
    ));
    assert!(matches!(
        Stp::classify_announce(&tree, p, &BTreeMap::new(), &skip, false),
        TreeDecision::SelfRoot
    ));
    // Control: unskipped, the same state keeps its parent.
    assert!(!matches!(
        Stp::classify_periodic(&tree, &BTreeMap::new(), &BTreeSet::new(), false),
        TreeDecision::SelfRoot
    ));
}

/// A skipped peer declaring a smaller root must not keep us off the root. X
/// (2) sits under P on root 0, and a skipped N declares the self-root [1].
/// P re-announces on root 5: the smallest root X can use is now 5, so both
/// classifiers self-root rather than read N's root 1 as "someone smaller".
#[test]
fn skipped_peer_root_does_not_block_self_root() {
    let p = make_node_addr(6);
    let n = make_node_addr(1);
    let mut tree = TreeState::new(make_node_addr(2), 1000);
    tree.update_peer(
        ParentDeclaration::new(p, make_node_addr(0), 1, 1000),
        make_coords(&[6, 0]),
    );
    tree.set_parent(p, 1, 1000, 1000);
    tree.recompute_coords();
    tree.update_peer(ParentDeclaration::self_root(n, 1, 1000), make_coords(&[1]));
    tree.update_peer(
        ParentDeclaration::new(p, make_node_addr(5), 2, 1000),
        make_coords(&[6, 5]),
    );
    assert!(!tree.is_root());

    let skip: BTreeSet<NodeAddr> = [n].into_iter().collect();
    assert!(matches!(
        Stp::classify_announce(&tree, p, &BTreeMap::new(), &skip, false),
        TreeDecision::SelfRoot
    ));
    assert!(matches!(
        Stp::classify_periodic(&tree, &BTreeMap::new(), &skip, false),
        TreeDecision::SelfRoot
    ));
}
