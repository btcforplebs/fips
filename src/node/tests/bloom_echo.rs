//! The child echo guard in `handle_filter_announce`: a tree child that
//! returns the filter we sent it is rejected and keeps its previous filter,
//! while honest child filters, parents' filters and children with nothing
//! stored are merged as before.
//!
//! Each test runs a four-node chain and works at the node U that has both a
//! parent P and a child C, gives P's side real size with a synthetic announce,
//! sends U's filter to C, then delivers C's (or P's) announce through the real
//! handler and reads U's next filter to P.

use super::spanning_tree::{TestNode, cleanup_nodes, run_tree_test};
use super::*;
use crate::node::diag::TreeRole;
use crate::proto::bloom::{BloomFilter, ECHO_MIN_BITS, FilterAnnounce};

/// A converged four-node chain and, at node `u`, its parent `p` and child `c`.
struct Chain {
    nodes: Vec<TestNode>,
    u: usize,
    p: NodeAddr,
    c: NodeAddr,
}

impl Chain {
    /// Build the chain, find the node with both a parent and a child, and
    /// give C a small honest stored filter, its own address.
    async fn new() -> Self {
        let nodes = run_tree_test(4, &[(0, 1), (1, 2), (2, 3)], false).await;
        let (u, p, c) = nodes
            .iter()
            .enumerate()
            .find_map(|(i, tn)| {
                let node = &tn.node;
                let with = |role| {
                    node.peers
                        .keys()
                        .copied()
                        .find(|a| node.tree_role(a) == role)
                };
                Some((i, with(TreeRole::Parent)?, with(TreeRole::Child)?))
            })
            .expect("precondition: a four-node chain has a node with a parent and a child");
        let mut chain = Chain { nodes, u, p, c };
        let mut own = BloomFilter::new();
        own.insert(&c);
        chain.announce(c, &own).await;
        assert_eq!(
            chain.stored(&c),
            Some(own),
            "setup: C's own filter is stored"
        );
        chain
    }

    /// The node under test.
    fn node(&mut self) -> &mut Node {
        &mut self.nodes[self.u].node
    }

    /// Deliver an announce of `filter` from `from` with its next sequence.
    async fn announce(&mut self, from: NodeAddr, filter: &BloomFilter) {
        let node = self.node();
        let seq = node.get_peer(&from).expect("a peer").filter_sequence() + 1;
        let payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
        node.handle_filter_announce(&from, &payload[1..]).await;
    }

    /// The filter U holds for `peer`.
    fn stored(&mut self, peer: &NodeAddr) -> Option<BloomFilter> {
        self.node().get_peer(peer)?.inbound_filter().cloned()
    }

    /// The sequence of `peer`'s stored filter at U.
    fn sequence(&mut self, peer: &NodeAddr) -> u64 {
        self.node().get_peer(peer).unwrap().filter_sequence()
    }

    /// The filter U would send `to` now.
    fn outgoing(&mut self, to: NodeAddr) -> BloomFilter {
        let node = self.node();
        let filters = node.peer_inbound_filters();
        node.bloom_state
            .compute_outgoing_filters(&[to], &filters)
            .remove(&to)
            .expect("a filter for the target")
    }

    /// Send U's current filter to `to`, so it is U's last-sent filter there.
    async fn send(&mut self, to: NodeAddr) -> BloomFilter {
        let filter = self.outgoing(to);
        let node = self.node();
        // The debounce is a brake, not what is under test.
        node.bloom_state.set_update_debounce_ms(0);
        node.bloom_state.mark_update_needed(to);
        node.send_filter_announce_to_peer(&to, filter.clone())
            .await
            .expect("the announce is sent");
        assert_eq!(node.bloom_state.last_sent_filter(&to), Some(&filter));
        filter
    }

    /// Give P's side `count` synthetic entries tagged `tag`, then send U's
    /// filter to C. Returns the entries and the filter sent.
    async fn parent_side(&mut self, tag: u8, count: u16) -> (Vec<NodeAddr>, BloomFilter) {
        let addrs = addrs(tag, count);
        let p = self.p;
        let mut filter = filter_of(&addrs);
        filter.insert(&p);
        self.announce(p, &filter).await;
        assert_eq!(self.stored(&p), Some(filter), "setup: P's filter is stored");
        let c = self.c;
        let sent = self.send(c).await;
        assert!(sent.count_ones() >= ECHO_MIN_BITS, "setup: above the floor");
        (addrs, sent)
    }

    /// Set U's `node.bloom.child_echo_threshold`.
    fn set_threshold(&mut self, threshold: f64) {
        self.node().replace_context(|ctx| {
            let mut cfg = (*ctx.config).clone();
            cfg.node.bloom.child_echo_threshold = threshold;
            ctx.config = std::sync::Arc::new(cfg);
        });
    }

    /// U's accepted and child-role rejection counters.
    fn counters(&mut self) -> (u64, u64) {
        let bloom = &self.node().metrics().bloom;
        (bloom.accepted.get(), bloom.child_role_rejected.get())
    }

    async fn cleanup(mut self) {
        cleanup_nodes(&mut self.nodes).await;
    }
}

/// `count` distinct addresses whose bytes are all `tag` but the index.
fn addrs(tag: u8, count: u16) -> Vec<NodeAddr> {
    (0..count)
        .map(|i| {
            let mut bytes = [tag; 16];
            bytes[1..3].copy_from_slice(&i.to_le_bytes());
            NodeAddr::from_bytes(bytes)
        })
        .collect()
}

/// A filter holding `addrs`.
fn filter_of(addrs: &[NodeAddr]) -> BloomFilter {
    let mut f = BloomFilter::new();
    for a in addrs {
        f.insert(a);
    }
    f
}

/// How many of `addrs` `filter` contains.
fn held(filter: &BloomFilter, addrs: &[NodeAddr]) -> usize {
    addrs.iter().filter(|a| filter.contains(a)).count()
}

#[tokio::test]
async fn a_child_returning_the_filter_we_sent_it_does_not_reach_the_filter_we_send_our_parent() {
    let mut chain = Chain::new().await;
    let (p_only, sent) = chain.parent_side(0xA1, 1000).await;
    let (p, c) = (chain.p, chain.c);
    let previous = chain.stored(&c);
    let previous_seq = chain.sequence(&c);
    let (accepted, rejected) = chain.counters();

    let mut echo = sent.clone();
    echo.insert(&c);
    chain.announce(c, &echo).await;

    let sample = &p_only[..20];
    let to_parent = chain.outgoing(p);
    assert_eq!(
        held(&to_parent, sample),
        0,
        "P's own entries must not come back to P through C"
    );
    assert_eq!(chain.stored(&c), previous, "C keeps its previous filter");
    assert_eq!(chain.sequence(&c), previous_seq, "and its sequence");
    assert_eq!(chain.counters(), (accepted, rejected + 1));

    chain.cleanup().await;
}

#[tokio::test]
async fn a_child_announcing_a_disjoint_subtree_of_200_entries_is_merged() {
    let mut chain = Chain::new().await;
    chain.parent_side(0xA1, 1000).await;
    let (p, c) = (chain.p, chain.c);
    let (accepted, rejected) = chain.counters();

    let subtree = addrs(0xE1, 200);
    let mut filter = filter_of(&subtree);
    filter.insert(&c);
    chain.announce(c, &filter).await;

    assert_eq!(chain.stored(&c), Some(filter));
    assert_eq!(held(&chain.outgoing(p), &subtree[..20]), 20);
    assert_eq!(chain.counters(), (accepted + 1, rejected));

    chain.cleanup().await;
}

/// C announces as its subtree `share` of the `total` entries U last sent it,
/// as a peer does whose subtree reached us through other tree peers before it
/// became our child. It must be merged.
async fn a_moved_subtree_is_merged(total: u16, share: u16) {
    let mut chain = Chain::new().await;
    let (p_side, sent) = chain.parent_side(0xA1, total).await;
    let c = chain.c;
    let (accepted, rejected) = chain.counters();

    let mut filter = filter_of(&p_side[..usize::from(share)]);
    filter.insert(&c);
    let overlap = filter.overlap(&sent).unwrap();
    chain.announce(c, &filter).await;

    assert_eq!(
        chain.stored(&c),
        Some(filter.clone()),
        "overlap {overlap:.3}, bound {:.3}",
        filter.echo_bound(0.8)
    );
    assert_eq!(chain.counters(), (accepted + 1, rejected));

    chain.cleanup().await;
}

#[tokio::test]
async fn a_peer_that_just_became_our_child_is_merged_although_we_sent_it_its_own_subtree_small_mesh()
 {
    a_moved_subtree_is_merged(50, 25).await;
}

#[tokio::test]
async fn a_peer_that_just_became_our_child_is_merged_although_we_sent_it_its_own_subtree_large_mesh()
 {
    a_moved_subtree_is_merged(1300, 650).await;
}

#[tokio::test]
async fn a_child_with_no_stored_filter_returning_our_filter_is_merged() {
    let mut chain = Chain::new().await;
    let (_, sent) = chain.parent_side(0xA1, 1000).await;
    let c = chain.c;
    chain.node().peers.get_mut(&c).unwrap().clear_filter();
    let (accepted, rejected) = chain.counters();

    let mut echo = sent.clone();
    echo.insert(&c);
    chain.announce(c, &echo).await;

    // With nothing to keep, a rejection would drop C's subtree outright.
    assert_eq!(chain.stored(&c), Some(echo));
    assert_eq!(chain.counters(), (accepted + 1, rejected));

    chain.cleanup().await;
}

#[tokio::test]
async fn a_parent_returning_the_filter_we_sent_it_is_merged() {
    let mut chain = Chain::new().await;
    let (p, c) = (chain.p, chain.c);
    let mut subtree = filter_of(&addrs(0xE1, 200));
    subtree.insert(&c);
    chain.announce(c, &subtree).await;
    let sent = chain.send(p).await;
    assert!(sent.count_ones() >= ECHO_MIN_BITS, "setup: above the floor");
    let (accepted, rejected) = chain.counters();

    let mut echo = sent.clone();
    echo.insert(&p);
    chain.announce(p, &echo).await;

    assert_eq!(chain.stored(&p), Some(echo));
    assert_eq!(chain.counters(), (accepted + 1, rejected));

    chain.cleanup().await;
}

#[tokio::test]
async fn a_child_echo_threshold_of_one_turns_the_guard_off() {
    let mut chain = Chain::new().await;
    let (_, sent) = chain.parent_side(0xA1, 1000).await;
    let c = chain.c;
    chain.set_threshold(1.0);
    let (accepted, rejected) = chain.counters();

    let mut echo = sent.clone();
    echo.insert(&c);
    chain.announce(c, &echo).await;

    assert_eq!(chain.stored(&c), Some(echo));
    assert_eq!(chain.counters(), (accepted + 1, rejected));

    chain.cleanup().await;
}
