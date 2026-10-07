//! Leaf-only mode tests (`node.leaf_only`).
//!
//! A leaf-only node is reachable as a destination but never carries other
//! nodes' traffic: it announces its tree position only to its own parent,
//! advertises only itself in its bloom filters, refuses transit datagrams,
//! and does not forward lookups for other targets.

use super::*;
use crate::identity::encode_nsec;
use crate::proto::link::SessionDatagram;
use spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets,
    run_tree_test_with_configs,
};

/// Configs for `n` nodes whose node addresses ascend with the index, so a
/// test can place the tree root (smallest address) deterministically.
/// `leaf` marks the index that runs leaf-only.
fn ordered_configs(n: usize, leaf: usize) -> Vec<crate::config::Config> {
    let mut identities: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
    identities.sort_by(|a, b| a.node_addr().cmp(b.node_addr()));
    identities
        .into_iter()
        .enumerate()
        .map(|(i, id)| {
            let mut config = crate::config::Config::new();
            config.node.identity.nsec = Some(encode_nsec(&id.keypair().secret_key()));
            config.node.leaf_only = i == leaf;
            config
        })
        .collect()
}

/// `(forwarded, no_route, delivered)` for one node.
fn counts(node: &TestNode) -> (u64, u64, u64) {
    let fwd = &node.node.metrics().forwarding;
    (
        fwd.forwarded_packets.get(),
        fwd.drop_no_route_packets.get(),
        fwd.delivered_packets.get(),
    )
}

async fn pump(nodes: &mut [TestNode], rounds: usize) {
    for _ in 0..rounds {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(nodes).await;
    }
}

#[tokio::test]
async fn test_leaf_announces_only_to_its_parent() {
    // Topology: node0 — leaf(2) — node1. The leaf has the largest address,
    // so it is never root; it picks node0 (the smaller root) as parent.
    let configs = ordered_configs(3, 2);
    let edges = vec![(0, 2), (2, 1)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;

    let node0_addr = *nodes[0].node.node_addr();
    let leaf_addr = *nodes[2].node.node_addr();

    assert!(nodes[2].node.is_leaf_only());
    assert_eq!(
        nodes[2].node.tree_state().my_declaration().parent_id(),
        &node0_addr,
        "leaf should take the smallest visible root as parent"
    );
    assert!(
        nodes[0]
            .node
            .tree_state()
            .peer_declaration(&leaf_addr)
            .is_some(),
        "the parent must learn the leaf's position to route to it"
    );
    // node1 holds a leaf declaration only if the leaf briefly chose it as
    // parent while converging. That stale declaration names node1 itself as
    // the parent, so loop rejection keeps node1 from ever adopting the leaf,
    // and it never carries the leaf's current position.
    let node1_addr = *nodes[1].node.node_addr();
    if let Some(decl) = nodes[1].node.tree_state().peer_declaration(&leaf_addr) {
        assert_eq!(
            decl.parent_id(),
            &node1_addr,
            "a non-parent peer received the leaf's current TreeAnnounce"
        );
    }
    assert!(
        nodes[1].node.tree_state().is_root(),
        "node1 cannot join a tree through the leaf"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_leaf_is_never_chosen_as_parent() {
    // Topology: node0 — leaf(1) — node2, where the leaf sits between the
    // smallest root and a larger node. A normal middle node would become
    // node2's parent; a leaf must not.
    let configs = ordered_configs(3, 1);
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;

    let leaf_addr = *nodes[1].node.node_addr();
    for (i, tn) in nodes.iter().enumerate() {
        if i == 1 {
            continue;
        }
        let decl = tn.node.tree_state().my_declaration();
        assert!(
            decl.is_root() || decl.parent_id() != &leaf_addr,
            "node {i} picked the leaf as its parent"
        );
    }

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_leaf_advertises_only_itself() {
    // Topology: node0 — leaf(2) — node1.
    let configs = ordered_configs(3, 2);
    let edges = vec![(0, 2), (2, 1)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;
    pump(&mut nodes, 5).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let leaf_addr = *nodes[2].node.node_addr();

    for (holder, other) in [(0usize, node1_addr), (1usize, node0_addr)] {
        let filter = nodes[holder]
            .node
            .get_peer(&leaf_addr)
            .and_then(|p| p.inbound_filter())
            .unwrap_or_else(|| panic!("node {holder} has no filter from the leaf"));
        assert!(filter.contains(&leaf_addr), "leaf must advertise itself");
        assert!(
            !filter.contains(&other),
            "node {holder} learned a route to another node through the leaf"
        );
    }

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_leaf_refuses_transit_datagrams() {
    // Topology: node0 — leaf(2) — node1. node0 pushes a datagram for node1
    // straight at the leaf, as an old or misbehaving peer might.
    let configs = ordered_configs(3, 2);
    let edges = vec![(0, 2), (2, 1)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let leaf_addr = *nodes[2].node.node_addr();

    let dg = SessionDatagram::new(node0_addr, node1_addr, vec![0x10, 0x00, 0x04, 0x00, 1, 2]);
    nodes[0]
        .node
        .send_encrypted_link_message(&leaf_addr, &dg.encode())
        .await
        .unwrap();
    pump(&mut nodes, 5).await;

    let (leaf_fwd, leaf_no_route, _) = counts(&nodes[2]);
    assert_eq!(leaf_fwd, 0, "leaf forwarded a transit datagram");
    assert!(leaf_no_route >= 1, "leaf should drop transit as NoRoute");
    assert_eq!(
        counts(&nodes[1]).2,
        0,
        "datagram reached node1 through the leaf"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_leaf_is_reachable_across_the_mesh() {
    // Topology: node0 — node1 — leaf(2). Traffic for the leaf must still
    // arrive through its parent.
    let configs = ordered_configs(3, 2);
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let leaf_addr = *nodes[2].node.node_addr();

    let dg = SessionDatagram::new(node0_addr, leaf_addr, vec![0x10, 0x00, 0x04, 0x00, 1, 2]);
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &dg.encode())
        .await
        .unwrap();
    pump(&mut nodes, 5).await;

    assert_eq!(counts(&nodes[1]).0, 1, "node1 should forward to the leaf");
    assert_eq!(
        counts(&nodes[2]).2,
        1,
        "leaf should receive its own traffic"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_leaf_does_not_forward_lookups_for_others() {
    // Topology: node0 — leaf(2) — node1. node0 looks up node1; the only path
    // runs through the leaf, which must not carry it.
    let configs = ordered_configs(3, 2);
    let edges = vec![(0, 2), (2, 1)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();
    nodes[0].node.register_identity(node1_addr, node1_pubkey);
    nodes[0].node.initiate_lookup(&node1_addr, 8).await;
    pump(&mut nodes, 5).await;

    assert_eq!(
        nodes[2].node.metrics().lookup.req_forwarded.get(),
        0,
        "leaf forwarded a lookup for another node"
    );
    assert!(
        nodes[1].node.lookup.recent_requests.is_empty(),
        "lookup reached node1 through the leaf"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_smallest_leaf_attaches_below_root() {
    // Topology: leaf(0) — node1. The leaf has the smallest address but must
    // not self-elect: it attaches under node1, which stays root and learns
    // the leaf as its child.
    let configs = ordered_configs(2, 0);
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;

    let leaf_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    assert!(!nodes[0].node.tree_state().is_root(), "leaf self-elected");
    assert_eq!(
        nodes[0].node.tree_state().my_declaration().parent_id(),
        &node1_addr
    );
    assert_eq!(nodes[0].node.tree_state().root(), &node1_addr);
    assert!(nodes[1].node.tree_state().is_root());
    assert_eq!(
        nodes[1]
            .node
            .tree_state()
            .peer_declaration(&leaf_addr)
            .map(|d| *d.parent_id()),
        Some(node1_addr),
        "the parent must accept the leaf's below-root announce"
    );
    assert_eq!(
        nodes[1].node.metrics().tree.ancestry_invalid.get(),
        0,
        "the parent rejected the leaf's announce"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_smallest_leaf_is_reachable_and_reaches_across_the_mesh() {
    // Topology: leaf(0) — node1 — node2. Before the gate the leaf rooted an
    // island of its own; now it shares node1's tree, node2 learns it through
    // node1's bloom filter, and traffic flows both ways through node1.
    let configs = ordered_configs(3, 0);
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_configs(configs, &edges).await;
    pump(&mut nodes, 5).await;
    populate_all_coord_caches(&mut nodes);

    let leaf_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    assert_eq!(nodes[0].node.tree_state().root(), &node1_addr);
    assert_eq!(nodes[2].node.tree_state().root(), &node1_addr);
    assert!(
        nodes[2]
            .node
            .get_peer(&node1_addr)
            .and_then(|p| p.inbound_filter())
            .is_some_and(|f| f.contains(&leaf_addr)),
        "node2 must learn the leaf through node1"
    );

    let to_leaf = SessionDatagram::new(node2_addr, leaf_addr, vec![0x10, 0x00, 0x04, 0x00, 1, 2]);
    nodes[2]
        .node
        .send_encrypted_link_message(&node1_addr, &to_leaf.encode())
        .await
        .unwrap();
    let from_leaf = SessionDatagram::new(leaf_addr, node2_addr, vec![0x10, 0x00, 0x04, 0x00, 3, 4]);
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &from_leaf.encode())
        .await
        .unwrap();
    pump(&mut nodes, 5).await;

    assert_eq!(counts(&nodes[1]).0, 2, "node1 should forward both ways");
    assert_eq!(counts(&nodes[0]).2, 1, "leaf should receive its traffic");
    assert_eq!(counts(&nodes[2]).2, 1, "node2 should receive the leaf's");

    cleanup_nodes(&mut nodes).await;
}
