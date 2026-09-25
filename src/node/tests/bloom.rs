//! Bloom filter integration tests.
//!
//! Verifies that bloom filters are exchanged between all peers and that
//! filter content propagates only through tree edges (tree-only propagation).

use super::spanning_tree::*;
use super::*;

/// Derive the tree edges from the converged spanning tree state.
///
/// For each non-root node, finds the parent relationship and returns
/// the corresponding edge as (child_index, parent_index).
fn get_tree_edges(nodes: &[TestNode]) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if !ts.is_root() {
            let parent_addr = ts.my_declaration().parent_id();
            if let Some(j) = nodes.iter().position(|n| n.node.node_addr() == parent_addr) {
                edges.push((i, j));
            }
        }
    }
    edges
}

/// Verify that all peer pairs on the given edges have exchanged bloom
/// filters and each peer's inbound filter contains the peer's own
/// node_addr.
fn verify_filter_exchange(nodes: &[TestNode], edges: &[(usize, usize)]) {
    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let i_addr = *nodes[i].node.node_addr();

        // Node i should have a filter from node j
        let peer_j = nodes[i]
            .node
            .get_peer(&j_addr)
            .unwrap_or_else(|| panic!("Node {} should have peer {}", i, j));
        let filter_from_j = peer_j.inbound_filter().unwrap_or_else(|| {
            panic!(
                "Node {} should have inbound filter from node {} (addr={})",
                i, j, j_addr
            )
        });

        // The filter from j must contain j's own node_addr
        assert!(
            filter_from_j.contains(&j_addr),
            "Node {}'s filter from node {} should contain node {}'s addr",
            i,
            j,
            j
        );

        // Node j should have a filter from node i
        let peer_i = nodes[j]
            .node
            .get_peer(&i_addr)
            .unwrap_or_else(|| panic!("Node {} should have peer {}", j, i));
        let filter_from_i = peer_i.inbound_filter().unwrap_or_else(|| {
            panic!(
                "Node {} should have inbound filter from node {} (addr={})",
                j, i, i_addr
            )
        });

        // The filter from i must contain i's own node_addr
        assert!(
            filter_from_i.contains(&i_addr),
            "Node {}'s filter from node {} should contain node {}'s addr",
            j,
            i,
            i
        );
    }
}

/// Verify propagation along tree edges: each node's filter from a tree
/// peer should contain addresses of the peer's tree neighbors (which
/// were merged into the peer's outgoing filter via tree-only propagation).
fn verify_tree_propagation(nodes: &[TestNode], tree_edges: &[(usize, usize)]) {
    let n = nodes.len();
    let mut tree_adj = vec![vec![]; n];
    for &(i, j) in tree_edges {
        tree_adj[i].push(j);
        tree_adj[j].push(i);
    }

    for &(i, j) in tree_edges {
        let j_addr = *nodes[j].node.node_addr();
        let peer_j = nodes[i].node.get_peer(&j_addr).unwrap();
        let filter = peer_j.inbound_filter().unwrap();

        // All of j's tree neighbors (except i) should be in j's filter to i
        for &neighbor_idx in &tree_adj[j] {
            if neighbor_idx == i {
                continue; // j excludes i's direction from i's filter
            }
            let neighbor_addr = *nodes[neighbor_idx].node.node_addr();
            assert!(
                filter.contains(&neighbor_addr),
                "Node {}'s filter from node {} should contain node {}'s tree neighbor {} (addr={})",
                i,
                j,
                j,
                neighbor_idx,
                neighbor_addr
            );
        }
    }
}

/// 10-node random graph: tree + bloom filter convergence.
#[tokio::test]
async fn test_bloom_filter_10_nodes() {
    let edges = generate_random_edges(10, 20, 123);
    let mut nodes = run_tree_test(10, &edges, false).await;
    verify_tree_convergence(&nodes);
    // All peers exchange filters
    verify_filter_exchange(&nodes, &edges);
    // Content propagation only along tree edges
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);
    print_filter_cardinality(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// 5-node star: hub node's filter should contain all spokes.
#[tokio::test]
async fn test_bloom_filter_star() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

    // Hub (node 0) sends each spoke a filter containing the other spokes
    let hub_addr = *nodes[0].node.node_addr();
    for spoke in 1..5 {
        let peer = nodes[spoke].node.get_peer(&hub_addr).unwrap();
        let filter = peer.inbound_filter().unwrap();

        // Filter from hub should contain all OTHER spokes
        for (other, other_node) in nodes[1..5].iter().enumerate() {
            let other = other + 1; // adjust for slice offset
            if other == spoke {
                continue;
            }
            let other_addr = *other_node.node.node_addr();
            assert!(
                filter.contains(&other_addr),
                "Spoke {}'s filter from hub should contain spoke {} (addr={})",
                spoke,
                other,
                other_addr
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// 8-node chain: verify full propagation.
///
/// Chain: 0-1-2-3-4-5-6-7. Each node's outgoing filter is the merge
/// of its own address plus all tree peer inbound filters (excluding the
/// destination peer). This means entries propagate through the entire
/// chain: node 1 merges node 2's filter, which contains node 3's
/// entries, and so on. Both endpoints should see all other nodes.
#[tokio::test]
async fn test_bloom_filter_chain_propagation() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)];
    let mut nodes = run_tree_test(8, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

    let addrs: Vec<NodeAddr> = nodes.iter().map(|tn| *tn.node.node_addr()).collect();

    // Node 0's filter from node 1 should contain node 1 and its
    // immediate neighbor node 2 (node 1 directly merges node 2's filter).
    let peer_1 = nodes[0].node.get_peer(&addrs[1]).unwrap();
    let filter = peer_1.inbound_filter().unwrap();
    assert!(filter.contains(&addrs[1]), "Should contain node 1 (self)");
    assert!(
        filter.contains(&addrs[2]),
        "Should contain node 2 (1-hop neighbor of node 1)"
    );

    // Entries propagate through the full chain because each
    // intermediate node merges its peer's filter into its outgoing
    // filter. Verify all nodes are reachable from the endpoints.
    for (i, addr) in addrs[2..8].iter().enumerate() {
        assert!(
            filter.contains(addr),
            "Node 0's filter from node 1 should contain node {} \
             (chain merge propagation)",
            i + 2
        );
    }

    // Verify symmetric: node 7's filter from node 6 should contain all
    for i in 0..6 {
        let peer_6 = nodes[7].node.get_peer(&addrs[6]).unwrap();
        let filter_6 = peer_6.inbound_filter().unwrap();
        assert!(
            filter_6.contains(&addrs[i]),
            "Node 7's filter from node 6 should contain node {} \
             (chain merge propagation)",
            i
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// 5-node ring: every node should see all others via peer filters.
///
/// All peers receive filters. Content propagates through the tree
/// (N-1=4 tree edges). Every node is reachable through at least one
/// peer's filter.
#[tokio::test]
async fn test_bloom_filter_ring() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    // All peers (including the non-tree edge) receive filters
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

    // Every node should be reachable via at least one peer's filter
    for i in 0..5 {
        for j in 0..5 {
            if i == j {
                continue;
            }
            let target_addr = *nodes[j].node.node_addr();
            let reachable = nodes[i]
                .node
                .peers()
                .any(|peer| peer.may_reach(&target_addr));
            assert!(
                reachable,
                "Node {} should see node {} as reachable via at least one peer's filter",
                i, j
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// Print filter cardinality for all peer relationships (diagnostic helper).
///
/// Useful with `--nocapture` to inspect filter sizes and tree/mesh distinction.
fn print_filter_cardinality(nodes: &[TestNode]) {
    println!("\n  === Filter Cardinality ===");
    for (i, tn) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate() {
            if i == j {
                continue;
            }
            let addr = *other.node.node_addr();
            if let Some(peer) = tn.node.get_peer(&addr)
                && let Some(filter) = peer.inbound_filter()
            {
                let is_tree = tn.node.is_tree_peer(&addr);
                println!(
                    "  n{} <- n{}: est={} set_bits={} fill={:.1}% tree={}",
                    i,
                    j,
                    match filter.estimated_count(f64::INFINITY) {
                        Some(n) => format!("{:.1}", n),
                        None => "saturated".to_string(),
                    },
                    filter.count_ones(),
                    filter.fill_ratio() * 100.0,
                    is_tree,
                );
            }
        }
    }
}

/// Compute the set of node indices in a subtree rooted at `subtree_root`,
/// given a tree adjacency list and the actual root of the whole tree.
fn collect_subtree(
    subtree_root: usize,
    parent: Option<usize>,
    tree_adj: &[Vec<usize>],
) -> Vec<usize> {
    let mut result = vec![subtree_root];
    for &neighbor in &tree_adj[subtree_root] {
        if Some(neighbor) != parent {
            result.extend(collect_subtree(neighbor, Some(subtree_root), tree_adj));
        }
    }
    result
}

/// 7-node tree: verify split-horizon asymmetry between upward and downward filters.
///
/// Creates a pure tree topology and verifies that:
/// - Upward filters (child→parent) contain only the child's subtree
/// - Downward filters (parent→child) contain only the complement
/// - Cardinality estimates match expected subtree sizes
///
/// The tree structure formed depends on which node gets the lowest NodeAddr
/// (becomes root), but the split-horizon property holds regardless.
#[tokio::test]
async fn test_bloom_filter_split_horizon() {
    // Pure tree: 7 nodes, 6 edges
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (1, 3), (1, 4), (2, 5), (5, 6)];
    let mut nodes = run_tree_test(7, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

    let addrs: Vec<NodeAddr> = nodes.iter().map(|tn| *tn.node.node_addr()).collect();

    // Build the actual tree adjacency from converged state
    let n = nodes.len();
    let mut tree_adj = vec![vec![]; n];
    for &(child, parent) in &tree_edges {
        tree_adj[child].push(parent);
        tree_adj[parent].push(child);
    }

    print_filter_cardinality(&nodes);

    // For each tree edge (child, parent), verify split-horizon:
    // - child's filter to parent contains child's subtree only
    // - parent's filter to child contains the complement only
    for &(child_idx, parent_idx) in &tree_edges {
        let child_subtree = collect_subtree(child_idx, Some(parent_idx), &tree_adj);
        let complement: Vec<usize> = (0..n).filter(|i| !child_subtree.contains(i)).collect();

        // --- Upward filter: child → parent ---
        // This is stored as parent's inbound filter from child
        let filter_up = nodes[parent_idx]
            .node
            .get_peer(&addrs[child_idx])
            .unwrap()
            .inbound_filter()
            .unwrap();

        // Should contain all nodes in child's subtree
        for &idx in &child_subtree {
            assert!(
                filter_up.contains(&addrs[idx]),
                "Upward filter (n{}→n{}): should contain subtree member n{} but doesn't",
                child_idx,
                parent_idx,
                idx
            );
        }

        // Should NOT contain nodes in the complement
        for &idx in &complement {
            assert!(
                !filter_up.contains(&addrs[idx]),
                "Upward filter (n{}→n{}): should NOT contain complement member n{} but does",
                child_idx,
                parent_idx,
                idx
            );
        }

        // Cardinality should match subtree size
        let up_est = filter_up
            .estimated_count(f64::INFINITY)
            .expect("upward filter should not be saturated in tree convergence test");
        assert!(
            (up_est - child_subtree.len() as f64).abs() < 1.5,
            "Upward filter (n{}→n{}): expected ~{} entries, got {:.1}",
            child_idx,
            parent_idx,
            child_subtree.len(),
            up_est
        );

        // --- Downward filter: parent → child ---
        // This is stored as child's inbound filter from parent
        let filter_down = nodes[child_idx]
            .node
            .get_peer(&addrs[parent_idx])
            .unwrap()
            .inbound_filter()
            .unwrap();

        // Should contain all nodes in the complement
        for &idx in &complement {
            assert!(
                filter_down.contains(&addrs[idx]),
                "Downward filter (n{}→n{}): should contain complement member n{} but doesn't",
                parent_idx,
                child_idx,
                idx
            );
        }

        // Should NOT contain nodes in child's subtree (except: split-horizon
        // excludes the child's direction, but child itself is NOT in parent's
        // outgoing filter to child — parent merges child's filter into filters
        // for OTHER peers, not back to child)
        for &idx in &child_subtree {
            assert!(
                !filter_down.contains(&addrs[idx]),
                "Downward filter (n{}→n{}): should NOT contain subtree member n{} but does",
                parent_idx,
                child_idx,
                idx
            );
        }

        // Cardinality should match complement size
        let down_est = filter_down
            .estimated_count(f64::INFINITY)
            .expect("downward filter should not be saturated in tree convergence test");
        assert!(
            (down_est - complement.len() as f64).abs() < 1.5,
            "Downward filter (n{}→n{}): expected ~{} entries, got {:.1}",
            parent_idx,
            child_idx,
            complement.len(),
            down_est
        );

        // Together, subtree + complement = all nodes
        assert_eq!(
            child_subtree.len() + complement.len(),
            n,
            "Subtree + complement should cover all {} nodes",
            n
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// Each peer's inbound filter contributes exactly once, independent of
/// tree-declaration state.
///
/// Under all-peers union semantics there is no parent/child gating and no
/// `peer_declaration` lookup, so a stale or contradictory declaration
/// cache cannot cause a peer's bloom cardinality to be folded twice. This
/// retains the spirit of the old parent-double-count regression: we set up
/// the same stale-cache scenario (the cached `peer_declaration(P)` still
/// names US as P's parent) and assert the estimate reflects each filter
/// counted once, not the double-count fingerprint.
#[test]
fn compute_mesh_size_counts_each_peer_filter_once() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;
    use crate::proto::stp::ParentDeclaration;

    let mut node = make_node();
    let my_addr = *node.tree_state().my_node_addr();

    // Generate a parent identity strictly less than my_addr so the
    // tree_state defensive check (my_node_addr > parent_root) accepts
    // the extension; otherwise recompute_coords would demote us back
    // to self-root and is_root() would stay true.
    let (parent_identity, parent_addr) = loop {
        let candidate = make_peer_identity();
        let addr = *candidate.node_addr();
        if addr < my_addr {
            break (candidate, addr);
        }
    };
    let mut parent_peer = ActivePeer::new(parent_identity, LinkId::new(1), 0);
    let mut parent_filter = BloomFilter::new();
    for i in 0..5u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x80 | i; // distinct namespace
        parent_filter.insert(&NodeAddr::from_bytes(bytes));
    }
    parent_peer.update_filter(parent_filter, 1, 0);
    node.peers.insert(parent_addr, parent_peer);

    // Inject legitimate child Q with a 3-entry inbound filter.
    let child_identity = make_peer_identity();
    let child_addr = *child_identity.node_addr();
    let mut child_peer = ActivePeer::new(child_identity, LinkId::new(2), 0);
    let mut child_filter = BloomFilter::new();
    for i in 0..3u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xC0 | i;
        child_filter.insert(&NodeAddr::from_bytes(bytes));
    }
    child_peer.update_filter(child_filter, 1, 0);
    node.peers.insert(child_addr, child_peer);

    // Seed parent ancestry first so recompute_coords can extend it and
    // flip is_root() to false; child ancestry is for completeness.
    let parent_ancestry = crate::proto::stp::TreeCoordinate::root_with_meta(parent_addr, 1, 1);
    let child_ancestry = crate::proto::stp::TreeCoordinate::root_with_meta(child_addr, 1, 1);
    // Inject the stale-cache scenario: peer_declaration(P) still names
    // US (M) as P's parent (the pre-switch advert that the cache hasn't
    // refreshed yet). Q is a legitimate child also naming M as parent.
    // Under all-peers semantics these declarations no longer affect the
    // estimate at all.
    let parent_decl_stale = ParentDeclaration::new(parent_addr, my_addr, 1, 1);
    let child_decl = ParentDeclaration::new(child_addr, my_addr, 1, 1);
    node.tree_state_mut()
        .update_peer(parent_decl_stale, parent_ancestry);
    node.tree_state_mut()
        .update_peer(child_decl, child_ancestry);

    // Switch our parent to P and recompute coords so root flips off self.
    node.tree_state_mut().set_parent(parent_addr, 2, 1, 1);
    node.tree_state_mut().recompute_coords();
    assert!(
        !node.tree_state().is_root(),
        "test setup broken: node should not be its own root after parent switch"
    );

    node.compute_mesh_size();

    let estimate = node
        .estimated_mesh_size()
        .expect("estimator should produce a value with filter data present");

    // Each filter counted once: 1 (self) + 5 (P) + 3 (Q) = 9.
    // A double-count of P (the old declaration-cache bug fingerprint)
    // would land near 1 + 2*5 + 3 = 14.
    // The estimator's log-based math rounds, so allow +/-1 tolerance.
    let diff = (estimate as i64 - 9).abs();
    assert!(
        diff <= 1,
        "expected mesh-size estimate ~9 (1+5+3), got {} (double-count fingerprint is ~14)",
        estimate
    );
}

/// Overlapping peer inbound filters must be OR-unioned, not summed.
///
/// Two connected peers share several NodeAddrs (plus a few distinct ones
/// each). The naive sum of per-filter cardinalities would over-count the
/// shared entries; the union estimate must instead approximate the number
/// of *distinct* addresses across both filters (plus self). Under all-peers
/// semantics the union folds in every connected peer regardless of tree
/// role, so no parent/child wiring is needed — this asserts the
/// overlap-dedup property directly on the union result that
/// `estimated_mesh_size` carries.
#[test]
fn compute_mesh_size_unions_overlapping_filters() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;

    let mut node = make_node();

    // Build the set of addresses. SHARED appear in both filters; the
    // distinct sets appear in only one each.
    let mk = |hi: u8, lo: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = hi;
        bytes[1] = lo;
        NodeAddr::from_bytes(bytes)
    };
    let shared: Vec<NodeAddr> = (0..6u8).map(|i| mk(0x10, i)).collect();
    let peer_a_only: Vec<NodeAddr> = (0..3u8).map(|i| mk(0x20, i)).collect();
    let peer_b_only: Vec<NodeAddr> = (0..3u8).map(|i| mk(0x30, i)).collect();

    // Distinct addresses across the union: shared + peer_a_only +
    // peer_b_only + self = 6 + 3 + 3 + 1 = 13. The naive sum of the two
    // filters' cardinalities would be (6+3) + (6+3) + 1 = 19.
    let distinct = shared.len() + peer_a_only.len() + peer_b_only.len() + 1; // 13
    let naive_sum = (shared.len() + peer_a_only.len()) + (shared.len() + peer_b_only.len()) + 1; // 19

    // Peer A with shared + peer_a_only.
    let peer_a_identity = make_peer_identity();
    let peer_a_addr = *peer_a_identity.node_addr();
    let mut peer_a = ActivePeer::new(peer_a_identity, LinkId::new(1), 0);
    let mut filter_a = BloomFilter::new();
    for addr in shared.iter().chain(peer_a_only.iter()) {
        filter_a.insert(addr);
    }
    peer_a.update_filter(filter_a, 1, 0);
    node.peers.insert(peer_a_addr, peer_a);

    // Peer B with a filter that overlaps A's on `shared`.
    let peer_b_identity = make_peer_identity();
    let peer_b_addr = *peer_b_identity.node_addr();
    let mut peer_b = ActivePeer::new(peer_b_identity, LinkId::new(2), 0);
    let mut filter_b = BloomFilter::new();
    for addr in shared.iter().chain(peer_b_only.iter()) {
        filter_b.insert(addr);
    }
    peer_b.update_filter(filter_b, 1, 0);
    node.peers.insert(peer_b_addr, peer_b);

    node.compute_mesh_size();

    let estimate =
        node.estimated_mesh_size()
            .expect("estimator should produce a value with filter data present") as i64;

    // The union estimate should approximate the distinct count (13), not
    // the naive sum (19). Bloom cardinality estimation rounds, so allow a
    // small absolute tolerance, and require we are clearly below the sum.
    let diff = (estimate - distinct as i64).abs();
    assert!(
        diff <= 2,
        "expected union mesh-size estimate ~{} (distinct addrs), got {}",
        distinct,
        estimate
    );
    assert!(
        estimate < naive_sum as i64,
        "estimate {} must be below the naive sum {} (overlap should be deduplicated)",
        estimate,
        naive_sum
    );
}

/// Flap-damping: the estimate survives a parent switch when a healthy
/// cross-link carries the upward coverage.
///
/// Under the old tree-only union, the upward leg of the estimate hinged
/// entirely on the current parent's filter; dropping the parent (a parent
/// switch transient, before the new parent's filter converges) collapsed
/// the estimate to self + children. Under all-peers semantics a cross-link
/// peer whose split-horizon `inbound_filter` carries the same upward
/// coverage keeps the union nearly intact across the drop. This builds a
/// node with a parent and one healthy cross-link, records the estimate,
/// removes the parent, and asserts the estimate does not collapse.
#[test]
fn compute_mesh_size_stable_across_parent_drop_with_cross_link() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;

    let mut node = make_node();

    let mk = |hi: u8, lo: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = hi;
        bytes[1] = lo;
        NodeAddr::from_bytes(bytes)
    };

    // Upward coverage: the set of addresses reachable through the rest of
    // the mesh (everything outside our local subtree). Both the parent and
    // a healthy cross-link advertise this under split-horizon propagation.
    let upward: Vec<NodeAddr> = (0..12u8).map(|i| mk(0x40, i)).collect();
    // The cross-link additionally knows a couple of addresses of its own.
    let cross_extra: Vec<NodeAddr> = (0..2u8).map(|i| mk(0x50, i)).collect();

    // Parent P: carries the upward coverage.
    let parent_identity = make_peer_identity();
    let parent_addr = *parent_identity.node_addr();
    let mut parent_peer = ActivePeer::new(parent_identity, LinkId::new(1), 0);
    let mut parent_filter = BloomFilter::new();
    for addr in &upward {
        parent_filter.insert(addr);
    }
    parent_peer.update_filter(parent_filter, 1, 0);
    node.peers.insert(parent_addr, parent_peer);

    // Cross-link X: a non-tree peer whose split-horizon filter also carries
    // the upward coverage (plus a little of its own).
    let cross_identity = make_peer_identity();
    let cross_addr = *cross_identity.node_addr();
    let mut cross_peer = ActivePeer::new(cross_identity, LinkId::new(2), 0);
    let mut cross_filter = BloomFilter::new();
    for addr in upward.iter().chain(cross_extra.iter()) {
        cross_filter.insert(addr);
    }
    cross_peer.update_filter(cross_filter, 1, 0);
    node.peers.insert(cross_addr, cross_peer);

    // Baseline estimate with both peers present.
    node.compute_mesh_size();
    let before =
        node.estimated_mesh_size()
            .expect("estimator should produce a value with filter data present") as i64;

    // Simulate a parent switch transient: the old parent is dropped before
    // the new parent's filter has converged. The cross-link remains.
    node.peers.remove(&parent_addr);
    node.compute_mesh_size();
    let after = node
        .estimated_mesh_size()
        .expect("estimator should still produce a value via the cross-link") as i64;

    // The estimate must not collapse: the cross-link still holds the upward
    // coverage. Old tree-only behavior would have lost the entire upward
    // leg (~12 addrs) and dropped to roughly self alone. Allow a small
    // tolerance for bloom rounding and the cross-link's couple extra bits.
    let diff = (before - after).abs();
    assert!(
        diff <= 2,
        "mesh-size estimate collapsed across parent drop: before={before}, after={after} \
         (cross-link should preserve upward coverage)"
    );
}

/// 100-node random graph: bloom filter exchange at scale.
#[tokio::test]
async fn test_bloom_filter_convergence_100_nodes() {
    let _guard = lock_large_network_test().await;

    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);
    print_filter_cardinality(&nodes);
    cleanup_nodes(&mut nodes).await;
}

// ===== Outgoing filter re-announce on a tree-peer flip =====
//
// These tests read only what M actually sent (`last_sent_filter`, written
// after a successful send) or what M has marked (`needs_update`). Recomputing
// an outgoing filter would read live peer state and bypass the marking under
// test, so none of them does.

use crate::node::tree::sign_declaration;
use crate::proto::bloom::{BloomFilter, FilterAnnounce};
use crate::proto::stp::{ParentDeclaration, TreeAnnounce, TreeCoordinate};

/// Three loopback nodes, P -- M -- C, with M's tree view forced so that P is
/// M's parent and C either names M as parent (a child) or names an unrelated
/// node (not a tree peer).
struct FlipFixture {
    nodes: Vec<TestNode>,
    m: NodeAddr,
    p: NodeAddr,
    c: NodeAddr,
    root: NodeAddr,
    fake: NodeAddr,
}

/// Index of M in `FlipFixture::nodes`.
const M: usize = 1;
/// Index of C in `FlipFixture::nodes`.
const C: usize = 2;

/// Synthetic address carried in C's filter and in no real one.
fn marker() -> NodeAddr {
    make_node_addr(0xab)
}

/// Build the fixture and flush whatever convergence left pending at M.
///
/// With `child_start`, C's stored declaration names M as parent; otherwise it
/// names `fake`. Every stored declaration uses sequence 1, so the sequence-5
/// announces from `deliver_tree_announce` are fresher.
async fn flip_fixture(child_start: bool) -> FlipFixture {
    let nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    let p = *nodes[0].node.node_addr();
    let m = *nodes[M].node.node_addr();
    let c = *nodes[C].node.node_addr();
    // All zero bytes: smaller than any real address, so it stays root.
    let root = make_node_addr(0);
    let fake = make_node_addr(1);
    let mut fx = FlipFixture {
        nodes,
        m,
        p,
        c,
        root,
        fake,
    };

    {
        let ts = fx.nodes[M].node.tree_state_mut();
        ts.remove_peer(&p);
        ts.update_peer(
            ParentDeclaration::new(p, root, 1, 1000),
            TreeCoordinate::from_addrs(vec![p, root]).unwrap(),
        );
        ts.set_parent(p, 1, 1000, 1000);
        ts.recompute_coords();
        ts.remove_peer(&c);
        let (parent, coords) = if child_start {
            (m, vec![c, m, p, root])
        } else {
            (fake, vec![c, fake, root])
        };
        ts.update_peer(
            ParentDeclaration::new(c, parent, 1, 1000),
            TreeCoordinate::from_addrs(coords).unwrap(),
        );
    }
    {
        let identity = fx.nodes[M].node.identity().clone();
        let decl_mut = fx.nodes[M].node.tree_state_mut().my_declaration_mut();
        sign_declaration(decl_mut, &identity).unwrap();
    }

    // Debounce is a brake, not the mechanism under test: send on every drain.
    fx.nodes[M].node.bloom_state.set_update_debounce_ms(0);
    fx.nodes[M].node.send_pending_filter_announces().await;

    let node = &fx.nodes[M].node;
    assert_eq!(
        node.is_tree_peer(&c),
        child_start,
        "setup: C's starting tree-peer state"
    );
    assert_eq!(
        node.tree_state().my_declaration().parent_id(),
        &p,
        "setup: M's parent must be P"
    );
    fx
}

/// Deliver a FilterAnnounce from C to M holding exactly `addrs`, and check M
/// stored it, so a rejected announce cannot decide a later assertion.
async fn deliver_filter(fx: &mut FlipFixture, addrs: &[NodeAddr]) {
    let c = fx.c;
    let mut filter = BloomFilter::new();
    for addr in addrs {
        filter.insert(addr);
    }
    let seq = fx.nodes[M].node.get_peer(&c).unwrap().filter_sequence() + 1;
    let mut payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
    payload.remove(0); // strip msg_type byte
    fx.nodes[M].node.handle_filter_announce(&c, &payload).await;

    let stored = fx.nodes[M].node.get_peer(&c).unwrap().inbound_filter();
    assert_eq!(
        stored,
        Some(&filter),
        "setup: M must store C's delivered filter"
    );
}

/// Deliver a signed sequence-5 TreeAnnounce from C to M through the real
/// handler, declaring `parent` with ancestry `coords`. Checks the announce was
/// accepted and that M did not switch parent, since a switch marks every peer
/// and would pass the tests for a reason unrelated to the flip.
async fn deliver_tree_announce(fx: &mut FlipFixture, parent: NodeAddr, coords: Vec<NodeAddr>) {
    let c = fx.c;
    let mut decl = ParentDeclaration::new(c, parent, 5, 2000);
    sign_declaration(&mut decl, fx.nodes[C].node.identity()).unwrap();
    let announce = TreeAnnounce::new(decl, TreeCoordinate::from_addrs(coords).unwrap());
    let encoded = announce.encode().unwrap();

    let node = &mut fx.nodes[M].node;
    let accepted_before = node.metrics().tree.accepted.get();
    let switches_before = node.metrics().tree.parent_switches.get();
    node.handle_tree_announce(&c, &encoded[1..]).await;

    assert_eq!(
        node.metrics().tree.accepted.get(),
        accepted_before + 1,
        "setup: C's tree announce must be accepted"
    );
    assert_eq!(
        node.tree_state().my_declaration().parent_id(),
        &fx.p,
        "setup: M's parent must still be P"
    );
    assert_eq!(
        node.metrics().tree.parent_switches.get(),
        switches_before,
        "setup: M must not switch parent"
    );
}

/// The filter M last sent to P, which must exist.
fn sent_to_parent(fx: &FlipFixture) -> &BloomFilter {
    fx.nodes[M]
        .node
        .bloom_state
        .last_sent_filter(&fx.p)
        .expect("M has sent a filter to P")
}

/// When C starts naming M as parent, M must re-announce to P a filter that
/// now includes C's contribution.
#[tokio::test]
async fn test_bloom_outgoing_filter_to_parent_reannounced_when_peer_becomes_child() {
    let mut fx = flip_fixture(false).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    assert!(
        !sent_to_parent(&fx).contains(&marker()),
        "control: a non-tree peer's filter must not reach P"
    );

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    assert!(fx.nodes[M].node.is_tree_peer(&c));
    fx.nodes[M].node.send_pending_filter_announces().await;

    assert!(
        sent_to_parent(&fx).contains(&marker()),
        "P must be sent C's filter once C becomes M's child"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// When C stops naming M as parent, M must re-announce to P a filter that no
/// longer includes C's contribution.
#[tokio::test]
async fn test_bloom_outgoing_filter_to_parent_reannounced_when_child_leaves() {
    let mut fx = flip_fixture(true).await;
    let (c, root, fake) = (fx.c, fx.root, fx.fake);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    assert!(
        sent_to_parent(&fx).contains(&marker()),
        "control: a child's filter must reach P"
    );

    deliver_tree_announce(&mut fx, fake, vec![c, fake, root]).await;
    assert!(!fx.nodes[M].node.is_tree_peer(&c));
    fx.nodes[M].node.send_pending_filter_announces().await;

    assert!(
        !sent_to_parent(&fx).contains(&marker()),
        "P must stop being sent C's filter once C leaves"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// A child's filter that arrives after its tree announce reaches the parent
/// through the ordinary filter-announce marking.
#[tokio::test]
async fn test_bloom_child_filter_after_tree_announce_reaches_parent() {
    let mut fx = flip_fixture(false).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;

    assert!(
        sent_to_parent(&fx).contains(&marker()),
        "P must be sent a child's filter delivered after its tree announce"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// A tree-peer flip that changes no outgoing filter marks no peer: C's filter
/// holds only M's own address, which M's base filter already carries.
#[tokio::test]
async fn test_bloom_tree_peer_flip_without_filter_change_marks_no_peer() {
    let mut fx = flip_fixture(false).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_filter(&mut fx, &[m]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p) && !bloom.needs_update(&c));

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    assert!(fx.nodes[M].node.is_tree_peer(&c));
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(!bloom.needs_update(&c), "C must not be marked");
    cleanup_nodes(&mut fx.nodes).await;
}

/// A fresher tree announce that leaves C a child of M marks no peer.
#[tokio::test]
async fn test_bloom_tree_announce_without_tree_peer_flip_marks_no_peer() {
    let mut fx = flip_fixture(true).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p) && !bloom.needs_update(&c));

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    assert!(fx.nodes[M].node.is_tree_peer(&c));
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(!bloom.needs_update(&c), "C must not be marked");
    cleanup_nodes(&mut fx.nodes).await;
}

// ===== Resend of a filter announce the peer did not receive =====
//
// A lost datagram is made by taking M's frame out of P's receive channel
// without processing it: the transport returned `Ok` and the receiver never
// saw the frame, which is the shape of a real loss on UDP or Ethernet. Final
// assertions read the filter P stores for M, never what M believes it sent.

/// Index of P in `FlipFixture::nodes`.
const P: usize = 0;

/// Set every link report interval on `node` to zero, so the next
/// `check_mmp_reports` sends each report that has interval data.
///
/// Processing a ReceiverReport re-derives the intervals from SRTT, so callers
/// re-apply this before every `check_mmp_reports`.
fn zero_intervals(node: &mut Node) {
    for peer in node.peers.values_mut() {
        if let Some(mmp) = peer.mmp_mut() {
            mmp.sender.update_report_interval_with_bounds(1_000, 0, 0);
            mmp.receiver.update_report_interval_with_bounds(1_000, 0, 0);
        }
    }
}

/// One MMP exchange between M and P: M reports, P processes, P reports, M
/// processes. C is never asked to report.
async fn mmp_round(nodes: &mut [TestNode]) {
    zero_intervals(&mut nodes[M].node);
    zero_intervals(&mut nodes[P].node);
    nodes[M].node.check_mmp_reports().await;
    process_available_packets(nodes).await;
    zero_intervals(&mut nodes[M].node);
    zero_intervals(&mut nodes[P].node);
    nodes[P].node.check_mmp_reports().await;
    process_available_packets(nodes).await;
}

/// Process packets on every node until a pass handles none, at most 50 passes.
async fn drain_quiet(nodes: &mut [TestNode]) {
    for _ in 0..50 {
        if process_available_packets(nodes).await == 0 {
            return;
        }
    }
    panic!("setup: packets still flowing after 50 passes");
}

/// Wait at most 1 s for `tn` to hold a queued frame, then take every queued
/// frame without processing it. Returns how many were taken.
async fn drop_queued(tn: &mut TestNode) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while tn.packet_rx.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut dropped = 0;
    while tn.packet_rx.try_recv().is_ok() {
        dropped += 1;
    }
    dropped
}

/// ReceiverReports M has seen from P, including stale and duplicate ones.
fn reports_seen(fx: &FlipFixture) -> u64 {
    fx.nodes[M]
        .node
        .get_peer(&fx.p)
        .and_then(|peer| peer.mmp())
        .map_or(0, |mmp| mmp.metrics.reports_seen())
}

/// Whether the filter P stores for M contains the marker.
fn holds_marker(fx: &FlipFixture) -> bool {
    fx.nodes[P]
        .node
        .get_peer(&fx.m)
        .and_then(|peer| peer.inbound_filter())
        .is_some_and(|filter| filter.contains(&marker()))
}

/// Parent-switch counts at M and P before a run of MMP rounds.
///
/// A first RTT sample can re-evaluate the parent, and a switch marks every
/// peer, which would pass a resend test for a reason unrelated to the resend.
struct SwitchGuard {
    m: u64,
    p: u64,
}

/// Snapshot M's and P's parent-switch counters.
fn switch_guard(fx: &FlipFixture) -> SwitchGuard {
    SwitchGuard {
        m: fx.nodes[M].node.metrics().tree.parent_switches.get(),
        p: fx.nodes[P].node.metrics().tree.parent_switches.get(),
    }
}

/// Assert neither M nor P switched parent since `guard`, and M's parent is P.
fn assert_unswitched(fx: &FlipFixture, guard: &SwitchGuard) {
    assert_eq!(
        fx.nodes[M].node.metrics().tree.parent_switches.get(),
        guard.m,
        "setup: M must not switch parent during the MMP rounds"
    );
    assert_eq!(
        fx.nodes[P].node.metrics().tree.parent_switches.get(),
        guard.p,
        "setup: P must not switch parent during the MMP rounds"
    );
    assert_eq!(
        fx.nodes[M].node.tree_state().my_declaration().parent_id(),
        &fx.p,
        "setup: M's parent must still be P"
    );
}

/// FilterAnnounces M has sent.
fn sent_count(fx: &FlipFixture) -> u64 {
    fx.nodes[M].node.metrics().bloom.sent.get()
}

/// Drain the fixture, then run MMP rounds until M has seen a report from P.
async fn start_reports(fx: &mut FlipFixture) {
    drain_quiet(&mut fx.nodes).await;
    for _ in 0..10 {
        if reports_seen(fx) >= 1 {
            break;
        }
        mmp_round(&mut fx.nodes).await;
    }
    assert!(reports_seen(fx) >= 1, "setup: P must report to M");
}

/// Deliver C's filter carrying the marker and send M's announce of it to P.
/// Returns M's sent count after the send.
async fn send_marker(fx: &mut FlipFixture) -> u64 {
    let c = fx.c;
    deliver_filter(fx, &[c, marker()]).await;
    let before = sent_count(fx);
    fx.nodes[M].node.send_pending_filter_announces().await;
    let after = sent_count(fx);
    assert_eq!(after, before + 1, "setup: M must send exactly one announce");
    after
}

/// Lose the announce just sent to P, and check the loss took.
async fn lose_announce(fx: &mut FlipFixture) {
    assert_eq!(
        drop_queued(&mut fx.nodes[P]).await,
        1,
        "setup: exactly the one announce frame must be lost"
    );
    assert!(
        !holds_marker(fx),
        "control: P must not hold the lost announce's content"
    );
    assert!(
        sent_to_parent(fx).contains(&marker()),
        "control: M must record the lost announce as sent"
    );
}

/// Get reports flowing from P to M, then send M's announce carrying the
/// marker and lose it on the way to P. Returns M's sent count after the send.
async fn lose_marker(fx: &mut FlipFixture) -> u64 {
    start_reports(fx).await;
    let sent = send_marker(fx).await;
    lose_announce(fx).await;
    sent
}

/// The first eight bytes of the handshake hash of M's current session with P.
fn link_epoch(fx: &FlipFixture) -> [u8; 8] {
    let hash = fx.nodes[M]
        .node
        .get_peer(&fx.p)
        .and_then(|peer| peer.noise_session())
        .expect("M has a session with P")
        .handshake_hash();
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&hash[..8]);
    epoch
}

/// A FilterAnnounce lost in transit is resent once a receiver report shows
/// the loss, so the peer ends up holding the filter.
#[tokio::test]
async fn test_bloom_filter_announce_lost_in_transit_reaches_the_peer_after_a_receiver_report() {
    let mut fx = flip_fixture(true).await;
    lose_marker(&mut fx).await;

    let seen = reports_seen(&fx);
    let guard = switch_guard(&fx);
    for _ in 0..3 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert!(
        reports_seen(&fx) > seen,
        "setup: a receiver report must arrive after the loss"
    );
    assert_unswitched(&fx, &guard);

    assert!(
        holds_marker(&fx),
        "P must hold the filter whose announce was lost"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// Receiving the same filter again under a newer sequence changes no outgoing
/// filter, so it marks no peer and cannot cascade.
#[tokio::test]
async fn test_bloom_unchanged_filter_with_newer_sequence_marks_no_peer() {
    let mut fx = flip_fixture(true).await;
    let (c, p) = (fx.c, fx.p);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(
        !bloom.needs_update(&p) && !bloom.needs_update(&c),
        "control: the first delivery must be fully sent"
    );

    deliver_filter(&mut fx, &[c, marker()]).await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(!bloom.needs_update(&c), "C must not be marked");
    cleanup_nodes(&mut fx.nodes).await;
}

/// Make M rekey on its next check: one message on a session is enough, time
/// never triggers it, and both ends of M's links are aged past the
/// responder's rekey-acceptance gate so both rekeys are ordinary ones.
fn arm_rekey(fx: &mut FlipFixture) {
    fx.nodes[M].node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.rekey.enabled = true;
        cfg.node.rekey.after_messages = 1;
        cfg.node.rekey.after_secs = u64::MAX;
        ctx.config = std::sync::Arc::new(cfg);
    });
    let (m, p, c) = (fx.m, fx.p, fx.c);
    let age = Duration::from_secs(31);
    for (i, remote) in [(M, p), (P, m), (M, c), (C, m)] {
        fx.nodes[i]
            .node
            .get_peer_mut(&remote)
            .expect("setup: link peer present")
            .test_backdate_session_established(age);
    }
}

/// Drive the real rekey handshake until M's session with P is cut over.
async fn rekey_cutover(fx: &mut FlipFixture) {
    let before = link_epoch(fx);
    for _ in 0..6 {
        fx.nodes[M].node.check_rekey().await;
        fx.nodes[P].node.check_rekey().await;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            process_available_packets(&mut fx.nodes).await;
        }
        if link_epoch(fx) != before {
            break;
        }
    }
    assert_ne!(link_epoch(fx), before, "setup: M's link to P must rekey");
    let (m, p) = (fx.m, fx.p);
    assert!(
        !fx.nodes[M].node.get_peer(&p).unwrap().rekey_in_progress(),
        "setup: M's rekey with P must be complete"
    );
    assert!(
        !fx.nodes[P].node.get_peer(&m).unwrap().rekey_in_progress(),
        "setup: P's rekey with M must be complete"
    );
}

/// An announce lost just before a link rekey is resent on the new session.
#[tokio::test]
async fn test_bloom_announce_lost_before_a_link_rekey_reaches_the_peer_after_the_cutover() {
    let mut fx = flip_fixture(true).await;
    let sent = lose_marker(&mut fx).await;

    arm_rekey(&mut fx);
    rekey_cutover(&mut fx).await;

    let guard = switch_guard(&fx);
    for _ in 0..5 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert_unswitched(&fx, &guard);

    assert_eq!(
        sent_count(&fx),
        sent + 1,
        "M must resend to P exactly once after the loss"
    );
    assert!(
        holds_marker(&fx),
        "P must hold the filter whose announce was lost before the rekey"
    );
    assert!(
        !fx.nodes[M].node.bloom_state.announce_outstanding(&fx.p),
        "M's resend on the new session must be confirmed"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// An announce that arrives is confirmed from the receiver reports and never
/// resent.
#[tokio::test]
async fn test_bloom_delivered_announce_is_confirmed_without_a_resend() {
    let mut fx = flip_fixture(true).await;
    let p = fx.p;
    start_reports(&mut fx).await;
    let sent = send_marker(&mut fx).await;
    process_available_packets(&mut fx.nodes).await;
    assert!(holds_marker(&fx), "control: P must hold the announce");

    let guard = switch_guard(&fx);
    for _ in 0..3 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert_unswitched(&fx, &guard);

    let bloom = &fx.nodes[M].node.bloom_state;
    assert_eq!(
        sent_count(&fx),
        sent,
        "M must not resend a delivered announce"
    );
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(
        !bloom.announce_outstanding(&p),
        "the delivered announce must be confirmed"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// On a converged mesh with clean links, every announce is confirmed from the
/// receiver reports and none is resent. The convergence announces go out
/// before any report, so this checks the zero baseline on real counters.
#[tokio::test]
async fn test_bloom_clean_links_confirm_every_announce_without_a_resend() {
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    drain_quiet(&mut nodes).await;
    let snapshot = |nodes: &[TestNode]| -> Vec<(u64, u64, NodeAddr)> {
        nodes
            .iter()
            .map(|tn| {
                (
                    tn.node.metrics().bloom.sent.get(),
                    tn.node.metrics().tree.parent_switches.get(),
                    *tn.node.tree_state().my_declaration().parent_id(),
                )
            })
            .collect()
    };
    let before = snapshot(&nodes);

    for _ in 0..5 {
        for i in 0..nodes.len() {
            zero_intervals(&mut nodes[i].node);
            nodes[i].node.check_mmp_reports().await;
            process_available_packets(&mut nodes).await;
        }
        for tn in nodes.iter_mut() {
            tn.node.check_bloom_state().await;
        }
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        snapshot(&nodes),
        before,
        "no node may send an announce, switch parent or change parent"
    );
    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers.keys() {
            assert!(
                !tn.node.bloom_state.announce_outstanding(peer),
                "node {i} must have confirmed its announce to every peer"
            );
        }
    }
    cleanup_nodes(&mut nodes).await;
}

/// With no receiver report at all, a lost announce is still resent once the
/// fallback interval passes.
#[tokio::test]
async fn test_bloom_lost_announce_is_resent_after_the_fallback_when_no_receiver_report_arrives() {
    let mut fx = flip_fixture(true).await;
    drain_quiet(&mut fx.nodes).await;
    fx.nodes[M].node.bloom_state.set_fallback(0);
    let seen = reports_seen(&fx);
    send_marker(&mut fx).await;
    lose_announce(&mut fx).await;

    fx.nodes[M].node.check_bloom_state().await;
    process_available_packets(&mut fx.nodes).await;

    assert_eq!(reports_seen(&fx), seen, "setup: P must send no report");
    assert!(
        holds_marker(&fx),
        "P must hold the filter once the fallback resends it"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// The cumulative counters of the last report `node` accepted from `peer`.
fn rr_counters(node: &Node, peer: &NodeAddr) -> Option<(u64, u64, u32)> {
    node.get_peer(peer)?.mmp()?.metrics.rr_counters()
}

/// The next send counter of `node`'s current session with `peer`.
fn next_counter(node: &Node, peer: &NodeAddr) -> u64 {
    node.get_peer(peer)
        .and_then(|p| p.noise_session())
        .expect("setup: session present")
        .current_send_counter()
}

/// Around a rekey, reports that describe the previous session reach both
/// ends of the link: the initiator accepts one the responder built before it
/// switched, and the responder's frames from the old session pollute the
/// initiator's receiver. Neither kind of report may trigger a resend.
#[tokio::test]
async fn test_bloom_reports_from_the_previous_session_do_not_trigger_resends() {
    let mut fx = flip_fixture(true).await;
    let (m, p) = (fx.m, fx.p);
    fx.nodes[P].node.bloom_state.set_update_debounce_ms(0);
    start_reports(&mut fx).await;
    arm_rekey(&mut fx);

    // A session reaching its rekey has carried many frames. Reserve counters
    // on both old sessions so their counters stay above the new sessions'
    // for the whole test, as they do in the field; with a short history the
    // new counters pass them within a few rounds, the reports become usable,
    // and each announce spends its one unchecked resend.
    for (i, remote) in [(M, p), (P, m)] {
        let session = fx.nodes[i]
            .node
            .get_peer_mut(&remote)
            .and_then(|peer| peer.noise_session_mut())
            .expect("setup: session present");
        for _ in 0..1000 {
            session
                .take_send_counter()
                .expect("setup: counter available");
        }
    }

    // Reports both ways, then M reports alone so P holds interval data.
    mmp_round(&mut fx.nodes).await;
    zero_intervals(&mut fx.nodes[M].node);
    zero_intervals(&mut fx.nodes[P].node);
    fx.nodes[M].node.check_mmp_reports().await;
    process_available_packets(&mut fx.nodes).await;

    // M starts the rekey and holds the new session, not yet cut over.
    let before = link_epoch(&fx);
    fx.nodes[M].node.check_rekey().await;
    for _ in 0..10 {
        if fx.nodes[M]
            .node
            .get_peer(&p)
            .is_some_and(|peer| peer.pending_new_session().is_some())
        {
            break;
        }
        process_available_packets(&mut fx.nodes).await;
    }
    assert!(
        fx.nodes[M]
            .node
            .get_peer(&p)
            .is_some_and(|peer| peer.pending_new_session().is_some()),
        "setup: M must hold P's new session"
    );
    assert_eq!(link_epoch(&fx), before, "setup: M must not have cut over");

    // P reports on the old session; hold its frames back from M.
    assert!(
        fx.nodes[M].packet_rx.is_empty(),
        "setup: M's queue is empty"
    );
    zero_intervals(&mut fx.nodes[P].node);
    fx.nodes[P].node.check_mmp_reports().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while fx.nodes[M].packet_rx.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut held = Vec::new();
    while let Ok(packet) = fx.nodes[M].packet_rx.try_recv() {
        held.push(packet);
    }
    assert!(!held.is_empty(), "setup: P must queue its reports for M");

    // M cuts over, then receives P's old-session frames.
    fx.nodes[M].node.check_rekey().await;
    assert_ne!(link_epoch(&fx), before, "setup: M must cut over");
    for packet in held {
        fx.nodes[M].node.handle_encrypted_frame(packet).await;
    }
    mmp_round(&mut fx.nodes).await;

    let m_rr = rr_counters(&fx.nodes[M].node, &p).expect("setup: M holds a report");
    let p_rr = rr_counters(&fx.nodes[P].node, &m).expect("setup: P holds a report");
    assert!(
        m_rr.0 >= next_counter(&fx.nodes[M].node, &p),
        "setup: M's report must describe M's previous session"
    );
    assert!(
        p_rr.0 >= next_counter(&fx.nodes[P].node, &m),
        "setup: P's report must carry P's previous-session counter"
    );

    fx.nodes[M].node.bloom_state.mark_update_needed(p);
    fx.nodes[P].node.bloom_state.mark_update_needed(m);
    fx.nodes[M].node.send_pending_filter_announces().await;
    fx.nodes[P].node.send_pending_filter_announces().await;
    process_available_packets(&mut fx.nodes).await;
    assert!(
        fx.nodes[M].node.bloom_state.announce_outstanding(&p)
            && fx.nodes[P].node.bloom_state.announce_outstanding(&m),
        "setup: both ends must have an announce outstanding"
    );

    let sent_m = fx.nodes[M].node.metrics().bloom.sent.get();
    let sent_p = fx.nodes[P].node.metrics().bloom.sent.get();
    let guard = switch_guard(&fx);
    let mut last = rr_counters(&fx.nodes[P].node, &m);
    let mut changes = 0;
    for _ in 0..5 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        fx.nodes[P].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
        let now = rr_counters(&fx.nodes[P].node, &m);
        if now != last {
            changes += 1;
        }
        last = now;
    }
    assert!(
        changes >= 2,
        "setup: P must accept at least two reports from M, saw {changes}"
    );
    assert_unswitched(&fx, &guard);
    let m_rr = rr_counters(&fx.nodes[M].node, &p).expect("setup: M holds a report");
    let p_rr = rr_counters(&fx.nodes[P].node, &m).expect("setup: P holds a report");
    assert!(
        m_rr.0 >= next_counter(&fx.nodes[M].node, &p)
            && p_rr.0 >= next_counter(&fx.nodes[P].node, &m),
        "setup: both reports must still describe a previous session"
    );

    assert_eq!(
        fx.nodes[M].node.metrics().bloom.sent.get(),
        sent_m,
        "M must not resend on reports from the previous session"
    );
    assert_eq!(
        fx.nodes[P].node.metrics().bloom.sent.get(),
        sent_p,
        "P must not resend on reports carrying its previous-session counter"
    );
    assert!(
        fx.nodes[M].node.bloom_state.announce_outstanding(&p),
        "M must still hold its announce to P"
    );
    assert!(
        fx.nodes[P].node.bloom_state.announce_outstanding(&m),
        "P must still hold its announce to M"
    );
    cleanup_nodes(&mut fx.nodes).await;
}
