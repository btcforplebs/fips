//! A transit LookupRequest must not be forwarded back to the peer that
//! delivered it, even when that peer's bloom filter matches the target.

use super::*;
use crate::proto::lookup::LookupRequest;
use spanning_tree::{cleanup_nodes, process_available_packets, run_tree_test};

/// Build a transit request from an origin that is no node's peer.
fn transit_request(request_id: u64, target: NodeAddr) -> LookupRequest {
    let origin = make_node_addr(0x77);
    LookupRequest::new(request_id, target, origin, 5, 0)
}

#[tokio::test]
async fn a_lookup_whose_only_matching_tree_peer_is_its_sender_is_not_echoed_back() {
    // node1 — node0 — node2. Node 1's only peer is node 0, whose filter
    // carries node 2. A request for node 2 that node 0 hands to node 1 has
    // nowhere further to go from node 1.
    let mut nodes = run_tree_test(3, &[(0, 1), (0, 2)], false).await;
    let node0 = *nodes[0].node.node_addr();
    let node2 = *nodes[2].node.node_addr();

    assert!(
        nodes[1].node.is_tree_peer(&node0),
        "precondition: node 0 is a tree peer of node 1"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&node0)
            .is_some_and(|peer| peer.may_reach(&node2)),
        "precondition: node 0's filter at node 1 carries node 2"
    );

    let request_id = 0x4b31_0001;
    let payload = &transit_request(request_id, node2).encode()[1..];
    let node0_received = nodes[0].node.metrics().lookup.req_received.get();
    let node1_received = nodes[1].node.metrics().lookup.req_received.get();
    let node1_no_peer = nodes[1].node.metrics().lookup.req_no_tree_peer.get();

    nodes[1].node.handle_lookup_request(&node0, payload).await;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        nodes[1].node.metrics().lookup.req_received.get(),
        node1_received + 1,
        "control: node 1 counted the request it was handed"
    );
    assert!(
        !nodes[0]
            .node
            .lookup
            .recent_requests
            .contains_key(&request_id),
        "node 1 echoed the request back to node 0, which recorded it"
    );
    assert_eq!(
        nodes[0].node.metrics().lookup.req_received.get(),
        node0_received,
        "node 1 echoed the request back to node 0, which counted it"
    );
    assert_eq!(
        nodes[1].node.metrics().lookup.req_no_tree_peer.get(),
        node1_no_peer + 1,
        "node 1 must end the request with no eligible peer"
    );

    cleanup_nodes(&mut nodes).await;
}
