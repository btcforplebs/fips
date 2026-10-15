//! Dials made because a transport neighbour claimed a key, beside the other
//! paths to the same node.
//!
//! A BLE or Ethernet neighbour's key claim is unproven until its handshake
//! completes, so a leg dialled on one must not hold back the node's
//! configured address or its LAN advert. The claim links use MockBleIo; a
//! LAN advert is dialled over a loopback UDP transport.

use super::ble::{
    base_config, ble_addr, inject_claim, larger_second, make_test_node_ble_with, pooled_at, until,
};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::config::BleConfig;

/// Node 1 (BLE `auto_connect`) and node 0, ordered so node 1 holds the larger
/// key and admits inbound links claiming node 0. Node 1 is running, so its
/// opportunistic layer dials.
async fn claim_pair() -> Vec<TestNode> {
    let auto = BleConfig {
        auto_connect: Some(true),
        ..base_config()
    };
    let mut nodes = vec![
        make_test_node_ble_with(1, auto.clone()).await,
        make_test_node_ble_with(2, auto).await,
    ];
    larger_second(&mut nodes);
    nodes[1].node.supervisor.state = NodeState::Running;
    nodes
}

// ============================================================================
// Where a dial came from
// ============================================================================

/// The origin of node 1's single dial to node 0, as its pending connect and
/// then its handshake leg record it.
async fn origins_across_the_hand_off(
    nodes: &mut [TestNode],
) -> (
    crate::peer::machine::DialOrigin,
    crate::peer::machine::DialOrigin,
) {
    let n0 = *nodes[0].node.node_addr();
    assert!(until(|| !nodes[1].node.peering.pending_connects.is_empty()).await);
    let pending = &nodes[1].node.peering.pending_connects;
    assert_eq!(pending.len(), 1, "one dial to node 0");
    let at_connect = pending[0].origin;
    assert_eq!(
        nodes[1].node.peer_machines[&pending[0].link_id].dial_origin(),
        at_connect,
        "the pending connect carries its machine's origin"
    );
    for _ in 0..50 {
        nodes[1].node.poll_pending_connects().await;
        if nodes[1].node.peering.pending_connects.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let legs: Vec<_> = nodes[1]
        .node
        .connections()
        .filter(|(_, machine)| {
            machine
                .conn_expected_identity()
                .is_some_and(|id| *id.node_addr() == n0)
        })
        .map(|(_, machine)| machine.dial_origin())
        .collect();
    assert_eq!(legs.len(), 1, "the dial became one handshake leg");
    (at_connect, legs[0])
}

/// A dial made on a transport neighbour's claim is marked as one from its
/// pending BLE connect through to its handshake leg.
#[tokio::test]
async fn a_claim_dial_keeps_its_origin_from_pending_connect_to_handshake_leg() {
    use crate::peer::machine::DialOrigin;
    let mut nodes = claim_pair().await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let at = ble_addr(20).to_transport_addr();
    let held = inject_claim(&nodes, 1, &ble_addr(20), key_0).await;
    assert!(until(|| pooled_at(&nodes[1], &at)).await);
    nodes[1].node.poll_transport_discovery().await;
    let origins = origins_across_the_hand_off(&mut nodes).await;
    drop(held);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        origins,
        (DialOrigin::NeighbourClaim, DialOrigin::NeighbourClaim)
    );
}

/// A configured dial over the same transport, to an address where a link
/// is already open, is not marked as a claim.
#[tokio::test]
async fn a_configured_dial_is_not_marked_as_a_claim() {
    use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
    use crate::peer::machine::DialOrigin;
    let mut nodes = claim_pair().await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let at = ble_addr(20).to_transport_addr();
    let held = inject_claim(&nodes, 1, &ble_addr(20), key_0).await;
    assert!(until(|| pooled_at(&nodes[1], &at)).await);
    let config = PeerConfig {
        npub: nodes[0].node.identity().npub(),
        alias: None,
        addresses: vec![PeerAddress::new("ble", at.as_str().unwrap())],
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    nodes[1]
        .node
        .initiate_peer_connection(&config)
        .await
        .unwrap();
    let origins = origins_across_the_hand_off(&mut nodes).await;
    drop(held);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(origins, (DialOrigin::Addressed, DialOrigin::Addressed));
}
