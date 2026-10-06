//! BLE transport integration tests.
//!
//! Tests that the BLE transport works end-to-end at the node level:
//! handshake, spanning tree convergence, mixed-transport routing.
//! All tests use MockBleIo (in-memory channels, no hardware needed).

use super::*;
use crate::config::BleConfig;
use crate::transport::ble::BleTransport;
use crate::transport::ble::addr::BleAddr;
use crate::transport::ble::io::{MockBleIo, MockBleStream};
use crate::transport::{Transport, TransportHandle, TransportId, packet_channel};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, process_available_packets,
    verify_tree_convergence,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

/// Generate a deterministic BLE address for test node `n`.
fn ble_addr(n: u8) -> BleAddr {
    BleAddr {
        adapter: "hci0".to_string(),
        device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
    }
}

/// A pre-connected stream bank for MockBleIo connect handlers.
///
/// When a connect handler fires, it looks up the target address in this
/// bank and returns the pre-created stream. The peer end should be
/// injected into the target node's acceptor separately.
type StreamBank = Arc<StdMutex<HashMap<String, MockBleStream>>>;

/// Create a test node with a BLE transport backed by MockBleIo.
///
/// Returns the TestNode and its MockBleIo (via Arc inside the transport)
/// for test injection of connections and scan results.
async fn make_test_node_ble(node_num: u8) -> TestNode {
    make_test_node_ble_with(node_num, test_ble_config()).await
}

/// The BLE configuration test nodes run with.
fn test_ble_config() -> BleConfig {
    BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(2048),
        accept_connections: Some(true),
        scan: Some(false),      // no auto-scan in tests
        advertise: Some(false), // no advertising in tests
        auto_connect: Some(false),
        ..Default::default()
    }
}

/// Create a test node with a BLE transport built from `config`.
async fn make_test_node_ble_with(node_num: u8, config: BleConfig) -> TestNode {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let addr = ble_addr(node_num);

    let io = MockBleIo::new("hci0", addr.clone());
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = BleTransport::new(transport_id, None, config, io, packet_tx);
    transport.start_async().await.unwrap();

    let ta = addr.to_transport_addr();

    node.transports
        .insert(transport_id, TransportHandle::Ble(transport));

    TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        addr: ta,
    }
}

/// Extract the BleAddr from a TestNode's TransportAddr.
fn node_ble_addr(node: &TestNode) -> BleAddr {
    BleAddr::parse(node.addr.as_str().unwrap()).unwrap()
}

/// Wire a unidirectional BLE connection from node `i` to node `j`.
///
/// Creates a MockBleStream pair, deposits one end in a stream bank for
/// node i's connect handler, and injects the other end into node j's
/// accept loop. Must be called after `make_test_node_ble()` and before
/// `initiate_handshake()`.
async fn wire_ble_connection(nodes: &[TestNode], i: usize, j: usize, bank: &StreamBank) {
    let addr_i = node_ble_addr(&nodes[i]);
    let addr_j = node_ble_addr(&nodes[j]);

    let (stream_i, stream_j) = MockBleStream::pair(addr_j.clone(), addr_i.clone(), 2048);

    // Store stream_i in the bank keyed by node j's address string.
    // When node i connects to node j, the handler returns this stream.
    let key = nodes[j].addr.to_string();
    bank.lock().unwrap().insert(key, stream_i);

    // Inject stream_j into node j's accept loop so it sees the inbound.
    let transport_j = nodes[j]
        .node
        .transports
        .get(&nodes[j].transport_id)
        .unwrap();
    match transport_j {
        TransportHandle::Ble(t) => {
            t.io().inject_inbound(stream_j).await;
        }
        _ => panic!("expected BLE transport"),
    }
}

/// Install a connect handler on node `i` that draws from the stream bank.
fn install_connect_handler(nodes: &[TestNode], i: usize, bank: &StreamBank) {
    let bank = Arc::clone(bank);
    let transport_i = nodes[i]
        .node
        .transports
        .get(&nodes[i].transport_id)
        .unwrap();
    match transport_i {
        TransportHandle::Ble(t) => {
            t.io().set_connect_handler(move |addr, _psm| {
                let key = addr.to_transport_addr().to_string();
                let mut map = bank.lock().unwrap();
                match map.remove(&key) {
                    Some(stream) => Ok(stream),
                    None => Err(crate::transport::TransportError::ConnectionRefused),
                }
            });
        }
        _ => panic!("expected BLE transport"),
    }
}

/// Establish a BLE connection from node `i` to node `j` via connect_async.
///
/// Must be called after `wire_ble_connection` and `install_connect_handler`.
/// BLE send_async fails fast if no connection exists, so connections must
/// be pre-established before initiating handshakes.
async fn establish_ble_connection(nodes: &[TestNode], i: usize, j: usize) {
    let transport = nodes[i]
        .node
        .transports
        .get(&nodes[i].transport_id)
        .unwrap();
    transport.connect(&nodes[j].addr).await.unwrap();
    // Let the background connect task complete
    tokio::task::yield_now().await;
}

/// Two BLE nodes complete a Noise handshake and establish bidirectional peering.
#[tokio::test]
async fn test_ble_two_node_handshake() {
    let mut nodes = vec![make_test_node_ble(1).await, make_test_node_ble(2).await];

    // Wire connection: node 0 → node 1
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(&nodes, 0, 1, &bank).await;
    install_connect_handler(&nodes, 0, &bank);
    establish_ble_connection(&nodes, 0, 1).await;

    // Initiate handshake
    initiate_handshake(&mut nodes, 0, 1).await;

    // Drain all packets (handshake + TreeAnnounce exchange)
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify bidirectional peering
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 should have node 1 as peer"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have node 0 as peer"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Three BLE nodes in a chain converge to a consistent spanning tree.
#[tokio::test]
async fn test_ble_three_node_chain() {
    let mut nodes = vec![
        make_test_node_ble(1).await,
        make_test_node_ble(2).await,
        make_test_node_ble(3).await,
    ];

    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));

    // Wire: 0 -- 1 -- 2
    wire_ble_connection(&nodes, 0, 1, &bank).await;
    wire_ble_connection(&nodes, 1, 2, &bank).await;
    install_connect_handler(&nodes, 0, &bank);
    install_connect_handler(&nodes, 1, &bank);
    establish_ble_connection(&nodes, 0, 1).await;
    establish_ble_connection(&nodes, 1, 2).await;

    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 2).await;

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify spanning tree convergence
    verify_tree_convergence(&nodes);

    // Verify correct root
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
    for tn in &nodes {
        assert_eq!(*tn.node.tree_state().root(), expected_root);
    }

    // Verify peer counts
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 2);
    assert_eq!(nodes[2].node.peer_count(), 1);

    // Verify bloom filter reachability: node 0 → node 2
    let addr_2 = *nodes[2].node.node_addr();
    let reaches = nodes[0].node.peers().any(|p| p.may_reach(&addr_2));
    assert!(reaches, "node 0 should see node 2 as reachable");

    cleanup_nodes(&mut nodes).await;
}

/// Mixed transport: UDP and BLE nodes coexist in independent components.
#[tokio::test]
async fn test_ble_mixed_transport() {
    use spanning_tree::{make_test_node, verify_tree_convergence_components};

    let udp_0 = make_test_node().await;
    let udp_1 = make_test_node().await;
    let ble_0 = make_test_node_ble(1).await;
    let ble_1 = make_test_node_ble(2).await;

    let mut nodes = vec![udp_0, udp_1, ble_0, ble_1];

    // Wire BLE pair
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(&nodes, 2, 3, &bank).await;
    install_connect_handler(&nodes, 2, &bank);
    establish_ble_connection(&nodes, 2, 3).await;

    // Handshake within each component
    initiate_handshake(&mut nodes, 0, 1).await; // UDP pair
    initiate_handshake(&mut nodes, 2, 3).await; // BLE pair

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify each component converges independently
    verify_tree_convergence_components(&nodes, &[vec![0, 1], vec![2, 3]]);

    // BLE component has its own root
    let ble_root = std::cmp::min(*nodes[2].node.node_addr(), *nodes[3].node.node_addr());
    assert_eq!(*nodes[2].node.tree_state().root(), ble_root);
    assert_eq!(*nodes[3].node.tree_state().root(), ble_root);

    cleanup_nodes(&mut nodes).await;
}

/// BLE scan+probe loop discovers peers via adapter scan events.
#[tokio::test(start_paused = true)]
async fn test_ble_discovery() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let addr = ble_addr(1);

    // Enable scanning so the scan+probe loop runs
    let config = BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(2048),
        accept_connections: Some(true),
        scan: Some(true),
        advertise: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    };

    let io = MockBleIo::new("hci0", addr.clone());
    // Probe connect must succeed for peers to reach the discovery buffer
    let local = addr.clone();
    io.set_connect_handler(move |target, _psm| {
        let (stream, _peer) = MockBleStream::pair(local.clone(), target.clone(), 2048);
        Ok(stream)
    });
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = BleTransport::new(transport_id, None, config, io, packet_tx);
    transport.start_async().await.unwrap();

    // Inject scan results via the I/O mock
    transport.io().inject_scan_result(ble_addr(2)).await;
    transport.io().inject_scan_result(ble_addr(3)).await;

    // Let scan_probe_loop pick up results and schedule jitter
    tokio::task::yield_now().await;
    // Advance past max jitter so probes fire
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    // Peers appear as bare addresses in discovery buffer after probe
    let peers = transport.discover().unwrap();
    assert_eq!(peers.len(), 2);

    let ta = addr.to_transport_addr();
    node.transports
        .insert(transport_id, TransportHandle::Ble(transport));

    let mut nodes = vec![TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        addr: ta,
    }];
    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Two BLE nodes that dial each other at once
// ============================================================================

/// How long a retired channel lingers in the race tests, as the transport's
/// connect timeout. Short, because these tests run on real time.
const RACE_LINGER_MS: u64 = 300;

/// How long the race tests wait for a condition they expect to reach. Long,
/// so a slow machine passes; a passing run returns as soon as it holds.
const RACE_DEADLINE: Duration = Duration::from_secs(10);

/// The BLE transport of a test node.
fn ble_transport(node: &TestNode) -> &BleTransport<MockBleIo> {
    match node.node.transports.get(&node.transport_id).unwrap() {
        TransportHandle::Ble(t) => t,
        _ => panic!("expected BLE transport"),
    }
}

/// Two BLE test nodes whose transports each hold two channels at the
/// other's address: L1, which node 0 dialled, and L2, which node 1 dialled.
/// That is what both nodes dialling each other at once leaves behind.
async fn two_racing_ble_nodes() -> Vec<TestNode> {
    let config = BleConfig {
        connect_timeout_ms: Some(RACE_LINGER_MS),
        ..test_ble_config()
    };
    let nodes = vec![
        make_test_node_ble_with(1, config.clone()).await,
        make_test_node_ble_with(2, config).await,
    ];
    let (addr0, addr1) = (ble_addr(1), ble_addr(2));
    // `pair(a, b)` gives the end at `a` (whose remote is `b`) first.
    let (l1_at_0, l1_at_1) = MockBleStream::pair(addr0.clone(), addr1.clone(), 2048);
    let (l2_at_1, l2_at_0) = MockBleStream::pair(addr1, addr0, 2048);
    for (i, dial) in [(0, l1_at_0), (1, l2_at_1)] {
        let dial = StdMutex::new(Some(dial));
        ble_transport(&nodes[i])
            .io()
            .set_connect_handler(move |_addr, _psm| {
                dial.lock()
                    .unwrap()
                    .take()
                    .ok_or(crate::transport::TransportError::ConnectionRefused)
            });
    }
    ble_transport(&nodes[0])
        .connect_async(&nodes[1].addr)
        .await
        .unwrap();
    ble_transport(&nodes[1])
        .connect_async(&nodes[0].addr)
        .await
        .unwrap();
    ble_transport(&nodes[0]).io().inject_inbound(l2_at_0).await;
    ble_transport(&nodes[1]).io().inject_inbound(l1_at_1).await;

    let end = tokio::time::Instant::now() + RACE_DEADLINE;
    while tokio::time::Instant::now() < end {
        let (held0, _) = ble_transport(&nodes[0]).channels_at(&nodes[1].addr).await;
        let (held1, _) = ble_transport(&nodes[1]).channels_at(&nodes[0].addr).await;
        if held0.len() == 2 && held1.len() == 2 {
            return nodes;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("each node should hold both channels before the handshake");
}

/// Process packets until each node holds one channel to the other and
/// retires nothing, or until the deadline passes. The caller asserts what
/// was reached, so a deadline that passes reports the state it stopped in.
async fn wait_for_one_channel_each(nodes: &mut [TestNode]) {
    let end = tokio::time::Instant::now() + RACE_DEADLINE;
    while tokio::time::Instant::now() < end {
        process_available_packets(nodes).await;
        let mut settled = true;
        for i in 0..2 {
            let peer_addr = nodes[1 - i].addr.clone();
            let (held, retiring) = ble_transport(&nodes[i]).channels_at(&peer_addr).await;
            settled &= held.len() == 1 && retiring.is_empty();
        }
        if settled {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Assert that the two nodes are peers on one session, that each holds one
/// channel to the other and nothing retiring, that it is the channel the
/// smaller node dialled, and that an encrypted frame crosses each way.
async fn assert_one_working_link(nodes: &mut [TestNode], when: &str) {
    let addr = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    let (on0, on1) = (
        nodes[0]
            .node
            .get_peer(&addr[1])
            .map(|p| (p.our_index(), p.their_index())),
        nodes[1]
            .node
            .get_peer(&addr[0])
            .map(|p| (p.our_index(), p.their_index())),
    );
    let (Some((our0, their0)), Some((our1, their1))) = (on0, on1) else {
        panic!("{when}: both nodes must hold the other as a peer: {on0:?} {on1:?}");
    };
    assert!(our0.is_some() && their0.is_some(), "{when}: indices set");
    assert_eq!(
        their0, our1,
        "{when}: node 0 sends on an index node 1 receives on"
    );
    assert_eq!(
        their1, our0,
        "{when}: node 1 sends on an index node 0 receives on"
    );

    for i in 0..2 {
        let peer_addr = nodes[1 - i].addr.clone();
        let (held, retiring) = ble_transport(&nodes[i]).channels_at(&peer_addr).await;
        let smaller = addr[i] < addr[1 - i];
        assert_eq!(
            held.len(),
            1,
            "{when}: node {i} holds one channel to its peer: {held:?}"
        );
        assert!(
            retiring.is_empty(),
            "{when}: node {i} retires nothing: {retiring:?}"
        );
        assert_eq!(
            held[0].1, smaller,
            "{when}: node {i} keeps the channel the smaller node dialled"
        );
    }

    for i in 0..2 {
        let peer = addr[1 - i];
        let before = nodes[1 - i]
            .node
            .get_peer(&addr[i])
            .unwrap()
            .link_stats()
            .packets_recv;
        nodes[i]
            .node
            .send_encrypted_link_message(&peer, &[0x51])
            .await
            .unwrap_or_else(|e| panic!("{when}: node {i} sends to its peer: {e}"));
        let mut arrived = false;
        let end = tokio::time::Instant::now() + RACE_DEADLINE;
        while tokio::time::Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(5)).await;
            process_available_packets(nodes).await;
            let after = nodes[1 - i]
                .node
                .get_peer(&addr[i])
                .unwrap()
                .link_stats()
                .packets_recv;
            if after > before {
                arrived = true;
                break;
            }
        }
        assert!(arrived, "{when}: node {i}'s frame is decrypted by its peer");
    }
}

/// Let retired channels linger out, then run both handshake reapers at a
/// time past the handshake timeout, as a long-running node would: the
/// inbound-leg reaper (`check_timeouts`) and the outbound one (the machine's
/// handshake timer). Then give any close they made time to reach the other
/// end before the caller asserts the link survived.
///
/// In the races these tests build, no handshake leg is left once the peer
/// is promoted, so both reapers find nothing to reap. The phase is there so
/// that a change which leaves a leg behind at the peer's address, where a
/// reap would close the peer's own link, would fail the assertion that
/// follows.
async fn age_past_linger_and_handshake_timeout(nodes: &mut [TestNode]) {
    wait_for_one_channel_each(nodes).await;
    drain_all_packets(nodes, false).await;
    let later = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 120_000;
    for tn in nodes.iter_mut() {
        let timeout_ms = tn.node.config().node.rate_limit.handshake_timeout_secs * 1000;
        assert!(timeout_ms < 120_000, "the reapers run past the timeout");
        tn.node.check_timeouts_at(later).await;
        tn.node.drive_peer_timers(later).await;
    }
    tokio::time::sleep(Duration::from_millis(RACE_LINGER_MS * 2)).await;
    drain_all_packets(nodes, false).await;
}

/// Two BLE nodes whose channels raced at one address, and whose handshakes
/// both start before either answers, end on one link that carries traffic,
/// and keep it past the handshake timeout.
#[tokio::test]
async fn two_ble_nodes_that_dial_each_other_keep_one_link() {
    let mut nodes = two_racing_ble_nodes().await;

    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;
    wait_for_one_channel_each(&mut nodes).await;
    assert_one_working_link(&mut nodes, "after the handshakes").await;

    age_past_linger_and_handshake_timeout(&mut nodes).await;
    assert_one_working_link(&mut nodes, "past the handshake timeout").await;

    cleanup_nodes(&mut nodes).await;
}
