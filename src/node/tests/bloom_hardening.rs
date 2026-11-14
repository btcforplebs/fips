//! FilterAnnounce hardening, ported from upstream a0bbdb26 (the hash_count,
//! per-peer sequence and per-tick recompute parts; the hold of an over-cap
//! outgoing filter was reverted upstream by a04ac80b and is not ported).
//!
//! The P -- M -- C fixture comes from `bloom.rs`: P is M's parent and C is
//! M's child.

use super::bloom::{FlipFixture, M, deliver_filter, flip_fixture, marker, sent_count};
use super::spanning_tree::*;
use super::*;
use crate::peer::ActivePeer;
use crate::proto::bloom::{BloomFilter, DEFAULT_FILTER_SIZE_BITS, FilterAnnounce};

/// Index of P in the fixture's node vector.
const P: usize = 0;

fn inject_peer(node: &mut Node) -> NodeAddr {
    let peer_identity = make_peer_identity();
    let peer_addr = *peer_identity.node_addr();
    let peer = ActivePeer::new(peer_identity, LinkId::new(1), 0);
    node.peers.insert(peer_addr, peer);
    peer_addr
}

fn encode_payload(announce: &FilterAnnounce) -> Vec<u8> {
    let mut full = announce.encode().unwrap();
    full.remove(0); // strip msg_type byte
    full
}

async fn assert_rejected_as_non_v1(announce: &FilterAnnounce) {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);
    let before_accepted = node.metrics().bloom.accepted.get();
    let before_non_v1 = node.metrics().bloom.non_v1.get();

    node.handle_filter_announce(&peer_addr, &encode_payload(announce))
        .await;

    assert_eq!(
        node.metrics().bloom.accepted.get(),
        before_accepted,
        "accepted must not increment for a hash_count other than 5"
    );
    assert_eq!(
        node.metrics().bloom.non_v1.get(),
        before_non_v1 + 1,
        "non_v1 must count the rejection"
    );
    let peer = node.get_peer(&peer_addr).expect("peer still present");
    assert!(peer.inbound_filter().is_none(), "no filter may be stored");
    assert_eq!(
        peer.filter_sequence(),
        0,
        "filter_sequence must not advance"
    );
}

/// 8,136 of 8,192 bits set. At k=255 its FPR is about 0.174, under the
/// default 0.20 cap; at k=5 the same bits would be about 0.966.
#[tokio::test]
async fn a_nearly_full_filter_announced_with_hash_count_255_is_rejected() {
    let mut bytes = vec![0xFFu8; 1017];
    bytes.extend_from_slice(&[0x00u8; 7]);
    let filter = BloomFilter::from_bytes(bytes, 255).unwrap();
    assert_eq!(filter.count_ones(), 8136);
    let cap = make_node().config().node.bloom.max_inbound_fpr;
    assert!(
        filter.fpr() < cap,
        "setup: the k=255 FPR ({}) must pass the cap ({cap})",
        filter.fpr()
    );
    let announce = FilterAnnounce::new(filter, 1);
    assert!(
        announce.is_valid(),
        "setup: the announce is self-consistent"
    );
    assert_rejected_as_non_v1(&announce).await;
}

#[tokio::test]
async fn a_sparse_filter_announced_with_hash_count_other_than_five_is_rejected() {
    let mut filter = BloomFilter::with_params(DEFAULT_FILTER_SIZE_BITS, 7).unwrap();
    for i in 0..50u8 {
        filter.insert(&make_node_addr(i));
    }
    let announce = FilterAnnounce::new(filter, 1);
    assert!(
        announce.is_valid(),
        "setup: the announce is self-consistent"
    );
    assert_rejected_as_non_v1(&announce).await;
}

/// The FilterAnnounce sequence P stores for M.
fn parent_seq(fx: &FlipFixture) -> u64 {
    fx.nodes[P]
        .node
        .get_peer(&fx.m)
        .expect("P has M as a peer")
        .filter_sequence()
}

/// Deliver to M, from P, an announce holding P and `addr`.
async fn deliver_from_parent(fx: &mut FlipFixture, addr: NodeAddr) {
    let p = fx.p;
    let mut filter = BloomFilter::new();
    filter.insert(&p);
    filter.insert(&addr);
    let seq = fx.nodes[M].node.get_peer(&p).unwrap().filter_sequence() + 1;
    let mut payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
    payload.remove(0);
    fx.nodes[M].node.handle_filter_announce(&p, &payload).await;
    assert_eq!(
        fx.nodes[M].node.get_peer(&p).unwrap().inbound_filter(),
        Some(&filter),
        "setup: M must store P's filter"
    );
}

async fn send_and_deliver(fx: &mut FlipFixture) {
    fx.nodes[M].node.send_pending_filter_announces().await;
    process_available_packets(&mut fx.nodes).await;
}

/// A peer's sequences advance by one per announce sent to that peer. With
/// one node-wide counter, P saw a gap for every announce M built for C,
/// and so could watch M's traffic to its other peers.
#[tokio::test]
async fn a_peer_sees_no_sequence_gap_for_announces_sent_to_other_peers() {
    let mut fx = flip_fixture(true).await;
    let c = fx.c;

    deliver_filter(&mut fx, &[c, marker()]).await;
    send_and_deliver(&mut fx).await;
    let s0 = parent_seq(&fx);
    assert!(s0 > 0, "control: P must hold a filter from M");

    // P's announces change only M's filter to C: one announce each, to C.
    for i in 0..4u8 {
        deliver_from_parent(&mut fx, make_node_addr(0xc0 + i)).await;
        let before = sent_count(&fx);
        send_and_deliver(&mut fx).await;
        assert_eq!(
            sent_count(&fx),
            before + 1,
            "control: M must send exactly one announce, to C"
        );
    }
    assert_eq!(
        parent_seq(&fx),
        s0,
        "control: P received nothing in between"
    );

    deliver_filter(&mut fx, &[c, marker(), make_node_addr(0xd0)]).await;
    send_and_deliver(&mut fx).await;
    assert_eq!(
        parent_seq(&fx),
        s0 + 1,
        "P's next sequence must follow its last one, not count announces sent to C"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// A burst of accepted announces from one peer is stored at once but costs
/// at most one outgoing-filter recompute per tick, using the newest filter.
#[tokio::test]
async fn a_burst_of_filter_announces_from_one_peer_costs_one_recompute_per_tick() {
    let mut fx = flip_fixture(true).await;
    let (c, p) = (fx.c, fx.p);
    let markers: Vec<NodeAddr> = (0..50u8).map(|i| make_node_addr(0x20 + i)).collect();

    let r0 = fx.nodes[M].node.bloom_state.inbound_recomputes();
    for marker in &markers {
        deliver_filter(&mut fx, &[c, *marker]).await;
    }
    fx.nodes[M].node.check_bloom_state().await;
    let r1 = fx.nodes[M].node.bloom_state.inbound_recomputes();

    assert!(
        r1 - r0 <= 1,
        "50 announces from one peer must cost at most one recompute per tick, ran {}",
        r1 - r0
    );
    let sent = fx.nodes[M]
        .node
        .bloom_state
        .last_sent_filter(&p)
        .expect("M has sent a filter to P");
    assert!(
        sent.contains(&markers[49]),
        "P gets the newest stored filter"
    );
    assert!(!sent.contains(&markers[0]), "not a superseded one");
    cleanup_nodes(&mut fx.nodes).await;
}

/// The floor a new peer's sequence starts from grows by at least 256 per
/// microsecond, so a re-established peer starts above everything it was
/// sent before.
#[test]
fn the_sequence_floor_rises_by_at_least_256_per_elapsed_microsecond() {
    let node = make_node();
    let before = node.seq_floor();
    let started = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let elapsed = u64::try_from(started.elapsed().as_micros()).unwrap();
    let after = node.seq_floor();
    assert!(elapsed >= 2000, "setup: the sleep must last 2ms");
    assert!(
        after - before >= 256 * elapsed,
        "the floor rose by {} over {elapsed}us",
        after - before
    );
}

/// Two nodes started at the same moment give a new peer unrelated first
/// sequences: the floor's random offset hides uptime.
#[test]
fn a_new_peers_first_sequence_carries_a_random_offset() {
    let a = make_node();
    let b = make_node();
    let (fa, fb) = (a.seq_floor(), b.seq_floor());
    assert!(fa >= 1 && fb >= 1);
    assert!(
        fa.abs_diff(fb) > 1 << 32,
        "two fresh nodes' floors differ by their random offsets ({fa} vs {fb})"
    );
}
