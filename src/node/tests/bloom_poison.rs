//! Direct tests for the M1 antipoison FPR cap in handle_filter_announce.
//!
//! These tests construct a minimal Node with a single synthetic peer,
//! then call handle_filter_announce directly with crafted FilterAnnounce
//! payloads. Focused on the ingress check semantics; broader
//! filter-exchange behavior is covered by the multi-node tests in
//! bloom.rs.

use super::*;
use crate::peer::ActivePeer;
use crate::proto::bloom::FilterAnnounce;
use crate::proto::bloom::{BloomFilter, DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT};

/// Inject a synthetic active peer into the node with a known NodeAddr.
/// Returns the peer's NodeAddr.
fn inject_peer(node: &mut Node) -> NodeAddr {
    let peer_identity = make_peer_identity();
    let peer_addr = *peer_identity.node_addr();
    let peer = ActivePeer::new(peer_identity, LinkId::new(1), 0);
    node.peers.insert(peer_addr, peer);
    peer_addr
}

/// Encode a FilterAnnounce to the payload format handle_filter_announce
/// expects (msg_type byte stripped).
fn encode_payload(announce: &FilterAnnounce) -> Vec<u8> {
    let mut full = announce.encode().unwrap();
    full.remove(0); // strip msg_type byte
    full
}

#[tokio::test]
async fn test_m1_rejects_all_ones_filter_announce() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // Craft an all-ones FilterAnnounce (the observed-in-the-wild attack).
    let all_ones = BloomFilter::from_bytes(
        vec![0xFFu8; DEFAULT_FILTER_SIZE_BITS / 8],
        DEFAULT_HASH_COUNT,
    )
    .unwrap();
    let announce = FilterAnnounce::new(all_ones, 1);
    let payload = encode_payload(&announce);

    let before_fill_exceeded = node.metrics().bloom.fill_exceeded.get();
    let before_accepted = node.metrics().bloom.accepted.get();

    node.handle_filter_announce(&peer_addr, &payload).await;

    // The rejection path bumps the counter once, through the typed
    // record_reject dispatch. The legacy direct bump has been removed,
    // so the rejection-path event yields a +1 delta.
    assert_eq!(
        node.metrics().bloom.fill_exceeded.get(),
        before_fill_exceeded + 1,
        "fill_exceeded counter must increment on all-ones rejection"
    );
    assert_eq!(
        node.metrics().bloom.accepted.get(),
        before_accepted,
        "accepted counter must NOT increment on rejection"
    );

    // Peer state unchanged: no filter stored, sequence not advanced.
    let peer = node.get_peer(&peer_addr).expect("peer still present");
    assert!(
        peer.inbound_filter().is_none(),
        "peer must NOT have a stored filter after rejection"
    );
    assert_eq!(
        peer.filter_sequence(),
        0,
        "peer filter_sequence must NOT advance on rejection"
    );
}

#[tokio::test]
async fn test_m1_accepts_sub_cap_filter() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // A legitimate filter with 50 entries — fill ~0.03, FPR ~2e-8,
    // far below the 0.05 cap. Represents normal mesh traffic.
    let mut filter = BloomFilter::new();
    for i in 0..50u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = i;
        filter.insert(&NodeAddr::from_bytes(bytes));
    }
    let announce = FilterAnnounce::new(filter, 1);
    let payload = encode_payload(&announce);

    let before_fill_exceeded = node.metrics().bloom.fill_exceeded.get();
    let before_accepted = node.metrics().bloom.accepted.get();

    node.handle_filter_announce(&peer_addr, &payload).await;

    assert_eq!(
        node.metrics().bloom.fill_exceeded.get(),
        before_fill_exceeded,
        "fill_exceeded must NOT increment on legitimate sub-cap filter"
    );
    assert_eq!(
        node.metrics().bloom.accepted.get(),
        before_accepted + 1,
        "accepted must increment on legitimate filter"
    );

    // Peer state updated: filter stored, sequence advanced.
    let peer = node.get_peer(&peer_addr).expect("peer still present");
    assert!(
        peer.inbound_filter().is_some(),
        "peer must have a stored filter after acceptance"
    );
    assert_eq!(
        peer.filter_sequence(),
        1,
        "peer filter_sequence must advance to announce's sequence"
    );
}

#[tokio::test]
async fn test_m1_sequence_not_advanced_allows_recovery() {
    // Confirms the "keep prior filter, don't advance seq" rejection
    // semantics: a compliant announce after a rejected one still
    // succeeds at seq=1, because the rejected announce (also seq=1)
    // did not advance the peer's recorded sequence.
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // First announce: all-ones, rejected.
    let bad = BloomFilter::from_bytes(
        vec![0xFFu8; DEFAULT_FILTER_SIZE_BITS / 8],
        DEFAULT_HASH_COUNT,
    )
    .unwrap();
    let bad_announce = FilterAnnounce::new(bad, 1);
    node.handle_filter_announce(&peer_addr, &encode_payload(&bad_announce))
        .await;
    assert_eq!(
        node.get_peer(&peer_addr).unwrap().filter_sequence(),
        0,
        "rejected announce must not advance sequence"
    );

    // Second announce: legitimate, seq=1 (would be stale if rejection
    // had advanced the recorded sequence). Must be accepted.
    let mut good = BloomFilter::new();
    for i in 0..10u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = i;
        good.insert(&NodeAddr::from_bytes(bytes));
    }
    let good_announce = FilterAnnounce::new(good, 1);
    node.handle_filter_announce(&peer_addr, &encode_payload(&good_announce))
        .await;

    let peer = node.get_peer(&peer_addr).unwrap();
    assert!(
        peer.inbound_filter().is_some(),
        "compliant announce at same seq must be accepted after rejection"
    );
    assert_eq!(peer.filter_sequence(), 1);
    // The typed record_reject dispatch increments the counter once; the
    // legacy direct bump has been removed.
    assert_eq!(node.metrics().bloom.fill_exceeded.get(), 1);
    assert_eq!(node.metrics().bloom.accepted.get(), 1);
}

/// A filter whose leading bytes are all ones, with the smallest such prefix
/// whose FPR lands in `(lo, hi]`.
fn filter_with_fpr_in(lo: f64, hi: f64) -> BloomFilter {
    let len = DEFAULT_FILTER_SIZE_BITS / 8;
    for ones in 1..=len {
        let mut bytes = vec![0u8; len];
        bytes[..ones].fill(0xFF);
        let filter = BloomFilter::from_bytes(bytes, DEFAULT_HASH_COUNT).unwrap();
        let fpr = filter.fpr();
        if fpr > lo && fpr <= hi {
            return filter;
        }
    }
    panic!("no prefix filter with fpr in ({lo}, {hi}]");
}

/// Share of `n` distinct targets the peer's view sends to the parent fallback.
fn fallback_draw(node: &Node, peer_addr: &NodeAddr, n: u32) -> f64 {
    let peer = node.get_peer(peer_addr).unwrap();
    let hits = (0..n)
        .filter(|i| {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            bytes[15] = 0xA5;
            peer.may_reach_beyond_view(&NodeAddr::from_bytes(bytes))
        })
        .count();
    hits as f64 / n as f64
}

#[tokio::test]
async fn a_refused_announce_draws_at_most_its_own_fpr_and_a_saturated_one_draws_nothing() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);
    let cap = node.config().node.bloom.max_inbound_fpr;
    let factor = crate::node::bloom::REFUSED_FILTER_FALLBACK_FACTOR;
    const N: u32 = 4000;

    let mut clean = BloomFilter::new();
    clean.insert(&NodeAddr::from_bytes([7u8; 16]));
    node.handle_filter_announce(&peer_addr, &encode_payload(&FilterAnnounce::new(clean, 1)))
        .await;
    assert_eq!(fallback_draw(&node, &peer_addr, N), 0.0, "current filter");

    // All-ones: refused, and it must not open the ask-the-parent fallback.
    let all_ones = BloomFilter::from_bytes(
        vec![0xFFu8; DEFAULT_FILTER_SIZE_BITS / 8],
        DEFAULT_HASH_COUNT,
    )
    .unwrap();
    node.handle_filter_announce(
        &peer_addr,
        &encode_payload(&FilterAnnounce::new(all_ones, 2)),
    )
    .await;
    assert_eq!(
        node.get_peer(&peer_addr).unwrap().filter_sequence(),
        1,
        "all-ones refused"
    );
    assert_eq!(
        fallback_draw(&node, &peer_addr, N),
        0.0,
        "a saturated filter must not open the fallback"
    );

    // The worst near-cap announce a parent can send without falling out of
    // the band: it draws about its own FPR, never every miss.
    let near = filter_with_fpr_in(cap * factor * 0.9, cap * factor);
    let near_fpr = near.fpr();
    node.handle_filter_announce(&peer_addr, &encode_payload(&FilterAnnounce::new(near, 3)))
        .await;
    assert_eq!(
        node.get_peer(&peer_addr).unwrap().filter_sequence(),
        1,
        "near-cap refused too"
    );
    let draw = fallback_draw(&node, &peer_addr, N);
    assert!(
        draw > 0.0,
        "a near-cap refusal opens the fallback for what it claims"
    );
    assert!(
        draw <= near_fpr + 0.05,
        "draw {draw:.3} must be bounded by the refused filter's fpr {near_fpr:.3}"
    );
}
