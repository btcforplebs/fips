//! A tree child that returns the filter we sent it is refused and keeps its
//! previous filter; honest child filters and the parent's are merged as
//! before. Port of upstream ba441c28.
//!
//! The P -- M -- C fixture comes from `bloom.rs`: P is M's parent and C is
//! M's child. A child's filter is merged into the one M sends P, so a child
//! echoing M's filter back would make M's upward filter claim everything M
//! already knows, P's own side included.

use super::bloom::{FlipFixture, M, flip_fixture};
use super::*;
use crate::proto::bloom::{BloomFilter, FilterAnnounce};

fn addrs(tag: u8, count: u16) -> Vec<NodeAddr> {
    (0..count)
        .map(|i| {
            let mut b = [tag; 16];
            b[0..2].copy_from_slice(&i.to_be_bytes());
            NodeAddr::from_bytes(b)
        })
        .collect()
}

fn filter_of(addrs: &[NodeAddr]) -> BloomFilter {
    let mut f = BloomFilter::new();
    for a in addrs {
        f.insert(a);
    }
    f
}

async fn announce(fx: &mut FlipFixture, from: NodeAddr, filter: &BloomFilter) {
    let node = &mut fx.nodes[M].node;
    let seq = node.get_peer(&from).expect("a peer").filter_sequence() + 1;
    let payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
    node.handle_filter_announce(&from, &payload[1..]).await;
}

fn stored(fx: &FlipFixture, peer: &NodeAddr) -> Option<BloomFilter> {
    fx.nodes[M].node.get_peer(peer)?.inbound_filter().cloned()
}

/// C stores its own address; P's side gets 60 synthetic entries; M sends C
/// its filter. Returns P's entries and the filter M sent C.
async fn setup(fx: &mut FlipFixture) -> (Vec<NodeAddr>, BloomFilter) {
    let (p, c) = (fx.p, fx.c);
    let own = filter_of(&[c]);
    announce(fx, c, &own).await;
    assert_eq!(stored(fx, &c), Some(own), "setup: C's own filter is stored");

    let p_side = addrs(0x5e, 60);
    let mut pf = filter_of(&p_side);
    pf.insert(&p);
    announce(fx, p, &pf).await;
    assert_eq!(stored(fx, &p), Some(pf), "setup: P's filter is stored");

    let node = &mut fx.nodes[M].node;
    let filters = node.peer_inbound_filters();
    let to_c = node
        .bloom_state
        .compute_outgoing_filters(&[c], &filters)
        .remove(&c)
        .unwrap();
    node.bloom_state.set_update_debounce_ms(0);
    node.bloom_state.mark_update_needed(c);
    node.send_filter_announce_to_peer(&c, to_c.clone())
        .await
        .expect("sent");
    assert_eq!(node.bloom_state.last_sent_filter(&c), Some(&to_c));
    assert!(
        to_c.count_ones() >= 128,
        "setup: the sent filter has real size"
    );
    (p_side, to_c)
}

#[tokio::test]
async fn a_child_returning_the_filter_we_sent_it_keeps_its_previous_filter() {
    let mut fx = flip_fixture(true).await;
    let c = fx.c;
    let (p_side, sent) = setup(&mut fx).await;
    let before = stored(&fx, &c);
    let seq = fx.nodes[M].node.get_peer(&c).unwrap().filter_sequence();

    let mut echo = sent.clone();
    echo.insert(&c);
    announce(&mut fx, c, &echo).await;

    assert_eq!(
        stored(&fx, &c),
        before,
        "a child's echo of our filter must not replace its stored filter"
    );
    assert_eq!(
        fx.nodes[M].node.get_peer(&c).unwrap().filter_sequence(),
        seq,
        "nor advance its sequence"
    );
    let filters = fx.nodes[M].node.peer_inbound_filters();
    let p = fx.p;
    let up = fx.nodes[M]
        .node
        .bloom_state
        .compute_outgoing_filters(&[p], &filters)
        .remove(&p)
        .unwrap();
    assert!(
        !p_side.iter().any(|a| up.contains(a)),
        "M's filter to P must not claim P's own side through C"
    );
    super::spanning_tree::cleanup_nodes(&mut fx.nodes).await;
}

#[tokio::test]
async fn an_honest_child_filter_is_still_merged() {
    let mut fx = flip_fixture(true).await;
    let c = fx.c;
    setup(&mut fx).await;
    let mut honest = filter_of(&addrs(0xc1, 60));
    honest.insert(&c);
    announce(&mut fx, c, &honest).await;
    assert_eq!(
        stored(&fx, &c),
        Some(honest),
        "an unrelated child filter is merged"
    );
    super::spanning_tree::cleanup_nodes(&mut fx.nodes).await;
}

#[tokio::test]
async fn a_child_with_no_stored_filter_is_not_checked() {
    // A false refusal must never drop a child's subtree outright.
    let mut fx = flip_fixture(true).await;
    let c = fx.c;
    setup(&mut fx).await;
    fx.nodes[M].node.peers.get_mut(&c).unwrap().clear_filter();
    let sent = fx.nodes[M]
        .node
        .bloom_state
        .last_sent_filter(&c)
        .cloned()
        .unwrap();
    let mut echo = sent;
    echo.insert(&c);
    announce(&mut fx, c, &echo).await;
    assert_eq!(
        stored(&fx, &c),
        Some(echo),
        "with nothing stored, the announce is merged"
    );
    super::spanning_tree::cleanup_nodes(&mut fx.nodes).await;
}
