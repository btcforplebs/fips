//! A destination writes a session peer's coordinates only once the message
//! carrying them authenticates, and never files a coordinate under its own
//! address.
//!
//! Port of upstream 33bf4e3b. Before it, an established FSP message with
//! cleartext coordinates was warmed into the destination's cache by the
//! forwarding path before the session was found or the AEAD opened, so any
//! node able to deliver a datagram naming a source could place coordinates
//! for that source, without a session or a key.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets, run_tree_test,
    verify_tree_convergence,
};
use crate::proto::fsp::wire::{FSP_FLAG_CP, build_fsp_header};
use crate::proto::link::SessionDatagram;
use crate::proto::stp::{TreeCoordinate, encode_coords};

/// Two linked nodes, converged; `a` is the root, `b` its child.
struct Pair {
    nodes: Vec<TestNode>,
    a: usize,
    b: usize,
}

impl Pair {
    fn addr(&self, i: usize) -> NodeAddr {
        *self.nodes[i].node.node_addr()
    }

    fn held_at_a(&self, addr: &NodeAddr) -> Option<Vec<NodeAddr>> {
        self.nodes[self.a]
            .node
            .coord_cache()
            .get_entry(addr)
            .map(|e| e.coords().node_addrs().copied().collect())
    }

    /// Hand `A` a `SessionDatagram` from `src` to `A`, arriving over its
    /// link with `B`.
    async fn deliver_from(&mut self, src: NodeAddr, fsp_payload: Vec<u8>) {
        let (a, b) = (self.addr(self.a), self.addr(self.b));
        let encoded = SessionDatagram::new(src, a, fsp_payload).encode();
        self.nodes[self.a]
            .node
            .handle_session_datagram(&b, &encoded[1..], false)
            .await;
    }

    /// An established, CP-flagged FSP message stating `src` and `dest`
    /// coordinates in front of a ciphertext no session key opens.
    fn forged(src: &TreeCoordinate, dest: &TreeCoordinate) -> Vec<u8> {
        let mut payload = build_fsp_header(1 << 20, FSP_FLAG_CP, 20).to_vec();
        encode_coords(src, &mut payload);
        encode_coords(dest, &mut payload);
        payload.extend_from_slice(&[0xCC; 36]);
        payload
    }

    async fn establish(&mut self) {
        let (a, b) = (self.addr(self.a), self.addr(self.b));
        let b_key = self.nodes[self.b].node.identity().pubkey_full();
        self.nodes[self.a]
            .node
            .initiate_session(b, b_key)
            .await
            .expect("A starts a session with B");
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            process_available_packets(&mut self.nodes).await;
        }
        assert!(
            self.nodes[self.a]
                .node
                .get_session(&b)
                .is_some_and(|s| s.is_established())
                && self.nodes[self.b]
                    .node
                    .get_session(&a)
                    .is_some_and(|s| s.is_established()),
            "precondition: the session is established at both ends"
        );
    }
}

async fn pair() -> Pair {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    let root = *nodes[0].node.tree_state().my_coords().root_id();
    let a = if *nodes[0].node.node_addr() == root {
        0
    } else {
        1
    };
    Pair { nodes, a, b: 1 - a }
}

#[tokio::test]
async fn a_forged_message_from_a_source_with_no_session_writes_nothing() {
    let mut p = pair().await;
    let a = p.addr(p.a);
    let a_coords = p.nodes[p.a].node.tree_state().my_coords().clone();
    let stranger = make_node_addr(0x5A);
    let stranger_coords = TreeCoordinate::from_addrs(vec![stranger, a]).unwrap();
    assert!(p.nodes[p.a].node.get_session(&stranger).is_none());
    assert_eq!(p.held_at_a(&stranger), None, "precondition");
    let own_before = p.held_at_a(&a);

    p.deliver_from(stranger, Pair::forged(&stranger_coords, &a_coords))
        .await;

    assert_eq!(
        p.held_at_a(&stranger),
        None,
        "a message with no session behind it must not write its source's coordinates"
    );
    assert_eq!(
        p.held_at_a(&a),
        own_before,
        "the destination must not file a coordinate under its own address"
    );
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn an_unauthenticated_frame_claiming_the_session_peer_does_not_write_its_coordinates() {
    let mut p = pair().await;
    p.establish().await;
    let (a, b) = (p.addr(p.a), p.addr(p.b));
    let a_coords = p.nodes[p.a].node.tree_state().my_coords().clone();
    let held = p.held_at_a(&b);
    assert!(held.is_some(), "precondition: A holds B's position");
    let elsewhere = TreeCoordinate::from_addrs(vec![b, make_node_addr(0x77), a]).unwrap();

    p.deliver_from(b, Pair::forged(&elsewhere, &a_coords)).await;

    assert_eq!(
        p.held_at_a(&b),
        held,
        "a frame no key of the session opens must not write coordinates at its destination"
    );
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn an_authenticated_warmup_still_writes_the_peers_coordinates() {
    // Positive control: the write moved, it did not go away.
    let mut p = pair().await;
    p.establish().await;
    let (a, b) = (p.addr(p.a), p.addr(p.b));
    let b_now: Vec<NodeAddr> = p.nodes[p.b]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    p.nodes[p.a].node.coord_cache_mut().remove(&b);
    assert_eq!(p.held_at_a(&b), None, "precondition: A forgot B");

    p.nodes[p.b]
        .node
        .send_coords_warmup(&a)
        .await
        .expect("B sends a CoordsWarmup");
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut p.nodes).await;
    }

    assert_eq!(
        p.held_at_a(&b),
        Some(b_now),
        "an authenticated CoordsWarmup writes the peer's own coordinates"
    );
    cleanup_nodes(&mut p.nodes).await;
}
