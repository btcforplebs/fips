//! Unit tests for the `PathBroken` link quorum.

use crate::NodeAddr;
use crate::proto::fsp::quorum::{LinkQuorum, QUORUM_LINKS, QUORUM_WINDOW_MS, QuorumVerdict};

fn addr(v: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = v;
    NodeAddr::from_bytes(bytes)
}

const T0: u64 = 1_000_000;

#[test]
fn the_quorum_needs_two_links() {
    // The tests below are written for this value; a change to it should be a
    // deliberate edit here too.
    assert_eq!(QUORUM_LINKS, 2);
}

#[test]
fn one_report_stays_below_the_quorum() {
    let mut q = LinkQuorum::new();
    assert_eq!(
        q.record(addr(1), addr(0xA), T0),
        QuorumVerdict::Below { distinct: 1 }
    );
}

#[test]
fn two_distinct_links_inside_the_window_reach_the_quorum() {
    let mut q = LinkQuorum::new();
    let _ = q.record(addr(1), addr(0xA), T0);
    assert_eq!(
        q.record(addr(1), addr(0xB), T0 + QUORUM_WINDOW_MS),
        QuorumVerdict::Reached
    );
}

#[test]
fn the_same_link_repeated_never_reaches_the_quorum() {
    let mut q = LinkQuorum::new();
    for i in 0..10 {
        assert_eq!(
            q.record(addr(1), addr(0xA), T0 + i),
            QuorumVerdict::Below { distinct: 1 },
            "repeat {i} counted again"
        );
    }
}

#[test]
fn links_further_apart_than_the_window_do_not_combine() {
    let mut q = LinkQuorum::new();
    let _ = q.record(addr(1), addr(0xA), T0);
    assert_eq!(
        q.record(addr(1), addr(0xB), T0 + QUORUM_WINDOW_MS + 1),
        QuorumVerdict::Below { distinct: 1 }
    );
}

#[test]
fn a_repeat_does_not_refresh_its_links_first_seen_time() {
    let mut q = LinkQuorum::new();
    let _ = q.record(addr(1), addr(0xA), T0);
    let _ = q.record(addr(1), addr(0xA), T0 + QUORUM_WINDOW_MS);
    // Had the repeat refreshed A's time, this would combine with it.
    assert_eq!(
        q.record(addr(1), addr(0xB), T0 + QUORUM_WINDOW_MS + 1),
        QuorumVerdict::Below { distinct: 1 }
    );
}

#[test]
fn reaching_the_quorum_clears_the_destination() {
    let mut q = LinkQuorum::new();
    let _ = q.record(addr(1), addr(0xA), T0);
    assert_eq!(q.record(addr(1), addr(0xB), T0 + 1), QuorumVerdict::Reached);
    assert_eq!(q.len(), 0);
    assert_eq!(
        q.record(addr(1), addr(0xA), T0 + 2),
        QuorumVerdict::Below { distinct: 1 },
        "the next demotion must need a fresh quorum"
    );
}

#[test]
fn clear_forgets_the_reports_about_a_destination() {
    let mut q = LinkQuorum::new();
    let _ = q.record(addr(1), addr(0xA), T0);
    q.clear(&addr(1));
    assert_eq!(
        q.record(addr(1), addr(0xB), T0 + 1),
        QuorumVerdict::Below { distinct: 1 }
    );
}

#[test]
fn destinations_are_counted_separately() {
    let mut q = LinkQuorum::new();
    let _ = q.record(addr(1), addr(0xA), T0);
    assert_eq!(
        q.record(addr(2), addr(0xB), T0),
        QuorumVerdict::Below { distinct: 1 }
    );
}

#[test]
fn the_sweep_drops_destinations_with_no_live_link() {
    let mut q = LinkQuorum::new();
    for d in 0..100 {
        let _ = q.record(addr(d), addr(0xA), T0);
    }
    assert_eq!(q.len(), 100);
    // One report a window and a millisecond later sweeps the stale records.
    let _ = q.record(addr(200), addr(0xA), T0 + QUORUM_WINDOW_MS + 1);
    assert_eq!(q.len(), 1);
}
