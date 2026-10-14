//! Tests for the probe loop's bounded address memory.

use std::time::Duration;

use super::*;

/// A distinct link address per `n`.
fn addr(n: u32) -> BleAddr {
    let [a, b, c, d] = n.to_be_bytes();
    BleAddr {
        adapter: "hci0".to_string(),
        device: [0x30, 0x00, a, b, c, d],
    }
}

/// No address is live.
fn none(_: &BleAddr) -> bool {
    false
}

#[test]
fn the_recall_never_holds_more_than_its_bound_over_ten_thousand_addresses() {
    let now = tokio::time::Instant::now();
    let mut recall = Recall::default();
    for n in 0..10_000 {
        recall.note(&addr(n), n, now, none);
        assert!(
            recall.len() <= MAX_RECALLED_ADDRS,
            "{} addresses remembered after {} notes",
            recall.len(),
            n + 1
        );
    }
    assert_eq!(recall.len(), MAX_RECALLED_ADDRS);
}

#[test]
fn at_the_bound_the_oldest_non_live_address_goes_and_a_live_one_never_does() {
    let now = tokio::time::Instant::now();
    let live = |a: &BleAddr| *a == addr(0);
    let mut recall = Recall::default();
    for n in 0..=MAX_RECALLED_ADDRS as u32 {
        recall.note(&addr(n), n, now, live);
    }
    // The live address and the bound's worth of non-live ones.
    assert_eq!(recall.len(), MAX_RECALLED_ADDRS + 1);

    recall.note(&addr(1_000), 1_000, now, live);
    assert_eq!(recall.get(&addr(0)), Some(&0), "the oldest, live, is kept");
    assert_eq!(recall.get(&addr(1)), None, "the oldest non-live goes");
    assert_eq!(recall.get(&addr(2)), Some(&2));
    assert_eq!(recall.get(&addr(1_000)), Some(&1_000));
    assert_eq!(recall.len(), MAX_RECALLED_ADDRS + 1);
}

#[test]
fn a_live_set_larger_than_the_bound_is_kept_and_non_live_entries_stay_bounded() {
    let now = tokio::time::Instant::now();
    let live = |a: &BleAddr| a.device[5] < 70 && a.device[2..5] == [0, 0, 0];
    let mut recall = Recall::default();
    for n in 0..70 {
        recall.note(&addr(n), n, now, live);
    }
    for n in 0..1_000 {
        recall.note(&addr(10_000 + n), n, now, live);
    }
    for n in 0..70 {
        assert_eq!(
            recall.get(&addr(n)),
            Some(&n),
            "live address {n} was evicted"
        );
    }
    assert!(
        recall.len() - 70 <= MAX_RECALLED_ADDRS,
        "{} non-live addresses remembered",
        recall.len() - 70
    );
}

#[test]
fn prune_drops_old_non_live_addresses_and_keeps_live_ones_of_any_age() {
    let t0 = tokio::time::Instant::now();
    let live = |a: &BleAddr| *a == addr(1);
    let mut recall = Recall::default();
    recall.note(&addr(1), 1, t0, live);
    recall.note(&addr(2), 2, t0, live);
    recall.note(&addr(3), 3, t0 + Duration::from_secs(500), live);

    recall.prune(t0 + RECALLED_ADDR_MAX_AGE + Duration::from_secs(1), live);
    assert_eq!(
        recall.get(&addr(1)),
        Some(&1),
        "a live address of any age stays"
    );
    assert_eq!(recall.get(&addr(2)), None, "an old non-live address goes");
    assert_eq!(
        recall.get(&addr(3)),
        Some(&3),
        "a young non-live address stays"
    );
    assert_eq!(recall.len(), 2);
}

#[test]
fn renoting_an_address_refreshes_it() {
    let t0 = tokio::time::Instant::now();
    let mut recall = Recall::default();
    for n in 0..MAX_RECALLED_ADDRS as u32 {
        recall.note(&addr(n), n, t0, none);
    }
    let later = t0 + Duration::from_secs(500);
    recall.note(&addr(0), 100, later, none);
    assert_eq!(
        recall.len(),
        MAX_RECALLED_ADDRS,
        "renoting does not duplicate"
    );
    assert_eq!(recall.get(&addr(0)), Some(&100));

    // The renoted address is now the newest, so the next newcomer evicts
    // the one noted after it originally.
    recall.note(&addr(1_000), 1_000, later, none);
    assert_eq!(recall.get(&addr(0)), Some(&100));
    assert_eq!(recall.get(&addr(1)), None);

    // And its age runs from the renote.
    recall.prune(t0 + RECALLED_ADDR_MAX_AGE + Duration::from_secs(1), none);
    assert_eq!(recall.get(&addr(0)), Some(&100));
    assert_eq!(recall.get(&addr(2)), None);
}

#[test]
fn an_address_released_after_a_long_live_spell_is_kept_for_the_age_limit() {
    let t0 = tokio::time::Instant::now();
    let mut recall = Recall::default();
    // Noted once, at its one advertisement, then live for well past the age
    // limit, with the retry tick pruning throughout.
    recall.note(&addr(1), 1, t0, |_| true);
    let released = t0 + Duration::from_secs(2_000);
    recall.prune(released, |_| true);
    assert_eq!(recall.get(&addr(1)), Some(&1));

    // The link drops; the next tick must keep it, since its age runs from
    // when it was last live.
    recall.prune(released + Duration::from_secs(1), none);
    assert_eq!(
        recall.get(&addr(1)),
        Some(&1),
        "the address was forgotten as soon as it stopped being live"
    );
    // And it goes once the age limit has passed since then.
    recall.prune(released + RECALLED_ADDR_MAX_AGE, none);
    assert_eq!(recall.get(&addr(1)), None);
}
