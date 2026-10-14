//! Tests for lookup rate limiting and backoff.

use super::util::distinct_addr as nth;
use crate::proto::lookup::{
    LookupBackoff, LookupForwardRateLimiter, MAX_BACKOFF_ENTRIES, MAX_FORWARD_ENTRIES,
};
use crate::testutil::make_node_addr as addr;

// --- LookupBackoff tests ---

#[test]
fn test_backoff_not_suppressed_initially() {
    let backoff = LookupBackoff::new();
    assert!(!backoff.is_suppressed(&addr(1), 0));
}

#[test]
fn test_backoff_suppressed_after_failure() {
    // Backoff is opt-in; exercise the suppression path with explicit params.
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    assert!(backoff.is_suppressed(&addr(1), now));
    // Different target not affected
    assert!(!backoff.is_suppressed(&addr(2), now));
}

#[test]
fn test_backoff_cleared_on_success() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    assert!(backoff.is_suppressed(&addr(1), now));

    backoff.record_success(&addr(1));
    assert!(!backoff.is_suppressed(&addr(1), now));
}

#[test]
fn test_backoff_reset_all() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(30, 300);
    backoff.record_failure(&addr(1), now);
    backoff.record_failure(&addr(2), now);
    assert_eq!(backoff.len(), 2);

    backoff.reset_all();
    assert_eq!(backoff.len(), 0);
    assert!(!backoff.is_suppressed(&addr(1), now));
}

#[test]
fn test_backoff_exponential() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(1, 300);

    // First failure: 1s backoff
    backoff.record_failure(&addr(1), now);
    assert_eq!(backoff.failure_count(&addr(1)), 1);

    // Second failure: 2s backoff
    backoff.record_failure(&addr(1), now);
    assert_eq!(backoff.failure_count(&addr(1)), 2);

    // Third failure: 4s backoff
    backoff.record_failure(&addr(1), now);
    assert_eq!(backoff.failure_count(&addr(1)), 3);
}

#[test]
fn test_backoff_expires() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(0, 0);
    backoff.record_failure(&addr(1), now);
    // With 0s backoff, should not be suppressed
    assert!(!backoff.is_suppressed(&addr(1), now));
    // and nothing is recorded while backoff is disabled.
    assert_eq!(backoff.entry_count(), 0);
}

#[test]
fn test_backoff_capped() {
    let now = 1_000;
    let mut backoff = LookupBackoff::with_params(1, 10);

    // Record many failures
    for _ in 0..20 {
        backoff.record_failure(&addr(1), now);
    }

    // Backoff should be capped at max (10s = 10_000ms), not overflow
    let entry = backoff.entries.get(&addr(1)).unwrap();
    let remaining = entry.suppress_until_ms - now;
    assert!(remaining <= 11_000);
}

#[test]
fn with_backoff_enabled_five_thousand_distinct_failures_never_hold_more_than_max_backoff_entries() {
    let mut backoff = LookupBackoff::with_params(30, 300);
    let mut largest = 0;
    // 1 ms steps: no entry reaches its forget time, so pruning removes
    // nothing and only the bound can hold the table.
    for i in 0..5_000u32 {
        backoff.record_failure(&nth(i), 1_000 + u64::from(i));
        largest = largest.max(backoff.entry_count());
    }
    assert!(
        largest <= MAX_BACKOFF_ENTRIES,
        "the failure table grew to {largest} entries, past its bound of {MAX_BACKOFF_ENTRIES}"
    );
    assert_eq!(backoff.entry_count(), MAX_BACKOFF_ENTRIES);
}

#[test]
fn at_the_failure_table_bound_the_entry_nearest_expiry_is_evicted_and_the_newest_is_kept() {
    let mut backoff = LookupBackoff::with_params(30, 300);
    let bound = MAX_BACKOFF_ENTRIES as u32;
    for i in 0..bound {
        backoff.record_failure(&nth(i), 1_000 + u64::from(i));
    }
    assert_eq!(
        backoff.entry_count(),
        MAX_BACKOFF_ENTRIES,
        "precondition: full"
    );
    assert_eq!(
        backoff.take_evicted(),
        0,
        "precondition: nothing evicted yet"
    );

    let newest = nth(bound);
    backoff.record_failure(&newest, 1_000 + u64::from(bound));
    assert!(
        !backoff.entries.contains_key(&nth(0)),
        "the entry with the earliest window end must be evicted"
    );
    assert!(backoff.entries.contains_key(&newest));
    assert!(backoff.entries.contains_key(&nth(1)));
    assert_eq!(backoff.take_evicted(), 1);
    assert_eq!(backoff.take_evicted(), 0, "taking the count resets it");
}

#[test]
fn at_the_failure_table_bound_eviction_follows_windows_moved_by_a_repeat_failure_and_skips_targets_cleared_by_success()
 {
    let mut backoff = LookupBackoff::with_params(30, 300);
    let bound = MAX_BACKOFF_ENTRIES as u32;
    for i in 0..bound {
        backoff.record_failure(&nth(i), 1_000 + u64::from(i));
    }
    let later = 1_000 + u64::from(bound);
    // The earliest window moves later on a second failure, and the next one
    // is cleared by a success, leaving one free slot.
    backoff.record_failure(&nth(0), later);
    backoff.record_success(&nth(1));
    assert_eq!(backoff.entry_count(), MAX_BACKOFF_ENTRIES - 1);

    backoff.record_failure(&nth(bound), later);
    assert_eq!(
        backoff.take_evicted(),
        0,
        "the free slot is used before anything is evicted"
    );
    backoff.record_failure(&nth(bound + 1), later);

    assert_eq!(backoff.entry_count(), MAX_BACKOFF_ENTRIES);
    assert_eq!(backoff.take_evicted(), 1);
    assert!(
        backoff.entries.contains_key(&nth(0)),
        "a target whose window moved later keeps its entry"
    );
    assert!(
        !backoff.entries.contains_key(&nth(2)),
        "the entry with the earliest window end now is the one evicted"
    );
    assert!(backoff.entries.contains_key(&nth(3)));
    assert!(backoff.entries.contains_key(&nth(bound)));
    assert!(backoff.entries.contains_key(&nth(bound + 1)));
}

#[test]
fn with_a_zero_backoff_cap_and_a_nonzero_base_one_hundred_distinct_failures_record_nothing() {
    // Control: the same calls with a working cap record every target, so
    // the zero below is not a dead path.
    let mut enabled = LookupBackoff::with_params(30, 300);
    for i in 0..100u32 {
        enabled.record_failure(&nth(i), 1_000);
    }
    assert_eq!(enabled.entry_count(), 100);

    let mut capped_to_zero = LookupBackoff::with_params(30, 0);
    for i in 0..100u32 {
        capped_to_zero.record_failure(&nth(i), 1_000);
    }
    assert_eq!(
        capped_to_zero.entry_count(),
        0,
        "a zero cap suppresses nothing, so nothing may be recorded"
    );
    assert!(!capped_to_zero.is_enabled());
}

// --- LookupForwardRateLimiter tests ---

#[test]
fn test_forward_first_allowed() {
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), 0));
}

#[test]
fn test_forward_rapid_rate_limited() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(!limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(!limiter.should_forward(&addr(0xF0), &addr(1), now));
}

#[test]
fn test_forward_different_targets_independent() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(limiter.should_forward(&addr(0xF0), &addr(2), now));
    assert!(!limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(!limiter.should_forward(&addr(0xF0), &addr(2), now));
}

#[test]
fn test_forward_allowed_after_interval() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::with_interval_ms(100);
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), now));

    // Advance past the minimum interval.
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), now + 110));
}

#[test]
fn test_forward_cleanup_removes_old() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(limiter.should_forward(&addr(0xF0), &addr(2), now));
    assert_eq!(limiter.len(), 2);

    let future = now + 61_000;
    limiter.prune(future);
    assert_eq!(limiter.len(), 0);
}

#[test]
fn test_forward_cleanup_preserves_recent() {
    // Two peers, so the second record's front purge cannot reach the first
    // peer's entry: only the sweep at 8_500 can drop it. The record at 7_000
    // is inside the sweep interval of the one at 1_000, so it does not sweep.
    let quiet = addr(0xF0);
    let busy = addr(0xF1);
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&quiet, &addr(1), 1_000));
    assert!(limiter.should_forward(&busy, &addr(2), 7_000));
    assert_eq!(limiter.len(), 2, "precondition: no sweep before 8_500");

    limiter.prune(8_500);
    assert!(
        !limiter.holds(&quiet, &addr(1)),
        "precondition: the sweep ran and dropped the expired entry"
    );
    assert!(
        limiter.holds(&busy, &addr(2)),
        "the sweep dropped an entry still inside its interval"
    );
}

#[test]
fn test_forward_different_peers_independent() {
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(limiter.should_forward(&addr(0xF1), &addr(1), now));
    assert!(!limiter.should_forward(&addr(0xF0), &addr(1), now));
    assert!(!limiter.should_forward(&addr(0xF1), &addr(1), now));
}

#[test]
fn an_entry_is_forgotten_once_its_interval_has_passed() {
    let peer = addr(0xF0);
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&peer, &addr(1), 1_000));
    assert!(!limiter.should_forward(&peer, &addr(1), 2_999));
    assert!(limiter.should_forward(&peer, &addr(1), 3_000));
    assert_eq!(limiter.len(), 1, "the refresh replaces the old entry");

    limiter.prune(3_000 + 60_000);
    assert_eq!(limiter.len(), 0, "the sweep drops an expired entry");
    assert_eq!(limiter.queued(&peer), 0, "and its queue element");
}

#[test]
fn a_full_limiter_charges_the_heaviest_peer_and_still_records_the_newcomer() {
    let flooder = addr(0x01);
    let honest = addr(0x02);
    let target = addr(0xAA);
    let now = 1_000;
    let mut limiter = LookupForwardRateLimiter::new();
    for i in 0..MAX_FORWARD_ENTRIES as u32 {
        assert!(limiter.should_forward(&flooder, &nth(i + 1), now));
    }
    assert_eq!(limiter.len(), MAX_FORWARD_ENTRIES, "precondition: full");
    assert_eq!(
        limiter.take_evicted(),
        0,
        "precondition: nothing evicted yet"
    );

    // Key number 4097.
    assert!(limiter.should_forward(&honest, &target, now));

    assert_eq!(
        limiter.len(),
        MAX_FORWARD_ENTRIES,
        "the limiter stays at its bound"
    );
    assert_eq!(limiter.take_evicted(), 1, "the eviction is reported");
    assert!(limiter.holds(&honest, &target), "the newcomer is recorded");
    assert!(
        !limiter.holds(&flooder, &nth(1)),
        "the heaviest peer pays with its oldest entry"
    );
    assert!(limiter.holds(&flooder, &nth(2)));
    assert!(
        !limiter.should_forward(&honest, &target, now + 100),
        "the newcomer's repeat inside the interval is suppressed"
    );
}

#[test]
fn equal_stamps_are_evicted_in_insertion_order_not_target_order() {
    // Every entry carries the same stamp and the targets arrive in
    // descending address order, so the oldest by insertion is the highest
    // address and the lowest address is the newest.
    let peer = addr(0x01);
    let now = 1_000;
    let count = MAX_FORWARD_ENTRIES as u32;
    let mut limiter = LookupForwardRateLimiter::new();
    for i in 0..count {
        limiter.should_forward(&peer, &nth(count - i), now);
    }

    assert!(limiter.should_forward(&addr(0x02), &addr(0xAA), now));

    assert!(
        !limiter.holds(&peer, &nth(count)),
        "the first-inserted entry is the one evicted"
    );
    assert!(
        limiter.holds(&peer, &nth(1)),
        "the lowest target address is not evicted for being lowest"
    );
}

#[test]
fn one_target_refreshed_for_an_hour_leaves_one_entry_and_one_queue_element() {
    let peer = addr(0x01);
    let target = addr(0xAA);
    let mut limiter = LookupForwardRateLimiter::new();
    let mut now = 1_000;
    while now < 1_000 + 3_600_000 {
        assert!(limiter.should_forward(&peer, &target, now));
        assert_eq!(limiter.len(), 1);
        assert_eq!(
            limiter.queued(&peer),
            1,
            "a refreshed target left a stale element in its peer's queue"
        );
        now += 2_001;
    }
}

#[test]
fn the_heaviest_peer_is_chosen_by_live_entries_not_queue_length() {
    // `long` holds two entries but a long queue: the clock stepped back, so
    // the refreshed target's old elements sit behind an entry that has not
    // expired by the new clock and the front purge stops there. The step
    // makes a sweep due at once, so everything after it stays within one
    // sweep interval, before the next sweep rebuilds the queue. `heavy`
    // holds three entries. Everyone else holds two, and one more fills the
    // limiter.
    let long = addr(0x01);
    let heavy = addr(0x02);
    let mut limiter = LookupForwardRateLimiter::new();
    assert!(limiter.should_forward(&long, &addr(0xA1), 10_000));
    for now in [1_000, 3_000, 5_000, 7_000] {
        assert!(limiter.should_forward(&long, &addr(0xA2), now));
    }
    assert_eq!(limiter.live(&long), 2, "precondition: two entries");
    assert!(
        limiter.queued(&long) > 3,
        "precondition: a queue longer than the heaviest peer's entry count"
    );
    for t in [0xB1, 0xB2, 0xB3] {
        assert!(limiter.should_forward(&heavy, &addr(t), 7_000));
    }
    let mut i = 0u32;
    while limiter.len() + 2 <= MAX_FORWARD_ENTRIES {
        // Addresses from a range no `addr` above can collide with.
        let other = nth(0x7000_0000 + i);
        limiter.should_forward(&other, &nth(1), 7_000);
        limiter.should_forward(&other, &nth(2), 7_000);
        i += 1;
    }
    while limiter.len() < MAX_FORWARD_ENTRIES {
        limiter.should_forward(&nth(0x7F00_0000), &nth(1), 7_000);
    }
    assert_eq!(
        limiter.take_evicted(),
        0,
        "precondition: filled without eviction"
    );

    assert!(limiter.should_forward(&addr(0x03), &addr(0xCC), 7_000));

    assert_eq!(limiter.take_evicted(), 1);
    assert_eq!(
        limiter.live(&heavy),
        2,
        "the peer with the most entries pays"
    );
    assert_eq!(
        limiter.live(&long),
        2,
        "not the peer with the longest queue"
    );
}

#[test]
fn after_a_backward_clock_step_a_peers_queue_stays_within_one_sweep_of_its_entries() {
    // An entry recorded just before the clock steps back an hour reads as
    // unexpired for the whole hour. A peer then re-asks for 100 targets
    // every 2.001 s for half an hour, with the shell's prune each round.
    let peer = addr(0x01);
    let mut limiter = LookupForwardRateLimiter::new();
    let before = 10_000_000u64;
    assert!(limiter.should_forward(&peer, &addr(0xA0), before));
    limiter.prune(before);
    let mut now = before - 3_600_000;
    let targets: u32 = 100;
    for _ in 0..900u32 {
        for t in 0..targets {
            assert!(limiter.should_forward(&peer, &nth(0x1000 + t), now));
        }
        limiter.prune(now);
        now += 2_001;
    }
    let live = limiter.live(&peer);
    assert_eq!(live, targets as usize + 1, "precondition: entry count flat");
    // A sweep every 7.5 s rebuilds the queue from the map, so between sweeps
    // it gains at most the requests of four 2.001 s rounds.
    let queued = limiter.queued(&peer);
    assert!(
        queued <= live + 4 * targets as usize,
        "{queued} queue elements for {live} entries"
    );
}
