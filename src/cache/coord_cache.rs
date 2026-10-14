//! Coordinate cache for routing decisions.
//!
//! Maps node addresses to their tree coordinates, enabling data packets
//! to be routed without carrying coordinates in every packet. Populated
//! by SessionSetup packets.

use alloc::collections::BTreeMap;
use std::collections::HashMap;

use super::CacheStats;
use super::entry::CacheEntry;
use crate::NodeAddr;
use crate::proto::stp::TreeCoordinate;

/// Default maximum entries in coordinate cache.
pub const DEFAULT_COORD_CACHE_SIZE: usize = 50_000;

/// Default TTL for coordinate cache entries (5 minutes in milliseconds).
pub const DEFAULT_COORD_CACHE_TTL_MS: u64 = 300_000;

/// Coordinate addresses the cache may store per entry of its configured
/// capacity, and the least weight any one entry is charged.
///
/// Bounds the main segment's coordinate storage at
/// `max_entries * ADDRS_PER_ENTRY` addresses in total (800,000 at the default
/// capacity, about 26 MB of coordinate entries) whatever depth the hints
/// claim; a frame can carry a coordinate of about seventy addresses, which
/// unbounded would be about 116 MB. It is a total, not a per-entry cap: one
/// entry deeper than this is stored and charged its depth, and one deeper than
/// the whole bound is stored alone. The probation segment is bounded by count
/// instead ([`PROBATION_SHARE_DIVISOR`]) and adds up to that many entries of
/// any depth. Honest depth follows the mesh's hop diameter, so an honest cache
/// fills by entry count first. Deep coordinates still cache and route; they
/// shrink how many entries fit. The floor makes a shallow entry cost as much as a depth-fifteen one, so
/// shallow keys do not buy faster entry turnover. No measured basis.
pub const ADDRS_PER_ENTRY: usize = 16;

/// The weight an entry holding `coords` is charged against the address bound.
fn weight_of(coords: &TreeCoordinate) -> u64 {
    coords.entries().len().max(ADDRS_PER_ENTRY) as u64
}

/// The probation segment holds `max(1, max_entries / PROBATION_SHARE_DIVISOR)`
/// entries on top of the main segment's bound (1,562 at the default capacity).
///
/// Probation is where a hint goes when its writer cannot pay for it: the frame
/// that carried it still routes, and the entry survives until this many further
/// unpaid writes arrive without a frame using it. Larger keeps an honest new
/// destination behind a drained neighbour longer; smaller lets an unpaid flood
/// displace it sooner. It is bounded by count, not weight, so its memory is at
/// most this many entries times the deepest coordinate a frame can carry. No
/// measured basis.
pub const PROBATION_SHARE_DIVISOR: usize = 32;

/// What the writer of a hint can pay toward the cache space it takes, in units
/// of weight (coordinate addresses, at least [`ADDRS_PER_ENTRY`] per entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Funding {
    /// The writer can pay at most this much. A write is paid only if its whole
    /// charge fits.
    Upto(u64),
    /// The write is not charged: it is paid for by other means, such as a
    /// handshake this node started.
    Uncharged,
}

impl Funding {
    /// Whether this funding pays a charge of `weight` in full.
    fn covers(self, weight: u64) -> bool {
        match self {
            Funding::Upto(available) => weight <= available,
            Funding::Uncharged => true,
        }
    }
}

/// The part of the cache an entry is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    /// The configured bound, where paid and verified entries live.
    Main,
    /// The allowance for unpaid new keys; it evicts only its own entries.
    Probation,
}

/// What a funded hint write did, and what it cost.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placed {
    /// The write's outcome, as for [`CoordCache::insert`].
    pub outcome: HintOutcome,
    /// The weight the write added to the main segment, which is what the
    /// writer pays. Never more than an `Upto` funding allowed.
    pub added_weight: u64,
    /// The segment the key is in after the write.
    pub segment: Segment,
    /// The funding could not pay for the write, so it did less than a paid
    /// write would: a new key went to probation, or a growing update of a main
    /// entry kept the old coordinates.
    pub unfunded: bool,
}

/// What a hint write did, which is the only place the precedence rule is
/// observable.
///
/// `#[must_use]` on purpose. A hint write can be refused, and a caller that
/// drops the outcome cannot tell a stored coordinate from a rejected one. It
/// also makes the compiler, rather than review, the thing that notices when a
/// write site is left on the hint path that should have been verified.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintOutcome {
    /// No entry existed; the hint was stored.
    Inserted,
    /// An entry existed and the hint replaced it with a different value.
    ///
    /// This is the security-interesting outcome. A destination's coordinates
    /// changing is ordinary when it moves in the tree and is also exactly what
    /// a poisoning looks like, so the two are not distinguishable here and the
    /// counter is a rate to watch rather than an alarm.
    Changed,
    /// An entry existed and the hint carried the same value.
    Unchanged,
    /// The hint was refused and the cache left as it was: the entry was
    /// verified and still within its verification window, or no room could be
    /// made in main because only live-verified entries remain (a new key from
    /// [`CoordCache::insert_funded`] goes to probation instead), or (from
    /// [`CoordCache::insert_funded`]) the writer could not pay for an update
    /// that deepens a main entry.
    Rejected,
}

/// Which eviction index holds a slot's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// In `by_use`, keyed `(stamp, seq)`: a candidate victim.
    ByUse,
    /// In `parked`, keyed `(verified_until, seq)`: live-verified when filed,
    /// so eviction skips it until its verification lapses.
    Parked,
    /// In `probation`, keyed `(stamp, seq)` like `ByUse`.
    Probation,
}

impl Place {
    /// The segment this place belongs to.
    fn segment(self) -> Segment {
        match self {
            Place::ByUse | Place::Parked => Segment::Main,
            Place::Probation => Segment::Probation,
        }
    }
}

/// One cached entry and where the eviction index files it.
#[derive(Clone, Debug)]
struct Slot {
    entry: CacheEntry,
    /// The slot's key in the index `place` names. For `ByUse` the first half
    /// is the entry's `last_used` when it was filed; the entry may have been
    /// touched since, which eviction notices and corrects lazily.
    key: (u64, u64),
    place: Place,
    /// What the entry counts against the address bound; see [`weight_of`].
    /// This is the most the entry has weighed since it entered its segment:
    /// an update that makes it shallower does not lower it, so it is never
    /// below the weight the entry holds. In main it is what the entry has
    /// been charged, so making it deep again is not charged twice; in
    /// probation it is the least a promotion pays, so a shallow rewrite
    /// cannot make a deep destination cheap to promote.
    weight: u64,
}

/// Coordinate cache for routing decisions.
///
/// Maps node addresses to their tree coordinates, enabling data packets
/// to be routed without carrying coordinates in every packet. Populated
/// by SessionSetup packets.
///
/// Eviction takes the least recently used entry that is not live-verified,
/// found through an ordered index rather than a scan of the map, so an insert
/// at capacity costs O(log n) amortised. Touching an entry does no index
/// work: the index is corrected when eviction reaches a stale key. Ties are
/// broken by a per-cache insertion sequence, never by address, because peers
/// choose addresses.
///
/// The main segment is bounded by entries and by the coordinate addresses it
/// stores ([`ADDRS_PER_ENTRY`]); a write that would exceed either evicts until
/// it fits. A hint whose writer cannot pay for it goes to a probation segment
/// on top ([`PROBATION_SHARE_DIVISOR`]), which evicts only its own entries, so
/// an unpaid write never displaces a paid one and the cache can hold
/// `max_entries + max(1, max_entries / PROBATION_SHARE_DIVISOR)` entries.
#[derive(Clone, Debug)]
pub struct CoordCache {
    /// NodeAddr -> coordinates mapping.
    entries: HashMap<NodeAddr, Slot>,
    /// Entries eviction may take, oldest stamp first.
    by_use: BTreeMap<(u64, u64), NodeAddr>,
    /// Entries that were live-verified when eviction reached them, by the
    /// time their verification lapses.
    parked: BTreeMap<(u64, u64), NodeAddr>,
    /// The probation segment's entries, oldest stamp first.
    probation: BTreeMap<(u64, u64), NodeAddr>,
    /// Insertion sequence for index keys.
    seq: u64,
    /// Sum of the main segment's entry weights.
    stored_weight: u64,
    /// Maximum number of entries.
    max_entries: usize,
    /// Default TTL for entries (milliseconds).
    default_ttl_ms: u64,
    /// Entries visited by eviction scans, so tests can measure eviction work
    /// without timing it.
    #[cfg(test)]
    eviction_examined: std::cell::Cell<u64>,
}

impl CoordCache {
    /// Create a new coordinate cache.
    pub fn new(max_entries: usize, default_ttl_ms: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1000)),
            by_use: BTreeMap::new(),
            parked: BTreeMap::new(),
            probation: BTreeMap::new(),
            seq: 0,
            stored_weight: 0,
            max_entries,
            default_ttl_ms,
            #[cfg(test)]
            eviction_examined: std::cell::Cell::new(0),
        }
    }

    /// Create a cache with default parameters.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_COORD_CACHE_SIZE, DEFAULT_COORD_CACHE_TTL_MS)
    }

    /// Get the maximum capacity.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Get the default TTL.
    pub fn default_ttl_ms(&self) -> u64 {
        self.default_ttl_ms
    }

    /// Set the default TTL.
    pub fn set_default_ttl_ms(&mut self, ttl_ms: u64) {
        self.default_ttl_ms = ttl_ms;
    }

    /// Insert or update a cache entry from an unauthenticated hint.
    ///
    /// **This and [`CoordCache::insert_funded`] are the only ways to write a
    /// coordinate learned off the wire, and this is deliberately the obvious
    /// name.** A hint never displaces an entry
    /// that a verified lookup established and whose verification has not yet
    /// aged out; see [`CacheEntry::is_verified`]. Conferring trust requires
    /// asking for it by name, with [`CoordCache::insert_verified`].
    ///
    /// The write is not charged ([`Funding::Uncharged`]); a write a link peer
    /// must pay for goes through [`CoordCache::insert_funded`].
    pub fn insert(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) -> HintOutcome {
        let ttl_ms = self.default_ttl_ms;
        self.place_hint(addr, coords, current_time_ms, ttl_ms, Funding::Uncharged)
            .outcome
    }

    /// Insert or update a cache entry from a hint its writer pays for.
    ///
    /// The charge is the weight the write adds to the main segment: a new
    /// key's weight, or what an update adds above the most the entry has been
    /// charged (nothing for an update no deeper than that). So an update that
    /// makes an entry shallower costs nothing and leaves its charge where it
    /// was, and a later update back to the old depth is free: a forged shallow
    /// rewrite cannot make the honest correction cost its writer anything. A
    /// write is paid only if `funding` covers the whole charge. Placement:
    ///
    /// - a paid new key goes to main, evicting by the main rule, or to
    ///   probation, charged nothing, if only live-verified entries remain;
    /// - an unpaid new key goes to probation, evicting only probation entries;
    /// - a paid write of a probation key promotes it to main, charged the
    ///   larger of the new weight and the most probation held, and nothing
    ///   else does (using an entry is no evidence: the first use of a new key
    ///   is the inserting frame's own routing);
    /// - a write of an expired key is placed as a new key's would be;
    /// - an unpaid update of a main entry beyond its charge keeps the old
    ///   coordinates;
    /// - an update of a probation entry is applied in place.
    ///
    /// The caller spends [`Placed::added_weight`] from the writer's budget.
    pub fn insert_funded(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        funding: Funding,
    ) -> Placed {
        let ttl_ms = self.default_ttl_ms;
        self.place_hint(addr, coords, current_time_ms, ttl_ms, funding)
    }

    /// Place a hint with an explicit TTL; see [`CoordCache::insert_funded`].
    fn place_hint(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
        funding: Funding,
    ) -> Placed {
        let weight = weight_of(&coords);
        let placed = |outcome, added_weight, segment, unfunded| Placed {
            outcome,
            added_weight,
            segment,
            unfunded,
        };
        // An expired entry is no route, so a write of its key is placed as a
        // new key's would be. Updating it instead would let an unpaid deeper
        // write keep the expired entry, which the frame's own next-hop lookup
        // then removes, leaving the frame no route.
        if self
            .entries
            .get(&addr)
            .is_some_and(|slot| slot.entry.is_expired(current_time_ms))
        {
            self.remove_slot(&addr);
        }
        let Some(slot) = self.entries.get(&addr) else {
            if !funding.covers(weight) {
                self.make_probation_room();
                let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
                self.file_new(addr, entry, weight, Segment::Probation);
                return placed(HintOutcome::Inserted, 0, Segment::Probation, true);
            }
            // Eviction can decline to free a slot when every entry is a live
            // verified one, which is the case the hint must not be allowed to
            // force. A link peer's write then goes to probation, as an unpaid
            // one would, because the budget decides placement and never
            // whether the frame routes. An uncharged write is refused.
            if !self.make_room(weight, current_time_ms) {
                if let Funding::Upto(_) = funding {
                    self.make_probation_room();
                    let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
                    self.file_new(addr, entry, weight, Segment::Probation);
                    return placed(HintOutcome::Inserted, 0, Segment::Probation, false);
                }
                return placed(HintOutcome::Rejected, 0, Segment::Main, false);
            }
            let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
            self.file_new(addr, entry, weight, Segment::Main);
            return placed(HintOutcome::Inserted, weight, Segment::Main, false);
        };

        if slot.entry.is_verified(current_time_ms) {
            return placed(HintOutcome::Rejected, 0, slot.place.segment(), false);
        }
        let outcome = if slot.entry.coords() != &coords {
            HintOutcome::Changed
        } else {
            HintOutcome::Unchanged
        };
        let (segment, old_weight) = (slot.place.segment(), slot.weight);

        match segment {
            Segment::Probation if funding.covers(weight.max(old_weight)) => {
                // Promotion: the key moves to main and pays its whole weight,
                // or stays where it is, updated, if main has no room. It is
                // charged at least the most probation held for it, so a
                // shallow rewrite cannot promote a deep destination cheaply
                // and leave its honest coordinates an unpaid growth.
                let charge = weight.max(old_weight);
                let Some(mut slot) = self.remove_slot(&addr) else {
                    return placed(HintOutcome::Rejected, 0, segment, false);
                };
                slot.entry.update(coords, current_time_ms, ttl_ms);
                if self.make_room(charge, current_time_ms) {
                    self.file_new(addr, slot.entry, charge, Segment::Main);
                    placed(outcome, charge, Segment::Main, false)
                } else {
                    self.file_new(addr, slot.entry, charge, Segment::Probation);
                    placed(outcome, 0, Segment::Probation, false)
                }
            }
            Segment::Probation => {
                self.update_in_place(addr, coords, current_time_ms, ttl_ms, weight);
                placed(outcome, 0, Segment::Probation, false)
            }
            Segment::Main if weight <= old_weight => {
                self.update_in_place(addr, coords, current_time_ms, ttl_ms, weight);
                placed(outcome, 0, Segment::Main, false)
            }
            Segment::Main if !funding.covers(weight - old_weight) => {
                placed(HintOutcome::Rejected, 0, Segment::Main, true)
            }
            Segment::Main => {
                // A growing update makes room like a new key does. The entry
                // is taken out first so it cannot be its own victim, and goes
                // back unchanged if no room can be made.
                let Some(mut slot) = self.remove_slot(&addr) else {
                    return placed(HintOutcome::Rejected, 0, segment, false);
                };
                if !self.make_room(weight, current_time_ms) {
                    self.file_new(addr, slot.entry, old_weight, Segment::Main);
                    return placed(HintOutcome::Rejected, 0, Segment::Main, false);
                }
                slot.entry.update(coords, current_time_ms, ttl_ms);
                self.file_new(addr, slot.entry, weight, Segment::Main);
                placed(outcome, weight - old_weight, Segment::Main, false)
            }
        }
    }

    /// Rewrite an existing entry's coordinates where it is, for an update
    /// that adds no weight to its segment's bound. The entry keeps the larger
    /// of its weight and the new one.
    fn update_in_place(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
        weight: u64,
    ) {
        let Some(slot) = self.entries.get_mut(&addr) else {
            return;
        };
        slot.entry.update(coords, current_time_ms, ttl_ms);
        let charged = slot.weight.max(weight);
        if slot.place.segment() == Segment::Main {
            self.stored_weight = self.stored_weight - slot.weight + charged;
        }
        slot.weight = charged;
        self.refile(addr);
    }

    /// Insert or update a cache entry from a lookup whose proof was verified.
    ///
    /// Unconditional: a verified value displaces whatever was there, which is
    /// the point — it is how a poisoned entry gets corrected. It makes room
    /// within the cache's bounds if it can, and is stored even if it cannot
    /// (only this node's own lookups write here, so the excess is bounded by
    /// them).
    pub fn insert_verified(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) {
        let weight = weight_of(&coords);
        let ttl_ms = self.default_ttl_ms;
        let entry = match self.remove_slot(&addr) {
            Some(mut slot) => {
                slot.entry.update_verified(coords, current_time_ms, ttl_ms);
                slot.entry
            }
            None => CacheEntry::new_verified(coords, current_time_ms, ttl_ms),
        };
        let _ = self.make_room(weight, current_time_ms);
        self.file_new(addr, entry, weight, Segment::Main);
    }

    /// Insert or update a verified cache entry with path MTU information.
    ///
    /// Used by discovery response handling to store the discovered path MTU
    /// alongside the target's coordinates. Verified for the same reason
    /// [`CoordCache::insert_verified`] is: the caller checked the proof.
    pub fn insert_verified_with_path_mtu(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        path_mtu: u16,
    ) {
        self.insert_verified(addr, coords, current_time_ms);
        if let Some(slot) = self.entries.get_mut(&addr) {
            slot.entry.set_path_mtu(path_mtu);
        }
    }

    /// Insert with a custom TTL.
    ///
    /// Eviction orders entries by last use, not by expiry, so an entry with a
    /// short TTL is not evicted ahead of an older one with a long TTL.
    pub fn insert_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        self.place_hint(addr, coords, current_time_ms, ttl_ms, Funding::Uncharged)
            .outcome
    }

    /// Look up coordinates for an address (without touching).
    pub fn get(&self, addr: &NodeAddr, current_time_ms: u64) -> Option<&TreeCoordinate> {
        self.entries.get(addr).and_then(|slot| {
            if slot.entry.is_expired(current_time_ms) {
                None
            } else {
                Some(slot.entry.coords())
            }
        })
    }

    /// Look up coordinates and refresh (update last_used and extend TTL).
    ///
    /// Does no index work when it only touches, so the forwarding path pays
    /// nothing for the eviction index.
    pub fn get_and_touch(
        &mut self,
        addr: &NodeAddr,
        current_time_ms: u64,
    ) -> Option<&TreeCoordinate> {
        // Check and remove if expired
        if self
            .entries
            .get(addr)
            .is_some_and(|slot| slot.entry.is_expired(current_time_ms))
        {
            self.remove_slot(addr);
            return None;
        }

        // Refresh TTL and return
        let ttl_ms = self.default_ttl_ms;
        let slot = self.entries.get_mut(addr)?;
        slot.entry.refresh(current_time_ms, ttl_ms);
        Some(slot.entry.coords())
    }

    /// Get the full cache entry.
    pub fn get_entry(&self, addr: &NodeAddr) -> Option<&CacheEntry> {
        self.entries.get(addr).map(|slot| &slot.entry)
    }

    /// Remove an entry.
    pub fn remove(&mut self, addr: &NodeAddr) -> Option<CacheEntry> {
        self.remove_slot(addr).map(|slot| slot.entry)
    }

    /// Demote an entry to an unverified hint, keeping its coordinates and TTL.
    ///
    /// The entry goes on routing, but a hint may now replace it. Returns
    /// whether an entry existed.
    pub fn demote(&mut self, addr: &NodeAddr) -> bool {
        match self.entries.get_mut(addr) {
            Some(slot) => {
                slot.entry.mark_hint();
                if slot.place == Place::Parked {
                    self.refile(*addr);
                }
                true
            }
            None => false,
        }
    }

    /// Forget the path MTU stored with an entry, keeping the entry.
    pub fn clear_path_mtu(&mut self, addr: &NodeAddr) {
        if let Some(slot) = self.entries.get_mut(addr) {
            slot.entry.clear_path_mtu();
        }
    }

    /// Check if an address is cached (and not expired).
    pub fn contains(&self, addr: &NodeAddr, current_time_ms: u64) -> bool {
        self.get(addr, current_time_ms).is_some()
    }

    /// Number of entries (including expired).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over non-expired entries.
    pub fn iter(&self, current_time_ms: u64) -> impl Iterator<Item = (&NodeAddr, &CacheEntry)> {
        self.entries
            .iter()
            .map(|(addr, slot)| (addr, &slot.entry))
            .filter(move |(_, entry)| !entry.is_expired(current_time_ms))
    }

    /// Remove all expired entries.
    pub fn purge_expired(&mut self, current_time_ms: u64) -> usize {
        self.retain_entries(|entry| !entry.is_expired(current_time_ms))
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_use.clear();
        self.parked.clear();
        self.probation.clear();
        self.stored_weight = 0;
    }

    /// Drop entries whose cached destination ancestry contains the given
    /// `NodeAddr`.
    ///
    /// Used at parent-position-change sites: when our own position in the
    /// tree changes, destinations downstream of us (whose cached coordinates
    /// embed our previous prefix) have stale path information and must be
    /// re-learned. Entries whose ancestry does not include `node_addr` are
    /// unaffected by the local position change and are retained.
    ///
    /// Returns the count of entries removed.
    pub fn invalidate_via_node(&mut self, node_addr: &NodeAddr) -> usize {
        self.retain_entries(|entry| !entry.coords().contains(node_addr))
    }

    /// Drop entries whose cached destination `root_id` differs from
    /// `current_root`.
    ///
    /// Used at root-change sites (become_root, root handover via
    /// TreeAnnounce). `find_next_hop` returns `None` for any destination
    /// whose root does not match the local root, so entries from a stale
    /// root cannot route and would otherwise occupy cache slots until
    /// TTL expiry.
    ///
    /// Returns the count of entries removed.
    pub fn invalidate_other_roots(&mut self, current_root: &NodeAddr) -> usize {
        self.retain_entries(|entry| entry.coords().root_id() == current_root)
    }

    /// Keep only the entries `keep` accepts, dropping the others' index keys.
    /// Returns the count removed.
    fn retain_entries(&mut self, mut keep: impl FnMut(&CacheEntry) -> bool) -> usize {
        let len_before = self.entries.len();
        let by_use = &mut self.by_use;
        let parked = &mut self.parked;
        let probation = &mut self.probation;
        let stored_weight = &mut self.stored_weight;
        self.entries.retain(|_, slot| {
            if keep(&slot.entry) {
                return true;
            }
            match slot.place {
                Place::ByUse => by_use.remove(&slot.key),
                Place::Parked => parked.remove(&slot.key),
                Place::Probation => probation.remove(&slot.key),
            };
            if slot.place.segment() == Segment::Main {
                *stored_weight -= slot.weight;
            }
            false
        });
        len_before - self.entries.len()
    }

    /// Next index key with the given first half.
    fn next_key(&mut self, first: u64) -> (u64, u64) {
        self.seq += 1;
        (first, self.seq)
    }

    /// Add a slot for a key not in the map, filed in `segment` for eviction by
    /// last use.
    fn file_new(&mut self, addr: NodeAddr, entry: CacheEntry, weight: u64, segment: Segment) {
        let key = self.next_key(entry.last_used());
        let place = match segment {
            Segment::Main => {
                self.stored_weight += weight;
                self.by_use.insert(key, addr);
                Place::ByUse
            }
            Segment::Probation => {
                self.probation.insert(key, addr);
                Place::Probation
            }
        };
        self.entries.insert(
            addr,
            Slot {
                entry,
                key,
                place,
                weight,
            },
        );
    }

    /// Entries in the main segment.
    fn main_len(&self) -> usize {
        self.by_use.len() + self.parked.len()
    }

    /// The most entries the probation segment holds.
    fn probation_bound(&self) -> usize {
        (self.max_entries / PROBATION_SHARE_DIVISOR).max(1)
    }

    /// Evict probation entries until one more fits. Probation holds no
    /// verified entries, so this always succeeds.
    fn make_probation_room(&mut self) {
        let bound = 2 * self.probation.len() + 1;
        let mut visited = 0;
        while self.probation.len() >= self.probation_bound() {
            let Some((stamp, addr)) = self.probation.pop_first() else {
                return;
            };
            self.note_examined();
            visited += 1;
            debug_assert!(
                visited <= bound,
                "probation eviction visited a key twice over"
            );
            let used = self.entries.get(&addr).map(|slot| slot.entry.last_used());
            match used {
                // Used by a frame since it was filed: restamp, as main does.
                Some(used) if used != stamp.0 => {
                    let key = self.next_key(used);
                    self.probation.insert(key, addr);
                    if let Some(slot) = self.entries.get_mut(&addr) {
                        slot.key = key;
                    }
                }
                _ => {
                    self.entries.remove(&addr);
                }
            }
        }
    }

    /// The most weight the cache may store.
    fn weight_bound(&self) -> u64 {
        (self.max_entries as u64).saturating_mul(ADDRS_PER_ENTRY as u64)
    }

    /// Evict until one more entry of `weight` fits both bounds. Returns
    /// whether it fits; it does not when only live-verified entries remain,
    /// and then nothing is evicted: the victims found are put back, so a
    /// refused write leaves every entry where it was.
    ///
    /// An entry heavier than the whole address bound fits once main is
    /// otherwise empty, so any depth a frame can carry can still be stored.
    fn make_room(&mut self, weight: u64, current_time_ms: u64) -> bool {
        let weight = weight.min(self.weight_bound());
        let (mut len, mut stored) = (self.main_len(), self.stored_weight);
        let mut victims = Vec::new();
        while len >= self.max_entries || stored + weight > self.weight_bound() {
            let Some(addr) = self.next_victim(current_time_ms) else {
                for addr in victims {
                    if let Some(slot) = self.entries.get(&addr) {
                        self.by_use.insert(slot.key, addr);
                    }
                }
                return false;
            };
            len -= 1;
            stored -= self.entries.get(&addr).map_or(0, |slot| slot.weight);
            victims.push(addr);
        }
        for addr in victims {
            if let Some(slot) = self.entries.remove(&addr) {
                self.stored_weight -= slot.weight;
            }
        }
        true
    }

    /// Re-file an existing slot in `by_use` at its entry's current last use,
    /// after a write changed it.
    fn refile(&mut self, addr: NodeAddr) {
        let Some(slot) = self.entries.get(&addr) else {
            return;
        };
        let (old, place, used) = (slot.key, slot.place, slot.entry.last_used());
        let key = self.next_key(used);
        let place = match place {
            Place::ByUse | Place::Parked => {
                if place == Place::Parked {
                    self.parked.remove(&old);
                } else {
                    self.by_use.remove(&old);
                }
                self.by_use.insert(key, addr);
                Place::ByUse
            }
            Place::Probation => {
                self.probation.remove(&old);
                self.probation.insert(key, addr);
                Place::Probation
            }
        };
        if let Some(slot) = self.entries.get_mut(&addr) {
            slot.key = key;
            slot.place = place;
        }
    }

    /// Remove a slot and its index key.
    fn remove_slot(&mut self, addr: &NodeAddr) -> Option<Slot> {
        let slot = self.entries.remove(addr)?;
        match slot.place {
            Place::ByUse => self.by_use.remove(&slot.key),
            Place::Parked => self.parked.remove(&slot.key),
            Place::Probation => self.probation.remove(&slot.key),
        };
        if slot.place.segment() == Segment::Main {
            self.stored_weight -= slot.weight;
        }
        Some(slot)
    }

    /// Find the least recently used entry that is not live-verified, and take
    /// its key out of `by_use`; the caller removes the entry, or files the key
    /// back under `slot.key`. Returns `None` when there is none.
    ///
    /// Restricting the victim pool is what stops a hint flood from
    /// manufacturing the empty slot the precedence rule depends on: without
    /// it, an attacker fills the cache with hints until a verified entry
    /// becomes the LRU, evicts it, and then plants into a slot that is now
    /// empty and so accepts an ordinary first write. Declining to evict is
    /// the correct outcome when every entry is live-verified; the caller
    /// refuses the hint rather than growing past the cap.
    ///
    /// Each key popped is either the victim, an entry touched since it was
    /// filed (restamped at its last use, which the touch paid for), or a
    /// live-verified entry (parked until its verification lapses). So the
    /// work is amortised over the touches and verified writes that caused it.
    fn next_victim(&mut self, current_time_ms: u64) -> Option<NodeAddr> {
        // Entries whose verification has lapsed are victims again.
        while let Some((&(until, _), _)) = self.parked.first_key_value() {
            if until >= current_time_ms {
                break;
            }
            let Some((_, addr)) = self.parked.pop_first() else {
                break;
            };
            self.note_examined();
            let used = self.entries.get(&addr).map(|s| s.entry.last_used());
            let key = self.next_key(used.unwrap_or(0));
            self.by_use.insert(key, addr);
            if let Some(slot) = self.entries.get_mut(&addr) {
                slot.key = key;
                slot.place = Place::ByUse;
            }
        }

        let bound = 2 * self.by_use.len() + 1;
        let mut visited = 0;
        while let Some((stamp, addr)) = self.by_use.pop_first() {
            self.note_examined();
            visited += 1;
            debug_assert!(visited <= bound, "eviction visited a key twice over");
            let Some(slot) = self.entries.get(&addr) else {
                debug_assert!(false, "an index key outlived its entry");
                continue;
            };
            let (used, verified, until) = (
                slot.entry.last_used(),
                slot.entry.is_verified(current_time_ms),
                slot.entry.verified_until(),
            );
            if used != stamp.0 {
                let key = self.next_key(used);
                self.by_use.insert(key, addr);
                if let Some(slot) = self.entries.get_mut(&addr) {
                    slot.key = key;
                }
                continue;
            }
            if verified {
                let key = self.next_key(until);
                self.parked.insert(key, addr);
                if let Some(slot) = self.entries.get_mut(&addr) {
                    slot.key = key;
                    slot.place = Place::Parked;
                }
                continue;
            }
            return Some(addr);
        }
        None
    }

    /// Count one entry visited by an eviction scan; a no-op outside tests.
    #[inline(always)]
    fn note_examined(&self) {
        #[cfg(test)]
        self.eviction_examined.set(self.eviction_examined.get() + 1);
    }

    /// Total entries eviction has visited since the cache was created.
    #[cfg(test)]
    pub fn eviction_examined(&self) -> u64 {
        self.eviction_examined.get()
    }

    /// The segment `addr` is in, if it is cached.
    #[cfg(test)]
    pub fn segment_of(&self, addr: &NodeAddr) -> Option<Segment> {
        self.entries.get(addr).map(|slot| slot.place.segment())
    }

    /// Entries in the probation segment.
    #[cfg(test)]
    pub fn probation_len(&self) -> usize {
        self.probation.len()
    }

    /// Total coordinate addresses stored across all entries, expired or not.
    #[cfg(test)]
    pub fn stored_addrs(&self) -> usize {
        self.entries
            .values()
            .map(|s| s.entry.coords().entries().len())
            .sum()
    }

    /// Get cache statistics.
    pub fn stats(&self, current_time_ms: u64) -> CacheStats {
        let mut expired = 0;
        let mut total_age = 0u64;

        for entry in self.entries.values().map(|slot| &slot.entry) {
            if entry.is_expired(current_time_ms) {
                expired += 1;
            }
            total_age += entry.age(current_time_ms);
        }

        CacheStats {
            entries: self.entries.len(),
            max_entries: self.max_entries,
            expired,
            avg_age_ms: if self.entries.is_empty() {
                0
            } else {
                total_age / self.entries.len() as u64
            },
        }
    }
}

impl Default for CoordCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::entry::VERIFIED_TTL_MS;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

    #[test]
    fn test_coord_cache_basic() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        let _ = cache.insert(addr, coords.clone(), 0);

        assert!(cache.contains(&addr, 0));
        assert_eq!(cache.get(&addr, 0), Some(&coords));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_coord_cache_expiry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        let _ = cache.insert(addr, coords, 0);

        assert!(cache.contains(&addr, 500));
        assert!(!cache.contains(&addr, 1500));
    }

    #[test]
    fn test_coord_cache_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        let _ = cache.insert(addr, make_coords(&[1, 2, 0]), 500);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 500).unwrap();
        assert_eq!(coords.depth(), 2);
    }

    #[test]
    fn test_coord_cache_eviction() {
        let mut cache = CoordCache::new(2, 10000);

        let addr1 = make_node_addr(1);
        let addr2 = make_node_addr(2);
        let addr3 = make_node_addr(3);

        let _ = cache.insert(addr1, make_coords(&[1, 0]), 0);
        let _ = cache.insert(addr2, make_coords(&[2, 0]), 100);

        // Touch addr2 to make it more recent
        let _ = cache.get_and_touch(&addr2, 200);

        // Insert addr3, should evict addr1 (LRU)
        let _ = cache.insert(addr3, make_coords(&[3, 0]), 300);

        assert!(!cache.contains(&addr1, 300));
        assert!(cache.contains(&addr2, 300));
        assert!(cache.contains(&addr3, 300));
    }

    #[test]
    fn test_coord_cache_evict_expired_first() {
        let mut cache = CoordCache::new(2, 100);

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        // At time 150, addr1 is expired, addr2 is not
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 150);

        // addr1 should be evicted (expired), not addr2 (LRU but not expired)
        assert!(!cache.contains(&make_node_addr(1), 150));
        assert!(cache.contains(&make_node_addr(2), 150));
        assert!(cache.contains(&make_node_addr(3), 150));
    }

    #[test]
    fn test_coord_cache_purge_expired() {
        let mut cache = CoordCache::new(100, 100);

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0); // expires at 100
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50); // expires at 150
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 200); // expires at 300

        assert_eq!(cache.len(), 3);

        let purged = cache.purge_expired(151); // both addr1 and addr2 expired

        // Entry 1 and 2 expired, entry 3 still valid
        assert_eq!(purged, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&make_node_addr(3), 151));
    }

    #[test]
    fn test_coord_cache_stats() {
        let mut cache = CoordCache::new(100, 100);

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        let stats = cache.stats(150);

        assert_eq!(stats.entries, 2);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 1); // addr1 expired
        assert!(stats.avg_age_ms > 0);
    }

    #[test]
    fn test_coord_cache_insert_with_ttl() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);

        // Should expire at 200, not the default 1000
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_insert_with_ttl_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);
        let _ = cache.insert_with_ttl(addr, make_coords(&[1, 2, 0]), 100, 300);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 100).unwrap();
        assert_eq!(coords.depth(), 2);
        // New TTL: 100 + 300 = 400
        assert!(cache.contains(&addr, 399));
        assert!(!cache.contains(&addr, 401));
    }

    #[test]
    fn test_coord_cache_get_and_touch_removes_expired() {
        let mut cache = CoordCache::new(100, 100);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        // Entry expired at time 200
        let result = cache.get_and_touch(&addr, 200);
        assert!(result.is_none());
        // Entry should be removed from the map
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_coord_cache_get_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 500);

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.created_at(), 500);
        assert_eq!(entry.expires_at(), 1500);

        assert!(cache.get_entry(&make_node_addr(99)).is_none());
    }

    #[test]
    fn test_coord_cache_remove() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(&addr);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 0);

        // Removing again returns None
        assert!(cache.remove(&addr).is_none());
    }

    #[test]
    fn test_coord_cache_clear_and_is_empty() {
        let mut cache = CoordCache::new(100, 1000);

        assert!(cache.is_empty());

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_coord_cache_default() {
        let cache = CoordCache::default();

        assert_eq!(cache.max_entries(), DEFAULT_COORD_CACHE_SIZE);
        assert_eq!(cache.default_ttl_ms(), DEFAULT_COORD_CACHE_TTL_MS);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_coord_cache_set_default_ttl() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.set_default_ttl_ms(200);
        assert_eq!(cache.default_ttl_ms(), 200);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        // New TTL applies: expires at 200
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_stats_empty() {
        let cache = CoordCache::new(100, 1000);
        let stats = cache.stats(0);

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.avg_age_ms, 0);
    }

    // ===== Surgical invalidation tests =====

    #[test]
    fn test_invalidate_via_node_at_self_depth() {
        // Entry whose own NodeAddr (depth 0) is the invalidation target.
        let mut cache = CoordCache::new(100, 1000);
        let target = make_node_addr(1);

        let _ = cache.insert(target, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        let removed = cache.invalidate_via_node(&target);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_invalidate_via_node_interior() {
        // Entry whose ancestry contains the target in the interior of the path.
        let mut cache = CoordCache::new(100, 1000);
        let dest = make_node_addr(5);
        // Path: 5 -> 3 -> 1 -> 0 (root). Target 3 appears at depth 1.
        let _ = cache.insert(dest, make_coords(&[5, 3, 1, 0]), 0);

        let removed = cache.invalidate_via_node(&make_node_addr(3));
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_invalidate_via_node_absent() {
        // Entry whose ancestry does NOT contain the target must be retained.
        let mut cache = CoordCache::new(100, 1000);
        let dest = make_node_addr(5);
        let _ = cache.insert(dest, make_coords(&[5, 3, 1, 0]), 0);

        let removed = cache.invalidate_via_node(&make_node_addr(99));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&dest, 0));
    }

    #[test]
    fn test_invalidate_via_node_empty_cache() {
        let mut cache = CoordCache::new(100, 1000);
        let removed = cache.invalidate_via_node(&make_node_addr(1));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_invalidate_other_roots_current_root_kept() {
        let mut cache = CoordCache::new(100, 1000);
        // Entries rooted at addr(0)
        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_invalidate_other_roots_different_root_dropped() {
        let mut cache = CoordCache::new(100, 1000);
        // Three entries rooted at addr(0), one rooted at addr(9)
        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 0);
        let _ = cache.insert(make_node_addr(4), make_coords(&[4, 9]), 0);

        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 3);
        assert!(!cache.contains(&make_node_addr(4), 0));
        assert!(cache.contains(&make_node_addr(1), 0));
    }

    #[test]
    fn test_invalidate_other_roots_all_match() {
        let mut cache = CoordCache::new(100, 1000);
        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_invalidate_other_roots_empty_cache() {
        let mut cache = CoordCache::new(100, 1000);
        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_hint_does_not_displace_a_live_verified_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let good = make_coords(&[1, 0]);
        let forged = make_coords(&[1, 2, 0]);

        cache.insert_verified(addr, good.clone(), 0);
        assert_eq!(cache.insert(addr, forged, 10), HintOutcome::Rejected);
        assert_eq!(
            cache.get(&addr, 10),
            Some(&good),
            "the verified value must survive the hint"
        );
    }

    #[test]
    fn a_verified_write_displaces_a_hint() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let hint = make_coords(&[1, 2, 0]);
        let good = make_coords(&[1, 0]);

        assert_eq!(cache.insert(addr, hint, 0), HintOutcome::Inserted);
        cache.insert_verified(addr, good.clone(), 10);
        assert_eq!(
            cache.get(&addr, 10),
            Some(&good),
            "a proof must be able to correct a poisoned entry"
        );
    }

    #[test]
    fn verification_ages_out_so_a_stale_verified_entry_stops_refusing_hints() {
        let mut cache = CoordCache::new(100, u64::MAX / 4);
        let addr = make_node_addr(1);
        cache.insert_verified(addr, make_coords(&[1, 0]), 0);

        // Inside the window: refused.
        assert_eq!(
            cache.insert(addr, make_coords(&[1, 2, 0]), VERIFIED_TTL_MS),
            HintOutcome::Rejected
        );
        // One millisecond past it: accepted, so a destination that genuinely
        // moved is not locked out forever by a verification nobody renews.
        let moved = make_coords(&[1, 3, 0]);
        assert_eq!(
            cache.insert(addr, moved.clone(), VERIFIED_TTL_MS + 1),
            HintOutcome::Changed
        );
        assert_eq!(cache.get(&addr, VERIFIED_TTL_MS + 1), Some(&moved));
    }

    #[test]
    fn ordinary_traffic_does_not_extend_the_verification_window() {
        // The entry TTL has to be long enough that the touches below keep the
        // entry alive; the test is about the verification clock, not expiry.
        let mut cache = CoordCache::new(100, VERIFIED_TTL_MS);
        let addr = make_node_addr(1);
        cache.insert_verified(addr, make_coords(&[1, 0]), 0);

        // Touch it repeatedly the way forwarding does, right up to the edge.
        for t in [100, 1000, 100_000, VERIFIED_TTL_MS] {
            let _ = cache.get_and_touch(&addr, t);
        }

        // The entry is alive but its verification has aged out on its own
        // clock, which is the whole point of keeping the two clocks separate.
        assert_eq!(
            cache.insert(addr, make_coords(&[1, 2, 0]), VERIFIED_TTL_MS + 1),
            HintOutcome::Changed,
            "refresh must not carry the verification forward"
        );
    }

    #[test]
    fn eviction_prefers_an_unverified_victim_over_a_verified_one() {
        let mut cache = CoordCache::new(2, 1_000_000);
        let verified = make_node_addr(1);
        let hint = make_node_addr(2);
        let newcomer = make_node_addr(3);

        // The verified entry is the least recently used, so an unrestricted
        // LRU would take it. That is exactly the eviction an attacker would
        // drive to manufacture an empty slot.
        cache.insert_verified(verified, make_coords(&[1, 0]), 0);
        assert_eq!(
            cache.insert(hint, make_coords(&[2, 0]), 100),
            HintOutcome::Inserted
        );
        assert_eq!(
            cache.insert(newcomer, make_coords(&[3, 0]), 200),
            HintOutcome::Inserted
        );

        assert!(
            cache.contains(&verified, 200),
            "the verified entry must not be the eviction victim"
        );
        assert!(
            !cache.contains(&hint, 200),
            "the unverified entry should have been evicted instead"
        );
    }

    #[test]
    fn a_cache_full_of_verified_entries_refuses_a_hint_rather_than_evicting_one() {
        let mut cache = CoordCache::new(2, 1_000_000);
        cache.insert_verified(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert_verified(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert_eq!(
            cache.insert(make_node_addr(3), make_coords(&[3, 0]), 10),
            HintOutcome::Rejected
        );
        assert!(cache.contains(&make_node_addr(1), 10));
        assert!(cache.contains(&make_node_addr(2), 10));
    }

    #[test]
    fn demote_keeps_the_value_and_lets_a_hint_replace_it() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let real = make_coords(&[1, 0]);
        cache.insert_verified_with_path_mtu(addr, real.clone(), 10, 1400);
        assert_eq!(
            cache.insert(addr, make_coords(&[1, 2, 0]), 10),
            HintOutcome::Rejected
        );

        assert!(cache.demote(&addr));

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.coords(), &real);
        assert_eq!(entry.source(), crate::cache::CoordSource::Hint);
        assert!(!entry.is_verified(10));
        assert_eq!(
            entry.path_mtu(),
            Some(1400),
            "demote leaves the path MTU to its caller"
        );
        assert_eq!(
            cache.insert(addr, make_coords(&[1, 2, 0]), 11),
            HintOutcome::Changed
        );
    }

    #[test]
    fn demote_of_an_absent_entry_reports_none() {
        let mut cache = CoordCache::new(100, 1000);
        assert!(!cache.demote(&make_node_addr(1)));
        assert!(cache.is_empty());
    }

    #[test]
    fn clear_path_mtu_keeps_the_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        cache.insert_verified_with_path_mtu(addr, make_coords(&[1, 0]), 10, 1400);

        cache.clear_path_mtu(&addr);

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.path_mtu(), None);
        assert!(entry.is_verified(10));
    }

    /// A distinct address per index, for fills larger than one byte can name.
    fn minted_addr(tag: u8, val: u32) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&val.to_le_bytes());
        bytes[15] = tag;
        NodeAddr::from_bytes(bytes)
    }

    /// Coordinates for `addr` carrying `len` addresses in all: `addr`, then
    /// `len - 2` minted ancestors, then `root`.
    fn coords_of_len(addr: NodeAddr, root: NodeAddr, len: usize) -> TreeCoordinate {
        let mut path = Vec::with_capacity(len);
        path.push(addr);
        path.extend((0..len as u32 - 2).map(|i| minted_addr(0xd0, i)));
        path.push(root);
        TreeCoordinate::from_addrs(path).unwrap()
    }

    /// The most entries one eviction may visit, averaged over many inserts, for
    /// eviction to count as cheap. Any constant independent of the cache size
    /// would do; a scan of the cache visits tens of thousands.
    const MAX_MEAN_EXAMINED_PER_INSERT: u64 = 8;

    #[test]
    fn eviction_at_capacity_examines_a_bounded_number_of_entries() {
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        let capacity = DEFAULT_COORD_CACHE_SIZE as u32;
        for i in 0..capacity {
            let addr = minted_addr(0xfe, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 2), 1_000 + u64::from(i));
        }
        assert_eq!(cache.len(), DEFAULT_COORD_CACHE_SIZE);
        assert_eq!(
            cache.eviction_examined(),
            0,
            "filling to capacity must not evict"
        );

        let fresh = 1_000u32;
        let now = 1_000 + u64::from(capacity);
        for i in 0..fresh {
            let addr = minted_addr(0xfd, i);
            assert_eq!(
                cache.insert(addr, coords_of_len(addr, root, 2), now + u64::from(i)),
                HintOutcome::Inserted
            );
        }
        assert_eq!(cache.len(), DEFAULT_COORD_CACHE_SIZE);

        let mean = cache.eviction_examined() / u64::from(fresh);
        assert!(
            mean <= MAX_MEAN_EXAMINED_PER_INSERT,
            "each insert at capacity examined {mean} entries on average, \
             against a bound of {MAX_MEAN_EXAMINED_PER_INSERT}"
        );
    }

    #[test]
    fn a_cache_filled_with_depth_seventy_hints_stays_within_its_address_budget() {
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        let capacity = DEFAULT_COORD_CACHE_SIZE as u32;
        let mut newest = None;
        for i in 0..capacity {
            let addr = minted_addr(0xfe, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 71), 1_000 + u64::from(i));
            newest = Some(addr);
        }
        let newest = newest.unwrap();
        assert!(
            cache.contains(&newest, 1_000 + u64::from(capacity)),
            "the newest hint must be stored"
        );

        let budget = DEFAULT_COORD_CACHE_SIZE * ADDRS_PER_ENTRY;
        assert!(
            cache.stored_addrs() <= budget,
            "the cache stores {} coordinate addresses in {} entries, against \
             a budget of {budget}",
            cache.stored_addrs(),
            cache.len()
        );
    }

    #[test]
    fn a_depth_five_fill_reaches_max_entries_with_nothing_evicted_early() {
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        let capacity = DEFAULT_COORD_CACHE_SIZE as u32;
        for i in 0..capacity {
            let addr = minted_addr(0xfe, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 6), 1_000 + u64::from(i));
        }
        let now = 1_000 + u64::from(capacity);
        assert_eq!(cache.len(), DEFAULT_COORD_CACHE_SIZE);
        assert!(
            cache.contains(&minted_addr(0xfe, 0), now),
            "the first entry of an honest fill must still be present"
        );
        assert_eq!(cache.eviction_examined(), 0, "nothing may be evicted");
        assert_eq!(cache.stored_addrs(), DEFAULT_COORD_CACHE_SIZE * 6);
    }

    #[test]
    fn a_touched_entry_survives_a_flood_of_new_keys() {
        let mut cache = CoordCache::new(1_000, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        for i in 0..1_000u32 {
            let addr = minted_addr(0xfe, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 2), 1_000 + u64::from(i));
        }
        let kept = minted_addr(0xfe, 0);
        let mut now = 3_000;
        for i in 0..5_000u32 {
            assert!(cache.get_and_touch(&kept, now).is_some(), "flood {i}");
            let addr = minted_addr(0xfd, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 2), now + 1);
            now += 2;
        }
        assert!(cache.contains(&kept, now));
        assert!(
            !cache.contains(&minted_addr(0xfe, 1), now),
            "an untouched entry should have been evicted by the flood"
        );
    }

    /// Assert every slot is filed under its own key in exactly the index its
    /// place names, and that the indexes hold nothing else.
    fn assert_index_matches_map(cache: &CoordCache, step: &str) {
        assert_eq!(
            cache.by_use.len() + cache.parked.len() + cache.probation.len(),
            cache.entries.len(),
            "{step}: index sizes do not add up to the map"
        );
        // A verified write is stored even when only live-verified entries
        // remain to evict, so only that can take main over its bound.
        assert!(
            cache.main_len() <= cache.max_entries
                || cache
                    .entries
                    .values()
                    .filter(|slot| slot.place.segment() == Segment::Main)
                    .all(|slot| slot.entry.source() == crate::cache::CoordSource::Verified),
            "{step}: main over its bound"
        );
        assert!(
            cache.probation.len() <= cache.probation_bound(),
            "{step}: probation over its bound"
        );
        for (addr, slot) in &cache.entries {
            let index = match slot.place {
                Place::ByUse => &cache.by_use,
                Place::Parked => &cache.parked,
                Place::Probation => &cache.probation,
            };
            assert_eq!(
                index.get(&slot.key),
                Some(addr),
                "{step}: {addr:?} is not filed under its key"
            );
        }
        // A shallower update leaves an entry's weight where it was.
        for slot in cache.entries.values() {
            let held = weight_of(slot.entry.coords());
            assert!(slot.weight >= held, "{step}: weight below held");
        }
        assert_eq!(
            cache.stored_weight,
            cache
                .entries
                .values()
                .filter(|slot| slot.place.segment() == Segment::Main)
                .map(|slot| slot.weight)
                .sum::<u64>(),
            "{step}: stored weight is not the sum over the main segment"
        );
        for (key, addr) in cache.by_use.iter() {
            let slot = cache
                .entries
                .get(addr)
                .expect("by_use names a missing entry");
            assert_eq!((slot.place, slot.key), (Place::ByUse, *key), "{step}");
        }
        for (key, addr) in cache.parked.iter() {
            let slot = cache
                .entries
                .get(addr)
                .expect("parked names a missing entry");
            assert_eq!((slot.place, slot.key), (Place::Parked, *key), "{step}");
        }
        for (key, addr) in cache.probation.iter() {
            let slot = cache
                .entries
                .get(addr)
                .expect("probation names a missing entry");
            assert_eq!((slot.place, slot.key), (Place::Probation, *key), "{step}");
        }
    }

    #[test]
    fn the_eviction_index_matches_the_map_after_every_mutation() {
        let root = make_node_addr(0);
        let other_root = make_node_addr(9);
        let via = minted_addr(0xd0, 0);
        let mut cache = CoordCache::new(8, 1_000);
        let mut now = 10_000u64;
        let mut parked_seen = false;
        let mut expiry_seen = false;
        let mut probation_seen = false;
        let mut promoted_seen = false;

        // A verified entry that eviction will reach first, and so park.
        cache.insert_verified(
            minted_addr(1, 0),
            coords_of_len(minted_addr(1, 0), root, 2),
            now,
        );
        assert_index_matches_map(&cache, "insert_verified");
        cache.insert_verified_with_path_mtu(
            minted_addr(1, 1),
            coords_of_len(minted_addr(1, 1), root, 2),
            now,
            1400,
        );
        assert_index_matches_map(&cache, "insert_verified_with_path_mtu");

        // A pseudo-random mix of every mutator, checked after each step.
        let mut state = 0x2545_f491_u32;
        for step in 0..4_000u32 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let addr = minted_addr(2, state % 24);
            now += u64::from(state % 7);
            let name = match (state >> 8) % 12 {
                0..=1 => {
                    let len = 2 + (state >> 4) as usize % 30;
                    let _ = cache.insert(addr, coords_of_len(addr, root, len), now);
                    "insert"
                }
                2..=3 => {
                    // Funding from none to enough for any write here, so new
                    // keys land in both segments and probation keys get
                    // promoted.
                    let len = 2 + (state >> 4) as usize % 30;
                    let funding = Funding::Upto(u64::from(state >> 20) % 48);
                    let placed =
                        cache.insert_funded(addr, coords_of_len(addr, root, len), now, funding);
                    probation_seen |= placed.segment == Segment::Probation;
                    promoted_seen |= placed.segment == Segment::Main
                        && placed.added_weight >= ADDRS_PER_ENTRY as u64
                        && placed.outcome != HintOutcome::Inserted;
                    "insert_funded"
                }
                4 => {
                    let had = cache.get_entry(&addr).is_some_and(|e| e.is_expired(now));
                    let _ = cache.get_and_touch(&addr, now);
                    expiry_seen |= had;
                    "get_and_touch"
                }
                5 => {
                    cache.insert_verified(addr, coords_of_len(addr, root, 2), now);
                    "insert_verified"
                }
                6 => {
                    let _ = cache.remove(&addr);
                    "remove"
                }
                7 => {
                    let _ = cache.demote(&addr);
                    "demote"
                }
                8 => {
                    let _ = cache.purge_expired(now);
                    "purge_expired"
                }
                9 => {
                    let _ = cache.insert(addr, coords_of_len(addr, other_root, 2), now);
                    let _ = cache.invalidate_other_roots(&root);
                    "invalidate_other_roots"
                }
                10 => {
                    let _ = cache.invalidate_via_node(&via);
                    "invalidate_via_node"
                }
                _ => {
                    if step % 500 == 499 {
                        cache.clear();
                        "clear"
                    } else {
                        now += 2_000;
                        "time passes"
                    }
                }
            };
            parked_seen |= !cache.parked.is_empty();
            assert_index_matches_map(&cache, &format!("step {step} ({name})"));
        }
        assert!(parked_seen, "the sequence never parked a verified entry");
        assert!(expiry_seen, "the sequence never expired an entry on touch");
        assert!(
            probation_seen,
            "the sequence never placed a key in probation"
        );
        assert!(
            promoted_seen,
            "the sequence never charged a whole key's weight on an update"
        );

        // Demote an entry that is parked, then let a parked entry's
        // verification lapse and be reached by eviction.
        cache.clear();
        cache.insert_verified(
            minted_addr(3, 0),
            coords_of_len(minted_addr(3, 0), root, 2),
            now,
        );
        cache.insert_verified(
            minted_addr(3, 1),
            coords_of_len(minted_addr(3, 1), root, 2),
            now,
        );
        for i in 0..8u32 {
            let addr = minted_addr(4, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 2), now + 1);
        }
        assert_eq!(cache.parked.len(), 2, "both verified entries were parked");
        assert!(cache.demote(&minted_addr(3, 0)));
        assert_index_matches_map(&cache, "demote of a parked entry");
        let lapsed = now + VERIFIED_TTL_MS + 1;
        let addr = minted_addr(5, 0);
        let _ = cache.insert(addr, coords_of_len(addr, root, 2), lapsed);
        assert_index_matches_map(&cache, "eviction after a verification lapsed");
    }

    #[test]
    fn an_entry_whose_verification_lapsed_becomes_evictable() {
        let mut cache = CoordCache::new(2, u64::MAX / 4);
        let root = make_node_addr(0);
        let verified = make_node_addr(1);
        cache.insert_verified(verified, make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 10);
        // Inside the window the verified entry is parked and the hint goes.
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 20);
        assert!(cache.contains(&verified, 20));
        assert!(!cache.contains(&make_node_addr(2), 20));

        // Past it, the once-verified entry is the least recently used and so
        // is the victim.
        let after = VERIFIED_TTL_MS + 1;
        let newcomer = minted_addr(0xfe, 0);
        assert_eq!(
            cache.insert(newcomer, coords_of_len(newcomer, root, 2), after),
            HintOutcome::Inserted
        );
        assert!(
            !cache.contains(&verified, after),
            "an entry whose verification lapsed must become evictable"
        );
        assert!(cache.contains(&make_node_addr(3), after));
    }

    #[test]
    fn entries_untouched_since_insertion_are_evicted_in_insertion_order() {
        let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        // One timestamp for all, and addresses whose order runs against the
        // insertion order, so only the sequence can explain the result.
        let now = 1_000;
        let addrs: Vec<NodeAddr> = (0..64u32).map(|i| minted_addr(0xfe, 1_000 - i)).collect();
        for addr in &addrs {
            let _ = cache.insert(*addr, coords_of_len(*addr, root, 2), now);
        }
        for i in 0..32u32 {
            let addr = minted_addr(0xfd, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 2), now);
        }
        for (i, addr) in addrs.iter().enumerate() {
            assert_eq!(
                cache.contains(addr, now),
                i >= 32,
                "entry {i} of the insertion order"
            );
        }
    }

    #[test]
    fn a_growing_update_evicts_others_to_stay_within_the_address_budget() {
        // Room for four entries by count and 64 addresses by weight.
        let mut cache = CoordCache::new(4, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let addrs: Vec<NodeAddr> = (0..4u32).map(|i| minted_addr(0xfe, i)).collect();
        for (i, addr) in addrs.iter().enumerate() {
            let _ = cache.insert(*addr, coords_of_len(*addr, root, 2), 1_000 + i as u64);
        }
        assert_eq!(cache.stored_weight, 64);

        // The oldest entry grows to 40 addresses: it must not be its own
        // victim, and two others must go to make room for 24 more.
        assert_eq!(
            cache.insert(addrs[0], coords_of_len(addrs[0], root, 40), 2_000),
            HintOutcome::Changed
        );
        assert_eq!(
            cache.get(&addrs[0], 2_000).map(|c| c.entries().len()),
            Some(40)
        );
        assert!(!cache.contains(&addrs[1], 2_000));
        assert!(!cache.contains(&addrs[2], 2_000));
        assert!(cache.contains(&addrs[3], 2_000));
        assert!(cache.stored_weight <= 64);
        assert_index_matches_map(&cache, "growing update");
    }

    /// Fill `cache` to its address bound with depth-five hints (weight 16
    /// each) under `root`, tagged `tag`, stamped from `start`.
    fn fill_depth_five(cache: &mut CoordCache, root: NodeAddr, tag: u8, start: u64) {
        let mut i = 0u32;
        while cache.main_len() < cache.max_entries {
            let addr = minted_addr(tag, i);
            let _ = cache.insert(addr, coords_of_len(addr, root, 6), start + u64::from(i));
            i += 1;
        }
    }

    /// The sustained rate, in weight per second, the stand-in sender of the
    /// budget tests here earns, matching the shipped per-peer hint budget. A
    /// literal so that the cache's tests do not depend on the node layer that
    /// owns the budget.
    const SENDER_WEIGHT_PER_SEC: u64 = 64 * ADDRS_PER_ENTRY as u64;

    #[test]
    fn alternating_deep_and_shallow_updates_of_one_key_evict_no_more_than_the_senders_budget_allows()
     {
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        fill_depth_five(&mut cache, root, 0xfe, 1_000);
        let mut now = 1_000 + DEFAULT_COORD_CACHE_SIZE as u64;
        let mut refill = 0u32;

        // A sender that starts empty and earns its rate per millisecond, as a
        // newly seen link peer does.
        let key = minted_addr(0xaa, 0);
        let mut milli = 0u64;
        let (mut evicted, mut paid_writes, mut growths_applied) = (0u64, 0u64, 0u64);
        let steps = 1_000u64;
        for i in 0..steps {
            now += 1;
            milli = (milli + SENDER_WEIGHT_PER_SEC).min(256 * ADDRS_PER_ENTRY as u64 * 1_000);
            let available = milli / 1_000;

            // An honest writer tops main back up to its bound in between, so
            // each growth has to evict to fit.
            while cache.main_len() < cache.max_entries
                && cache.stored_weight + ADDRS_PER_ENTRY as u64 <= cache.weight_bound()
            {
                let addr = minted_addr(0xfc, refill);
                let _ = cache.insert(addr, coords_of_len(addr, root, 6), now);
                refill += 1;
            }

            let len = if i % 2 == 0 { 3 } else { 71 };
            let in_main = cache.segment_of(&key) == Some(Segment::Main);
            let main_before = cache.main_len() as u64;
            let placed = cache.insert_funded(
                key,
                coords_of_len(key, root, len),
                now,
                Funding::Upto(available),
            );
            let joined = u64::from(!in_main && placed.segment == Segment::Main);
            evicted += main_before + joined - cache.main_len() as u64;
            assert!(placed.added_weight <= available, "write {i} overspent");
            milli -= placed.added_weight * 1_000;
            paid_writes += u64::from(placed.added_weight > 0);
            growths_applied += u64::from(len == 71 && placed.outcome == HintOutcome::Changed);
        }

        // Entries are evicted whole, so one paid write may free up to one entry
        // more than its charge covers.
        let earned = steps * SENDER_WEIGHT_PER_SEC / 1_000;
        let allowed = earned.div_ceil(ADDRS_PER_ENTRY as u64) + paid_writes;
        assert!(growths_applied > 0, "no growth was ever paid for");
        assert!(
            evicted <= allowed,
            "{steps} alternating updates evicted {evicted} main entries, against \
             an allowance of {allowed} for {earned} weight earned"
        );
    }

    #[test]
    fn growing_updates_of_many_keys_evict_no_more_than_the_senders_budget_allows() {
        // Each key is charged once for its deepest form, so one key alternating
        // evicts at most once; a sender deepening many keys pays for each.
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        fill_depth_five(&mut cache, root, 0xfe, 1_000);
        let mut now = 1_000 + DEFAULT_COORD_CACHE_SIZE as u64;
        let (mut refill, mut milli) = (0u32, 0u64);
        let (mut evicted, mut paid_writes) = (0u64, 0u64);
        let steps = 1_000u32;
        for i in 0..steps {
            now += 1;
            milli = (milli + SENDER_WEIGHT_PER_SEC).min(256 * ADDRS_PER_ENTRY as u64 * 1_000);
            let available = milli / 1_000;
            while cache.main_len() < cache.max_entries
                && cache.stored_weight + ADDRS_PER_ENTRY as u64 <= cache.weight_bound()
            {
                let addr = minted_addr(0xfc, refill);
                let _ = cache.insert(addr, coords_of_len(addr, root, 6), now);
                refill += 1;
            }

            // Deepen a key the honest fill put in main, newest first so the
            // eviction it causes does not take the next one.
            let key = minted_addr(0xfe, DEFAULT_COORD_CACHE_SIZE as u32 - 1 - i);
            if cache.segment_of(&key) != Some(Segment::Main) {
                continue;
            }
            let main_before = cache.main_len() as u64;
            let placed = cache.insert_funded(
                key,
                coords_of_len(key, root, 71),
                now,
                Funding::Upto(available),
            );
            evicted += main_before - cache.main_len() as u64;
            assert!(placed.added_weight <= available, "write {i} overspent");
            milli -= placed.added_weight * 1_000;
            paid_writes += u64::from(placed.added_weight > 0);
        }

        let earned = u64::from(steps) * SENDER_WEIGHT_PER_SEC / 1_000;
        let allowed = earned.div_ceil(ADDRS_PER_ENTRY as u64) + paid_writes;
        assert!(
            evicted <= allowed,
            "{steps} growing updates evicted {evicted} main entries, against \
             an allowance of {allowed} for {earned} weight earned"
        );
        assert!(paid_writes > 0, "no growth was ever paid for");
    }

    #[test]
    fn a_growing_update_is_charged_its_added_weight() {
        let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let placed = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(16));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.segment),
            (HintOutcome::Inserted, 16, Segment::Main)
        );
        let placed = cache.insert_funded(key, coords_of_len(key, root, 40), 20, Funding::Upto(24));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.unfunded),
            (HintOutcome::Changed, 24, false)
        );
        assert_eq!(cache.stored_weight, 40);
    }

    #[test]
    fn an_unpaid_growing_update_keeps_the_old_coordinates() {
        let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let old = coords_of_len(key, root, 2);
        let _ = cache.insert(key, old.clone(), 10);
        fill_depth_five(&mut cache, root, 0xfe, 20);
        let before = cache.len();

        let placed = cache.insert_funded(key, coords_of_len(key, root, 40), 30, Funding::Upto(23));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.unfunded),
            (HintOutcome::Rejected, 0, true)
        );
        assert_eq!(cache.get(&key, 30), Some(&old), "the old coordinates stay");
        assert_eq!(cache.len(), before, "an unpaid growth evicts nothing");
    }

    #[test]
    fn a_same_weight_rewrite_of_an_existing_key_is_never_charged() {
        let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let _ = cache.insert(key, coords_of_len(key, root, 20), 10);

        // Same weight, different value; then a shrink.
        let moved = TreeCoordinate::from_addrs(
            core::iter::once(key)
                .chain((0..18u32).map(|i| minted_addr(0xc0, i)))
                .chain(core::iter::once(root))
                .collect(),
        )
        .unwrap();
        let placed = cache.insert_funded(key, moved.clone(), 20, Funding::Upto(0));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.unfunded),
            (HintOutcome::Changed, 0, false)
        );
        assert_eq!(cache.get(&key, 20), Some(&moved));
        let shallow = coords_of_len(key, root, 3);
        let placed = cache.insert_funded(key, shallow.clone(), 30, Funding::Upto(0));
        assert_eq!((placed.added_weight, placed.unfunded), (0, false));
        assert_eq!(cache.get(&key, 30), Some(&shallow));
        assert_eq!(cache.stored_weight, 20, "a shrink keeps the entry's charge");
    }

    #[test]
    fn an_unpaid_rewrite_back_to_an_entrys_charged_depth_corrects_a_shallow_forgery() {
        let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let real = coords_of_len(key, root, 20);
        let placed = cache.insert_funded(key, real.clone(), 10, Funding::Upto(20));
        assert_eq!((placed.segment, placed.added_weight), (Segment::Main, 20));

        // A forged shallow rewrite from a peer with nothing to spend.
        let forged = coords_of_len(key, root, 3);
        let _ = cache.insert_funded(key, forged.clone(), 20, Funding::Upto(0));
        assert_eq!(cache.get(&key, 20), Some(&forged));

        // The honest coordinates, from a peer that also has nothing to spend.
        let placed = cache.insert_funded(key, real.clone(), 30, Funding::Upto(0));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.unfunded),
            (HintOutcome::Changed, 0, false)
        );
        assert_eq!(
            cache.get(&key, 30),
            Some(&real),
            "the forgery must not stick"
        );

        // Deeper than the entry was ever charged for still has to be paid.
        let placed = cache.insert_funded(key, coords_of_len(key, root, 21), 40, Funding::Upto(0));
        assert_eq!(
            (placed.outcome, placed.unfunded),
            (HintOutcome::Rejected, true)
        );
        assert_eq!(cache.get(&key, 40), Some(&real));
        assert_eq!(cache.stored_weight, 20);
    }

    #[test]
    fn a_paid_new_key_main_has_no_room_for_goes_to_probation_and_evicts_nothing() {
        // Bound: 8 entries, 128 weight. One hint, then three verified entries
        // of weight 37 (verified writes are this node's own lookups), 127 in all.
        let mut cache = CoordCache::new(8, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let hint = minted_addr(0xaa, 0);
        let _ = cache.insert(hint, coords_of_len(hint, root, 2), 10);
        for i in 0..3u32 {
            let verified = minted_addr(0xbb, i);
            cache.insert_verified(verified, coords_of_len(verified, root, 37), 20);
        }
        assert_eq!(cache.stored_weight, 127);

        // A paid new key of weight 30 cannot fit in main even with the hint
        // gone, so it goes to probation, charged nothing, and still routes.
        let key = minted_addr(0xcc, 0);
        let placed = cache.insert_funded(key, coords_of_len(key, root, 30), 30, Funding::Upto(30));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.segment),
            (HintOutcome::Inserted, 0, Segment::Probation)
        );
        assert!(cache.contains(&key, 30), "the paid write left no route");
        assert!(
            cache.contains(&hint, 30),
            "a write main had no room for, and charged nothing, evicted a hint"
        );
        assert_eq!(cache.stored_weight, 127);
        assert_index_matches_map(&cache, "placed in probation for want of room");

        // A key that fits still evicts the hint to make room.
        let small = minted_addr(0xcc, 1);
        let placed =
            cache.insert_funded(small, coords_of_len(small, root, 2), 40, Funding::Upto(16));
        assert_eq!(placed.outcome, HintOutcome::Inserted);
        assert!(!cache.contains(&hint, 40));
        assert_index_matches_map(&cache, "room made");
    }

    #[test]
    fn an_unpaid_write_evicts_only_probation_entries() {
        let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        fill_depth_five(&mut cache, root, 0xfe, 10);
        assert_eq!(cache.probation_bound(), 2);

        for i in 0..10u32 {
            let addr = minted_addr(0xaa, i);
            let placed =
                cache.insert_funded(addr, coords_of_len(addr, root, 2), 100, Funding::Upto(0));
            assert_eq!(
                (placed.outcome, placed.segment, placed.unfunded),
                (HintOutcome::Inserted, Segment::Probation, true)
            );
        }
        for i in 0..64u32 {
            assert!(cache.contains(&minted_addr(0xfe, i), 100), "main entry {i}");
        }
        assert_eq!(cache.probation_len(), 2);
        assert!(cache.contains(&minted_addr(0xaa, 9), 100));
        assert!(cache.contains(&minted_addr(0xaa, 8), 100));
        assert!(!cache.contains(&minted_addr(0xaa, 7), 100));
    }

    #[test]
    fn a_probation_entry_is_not_promoted_by_get_and_touch() {
        let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let _ = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(0));
        for t in 11..100 {
            assert!(cache.get_and_touch(&key, t).is_some());
        }
        assert_eq!(cache.segment_of(&key), Some(Segment::Probation));
    }

    #[test]
    fn a_paid_write_of_a_probation_key_promotes_it() {
        let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let _ = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(0));

        // Fifteen units do not pay for a weight-16 key; sixteen do.
        let placed = cache.insert_funded(key, coords_of_len(key, root, 2), 20, Funding::Upto(15));
        assert_eq!(placed.segment, Segment::Probation);
        let placed = cache.insert_funded(key, coords_of_len(key, root, 2), 30, Funding::Upto(16));
        assert_eq!(
            (placed.segment, placed.added_weight),
            (Segment::Main, 16),
            "a write paying the whole weight promotes the key"
        );
        assert_eq!(cache.probation_len(), 0);

        // An uncharged write promotes too.
        let other = minted_addr(0xaa, 1);
        let _ = cache.insert_funded(other, coords_of_len(other, root, 2), 40, Funding::Upto(0));
        let _ = cache.insert(other, coords_of_len(other, root, 2), 50);
        assert_eq!(cache.segment_of(&other), Some(Segment::Main));
    }

    #[test]
    fn probation_holds_its_entry_count_whatever_the_depth() {
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        let bound = DEFAULT_COORD_CACHE_SIZE / PROBATION_SHARE_DIVISOR;
        for i in 0..5_000u32 {
            let addr = minted_addr(0xaa, i);
            let _ = cache.insert_funded(
                addr,
                coords_of_len(addr, root, 71),
                1_000 + u64::from(i),
                Funding::Upto(0),
            );
        }
        assert_eq!(cache.probation_len(), bound);
        assert_eq!(cache.len(), bound, "nothing reached main");
        assert_eq!(cache.stored_weight, 0);
    }

    #[test]
    fn a_probation_entry_a_frame_used_survives_a_flood_of_unpaid_keys() {
        let mut cache = CoordCache::with_defaults();
        let root = make_node_addr(0);
        let used = minted_addr(0xab, 0);
        let idle = minted_addr(0xab, 1);
        let _ = cache.insert_funded(used, coords_of_len(used, root, 2), 1_000, Funding::Upto(0));
        let _ = cache.insert_funded(idle, coords_of_len(idle, root, 2), 1_000, Funding::Upto(0));

        // Five probation turnovers of unpaid keys, with a frame of the flow
        // using `used` every hundred of them.
        let mut now = 1_001;
        for i in 0..8_000u32 {
            if i % 100 == 0 {
                assert!(cache.get_and_touch(&used, now).is_some(), "flood {i}");
            }
            let addr = minted_addr(0xaa, i);
            let _ = cache.insert_funded(addr, coords_of_len(addr, root, 71), now, Funding::Upto(0));
            now += 1;
        }
        assert!(cache.contains(&used, now), "the entry in use must survive");
        assert!(!cache.contains(&idle, now), "the idle entry must not");
    }

    #[test]
    fn a_promotion_is_charged_at_least_the_weight_probation_held() {
        let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let real = coords_of_len(key, root, 20);
        let _ = cache.insert_funded(key, real.clone(), 10, Funding::Upto(0));
        assert_eq!(cache.segment_of(&key), Some(Segment::Probation));

        // A shallow write that pays its own weight but not the held one stays
        // in probation, where the next honest write corrects it.
        let forged = coords_of_len(key, root, 3);
        let placed = cache.insert_funded(key, forged.clone(), 20, Funding::Upto(16));
        assert_eq!(
            (placed.segment, placed.added_weight),
            (Segment::Probation, 0)
        );
        assert_eq!(cache.get(&key, 20), Some(&forged));
        let _ = cache.insert_funded(key, real.clone(), 30, Funding::Upto(0));
        assert_eq!(cache.get(&key, 30), Some(&real));

        // Paying the held weight promotes it, charged that weight, so the
        // honest rewrite after a shallow promotion is free.
        let placed = cache.insert_funded(key, forged.clone(), 40, Funding::Upto(20));
        assert_eq!((placed.segment, placed.added_weight), (Segment::Main, 20));
        assert_eq!(cache.stored_weight, 20);
        let placed = cache.insert_funded(key, real.clone(), 50, Funding::Upto(0));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.unfunded),
            (HintOutcome::Changed, 0, false)
        );
        assert_eq!(cache.get(&key, 50), Some(&real));
        assert_index_matches_map(&cache, "promoted at the held weight");
    }

    /// An expired main entry that a drained link peer's frame would deepen is
    /// replaced as a new key would be, so the frame's own next-hop lookup
    /// finds a route, as it does for a key the cache never held.
    #[test]
    fn an_unpaid_deepening_of_an_expired_entry_still_leaves_a_route() {
        let mut cache = CoordCache::new(64, 1_000);
        let root = make_node_addr(0);
        let d = minted_addr(0xdd, 0);
        let placed = cache.insert_funded(d, coords_of_len(d, root, 17), 0, Funding::Upto(17));
        assert_eq!(placed.segment, Segment::Main);

        let later = 5_000;
        let control = minted_addr(0xdd, 1);
        let _ = cache.insert_funded(
            control,
            coords_of_len(control, root, 18),
            later,
            Funding::Upto(0),
        );
        assert!(
            cache.get_and_touch(&control, later).is_some(),
            "control: a never-seen key written unpaid routes from probation"
        );
        let placed = cache.insert_funded(d, coords_of_len(d, root, 18), later, Funding::Upto(0));
        assert_eq!(
            (placed.outcome, placed.segment, placed.unfunded),
            (HintOutcome::Inserted, Segment::Probation, true)
        );
        assert!(
            cache.get_and_touch(&d, later).is_some(),
            "the frame's next-hop lookup finds no route"
        );
        assert_eq!(cache.stored_weight, 0, "the expired entry's charge is gone");
        assert_index_matches_map(&cache, "expired entry replaced");
    }

    #[test]
    fn a_hint_deeper_than_the_whole_address_bound_is_stored_alone() {
        let mut cache = CoordCache::new(1, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let d = minted_addr(0xde, 0);
        let outcome = cache.insert(d, coords_of_len(d, root, 20), 10);
        assert_eq!(outcome, HintOutcome::Inserted);
        assert!(cache.contains(&d, 10));

        // Another one replaces it, paid in full.
        let e = minted_addr(0xde, 1);
        let placed = cache.insert_funded(e, coords_of_len(e, root, 30), 20, Funding::Upto(30));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.segment),
            (HintOutcome::Inserted, 30, Segment::Main)
        );
        assert!(!cache.contains(&d, 20));
        assert_eq!(cache.stored_weight, 30);
        assert_index_matches_map(&cache, "one deep entry");
    }

    /// Main's room held by live-verified entries: four of weight 16 fill a
    /// bound of 4 entries and 64 weight.
    fn fill_verified(cache: &mut CoordCache, root: NodeAddr, count: u32, now: u64) {
        for i in 0..count {
            let addr = minted_addr(0xbb, i);
            cache.insert_verified(addr, coords_of_len(addr, root, 2), now);
        }
    }

    #[test]
    fn a_growing_update_refused_for_want_of_room_keeps_the_entry() {
        let mut cache = CoordCache::new(4, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let old = coords_of_len(key, root, 2);
        let _ = cache.insert(key, old.clone(), 10);
        fill_verified(&mut cache, root, 3, 20);
        assert_eq!(cache.stored_weight, 64);

        let placed = cache.insert_funded(key, coords_of_len(key, root, 20), 30, Funding::Upto(100));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.unfunded),
            (HintOutcome::Rejected, 0, false)
        );
        assert_eq!(cache.get(&key, 30), Some(&old), "the entry stays as it was");
        assert_eq!(cache.segment_of(&key), Some(Segment::Main));
        assert_eq!(cache.stored_weight, 64);
        assert_index_matches_map(&cache, "growing update refused");
    }

    #[test]
    fn a_promotion_refused_for_want_of_room_keeps_the_key_in_probation() {
        let mut cache = CoordCache::new(4, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let _ = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(0));
        fill_verified(&mut cache, root, 4, 20);

        let new = coords_of_len(key, root, 3);
        let placed = cache.insert_funded(key, new.clone(), 30, Funding::Upto(100));
        assert_eq!(
            (placed.outcome, placed.added_weight, placed.segment),
            (HintOutcome::Changed, 0, Segment::Probation)
        );
        assert_eq!(cache.get(&key, 30), Some(&new), "the key stays, updated");
        assert_eq!(cache.segment_of(&key), Some(Segment::Probation));
        assert_index_matches_map(&cache, "promotion refused");
    }

    #[test]
    fn a_shallow_rewrite_in_probation_does_not_lower_the_weight_a_promotion_pays() {
        let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
        let root = make_node_addr(0);
        let key = minted_addr(0xaa, 0);
        let real = coords_of_len(key, root, 20);
        let _ = cache.insert_funded(key, real.clone(), 10, Funding::Upto(0));

        // A peer with nothing to spend rewrites it shallow, then pays 16.
        let forged = coords_of_len(key, root, 3);
        let _ = cache.insert_funded(key, forged.clone(), 20, Funding::Upto(0));
        let placed = cache.insert_funded(key, forged.clone(), 30, Funding::Upto(16));
        assert_eq!(
            placed.segment,
            Segment::Probation,
            "promoted below the held depth"
        );

        // The honest coordinates through a drained hub still correct it.
        let _ = cache.insert_funded(key, real.clone(), 40, Funding::Upto(0));
        assert_eq!(cache.get(&key, 40), Some(&real));
        assert_index_matches_map(&cache, "probation charge kept");
    }
}
