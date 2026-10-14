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
    /// An entry existed, was verified and still within its verification
    /// window, so the hint was refused.
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
#[derive(Clone, Debug)]
pub struct CoordCache {
    /// NodeAddr -> coordinates mapping.
    entries: HashMap<NodeAddr, Slot>,
    /// Entries eviction may take, oldest stamp first.
    by_use: BTreeMap<(u64, u64), NodeAddr>,
    /// Entries that were live-verified when eviction reached them, by the
    /// time their verification lapses.
    parked: BTreeMap<(u64, u64), NodeAddr>,
    /// Insertion sequence for index keys.
    seq: u64,
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
            seq: 0,
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
    /// **This is the only way to write a coordinate learned off the wire, and
    /// it is deliberately the obvious name.** A hint never displaces an entry
    /// that a verified lookup established and whose verification has not yet
    /// aged out; see [`CacheEntry::is_verified`]. Conferring trust requires
    /// asking for it by name, with [`CoordCache::insert_verified`].
    pub fn insert(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) -> HintOutcome {
        self.insert_hint_with_ttl(addr, coords, current_time_ms, self.default_ttl_ms)
    }

    /// Insert or update a cache entry from a hint, with an explicit TTL.
    fn insert_hint_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        if let Some(slot) = self.entries.get_mut(&addr) {
            if slot.entry.is_verified(current_time_ms) {
                return HintOutcome::Rejected;
            }
            let changed = slot.entry.coords() != &coords;
            slot.entry.update(coords, current_time_ms, ttl_ms);
            self.refile(addr);
            return if changed {
                HintOutcome::Changed
            } else {
                HintOutcome::Unchanged
            };
        }

        // Eviction can decline to free a slot when every entry is a live
        // verified one, which is the case the hint must not be allowed to
        // force. Refuse rather than grow past the cap.
        if self.entries.len() >= self.max_entries && !self.evict_one(current_time_ms) {
            return HintOutcome::Rejected;
        }

        let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
        self.file_new(addr, entry);
        HintOutcome::Inserted
    }

    /// Insert or update a cache entry from a lookup whose proof was verified.
    ///
    /// Unconditional: a verified value displaces whatever was there, which is
    /// the point — it is how a poisoned entry gets corrected.
    pub fn insert_verified(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) {
        if let Some(slot) = self.entries.get_mut(&addr) {
            slot.entry
                .update_verified(coords, current_time_ms, self.default_ttl_ms);
            self.refile(addr);
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_one(current_time_ms);
        }

        let entry = CacheEntry::new_verified(coords, current_time_ms, self.default_ttl_ms);
        self.file_new(addr, entry);
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
        self.insert_hint_with_ttl(addr, coords, current_time_ms, ttl_ms)
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
        self.entries.retain(|_, slot| {
            if keep(&slot.entry) {
                return true;
            }
            match slot.place {
                Place::ByUse => by_use.remove(&slot.key),
                Place::Parked => parked.remove(&slot.key),
            };
            false
        });
        len_before - self.entries.len()
    }

    /// Next index key with the given first half.
    fn next_key(&mut self, first: u64) -> (u64, u64) {
        self.seq += 1;
        (first, self.seq)
    }

    /// Add a slot for a key not in the map, filed for eviction by last use.
    fn file_new(&mut self, addr: NodeAddr, entry: CacheEntry) {
        let key = self.next_key(entry.last_used());
        self.by_use.insert(key, addr);
        self.entries.insert(
            addr,
            Slot {
                entry,
                key,
                place: Place::ByUse,
            },
        );
    }

    /// Re-file an existing slot in `by_use` at its entry's current last use,
    /// after a write changed it.
    fn refile(&mut self, addr: NodeAddr) {
        let Some(slot) = self.entries.get(&addr) else {
            return;
        };
        let (old, place, used) = (slot.key, slot.place, slot.entry.last_used());
        match place {
            Place::ByUse => self.by_use.remove(&old),
            Place::Parked => self.parked.remove(&old),
        };
        let key = self.next_key(used);
        self.by_use.insert(key, addr);
        if let Some(slot) = self.entries.get_mut(&addr) {
            slot.key = key;
            slot.place = Place::ByUse;
        }
    }

    /// Remove a slot and its index key.
    fn remove_slot(&mut self, addr: &NodeAddr) -> Option<Slot> {
        let slot = self.entries.remove(addr)?;
        match slot.place {
            Place::ByUse => self.by_use.remove(&slot.key),
            Place::Parked => self.parked.remove(&slot.key),
        };
        Some(slot)
    }

    /// Evict the least recently used entry that is not live-verified.
    /// Returns whether an entry was evicted.
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
    fn evict_one(&mut self, current_time_ms: u64) -> bool {
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
            self.entries.remove(&addr);
            return true;
        }
        false
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
            cache.by_use.len() + cache.parked.len(),
            cache.entries.len(),
            "{step}: index sizes do not add up to the map"
        );
        for (addr, slot) in &cache.entries {
            let index = match slot.place {
                Place::ByUse => &cache.by_use,
                Place::Parked => &cache.parked,
            };
            assert_eq!(
                index.get(&slot.key),
                Some(addr),
                "{step}: {addr:?} is not filed under its key"
            );
        }
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
                0..=3 => {
                    let len = 2 + (state >> 4) as usize % 3;
                    let _ = cache.insert(addr, coords_of_len(addr, root, len), now);
                    "insert"
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
}
