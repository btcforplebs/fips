//! The probe loop's memory of what it learned about link addresses.
//!
//! The scan and probe loop remembers, per link address, the L2CAP PSM a peer
//! advertised and the node a completed key exchange resolved the address to.
//! Link addresses rotate and any device in radio range can present new ones,
//! so this memory is fed by untrusted input and is bounded. An address the
//! loop still depends on (a link is pooled there, or it is in the retry book)
//! is live: it is never evicted or expired and does not count toward the
//! bound, since the pool and the retry book bound the live set themselves.
//! Losing a non-live address costs one extra probe, or one dial at the
//! configured PSM, so eviction fails open.

use std::collections::{BTreeMap, HashMap};

use super::addr::BleAddr;

/// Non-live addresses the memory keeps. Live addresses (pooled or in the
/// retry book) are not counted. The honest non-live load is the older
/// aliases of connected peers, which rotate their addresses, and the
/// addresses of peers that left recently; when a newer non-live address is
/// noted beyond the bound, the oldest non-live one goes. An attacker
/// presenting new addresses can flush non-live entries, costing an honest
/// departed peer one probe at the configured PSM, but cannot grow the memory
/// or touch a live entry. No measured basis.
pub(super) const MAX_RECALLED_ADDRS: usize = 64;

/// How long a non-live address is kept after it was last noted or last
/// found live. Long enough for the node to redial a peer whose link dropped.
/// It bounds how long an attacker's addresses stay in the memory once the
/// attacker stops presenting them; while it keeps presenting new ones, the
/// size bound, not this age, is what limits it. No measured basis.
pub(super) const RECALLED_ADDR_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// One remembered address.
#[derive(Debug)]
struct Entry<V> {
    value: V,
    /// When the address was last noted, or last found live by `prune`.
    seen: tokio::time::Instant,
    /// Its key in the age order.
    seq: u64,
}

/// A bounded memory of one value per link address.
///
/// Callers pass which addresses are live with each `note` and `prune`; the
/// memory keeps no view of the pool or the retry book itself.
#[derive(Debug)]
pub(super) struct Recall<V> {
    entries: HashMap<BleAddr, Entry<V>>,
    /// Addresses by when they were last noted, oldest first. Keyed by a
    /// sequence number, never by address, which an attacker chooses.
    order: BTreeMap<u64, BleAddr>,
    next_seq: u64,
}

impl<V> Default for Recall<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
        }
    }
}

impl<V> Recall<V> {
    /// The value remembered for `addr`.
    pub(super) fn get(&self, addr: &BleAddr) -> Option<&V> {
        self.entries.get(addr).map(|e| &e.value)
    }

    /// Remember `value` for `addr`, seen at `now`, replacing any earlier
    /// value and making the address the newest. Then, while more than
    /// [`MAX_RECALLED_ADDRS`] addresses are not `live`, the oldest of them
    /// is forgotten. Returns the addresses forgotten that way, oldest first.
    pub(super) fn note(
        &mut self,
        addr: &BleAddr,
        value: V,
        now: tokio::time::Instant,
        live: impl Fn(&BleAddr) -> bool,
    ) -> Vec<BleAddr> {
        if let Some(old) = self.entries.remove(addr) {
            self.order.remove(&old.seq);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.order.insert(seq, addr.clone());
        self.entries.insert(
            addr.clone(),
            Entry {
                value,
                seen: now,
                seq,
            },
        );

        let non_live: Vec<u64> = self
            .order
            .iter()
            .filter(|(_, a)| !live(a))
            .map(|(seq, _)| *seq)
            .collect();
        let excess = non_live.len().saturating_sub(MAX_RECALLED_ADDRS);
        let mut evicted = Vec::with_capacity(excess);
        for seq in &non_live[..excess] {
            if let Some(gone) = self.order.remove(seq) {
                self.entries.remove(&gone);
                evicted.push(gone);
            }
        }
        evicted
    }

    /// Forget `addr`.
    pub(super) fn remove(&mut self, addr: &BleAddr) -> Option<V> {
        let entry = self.entries.remove(addr)?;
        self.order.remove(&entry.seq);
        Some(entry.value)
    }

    /// Forget every address that is not `live` and was last noted, or last
    /// found live, [`RECALLED_ADDR_MAX_AGE`] or more before `now`. A live
    /// address is marked seen at `now`, so its age runs from when it stopped
    /// being live rather than from its last advertisement.
    pub(super) fn prune(&mut self, now: tokio::time::Instant, live: impl Fn(&BleAddr) -> bool) {
        let entries = &mut self.entries;
        self.order.retain(|_, addr| {
            if live(addr) {
                if let Some(e) = entries.get_mut(addr) {
                    e.seen = now;
                }
                return true;
            }
            let old = entries
                .get(addr)
                .is_some_and(|e| now.saturating_duration_since(e.seen) >= RECALLED_ADDR_MAX_AGE);
            if old {
                entries.remove(addr);
            }
            !old
        });
    }

    /// How many addresses are remembered.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[path = "tests/recall.rs"]
mod tests;
