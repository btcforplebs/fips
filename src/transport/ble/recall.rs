//! The probe loop's memory of what it learned about link addresses.
//!
//! The scan and probe loop remembers, per link address, the L2CAP PSM a peer
//! advertised and the node a completed key exchange resolved the address to.
//! Link addresses rotate and any device in radio range can present new ones,
//! so this memory is fed by untrusted input.

use std::collections::HashMap;

use super::addr::BleAddr;

/// Non-live addresses the memory keeps; not enforced yet.
#[allow(dead_code)]
pub(super) const MAX_RECALLED_ADDRS: usize = 64;

/// How long a non-live address is kept; not enforced yet.
#[allow(dead_code)]
pub(super) const RECALLED_ADDR_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// A memory of one value per link address.
///
/// An address is live while the caller still depends on it: the probe loop
/// treats an address as live while a link is pooled there or it is in the
/// retry book.
#[derive(Debug)]
pub(super) struct Recall<V> {
    entries: HashMap<BleAddr, V>,
}

impl<V> Default for Recall<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<V> Recall<V> {
    /// The value remembered for `addr`.
    pub(super) fn get(&self, addr: &BleAddr) -> Option<&V> {
        self.entries.get(addr)
    }

    /// Remember `value` for `addr`, seen at `now`, replacing any earlier
    /// value. `live` reports which addresses the caller still depends on.
    pub(super) fn note(
        &mut self,
        addr: &BleAddr,
        value: V,
        _now: tokio::time::Instant,
        _live: impl Fn(&BleAddr) -> bool,
    ) {
        self.entries.insert(addr.clone(), value);
    }

    /// Forget `addr`.
    pub(super) fn remove(&mut self, addr: &BleAddr) -> Option<V> {
        self.entries.remove(addr)
    }

    /// Forget old addresses that are not live at `now`.
    pub(super) fn prune(&mut self, _now: tokio::time::Instant, _live: impl Fn(&BleAddr) -> bool) {}
}
