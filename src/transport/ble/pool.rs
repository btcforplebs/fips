//! BLE connection pool with priority eviction.
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum and prioritizes static (configured)
//! peers over dynamically discovered ones.
//!
//! ## Two channels to one address
//!
//! Two nodes that dial each other at once each end up with two L2CAP
//! channels at the same address: the one it dialled and the one the peer
//! dialled. Before the XX handshake neither end has an input the other
//! shares that could pick one: direction is mirrored, and BLE addresses
//! rotate and are not always known to their owner. So the pool keeps a
//! short list of channels per address. The second one is *held* beside the
//! first until the handshake names the peer, and the node then *settles*
//! the address, telling the pool which direction to keep. Both ends
//! compute that from node order, so both keep the same channel.
//!
//! A channel the pool lets go on purpose is *retired*, not dropped: it
//! takes no new frames, its writer finishes what is already queued, and
//! its reader keeps delivering until the peer closes it or the driver's
//! linger ends. The decisions here are pure ([`admit`], [`settle`]); the
//! driver in `mod.rs` spawns the tasks and the linger timers.

use std::collections::HashMap;

use tokio::task::JoinHandle;

use crate::transport::{TransportAddr, TransportError};

use super::addr::BleAddr;

/// How many frames may be queued for one BLE connection before sends to it
/// fail. Shallower than the IP transports': a BLE link carries a fraction of
/// their throughput, so a queue of the same depth would represent seconds of
/// backlog rather than a burst.
pub const SEND_QUEUE_DEPTH: usize = 16;

/// Most channels held at one address.
///
/// One side has at most two concurrent dials to an address (the scan
/// loop's probe and the node's own dial), and keeps at most one of them
/// (see [`admit`]), so a conforming peer leaves at most one outbound and
/// two inbound channels here.
pub const MAX_HELD: usize = 3;

/// A single BLE connection in the pool.
pub struct BleConnection<S> {
    /// The L2CAP stream for this connection.
    pub stream: S,
    /// Frames queued for the writer task. Sending is an enqueue, never a
    /// write: the write is awaited only by `send_task`, so no caller can be
    /// held by a peer that has stopped draining — and, on this transport in
    /// particular, no caller holds the pool lock while it happens.
    pub send_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Writer task for this connection.
    pub send_task: Option<JoinHandle<()>>,
    /// Background receive task handle.
    pub recv_task: Option<JoinHandle<()>>,
    /// Negotiated L2CAP send MTU.
    pub send_mtu: u16,
    /// Negotiated L2CAP receive MTU.
    pub recv_mtu: u16,
    /// When the connection was established.
    pub established_at: tokio::time::Instant,
    /// Whether this is a static (configured) peer.
    pub is_static: bool,
    /// Parsed remote address.
    pub addr: BleAddr,
    /// Whether this side dialled the channel.
    pub outbound: bool,
    /// Tells this channel apart from others at its address. The channel's
    /// own tasks remove it by `(address, id)`, so the end of one channel
    /// cannot take another at the same address with it.
    pub id: u64,
}

impl<S> BleConnection<S> {
    /// Effective MTU for this connection: min(send, recv).
    pub fn effective_mtu(&self) -> u16 {
        self.send_mtu.min(self.recv_mtu)
    }

    /// Stop the channel taking new frames.
    ///
    /// Swapping in a sender whose receiver is already gone drops the only
    /// stored sender of the writer's queue, so the writer task writes every
    /// frame already queued and then ends. The receive task is untouched.
    fn retire(&mut self) {
        let (closed, _) = tokio::sync::mpsc::channel(1);
        self.send_tx = closed;
    }
}

impl<S> Drop for BleConnection<S> {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
        if let Some(task) = self.send_task.take() {
            task.abort();
        }
    }
}

/// What the pool does with a channel offered at an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The address had no channel: this one is its link.
    Admit,
    /// Kept beside the channels already held, until the address is settled.
    Hold,
    /// Kept, and every channel already held is retired.
    Replace,
    /// Retired on arrival.
    Retire,
}

/// Decide what to do with a channel offered at an address.
///
/// `held_out` and `held_in` count the channels already held there by
/// direction, `verdict` is the direction a settlement chose to keep, if
/// one has, and `outbound` is the newcomer's direction. The rules, first
/// match wins:
///
/// 1. Nothing held: admit. A lone link is always admitted, whichever side
///    dialled it.
/// 2. [`MAX_HELD`] channels held: retire the newcomer.
/// 3. An outbound newcomer where an outbound is held: retire the newcomer.
///    This side dialled twice, so it alone decides; the peer holds both as
///    inbound and follows when it reads end-of-stream.
/// 4. An inbound newcomer where an inbound is held: hold it. The peer
///    dialled twice and decides by rule 3; this side never retires one of
///    these itself. If both sides decided they could pick different
///    channels, and if neither did both would stay for the life of the
///    link.
/// 5. Otherwise the newcomer is opposite in direction to every held
///    channel. With no verdict, hold it; with a verdict for its direction,
///    replace the held channels with it; with a verdict against it, retire
///    it.
pub fn admit(held_out: usize, held_in: usize, verdict: Option<bool>, outbound: bool) -> Admission {
    if held_out + held_in == 0 {
        return Admission::Admit;
    }
    if held_out + held_in >= MAX_HELD {
        return Admission::Retire;
    }
    if outbound && held_out > 0 {
        return Admission::Retire;
    }
    if !outbound && held_in > 0 {
        return Admission::Hold;
    }
    match verdict {
        None => Admission::Hold,
        Some(keep_outbound) if keep_outbound == outbound => Admission::Replace,
        Some(_) => Admission::Retire,
    }
}

/// Decide which held channels a settlement retires.
///
/// `held` lists each held channel's `(id, outbound)`. If a channel of the
/// kept direction is held, every channel of the other direction goes.
/// Otherwise none does: the verdict waits for the winning channel to
/// arrive, so a side never retires its only link.
pub fn settle(held: &[(u64, bool)], keep_outbound: bool) -> Vec<u64> {
    if !held.iter().any(|&(_, outbound)| outbound == keep_outbound) {
        return Vec::new();
    }
    held.iter()
        .filter(|&&(_, outbound)| outbound != keep_outbound)
        .map(|&(id, _)| id)
        .collect()
}

/// The outcome of offering a channel to the pool.
#[derive(Debug, PartialEq, Eq)]
pub struct Admitted {
    /// What happened to the channel offered.
    pub admission: Admission,
    /// An address evicted to make room, if one was.
    pub evicted: Option<TransportAddr>,
    /// Ids of the channels at this address the offer retired, the newcomer
    /// included when it was itself retired.
    pub retired: Vec<u64>,
}

/// The channels at one address.
struct Slot<S> {
    /// Held channels, oldest first. Sends use the first. Never empty: the
    /// slot goes when its last held channel does.
    held: Vec<BleConnection<S>>,
    /// The direction a settlement chose to keep, once one has.
    verdict: Option<bool>,
}

/// Connection pool managing BLE connections with priority eviction.
///
/// Capacity counts addresses, not channels: the extra channels held during
/// a race, and the retiring ones, are the same device on the same link.
pub struct ConnectionPool<S> {
    slots: HashMap<TransportAddr, Slot<S>>,
    /// Retired channels still writing out their queue or lingering for the
    /// peer's last frames.
    retiring: Vec<(TransportAddr, BleConnection<S>)>,
    max_connections: usize,
}

impl<S> ConnectionPool<S> {
    /// Create a new pool with the given maximum capacity.
    pub fn new(max_connections: usize) -> Self {
        Self {
            slots: HashMap::new(),
            retiring: Vec::new(),
            max_connections,
        }
    }

    /// Get the number of linked addresses.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Check if the pool is at capacity.
    pub fn is_full(&self) -> bool {
        self.slots.len() >= self.max_connections
    }

    /// Get the maximum pool capacity.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The channel sends to `addr` use: the oldest held there.
    pub fn get(&self, addr: &TransportAddr) -> Option<&BleConnection<S>> {
        self.slots.get(addr).and_then(|slot| slot.held.first())
    }

    /// Check if a connection exists for the given address.
    pub fn contains(&self, addr: &TransportAddr) -> bool {
        self.slots.contains_key(addr)
    }

    /// `(id, outbound)` of each channel held at `addr`, oldest first.
    pub fn held(&self, addr: &TransportAddr) -> Vec<(u64, bool)> {
        self.slots
            .get(addr)
            .map(|slot| slot.held.iter().map(|c| (c.id, c.outbound)).collect())
            .unwrap_or_default()
    }

    /// Ids of the channels retiring at `addr`.
    pub fn retiring(&self, addr: &TransportAddr) -> Vec<u64> {
        self.retiring
            .iter()
            .filter(|(a, _)| a == addr)
            .map(|(_, c)| c.id)
            .collect()
    }

    /// Offer a channel at `addr`, evicting another address if the pool is
    /// full and this address is new.
    ///
    /// Returns `Err` if the pool is full and nothing can be evicted; the
    /// channel is then dropped.
    pub fn insert(
        &mut self,
        addr: TransportAddr,
        mut conn: BleConnection<S>,
    ) -> Result<Admitted, TransportError> {
        let (held_out, held_in, verdict) = match self.slots.get(&addr) {
            Some(slot) => {
                let held_out = slot.held.iter().filter(|c| c.outbound).count();
                (held_out, slot.held.len() - held_out, slot.verdict)
            }
            None => (0, 0, None),
        };
        let admission = admit(held_out, held_in, verdict, conn.outbound);
        let mut evicted = None;
        let mut retired = Vec::new();
        match admission {
            Admission::Admit => {
                if self.is_full() {
                    let candidate = self.find_eviction_candidate(conn.is_static)?;
                    self.remove(&candidate);
                    evicted = Some(candidate);
                }
                self.slots.insert(
                    addr,
                    Slot {
                        held: vec![conn],
                        verdict: None,
                    },
                );
            }
            Admission::Hold => {
                if let Some(slot) = self.slots.get_mut(&addr) {
                    slot.held.push(conn);
                }
            }
            Admission::Replace => {
                if let Some(slot) = self.slots.get_mut(&addr) {
                    for mut old in std::mem::replace(&mut slot.held, vec![conn]) {
                        old.retire();
                        retired.push(old.id);
                        self.retiring.push((addr.clone(), old));
                    }
                }
            }
            Admission::Retire => {
                conn.retire();
                retired.push(conn.id);
                self.retiring.push((addr, conn));
            }
        }
        Ok(Admitted {
            admission,
            evicted,
            retired,
        })
    }

    /// Remove every channel at an address, held or retiring. Returns how
    /// many went.
    pub fn remove(&mut self, addr: &TransportAddr) -> usize {
        let held = self.slots.remove(addr).map_or(0, |slot| slot.held.len());
        let before = self.retiring.len();
        self.retiring.retain(|(a, _)| a != addr);
        held + before - self.retiring.len()
    }

    /// Remove one channel, held or retiring. When the last held channel at
    /// an address goes, the address and its verdict go with it, so a later
    /// link there gets a fresh decision.
    pub fn remove_channel(&mut self, addr: &TransportAddr, id: u64) -> bool {
        if let Some(i) = self
            .retiring
            .iter()
            .position(|(a, c)| a == addr && c.id == id)
        {
            self.retiring.remove(i);
            return true;
        }
        let Some(slot) = self.slots.get_mut(addr) else {
            return false;
        };
        let Some(i) = slot.held.iter().position(|c| c.id == id) else {
            return false;
        };
        slot.held.remove(i);
        if slot.held.is_empty() {
            self.slots.remove(addr);
        }
        true
    }

    /// Record which direction to keep at `addr`, and retire the held
    /// channels of the other direction if one of the kept direction is
    /// held. Returns the ids retired.
    pub fn settle(&mut self, addr: &TransportAddr, keep_outbound: bool) -> Vec<u64> {
        let Some(slot) = self.slots.get_mut(addr) else {
            return Vec::new();
        };
        slot.verdict = Some(keep_outbound);
        let held: Vec<(u64, bool)> = slot.held.iter().map(|c| (c.id, c.outbound)).collect();
        let losers = settle(&held, keep_outbound);
        let (kept, gone): (Vec<_>, Vec<_>) = std::mem::take(&mut slot.held)
            .into_iter()
            .partition(|c| !losers.contains(&c.id));
        slot.held = kept;
        for mut conn in gone {
            conn.retire();
            self.retiring.push((addr.clone(), conn));
        }
        losers
    }

    /// Get all linked addresses.
    pub fn addrs(&self) -> Vec<TransportAddr> {
        self.slots.keys().cloned().collect()
    }

    /// Find the best eviction candidate.
    ///
    /// Static peers requesting a slot can evict the oldest non-static peer.
    /// Non-static peers cannot evict anyone if all slots are static.
    fn find_eviction_candidate(
        &self,
        new_is_static: bool,
    ) -> Result<TransportAddr, TransportError> {
        // An address is as old, and as static, as the channel its sends use.
        let candidates = self
            .slots
            .iter()
            .filter_map(|(addr, slot)| slot.held.first().map(|c| (addr, c)));
        if new_is_static {
            // Static peer can evict oldest non-static
            candidates
                .filter(|(_, c)| !c.is_static)
                .min_by_key(|(_, c)| c.established_at)
                .map(|(addr, _)| addr.clone())
                .ok_or_else(|| {
                    TransportError::NotSupported("BLE pool full: all connections are static".into())
                })
        } else {
            // Non-static peer evicts oldest non-static
            candidates
                .filter(|(_, c)| !c.is_static)
                .min_by_key(|(_, c)| c.established_at)
                .map(|(addr, _)| addr.clone())
                .ok_or_else(|| {
                    TransportError::NotSupported("BLE pool full: all connections are static".into())
                })
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(n: u8) -> TransportAddr {
        TransportAddr::from_string(&format!("hci0/AA:BB:CC:DD:EE:{n:02X}"))
    }

    fn test_ble_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    fn test_conn(n: u8, is_static: bool) -> BleConnection<()> {
        channel(n, is_static, false, 0)
    }

    fn channel(n: u8, is_static: bool, outbound: bool, id: u64) -> BleConnection<()> {
        BleConnection {
            stream: (),
            send_tx: tokio::sync::mpsc::channel(1).0,
            send_task: None,
            recv_task: None,
            send_mtu: 2048,
            recv_mtu: 2048,
            established_at: tokio::time::Instant::now(),
            is_static,
            addr: test_ble_addr(n),
            outbound,
            id,
        }
    }

    #[test]
    fn test_pool_basic_insert() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        assert!(pool.is_empty());

        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert!(pool.contains(&test_addr(1)));
    }

    #[test]
    fn test_pool_remove() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        assert_eq!(pool.remove(&test_addr(1)), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_pool_full_eviction() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(3);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        pool.insert(test_addr(2), test_conn(2, false)).unwrap();
        pool.insert(test_addr(3), test_conn(3, false)).unwrap();
        assert!(pool.is_full());

        // Inserting a 4th should evict the oldest non-static
        let result = pool.insert(test_addr(4), test_conn(4, false));
        assert!(result.is_ok());
        assert!(result.unwrap().evicted.is_some()); // something was evicted
        assert_eq!(pool.len(), 3);
        assert!(pool.contains(&test_addr(4)));
    }

    #[test]
    fn test_pool_static_evicts_nonstatic() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        pool.insert(test_addr(2), test_conn(2, false)).unwrap();

        // Static peer should evict a non-static
        let result = pool.insert(test_addr(3), test_conn(3, true));
        assert!(result.is_ok());
        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&test_addr(3)));
    }

    #[test]
    fn test_pool_all_static_rejects() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2);
        pool.insert(test_addr(1), test_conn(1, true)).unwrap();
        pool.insert(test_addr(2), test_conn(2, true)).unwrap();

        // Non-static peer cannot evict static peers
        let result = pool.insert(test_addr(3), test_conn(3, false));
        assert!(result.is_err());
    }

    #[test]
    fn a_second_channel_at_an_address_is_held_not_counted() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(1);
        pool.insert(test_addr(1), channel(1, false, true, 1))
            .unwrap();

        // The peer's own dial arrives at the same address: held beside the
        // first, not replacing it, and not taking a pool slot.
        let result = pool
            .insert(test_addr(1), channel(1, false, false, 2))
            .unwrap();
        assert_eq!(result.admission, Admission::Hold);
        assert_eq!(result.evicted, None);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.held(&test_addr(1)), vec![(1, true), (2, false)]);
        assert_eq!(
            pool.get(&test_addr(1)).unwrap().id,
            1,
            "sends use the oldest"
        );
    }

    #[test]
    fn a_channel_ending_removes_only_itself() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), channel(1, false, true, 1))
            .unwrap();
        pool.insert(test_addr(1), channel(1, false, false, 2))
            .unwrap();

        assert!(pool.remove_channel(&test_addr(1), 1));
        assert_eq!(pool.held(&test_addr(1)), vec![(2, false)]);
        assert!(!pool.remove_channel(&test_addr(1), 1), "already gone");
        assert!(pool.remove_channel(&test_addr(1), 2));
        assert!(
            !pool.contains(&test_addr(1)),
            "the last channel takes the address"
        );
    }

    #[test]
    fn settling_retires_the_other_direction_and_keeps_the_verdict() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), channel(1, false, false, 1))
            .unwrap();
        pool.insert(test_addr(1), channel(1, false, true, 2))
            .unwrap();

        assert_eq!(pool.settle(&test_addr(1), true), vec![1]);
        assert_eq!(pool.held(&test_addr(1)), vec![(2, true)]);
        assert_eq!(pool.retiring(&test_addr(1)), vec![1]);

        // A later inbound at a settled address is retired on arrival.
        let late = pool
            .insert(test_addr(1), channel(1, false, false, 3))
            .unwrap();
        assert_eq!(late.admission, Admission::Retire);
        assert_eq!(late.retired, vec![3]);
        assert_eq!(pool.held(&test_addr(1)), vec![(2, true)]);

        // Removing the address takes the retiring channels with it.
        assert_eq!(pool.remove(&test_addr(1)), 3);
        assert!(pool.retiring(&test_addr(1)).is_empty());
    }

    #[test]
    fn a_verdict_waits_for_the_winning_channel() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), channel(1, false, false, 1))
            .unwrap();

        // Only the losing direction is held: nothing is retired, so a side
        // never loses its only link to a verdict.
        assert!(pool.settle(&test_addr(1), true).is_empty());
        assert_eq!(pool.held(&test_addr(1)), vec![(1, false)]);

        // The winner arrives and replaces it.
        let result = pool
            .insert(test_addr(1), channel(1, false, true, 2))
            .unwrap();
        assert_eq!(result.admission, Admission::Replace);
        assert_eq!(result.retired, vec![1]);
        assert_eq!(pool.held(&test_addr(1)), vec![(2, true)]);
    }

    /// Every input combination: 0 or 1 held outbound, 0 to 2 held inbound,
    /// three verdicts, two newcomer directions. Combinations a conforming
    /// pair of nodes cannot reach are still pinned, so the result for each
    /// is a decision rather than an accident.
    #[test]
    fn admission_table() {
        use Admission::*;
        let none = None;
        let out = Some(true);
        let inb = Some(false);
        // (held_out, held_in, verdict, newcomer outbound, expected, reachable)
        let table = [
            (0, 0, none, true, Admit, true),
            (0, 0, none, false, Admit, true),
            (0, 0, out, true, Admit, false),
            (0, 0, out, false, Admit, false),
            (0, 0, inb, true, Admit, false),
            (0, 0, inb, false, Admit, false),
            (1, 0, none, true, Retire, true),
            (1, 0, none, false, Hold, true),
            (1, 0, out, true, Retire, true),
            (1, 0, out, false, Retire, true),
            (1, 0, inb, true, Retire, true),
            (1, 0, inb, false, Replace, true),
            (0, 1, none, true, Hold, true),
            (0, 1, none, false, Hold, true),
            (0, 1, out, true, Replace, true),
            (0, 1, out, false, Hold, true),
            (0, 1, inb, true, Retire, true),
            (0, 1, inb, false, Hold, true),
            (0, 2, none, true, Hold, true),
            (0, 2, none, false, Hold, false),
            (0, 2, out, true, Replace, true),
            (0, 2, out, false, Hold, false),
            (0, 2, inb, true, Retire, true),
            (0, 2, inb, false, Hold, false),
            (1, 1, none, true, Retire, true),
            (1, 1, none, false, Hold, true),
            (1, 1, out, true, Retire, false),
            (1, 1, out, false, Hold, false),
            (1, 1, inb, true, Retire, false),
            (1, 1, inb, false, Hold, false),
            (1, 2, none, true, Retire, false),
            (1, 2, none, false, Retire, false),
            (1, 2, out, true, Retire, false),
            (1, 2, out, false, Retire, false),
            (1, 2, inb, true, Retire, false),
            (1, 2, inb, false, Retire, false),
        ];
        assert_eq!(table.len(), 36);
        for (held_out, held_in, verdict, outbound, expected, reachable) in table {
            assert_eq!(
                admit(held_out, held_in, verdict, outbound),
                expected,
                "held_out={held_out} held_in={held_in} verdict={verdict:?} \
                 outbound={outbound} (reachable: {reachable})"
            );
        }
    }

    #[test]
    fn settlement_table() {
        // (held, keep_outbound, retired)
        type Row = (&'static [(u64, bool)], bool, &'static [u64]);
        let table: [Row; 10] = [
            (&[], true, &[]),
            (&[(1, true)], true, &[]),
            (&[(1, true)], false, &[]),
            (&[(1, false)], true, &[]),
            (&[(1, false)], false, &[]),
            (&[(1, true), (2, false)], true, &[2]),
            (&[(1, true), (2, false)], false, &[1]),
            (&[(1, false), (2, false), (3, true)], true, &[1, 2]),
            (&[(1, false), (2, false), (3, true)], false, &[3]),
            (&[(1, false), (2, false)], true, &[]),
        ];
        for (held, keep_outbound, retired) in table {
            assert_eq!(
                settle(held, keep_outbound),
                retired,
                "held={held:?} keep_outbound={keep_outbound}"
            );
        }
    }

    #[test]
    fn test_pool_effective_mtu() {
        let mut conn = test_conn(1, false);
        conn.send_mtu = 1024;
        conn.recv_mtu = 2048;
        assert_eq!(conn.effective_mtu(), 1024);
    }

    #[test]
    fn test_pool_addrs() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        pool.insert(test_addr(2), test_conn(2, false)).unwrap();

        let mut addrs = pool.addrs();
        addrs.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        assert_eq!(addrs.len(), 2);
    }
}
