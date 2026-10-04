//! UDP transport statistics.

use portable_atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a UDP transport instance.
///
/// Uses atomic counters for lock-free updates from the receive loop
/// and send path concurrently.
pub struct UdpStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub mtu_exceeded: AtomicU64,
    pub kernel_drops: AtomicU64,
}

impl UdpStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            mtu_exceeded: AtomicU64::new(0),
            kernel_drops: AtomicU64::new(0),
        }
    }

    /// Record a successful send.
    pub fn record_send(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record `packets` datagrams totalling `bytes` handed to the kernel in
    /// one batched send (`sendmmsg(2)` or UDP GSO), counted as that many
    /// separate sends.
    pub fn record_sends(&self, packets: u64, bytes: u64) {
        self.packets_sent.fetch_add(packets, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record `packets` datagrams a batched send did not deliver to the
    /// kernel, whether after an error or because the kernel took none of
    /// them, counted as that many send errors.
    pub fn record_unsent(&self, packets: u64) {
        self.send_errors.fetch_add(packets, Ordering::Relaxed);
    }

    /// Record a successful receive.
    pub fn record_recv(&self, bytes: usize) {
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a send error.
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive error.
    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an MTU exceeded rejection.
    pub fn record_mtu_exceeded(&self) {
        self.mtu_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the kernel drop count.
    ///
    /// The value is the cumulative `SO_RXQ_OVFL` count the kernel attaches
    /// to datagrams read from the wildcard listen socket, so it covers that
    /// socket only, not the per-peer connected sockets. It is updated only
    /// as that socket is read, so it stops moving whenever the listen socket
    /// is not being read. It is wired only on Linux; elsewhere (Darwin,
    /// Windows, other Unix) it stays zero.
    pub fn set_kernel_drops(&self, drops: u64) {
        self.kernel_drops.store(drops, Ordering::Relaxed);
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> UdpStatsSnapshot {
        UdpStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            mtu_exceeded: self.mtu_exceeded.load(Ordering::Relaxed),
            kernel_drops: self.kernel_drops.load(Ordering::Relaxed),
        }
    }
}

impl Default for UdpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of UDP stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct UdpStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub kernel_drops: u64,
}
