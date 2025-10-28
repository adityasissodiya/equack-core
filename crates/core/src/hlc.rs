//! Minimal Hybrid Logical Clock (HLC) for tie-breaking.
//! We *do not* consult wall clock in replay; HLC is carried in ops.

use core::cmp::Ordering;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Hlc {
    /// Milliseconds (physical component) chosen by the emitter when creating the op.
    pub physical_ms: u64,
    /// Logical counter for causality when physical times are equal.
    pub logical: u32,
    /// Fixed node id (small integer) to break ties deterministically.
    pub node_id: u32,
}

impl Hlc {
    /// Create a fresh HLC reading (caller supplies physical_ms).
    pub fn new(physical_ms: u64, node_id: u32) -> Self {
        Self { physical_ms, logical: 0, node_id }
    }

    /// Tick for a *local* event at (maybe) the same physical_ms.
    pub fn tick_local(&mut self, now_ms: u64) {
        if now_ms > self.physical_ms {
            self.physical_ms = now_ms;
            self.logical = 0;
        } else {
            // same or older physical: bump logical
            self.logical = self.logical.saturating_add(1);
        }
    }

    /// Merge with a *remote* HLC (Lamport-ish): returns the next local value.
    pub fn observed(&mut self, remote: Hlc, now_ms: u64) {
        let max_phys = self.physical_ms.max(now_ms).max(remote.physical_ms);
        let new_logical = match max_phys {
            p if p == self.physical_ms && p == remote.physical_ms => self.logical.max(remote.logical) + 1,
            p if p == self.physical_ms && p != remote.physical_ms => self.logical + 1,
            p if p == remote.physical_ms && p != self.physical_ms => remote.logical + 1,
            _ => 0,
        };
        self.physical_ms = max_phys;
        self.logical = new_logical;
    }
}

impl Default for Hlc {
        fn default() -> Self {
            // Safe legacy default for CBOR missing `hlc` (pre-M2 files).
            Hlc { physical_ms: 0, logical: 0, node_id: 0 }
        }
    }

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.physical_ms, self.logical, self.node_id).cmp(&(other.physical_ms, other.logical, other.node_id))
    }
}
impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_lexicographic() {
        let a = Hlc { physical_ms: 10, logical: 0, node_id: 1 };
        let b = Hlc { physical_ms: 10, logical: 1, node_id: 1 };
        assert!(a < b);
    }

    #[test]
    fn tick_and_merge_behave() {
        let mut local = Hlc::new(100, 1);
        local.tick_local(100);
        assert_eq!(local.logical, 1);

        let remote = Hlc { physical_ms: 120, logical: 5, node_id: 2 };
        local.observed(remote, 110);
        assert!(local.physical_ms >= 120);
    }
}
