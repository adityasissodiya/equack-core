//! MV-Register with HB-aware semantics.
//!
//! Semantics:
//!   - Each write is identified by its op_id (tag) and carries a value (Vec<u8>).
//!   - When applying a new write X, we drop any existing winners whose tags are
//!     ancestors of X (i.e., HB older). Concurrent winners remain.
//!   - We keep *all* concurrent winners. Deterministic projection chooses the
//!     value with the smallest blake3 hash (ties break by the value bytes).
//!
//! Notes:
//!   - We only keep the current winner set (tags -> values), not full history.
//!   - HB oracle is provided by the caller as a closure `hb(a,b)` meaning
//!     "a happens-before b". We assume strict ancestor (a != b).

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::op::OpId;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MVReg {
    /// Current non-dominated winner set: tag(op_id) -> value.
    winners: BTreeMap<OpId, Vec<u8>>,
}

impl MVReg {
    pub fn new() -> Self {
        Self { winners: BTreeMap::new() }
    }

    /// Apply a put tagged by `op_id` with `value`, removing any prior winners
    /// that HB-precede this write.
    pub fn apply_put<F>(&mut self, op_id: OpId, value: Vec<u8>, mut hb: F)
    where
        F: FnMut(&OpId, &OpId) -> bool,
    {
        // Collect tags to remove (ancestors of this op).
        let to_remove: Vec<OpId> = self
            .winners
            .keys()
            .filter(|existing| hb(*existing, &op_id))
            .cloned()
            .collect();
        for t in to_remove {
            self.winners.remove(&t);
        }
        // Insert/replace the value for the new tag.
        self.winners.insert(op_id, value);
    }

    /// Return the set of unique winner values (deduped by bytes) in deterministic order.
    /// Order: lexicographic by bytes.
    pub fn values(&self) -> Vec<Vec<u8>> {
        let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
        for v in self.winners.values() {
            set.insert(v.clone());
        }
        set.into_iter().collect()
    }

    /// Deterministic projection for UI/tests: choose the value with the smallest
    /// blake3 hash, tie-breaking by raw bytes.
    pub fn project(&self) -> Option<Vec<u8>> {
        let mut best: Option<( [u8; 32], Vec<u8> )> = None;
        for v in self.winners.values() {
            let mut hasher = Hasher::new();
            hasher.update(v);
            let h = hasher.finalize().into();
            match &mut best {
                None => best = Some((h, v.clone())),
                Some((bh, bv)) => {
                    if h < *bh || (h == *bh && v < bv) {
                        *bh = h;
                        *bv = v.clone();
                    }
                }
            }
        }
        best.map(|(_, v)| v)
    }

    /// Expose internal winner tags (deterministic order by OpId).
    pub fn winner_tags(&self) -> Vec<OpId> {
        self.winners.keys().cloned().collect()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.winners.is_empty()
    }
}
