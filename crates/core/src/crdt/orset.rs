//! Observed-Remove Set (OR-Set) with HB-aware removals.
//!
//! Semantics per OR-Set spec:
//!   - Each add of elem_key is tagged by op_id and stores a value (payload).
//!   - A remove at op R only kills add-tags A such that A HB-precedes R.
//!   - An element is present iff it has at least one active tag (add minus tombstones).
//!   - Deterministic projection for an element picks the value with min blake3(value);
//!     iteration order over elements is lexicographic by elem_key.
//!
//! We keep all add-tags and tombstones; projection is derived on demand.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::op::OpId;

/// Per-element state: add-tags with payloads, and tombstones.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrElem {
    pub adds: BTreeMap<OpId, Vec<u8>>,
    pub tombstones: BTreeSet<OpId>,
}

impl OrElem {
    /// Active tags = adds \ tombstones.
    pub fn active_tags(&self) -> impl Iterator<Item = (&OpId, &Vec<u8>)> {
        self.adds.iter().filter(move |(tag, _)| !self.tombstones.contains(*tag))
    }

    /// True if has any active tag.
    pub fn is_present(&self) -> bool {
        self.active_tags().next().is_some()
    }

    /// Deterministic value projection for the element (if present).
    pub fn project_value(&self) -> Option<Vec<u8>> {
        let mut best: Option<([u8; 32], Vec<u8>)> = None;
        for (_, v) in self.active_tags() {
            let mut hasher = Hasher::new();
            hasher.update(v);
            let h: [u8; 32] = hasher.finalize().into();
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
}

/// Field-level OR-Set across all elements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ORSet {
    elems: BTreeMap<String, OrElem>, // elem_key -> OrElem
}

impl ORSet {
    pub fn new() -> Self {
        Self { elems: BTreeMap::new() }
    }

    /// Add an element occurrence tagged by `op_id` with payload `value`.
    pub fn add(&mut self, elem_key: String, op_id: OpId, value: Vec<u8>) {
        let e = self.elems.entry(elem_key).or_default();
        e.adds.insert(op_id, value);
        // No need to touch tombstones here.
    }

    /// Remove all HB-visible add-tags for `elem_key` as of remover `rem_op`.
    pub fn remove_with_hb<F>(&mut self, elem_key: &str, rem_op: &OpId, mut hb: F)
    where
        F: FnMut(&OpId, &OpId) -> bool,
    {
        if let Some(e) = self.elems.get_mut(elem_key) {
            let to_tombstone: Vec<OpId> = e
                .adds
                .keys()
                .filter(|tag| hb(*tag, rem_op))
                .cloned()
                .collect();
            for t in to_tombstone {
                e.tombstones.insert(t);
            }
        }
    }

    /// Enumerate present elements with deterministic projection of value.
    /// Order: lexicographic by elem_key.
    pub fn iter_present(&self) -> impl Iterator<Item = (&String, Vec<u8>)> {
        self.elems.iter().filter_map(|(k, e)| e.project_value().map(|v| (k, v)))
    }

    /// Access raw element record (for tests/debugging).
    pub fn get(&self, elem_key: &str) -> Option<&OrElem> {
        self.elems.get(elem_key)
    }

    /// True if no element has any active tag.
    pub fn is_empty(&self) -> bool {
        self.elems.values().all(|e| !e.is_present())
    }

    /// Convenience for tests: does an element currently exist (any active tag)?
    pub fn contains_elem(&self, elem_key: &str) -> bool {
        self.elems.get(elem_key).map(|e| e.is_present()).unwrap_or(false)
    }
}
