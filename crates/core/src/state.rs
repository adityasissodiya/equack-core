//! Materialized state for ECAC M2.
//!
//! State model:
//!   objects: BTreeMap<obj_id, BTreeMap<field_name, FieldValue>>
//! FieldValue:
//!   - MVReg: multi-value register for "set field" semantics.
//!   - ORSet: add/remove set for collection semantics.
//!
//! The in-memory structures use BTreeMap/BTreeSet so iteration is deterministic.
//! For JSON export, we emit a stable, deterministic structure suitable for
//! byte-wise comparison in tests. Bytes are hex-encoded for readability.
//!
//! Checkpoints: We support in-memory snapshot/restore using CBOR to capture
//! full CRDT internals (including tags). This allows incremental apply after
//! restore without losing HB correctness.

use std::collections::BTreeMap;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::crdt::{MVReg, ORSet};

/// A field value is one of the supported CRDTs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldValue {
    MV(MVReg),
    Set(ORSet),
}

impl FieldValue {
    pub fn as_mv_mut(&mut self) -> Option<&mut MVReg> {
        match self {
            FieldValue::MV(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_set_mut(&mut self) -> Option<&mut ORSet> {
        match self {
            FieldValue::Set(s) => Some(s),
            _ => None,
        }
    }
}

/// Deterministic, in-memory materialized state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub objects: BTreeMap<String, BTreeMap<String, FieldValue>>,
    /// Number of topo-ordered ops already applied (for incremental).
    processed_count: usize,
}

impl State {
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            processed_count: 0,
        }
    }

    pub fn processed_count(&self) -> usize {
        self.processed_count
    }

    pub fn set_processed_count(&mut self, n: usize) {
        self.processed_count = n;
    }

    /// Get or create an MVReg field.
    pub fn mv_field_mut(&mut self, obj: &str, field: &str) -> &mut MVReg {
        let fields = self.objects.entry(obj.to_string()).or_default();
        match fields.entry(field.to_string()) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(FieldValue::MV(MVReg::new()));
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if !matches!(e.get(), FieldValue::MV(_)) {
                    // Strictness choice: coerce to MV if previously different.
                    e.insert(FieldValue::MV(MVReg::new()));
                }
            }
        }
        match fields.get_mut(field).unwrap() {
            FieldValue::MV(m) => m,
            _ => unreachable!(),
        }
    }

    /// Get or create an ORSet field.
    pub fn set_field_mut(&mut self, obj: &str, field: &str) -> &mut ORSet {
        let fields = self.objects.entry(obj.to_string()).or_default();
        match fields.entry(field.to_string()) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(FieldValue::Set(ORSet::new()));
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if !matches!(e.get(), FieldValue::Set(_)) {
                    e.insert(FieldValue::Set(ORSet::new()));
                }
            }
        }
        match fields.get_mut(field).unwrap() {
            FieldValue::Set(s) => s,
            _ => unreachable!(),
        }
    }

    /// Deterministic JSON export (stable ordering).
    ///
    /// Structure:
    /// {
    ///   "objects": [
    ///     { "id": "<obj>", "fields": [
    ///       { "name": "<field>", "type": "mv", "winners": ["<hex>", ...], "project": "<hex>" },
    ///       { "name": "<field>", "type": "set", "elems": [{"key":"<elem>", "value":"<hex>"} , ...] }
    ///     ] }
    ///   ],
    ///   "processed_count": <usize>
    /// }
    pub fn to_deterministic_json_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct MVOut<'a> {
            name: &'a str,
            #[serde(rename = "type")]
            ty: &'static str,
            winners: Vec<String>,
            project: Option<String>,
        }

        #[derive(Serialize)]
        struct SetElem<'a> {
            key: &'a str,
            value: String,
        }

        #[derive(Serialize)]
        struct SetOut<'a> {
            name: &'a str,
            #[serde(rename = "type")]
            ty: &'static str,
            elems: Vec<SetElem<'a>>,
        }

        #[derive(Serialize)]
        struct ObjOut<'a> {
            id: &'a str,
            fields: Vec<serde_json::Value>,
        }

        #[derive(Serialize)]
        struct Root<'a> {
            objects: Vec<ObjOut<'a>>,
            processed_count: usize,
        }

        let mut objects: Vec<ObjOut> = Vec::new();

        for (obj_id, fields) in &self.objects {
            let mut fouts: Vec<serde_json::Value> = Vec::new();
            for (fname, fval) in fields {
                match fval {
                    FieldValue::MV(mv) => {
                        // winners sorted by *hash*, tie-break by bytes
                        let winners_bytes = mv.values();
                        let mut winners_sorted = winners_bytes
                            .into_iter()
                            .map(|v| {
                                let mut hasher = Hasher::new();
                                hasher.update(&v);
                                let h: [u8; 32] = hasher.finalize().into();
                                (h, v)
                            })
                            .collect::<Vec<_>>();
                        winners_sorted.sort_by(|a, b| {
                            if a.0 != b.0 {
                                a.0.cmp(&b.0)
                            } else {
                                a.1.cmp(&b.1)
                            }
                        });
                        let winners: Vec<String> =
                            winners_sorted.into_iter().map(|(_, v)| hex(v)).collect();

                        let project = mv.project().map(hex);
                        let out = MVOut {
                            name: fname,
                            ty: "mv",
                            winners,
                            project,
                        };
                        fouts.push(serde_json::to_value(out).unwrap());
                    }
                    FieldValue::Set(set) => {
                        let mut elems: Vec<SetElem> = Vec::new();
                        for (ek, v) in set.iter_present() {
                            elems.push(SetElem {
                                key: ek,
                                value: hex(&v),
                            });
                        }
                        let out = SetOut {
                            name: fname,
                            ty: "set",
                            elems,
                        };
                        fouts.push(serde_json::to_value(out).unwrap());
                    }
                }
            }
            objects.push(ObjOut {
                id: obj_id,
                fields: fouts,
            });
        }

        let root = Root {
            objects,
            processed_count: self.processed_count,
        };
        serde_json::to_vec(&root).unwrap()
    }

    /// Deterministic digest (blake3 of deterministic JSON bytes).
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.to_deterministic_json_bytes();
        let mut hasher = Hasher::new();
        hasher.update(b"ECAC_STATE_V1");
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    /// Convenience for tests/examples.
    pub fn to_deterministic_json_string(&self) -> String {
        String::from_utf8(self.to_deterministic_json_bytes()).unwrap()
    }

    // ---------------------------
    // In-memory checkpoints (CBOR)

    /// Serialize the full state (including CRDT tags) to CBOR bytes.
    pub fn snapshot_to_cbor(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("CBOR serialize State")
    }

    /// Restore a state from CBOR bytes previously produced by `snapshot_to_cbor`.
    pub fn restore_from_cbor(bytes: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(bytes)
    }
}

/// Hex-encode bytes.
fn hex<T: AsRef<[u8]>>(v: T) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = v.as_ref();
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0f) as usize] as char);
    }
    out
}
