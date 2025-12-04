//! M10 in-band trust view (issuer keys + status lists).
//!
//! This module derives a deterministic snapshot of trust state from the same
//! signed op log as replay:
//!   - Issuer public keys (`IssuerKey` / `IssuerKeyRevoke`)
//!   - Credential status lists (`StatusListChunk`)
//!
//! Given the same DAG + topo order, all replicas build the same `TrustView`.
//! At this stage we:
//!   - assemble issuer key definitions with first-wins semantics per
//!     `(issuer_id, key_id)`, and
//!   - assemble status-list versions as sets of chunks, and expose a helper
//!     for checking `revoked(list_id, index)` against the latest version
//!     per list id.
//!
//! This file intentionally *only* depends on the op log (no filesystem trust);
//! later patches will plug this into VC verification and policy epochs.

use std::collections::{BTreeMap, HashMap};
// Used for status-list digest verification.
use sha2::{Digest as _, Sha256};

use crate::dag::Dag;
use crate::op::{OpId, Payload};

/// Logical issuer identifier (must match VC `iss` in M10).
pub type IssuerId = String;
/// Issuer-local key identifier (must match VC `kid` when present).
pub type KeyId = String;
/// Logical status-list identifier.
pub type ListId = String;

/// One issuer key as published on the log.
#[derive(Debug, Clone)]
pub struct IssuerKeyRecord {
    pub issuer_id: IssuerId,
    pub key_id: KeyId,
    pub algo: String,
    pub pubkey: Vec<u8>,

    /// Declared key validity window (ms since epoch).
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    /// First HLC physical ms at which this key becomes usable on-log.
    ///
    /// Spec: activation time is `max(valid_from_ms, op.hlc.physical_ms)` in
    /// the total order used for replay.
    pub activated_at_ms: u64,
    /// First HLC physical ms at which we observed a revoke for this key
    /// (if any). Once `at_ms >= revoked_at_ms`, the key must not be used.
    pub revoked_at_ms: Option<u64>,
}

impl IssuerKeyRecord {
    /// Return true if this key is active at logical time `t_ms`, taking into
    /// account the declared validity window and any on-log revocation.
    ///
    /// Semantics:
    ///   - inactive before `activated_at_ms`
    ///   - inactive at or after `valid_until_ms`
    ///   - if `revoked_at_ms` is Some(t), inactive at or after `t`
    pub fn is_active_at(&self, t_ms: u64) -> bool {
        if t_ms < self.activated_at_ms {
            return false;
        }
        if t_ms >= self.valid_until_ms {
            return false;
        }
        if let Some(rev) = self.revoked_at_ms {
            if t_ms >= rev {
                return false;
            }
        }
        true
    }
}

/// One assembled status-list version (all chunks we have for a given version).
///
/// Invariants for a *complete* list (enforced when we expose it via
/// `TrustView.status_lists`):
///   - `chunks` is non-empty.
///   - Chunk indices are contiguous starting at 0.
///   - SHA-256 over the concatenated chunk bytes equals `bitset_sha256`.
#[derive(Debug, Clone)]
pub struct StatusList {
    pub issuer_id: IssuerId,
    pub list_id: ListId,
    pub version: u32,
    /// Chunks keyed by `chunk_index` in ascending order.
    pub chunks: BTreeMap<u32, Vec<u8>>,
    /// Advertised SHA-256 over the concatenated chunks.
    pub bitset_sha256: [u8; 32],
}

impl StatusList {
    /// Check whether this status-list version is structurally complete and
    /// its concatenated bytes match `bitset_sha256`.
    ///
    /// Rules:
    ///   - At least one chunk must be present.
    ///   - The smallest index must be 0.
    ///   - Indices must be contiguous: {0,1,...,max_index}.
    ///   - sha256(concat(chunks[0], chunks[1], ..., chunks[max_index])) must
    ///     equal `bitset_sha256`.
    pub fn digest_matches(&self) -> bool {
        if self.chunks.is_empty() {
            return false;
        }

        let (&first_idx, _) = match self.chunks.iter().next() {
            Some(pair) => pair,
            None => return false,
        };
        let (&last_idx, _) = match self.chunks.iter().next_back() {
            Some(pair) => pair,
            None => return false,
        };

        // Require contiguous [0, last_idx].
        if first_idx != 0 {
            return false;
        }
        let expected_len = (last_idx - first_idx + 1) as usize;
        if expected_len != self.chunks.len() {
            return false;
        }

        let mut hasher = Sha256::new();
        for (_idx, bytes) in self.chunks.iter() {
            hasher.update(bytes);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        digest == self.bitset_sha256
    }

    /// Check whether a given `index` is revoked according to this status list.
    ///
    /// Semantics match `StatusCache::is_revoked`:
    /// - Bitstring is interpreted little-endian within each byte (LSB = bit 0).
    /// - Missing chunks / out-of-range bits are treated as "not revoked".
    pub fn is_revoked(&self, index: u32) -> bool {
        if self.chunks.is_empty() {
            return false;
        }

        // Assume fixed-size chunks; use chunk 0 as the reference.
        let first_chunk = match self.chunks.get(&0) {
            Some(c) if !c.is_empty() => c,
            _ => return false,
        };
        let bits_per_chunk = first_chunk.len() * 8;
        let idx = index as usize;

        let chunk_idx = idx / bits_per_chunk;
        let bit_in_chunk = idx % bits_per_chunk;
        let byte_idx = bit_in_chunk / 8;
        let bit_offset = bit_in_chunk % 8;

        let Some(chunk_bytes) = self.chunks.get(&(chunk_idx as u32)) else {
            return false;
        };
        if byte_idx >= chunk_bytes.len() {
            return false;
        }

        (chunk_bytes[byte_idx] & (1u8 << bit_offset)) != 0
    }
}

/// Snapshot of in-band trust and revocation state derived from the log.
///
/// This is intentionally "dumb": it just reflects the latest non-conflicting
/// key and status-list view per identifier. Higher-level components decide how
/// to interpret time, revocation, and key rollovers.
#[derive(Debug, Clone, Default)]
pub struct TrustView {
    /// Active issuer keys per issuer, keyed by `key_id`.
    pub issuer_keys: HashMap<IssuerId, HashMap<KeyId, IssuerKeyRecord>>,
    /// Latest assembled status list per logical list id.
    pub status_lists: HashMap<ListId, StatusList>,
}

impl TrustView {
    /// Build a `TrustView` from a deterministic total order over the DAG.
    ///
    /// Deterministic rules (partial M10 implementation):
    /// - For each `(issuer_id, key_id)` pair, the *first* `IssuerKey` op wins.
    ///   Later ops with a different `pubkey` / `algo` are ignored.
    /// - Status lists are tracked per `(issuer_id, list_id, version)` and we
    ///   expose only the highest `version` we have seen for each `(issuer_id,
    ///   list_id)` pair.
    pub fn build_from_dag(dag: &Dag, order: &[OpId]) -> Self {
        let mut issuer_keys: HashMap<IssuerId, HashMap<KeyId, IssuerKeyRecord>> = HashMap::new();
        let mut status_versions: HashMap<(IssuerId, ListId, u32), StatusList> = HashMap::new();

        for id in order {
            let Some(op) = dag.get(id) else {
                continue;
            };
            match &op.header.payload {
                Payload::IssuerKey {
                    issuer_id,
                    key_id,
                    algo,
                    pubkey,
                    valid_from_ms,
                    valid_until_ms,
                    ..
                } => {
                    let by_kid = issuer_keys.entry(issuer_id.clone()).or_default();
                    if let Some(existing) = by_kid.get(key_id) {
                        // First-wins semantics: if the tuple already exists with
                        // a different definition, ignore this op (key_conflict).
                        if existing.algo != *algo
                            || existing.pubkey != *pubkey
                            || existing.valid_from_ms != *valid_from_ms
                            || existing.valid_until_ms != *valid_until_ms
                        {
                            continue;
                        }
                    } else {
                        // Activation is pinned to the max of the declared window
                        // and the on-log time for this op.
                        let activation_ms =
                            core::cmp::max(*valid_from_ms, op.header.hlc.physical_ms);
                        by_kid.insert(
                            key_id.clone(),
                            IssuerKeyRecord {
                                issuer_id: issuer_id.clone(),
                                key_id: key_id.clone(),
                                algo: algo.clone(),
                                pubkey: pubkey.clone(),
                                valid_from_ms: *valid_from_ms,
                                valid_until_ms: *valid_until_ms,
                                activated_at_ms: activation_ms,
                                revoked_at_ms: None,
                            },
                        );
                    }
                }
                Payload::IssuerKeyRevoke {
                    issuer_id, key_id, ..
                } => {
                    // Revoke immediately deactivates the key from this point
                    // onwards in the same total order used by replay. If
                    // multiple revokes exist, we keep the earliest revocation
                    // point.
                    if let Some(by_kid) = issuer_keys.get_mut(issuer_id) {
                        if let Some(rec) = by_kid.get_mut(key_id) {
                            let rev_ms = op.header.hlc.physical_ms;
                            rec.revoked_at_ms = Some(match rec.revoked_at_ms {
                                Some(prev) => core::cmp::min(prev, rev_ms),
                                None => rev_ms,
                            });
                        }
                    }
                }
                Payload::StatusListChunk {
                    issuer_id,
                    list_id,
                    version,
                    chunk_index,
                    bitset_sha256,
                    chunk_bytes,
                } => {
                    let key = (issuer_id.clone(), list_id.clone(), *version);
                    let entry = status_versions.entry(key).or_insert_with(|| StatusList {
                        issuer_id: issuer_id.clone(),
                        list_id: list_id.clone(),
                        version: *version,
                        chunks: BTreeMap::new(),
                        bitset_sha256: *bitset_sha256,
                    });

                    // Enforce per-version hash consistency: all chunks for a
                    // given (issuer_id, list_id, version) must advertise the
                    // same bitset_sha256. If we see a conflicting hash, we
                    // ignore that chunk (invalid payload).
                    if entry.bitset_sha256 != *bitset_sha256 {
                        // Conflicting hash for the same logical version; drop.
                        continue;
                    }

                    entry.chunks.insert(*chunk_index, chunk_bytes.clone());
                }
                _ => {}
            }
        }

        // Collapse `(issuer_id, list_id, version)` into "latest version per list".
        let mut status_lists: HashMap<ListId, StatusList> = HashMap::new();
        for ((_iss, list_id, ver), sl) in status_versions {
            // Only expose *complete* and hash-valid versions. Incomplete
            // versions (missing chunks or digest mismatch) are ignored; from
            // the caller's perspective this means "treat as not revoked".
            if !sl.digest_matches() {
                continue;
            }

            match status_lists.get_mut(&list_id) {
                Some(existing) => {
                    // Highest version wins for a given logical list id.
                    if ver >= existing.version {
                        *existing = sl;
                    }
                }
                None => {
                    status_lists.insert(list_id.clone(), sl);
                }
            }
        }

        TrustView {
            issuer_keys,
            status_lists,
        }
    }

    /// Check whether a credential index is revoked in the latest assembled
    /// status list for `list_id`.
    ///
    /// Semantics (partial M10):
    ///   - We look up the *latest complete version* we have for this logical
    ///     list id (see `build_from_dag` and `StatusList::digest_matches`).
    ///   - Within that version, we assume a fixed chunk size for all chunks
    ///     and interpret them as a contiguous little-endian bitstring.
    ///   - If the list or the relevant chunk/byte is missing, we treat the
    ///     index as *not revoked* (availability-biased; deterministic).
    pub fn is_revoked(&self, list_id: &str, index: u32) -> bool {
        let sl = match self.status_lists.get(list_id) {
            Some(sl) => sl,
            None => return false,
        };

        if sl.chunks.is_empty() {
            return false;
        }

        // All chunks in a given version are expected to have the same length.
        // Use the first chunk to derive bits-per-chunk.
        let (_, first_chunk) = match sl.chunks.iter().next() {
            Some(pair) => pair,
            None => return false,
        };
        if first_chunk.is_empty() {
            return false;
        }
        let bits_per_chunk = first_chunk.len() * 8;
        let idx = index as usize;
        let chunk_idx = idx / bits_per_chunk;
        let bit_idx = idx % bits_per_chunk;
        let byte_idx = bit_idx / 8;
        let bit_in_byte = bit_idx % 8;

        let chunk = match sl.chunks.get(&(chunk_idx as u32)) {
            Some(c) => c,
            None => return false,
        };
        if byte_idx >= chunk.len() {
            return false;
        }
        (chunk[byte_idx] & (1u8 << bit_in_byte)) != 0
    }

    /// Select an issuer key that is active at logical time `at_ms` for the
    /// given issuer and optional `kid`.
    ///
    /// Semantics (matches the M10 spec):
    ///   - Keys are identified by `(issuer_id, key_id)`.
    ///   - A key is usable at `at_ms` iff:
    ///       * `at_ms >= activated_at_ms`
    ///       * `at_ms < valid_until_ms`
    ///       * and either no revoke has been observed, or `at_ms < revoked_at_ms`.
    ///   - If `kid` is present, we only consider that key.
    ///   - If `kid` is missing, we pick the lexicographically highest
    ///     `(activated_at_ms, key_id)` among usable keys.
    pub fn select_key(
        &self,
        issuer: &str,
        kid: Option<&str>,
        at_ms: u64,
    ) -> Option<&IssuerKeyRecord> {
        let by_kid = self.issuer_keys.get(issuer)?;

        if let Some(k) = kid {
            let rec = by_kid.get(k)?;
            if rec.is_active_at(at_ms) {
                Some(rec)
            } else {
                None
            }
        } else {
            by_kid
                .values()
                .filter(|rec| rec.is_active_at(at_ms))
                .max_by(|a, b| match a.activated_at_ms.cmp(&b.activated_at_ms) {
                    core::cmp::Ordering::Equal => a.key_id.cmp(&b.key_id),
                    ord => ord,
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, vk_to_bytes};
    use crate::dag::Dag;
    use crate::hlc::Hlc;
    use crate::op::{Op, Payload};
    use std::collections::BTreeMap;

    #[test]
    fn status_list_is_revoked_matches_little_endian_bits() {
        // Single chunk, 1 byte: bit 0 set => index 0 revoked, others not.
        let mut chunks = BTreeMap::new();
        chunks.insert(0u32, vec![0b0000_0001]);

        let sl = StatusList {
            issuer_id: "iss".to_string(),
            list_id: "list-0".to_string(),
            version: 1,
            chunks,
            bitset_sha256: [0u8; 32],
        };

        assert!(sl.is_revoked(0));
        for i in 1..8 {
            assert!(!sl.is_revoked(i), "index {} must not be revoked", i);
        }
        // Out of range -> not revoked.
        assert!(!sl.is_revoked(1000));
    }

    #[test]
    fn status_list_digest_matches_and_contiguous() {
        // Build a two-chunk list [0,1] with a correct sha256.
        let mut chunks = BTreeMap::new();
        chunks.insert(0u32, vec![0xAA, 0xBB]);
        chunks.insert(1u32, vec![0xCC]);

        let mut hasher = Sha256::new();
        hasher.update(&[0xAA, 0xBB]);
        hasher.update(&[0xCC]);
        let digest: [u8; 32] = hasher.finalize().into();

        let sl = StatusList {
            issuer_id: "iss".into(),
            list_id: "list-0".into(),
            version: 1,
            chunks,
            bitset_sha256: digest,
        };
        assert!(sl.digest_matches());
    }

    #[test]
    fn issuer_key_activation_revocation_and_select_key() {
        let (sk, vk) = generate_keypair();
        let issuer_pk = vk_to_bytes(&vk);
        let issuer_id = "iss-1".to_string();
        let key_id = "k1".to_string();

        // IssuerKey: payload valid_from_ms is *after* the op's HLC physical time.
        // HLC physical = 50, valid_from_ms = 100 → activation pinned at 100.
        let key_op = Op::new(
            vec![],
            Hlc::new(50, 0),
            issuer_pk,
            Payload::IssuerKey {
                issuer_id: issuer_id.clone(),
                key_id: key_id.clone(),
                algo: "EdDSA".to_string(),
                pubkey: issuer_pk.to_vec(),
                valid_from_ms: 100,
                valid_until_ms: 1_000,
                prev_key_id: None,
            },
            &sk,
        );

        // Revoke later at t = 600.
        let revoke_op = Op::new(
            vec![key_op.op_id],
            Hlc::new(600, 0),
            issuer_pk,
            Payload::IssuerKeyRevoke {
                issuer_id: issuer_id.clone(),
                key_id: key_id.clone(),
                reason: "test".to_string(),
            },
            &sk,
        );

        let mut dag = Dag::new();
        dag.insert(key_op.clone());
        dag.insert(revoke_op.clone());
        let order = vec![key_op.op_id, revoke_op.op_id];

        let tv = TrustView::build_from_dag(&dag, &order);
        let rec = tv
            .issuer_keys
            .get(&issuer_id)
            .and_then(|m| m.get(&key_id))
            .expect("issuer key present");

        // Check the recorded lifecycle.
        assert_eq!(rec.valid_from_ms, 100);
        assert_eq!(rec.valid_until_ms, 1_000);
        assert_eq!(rec.activated_at_ms, 100);
        assert_eq!(rec.revoked_at_ms, Some(600));

        // Before activation → inactive.
        assert!(!rec.is_active_at(99));
        // Within [activated_at_ms, revoked_at_ms) → active.
        assert!(rec.is_active_at(100));
        assert!(rec.is_active_at(599));
        // At revoke or after valid_until → inactive.
        assert!(!rec.is_active_at(600));
        assert!(!rec.is_active_at(1_000));

        // Now exercise TrustView::select_key on top of the same data.
        assert!(tv.select_key(&issuer_id, Some(&key_id), 150).is_some());
        assert!(tv.select_key(&issuer_id, Some(&key_id), 599).is_some());
        assert!(tv.select_key(&issuer_id, Some(&key_id), 600).is_none());
        assert!(tv.select_key(&issuer_id, Some(&key_id), 1_000).is_none());
    }
}
