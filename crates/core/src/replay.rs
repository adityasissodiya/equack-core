//! Deterministic replay with CRDTs (M2) + policy deny-wins filter (M3).
//!
//! Order: parents-first topo; tie: HLC, op_id (from Dag).
//! Policy: build epochs over the SAME order; deny-wins gate before applying data.
//! M2 compatibility: if the log contains **no** policy events, we default-allow.

#[cfg(feature = "audit")]
use crate::policy::DenyDetail;

use crate::trustview::TrustView;

use std::collections::{HashMap, HashSet};

use crate::crypto::{decrypt_value, derive_enc_aad, EncV1, PublicKeyBytes};
use crate::dag::Dag;
use crate::metrics::METRICS;
use crate::op::{OpId, Payload};
use crate::policy::{self, Action};
use crate::state::{FieldValue, State};

use std::time::Instant;

#[cfg(feature = "audit")]
use crate::audit::{AppliedReason, AuditEvent, SkipReason};
#[cfg(feature = "audit")]
use crate::audit_hook::{AuditHook, NoopAuditHook};

/// Full rebuild over the DAG's activated nodes.
pub fn replay_full(dag: &Dag) -> (State, [u8; 32]) {
    let t0 = Instant::now();
    let order = dag.topo_sort();
    let mut state = State::new();
    #[cfg(feature = "audit")]
    {
        let mut noop = NoopAuditHook;
        apply_over_order_with_audit(dag, &order, &mut state, &mut noop);
    }
    #[cfg(not(feature = "audit"))]
    {
        apply_over_order(dag, &order, &mut state);
    }
    let digest = state.digest();
    METRICS.observe_ms("replay_full_ms", t0.elapsed().as_millis() as u64);
    (state, digest)
}

/// Incremental: apply only new suffix relative to state's processed_count().
/// Signature matches M2 tests: (&mut State, &Dag) -> (State, digest)
pub fn apply_incremental(state: &mut State, dag: &Dag) -> (State, [u8; 32]) {
    let t0 = Instant::now();
    let order = dag.topo_sort();
    #[cfg(feature = "audit")]
    {
        let mut noop = NoopAuditHook;
        apply_over_order_with_audit(dag, &order, state, &mut noop);
    }
    #[cfg(not(feature = "audit"))]
    {
        apply_over_order(dag, &order, state);
    }
    let digest = state.digest();
    METRICS.observe_ms("replay_incremental_ms", t0.elapsed().as_millis() as u64);
    (state.clone(), digest)
}

/// Legacy alias for the M10 in-band replay path.
///
/// Default replay already uses TrustView for VC-backed epochs, so this is
/// now just a thin wrapper around `replay_full`.
pub fn replay_full_inband(dag: &Dag) -> (State, [u8; 32]) {
    replay_full(dag)
}

/// Legacy alias for the M10 in-band incremental replay path.
///
/// Default incremental replay already uses TrustView for VC-backed epochs,
/// so this is now just a thin wrapper around `apply_incremental`.
pub fn apply_incremental_inband(state: &mut State, dag: &Dag) -> (State, [u8; 32]) {
    apply_incremental(state, dag)
}

#[cfg(not(feature = "audit"))]
fn apply_over_order(dag: &Dag, order: &[OpId], state: &mut State) {
    // Detect whether any policy events exist; if none, default-allow (M2 compatibility).
    let has_policy = order.iter().any(|id| {
        dag.get(id)
            .map(|op| {
                matches!(
                    op.header.payload,
                    Payload::Grant { .. } | Payload::Revoke { .. }
                )
            })
            .unwrap_or(false)
    });

    // Build epochs from in-band TrustView (M10 path).
    let epoch_index = if has_policy {
        let trust_view = TrustView::build_from_dag(dag, order);
        policy::build_auth_epochs_with_trustview(dag, order, &trust_view)
    } else {
        Default::default()
    };

    // Start position for incremental suffix.
    let mut start_pos = state.processed_count();
    if start_pos > order.len() {
        start_pos = order.len();
    }
    // M7 counters (we accumulate locally, then bump the global registry once).
    let mut data_total: u64 = 0;
    let mut data_applied: u64 = 0;
    let mut data_skipped_policy: u64 = 0;

    // Map each op id to its global topo position so we can validate
    // “parent appears earlier” even when we’re processing only a suffix.
    let _pos_index: HashMap<OpId, usize> = order
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, id)| (id, i))
        .collect();

    for (pos, id) in order.iter().enumerate().skip(start_pos) {
        let Some(op) = dag.get(id) else {
            continue;
        };
        // Invalid signature => skip (no audit in non-audit build)
        if !op.verify() {
            continue;
        }
        match &op.header.payload {
            Payload::Data { key, value } => {
                data_total += 1;
                if let Some((action, obj, field, elem_opt, resource_tags)) =
                    policy::derive_action_and_tags(key)
                {
                    let allowed = if has_policy {
                        policy::is_permitted_at_pos_with_reason(
                            &epoch_index,
                            &op.header.author_pk,
                            action,
                            &resource_tags,
                            pos,
                            op.hlc(),
                        )
                        .is_ok()
                    } else {
                        true
                    };
                    if !allowed {
                        data_skipped_policy += 1;
                        continue;
                    }

                    match action {
                        Action::SetField => {
                            // MVReg put(tag,value) with HB oracle
                            let mv = state.mv_field_mut(&obj, &field);
                            mv.apply_put(*id, value.clone(), |a, b| dag_is_ancestor(dag, a, b));
                            // Observe current winner count (used as a distribution).
                            // Units aren’t time; we still log via observe_ms() per the M7 API.
                            METRICS
                                .observe_ms("mvreg_concurrent_winners", mv.values().len() as u64);
                            data_applied += 1;
                        }
                        Action::SetAdd => {
                            if let Some(elem) = elem_opt {
                                let set = state.set_field_mut(&obj, &field);
                                set.add(elem, *id, value.clone());
                                data_applied += 1;
                            }
                        }
                        Action::SetRem => {
                            if let Some(elem) = elem_opt {
                                let set = state.set_field_mut(&obj, &field);
                                set.remove_with_hb(&elem, id, |add_tag, rem| {
                                    dag_is_ancestor(dag, add_tag, rem)
                                });
                                data_applied += 1;
                            }
                        }
                    }
                }
                // Unknown prefixes ignored (forward-compatible).
            }
            // Policy events: consumed by epoch builder; no data-layer state change.
            Payload::Grant { .. } | Payload::Revoke { .. } => {}
            _ => {}
        }
    }

    // Processed count = entire order length (we traversed all).
    state.set_processed_count(order.len());

    // Push counters once per call (avoids accidental double-counting if the caller loops).
    if data_total > 0 {
        METRICS.inc("ops_total", data_total);
        METRICS.inc("ops_applied", data_applied);
        METRICS.inc("ops_skipped_policy", data_skipped_policy);
    }
}

// ---- Audit-enabled versions -------------------------------------------------

#[cfg(feature = "audit")]
pub fn replay_full_with_audit(dag: &Dag, audit: &mut dyn AuditHook) -> (State, [u8; 32]) {
    let t0 = Instant::now();
    let order = dag.topo_sort();
    let mut state = State::new();
    apply_over_order_with_audit(dag, &order, &mut state, audit);
    let digest = state.digest();
    METRICS.observe_ms("replay_full_ms", t0.elapsed().as_millis() as u64);
    (state, digest)
}

#[cfg(feature = "audit")]
pub fn apply_incremental_with_audit(
    state: &mut State,
    dag: &Dag,
    audit: &mut dyn AuditHook,
) -> (State, [u8; 32]) {
    let t0 = Instant::now();
    let order = dag.topo_sort();
    apply_over_order_with_audit(dag, &order, state, audit);
    let digest = state.digest();
    METRICS.observe_ms("replay_incremental_ms", t0.elapsed().as_millis() as u64);
    (state.clone(), digest)
}

#[cfg(feature = "audit")]
fn apply_over_order_with_audit(
    dag: &Dag,
    order: &[OpId],
    state: &mut State,
    audit: &mut dyn AuditHook,
) {
    // Detect whether any policy events exist; if none, default-allow (M2 compatibility).
    let has_policy = order.iter().any(|id| {
        dag.get(id)
            .map(|op| {
                matches!(
                    op.header.payload,
                    Payload::Grant { .. } | Payload::Revoke { .. }
                )
            })
            .unwrap_or(false)
    });

    // Build epochs from in-band TrustView (M10 path).
    let epoch_index = if has_policy {
        let trust_view = TrustView::build_from_dag(dag, order);
        policy::build_auth_epochs_with_trustview(dag, order, &trust_view)
    } else {
        Default::default()
    };

    // Start position for incremental suffix.
    let mut start_pos = state.processed_count();
    if start_pos > order.len() {
        start_pos = order.len();
    }

    // Counters
    let mut data_total: u64 = 0;
    let mut data_applied: u64 = 0;
    let mut data_skipped_policy: u64 = 0;

    // Absolute parent sanity: map each op id to its topo index.
    let pos_index: HashMap<OpId, usize> = order
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, id)| (id, i))
        .collect();

    for (pos, id) in order.iter().enumerate().skip(start_pos) {
        let Some(op) = dag.get(id) else {
            continue;
        };

        // Invalid signature => SkippedOp(InvalidSig)
        if !op.verify() {
            audit.on_event(AuditEvent::SkippedOp {
                op_id: *id,
                topo_idx: pos as u64,
                reason: SkipReason::InvalidSig,
            });
            continue;
        }

        // Parent sanity: every declared parent must appear earlier in topo order.
        let parents_ok = op
            .header
            .parents
            .iter()
            .all(|p| pos_index.get(p).map_or(false, |ppos| *ppos < pos));
        if !parents_ok {
            audit.on_event(AuditEvent::SkippedOp {
                op_id: *id,
                topo_idx: pos as u64,
                reason: SkipReason::BadParent,
            });
            continue;
        }

        match &op.header.payload {
            Payload::Data { key, value } => {
                data_total += 1;

                if let Some((action, obj, field, elem_opt, resource_tags)) =
                    policy::derive_action_and_tags(key)
                {
                    // Deny-wins gate with reason classification.
                    let deny_detail = if has_policy {
                        match policy::is_permitted_at_pos_with_reason(
                            &epoch_index,
                            &op.header.author_pk,
                            action,
                            &resource_tags,
                            pos,
                            op.hlc(),
                        ) {
                            Ok(()) => None,
                            Err(d) => Some(d),
                        }
                    } else {
                        None
                    };

                    if let Some(detail) = deny_detail {
                        data_skipped_policy += 1;
                        let reason = match detail {
                            DenyDetail::GenericDeny => SkipReason::DenyWins,
                            DenyDetail::RevokedCred => SkipReason::RevokedCred,
                            DenyDetail::ExpiredCred => SkipReason::ExpiredCred,
                            DenyDetail::OutOfScope => SkipReason::OutOfScope,
                        };
                        audit.on_event(AuditEvent::SkippedOp {
                            op_id: *id,
                            topo_idx: pos as u64,
                            reason,
                        });
                        continue;
                    }

                    match action {
                        Action::SetField => {
                            let mv = state.mv_field_mut(&obj, &field);
                            mv.apply_put(*id, value.clone(), |a, b| dag_is_ancestor(dag, a, b));
                            METRICS
                                .observe_ms("mvreg_concurrent_winners", mv.values().len() as u64);
                            data_applied += 1;
                            audit.on_event(AuditEvent::AppliedOp {
                                op_id: *id,
                                topo_idx: pos as u64,
                                reason: AppliedReason::Authorized,
                            });
                        }
                        Action::SetAdd => {
                            if let Some(elem) = elem_opt {
                                let set = state.set_field_mut(&obj, &field);
                                set.add(elem, *id, value.clone());
                                data_applied += 1;
                                audit.on_event(AuditEvent::AppliedOp {
                                    op_id: *id,
                                    topo_idx: pos as u64,
                                    reason: AppliedReason::Authorized,
                                });
                            }
                        }
                        Action::SetRem => {
                            if let Some(elem) = elem_opt {
                                let set = state.set_field_mut(&obj, &field);
                                set.remove_with_hb(&elem, id, |add_tag, rem| {
                                    dag_is_ancestor(dag, add_tag, rem)
                                });
                                data_applied += 1;
                                audit.on_event(AuditEvent::AppliedOp {
                                    op_id: *id,
                                    topo_idx: pos as u64,
                                    reason: AppliedReason::Authorized,
                                });
                            }
                        }
                    }
                }
                // Unknown prefixes ignored (forward-compatible).
            }
            // Policy events: consumed by epoch builder; no data-layer state change.
            Payload::Grant { .. } | Payload::Revoke { .. } => {}
            _ => {}
        }
    }

    // Processed count = entire order length (we traversed all).
    state.set_processed_count(order.len());

    // Push counters once per call.
    if data_total > 0 {
        METRICS.inc("ops_total", data_total);
        METRICS.inc("ops_applied", data_applied);
        METRICS.inc("ops_skipped_policy", data_skipped_policy);
    }

    // Emit a checkpoint at the end of the replay window.
    let digest = state.digest();
    audit.on_event(AuditEvent::Checkpoint {
        checkpoint_id: state.processed_count() as u64,
        topo_idx: state.processed_count() as u64,
        state_digest: digest,
    });
}

fn to_hex<T: AsRef<[u8]>>(v: T) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = v.as_ref();
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0f) as usize] as char);
    }
    out
}

fn bytes_to_display(v: &[u8]) -> String {
    match std::str::from_utf8(v) {
        Ok(s) => s.to_string(),
        Err(_) => to_hex(v),
    }
}

/// Project the logical value of `<obj>.<field>` for a given subject, applying
/// M9 read-control (role/scope epochs + KeyGrant + AEAD decrypt).
///
/// Inputs:
///   - `dag`: the SAME DAG used for replay.
///   - `state`: the materialized CRDT state from `replay_full` / `apply_incremental`.
///   - `subject_pk`: viewer identity.
///   - `key_lookup`: closure providing `(tag, version) -> key_bytes` from the keyring.
///
/// Behaviour:
///   - If the field is MV:
///       * Plaintext winner ⇒ always visible.
///       * EncV1 winner ⇒ visible iff `policy::can_read_tag_version` allows it AND
///         `key_lookup` returns a key and AEAD decryption with header-based AAD succeeds.
///   - If the field is a Set: we currently render a deterministic JSON-ish view and do
///     not apply redaction (M9 does not encrypt sets).
///
/// Returns `Some(string)` if the subject sees a value, or `None` if fully redacted.
pub fn project_field_for_subject<F>(
    dag: &Dag,
    state: &State,
    subject_pk: &PublicKeyBytes,
    key_lookup: F,
    obj: &str,
    field: &str,
) -> Option<String>
where
    F: Fn(&str, u32) -> Option<[u8; 32]>,
{
    // Resolve field first; if it doesn't exist, signal "no value".
    let fields = state.objects.get(obj)?;
    let fv = fields.get(field)?;

    // If there are no policy-like events at all, we still want the same epoch
    // building behaviour as write replay; but we also turn it on when there
    // are KeyGrant events.
    let order = dag.topo_sort();
    let has_policy_like = order.iter().any(|id| {
        let Some(op) = dag.get(id) else {
            return false;
        };
        matches!(
            op.header.payload,
            Payload::Grant { .. } | Payload::Revoke { .. } | Payload::KeyGrant { .. }
        )
    });

    let epoch_index = if has_policy_like {
        // Use in-band TrustView, same as write replay (M10).
        let trust_view = TrustView::build_from_dag(dag, &order);
        policy::build_auth_epochs_with_trustview(dag, &order, &trust_view)
    } else {
        policy::EpochIndex::default()
    };

    // Map each OpId to its topo index so we can feed pos_idx into policy.
    let pos_index: HashMap<OpId, usize> = order
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, id)| (id, i))
        .collect();

    match fv {
        FieldValue::MV(mv) => {
            // Candidate plaintext the viewer is allowed to see.
            let mut candidate: Option<String> = None;
            // If we ever see an encrypted winner that the viewer is *not*
            // allowed to read, we treat the whole field as redacted. This
            // prevents falling back to older/plaintext winners once the
            // field has a confidential write the subject cannot decrypt.
            let mut saw_encrypted_denied = bool::default();

            // Iterate winners in deterministic OpId order.
            for (op_id, val) in mv.winners_with_tags() {
                if val.is_empty() {
                    continue;
                }

                // Try encrypted path first.
                if let Ok(enc) = serde_cbor::from_slice::<EncV1>(val) {
                    let Some(pos) = pos_index.get(op_id).copied() else {
                        saw_encrypted_denied = true;
                        continue;
                    };
                    let Some(op) = dag.get(op_id) else {
                        continue;
                    };

                    // Policy gate: role/scope epoch + KeyGrant(epoch) + HLC guards.
                    if !policy::can_read_tag_version(
                        &epoch_index,
                        subject_pk,
                        &enc.tag,
                        enc.key_version,
                        pos,
                        op.hlc(),
                    ) {
                        // Viewer lacks a valid read epoch for this (tag,version).
                        saw_encrypted_denied = true;
                        continue;
                    }

                    // Keyring gate.
                    let Some(key) = key_lookup(&enc.tag, enc.key_version) else {
                        // Key not present locally – treat as denied for this subject.
                        saw_encrypted_denied = true;
                        continue;
                    };

                    let aad = derive_enc_aad(
                        &op.header.author_pk,
                        op.header.hlc.physical_ms,
                        op.header.hlc.logical as u64,
                        &op.header.parents,
                        obj,
                        field,
                    );

                    if let Some(pt) = decrypt_value(&key, &enc, &aad) {
                        candidate = Some(bytes_to_display(&pt));
                        break;
                    } else {
                        // AEAD failure ⇒ treat as denied.
                        saw_encrypted_denied = true;
                        continue;
                    }
                } else {
                    // Plaintext winner.
                    //
                    // If we have ALREADY seen an encrypted winner we couldn't
                    // authorize, we do *not* fall back to a plaintext value:
                    // the field is considered confidential from that point on.
                    if saw_encrypted_denied {
                        continue;
                    }
                    candidate = Some(bytes_to_display(val));
                    break;
                }
            }

            // If we ever saw an encrypted winner we could not authorize, the
            // whole field is treated as redacted for this subject, even if an
            // older/plaintext winner exists.
            if saw_encrypted_denied {
                None
            } else {
                candidate
            }
        }
        FieldValue::Set(set) => {
            // M9 does not encrypt sets. Keep old "deterministic JSON-ish" view.
            let mut elems = Vec::new();
            for (ek, v) in set.iter_present() {
                elems.push(format!(r#"{{"key":"{}","value":"{}"}}"#, ek, to_hex(&v)));
            }
            Some(format!("[{}]", elems.join(",")))
        }
    }
}

fn dag_is_ancestor(dag: &Dag, a: &OpId, b: &OpId) -> bool {
    if a == b {
        return false;
    }
    let mut stack = vec![*b];
    let mut seen = HashSet::new();
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur) {
            continue;
        }
        if let Some(op) = dag.get(&cur) {
            for p in &op.header.parents {
                if p == a {
                    return true;
                }
                stack.push(*p);
            }
        }
    }
    false
}
