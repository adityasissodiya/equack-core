//! Deterministic replay with CRDTs (M2) + policy deny-wins filter (M3).
//!
//! Order: parents-first topo; tie: HLC, op_id (from Dag).
//! Policy: build epochs over the SAME order; deny-wins gate before applying data.
//! M2 compatibility: if the log contains **no** policy events, we default-allow.

use std::collections::HashSet;

use crate::dag::Dag;
use crate::op::{OpId, Payload};
use crate::policy::{self, Action};
use crate::state::State;
use crate::metrics::METRICS;
use std::time::Instant;

/// Full rebuild over the DAG's activated nodes.
pub fn replay_full(dag: &Dag) -> (State, [u8; 32]) {
    let t0 = Instant::now();
    let order = dag.topo_sort();
    let mut state = State::new();
    apply_over_order(dag, &order, &mut state);
    let digest = state.digest();
    METRICS.observe_ms("replay_full_ms", t0.elapsed().as_millis() as u64);
    (state, digest)
}

/// Incremental: apply only new suffix relative to state's processed_count().
/// Signature matches M2 tests: (&mut State, &Dag) -> (State, digest)
pub fn apply_incremental(state: &mut State, dag: &Dag) -> (State, [u8; 32]) {
    let t0 = Instant::now();
    let order = dag.topo_sort();
    apply_over_order(dag, &order, state);
    let digest = state.digest();
    METRICS.observe_ms("replay_incremental_ms", t0.elapsed().as_millis() as u64);
    (state.clone(), digest)
}

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

    // Build epochs (cheap at our scale).
    let epoch_index = if has_policy {
        policy::build_auth_epochs(dag, order)
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
    
    for (pos, id) in order.iter().enumerate().skip(start_pos) {
        let Some(op) = dag.get(id) else {
            continue;
        };
        if !op.verify() {
            continue;
        }

        match &op.header.payload {
            Payload::Data { key, value } => {
                data_total += 1;
                if let Some((action, obj, field, elem_opt, resource_tags)) =
                    policy::derive_action_and_tags(key)
                {
                    // Deny-wins gate
                    let allowed = if has_policy {
                        policy::is_permitted_at_pos(
                            &epoch_index,
                            &op.header.author_pk,
                            action,
                            &resource_tags,
                            pos,
                            op.hlc(),
                        )
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
                            METRICS.observe_ms(
                                "mvreg_concurrent_winners",
                                mv.values().len() as u64
                            );
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
