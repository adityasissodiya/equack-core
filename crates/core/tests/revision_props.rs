//! Revision property tests (Phase 3.5 of the EQUACK revision plan).
//!
//! Four Jepsen-style invariants tested via `proptest` with random DAGs
//! containing a mix of policy (Credential, Grant, Revoke) and data ops:
//!
//!   P1 — Convergence:  any permutation of the same event set produces an
//!         identical state digest.
//!   P2 — Safety:       no applied DATA op lacks a valid authorization epoch
//!         at its replay position.
//!   P3 — Deny-wins:    if a REVOKE exists for a credential, no DATA op
//!         authored by that credential's subject after the REVOKE's topo
//!         position (in scope) is applied.
//!   P4 — Audit integrity:  the audit checkpoint digest is deterministic
//!         for the same event set regardless of insertion order
//!         (requires "audit" feature).
//!
//! NOTE on coverage overlap:
//!   - `replay_prop.rs` already tests convergence for DATA-only DAGs.
//!   - `replay_policy_prop.rs` tests convergence with a fixed policy pattern.
//!   - This file adds:
//!       * Convergence with *random* mixes of policy + data (P1).
//!       * Explicit safety/epoch-validity invariant (P2).
//!       * Explicit deny-wins invariant with random revoke placement (P3).
//!       * Audit determinism (P4, behind cfg(feature = "audit")).

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::policy;
use ecac_core::replay::replay_full;
use ecac_core::trustview::TrustView;
use proptest::prelude::*;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};

mod util;
use util::make_credential_and_grant;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a mixed policy+data DAG from a seed.  Returns the full op list and
/// metadata needed to validate properties.
///
/// Structure (all HLC-ordered to keep reasoning about "before/after" simple):
///   1. IssuerKey  — registers the issuer's pubkey in TrustView.
///   2. Credential + Grant — opens an epoch for the user.
///   3. N data ops (random mix of mv/set+/set- on known keys).
///   4. Optionally a Revoke event at a random position among the data ops.
///   5. M more data ops after the revoke (if any).
///
/// Returns (ops, revoke_hlc, user_pk)
///   - `revoke_hlc`: `Some(hlc)` of the revoke if emitted; `None` otherwise.
///   - `user_pk`:   the public key bytes of the data-authoring user.
struct ScenarioOps {
    ops: Vec<Op>,
    /// Physical HLC of the Revoke op (if emitted).
    revoke_hlc_phys: Option<u64>,
    /// Public key of the data-authoring user.
    user_pk: [u8; 32],
    /// Public key of the admin (issuer + grant author).
    admin_pk: [u8; 32],
}

fn build_scenario(seed: u64, n_data: usize, emit_revoke: bool) -> ScenarioOps {
    let mut rng = StdRng::seed_from_u64(seed);

    // Identities.
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let issuer_id = "issuer-1";

    // Epoch validity window — generous, so data ops inside [nbf, exp).
    let nbf: u64 = 1_000;
    let exp: u64 = 1_000_000;

    let mut ops: Vec<Op> = Vec::new();
    let mut hlc_counter: u64 = nbf;
    let mut next_hlc = |rng_: &mut StdRng| -> Hlc {
        hlc_counter += 1 + rng_.gen_range(0..5);
        Hlc::new(hlc_counter, rng_.gen_range(0..4))
    };

    // (1) IssuerKey — register the issuer pubkey so TrustView can verify VCs.
    let ik = Op::new(
        vec![],
        Hlc::new(nbf - 1, 0),
        admin_pk,
        Payload::IssuerKey {
            issuer_id: issuer_id.to_string(),
            key_id: "k1".to_string(),
            algo: "EdDSA".to_string(),
            pubkey: admin_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &admin_sk,
    );
    ops.push(ik);

    // (2) Credential + Grant.
    let (cred, grant) = make_credential_and_grant(
        &admin_sk, issuer_id, user_pk, "editor", &["hv", "mech"],
        nbf, exp, &admin_sk, admin_pk,
    );
    ops.push(cred);
    ops.push(grant);

    // Choose a position for the revoke among data ops (0-indexed into the data
    // portion).  If `emit_revoke` is false, `revoke_at` is meaningless.
    let revoke_at: usize = if n_data > 0 { rng.gen_range(0..n_data) } else { 0 };
    let mut revoke_hlc_phys: Option<u64> = None;

    // (3+4+5) Data ops, with optional revoke spliced in.
    for i in 0..n_data {
        // Splice revoke just before the `revoke_at`-th data op.
        if emit_revoke && i == revoke_at {
            let hlc = next_hlc(&mut rng);
            revoke_hlc_phys = Some(hlc.physical_ms);
            let revoke = Op::new(
                vec![],
                hlc,
                admin_pk,
                Payload::Revoke {
                    subject_pk: user_pk,
                    role: "editor".into(),
                    scope_tags: vec!["hv".into(), "mech".into()],
                    at: hlc,
                },
                &admin_sk,
            );
            ops.push(revoke);
        }

        let hlc = next_hlc(&mut rng);
        let kind: u8 = rng.gen_range(0..3);
        let (key, value) = match kind {
            0 => ("mv:o:x".to_string(), vec![rng.gen::<u8>()]),
            1 => (format!("set+:o:s:{}", rng.gen_range(0u8..4)), vec![rng.gen::<u8>()]),
            _ => (format!("set-:o:s:{}", rng.gen_range(0u8..4)), vec![]),
        };
        let data_op = Op::new(vec![], hlc, user_pk, Payload::Data { key, value }, &user_sk);
        ops.push(data_op);
    }

    ScenarioOps { ops, revoke_hlc_phys, user_pk, admin_pk }
}

/// Insert all ops into a DAG in the order specified by `indices`.
fn build_dag_with_order(ops: &[Op], indices: &[usize]) -> Dag {
    let mut dag = Dag::new();
    for &i in indices {
        dag.insert(ops[i].clone());
    }
    dag
}

// ---------------------------------------------------------------------------
// P1 — Convergence: any permutation of the same event set → identical digest
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(80))]

    #[test]
    fn p1_convergence_with_policy(seed in any::<u64>(), n_data in 1usize..10) {
        // Build a scenario with policy + data (no revoke, to keep state simple).
        let scenario = build_scenario(seed, n_data, false);
        let ops = &scenario.ops;

        // Reference digest: sequential insertion.
        let dag_ref = build_dag_with_order(ops, &(0..ops.len()).collect::<Vec<_>>());
        let (_state_ref, digest_ref) = replay_full(&dag_ref);

        // Check 5 random permutations.
        let mut rng = StdRng::seed_from_u64(seed ^ 0xCAFE);
        for _ in 0..5 {
            let mut indices: Vec<usize> = (0..ops.len()).collect();
            indices.shuffle(&mut rng);
            let dag = build_dag_with_order(ops, &indices);
            let (_state, digest) = replay_full(&dag);
            prop_assert_eq!(
                digest, digest_ref,
                "P1 violated: permutation produced a different digest"
            );
        }
    }

    #[test]
    fn p1_convergence_with_revoke(seed in any::<u64>(), n_data in 2usize..10) {
        // Same as above but with a revoke spliced in — exercises deny-wins path
        // for convergence.
        let scenario = build_scenario(seed, n_data, true);
        let ops = &scenario.ops;

        let dag_ref = build_dag_with_order(ops, &(0..ops.len()).collect::<Vec<_>>());
        let (_state_ref, digest_ref) = replay_full(&dag_ref);

        let mut rng = StdRng::seed_from_u64(seed ^ 0xBEEF);
        for _ in 0..5 {
            let mut indices: Vec<usize> = (0..ops.len()).collect();
            indices.shuffle(&mut rng);
            let dag = build_dag_with_order(ops, &indices);
            let (_state, digest) = replay_full(&dag);
            prop_assert_eq!(
                digest, digest_ref,
                "P1 violated: permutation with revoke produced a different digest"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// P2 — Safety: no applied DATA op lacks a valid epoch at its replay position
// ---------------------------------------------------------------------------
//
// Strategy: replay the DAG, then independently rebuild the EpochIndex and
// verify that every DATA op that made it into the state (i.e., the state
// contains its effect) was authorized at its topo position.
//
// Because directly checking "which op contributed to the state" is complex
// with CRDTs, we instead take the contrapositive: for every DATA op that is
// NOT authorized by the epoch index, assert it had no effect on state by
// comparing full replay vs a replay that omits that op.  A stronger (and
// simpler) formulation: replay with the epoch index and assert that every
// position where `is_permitted_at_pos` returns false is indeed skipped.
// We do this by replaying twice — once with the op removed — and checking
// that the digests are equal (i.e., the unauthorized op had no effect).

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn p2_safety_no_unauthorized_data_applied(seed in any::<u64>(), n_data in 2usize..8) {
        let scenario = build_scenario(seed, n_data, true);
        let ops = &scenario.ops;

        // Build reference DAG (sequential insert).
        let mut dag = Dag::new();
        for op in ops { dag.insert(op.clone()); }

        let topo = dag.topo_sort();

        // Build epoch index (same logic replay uses).
        let has_policy = topo.iter().any(|id| {
            dag.get(id).map(|op| matches!(
                op.header.payload,
                Payload::Grant { .. } | Payload::Revoke { .. }
            )).unwrap_or(false)
        });

        if !has_policy {
            // No policy → default-allow, nothing to check.
            return Ok(());
        }

        let trust_view = TrustView::build_from_dag(&dag, &topo);
        let epoch_index = policy::build_auth_epochs_with_trustview(&dag, &topo, &trust_view);

        // Full replay state.
        let (_state_full, digest_full) = replay_full(&dag);

        // For each DATA op that is NOT authorized, verify removing it does not
        // change the digest (i.e., it was indeed skipped during replay).
        for (pos, id) in topo.iter().enumerate() {
            let Some(op) = dag.get(id) else { continue };
            let Payload::Data { ref key, .. } = op.header.payload else { continue };

            let parsed = policy::derive_action_and_tags(key);
            let Some((action, _obj, _field, _elem_opt, resource_tags)) = parsed else {
                continue;
            };

            let authorized = policy::is_permitted_at_pos(
                &epoch_index,
                &op.header.author_pk,
                action,
                &resource_tags,
                pos,
                op.hlc(),
            );

            if !authorized {
                // This DATA op should have been skipped.
                // Verify by building a DAG without it and replaying.
                let mut dag_without = Dag::new();
                for other_op in ops {
                    if other_op.op_id != *id {
                        dag_without.insert(other_op.clone());
                    }
                }
                let (_state_without, digest_without) = replay_full(&dag_without);

                prop_assert_eq!(
                    digest_full, digest_without,
                    "P2 violated: unauthorized DATA op at topo pos {} changed the state",
                    pos
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// P3 — Deny-wins: after a REVOKE for a credential's scope, no DATA by that
//       subject using that scope is applied at topo positions after the revoke.
// ---------------------------------------------------------------------------
//
// Strategy: build a scenario with a known revoke.  After replay, check that
// the materialized state is identical to a replay that omits all post-revoke
// DATA ops from the revoked user.  This confirms the deny-wins gate filtered
// them all.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(60))]

    #[test]
    fn p3_deny_wins_revoke_blocks_subsequent_data(seed in any::<u64>(), n_data in 3usize..10) {
        let scenario = build_scenario(seed, n_data, true);
        let ops = &scenario.ops;
        let user_pk = scenario.user_pk;

        // We need the revoke to have been emitted.
        let Some(_revoke_phys) = scenario.revoke_hlc_phys else {
            // n_data was 0, skip.
            return Ok(());
        };

        // Full replay.
        let mut dag_full = Dag::new();
        for op in ops { dag_full.insert(op.clone()); }
        let topo = dag_full.topo_sort();
        let (_state_full, digest_full) = replay_full(&dag_full);

        // Find the topo position of the Revoke op.
        let revoke_topo_pos = topo.iter().enumerate().find_map(|(pos, id)| {
            let op = dag_full.get(id)?;
            if matches!(op.header.payload, Payload::Revoke { .. }) {
                Some(pos)
            } else {
                None
            }
        });

        let Some(revoke_pos) = revoke_topo_pos else {
            return Ok(());
        };

        // Build a DAG that omits all DATA ops from the revoked user at topo
        // positions strictly after the revoke.
        let mut dag_trimmed = Dag::new();
        // We need to figure out which op_ids appear after the revoke in topo.
        let post_revoke_user_data: std::collections::HashSet<OpId> = topo.iter()
            .enumerate()
            .filter_map(|(pos, id)| {
                if pos <= revoke_pos {
                    return None;
                }
                let op = dag_full.get(id)?;
                if op.header.author_pk == user_pk
                    && matches!(op.header.payload, Payload::Data { .. })
                {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        for op in ops {
            if !post_revoke_user_data.contains(&op.op_id) {
                dag_trimmed.insert(op.clone());
            }
        }

        let (_state_trimmed, digest_trimmed) = replay_full(&dag_trimmed);

        prop_assert_eq!(
            digest_full, digest_trimmed,
            "P3 violated: post-revoke DATA ops from the revoked user affected the state"
        );
    }
}

// ---------------------------------------------------------------------------
// P4 — Audit integrity: audit checkpoint digest is deterministic for the
//       same event set (requires "audit" feature).
// ---------------------------------------------------------------------------

#[cfg(feature = "audit")]
mod audit_integrity {
    use super::*;
    use ecac_core::audit::AuditEvent;
    use ecac_core::audit_hook::AuditHook;
    use ecac_core::replay::replay_full_with_audit;

    /// Collecting audit hook: records all events for later inspection.
    struct CollectingHook {
        events: Vec<AuditEvent>,
    }

    impl CollectingHook {
        fn new() -> Self { Self { events: Vec::new() } }

        /// Return the final Checkpoint event's state_digest, if any.
        fn checkpoint_digest(&self) -> Option<[u8; 32]> {
            self.events.iter().rev().find_map(|ev| {
                if let AuditEvent::Checkpoint { state_digest, .. } = ev {
                    Some(*state_digest)
                } else {
                    None
                }
            })
        }

        /// Return the full sequence of (op_id, event_kind) tuples for
        /// determinism comparison.
        fn event_fingerprint(&self) -> Vec<(OpId, &'static str)> {
            self.events.iter().filter_map(|ev| match ev {
                AuditEvent::AppliedOp { op_id, .. } => Some((*op_id, "applied")),
                AuditEvent::SkippedOp { op_id, .. } => Some((*op_id, "skipped")),
                _ => None,
            }).collect()
        }
    }

    impl AuditHook for CollectingHook {
        fn on_event(&mut self, ev: AuditEvent) {
            self.events.push(ev);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn p4_audit_determinism_with_policy(seed in any::<u64>(), n_data in 2usize..8) {
            let scenario = build_scenario(seed, n_data, true);
            let ops = &scenario.ops;

            // Reference: sequential insertion.
            let dag_ref = build_dag_with_order(ops, &(0..ops.len()).collect::<Vec<_>>());
            let mut hook_ref = CollectingHook::new();
            let (_state_ref, _digest_ref) = replay_full_with_audit(&dag_ref, &mut hook_ref);
            let cp_ref = hook_ref.checkpoint_digest();
            let fp_ref = hook_ref.event_fingerprint();

            // 5 random permutations.
            let mut rng = StdRng::seed_from_u64(seed ^ 0xA0D1);
            for _ in 0..5 {
                let mut indices: Vec<usize> = (0..ops.len()).collect();
                indices.shuffle(&mut rng);
                let dag = build_dag_with_order(ops, &indices);
                let mut hook = CollectingHook::new();
                let (_state, _digest) = replay_full_with_audit(&dag, &mut hook);

                // Checkpoint digest must match.
                let cp = hook.checkpoint_digest();
                prop_assert_eq!(
                    cp, cp_ref,
                    "P4 violated: audit checkpoint digest differs across permutations"
                );

                // Applied/skipped sequence must match (deterministic audit trail).
                let fp = hook.event_fingerprint();
                prop_assert_eq!(
                    fp, fp_ref,
                    "P4 violated: audit event sequence differs across permutations"
                );
            }
        }
    }
}
