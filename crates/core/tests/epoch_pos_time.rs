//! E5-style tests for position+time epoch semantics.
//!
//! 1) pos-boundary closes epochs: grant → 2 writes → revoke → 2 writes
//! 2) time-boundary enforces VC validity (nbf/exp)
//! 3) determinism under shuffle: 50 shuffles, same digest

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay::replay_full;

mod util;
use util::make_credential_and_grant;

/// Helper: create an IssuerKey op that registers the issuer's pubkey in TrustView.
fn issuer_key_op(
    issuer_id: &str,
    sk: &ed25519_dalek::SigningKey,
    hlc_ms: u64,
    parents: Vec<OpId>,
) -> Op {
    let pk = vk_to_bytes(&sk.verifying_key());
    Op::new(
        parents,
        Hlc::new(hlc_ms, 0),
        pk,
        Payload::IssuerKey {
            issuer_id: issuer_id.to_string(),
            key_id: "k1".to_string(),
            algo: "EdDSA".to_string(),
            pubkey: pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        sk,
    )
}

/// Helper: create a set-add Data op (adds `elem` to OR-set at (o, x)).
/// Uses field "x" on object "o" because tags_for("o","x") → {"hv","confidential"}.
fn set_add_op(
    elem: &str,
    parents: Vec<OpId>,
    hlc: Hlc,
    author_pk: [u8; 32],
    sk: &ed25519_dalek::SigningKey,
) -> Op {
    Op::new(
        parents,
        hlc,
        author_pk,
        Payload::Data {
            key: format!("set+:o:x:{elem}"),
            value: vec![],
        },
        sk,
    )
}

/// Test 1: Position-boundary closes epochs.
///
/// Build: IssuerKey → cred → grant → add(A) → add(B) → revoke → add(C) → add(D)
/// Expected after replay: A and B in the set; C and D skipped.
#[test]
fn pos_boundary_closes_epochs() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 1_000u64;
    let exp = 100_000u64;

    // IssuerKey (registers issuer pubkey in TrustView)
    let ik = issuer_key_op("issuer-1", &admin_sk, nbf - 1, vec![]);

    // Credential + Grant (opens epoch at grant's position)
    let (cred, grant) = make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    // Two pre-revocation set-adds (should be applied)
    let add_a = set_add_op("A", vec![grant.op_id], Hlc::new(nbf + 10, 1), user_pk, &user_sk);
    let add_b = set_add_op("B", vec![add_a.op_id], Hlc::new(nbf + 20, 1), user_pk, &user_sk);

    // Revoke (closes epoch at this position)
    let revoke = Op::new(
        vec![add_b.op_id],
        Hlc::new(nbf + 30, 1),
        admin_pk,
        Payload::Revoke {
            subject_pk: user_pk,
            role: "editor".into(),
            scope_tags: vec!["hv".into()],
            at: Hlc::new(nbf + 30, 1),
        },
        &admin_sk,
    );

    // Two post-revocation set-adds (should be skipped)
    let add_c = set_add_op("C", vec![revoke.op_id], Hlc::new(nbf + 40, 1), user_pk, &user_sk);
    let add_d = set_add_op("D", vec![add_c.op_id], Hlc::new(nbf + 50, 1), user_pk, &user_sk);

    let mut dag = Dag::new();
    dag.insert(ik);
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(add_a);
    dag.insert(add_b);
    dag.insert(revoke);
    dag.insert(add_c);
    dag.insert(add_d);

    let (state, _digest) = replay_full(&dag);
    let json = state.to_deterministic_json_string();

    // A and B must be present (applied); C and D must be absent (skipped).
    assert!(json.contains("\"key\":\"A\""), "set-add A should be applied\n{json}");
    assert!(json.contains("\"key\":\"B\""), "set-add B should be applied\n{json}");
    assert!(!json.contains("\"key\":\"C\""), "set-add C should be skipped (post-revoke)\n{json}");
    assert!(!json.contains("\"key\":\"D\""), "set-add D should be skipped (post-revoke)\n{json}");
}

/// Test 2: Time-boundary enforces VC validity window.
///
/// VC valid in [10_000, 20_000).
/// add_early at t=5_000 → skipped (before nbf)
/// add_ok    at t=15_000 → applied (within window)
/// add_late  at t=25_000 → skipped (after exp)
#[test]
fn time_boundary_enforces_vc_validity() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    // IssuerKey (registers issuer pubkey in TrustView)
    let ik = issuer_key_op("issuer-1", &admin_sk, 1, vec![]);

    let (cred, grant) = make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    // Set-add before nbf (should be skipped)
    let add_early = set_add_op("EARLY", vec![grant.op_id], Hlc::new(5_000, 1), user_pk, &user_sk);

    // Set-add within [nbf, exp) (should be applied)
    let add_ok = set_add_op("OK", vec![grant.op_id], Hlc::new(15_000, 1), user_pk, &user_sk);

    // Set-add after exp (should be skipped)
    let add_late = set_add_op("LATE", vec![grant.op_id], Hlc::new(25_000, 1), user_pk, &user_sk);

    let mut dag = Dag::new();
    dag.insert(ik);
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(add_early);
    dag.insert(add_ok);
    dag.insert(add_late);

    let (state, _digest) = replay_full(&dag);
    let json = state.to_deterministic_json_string();

    assert!(
        !json.contains("\"key\":\"EARLY\""),
        "set-add before nbf should be skipped\n{json}"
    );
    assert!(
        json.contains("\"key\":\"OK\""),
        "set-add within [nbf, exp) should be applied\n{json}"
    );
    assert!(
        !json.contains("\"key\":\"LATE\""),
        "set-add after exp should be skipped\n{json}"
    );
}

/// Test 3: Determinism under insertion-order shuffling.
///
/// Build a DAG with IssuerKey + grant + 4 concurrent set-adds, shuffle
/// insertion order 50 times, assert identical state digest every time.
#[test]
fn determinism_under_shuffle() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 1_000u64;
    let exp = 100_000u64;

    // IssuerKey (registers issuer pubkey in TrustView)
    let ik = issuer_key_op("issuer-1", &admin_sk, nbf - 1, vec![]);

    let (cred, grant) = make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    // 4 concurrent set-adds (all depend on grant, not on each other)
    let adds: Vec<Op> = (0..4)
        .map(|i| {
            set_add_op(
                &format!("V{i}"),
                vec![grant.op_id],
                Hlc::new(nbf + 100 + i as u64, i as u32),
                user_pk,
                &user_sk,
            )
        })
        .collect();

    let all_ops: Vec<Op> = std::iter::once(ik)
        .chain(std::iter::once(cred))
        .chain(std::iter::once(grant))
        .chain(adds)
        .collect();

    // First run: canonical order
    let mut dag0 = Dag::new();
    for op in all_ops.iter().cloned() {
        dag0.insert(op);
    }
    let (state0, digest0) = replay_full(&dag0);
    let json0 = state0.to_deterministic_json_string();
    // Verify data was actually applied (not vacuously passing with empty state)
    assert!(json0.contains("\"key\":\"V0\""), "V0 should be applied\n{json0}");

    // 50 shuffled insertion orders
    for seed in 0u64..50 {
        let mut indices: Vec<usize> = (0..all_ops.len()).collect();
        // Simple seeded Fisher-Yates shuffle
        for i in (1..indices.len()).rev() {
            let mut h = DefaultHasher::new();
            seed.hash(&mut h);
            i.hash(&mut h);
            let j = (h.finish() as usize) % (i + 1);
            indices.swap(i, j);
        }

        let mut dag = Dag::new();
        for &idx in &indices {
            dag.insert(all_ops[idx].clone());
        }
        let (_state, digest) = replay_full(&dag);
        assert_eq!(
            digest, digest0,
            "digest mismatch at shuffle seed={seed}"
        );
    }
}
