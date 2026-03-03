use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::{apply_incremental, replay_full};
use ecac_core::state::State;

mod util;

#[test]
fn incremental_parity_with_policy_any_split() {
    // Admin + user
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Policy+data:
    // grant → write(A) → revoke → write(B) → grant → write(C)
    // Expected final: only A and C (B denied by revoke).
    let (cred1, g1) = util::make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        10,
        10_000,
        &admin_sk,
        admin_pk,
    );
    let w1 = Op::new(
        vec![],
        Hlc::new(11, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"A".to_vec(),
        },
        &user_sk,
    );
    let r1 = Op::new(
        vec![],
        Hlc::new(12, 1),
        admin_pk,
        Payload::Revoke {
            subject_pk: user_pk,
            role: "editor".into(),
            scope_tags: vec!["hv".into()],
            at: Hlc::new(12, 1),
        },
        &admin_sk,
    );
    let w2 = Op::new(
        vec![],
        Hlc::new(13, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"B".to_vec(),
        },
        &user_sk,
    );
    let (cred2, g2) = util::make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        14,
        10_000,
        &admin_sk,
        admin_pk,
    );
    let w3 = Op::new(
        vec![],
        Hlc::new(15, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"C".to_vec(),
        },
        &user_sk,
    );

    let ops = vec![cred1, g1, w1, r1, w2, cred2, g2, w3];

    // Baseline: full replay over all ops.
    let mut dag_all = Dag::new();
    for op in ops.iter().cloned() {
        dag_all.insert(op);
    }
    let (state_full, digest_full) = replay_full(&dag_all);
    let json_full = state_full.to_deterministic_json_string();

    // For every split point, do incremental: prefix, then all.
    for split in 0..=ops.len() {
        let mut dag_prefix = Dag::new();
        for op in ops[..split].iter().cloned() {
            dag_prefix.insert(op);
        }

        let mut s_inc = State::new();
        // Apply prefix only (sets processed_count to prefix topo length)
        let (_s1, _d1) = apply_incremental(&mut s_inc, &dag_prefix);
        // Then apply against full DAG to process the remaining suffix
        let (_s2, _d2) = apply_incremental(&mut s_inc, &dag_all);

        assert_eq!(
            s_inc.to_deterministic_json_string(),
            json_full,
            "split={split}"
        );
        assert_eq!(s_inc.digest(), digest_full, "split={split}");
    }
}
