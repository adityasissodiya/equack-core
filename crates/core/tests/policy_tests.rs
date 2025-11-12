use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::replay_full;

mod util; // VC helper

// Keep Revoke helper (unchanged semantics in M4)
fn revoke(
    subject: [u8; 32],
    role: &str,
    scope: &[&str],
    hlc: Hlc,
    signer: &ed25519_dalek::SigningKey,
    signer_pk: [u8; 32],
) -> Op {
    let scope_tags = scope.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Op::new(
        vec![],
        hlc,
        signer_pk,
        Payload::Revoke {
            subject_pk: subject,
            role: role.to_string(),
            scope_tags,
            at: hlc,
        },
        signer,
    )
}

#[test]
fn grant_allows_then_apply() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC-backed grant for {"hv"}
    let (cred, g) = util::make_credential_and_grant(
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
    let w = Op::new(
        vec![],
        Hlc::new(11, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"V".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(g);
    dag.insert(w);
    let (state, _d) = replay_full(&dag);

    let obj = state.objects.get("o").expect("obj o");
    let fv = obj.get("x").expect("field x");
    match fv {
        ecac_core::state::FieldValue::MV(mv) => {
            let winners = mv.values();
            assert_eq!(winners.len(), 1);
            assert_eq!(winners[0].as_slice(), b"V");
        }
        _ => panic!("expected mv"),
    }
}

#[test]
fn revoke_denies() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let (cred, g) = util::make_credential_and_grant(
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
    let r = revoke(
        user_pk,
        "editor",
        &["hv"],
        Hlc::new(11, 1),
        &admin_sk,
        admin_pk,
    );
    let w = Op::new(
        vec![],
        Hlc::new(12, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"V".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(g);
    dag.insert(r);
    dag.insert(w);
    let (state, _d) = replay_full(&dag);

    assert!(
        state.objects.get("o").and_then(|m| m.get("x")).is_none(),
        "write should be skipped after revoke"
    );
}

#[test]
fn regrant_restores() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

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
    let r = revoke(
        user_pk,
        "editor",
        &["hv"],
        Hlc::new(11, 1),
        &admin_sk,
        admin_pk,
    );
    let (cred2, g2) = util::make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        12,
        10_000,
        &admin_sk,
        admin_pk,
    );
    let w = Op::new(
        vec![],
        Hlc::new(13, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"V2".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred1);
    dag.insert(g1);
    dag.insert(r);
    dag.insert(cred2);
    dag.insert(g2);
    dag.insert(w);
    let (state, _d) = replay_full(&dag);

    let obj = state.objects.get("o").expect("obj o");
    let fv = obj.get("x").expect("field x");
    match fv {
        ecac_core::state::FieldValue::MV(mv) => {
            let winners = mv.values();
            assert_eq!(winners.len(), 1);
            assert_eq!(winners[0].as_slice(), b"V2");
        }
        _ => panic!("expected mv"),
    }
}

#[test]
fn scope_mismatch_skips() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Grant on {"mech"} but write to tags {"hv"} (mv:o:x)
    let (cred, g) = util::make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["mech"],
        10,
        10_000,
        &admin_sk,
        admin_pk,
    );
    let w = Op::new(
        vec![],
        Hlc::new(11, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"V".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(g);
    dag.insert(w);
    let (state, _d) = replay_full(&dag);

    assert!(
        state.objects.get("o").and_then(|m| m.get("x")).is_none(),
        "scope mismatch should skip"
    );
}

#[test]
fn overlapping_scope_allows() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Grant on {"hv","mech"}; both mv:o:x and set+:o:s:e should be allowed.
    let (cred, g) = util::make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv", "mech"],
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
            value: b"V".to_vec(),
        },
        &user_sk,
    );
    let w2 = Op::new(
        vec![],
        Hlc::new(11, 2),
        user_pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"E".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(g);
    dag.insert(w1);
    dag.insert(w2);
    let (state, _d) = replay_full(&dag);

    // mv:o:x present
    let mv_ok = state
        .objects
        .get("o")
        .and_then(|m| m.get("x"))
        .map(|fv| matches!(fv, ecac_core::state::FieldValue::MV(_)))
        .unwrap_or(false);
    assert!(mv_ok);

    // set o.s contains elem "e"
    let set_ok = state
        .objects
        .get("o")
        .and_then(|m| m.get("s"))
        .map(|fv| match fv {
            ecac_core::state::FieldValue::Set(s) => s.contains_elem("e"),
            _ => false,
        })
        .unwrap_or(false);
    assert!(set_ok);
}

#[test]
fn concurrency_grant_vs_op_resolved_by_order() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Case A: grant before op by HLC tie-break
    let (cred_a, g_a) = util::make_credential_and_grant(
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
    let w_a = Op::new(
        vec![],
        Hlc::new(11, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"A".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred_a.clone());
    dag.insert(g_a.clone());
    dag.insert(w_a.clone());
    let (state_a, _d) = replay_full(&dag);
    let present_a = state_a.objects.get("o").and_then(|m| m.get("x")).is_some();
    assert!(present_a, "grant before op → allowed");

    // Case B: op before grant (reverse HLC) → denied
    let (cred_b, g_b) = util::make_credential_and_grant(
        &admin_sk,
        "issuer-1",
        user_pk,
        "editor",
        &["hv"],
        20,
        10_000,
        &admin_sk,
        admin_pk,
    );
    let w_b = Op::new(
        vec![],
        Hlc::new(19, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"B".to_vec(),
        },
        &user_sk,
    );

    let mut dag2 = Dag::new();
    dag2.insert(w_b);
    dag2.insert(cred_b);
    dag2.insert(g_b);
    let (state_b, _d2) = replay_full(&dag2);
    let present_b = state_b.objects.get("o").and_then(|m| m.get("x")).is_some();
    assert!(!present_b, "op before grant → denied (not retroactive)");
}

#[test]
fn revoke_vs_op_concurrent_deny_wins() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Grant earlier so user had access.
    let (cred, g) = util::make_credential_and_grant(
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
    // Concurrent revoke/op resolved by total order: if revoke before op, deny.
    let r = revoke(
        user_pk,
        "editor",
        &["hv"],
        Hlc::new(20, 1),
        &admin_sk,
        admin_pk,
    );
    let w = Op::new(
        vec![],
        Hlc::new(20, 2),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"X".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(g);
    dag.insert(r);
    dag.insert(w);
    let (state, _d) = replay_full(&dag);
    let present = state.objects.get("o").and_then(|m| m.get("x")).is_some();
    assert!(!present, "revoke before op in total order → deny-wins");
}
