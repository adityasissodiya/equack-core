use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::replay_full;

// Helpers to build policy events
fn grant(subject: [u8;32], role: &str, scope: &[&str], hlc: Hlc, signer: &ed25519_dalek::SigningKey, signer_pk: [u8;32]) -> Op {
    let scope_tags = scope.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Op::new(
        vec![],
        hlc,
        signer_pk,
        Payload::Grant {
            subject_pk: subject,
            role: role.to_string(),
            scope_tags,
            not_before: hlc,
            not_after: None,
        },
        signer
    )
}
fn revoke(subject: [u8;32], role: &str, scope: &[&str], hlc: Hlc, signer: &ed25519_dalek::SigningKey, signer_pk: [u8;32]) -> Op {
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
        signer
    )
}

#[test]
fn grant_allows_then_apply() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Grant editor on {"hv"} then user writes mv:o:x (tags {"hv"})
    let g = grant(user_pk, "editor", &["hv"], Hlc::new(10,1), &admin_sk, admin_pk);
    let w = Op::new(vec![], Hlc::new(11,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"V".to_vec() }, &user_sk);

    let mut dag = Dag::new();
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

    let g = grant(user_pk, "editor", &["hv"], Hlc::new(10,1), &admin_sk, admin_pk);
    let r = revoke(user_pk, "editor", &["hv"], Hlc::new(11,1), &admin_sk, admin_pk);
    let w = Op::new(vec![], Hlc::new(12,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"V".to_vec() }, &user_sk);

    let mut dag = Dag::new();
    dag.insert(g);
    dag.insert(r);
    dag.insert(w);
    let (state, _d) = replay_full(&dag);

    assert!(state.objects.get("o").and_then(|m| m.get("x")).is_none(), "write should be skipped after revoke");
}

#[test]
fn regrant_restores() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let g1 = grant(user_pk, "editor", &["hv"], Hlc::new(10,1), &admin_sk, admin_pk);
    let r  = revoke(user_pk, "editor", &["hv"], Hlc::new(11,1), &admin_sk, admin_pk);
    let g2 = grant(user_pk, "editor", &["hv"], Hlc::new(12,1), &admin_sk, admin_pk);
    let w  = Op::new(vec![], Hlc::new(13,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"V2".to_vec() }, &user_sk);

    let mut dag = Dag::new();
    dag.insert(g1); dag.insert(r); dag.insert(g2); dag.insert(w);
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
    let g = grant(user_pk, "editor", &["mech"], Hlc::new(10,1), &admin_sk, admin_pk);
    let w = Op::new(vec![], Hlc::new(11,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"V".to_vec() }, &user_sk);

    let mut dag = Dag::new();
    dag.insert(g); dag.insert(w);
    let (state, _d) = replay_full(&dag);

    assert!(state.objects.get("o").and_then(|m| m.get("x")).is_none(), "scope mismatch should skip");
}

#[test]
fn overlapping_scope_allows() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Grant on {"hv","mech"}; both mv:o:x and set+:o:s:e should be allowed.
    let g = grant(user_pk, "editor", &["hv","mech"], Hlc::new(10,1), &admin_sk, admin_pk);
    let w1 = Op::new(vec![], Hlc::new(11,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"V".to_vec() }, &user_sk);
    let w2 = Op::new(vec![], Hlc::new(11,2), user_pk, Payload::Data { key: "set+:o:s:e".into(), value: b"E".to_vec() }, &user_sk);

    let mut dag = Dag::new();
    dag.insert(g); dag.insert(w1); dag.insert(w2);
    let (state, _d) = replay_full(&dag);

    // mv:o:x present
    let mv_ok = state.objects.get("o")
        .and_then(|m| m.get("x"))
        .map(|fv| matches!(fv, ecac_core::state::FieldValue::MV(_)))
        .unwrap_or(false);
    assert!(mv_ok);

    // set o.s contains elem "e"
    let set_ok = state.objects.get("o")
        .and_then(|m| m.get("s"))
        .map(|fv| match fv {
            ecac_core::state::FieldValue::Set(s) => s.contains_elem("e"),
            _ => false
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
    let gA = grant(user_pk, "editor", &["hv"], Hlc::new(10,1), &admin_sk, admin_pk);
    let wA = Op::new(vec![], Hlc::new(11,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"A".to_vec() }, &user_sk);

    let mut dag = Dag::new();
    dag.insert(gA.clone()); dag.insert(wA.clone());
    let (stateA, _d) = replay_full(&dag);
    let presentA = stateA.objects.get("o").and_then(|m| m.get("x")).is_some();
    assert!(presentA, "grant before op → allowed");

    // Case B: op before grant (reverse HLC)
    let gB = grant(user_pk, "editor", &["hv"], Hlc::new(20,1), &admin_sk, admin_pk);
    let wB = Op::new(vec![], Hlc::new(19,1), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"B".to_vec() }, &user_sk);

    let mut dag2 = Dag::new();
    dag2.insert(wB); dag2.insert(gB);
    let (stateB, _d2) = replay_full(&dag2);
    let presentB = stateB.objects.get("o").and_then(|m| m.get("x")).is_some();
    assert!(!presentB, "op before grant → denied (not retroactive)");
}

#[test]
fn revoke_vs_op_concurrent_deny_wins() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Grant earlier so user had access.
    let g = grant(user_pk, "editor", &["hv"], Hlc::new(10,1), &admin_sk, admin_pk);
    // Concurrent revoke/op resolved by total order: if revoke before op, deny.
    let r = revoke(user_pk, "editor", &["hv"], Hlc::new(20,1), &admin_sk, admin_pk);
    let w = Op::new(vec![], Hlc::new(20,2), user_pk, Payload::Data { key: "mv:o:x".into(), value: b"X".to_vec() }, &user_sk);

    let mut dag = Dag::new();
    dag.insert(g); dag.insert(r); dag.insert(w);
    let (state, _d) = replay_full(&dag);
    let present = state.objects.get("o").and_then(|m| m.get("x")).is_some();
    assert!(!present, "revoke before op in total order → deny-wins");
}
