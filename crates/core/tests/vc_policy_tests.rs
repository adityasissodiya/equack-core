use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;

mod util;
use util::make_credential_and_grant;

// Minimal helper for tests: create a TrustStore with exactly one issuer.
fn trust_from_single(issuer_id: &str, vk: VerifyingKey) -> TrustStore {
    let mut issuers = HashMap::new();
    issuers.insert(issuer_id.to_string(), vk);
    TrustStore {
        issuers,
        schemas: HashMap::new(),
    }
}

#[test]
fn vc_valid_allows() {
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let write = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 1, 42),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"OK".to_vec(),
        },
        &user_sk,
    );

    // Capture IDs BEFORE moving ops into the DAG.
    let cred_id = cred.op_id;
    let grant_id = grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(write);

    let topo_like_pos = 1_000_000usize;

    let idx = {
        let ids = vec![cred_id, grant_id, write_id];
        build_auth_epochs_with(&dag, &ids, &trust, &mut status)
    };

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    assert!(is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(nbf + 1, 42)
    ));
}

#[test]
fn vc_status_revoked_denies() {
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    // list-0 bit 0 set -> revoked
    let mut status = StatusCache::from_map(vec![("list-0".to_string(), vec![0b0000_0001])]);

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let write = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 1, 7),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"NOPE".to_vec(),
        },
        &user_sk,
    );

    // Capture IDs BEFORE moving ops into the DAG.
    let cred_id = cred.op_id;
    let grant_id = grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(write);

    let topo_like_pos = 1_000_000usize;

    let idx = {
        let ids = vec![cred_id, grant_id, write_id];
        build_auth_epochs_with(&dag, &ids, &trust, &mut status)
    };

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(nbf + 1, 7)
    ));
}

#[test]
fn vc_expired_denies() {
    use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};

    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC valid only in [10_000, 12_000); write happens at 15_000 -> should be denied
    let nbf = 10_000u64;
    let exp = 12_000u64;
    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let write = Op::new(
        vec![grant.op_id],
        Hlc::new(15_000, 1),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"EXPIRED".to_vec(),
        },
        &user_sk,
    );

    // Capture ids before moving ops into DAG
    let cred_id = cred.op_id;
    let grant_id = grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(write);

    let ids = vec![cred_id, grant_id, write_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let topo_like_pos = 1_000_000usize;
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(15_000, 1)
    ));
}

#[test]
fn vc_not_yet_valid_denies() {
    use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};

    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC valid only from 10_000; write happens at 9_000 -> should be denied
    let nbf = 10_000u64;
    let exp = 20_000u64;
    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let write = Op::new(
        vec![grant.op_id],
        Hlc::new(9_000, 7),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"EARLY".to_vec(),
        },
        &user_sk,
    );

    let cred_id = cred.op_id;
    let grant_id = grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(write);

    let ids = vec![cred_id, grant_id, write_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let topo_like_pos = 1_000_000usize;
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(9_000, 7)
    ));
}

#[test]
fn vc_unknown_issuer_denies() {
    use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};

    // VC is signed by an issuer that's NOT in the TrustStore
    let (unknown_iss_sk, _unknown_iss_vk) = generate_keypair();
    let vc_issuer_id = "unknown-issuer";

    // TrustStore has some other issuer/key
    let (_trusted_sk, trusted_vk) = generate_keypair();
    let trust = trust_from_single("trusted-issuer", trusted_vk.clone());
    let mut status = StatusCache::empty();

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;
    let (cred, grant) = make_credential_and_grant(
        &unknown_iss_sk,
        vc_issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let write = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 1, 9),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"NO-TRUST".to_vec(),
        },
        &user_sk,
    );

    let cred_id = cred.op_id;
    let grant_id = grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred);
    dag.insert(grant);
    dag.insert(write);

    let ids = vec![cred_id, grant_id, write_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let topo_like_pos = 1_000_000usize;
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(nbf + 1, 9)
    ));
}

#[test]
fn vc_hash_mismatch_denies() {
    use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};

    // Trusted issuer
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    // Subject that will actually write
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    // Build a valid credential op (A) for the real subject
    let (cred_a, _grant_a_unused) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    // Build a DIFFERENT credential (B) for another subject just to obtain a different cred_hash
    let (other_user_sk, other_user_vk) = generate_keypair();
    let other_user_pk = vk_to_bytes(&other_user_vk);
    let (cred_b, _grant_b_unused) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        other_user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    // Compute cred_hash for B (but we won't include cred_b in the DAG)
    let cred_b_hash = match &cred_b.header.payload {
        Payload::Credential { cred_bytes, .. } => ecac_core::vc::blake3_hash32(cred_bytes),
        _ => panic!("expected Credential payload"),
    };

    // Malicious/mismatched Grant: references hash of B but depends on op A
    let bad_grant = Op::new(
        vec![cred_a.op_id],
        Hlc::new(nbf, 2),
        admin_pk,
        Payload::Grant {
            subject_pk: user_pk,    // real subject
            cred_hash: cred_b_hash, // WRONG hash (no matching Credential in DAG)
        },
        &admin_sk,
    );

    // Write inside the purported valid window, but it must still be denied because the hash doesn't match any verified VC in DAG.
    let write = Op::new(
        vec![bad_grant.op_id],
        Hlc::new(nbf + 1, 3),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"HASH-MISMATCH".to_vec(),
        },
        &user_sk,
    );

    // Capture ids then insert ops (note: cred_b is NOT inserted)
    let cred_a_id = cred_a.op_id;
    let bad_grant_id = bad_grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred_a);
    dag.insert(bad_grant);
    dag.insert(write);

    let ids = vec![cred_a_id, bad_grant_id, write_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let topo_like_pos = 1_000_000usize;
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(nbf + 1, 3)
    ));
}

#[test]
fn vc_scope_disjoint_set_add_denies() {
    // issuer/admin/user
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC scope only {"hv"}; write tries "set+:o:s:e" (tag "mech") → deny
    let nbf = 10_000u64;
    let exp = 20_000u64;
    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["hv"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let add_mech = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 1, 1),
        user_pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"E".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred.clone());
    dag.insert(grant.clone());
    dag.insert(add_mech.clone());

    let topo_like_pos = 1_000usize;
    let idx = {
        let ids = vec![cred.op_id, grant.op_id, add_mech.op_id];
        build_auth_epochs_with(&dag, &ids, &trust, &mut status)
    };

    let (action, _o, _f, _e, tags) = derive_action_and_tags("set+:o:s:e").unwrap();
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        action,
        &tags,
        topo_like_pos,
        Hlc::new(nbf + 1, 1)
    ));
}

#[test]
fn vc_scope_mech_allows_set_add_and_rem() {
    // issuer/admin/user
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC scope only {"mech"}; both set+ and set- on o.s:e should be allowed.
    let nbf = 10_000u64;
    let exp = 20_000u64;
    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &["mech"],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let add = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 1, 2),
        user_pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"VAL".to_vec(),
        },
        &user_sk,
    );
    let rem = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 2, 2),
        user_pk,
        Payload::Data {
            key: "set-:o:s:e".into(),
            value: b"VAL".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred.clone());
    dag.insert(grant.clone());
    dag.insert(add.clone());
    dag.insert(rem.clone());

    let ids = vec![cred.op_id, grant.op_id, add.op_id, rem.op_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    // Both actions permitted at their positions
    let (a_add, _o, _f, _e, tags_add) = derive_action_and_tags("set+:o:s:e").unwrap();
    assert!(is_permitted_at_pos(
        &idx,
        &user_pk,
        a_add,
        &tags_add,
        2,
        Hlc::new(nbf + 1, 2)
    ));
    let (a_rem, _o2, _f2, _e2, tags_rem) = derive_action_and_tags("set-:o:s:e").unwrap();
    assert!(is_permitted_at_pos(
        &idx,
        &user_pk,
        a_rem,
        &tags_rem,
        3,
        Hlc::new(nbf + 2, 2)
    ));
}

#[test]
fn vc_empty_scope_denies_everything() {
    // issuer/admin/user
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    let mut status = StatusCache::empty();
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Empty scope: []
    let nbf = 10_000u64;
    let exp = 20_000u64;
    let (cred, grant) = make_credential_and_grant(
        &issuer_sk,
        issuer_id,
        user_pk,
        "editor",
        &[],
        nbf,
        exp,
        &admin_sk,
        admin_pk,
    );

    let w1 = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 1, 7),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"X".to_vec(),
        },
        &user_sk,
    );
    let w2 = Op::new(
        vec![grant.op_id],
        Hlc::new(nbf + 2, 7),
        user_pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"E".to_vec(),
        },
        &user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred.clone());
    dag.insert(grant.clone());
    dag.insert(w1.clone());
    dag.insert(w2.clone());

    let ids = vec![cred.op_id, grant.op_id, w1.op_id, w2.op_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (a1, _o, _f, _e, t1) = derive_action_and_tags("mv:o:x").unwrap();
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        a1,
        &t1,
        2,
        Hlc::new(nbf + 1, 7)
    ));

    let (a2, _o2, _f2, _e2, t2) = derive_action_and_tags("set+:o:s:e").unwrap();
    assert!(!is_permitted_at_pos(
        &idx,
        &user_pk,
        a2,
        &t2,
        3,
        Hlc::new(nbf + 2, 7)
    ));
}
