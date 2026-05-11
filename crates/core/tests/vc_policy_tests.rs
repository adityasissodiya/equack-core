use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;
use ecac_core::trustview::{IssuerKeyRecord, StatusList, TrustView};
use ecac_core::vc::verify_vc_with_trustview;
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, HashMap};

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
    let (_other_user_sk, other_user_vk) = generate_keypair();
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

#[test]
fn vc_inband_trustview_allows() {
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (_user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    // Build a normal Credential + Grant pair using the signing key.
    let (cred, _grant) = make_credential_and_grant(
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

    // Construct an in-band TrustView with exactly one issuer key.
    let issuer_vk_bytes = vk_to_bytes(&issuer_vk);
    let mut per_issuer = HashMap::new();
    per_issuer.insert(
        "k1".to_string(),
        IssuerKeyRecord {
            issuer_id: issuer_id.to_string(),
            key_id: "k1".to_string(),
            algo: "EdDSA".to_string(),
            pubkey: issuer_vk_bytes.to_vec(),
            // For this test, make the key effectively always valid.
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            activated_at_ms: 0,
            revoked_at_ms: None,
        },
    );

    let mut issuer_keys = HashMap::new();
    issuer_keys.insert(issuer_id.to_string(), per_issuer);

    let tv = TrustView {
        issuer_keys,
        status_lists: HashMap::new(),
    };

    // Extract the compact JWT and verify using only the in-band TrustView.
    let cred_bytes = match &cred.header.payload {
        Payload::Credential { cred_bytes, .. } => cred_bytes,
        _ => panic!("expected Credential payload"),
    };

    let verified =
        verify_vc_with_trustview(cred_bytes, &tv).expect("VC must verify under in-band trust");

    assert_eq!(verified.issuer, issuer_id);
    assert_eq!(verified.subject_pk, user_pk);
    assert_eq!(verified.role, "editor");
    assert_eq!(verified.scope_tags.contains("hv"), true);
}

#[test]
fn vc_inband_trustview_status_revoked_denies() {
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (_user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    // This helper already issues a VC with a status entry pointing at "list-0", index 0.
    let (cred, _grant) = make_credential_and_grant(
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

    // In-band issuer key.
    let issuer_vk_bytes = vk_to_bytes(&issuer_vk);
    let mut per_issuer = HashMap::new();
    per_issuer.insert(
        "k1".to_string(),
        IssuerKeyRecord {
            issuer_id: issuer_id.to_string(),
            key_id: "k1".to_string(),
            algo: "EdDSA".to_string(),
            pubkey: issuer_vk_bytes.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            activated_at_ms: 0,
            revoked_at_ms: None,
        },
    );

    // In-band status list: list-0, bit 0 set -> revoked.
    let mut chunks = BTreeMap::new();
    chunks.insert(0u32, vec![0b0000_0001]);

    let status_list = StatusList {
        issuer_id: issuer_id.to_string(),
        list_id: "list-0".to_string(),
        version: 1,
        chunks,
        bitset_sha256: [0u8; 32], // digest ignored in this partial M10 impl
    };

    let mut status_lists = HashMap::new();
    status_lists.insert("list-0".to_string(), status_list);

    let tv = TrustView {
        issuer_keys: {
            let mut m = HashMap::new();
            m.insert(issuer_id.to_string(), per_issuer);
            m
        },
        status_lists,
    };

    let cred_bytes = match &cred.header.payload {
        Payload::Credential { cred_bytes, .. } => cred_bytes,
        _ => panic!("expected Credential payload"),
    };

    let res = verify_vc_with_trustview(cred_bytes, &tv);
    assert!(matches!(res, Err(ecac_core::vc::VcError::Revoked)));
}

// =========================================================================
// Concurrent GRANT/REVOKE (Reviewer MAJOR 4 — IoT-J revision)
//
// These two tests pin the semantics of a concurrent GRANT/REVOKE pair when
// the deterministic linearization places the REVOKE before the GRANT:
//
//  - `concurrent_grant_revoke_same_credential_suppressed`
//        The re-ordered GRANT references the SAME credential whose status
//        list entry is now marked revoked. The VC check must fail and no
//        new epoch may open. DATA authored after that GRANT must be denied.
//
//  - `concurrent_grant_revoke_fresh_credential_regrants`
//        The re-ordered GRANT references a DIFFERENT (still-valid)
//        credential. A fresh epoch must open at the GRANT's position and
//        DATA authored under it must be permitted.
//
// Together, these pin down the "deny-wins is per-epoch, not per-subject"
// re-grant semantics discussed in Section~3.3 of the paper.
// =========================================================================

// Local helper: issue a JWT-format credential with a caller-chosen jti and
// status index, then return (Credential op, Grant op).
#[allow(clippy::too_many_arguments)]
fn make_credential_and_grant_custom(
    issuer_sk: &ed25519_dalek::SigningKey,
    issuer_id: &str,
    subject_pk: [u8; 32],
    role: &str,
    scope: &[&str],
    nbf_phys: u64,
    exp_phys: u64,
    admin_sk: &ed25519_dalek::SigningKey,
    admin_pk_bytes: [u8; 32],
    jti: &str,
    status_list_id: &str,
    status_index: u64,
) -> (Op, Op) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ecac_core::crypto::vk_to_bytes;
    use ecac_core::op::CredentialFormat;
    use ed25519_dalek::{Signature, Signer};
    use serde_json::json;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let sub_hex = {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in subject_pk {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    };
    let claims = json!({
        "sub_pk": sub_hex,
        "role": role,
        "scope": scope,
        "nbf": nbf_phys,
        "exp": exp_phys,
        "iss": issuer_id,
        "jti": jti,
        "status": { "id": status_list_id, "index": status_index }
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let sig: Signature = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");
    let cred_bytes = compact.as_bytes().to_vec();

    let cred_hash: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(&cred_bytes);
        h.finalize().into()
    };

    let issuer_vk = ed25519_dalek::VerifyingKey::from(issuer_sk);
    let issuer_pk_bytes = vk_to_bytes(&issuer_vk);

    let cred_op = Op::new(
        vec![],
        Hlc::new(nbf_phys, 1),
        issuer_pk_bytes,
        Payload::Credential {
            cred_id: jti.to_string(),
            cred_bytes,
            format: CredentialFormat::Jwt,
        },
        issuer_sk,
    );

    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(nbf_phys, 2),
        admin_pk_bytes,
        Payload::Grant {
            subject_pk,
            cred_hash,
        },
        admin_sk,
    );

    (cred_op, grant_op)
}

#[test]
fn concurrent_grant_revoke_same_credential_suppressed() {
    // Setup: one issuer, one user. Credential c1 has status index 0.
    // The status list bit 0 is set -> c1 is revoked. A REVOKE event also
    // scope-closes any open epoch. A second GRANT referencing the SAME
    // revoked credential is placed LATER in the deterministic order, and
    // a DATA op authored after that GRANT must be denied because c1's VC
    // check fails (status-revoked).
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    // list-0, bit 0 = c1 is revoked in the status list.
    let mut status = StatusCache::from_map(vec![("list-0".to_string(), vec![0b0000_0001])]);

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    // c1 references list-0, index 0 (will be revoked).
    let (cred1, grant1) = make_credential_and_grant_custom(
        &issuer_sk, issuer_id, user_pk, "editor", &["hv"], nbf, exp, &admin_sk, admin_pk,
        "cred-1", "list-0", 0,
    );
    // A second GRANT referencing the SAME credential hash (pretend a late
    // concurrent re-grant ordered after the REVOKE).
    let cred1_hash = match &cred1.header.payload {
        Payload::Credential { cred_bytes, .. } => ecac_core::vc::blake3_hash32(cred_bytes),
        _ => panic!("expected Credential payload"),
    };
    let late_grant = Op::new(
        vec![grant1.op_id],
        Hlc::new(nbf + 5, 9),
        admin_pk,
        Payload::Grant {
            subject_pk: user_pk,
            cred_hash: cred1_hash,
        },
        &admin_sk,
    );
    // A scope-matching REVOKE that closes any open epoch.
    let revoke = Op::new(
        vec![grant1.op_id],
        Hlc::new(nbf + 3, 1),
        admin_pk,
        Payload::Revoke {
            subject_pk: user_pk,
            role: "editor".into(),
            scope_tags: vec!["hv".into()],
            at: Hlc::new(nbf + 3, 1),
        },
        &admin_sk,
    );
    // DATA op written after the late GRANT. Must be denied.
    let write = Op::new(
        vec![late_grant.op_id],
        Hlc::new(nbf + 7, 3),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"SUPPRESSED".to_vec(),
        },
        &user_sk,
    );

    let cred1_id = cred1.op_id;
    let grant1_id = grant1.op_id;
    let revoke_id = revoke.op_id;
    let late_grant_id = late_grant.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred1);
    dag.insert(grant1);
    dag.insert(revoke);
    dag.insert(late_grant);
    dag.insert(write);

    // Ordered so REVOKE precedes the late GRANT, mirroring the deterministic
    // linearization after tie-breaking.
    let ids = vec![cred1_id, grant1_id, revoke_id, late_grant_id, write_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let topo_like_pos = 1_000_000usize;
    assert!(
        !is_permitted_at_pos(
            &idx,
            &user_pk,
            action,
            &tags,
            topo_like_pos,
            Hlc::new(nbf + 7, 3)
        ),
        "DATA after a GRANT that re-references a status-revoked credential \
         must be denied (concurrent GRANT/REVOKE, same credential)"
    );
}

#[test]
fn concurrent_grant_revoke_fresh_credential_regrants() {
    // Setup: one issuer, one user. Credential c1 is revoked in the status
    // list (bit 0). A scope-matching REVOKE closes c1's epoch. A LATER
    // GRANT references a FRESH credential c2 whose status bit is clear;
    // c2 must verify, a new epoch must open, and a DATA op authored after
    // the fresh GRANT must be permitted.
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";
    let trust = trust_from_single(issuer_id, issuer_vk.clone());
    // list-0 bit 0 = c1 revoked, bit 1 = c2 still valid.
    let mut status = StatusCache::from_map(vec![("list-0".to_string(), vec![0b0000_0001])]);

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let nbf = 10_000u64;
    let exp = 20_000u64;

    // c1 at status index 0 (revoked).
    let (cred1, grant1) = make_credential_and_grant_custom(
        &issuer_sk, issuer_id, user_pk, "editor", &["hv"], nbf, exp, &admin_sk, admin_pk,
        "cred-1", "list-0", 0,
    );
    // c2 at status index 1 (still valid).
    let (cred2, grant2) = make_credential_and_grant_custom(
        &issuer_sk, issuer_id, user_pk, "editor", &["hv"], nbf, exp, &admin_sk, admin_pk,
        "cred-2", "list-0", 1,
    );
    // Scope-matching REVOKE, ordered AFTER grant1 and BEFORE grant2.
    let revoke = Op::new(
        vec![grant1.op_id],
        Hlc::new(nbf + 3, 1),
        admin_pk,
        Payload::Revoke {
            subject_pk: user_pk,
            role: "editor".into(),
            scope_tags: vec!["hv".into()],
            at: Hlc::new(nbf + 3, 1),
        },
        &admin_sk,
    );
    // DATA written after the fresh GRANT referencing c2.
    let write = Op::new(
        vec![grant2.op_id],
        Hlc::new(nbf + 7, 3),
        user_pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"REGRANTED".to_vec(),
        },
        &user_sk,
    );

    let cred1_id = cred1.op_id;
    let grant1_id = grant1.op_id;
    let cred2_id = cred2.op_id;
    let grant2_id = grant2.op_id;
    let revoke_id = revoke.op_id;
    let write_id = write.op_id;

    let mut dag = Dag::new();
    dag.insert(cred1);
    dag.insert(grant1);
    dag.insert(revoke);
    dag.insert(cred2);
    dag.insert(grant2);
    dag.insert(write);

    // Topo-like order: REVOKE precedes grant2 (the fresh re-grant).
    let ids = vec![cred1_id, grant1_id, revoke_id, cred2_id, grant2_id, write_id];
    let idx = build_auth_epochs_with(&dag, &ids, &trust, &mut status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let topo_like_pos = 1_000_000usize;
    assert!(
        is_permitted_at_pos(
            &idx,
            &user_pk,
            action,
            &tags,
            topo_like_pos,
            Hlc::new(nbf + 7, 3)
        ),
        "DATA after a fresh-credential re-grant (concurrent GRANT/REVOKE, \
         different credential) must be permitted"
    );
}
