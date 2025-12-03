//! M9 read-control tests.
//!
//! These tests exercise the project_field_for_subject + policy::can_read_tag_version
//! path directly, without going through the CLI or store.
//!
//! Scenarios:
//!   - redaction_without_keygrant: no KeyGrant in the log -> encrypted
//!     confidential field is not visible even if the key is available.
//!   - grant_allows_read_confidential: VC-backed Grant + KeyGrant epoch +
//!     keyring entry -> decrypted plaintext is visible.
//!   - key_version_rotation_blocks_future_but_keeps_history_readable:
//!       * subject has KeyGrant(tag="confidential", version=1)
//!       * later write uses version=2
//!       * state after first write is readable
//!       * state after second write is redacted (forward secrecy w.r.t. v1 grant).

use blake3::Hasher;

use ecac_core::crypto::{derive_enc_aad, encrypt_value, generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{CredentialFormat, Op, Payload};
use ecac_core::policy::tags_for;
use ecac_core::replay::{project_field_for_subject, replay_full};

mod util;
use util::make_credential_and_grant;

// Handy constants for the confidential field used below.
const OBJ: &str = "o";
const FIELD: &str = "x";
const CONF_TAG: &str = "confidential";

fn compute_cred_hash(cred_op: &Op) -> [u8; 32] {
    let Payload::Credential { cred_bytes, .. } = &cred_op.header.payload else {
        panic!("expected Credential payload");
    };
    let mut h = Hasher::new();
    h.update(cred_bytes);
    h.finalize().into()
}

#[test]
fn redaction_without_keygrant() {
    // Writer identity
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Sanity: o.x has the confidential tag wired in policy::tags_for.
    let tags = tags_for(OBJ, FIELD);
    assert!(
        tags.contains(CONF_TAG),
        "tags_for(o,x) must contain 'confidential' for this test"
    );

    // One symmetric key for tag="confidential", version=1
    let key_version = 1u32;
    let key = [7u8; 32];

    // Build encrypted Data op:
    // AAD must match the read path: (author_pk, hlc, parents, obj, field).
    let parents: Vec<[u8; 32]> = vec![];
    let hlc = Hlc::new(1_000, 1);
    let aad = derive_enc_aad(
        &user_pk,
        hlc.physical_ms,
        hlc.logical as u64,
        &parents,
        OBJ,
        FIELD,
    );

    let plaintext = b"SECRET-M9-NO-GRANT";
    let enc = encrypt_value(CONF_TAG, key_version, &key, plaintext, &aad);
    let enc_bytes = serde_cbor::to_vec(&enc).expect("enc cbor");

    let data_op = Op::new(
        parents.clone(),
        hlc,
        user_pk,
        Payload::Data {
            key: format!("mv:{OBJ}:{FIELD}"),
            value: enc_bytes,
        },
        &user_sk,
    );

    // DAG with just this encrypted write; no Credential/Grant/KeyGrant events.
    let mut dag = Dag::new();
    dag.insert(data_op);
    let (state, _digest) = replay_full(&dag);

    // Viewer is the same subject; keyring *does* have the key, but there is
    // no KeyGrant in the log, so policy must still deny.
    let visible = project_field_for_subject(
        &dag,
        &state,
        &user_pk,
        |_tag, _ver| Some(key),
        OBJ,
        FIELD,
    );

    assert!(
        visible.is_none(),
        "without any KeyGrant epochs, encrypted confidential field must be redacted"
    );
}

#[test]
fn grant_allows_read_confidential() {
    // Admin == issuer (same pattern as policy_tests.rs)
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    // User / subject
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC-backed Credential + Grant for role="editor" on scope including "confidential".
    //
    // NOTE: scope must contain "confidential" so read epochs intersect the
    // resource-tag { "confidential" } used by can_read_tag_version.
    let (cred_op, grant_op) = make_credential_and_grant(
        &admin_sk,
        "issuer-m9",
        user_pk,
        "editor",
        &["confidential"],
        10,
        10_000,
        &admin_sk,
        admin_pk,
    );

    // Derive cred_hash the same way util::make_credential_and_grant does.
    let cred_hash = compute_cred_hash(&cred_op);

    // And sanity-check that Grant points at the same hash.
    if let Payload::Grant {
        cred_hash: gh, ..
    } = &grant_op.header.payload
    {
        assert_eq!(
            &cred_hash, gh,
            "Grant must reference the Credential's cred_hash"
        );
    } else {
        panic!("expected Grant payload");
    }

    // KeyGrant for tag="confidential", version=1, backed by the same VC (cred_hash).
    let key_version = 1u32;
    let keygrant_op = Op::new(
        vec![grant_op.op_id],
        Hlc::new(11, 3),
        admin_pk,
        Payload::KeyGrant {
            subject_pk: user_pk,
            tag: CONF_TAG.to_string(),
            key_version,
            cred_hash,
        },
        &admin_sk,
    );

    // Symmetric key; policy does not know it, only the viewer's key_lookup closure.
    let key = [9u8; 32];

    // Build a single encrypted write to mv:o:x.
    let parents: Vec<[u8; 32]> = vec![];
    let hlc_data = Hlc::new(20, 1);
    let aad = derive_enc_aad(
        &user_pk,
        hlc_data.physical_ms,
        hlc_data.logical as u64,
        &parents,
        OBJ,
        FIELD,
    );
    let plaintext = b"VISIBLE-SECRET";
    let enc = encrypt_value(CONF_TAG, key_version, &key, plaintext, &aad);
    let enc_bytes = serde_cbor::to_vec(&enc).expect("enc cbor");

    let data_op = Op::new(
        parents.clone(),
        hlc_data,
        user_pk,
        Payload::Data {
            key: format!("mv:{OBJ}:{FIELD}"),
            value: enc_bytes,
        },
        &user_sk,
    );

    // Build DAG with Credential, Grant, KeyGrant, and the encrypted write.
    let mut dag = Dag::new();
    dag.insert(cred_op);
    dag.insert(grant_op);
    dag.insert(keygrant_op);
    dag.insert(data_op);

    let (state, _digest) = replay_full(&dag);

    // Viewer = user with a keyring that knows (tag="confidential", version=1).
    let visible = project_field_for_subject(
        &dag,
        &state,
        &user_pk,
        |tag, ver| {
            if tag == CONF_TAG && ver == key_version {
                Some(key)
            } else {
                None
            }
        },
        OBJ,
        FIELD,
    );

    assert_eq!(
        visible.as_deref(),
        Some("VISIBLE-SECRET"),
        "VC-backed Grant + KeyGrant + keyring must reveal plaintext"
    );
}

#[test]
fn key_version_rotation_blocks_future_but_keeps_history_readable() {
    // Admin == issuer
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    // User / subject
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC-backed Credential + Grant, scoped to "confidential".
    let (cred_op, grant_op) = make_credential_and_grant(
        &admin_sk,
        "issuer-m9-2",
        user_pk,
        "editor",
        &["confidential"],
        10,
        10_000,
        &admin_sk,
        admin_pk,
    );
    let cred_hash = compute_cred_hash(&cred_op);

    // KeyGrant only for (tag="confidential", version=1).
    let v1 = 1u32;
    let keygrant_v1 = Op::new(
        vec![grant_op.op_id],
        Hlc::new(11, 3),
        admin_pk,
        Payload::KeyGrant {
            subject_pk: user_pk,
            tag: CONF_TAG.to_string(),
            key_version: v1,
            cred_hash,
        },
        &admin_sk,
    );

    // Two different symmetric keys for version 1 and version 2.
    let key_v1 = [1u8; 32];
    let key_v2 = [2u8; 32];

    // First write: version=1, older HLC.
    let parents: Vec<[u8; 32]> = vec![];
    let hlc_v1 = Hlc::new(20, 1);
    let aad_v1 = derive_enc_aad(
        &user_pk,
        hlc_v1.physical_ms,
        hlc_v1.logical as u64,
        &parents,
        OBJ,
        FIELD,
    );
    let pt_v1 = b"OLD-V1";
    let enc_v1 = encrypt_value(CONF_TAG, v1, &key_v1, pt_v1, &aad_v1);
    let enc_bytes_v1 = serde_cbor::to_vec(&enc_v1).expect("enc v1 cbor");

    let w_v1 = Op::new(
        parents.clone(),
        hlc_v1,
        user_pk,
        Payload::Data {
            key: format!("mv:{OBJ}:{FIELD}"),
            value: enc_bytes_v1,
        },
        &user_sk,
    );

    // Second write: version=2, later HLC (wins in MVReg).
    let v2 = 2u32;
    let hlc_v2 = Hlc::new(21, 1);
    let aad_v2 = derive_enc_aad(
        &user_pk,
        hlc_v2.physical_ms,
        hlc_v2.logical as u64,
        &parents,
        OBJ,
        FIELD,
    );
    let pt_v2 = b"NEW-V2";
    let enc_v2 = encrypt_value(CONF_TAG, v2, &key_v2, pt_v2, &aad_v2);
    let enc_bytes_v2 = serde_cbor::to_vec(&enc_v2).expect("enc v2 cbor");

    let w_v2 = Op::new(
        parents.clone(),
        hlc_v2,
        user_pk,
        Payload::Data {
            key: format!("mv:{OBJ}:{FIELD}"),
            value: enc_bytes_v2,
        },
        &user_sk,
    );

    // DAG with history only up to v1 write.
    let mut dag_hist = Dag::new();
    dag_hist.insert(cred_op.clone());
    dag_hist.insert(grant_op.clone());
    dag_hist.insert(keygrant_v1.clone());
    dag_hist.insert(w_v1.clone());

    // DAG with both writes (final winner is v2).
    let mut dag_full = Dag::new();
    dag_full.insert(cred_op);
    dag_full.insert(grant_op);
    dag_full.insert(keygrant_v1);
    dag_full.insert(w_v1);
    dag_full.insert(w_v2);

    // State after first write: should be readable under v1 grant.
    let (state_hist, _d_hist) = replay_full(&dag_hist);
    let visible_hist = project_field_for_subject(
        &dag_hist,
        &state_hist,
        &user_pk,
        |tag, ver| {
            if tag == CONF_TAG && ver == v1 {
                Some(key_v1)
            } else {
                None
            }
        },
        OBJ,
        FIELD,
    );
    assert_eq!(
        visible_hist.as_deref(),
        Some("OLD-V1"),
        "history: v1 ciphertext must remain readable to subject with KeyGrant(v1)"
    );

    // State after second write:
    //  - MVReg winner is the v2 op
    //  - subject has *no* KeyGrant for version 2
    //  - key_lookup knows both keys, but policy must deny before decryption
    //    for v2, so the field is redacted.
    let (state_full, _d_full) = replay_full(&dag_full);
    let visible_full = project_field_for_subject(
        &dag_full,
        &state_full,
        &user_pk,
        |tag, ver| {
            if tag == CONF_TAG && ver == v1 {
                Some(key_v1)
            } else if tag == CONF_TAG && ver == v2 {
                Some(key_v2)
            } else {
                None
            }
        },
        OBJ,
        FIELD,
    );
    assert!(
        visible_full.is_none(),
        "after a newer write under version=2 with no KeyGrant(v2), final value must be redacted"
    );
}
