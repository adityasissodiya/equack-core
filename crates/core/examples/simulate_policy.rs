// crates/core/examples/simulate_policy.rs
//! M4 policy simulation: VC-backed grants (allowed vs revoked).
//!
//! Case A: status bit = 0 → write is ALLOWED.
//! Case B: status bit = 1 → write is DENIED.
//!
//! We *don’t* panic if VC verification fails in Case B (revoked). The
//! replay pipeline checks revocation when building epochs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{CredentialFormat, Op, Payload};
use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;
use ecac_core::vc::{blake3_hash32, verify_vc};

fn main() {
    // Keys
    let (issuer_sk, issuer_vk) = generate_keypair();
    let issuer_id = "oem-issuer-1";

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);

    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // VC claims
    let cred_id = "example-cred-1";
    let nbf = 10_000u64;
    let exp = 20_000u64;
    let status_list_id = "list-0";
    let status_index = 1u32;

    // Build compact JWT
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = json!({
        "sub_pk": hex32(&user_pk),
        "role": "editor",
        "scope": ["hv"],
        "nbf": nbf,
        "exp": exp,
        "iss": issuer_id,
        "jti": cred_id,
        "status": { "id": status_list_id, "index": status_index }
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");
    let cred_bytes = compact.as_bytes().to_vec();
    let cred_hash = blake3_hash32(&cred_bytes);

    // Trust
    let trust = TrustStore::from_single(issuer_id, issuer_vk.clone());

    // Case A: NOT REVOKED → allowed
    let mut status_ok = StatusCache::empty();
    run_case(
        "A: not revoked → allowed",
        cred_id,
        &issuer_sk,
        admin_pk,
        &admin_sk,
        user_pk,
        &user_sk,
        &cred_bytes,
        cred_hash,
        nbf,
        &trust,
        &mut status_ok,
        /*verify_hint=*/true,
    );

    // Case B: REVOKED → denied (bit 1 set)
    let mut status_revoked = StatusCache::from_map(vec![(status_list_id.to_string(), vec![0b0000_0010])]);
    run_case(
        "B: revoked → denied",
        cred_id,
        &issuer_sk,
        admin_pk,
        &admin_sk,
        user_pk,
        &user_sk,
        &cred_bytes,
        cred_hash,
        nbf,
        &trust,
        &mut status_revoked,
        /*verify_hint=*/false, // don't panic if verify fails; epochs will handle it
    );
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    label: &str,
    cred_id: &str,
    issuer_sk: &SigningKey,
    admin_pk: [u8; 32],
    admin_sk: &SigningKey,
    user_pk: [u8; 32],
    user_sk: &SigningKey,
    cred_bytes: &[u8],
    cred_hash: [u8; 32],
    nbf: u64,
    trust: &TrustStore,
    status: &mut StatusCache,
    verify_hint: bool,
) {
    // Optional best-effort verification (don’t crash if revoked/invalid)
    if verify_hint {
        let _ = verify_vc(cred_bytes, trust, status);
    }

    // Build ops using known cred_id and user_pk (no need to parse from VC here)
    let cred_op = Op::new(
        vec![],
        Hlc::new(nbf, 1),
        vk_to_bytes(&issuer_sk.verifying_key()),
        Payload::Credential {
            cred_id: cred_id.to_string(),
            cred_bytes: cred_bytes.to_vec(),
            format: CredentialFormat::Jwt,
        },
        issuer_sk,
    );

    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(nbf, 2),
        admin_pk,
        Payload::Grant {
            subject_pk: user_pk,
            cred_hash,
        },
        admin_sk,
    );

    let write_op = Op::new(
        vec![grant_op.op_id],
        Hlc::new(nbf + 1, 7),
        user_pk,
        Payload::Data { key: "mv:o:x".into(), value: b"OK".to_vec() },
        user_sk,
    );

    let mut dag = Dag::new();
    dag.insert(cred_op.clone());
    dag.insert(grant_op.clone());
    dag.insert(write_op.clone());

    let topo = dag.topo_sort();
    let idx = build_auth_epochs_with(&dag, &topo, trust, status);

    let (action, _obj, _field, _elem, tags) = derive_action_and_tags("mv:o:x").unwrap();
    let pos = topo.iter().position(|id| *id == write_op.op_id).unwrap();
    let allowed = is_permitted_at_pos(&idx, &user_pk, action, &tags, pos, write_op.hlc());

    println!("\n== {label} ==");
    println!("order={:?}", topo.iter().map(hex32).collect::<Vec<_>>());
    println!("write {} → {}", hex32(&write_op.op_id), if allowed { "ALLOWED" } else { "DENIED" });
}

fn hex32(arr: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in arr {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
