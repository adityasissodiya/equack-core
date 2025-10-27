use blake3::Hasher;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer};
use serde_json::json;

use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::crypto::vk_to_bytes;
use ecac_core::op::CredentialFormat; // re-exported alias from lib

/// Build a compact JWT (header.payload.signature) with Ed25519, then the ops:
///   1) Credential { cred_id, cred_bytes, format=Jwt }
///   2) Grant      { subject_pk, cred_hash }
///
/// `nbf_phys` / `exp_phys` are milliseconds since epoch (u64) used as VC times.
/// The two returned ops are linked: the Grant has the Credential as its parent.
pub fn make_credential_and_grant(
    issuer_sk: &SigningKey,
    issuer_id: &str,
    subject_pk: [u8; 32],
    role: &str,
    scope: &[&str],
    nbf_phys: u64,
    exp_phys: u64,
    admin_sk: &SigningKey,
    admin_pk_bytes: [u8; 32],
) -> (Op, Op) {
    // 1) Make a compact JWT with EdDSA header and fixed claims
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = json!({
        "sub_pk": hex(subject_pk),
        "role": role,
        "scope": scope,
        "nbf": nbf_phys,
        "exp": exp_phys,
        "iss": issuer_id,
        "jti": "test-cred-1",
        "status": { "id": "list-0", "index": 0 }
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{payload}");

    // Sign over ASCII "header.payload"
    let sig: Signature = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");
    let cred_bytes = compact.as_bytes().to_vec();

    // cred_hash = blake3(compact_jwt_bytes)
    let mut h = Hasher::new();
    h.update(&cred_bytes);
    let cred_hash: [u8; 32] = h.finalize().into();

    // 2) Emit ops (Credential, then Grant{cred_hash})
    let issuer_vk = VerifyingKey::from(issuer_sk);
    let issuer_pk_bytes = vk_to_bytes(&issuer_vk);

    let cred_op = Op::new(
        vec![],
        Hlc::new(nbf_phys, 1),
        issuer_pk_bytes,
        Payload::Credential {
            cred_id: "test-cred-1".to_string(),
            cred_bytes: cred_bytes.clone(),
            format: CredentialFormat::Jwt,
        },
        issuer_sk,
    );

    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(nbf_phys, 2),
        admin_pk_bytes,
        Payload::Grant { subject_pk, cred_hash },
        admin_sk,
    );

    (cred_op, grant_op)
}

fn hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
