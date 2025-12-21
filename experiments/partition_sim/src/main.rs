use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use blake3;
use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay;
use ed25519_dalek::{SigningKey, Signature, Signer};
use hex;

fn parse_sk_hex(hex: &str) -> Result<SigningKey> {
    let b = hex.trim();
    if b.len() != 64 {
        return Err(anyhow!("expected 64 hex chars, got {}", b.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] =
            (hex_nibble(b.as_bytes()[2 * i])? << 4) | hex_nibble(b.as_bytes()[2 * i + 1])?;
    }
    Ok(SigningKey::from_bytes(&out))
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(anyhow!("bad hex nibble {}", b)),
    }
}

fn issuer_key_op(
    issuer_id: &str,
    key_id: &str,
    sk: &SigningKey,
    hlc_ms: u64,
    parents: Vec<OpId>,
) -> Op {
    let pk = vk_to_bytes(&sk.verifying_key());
    Op::new(
        parents,
        Hlc::new(hlc_ms, 1),
        pk,
        Payload::IssuerKey {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            algo: "EdDSA".to_string(),
            pubkey: pk.to_vec(),
            prev_key_id: None,
            valid_from_ms: hlc_ms,
            valid_until_ms: hlc_ms + 86_400_000 * 7,
        },
        sk,
    )
}

fn jwt_compact(
    issuer_id: &str,
    subject_pk_hex: &str,
    role: &str,
    scope_tags: &[&str],
    nbf_ms: u64,
    exp_ms: u64,
    sk: &SigningKey,
) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
    });
    let payload = serde_json::json!({
        "iss": issuer_id,
        "jti": format!("part-{}-{}", issuer_id, nbf_ms),
        "role": role,
        "sub_pk": subject_pk_hex,
        "nbf": nbf_ms,
        "exp": exp_ms,
        "scope": scope_tags,
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(format!("{}.{}.{}", h_b64, p_b64, sig_b64).into_bytes())
}

fn cred_and_grant_ops(
    cred_bytes: Vec<u8>,
    issuer_sk: &SigningKey,
    admin_sk: &SigningKey,
    subject_pk: [u8; 32],
    base_ms: u64,
    parent: OpId,
) -> (Op, Op, [u8; 32]) {
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());
    let cred_hash = blake3::hash(&cred_bytes).into();

    let cred_op = Op::new(
        vec![parent],
        Hlc::new(base_ms, 1),
        issuer_pk,
        Payload::Credential {
            cred_id: "part:cred".to_string(),
            cred_bytes: cred_bytes.clone(),
            format: ecac_core::op::CredentialFormat::Jwt,
        },
        issuer_sk,
    );

    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(base_ms + 1, 1),
        admin_pk,
        Payload::Grant {
            subject_pk,
            cred_hash,
        },
        admin_sk,
    );

    (cred_op, grant_op, cred_hash)
}

fn revoke_op(author_sk: &SigningKey, subject_pk: [u8; 32], role: &str, scope_tags: &[&str], hlc_ms: u64, parent: OpId) -> Op {
    let pk = vk_to_bytes(&author_sk.verifying_key());
    Op::new(
        vec![parent],
        Hlc::new(hlc_ms, 1),
        pk,
        Payload::Revoke {
            subject_pk,
            role: role.to_string(),
            scope_tags: scope_tags.iter().map(|s| s.to_string()).collect(),
            at: Hlc::new(hlc_ms, 0),
        },
        author_sk,
    )
}

fn data_op(author_sk: &SigningKey, key: &str, val: &str, hlc_ms: u64, parent: OpId) -> Op {
    let pk = vk_to_bytes(&author_sk.verifying_key());
    Op::new(
        vec![parent],
        Hlc::new(hlc_ms, 1),
        pk,
        Payload::Data {
            key: key.to_string(),
            value: val.as_bytes().to_vec(),
        },
        author_sk,
    )
}

fn partition_logs(out_a: &Path, out_b: &Path) -> Result<()> {
    let issuer_a_sk = parse_sk_hex(&"aa".repeat(32))?;
    let admin_sk = parse_sk_hex(&"bb".repeat(32))?;
    let subject_sk = parse_sk_hex(&"cc".repeat(32))?;
    let subject_pk = vk_to_bytes(&subject_sk.verifying_key());
    let subject_hex = hex::encode(subject_pk);

    // Partition A: issuer key, VC+grant, some writes, revoke.
    let mut ops_a: Vec<Op> = Vec::new();
    let mut last_a: Option<OpId> = None;
    let mut hlc_a = 1_000u64;

    let ik = issuer_key_op("issuer-A", "kA", &issuer_a_sk, hlc_a, vec![]);
    last_a = Some(ik.op_id);
    ops_a.push(ik);

    hlc_a += 1;
    let vc_bytes = jwt_compact("issuer-A", &subject_hex, "editor", &["confidential"], hlc_a, hlc_a + 1_000_000, &issuer_a_sk)?;
    let (cred, grant, _) = cred_and_grant_ops(vc_bytes, &issuer_a_sk, &admin_sk, subject_pk, hlc_a, last_a.unwrap());
    ops_a.push(cred);
    let grant_id = grant.op_id;
    ops_a.push(grant);
    last_a = Some(grant_id);
    hlc_a += 2;

    for i in 0..50 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("A_pre{i}"), hlc_a, last_a.unwrap());
        last_a = Some(op.op_id);
        ops_a.push(op);
        hlc_a += 1;
    }

    let rev = revoke_op(&admin_sk, subject_pk, "editor", &["confidential"], hlc_a, last_a.unwrap());
    last_a = Some(rev.op_id);
    ops_a.push(rev);
    hlc_a += 1;

    for i in 0..10 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("A_post{i}"), hlc_a, last_a.unwrap());
        last_a = Some(op.op_id);
        ops_a.push(op);
        hlc_a += 1;
    }

    fs::write(out_a, serde_cbor::to_vec(&ops_a)?)?;

    // Partition B: has issuer key + grant (authorized), emits pre- and post-revoke writes.
    let mut ops_b: Vec<Op> = Vec::new();
    let mut last_b: Option<OpId> = None;
    let mut hlc_b = 1_005u64;

    let ik_b = issuer_key_op("issuer-A", "kA", &issuer_a_sk, hlc_b, vec![]);
    last_b = Some(ik_b.op_id);
    ops_b.push(ik_b);
    hlc_b += 1;

    let vc_bytes_b = jwt_compact("issuer-A", &subject_hex, "editor", &["confidential"], hlc_b, hlc_b + 1_000_000, &issuer_a_sk)?;
    let (cred_b, grant_b, _) = cred_and_grant_ops(vc_bytes_b, &issuer_a_sk, &admin_sk, subject_pk, hlc_b, last_b.unwrap());
    ops_b.push(cred_b);
    let grant_b_id = grant_b.op_id;
    ops_b.push(grant_b);
    last_b = Some(grant_b_id);
    hlc_b += 2;

    // Pre-revoke writes.
    for i in 0..20 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("B_pre{i}"), hlc_b, last_b.unwrap());
        last_b = Some(op.op_id);
        ops_b.push(op);
        hlc_b += 1;
    }

    // Post-revoke writes (occur after revoke time; should be skipped post-merge).
    for i in 0..10 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("B_post{i}"), hlc_b, last_b.unwrap());
        last_b = Some(op.op_id);
        ops_b.push(op);
        hlc_b += 1;
    }
    fs::write(out_b, serde_cbor::to_vec(&ops_b)?)?;

    Ok(())
}

fn merge_and_replay(paths: &[&str]) -> Result<()> {
    let mut dag = Dag::new();
    let mut seen = HashSet::new();
    for p in paths {
        let bytes = fs::read(p)?;
        let ops: Vec<Op> = serde_cbor::from_slice(&bytes)?;
        for op in ops {
            if seen.insert(op.op_id) {
                dag.insert(op);
            }
        }
    }
    let (_state, digest) = replay::replay_full(&dag);
    println!("merged replay digest: {:02x?}", digest);
    Ok(())
}

fn main() -> Result<()> {
    let out_a = Path::new("docs/eval/out/partition-A.cbor");
    let out_b = Path::new("docs/eval/out/partition-B.cbor");
    partition_logs(out_a, out_b)?;
    println!("wrote partition logs:\n  {}\n  {}", out_a.display(), out_b.display());

    merge_and_replay(&[out_a.to_str().unwrap(), out_b.to_str().unwrap()])?;
    Ok(())
}
