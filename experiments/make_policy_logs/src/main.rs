use std::env;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake3;
use ecac_core::crypto::vk_to_bytes;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ed25519_dalek::{SigningKey, Signature, Signer};

fn parse_sk_hex(hex: &str) -> Result<SigningKey> {
    let b = hex.trim();
    if b.len() != 64 {
        return Err(anyhow!("expected 64 hex chars for sk, got {}", b.len()));
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

fn jwt_compact(
    issuer_id: &str,
    subject_pk_hex: &str,
    role: &str,
    scope_tags: &[&str],
    nbf_ms: u64,
    exp_ms: u64,
    sk: &SigningKey,
) -> Result<Vec<u8>> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
    });
    let payload = serde_json::json!({
        "iss": issuer_id,
        "jti": format!("{}-{}", issuer_id, nbf_ms),
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
            valid_until_ms: hlc_ms + 86_400_000 * 7, // +7 days
        },
        sk,
    )
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
            cred_id: "e3-cred".to_string(),
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

fn e3_log(out: &Path) -> Result<()> {
    let issuer_sk = parse_sk_hex(&"11".repeat(32))?;
    let admin_sk = parse_sk_hex(&"22".repeat(32))?;
    let subject_sk = parse_sk_hex(&"33".repeat(32))?;
    let subject_pk = vk_to_bytes(&subject_sk.verifying_key());

    let mut ops: Vec<Op> = Vec::new();
    let mut last: Option<OpId> = None;
    let mut hlc_ms: u64 = 1_000;

    // IssuerKey
    let ik = issuer_key_op("issuer-A", "k1", &issuer_sk, hlc_ms, last.into_iter().collect());
    last = Some(ik.op_id);
    ops.push(ik);

    // VC (editor, scope=confidential)
    hlc_ms += 1;
    let vc_bytes = jwt_compact("issuer-A", &hex::encode(subject_pk), "editor", &["confidential"], hlc_ms, hlc_ms + 1_000_000, &issuer_sk)?;
    let (cred_op, grant_op, _cred_hash) = cred_and_grant_ops(vc_bytes, &issuer_sk, &admin_sk, subject_pk, hlc_ms, last.unwrap());
    ops.push(cred_op);
    let grant_id = grant_op.op_id;
    ops.push(grant_op);
    last = Some(grant_id);
    hlc_ms += 2;

    // Data writes before revoke (1..500)
    for i in 0..500 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("v{i}"), hlc_ms, last.unwrap());
        last = Some(op.op_id);
        ops.push(op);
        hlc_ms += 1;
    }

    // Revoke at this point
    let revoke = revoke_op(&admin_sk, subject_pk, "editor", &["confidential"], hlc_ms, last.unwrap());
    last = Some(revoke.op_id);
    ops.push(revoke);
    hlc_ms += 1;

    // Data writes after revoke (should be skipped)
    for i in 500..1000 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("v{i}"), hlc_ms, last.unwrap());
        last = Some(op.op_id);
        ops.push(op);
        hlc_ms += 1;
    }

    let bytes = serde_cbor::to_vec(&ops)?;
    fs::write(out, &bytes).with_context(|| format!("write {}", out.display()))?;
    println!("E3 log written: {} ({} ops)", out.display(), ops.len());
    Ok(())
}

fn e4_log(out: &Path) -> Result<()> {
    let issuer_a_sk = parse_sk_hex(&"44".repeat(32))?;
    let issuer_b_sk = parse_sk_hex(&"55".repeat(32))?;
    let issuer_c_sk = parse_sk_hex(&"66".repeat(32))?;
    let admin_sk = parse_sk_hex(&"77".repeat(32))?;
    let subject_sk = parse_sk_hex(&"88".repeat(32))?;
    let subject_pk = vk_to_bytes(&subject_sk.verifying_key());

    let mut ops: Vec<Op> = Vec::new();
    let mut last: Option<OpId> = None;
    let mut hlc_ms: u64 = 2_000;

    // Issuer keys A, B, C
    for (issuer_id, key_id, sk) in [
        ("issuer-A", "kA", &issuer_a_sk),
        ("issuer-B", "kB", &issuer_b_sk),
        ("issuer-C", "kC", &issuer_c_sk),
    ] {
        let op = issuer_key_op(issuer_id, key_id, sk, hlc_ms, last.into_iter().collect());
        last = Some(op.op_id);
        ops.push(op);
        hlc_ms += 1;
    }

    // VC from issuer A
    let vc_a = jwt_compact("issuer-A", &hex::encode(subject_pk), "editor", &["confidential"], hlc_ms, hlc_ms + 1_000_000, &issuer_a_sk)?;
    let (cred_a, grant_a, _) = cred_and_grant_ops(vc_a, &issuer_a_sk, &admin_sk, subject_pk, hlc_ms, last.unwrap());
    let grant_a_id = grant_a.op_id;
    ops.push(cred_a);
    ops.push(grant_a);
    last = Some(grant_a_id);
    hlc_ms += 2;

    // VC from issuer B (concurrent grant)
    let vc_b = jwt_compact("issuer-B", &hex::encode(subject_pk), "editor", &["confidential"], hlc_ms, hlc_ms + 1_000_000, &issuer_b_sk)?;
    let (cred_b, grant_b, _) = cred_and_grant_ops(vc_b, &issuer_b_sk, &admin_sk, subject_pk, hlc_ms, last.unwrap());
    let grant_b_id = grant_b.op_id;
    ops.push(cred_b);
    ops.push(grant_b);
    last = Some(grant_b_id);
    hlc_ms += 2;

    // Writes before revoke
    for i in 0..100 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("pre{i}"), hlc_ms, last.unwrap());
        last = Some(op.op_id);
        ops.push(op);
        hlc_ms += 1;
    }

    // Revoke by issuer C
    let rev = revoke_op(&issuer_c_sk, subject_pk, "editor", &["confidential"], hlc_ms, last.unwrap());
    last = Some(rev.op_id);
    ops.push(rev);
    hlc_ms += 1;

    // Writes after revoke (should be skipped)
    for i in 0..20 {
        let op = data_op(&subject_sk, "mv:o:x", &format!("post{i}"), hlc_ms, last.unwrap());
        last = Some(op.op_id);
        ops.push(op);
        hlc_ms += 1;
    }

    let bytes = serde_cbor::to_vec(&ops)?;
    fs::write(out, &bytes).with_context(|| format!("write {}", out.display()))?;
    println!("E4 log written: {} ({} ops)", out.display(), ops.len());
    Ok(())
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or_else(|| anyhow!("usage: make_policy_logs <e3|e4> <out.cbor>"))?;
    let out = args
        .next()
        .ok_or_else(|| anyhow!("missing output path"))?;
    let out_path = Path::new(&out);

    match mode.as_str() {
        "e3" => e3_log(out_path)?,
        "e4" => e4_log(out_path)?,
        other => return Err(anyhow!("unknown mode {}", other)),
    }

    Ok(())
}
