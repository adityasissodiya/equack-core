//! E2: Cross-platform replay determinism.
//!
//! Replays a fixed CBOR fixture containing concurrency, revoke, and trust events.
//! Asserts the final digest equals a hardcoded hex constant, proving that the
//! replay engine is deterministic regardless of platform.
//!
//! Run: cargo test -p ecac-core --test cross_platform_determinism -- --nocapture

mod util;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay;
use ed25519_dalek::SigningKey;
use util::make_credential_and_grant;

/// Generate the compliance log deterministically.
/// Includes: IssuerKey, Credential, Grant, concurrent Data, Revoke, post-revoke Data.
fn generate_compliance_ops() -> Vec<Op> {
    let issuer_sk = key_pair(1, b"issuer");
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());

    let admin_sk = key_pair(2, b"admin");
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());

    let writer_a_sk = key_pair(3, b"writer_a");
    let writer_a_pk = vk_to_bytes(&writer_a_sk.verifying_key());

    let writer_b_sk = key_pair(4, b"writer_b");
    let writer_b_pk = vk_to_bytes(&writer_b_sk.verifying_key());

    let mut ops = Vec::new();

    // 1) IssuerKey — register the issuer's public key in TrustView
    let issuer_key_op = Op::new(
        vec![],
        Hlc::new(1_000, 1),
        issuer_pk,
        Payload::IssuerKey {
            issuer_id: "issuer-1".to_string(),
            key_id: "k1".to_string(),
            algo: "EdDSA".to_string(),
            pubkey: issuer_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &issuer_sk,
    );
    ops.push(issuer_key_op.clone());

    // 2) Credential + Grant for writer_a (valid 2000..50000)
    let (cred_a, grant_a) = make_credential_and_grant(
        &issuer_sk,
        "issuer-1",
        writer_a_pk,
        "editor",
        &["hv"],
        2_000,
        50_000,
        &admin_sk,
        admin_pk,
    );
    // Set parents to chain after issuer_key_op
    let cred_a = Op::new(
        vec![issuer_key_op.op_id],
        Hlc::new(2_000, 1),
        issuer_pk,
        cred_a.header.payload.clone(),
        &issuer_sk,
    );
    let grant_a = Op::new(
        vec![cred_a.op_id],
        Hlc::new(2_000, 2),
        admin_pk,
        grant_a.header.payload.clone(),
        &admin_sk,
    );
    ops.push(cred_a.clone());
    ops.push(grant_a.clone());

    // 3) Credential + Grant for writer_b (valid 2000..50000)
    let (cred_b, grant_b) = make_credential_and_grant(
        &issuer_sk,
        "issuer-1",
        writer_b_pk,
        "editor",
        &["hv"],
        2_000,
        50_000,
        &admin_sk,
        admin_pk,
    );
    let cred_b = Op::new(
        vec![grant_a.op_id],
        Hlc::new(2_000, 3),
        issuer_pk,
        cred_b.header.payload.clone(),
        &issuer_sk,
    );
    let grant_b = Op::new(
        vec![cred_b.op_id],
        Hlc::new(2_000, 4),
        admin_pk,
        grant_b.header.payload.clone(),
        &admin_sk,
    );
    ops.push(cred_b.clone());
    ops.push(grant_b.clone());

    // 4) Concurrent data ops from both writers (no causal relation between them)
    //    Both branch off grant_b as their common ancestor.
    let mut a_parents = vec![grant_b.op_id];
    let mut b_parents = vec![grant_b.op_id];

    for i in 0..50 {
        // Writer A
        let op_a = Op::new(
            a_parents.clone(),
            Hlc::new(3_000 + i * 2, 1),
            writer_a_pk,
            Payload::Data {
                key: format!("set+:o:x:a{}", i),
                value: vec![],
            },
            &writer_a_sk,
        );
        a_parents = vec![op_a.op_id];
        ops.push(op_a);

        // Writer B (concurrent — same timestamp range, no causal link to A's ops)
        let op_b = Op::new(
            b_parents.clone(),
            Hlc::new(3_000 + i * 2 + 1, 1),
            writer_b_pk,
            Payload::Data {
                key: format!("set+:o:x:b{}", i),
                value: vec![],
            },
            &writer_b_sk,
        );
        b_parents = vec![op_b.op_id];
        ops.push(op_b);
    }

    // 5) Merge point: sync op from admin that sees both chains' tips
    let merge_parents = vec![a_parents[0], b_parents[0]];
    let merge_op = Op::new(
        merge_parents,
        Hlc::new(4_000, 1),
        admin_pk,
        Payload::Data {
            key: "set+:o:x:merged".to_string(),
            value: vec![],
        },
        &admin_sk,
    );
    ops.push(merge_op.clone());

    // 6) REVOKE writer_b
    let revoke_op = Op::new(
        vec![merge_op.op_id],
        Hlc::new(4_500, 1),
        admin_pk,
        Payload::Revoke {
            subject_pk: writer_b_pk,
            role: "editor".to_string(),
            scope_tags: vec!["hv".to_string()],
            at: Hlc::new(4_500, 1),
        },
        &admin_sk,
    );
    ops.push(revoke_op.clone());

    // 7) Post-revoke data from writer_b (should be gated out)
    let mut post_parent = vec![revoke_op.op_id];
    for i in 0..10 {
        let op = Op::new(
            post_parent.clone(),
            Hlc::new(5_000 + i, 1),
            writer_b_pk,
            Payload::Data {
                key: format!("set+:o:x:post_revoke_b{}", i),
                value: vec![],
            },
            &writer_b_sk,
        );
        post_parent = vec![op.op_id];
        ops.push(op);
    }

    // 8) Post-revoke data from writer_a (should still be allowed)
    let mut post_a_parent = vec![revoke_op.op_id];
    for i in 0..10 {
        let op = Op::new(
            post_a_parent.clone(),
            Hlc::new(5_000 + i, 2),
            writer_a_pk,
            Payload::Data {
                key: format!("set+:o:x:post_revoke_a{}", i),
                value: vec![],
            },
            &writer_a_sk,
        );
        post_a_parent = vec![op.op_id];
        ops.push(op);
    }

    ops
}

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn cross_platform_replay_determinism() {
    // Generate ops deterministically
    let ops = generate_compliance_ops();

    // Write fixture if it doesn't exist
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../results/fixtures/compliance_log.cbor");
    if !fixture_path.exists() {
        if let Some(parent) = fixture_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let cbor = serde_cbor::to_vec(&ops).unwrap();
        std::fs::write(&fixture_path, &cbor).unwrap();
        eprintln!("wrote fixture: {} ({} ops, {} bytes)", fixture_path.display(), ops.len(), cbor.len());
    }

    // Load fixture from disk (proves we're replaying the serialized version)
    let fixture_bytes = std::fs::read(&fixture_path)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", fixture_path.display(), e));
    let loaded_ops: Vec<Op> = serde_cbor::from_slice(&fixture_bytes).unwrap();

    // Build DAG and replay
    let mut dag = Dag::new();
    for op in &loaded_ops {
        dag.insert(op.clone());
    }
    let (state, digest) = replay::replay_full(&dag);
    let digest_hex = to_hex(&digest);

    eprintln!("ops: {}", loaded_ops.len());
    eprintln!("digest: {}", digest_hex);
    eprintln!("processed_count: {}", state.processed_count());

    // Hardcoded expected digest — must be identical on all platforms.
    // If this assertion fails, the replay engine's determinism has been broken.
    const EXPECTED: &str =
        "4ea9684a5a81b022ff9cb76dc2d94e601088e772a3420121631f81c9f8bdc2b9";
    assert_eq!(
        digest_hex, EXPECTED,
        "cross-platform digest mismatch!\n  got:    {}\n  expect: {}",
        digest_hex, EXPECTED
    );
}
