#![cfg(feature = "audit")]

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay::replay_full_with_audit;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

use ecac_store::audit::AuditReader;
use ecac_store::StoreAuditHook;

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut bytes = [0u8; 32];
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn gen_hb_chain(seed: u64, n: usize) -> Vec<Op> {
    let sk = key_pair(seed, b"hb");
    let pk = vk_to_bytes(&sk.verifying_key());
    let mut out = Vec::with_capacity(n);
    let mut parents: Vec<OpId> = vec![];
    let mut logical = 1u32;
    for i in 0..n {
        let payload = Payload::Data {
            key: "mv:o:x".to_string(),
            value: format!("v{i}").into_bytes(),
        };
        let op = Op::new(
            parents.clone(),
            Hlc::new(1_000 + i as u64, logical),
            pk,
            payload,
            &sk,
        );
        parents = vec![op.op_id];
        logical = logical.saturating_add(1);
        out.push(op);
    }
    out
}

#[test]
fn audit_end_to_end_roundtrip() {
    // DAG
    let ops = gen_hb_chain(7, 50);
    let mut dag = Dag::new();
    for op in &ops {
        dag.insert(op.clone());
    }

    // Sink writing to disk
    let tmp = tempdir().unwrap();
    let audit_dir = tmp.path().join("audit");
    let sk = key_pair(99, b"node");
    let node_id: [u8; 32] = blake3::hash(b"node-99").as_bytes()[..32]
        .try_into()
        .unwrap();
    let mut sink = StoreAuditHook::open(&audit_dir, sk, node_id).unwrap();

    // Replay with audit
    let (_state, _digest) = replay_full_with_audit(&dag, &mut sink);

    // Verify the audit chain
    let reader = AuditReader::open(&audit_dir).unwrap();
    reader.verify().unwrap();
}
