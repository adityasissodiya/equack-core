use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ed25519_dalek::SigningKey;

/// Deterministic keypair (matches bench style).
fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut bytes = [0u8; 32];
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

/// Minimal hb-chain generator for test.
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
fn replay_parity_hb_chain_full_vs_incremental() {
    let n = 200usize;
    let seed = 42u64;
    let ops = gen_hb_chain(seed, n);

    // Full DAG
    let mut dag = Dag::new();
    for op in &ops {
        dag.insert(op.clone());
    }

    // Full replay
    let (_state_full, digest_full) = ecac_core::replay::replay_full(&dag);

    // Build a checkpoint state from a clean prefix to avoid double-processing tail.
    let suffix = std::cmp::max(1, n / 10);
    let checkpoint_idx = n.saturating_sub(suffix);

    let mut dag_prefix = Dag::new();
    for op in ops.iter().take(checkpoint_idx) {
        dag_prefix.insert(op.clone());
    }
    let (mut state_ck, _digest_ck) = ecac_core::replay::replay_full(&dag_prefix);

    // Incremental apply over the full DAG
    let (_state_inc, digest_inc) = ecac_core::replay::apply_incremental(&mut state_ck, &dag);

    // Parity: digests must match
    assert_eq!(
        digest_full, digest_inc,
        "full vs incremental digest mismatch"
    );
}
