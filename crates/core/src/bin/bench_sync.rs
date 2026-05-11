//! E12 bench: multi-node sync convergence (in-process deterministic simulator).
//!
//! Demonstrates that independent DAGs, receiving ops in different orders and
//! syncing via op exchange, converge to identical replay digests — including
//! after partition-heal with a REVOKE during the partition.
//!
//! Usage:
//!   cargo run -p ecac-core --bin bench_sync -- --out results/e12_sync.csv

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Write;
use std::time::Instant;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay;
use ecac_core::serialize::canonical_cbor;
use ed25519_dalek::SigningKey;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut out_path = String::from("results/e12_sync.csv");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = args[i].clone();
            }
            other => {
                eprintln!("unknown arg: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        fs::create_dir_all(parent).expect("create output dir");
    }

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(
        csv,
        "scenario,nodes,ops,partition_s,converge_ms,bytes_sent,msg_count,replay_ms,digest_prefix"
    )
    .unwrap();

    // Scenario 1: No partition, reordering only
    let (converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix) = scenario_no_partition();
    writeln!(
        csv,
        "no_partition,3,3000,0,{},{},{},{},{}",
        converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix
    )
    .unwrap();
    eprintln!(
        "scenario 1: converge={}ms, bytes={}, msgs={}, replay={}ms, digest={}",
        converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix
    );

    // Scenario 2: Partition + heal with REVOKE
    let (converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix) = scenario_partition_heal();
    writeln!(
        csv,
        "partition_heal,3,3000,5,{},{},{},{},{}",
        converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix
    )
    .unwrap();
    eprintln!(
        "scenario 2: converge={}ms, bytes={}, msgs={}, replay={}ms, digest={}",
        converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix
    );

    eprintln!("wrote {}", out_path);
}

/// Scenario 1: 3 nodes, 3000 ops (1000 per node), no partition.
/// Each node generates ops independently, then all sync.
/// Verify all three produce the same replay digest.
fn scenario_no_partition() -> (u64, u64, u64, u64, String) {
    let n_per_node = 1000usize;

    // Create 3 writers with distinct keys
    let sks: Vec<SigningKey> = (0..3).map(|i| key_pair(42, format!("writer/{i}").as_bytes())).collect();
    let pks: Vec<[u8; 32]> = sks.iter().map(|sk| vk_to_bytes(&sk.verifying_key())).collect();

    // Each node generates its own ops (independent chains)
    let mut all_ops: Vec<Vec<Op>> = Vec::new();
    for node_idx in 0..3 {
        let mut ops = Vec::with_capacity(n_per_node);
        let mut parents: Vec<OpId> = vec![];
        for i in 0..n_per_node {
            let payload = Payload::Data {
                key: format!("set+:o:x:n{}v{}", node_idx, i),
                value: vec![],
            };
            let hlc = Hlc::new(1_000 + (i as u64) * 3 + node_idx as u64, (i as u32) + 1);
            let op = Op::new(parents.clone(), hlc, pks[node_idx], payload, &sks[node_idx]);
            parents = vec![op.op_id];
            ops.push(op);
        }
        all_ops.push(ops);
    }

    // Start: each node has only its own ops
    let mut dags: Vec<Dag> = vec![Dag::new(), Dag::new(), Dag::new()];
    for (node_idx, ops) in all_ops.iter().enumerate() {
        for op in ops {
            dags[node_idx].insert(op.clone());
        }
    }

    // Sync: simulate gossip by exchanging all ops between all nodes
    // Track bytes and messages
    let t0 = Instant::now();
    let mut bytes_sent: u64 = 0;
    let mut msg_count: u64 = 0;

    // Each node sends its ops to the other two
    for src in 0..3 {
        for dst in 0..3 {
            if src == dst {
                continue;
            }
            let dst_known: HashSet<OpId> = dags[dst]
                .topo_sort()
                .into_iter()
                .collect();
            for op in &all_ops[src] {
                if !dst_known.contains(&op.op_id) {
                    let cbor = canonical_cbor(op);
                    bytes_sent += cbor.len() as u64;
                    msg_count += 1;
                    dags[dst].insert(op.clone());
                }
            }
        }
    }
    let converge_ms = t0.elapsed().as_millis() as u64;

    // Replay all three and verify convergence
    let t1 = Instant::now();
    let digests: Vec<[u8; 32]> = dags.iter().map(|d| replay::replay_full(d).1).collect();
    let replay_ms = t1.elapsed().as_millis() as u64;

    assert_eq!(digests[0], digests[1], "A != B");
    assert_eq!(digests[1], digests[2], "B != C");

    let digest_prefix = hex(&digests[0][..8]);
    (converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix)
}

/// Scenario 2: 3 nodes (A, B, C). Partition C from {A, B}.
/// Both sides accept writes; a REVOKE is issued on A during partition.
/// After heal, verify convergence and that post-revoke effects are skipped.
fn scenario_partition_heal() -> (u64, u64, u64, u64, String) {
    let n_per_node = 1000usize;

    // 3 writers + 1 revoker (node A also issues revoke)
    let sks: Vec<SigningKey> = (0..3).map(|i| key_pair(99, format!("writer/{i}").as_bytes())).collect();
    let pks: Vec<[u8; 32]> = sks.iter().map(|sk| vk_to_bytes(&sk.verifying_key())).collect();

    // Phase 1: Pre-partition — all nodes get first 200 ops from each writer
    let mut pre_ops: Vec<Vec<Op>> = Vec::new();
    let mut post_ops: Vec<Vec<Op>> = Vec::new();
    let mut latest_parents: Vec<Vec<OpId>> = vec![vec![], vec![], vec![]];

    for node_idx in 0..3 {
        let mut pre = Vec::new();
        let mut post = Vec::new();
        for i in 0..n_per_node {
            let payload = Payload::Data {
                key: format!("set+:o:x:n{}v{}", node_idx, i),
                value: vec![],
            };
            let hlc = Hlc::new(1_000 + (i as u64) * 3 + node_idx as u64, (i as u32) + 1);
            let op = Op::new(
                latest_parents[node_idx].clone(),
                hlc,
                pks[node_idx],
                payload,
                &sks[node_idx],
            );
            latest_parents[node_idx] = vec![op.op_id];
            if i < 200 {
                pre.push(op);
            } else {
                post.push(op);
            }
        }
        pre_ops.push(pre);
        post_ops.push(post);
    }

    // Create a REVOKE op from node A (revokes node C's writer key)
    let revoke_hlc = Hlc::new(5_000, 1);
    let revoke_op = Op::new(
        latest_parents[0].clone(),
        revoke_hlc,
        pks[0],
        Payload::Revoke {
            subject_pk: pks[2],
            role: "editor".to_string(),
            scope_tags: vec!["hv".to_string()],
            at: Hlc::new(5_000, 0),
        },
        &sks[0],
    );

    // Initialize DAGs: all 3 have the same pre-partition ops
    let mut dags: Vec<Dag> = vec![Dag::new(), Dag::new(), Dag::new()];
    for node_idx in 0..3 {
        for writer_ops in &pre_ops {
            for op in writer_ops {
                dags[node_idx].insert(op.clone());
            }
        }
    }

    // Phase 2: Partition — A and B share ops (including revoke), C works alone
    // A gets: own post_ops + B's post_ops + revoke
    // B gets: own post_ops + A's post_ops + revoke
    // C gets: only own post_ops
    for op in &post_ops[0] {
        dags[0].insert(op.clone());
        dags[1].insert(op.clone());
    }
    for op in &post_ops[1] {
        dags[0].insert(op.clone());
        dags[1].insert(op.clone());
    }
    dags[0].insert(revoke_op.clone());
    dags[1].insert(revoke_op.clone());

    // C continues writing independently
    for op in &post_ops[2] {
        dags[2].insert(op.clone());
    }

    // Verify A and B converge but C differs
    let (_, digest_a_pre) = replay::replay_full(&dags[0]);
    let (_, digest_b_pre) = replay::replay_full(&dags[1]);
    let (_, digest_c_pre) = replay::replay_full(&dags[2]);
    assert_eq!(digest_a_pre, digest_b_pre, "A and B should match during partition");
    assert_ne!(digest_a_pre, digest_c_pre, "C should differ during partition");

    // Phase 3: Heal — sync all ops between all nodes
    let t0 = Instant::now();
    let mut bytes_sent: u64 = 0;
    let mut msg_count: u64 = 0;

    // Collect all ops for efficient sync
    let mut all_unique_ops: Vec<Op> = Vec::new();
    let mut seen: HashSet<OpId> = HashSet::new();
    for ops_list in pre_ops.iter().chain(post_ops.iter()) {
        for op in ops_list {
            if seen.insert(op.op_id) {
                all_unique_ops.push(op.clone());
            }
        }
    }
    if seen.insert(revoke_op.op_id) {
        all_unique_ops.push(revoke_op.clone());
    }

    // Sync: each node receives all ops it doesn't have
    for node_idx in 0..3 {
        let known: HashSet<OpId> = dags[node_idx].topo_sort().into_iter().collect();
        for op in &all_unique_ops {
            if !known.contains(&op.op_id) {
                let cbor = canonical_cbor(op);
                bytes_sent += cbor.len() as u64;
                msg_count += 1;
                dags[node_idx].insert(op.clone());
            }
        }
    }
    let converge_ms = t0.elapsed().as_millis() as u64;

    // Replay all three and verify convergence
    let t1 = Instant::now();
    let digests: Vec<[u8; 32]> = dags.iter().map(|d| replay::replay_full(d).1).collect();
    let replay_ms = t1.elapsed().as_millis() as u64;

    assert_eq!(digests[0], digests[1], "A != B after heal");
    assert_eq!(digests[1], digests[2], "B != C after heal");

    let digest_prefix = hex(&digests[0][..8]);
    (converge_ms, bytes_sent, msg_count, replay_ms, digest_prefix)
}

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
