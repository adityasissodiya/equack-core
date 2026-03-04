//! E8 bench: storage growth (log + checkpoints) at various op counts.
//!
//! Usage:
//!   cargo run -p ecac-store --bin bench_storage -- \
//!     --sizes 10000,50000,100000,500000 \
//!     --out results/e8_storage.csv

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay;
use ecac_core::serialize::canonical_cbor;
use ecac_store::{Store, StoreOptions};
use ed25519_dalek::SigningKey;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut sizes: Vec<usize> = vec![10_000, 50_000, 100_000, 500_000];
    let mut out_path = String::from("results/e8_storage.csv");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sizes" => {
                i += 1;
                sizes = args[i]
                    .split(',')
                    .map(|s| s.trim().parse::<usize>().expect("invalid size"))
                    .collect();
            }
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

    if let Some(parent) = Path::new(&out_path).parent() {
        fs::create_dir_all(parent).expect("create output dir");
    }

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(csv, "op_count,log_bytes,checkpoint_bytes,total_store_bytes,bytes_per_op").unwrap();

    for &size in &sizes {
        eprintln!("--- size={} ---", size);

        // Generate workload
        let ops = gen_hb_chain(42, size);

        // Measure raw CBOR op sizes
        let raw_cbor_total: u64 = ops.iter().map(|op| canonical_cbor(op).len() as u64).sum();

        // Create temp store
        let tmp = tempfile::tempdir().expect("create tmpdir");
        let store_path = tmp.path().join("bench.db");
        let store = Store::open(
            &store_path,
            StoreOptions {
                create_if_missing: true,
                sync_writes: false, // faster for bench
            },
        )
        .expect("open store");

        // Insert all ops
        for op in &ops {
            let cbor = canonical_cbor(op);
            store.put_op_cbor(&cbor).expect("put op");
        }

        // Create checkpoint and measure its CBOR size directly
        let mut dag = Dag::new();
        for op in &ops {
            dag.insert(op.clone());
        }
        let (state, _digest) = replay::replay_full(&dag);
        let checkpoint_cbor = canonical_cbor(&state);
        let checkpoint_bytes = checkpoint_cbor.len() as u64;

        store
            .checkpoint_create(&state, size as u64)
            .expect("checkpoint create");

        // Measure total store directory size
        let total_store_bytes = dir_size(&store_path);
        let bytes_per_op = total_store_bytes / size as u64;

        writeln!(
            csv,
            "{},{},{},{},{}",
            size, raw_cbor_total, checkpoint_bytes, total_store_bytes, bytes_per_op
        )
        .unwrap();
        eprintln!(
            "  raw_cbor={}KB, ckpt_state={}B, store={}KB, {:.0}B/op",
            raw_cbor_total / 1024,
            checkpoint_bytes,
            total_store_bytes / 1024,
            bytes_per_op
        );

        drop(store);
        drop(tmp);
    }

    eprintln!("wrote {}", out_path);
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = entry.metadata().unwrap();
            if meta.is_file() {
                total += meta.len();
            } else if meta.is_dir() {
                total += dir_size(&entry.path());
            }
        }
    }
    total
}

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    let mut bytes = [0u8; 32];
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
