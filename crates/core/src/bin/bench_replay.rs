//! E6 bench: replay scaling across multiple log sizes.
//!
//! Usage:
//!   cargo run -p ecac-core --bin bench_replay -- \
//!     --sizes 10000,20000,50000,100000,250000,500000 \
//!     --trials 5 --checkpoint 0.9 --out results/e6_replay.csv

use std::env;
use std::fs;
use std::io::Write;
use std::time::Instant;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay;
use ed25519_dalek::SigningKey;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut sizes: Vec<usize> = vec![10_000, 20_000, 50_000, 100_000, 250_000, 500_000];
    let mut trials: usize = 5;
    let mut checkpoint_frac: f64 = 0.9;
    let mut out_path = String::from("results/e6_replay.csv");

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
            "--trials" => {
                i += 1;
                trials = args[i].parse().expect("invalid trials");
            }
            "--checkpoint" => {
                i += 1;
                checkpoint_frac = args[i].parse().expect("invalid checkpoint fraction");
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

    // Ensure output directory exists
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        fs::create_dir_all(parent).expect("create output dir");
    }

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(csv, "log_size,trial,full_replay_ms,incremental_replay_ms,checkpoint_position").unwrap();

    for &size in &sizes {
        eprintln!("--- size={} ---", size);
        // Generate workload once per size (deterministic seed)
        let ops = gen_hb_chain(42, size);

        for trial in 1..=trials {
            // Build DAG
            let mut dag = Dag::new();
            for op in &ops {
                dag.insert(op.clone());
            }

            // Full replay
            let t0 = Instant::now();
            let (_state_full, digest_full) = replay::replay_full(&dag);
            let full_ms = t0.elapsed().as_millis() as u64;

            // Incremental: checkpoint at (checkpoint_frac * size)
            let ckpt_pos = (size as f64 * checkpoint_frac) as usize;
            let mut dag_prefix = Dag::new();
            for op in ops.iter().take(ckpt_pos) {
                dag_prefix.insert(op.clone());
            }
            let (mut state_ck, _) = replay::replay_full(&dag_prefix);

            let t1 = Instant::now();
            let (_state_inc, digest_inc) = replay::apply_incremental(&mut state_ck, &dag);
            let incr_ms = t1.elapsed().as_millis() as u64;

            // Parity check
            assert_eq!(
                digest_full, digest_inc,
                "parity failed: size={}, trial={}",
                size, trial
            );

            writeln!(csv, "{},{},{},{},{}", size, trial, full_ms, incr_ms, ckpt_pos).unwrap();
            eprintln!(
                "  trial {}: full={}ms, incr={}ms (ckpt@{})",
                trial, full_ms, incr_ms, ckpt_pos
            );
        }
    }

    eprintln!("wrote {}", out_path);
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
