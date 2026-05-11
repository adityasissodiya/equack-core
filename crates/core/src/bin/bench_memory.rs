//! E9 bench: peak RSS during replay at various log sizes.
//!
//! Usage:
//!   cargo run -p ecac-core --bin bench_memory -- \
//!     --sizes 20000,100000,250000 \
//!     --out results/e9_memory.csv

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

    let mut sizes: Vec<usize> = vec![20_000, 100_000, 250_000];
    let mut out_path = String::from("results/e9_memory.csv");

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

    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        fs::create_dir_all(parent).expect("create output dir");
    }

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(csv, "log_size,peak_rss_bytes,replay_ms").unwrap();

    for &size in &sizes {
        eprintln!("--- size={} ---", size);

        // Generate workload
        let ops = gen_hb_chain(42, size);

        // Build DAG
        let mut dag = Dag::new();
        for op in &ops {
            dag.insert(op.clone());
        }

        // Record RSS before replay
        let _rss_before = peak_rss_bytes();

        // Full replay
        let t0 = Instant::now();
        let (_state, _digest) = replay::replay_full(&dag);
        let replay_ms = t0.elapsed().as_millis() as u64;

        // Record peak RSS after replay
        let rss_after = peak_rss_bytes();

        writeln!(csv, "{},{},{}", size, rss_after, replay_ms).unwrap();
        eprintln!(
            "  peak_rss={}MB, replay={}ms",
            rss_after / (1024 * 1024),
            replay_ms
        );

        // Drop to free memory before next iteration
        drop(_state);
        drop(dag);
    }

    eprintln!("wrote {}", out_path);
}

/// Read peak RSS (VmHWM) from /proc/self/status on Linux.
/// Falls back to current RSS (VmRSS) if VmHWM is unavailable.
fn peak_rss_bytes() -> u64 {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    // Try VmHWM first (peak RSS), then VmRSS (current RSS)
    for key in ["VmHWM:", "VmRSS:"] {
        for line in status.lines() {
            if line.starts_with(key) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb * 1024; // /proc reports in kB
                    }
                }
            }
        }
    }
    0
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
