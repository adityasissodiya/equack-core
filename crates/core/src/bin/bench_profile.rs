//! W4 profiling bench: phase breakdown of replay on the 8-writer concurrent
//! workload (the same workload that drives E7's "concurrent" row).
//!
//! Why this exists. perf/cargo-flamegraph is unavailable on the revision host
//! (perf_event_paranoid=4, no CAP_PERFMON), so this bench reproduces the
//! replay pipeline phase by phase with `Instant::now()` so we can attribute
//! wall time to:
//!
//!   * dag_insert      -- structural insertion into the DAG
//!   * topo_sort       -- Algorithm 1 (Kahn + deterministic min-heap)
//!   * mvreg_apply     -- the inner loop's MVReg HB-aware put, which is the
//!                        suspected hotspot for concurrent writers (each put
//!                        walks `dag_is_ancestor` over prior winners)
//!   * sig_verify      -- ed25519 signature verification per op
//!   * digest          -- terminal blake3 digest of the materialized state
//!   * replay_full     -- the unmodified `replay::replay_full` for parity
//!
//! The MVReg+HB phase reproduces what `apply_over_order` does for DATA ops
//! when no policy events are present (gen_concurrent has none, so the gate
//! is always allow). The signature-verify phase isolates `Op::verify` so we
//! can separate crypto cost from CRDT cost. Numbers are reported per-call
//! and as a percentage of replay_full to make hotspot identification trivial.
//!
//! Usage:
//!   cargo run -p ecac-core --bin bench_profile --release -- \
//!       --ops 10000 --writers 8 --out results/w4_profile.csv

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
use ecac_core::state::State;
use ed25519_dalek::SigningKey;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut ops_n: usize = 10_000;
    let mut writers: usize = 8;
    let mut seed: u64 = 0xC0FFEE;
    let mut out_path = String::from("results/w4_profile.csv");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ops" => {
                i += 1;
                ops_n = args[i].parse().expect("--ops <usize>");
            }
            "--writers" => {
                i += 1;
                writers = args[i].parse().expect("--writers <usize>");
            }
            "--seed" => {
                i += 1;
                seed = args[i].parse().expect("--seed <u64>");
            }
            "--out" => {
                i += 1;
                out_path = args[i].clone();
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        fs::create_dir_all(parent).expect("create output dir");
    }

    eprintln!(
        "[W4-profile] ops={} writers={} seed=0x{:x}",
        ops_n, writers, seed
    );

    let ops = gen_concurrent_writers(seed, ops_n, writers);

    // Phase 1: DAG insert -- pure structural cost.
    let mut dag = Dag::new();
    let t = Instant::now();
    for op in &ops {
        dag.insert(op.clone());
    }
    let dag_insert_ms = t.elapsed().as_micros() as u64;

    // Phase 2: topo_sort.
    let t = Instant::now();
    let order = dag.topo_sort();
    let topo_sort_ms = t.elapsed().as_micros() as u64;
    assert_eq!(order.len(), ops.len());

    // Phase 3: signature verification (Op::verify) over the topo order.
    let t = Instant::now();
    let mut verified = 0usize;
    for id in &order {
        if let Some(op) = dag.get(id) {
            if op.verify() {
                verified += 1;
            }
        }
    }
    let sig_verify_ms = t.elapsed().as_micros() as u64;

    // Phase 4: MVReg HB-aware put loop. Reproduces apply_over_order's data
    // path for the concurrent workload (no policy events => gate is allow).
    // We thread the same `dag_is_ancestor` walker the real replay uses.
    let mut state = State::new();
    let t = Instant::now();
    for id in &order {
        let Some(op) = dag.get(id) else { continue };
        if let Payload::Data { key, value } = &op.header.payload {
            // Concurrent generator uses key="mv:o:x"; mirror policy::derive
            // by stripping the "mv:" prefix and the "o:x" object/field.
            let (obj, field) = ("o", "x");
            let _ = key; // hardcoded for the concurrent workload
            let mv = state.mv_field_mut(obj, field);
            mv.apply_put(*id, value.clone(), |a, b| local_dag_is_ancestor(&dag, a, b));
        }
    }
    let mvreg_apply_ms = t.elapsed().as_micros() as u64;

    // Phase 5: terminal digest.
    let t = Instant::now();
    let _digest = state.digest();
    let digest_ms = t.elapsed().as_micros() as u64;

    // Phase 6: end-to-end replay_full for parity.
    let t = Instant::now();
    let (_state2, _digest2) = replay::replay_full(&dag);
    let replay_full_ms = t.elapsed().as_micros() as u64;

    let pct = |x: u64| -> f64 {
        if replay_full_ms == 0 {
            0.0
        } else {
            100.0 * (x as f64) / (replay_full_ms as f64)
        }
    };

    eprintln!("--- phase breakdown (microseconds) ---");
    eprintln!("dag_insert    : {:>10} us", dag_insert_ms);
    eprintln!("topo_sort     : {:>10} us  ({:5.1}% of replay_full)", topo_sort_ms, pct(topo_sort_ms));
    eprintln!("sig_verify    : {:>10} us  ({:5.1}% of replay_full)  [{} verified]", sig_verify_ms, pct(sig_verify_ms), verified);
    eprintln!("mvreg_apply   : {:>10} us  ({:5.1}% of replay_full)", mvreg_apply_ms, pct(mvreg_apply_ms));
    eprintln!("digest        : {:>10} us  ({:5.1}% of replay_full)", digest_ms, pct(digest_ms));
    eprintln!("replay_full   : {:>10} us  (100.0%)", replay_full_ms);

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(
        csv,
        "scenario,ops,writers,dag_insert_us,topo_sort_us,sig_verify_us,mvreg_apply_us,digest_us,replay_full_us"
    )
    .unwrap();
    writeln!(
        csv,
        "concurrent,{ops_n},{writers},{dag_insert_ms},{topo_sort_ms},{sig_verify_ms},{mvreg_apply_ms},{digest_ms},{replay_full_ms}"
    )
    .unwrap();
    eprintln!("wrote {}", out_path);
}

fn local_dag_is_ancestor(dag: &Dag, a: &OpId, b: &OpId) -> bool {
    if a == b {
        return false;
    }
    let mut stack = vec![*b];
    let mut seen: HashSet<OpId> = HashSet::new();
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur) {
            continue;
        }
        if let Some(op) = dag.get(&cur) {
            for p in &op.header.parents {
                if p == a {
                    return true;
                }
                stack.push(*p);
            }
        }
    }
    false
}

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn gen_concurrent_writers(seed: u64, n: usize, writers: usize) -> Vec<Op> {
    let n_authors = writers.clamp(2, 8);
    let sks: Vec<SigningKey> = (0..n_authors)
        .map(|i| key_pair(seed, format!("concurrent/{i}").as_bytes()))
        .collect();
    let pks: Vec<[u8; 32]> = sks
        .iter()
        .map(|sk| vk_to_bytes(&sk.verifying_key()))
        .collect();
    let mut parents: Vec<Vec<OpId>> = vec![Vec::new(); n_authors];

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let a = i % n_authors;
        let payload = Payload::Data {
            key: "mv:o:x".to_string(),
            value: format!("v{i}").into_bytes(),
        };
        let tick = 1_000u64 + i as u64;
        let op = Op::new(
            parents[a].clone(),
            Hlc::new(tick, (i as u32) + 1),
            pks[a],
            payload,
            &sks[a],
        );
        parents[a].clear();
        parents[a].push(op.op_id);
        out.push(op);
    }
    out
}
