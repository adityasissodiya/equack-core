use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpHeader, OpId, Payload};
use ecac_core::metrics::METRICS;

/// CLI-facing options (kept simple & deterministic).
pub struct Options {
    pub scenario: String,
    pub seed: u64,
    pub ops: usize,
    pub peers: usize,
    pub net: bool,
    pub partition: Option<PathBuf>,
    pub checkpoint_every: Option<usize>,
    pub out_dir: PathBuf,
}

pub fn run(opts: Options) -> Result<()> {
    // Guard: M7 is measurement-only. Net scenarios require later wiring.
    if opts.net {
        return Err(anyhow!(
            "--net is not supported in this drop. Run local scenarios (hb-chain | concurrent) without --net."
        ));
    }

    fs::create_dir_all(&opts.out_dir)?;

    // Start clean & pre-register all keys we want in the CSV (stable schema).
    METRICS.reset();
    // Counters
   for k in [
        "ops_total",
        "ops_applied",
        "ops_skipped_policy",
        "revocations_seen",
        "ops_invalidated_by_revoke",
        "epochs_total",
        "gossip_announces_sent",
        "gossip_announces_recv",
        "fetch_batches",
        "ops_fetched",
        "ops_duplicates_dropped",
        "orset_tombstones_total",
    ] {
        METRICS.inc(k, 0);
    }
    // Histograms
    for h in [
        "replay_full_ms",
        "replay_incremental_ms",
        "epoch_build_ms",
        "mvreg_concurrent_winners",
        "batch_write_ms",
        "checkpoint_create_ms",
        "checkpoint_load_ms",
        "convergence_ms",
    ] {
        METRICS.observe_ms(h, 0);
    }

    // Generate a synthetic op set deterministically
    let ops = match opts.scenario.as_str() {
        "hb-chain" => gen_hb_chain(opts.seed, opts.ops)?,
        "concurrent" => gen_concurrent_writers(opts.seed, opts.ops)?,
        other => {
            return Err(anyhow!(
                "unsupported scenario '{}'. Supported: hb-chain, concurrent",
                other
            ))
        }
    };

    // Build full DAG for replay
    let mut dag = Dag::new();
    for op in &ops {
        dag.insert(op.clone());
    }

    // Measure full replay (core will also record replay_full_ms)
    let t0 = Instant::now();
    let (state_full, _digest_full) = ecac_core::replay::replay_full(&dag);
    let replay_full_ms = t0.elapsed().as_millis() as u64;

    // Measure incremental replay over a suffix (simulate a checkpoint)
    let total = ops.len();
    let suffix = std::cmp::max(1, total / 10); // 10% tail (>=1)
    let checkpoint_idx = total.saturating_sub(suffix);

    let t1 = Instant::now();
    // Build a "checkpointed" state: processed_count = checkpoint_idx
    let mut state_ck = state_full.clone(); // reuse structure
    state_ck.set_processed_count(checkpoint_idx);
    let (_state_inc, _digest_inc) = ecac_core::replay::apply_incremental(&mut state_ck, &dag);
    let replay_incremental_ms = t1.elapsed().as_millis() as u64;

        // Also record ops_total for completeness (core increments ops_* inside replay).
        METRICS.inc("ops_total", ops.len() as u64);

    // Write artifacts
    let prefix = format!("{}-{}", opts.scenario, opts.seed);

    // 1) CSV summary (stable column order)
    let mut csv_path = opts.out_dir.clone();
    csv_path.push(format!("{}.csv", &prefix));
    let mut csv = fs::File::create(&csv_path)?;
    let commit = std::env::var("ECAC_COMMIT")
        .or_else(|_| std::env::var("GIT_COMMIT"))
        .unwrap_or_else(|_| "unknown".into());
    writeln!(
        csv,
        "# ecac-metrics v1, commit={}, scenario={}, seed={}",
        commit, opts.scenario, opts.seed
    )?;
        let snapshot = METRICS.snapshot_csv(); // 2-line csv: header + row
        write!(csv, "{}", snapshot)?;

    // 2) Timeline JSONL (lightweight breadcrumbs for plots)
    let mut tl_path = opts.out_dir.clone();
    tl_path.push(format!("{}-timeline.jsonl", &prefix));
    let mut tl = fs::File::create(&tl_path)?;
    writeln!(
        tl,
        r#"{{"t_ms":0,"type":"begin","scenario":"{}","seed":{}}}"#,
        opts.scenario, opts.seed
    )?;
    writeln!(
        tl,
        r#"{{"t_ms":{},"type":"replay_full_done"}}"#,
        replay_full_ms
    )?;
    writeln!(
        tl,
        r#"{{"t_ms":{},"type":"replay_incremental_done"}}"#,
        replay_full_ms + replay_incremental_ms
    )?;

    // 3) Final state JSON (deterministic)
    let mut st_path = opts.out_dir.clone();
    st_path.push(format!("{}-state.json", &prefix));
    fs::write(&st_path, state_full.to_deterministic_json_string())?;

    eprintln!("wrote:");
    eprintln!("  {}", csv_path.display());
    eprintln!("  {}", tl_path.display());
    eprintln!("  {}", st_path.display());
    Ok(())
}

// -------------------- Generators (deterministic; no RNG dep) --------------------

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut bytes = [0u8; 32];
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn gen_hb_chain(seed: u64, n: usize) -> Result<Vec<Op>> {
    // One author, linear parents: mv:o:x = "v{i}"
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
        let op = Op::new(parents.clone(), Hlc::new(1_000 + i as u64, logical), pk, payload, &sk);
        parents = vec![op.op_id];
        logical = logical.saturating_add(1);
        out.push(op);
    }
    Ok(out)
}

fn gen_concurrent_writers(seed: u64, n: usize) -> Result<Vec<Op>> {
    // Two authors race on the same key; no parent edges between them for concurrency.
    // We still produce a few linear parents per author to avoid pure roots-only DAG.
    let sk_a = key_pair(seed, b"concurrent/a");
    let pk_a = vk_to_bytes(&sk_a.verifying_key());
    let sk_b = key_pair(seed, b"concurrent/b");
    let pk_b = vk_to_bytes(&sk_b.verifying_key());

    let mut out = Vec::with_capacity(n);
    let mut pa: Vec<OpId> = vec![];
    let mut pb: Vec<OpId> = vec![];

    for i in 0..n {
        // Alternate authors, same field, independent parent chains
        let (sk, pk, parents, tick) = if i % 2 == 0 {
            (&sk_a, pk_a, &mut pa, 1_000u64 + i as u64)
        } else {
            (&sk_b, pk_b, &mut pb, 1_000u64 + i as u64)
        };
        let payload = Payload::Data {
            key: "mv:o:x".to_string(),
            value: format!("v{i}").into_bytes(),
        };
        let op = Op::new(parents.clone(), Hlc::new(tick, (i as u32) + 1), pk, payload, sk);
        parents.clear();
        parents.push(op.op_id);
        out.push(op);
    }
    Ok(out)
}

// (No local mvreg p95 anymore; it's captured via METRICS histogram.)
