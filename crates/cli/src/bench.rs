use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
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

    // Normalize scenario aliases to keep the rest simple.
    let scenario_norm: String = match opts.scenario.as_str() {
        "concurrent-writers" => "concurrent".to_string(),
        s => s.to_string(),
    };
    let scenario_str = scenario_norm.as_str();

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

        // Generate deterministic workload; offline-revocation is planned here (kept vs skipped).
        let (ops_to_insert, total_ops, skipped_policy, revoke_t_ms) = match scenario_str {
            "hb-chain" => {
            let ops = gen_hb_chain(opts.seed, opts.ops)?;
            let n = ops.len();
            (ops, n, 0usize, None)
            }
            "concurrent" => {
                // your signature is (seed, n, peers)
                            let ops = gen_concurrent_writers(opts.seed, opts.ops, opts.peers)?;
                            let n = ops.len();
                            (ops, n, 0usize, None)
            }
            "offline-revocation" => {
                let (kept, total, skipped, t_ms) = plan_offline_revocation(opts.seed, opts.ops)?;
                (kept, total, skipped, Some(t_ms))
            }
            other => {
                return Err(anyhow!(
                    "unsupported scenario '{}'. Supported: hb-chain, concurrent, offline-revocation",
                    other
                ));
            }
        };

    // Silence "unused field" warnings if some knobs are not consumed yet by local scenarios.
    // (They will be used fully when net/partition harness is wired.)
    let _maybe_unused_partition = &opts.partition;


    // Build full DAG for replay
    let mut dag = Dag::new();
    for op in &ops_to_insert {
        dag.insert(op.clone());
    }

    // Measure full replay (core will also record replay_full_ms)
    let t0 = Instant::now();
    let (state_full, digest_full) = ecac_core::replay::replay_full(&dag);
    let replay_full_ms = t0.elapsed().as_millis() as u64;
    METRICS.observe_ms("replay_full_ms", replay_full_ms);

    // Measure incremental replay over a suffix (simulate a checkpoint)
    let total = ops_to_insert.len();
        let suffix = match opts.checkpoint_every {
                Some(k) if k > 0 => std::cmp::min(k, total).max(1),
                _ => std::cmp::max(1, total / 10), // default: 10% tail (>=1)
            };
            let checkpoint_idx = total.saturating_sub(suffix);

                // IMPORTANT: build a *consistent* checkpoint from the prefix only.
                // Cloning the final state and rewinding processed_count replays the tail twice
                // and creates artificial MVReg multi-winner samples (p95 spikes to 2).
                //
                // Construct a prefix DAG with ops[0..checkpoint_idx), replay it to get a clean
                // checkpoint state, then apply the incremental over the *full* DAG.
                let mut dag_prefix = Dag::new();
                for op in ops_to_insert.iter().take(checkpoint_idx)  {
                    dag_prefix.insert(op.clone());
                }
                let (mut state_ck, _digest_ck) = ecac_core::replay::replay_full(&dag_prefix);
            
                                let t1 = Instant::now();
                                let (_state_inc, digest_inc) = ecac_core::replay::apply_incremental(&mut state_ck, &dag);
                                let replay_incremental_ms = t1.elapsed().as_millis() as u64;
                                // Parity check: full vs incremental digest must match.
                                if digest_full != digest_inc {
                                    return Err(anyhow!(
                                        "replay parity failed: digest_full != digest_inc (scenario={}, seed={})",
                                        opts.scenario, opts.seed
                                    ));
                                }
    METRICS.observe_ms("replay_incremental_ms", replay_incremental_ms);

    // Write artifacts
    let prefix = format!("{}-{}", scenario_str, opts.seed);

        // Sanity: incremental should not produce a different digest.
    if digest_full != digest_inc {
        return Err(anyhow!(
            "replay parity failed: digest_full != digest_inc (scenario={}, seed={})",
            opts.scenario,
            opts.seed
        ));
    }
    // Soft assertion on cost: full >= incremental (don’t fail, just record).
    if replay_full_ms < replay_incremental_ms {
        // No-op: timing noise is allowed; parity is the hard requirement.
    }

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
        commit, scenario_str, opts.seed
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
        scenario_str, opts.seed
    )?;
    if let Some(t_ms) = revoke_t_ms {
                writeln!(tl, r#"{{"t_ms":{},"type":"revoke","note":"offline deny-wins"}}"#, t_ms)?;
            }
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

fn gen_concurrent_writers(seed: u64, n: usize, peers: usize) -> Result<Vec<Op>> {
        // N authors race on the same key; no edges between authors (true concurrency).
        let n_authors = std::cmp::max(2, std::cmp::min(peers, 8)); // clamp to [2..8]
    
        // Build keypairs and per-author parent chains.
        let sks: Vec<SigningKey> = (0..n_authors)
            .map(|i| key_pair(seed, format!("concurrent/{i}").as_bytes()))
            .collect();
        let pks: Vec<[u8; 32]> = sks.iter().map(|sk| vk_to_bytes(&sk.verifying_key())).collect();
        let mut parents: Vec<Vec<OpId>> = vec![Vec::new(); n_authors];
    
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let a = i % n_authors;
            let sk = &sks[a];
            let pk = pks[a];
            let payload = Payload::Data {
                key: "mv:o:x".to_string(),
                value: format!("v{i}").into_bytes(),
            };
            let tick = 1_000u64 + i as u64; // deterministic HLC ts
            let op = Op::new(parents[a].clone(), Hlc::new(tick, (i as u32) + 1), pk, payload, sk);
            parents[a].clear();
            parents[a].push(op.op_id);
            out.push(op);
        }
        Ok(out)
    }
    
    fn gen_offline_revocation(seed: u64, n: usize, peers: usize) -> Result<Vec<Op>> {
        // For now, synthesize using the concurrent generator as the op source.
        // The policy engine (when active) will decide what to skip after a revoke.
        gen_concurrent_writers(seed, n, peers)
}

// (No local mvreg p95 anymore; it's captured via METRICS histogram.)

/// Deterministic "offline-revocation" generator:
/// - Produce a linear HB chain of `n` ops for a single author.
/// - Choose a deterministic cut index; everything after the cut is considered
///   invalidated by a revoke and *not* inserted into the DAG.
/// - Return (kept_ops, total_ops, skipped_due_to_policy, revoke_time_ms).


/// Plan an offline-revocation run by splitting a linear HB chain into kept vs. skipped tail.
/// Returns (ops_kept_for_DAG, total_requested_ops, skipped_due_to_policy, revoke_time_ms).
fn plan_offline_revocation(seed: u64, n: usize) -> Result<(Vec<Op>, usize, usize, u64)> {
    // tweak seed with a VALID hex constant to avoid exact reuse of hb-chain sequence
    let all = gen_hb_chain(seed ^ 0x5EED_CAFEu64, n)?;
    if n == 0 {
        return Ok((Vec::new(), 0, 0, 0));
    }
    // Deterministic cut: ~30% tail invalidated; keep at least 1 op.
    let cut = std::cmp::max(1, (n as f64 * 0.7).round() as usize);
    let kept = all[..cut].to_vec();
    let skipped = n.saturating_sub(cut);
    // HB timestamps are 1_000 + i; revoke at first dropped op.
    let revoke_t_ms = 1_000u64 + (cut as u64);
    Ok((kept, n, skipped, revoke_t_ms))
}