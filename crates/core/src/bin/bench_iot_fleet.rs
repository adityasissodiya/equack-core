//! E17 bench: IoT fleet maintenance workload (domain-shaped scenario).
//!
//! Motivated by reviewer MAJOR 2 (IEEE IoT-J revision): prior benchmarks
//! used synthetic single-key logs; this scenario models a realistic
//! fleet-maintenance deployment with multiple vendors, maintenance
//! engineers, and controllers, a mixed operation mix, multi-key data, and
//! at least one partition-heal cycle with mid-partition revocation.
//!
//! 10 April 2026 revision (M3 fix + Q3 + W4):
//!   * Genuine partition simulation: side A (vendors) and side B (a subset
//!     of engineers) accumulate ops independently during the partition
//!     window. Side A issues a REVOKE that targets a writer on side B; the
//!     post-partition merged log therefore contains writes from the
//!     revoked engineer ordered AFTER the REVOKE and is expected to skip
//!     them at the deny-wins gate.
//!   * REVOKE percentage is now a CLI knob (`--revoke-pct`), enabling Q3
//!     sensitivity sweeps without recompiling.
//!   * Applied / skipped counts come from the metrics registry rather than
//!     a coarse `data_ops` upper bound, so the CSV no longer reports zero
//!     skipped ops.
//!   * Peak RSS is sampled from /proc/self/status (VmRSS) and emitted in
//!     the CSV row to support W4 (memory characterisation).
//!
//! Fleet composition (default; override via CLI flags):
//!   - 50 controllers (the subjects of data operations)
//!   - 5  vendor organizations (independent issuers)
//!   - 20 maintenance engineers (VC subjects for GRANT/REVOKE)
//!
//! Operation mix (per-tick draw, defaults; tunable via --revoke-pct):
//!   70% DATA           -- parameter reads/writes on random keys
//!   15% TRUST / CRED   -- issuer key rotations and status-list chunks
//!   10% GRANT          -- new credential + grant for an engineer
//!    5% REVOKE         -- close an existing epoch (override with --revoke-pct)
//!
//! Usage:
//!   cargo run -p ecac-core --bin bench_iot_fleet --release -- \
//!       --ops 10000 --out results/e17_iot_fleet.csv

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::time::Instant;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::metrics::METRICS;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay;
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Fleet sizing -- tuned to be representative of a small industrial
/// deployment without blowing up replay cost for a laptop run.
#[derive(Clone, Copy)]
struct FleetCfg {
    controllers: usize,
    vendors: usize,
    engineers: usize,
    ops: usize,
    partition_start_frac: f64,
    partition_len_frac: f64,
    /// Probability (0..=100) of REVOKE in the per-tick op-mix draw.
    /// The remaining 100-revoke_pct is split 70/15/10 across
    /// DATA/TRUST/GRANT, scaled proportionally.
    revoke_pct: u8,
    seed: u64,
}

impl Default for FleetCfg {
    fn default() -> Self {
        Self {
            controllers: 50,
            vendors: 5,
            engineers: 20,
            ops: 10_000,
            partition_start_frac: 0.4,
            partition_len_frac: 0.2,
            revoke_pct: 5,
            seed: 0xE17_BEEF,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut cfg = FleetCfg::default();
    let mut out_path = String::from("results/e17_iot_fleet.csv");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ops" => {
                i += 1;
                cfg.ops = args[i].parse().expect("--ops <usize>");
            }
            "--controllers" => {
                i += 1;
                cfg.controllers = args[i].parse().expect("--controllers <usize>");
            }
            "--vendors" => {
                i += 1;
                cfg.vendors = args[i].parse().expect("--vendors <usize>");
            }
            "--engineers" => {
                i += 1;
                cfg.engineers = args[i].parse().expect("--engineers <usize>");
            }
            "--seed" => {
                i += 1;
                cfg.seed = args[i].parse().expect("--seed <u64>");
            }
            "--revoke-pct" => {
                i += 1;
                let v: u8 = args[i].parse().expect("--revoke-pct <0..=50>");
                assert!(v <= 50, "--revoke-pct must be in 0..=50");
                cfg.revoke_pct = v;
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
        "[E17] iot-fleet: controllers={} vendors={} engineers={} ops={} revoke_pct={}",
        cfg.controllers, cfg.vendors, cfg.engineers, cfg.ops, cfg.revoke_pct
    );

    let result = run_iot_fleet(&cfg);

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(
        csv,
        "scenario,controllers,vendors,engineers,ops,revoke_pct,data_ops,grant_ops,revoke_ops,trust_ops,\
         partition_ticks,side_b_post_revoke_writes,generate_ms,replay_ms,applied,skipped,peak_rss_kb,digest_prefix"
    )
    .unwrap();
    writeln!(
        csv,
        "iot_fleet_heal,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        cfg.controllers,
        cfg.vendors,
        cfg.engineers,
        cfg.ops,
        cfg.revoke_pct,
        result.data_ops,
        result.grant_ops,
        result.revoke_ops,
        result.trust_ops,
        result.partition_ticks,
        result.side_b_post_revoke_writes,
        result.generate_ms,
        result.replay_ms,
        result.applied,
        result.skipped,
        result.peak_rss_kb,
        result.digest_prefix
    )
    .unwrap();

    eprintln!(
        "[E17] data={} grant={} revoke={} trust={} partition_ticks={} \
         side_b_post_revoke_writes={} generate={}ms replay={}ms applied={} \
         skipped={} peak_rss={}KB digest={}",
        result.data_ops,
        result.grant_ops,
        result.revoke_ops,
        result.trust_ops,
        result.partition_ticks,
        result.side_b_post_revoke_writes,
        result.generate_ms,
        result.replay_ms,
        result.applied,
        result.skipped,
        result.peak_rss_kb,
        result.digest_prefix
    );
    eprintln!("[E17] wrote {out_path}");
}

#[allow(dead_code)]
struct IotFleetResult {
    data_ops: usize,
    grant_ops: usize,
    revoke_ops: usize,
    trust_ops: usize,
    partition_ticks: usize,
    /// Writes that side B (the partitioned engineer) emitted strictly
    /// AFTER side A's mid-partition REVOKE. These are expected to be
    /// denied by the gate at replay time and counted as `skipped`.
    side_b_post_revoke_writes: usize,
    generate_ms: u64,
    replay_ms: u64,
    applied: usize,
    skipped: usize,
    peak_rss_kb: u64,
    digest_prefix: String,
}

fn run_iot_fleet(cfg: &FleetCfg) -> IotFleetResult {
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    // ----- identities -----------------------------------------------------
    let vendor_sks: Vec<SigningKey> = (0..cfg.vendors)
        .map(|v| key_pair(cfg.seed, format!("vendor/{v}").as_bytes()))
        .collect();
    let vendor_pks: Vec<[u8; 32]> = vendor_sks
        .iter()
        .map(|sk| vk_to_bytes(&sk.verifying_key()))
        .collect();

    let engineer_sks: Vec<SigningKey> = (0..cfg.engineers)
        .map(|e| key_pair(cfg.seed, format!("engineer/{e}").as_bytes()))
        .collect();
    let engineer_pks: Vec<[u8; 32]> = engineer_sks
        .iter()
        .map(|sk| vk_to_bytes(&sk.verifying_key()))
        .collect();

    let mut parents_by_engineer: HashMap<usize, Vec<OpId>> = HashMap::new();
    for e in 0..cfg.engineers {
        parents_by_engineer.insert(e, vec![]);
    }

    // Two op streams: side_a (vendors + engineers that are NOT partitioned)
    // and side_b (the engineer partitioned during the heal window).
    let mut side_a: Vec<Op> = Vec::with_capacity(cfg.ops);
    let mut side_b: Vec<Op> = Vec::new();
    let mut hlc_ms: u64 = 1_000_000;
    let mut hlc_logical: u32 = 0;
    let mut next_hlc = |rng: &mut StdRng| -> Hlc {
        hlc_ms += 1 + rng.gen_range(0..5);
        hlc_logical = hlc_logical.wrapping_add(1);
        Hlc::new(hlc_ms, hlc_logical)
    };

    // ----- bootstrap: one IssuerKey per vendor ---------------------------
    let mut trust_ops_count = 0usize;
    for (vi, _vk) in vendor_pks.iter().enumerate() {
        let ik = Op::new(
            vec![],
            next_hlc(&mut rng),
            vendor_pks[vi],
            Payload::IssuerKey {
                issuer_id: format!("vendor-{vi}"),
                key_id: "k1".to_string(),
                algo: "EdDSA".to_string(),
                pubkey: vendor_pks[vi].to_vec(),
                valid_from_ms: 0,
                valid_until_ms: u64::MAX,
                prev_key_id: None,
            },
            &vendor_sks[vi],
        );
        side_a.push(ik);
        trust_ops_count += 1;
    }

    // The partitioned engineer: a fixed index so the workload is
    // deterministic and easy to inspect post-hoc.
    let target_engineer: usize = 0;
    // Pre-grant the target engineer up front so the partition window has a
    // live epoch to revoke. This grant is explicitly issued by vendor 0.
    {
        let v = 0usize;
        let (cred_op, grant_op) = synth_credential_and_grant(
            &vendor_sks[v],
            &vendor_pks[v],
            format!("vendor-{v}"),
            engineer_pks[target_engineer],
            next_hlc(&mut rng),
        );
        parents_by_engineer.insert(target_engineer, vec![grant_op.op_id]);
        side_a.push(cred_op);
        side_a.push(grant_op);
        trust_ops_count += 1;
    }

    // Categories use the configured REVOKE percentage; the remainder is
    // split proportional to the original 70/15/10 weights.
    let revoke_pct = cfg.revoke_pct as u32;
    let remaining = 100u32.saturating_sub(revoke_pct);
    let data_thr: u32 = (remaining * 70) / 95;
    let trust_thr: u32 = data_thr + (remaining * 15) / 95;
    let grant_thr: u32 = remaining; // up to grant_thr is GRANT; >= is REVOKE
    debug_assert!(data_thr <= trust_thr && trust_thr <= grant_thr);

    let partition_start = (cfg.ops as f64 * cfg.partition_start_frac) as usize;
    let partition_len = (cfg.ops as f64 * cfg.partition_len_frac) as usize;
    let partition_end = partition_start + partition_len;

    let mut data_ops = 0usize;
    let mut grant_ops = 0usize;
    let mut revoke_ops = 0usize;
    let mut partition_ticks = 0usize;
    let mut side_b_post_revoke_writes = 0usize;

    // Track which engineers have at least one credential+grant emitted so
    // DATA ops attribute to a subject that could in principle be authorised.
    let mut engineers_with_grant: Vec<usize> = vec![target_engineer];

    // Snapshot of the parent chain for the target engineer captured at the
    // moment we enter the partition window. Side B continues to extend
    // *this* chain in isolation while side A's events (including the
    // REVOKE) accumulate in parallel.
    let mut side_b_parents: Option<Vec<OpId>> = None;
    let mut side_a_revoke_emitted = false;

    let t_gen = Instant::now();
    for step in 0..cfg.ops {
        let in_partition = step >= partition_start && step < partition_end;

        // Step 1: when we enter the partition window, snapshot the current
        // parent chain for side B and stage side A's REVOKE for the target
        // engineer at the very first partition tick.
        if in_partition {
            if side_b_parents.is_none() {
                side_b_parents = parents_by_engineer.get(&target_engineer).cloned();
            }
            if !side_a_revoke_emitted {
                let v = 0usize;
                let hlc = next_hlc(&mut rng);
                let revoke = Op::new(
                    parents_by_engineer
                        .get(&target_engineer)
                        .cloned()
                        .unwrap_or_default(),
                    hlc,
                    vendor_pks[v],
                    Payload::Revoke {
                        subject_pk: engineer_pks[target_engineer],
                        role: "editor".into(),
                        scope_tags: vec!["hv".into(), "mech".into()],
                        at: hlc,
                    },
                    &vendor_sks[v],
                );
                // Side A's revoke advances the parent chain *for side A*,
                // but side B (the partitioned writer) keeps using the
                // pre-partition snapshot in side_b_parents.
                parents_by_engineer.insert(target_engineer, vec![revoke.op_id]);
                side_a.push(revoke);
                revoke_ops += 1;
                side_a_revoke_emitted = true;
            }

            // While inside the partition window, every other tick is a
            // side-B write from the target engineer. The HLCs of these
            // writes are strictly greater than the REVOKE's HLC, so after
            // merge they are ordered AFTER the REVOKE in the deterministic
            // total order and must be denied at the gate.
            if step % 2 == 0 {
                let key = format!(
                    "mv:c{}:param{}",
                    rng.gen_range(0..cfg.controllers),
                    rng.gen_range(0..5)
                );
                let parents_b = side_b_parents.clone().unwrap_or_default();
                let data = Op::new(
                    parents_b,
                    next_hlc(&mut rng),
                    engineer_pks[target_engineer],
                    Payload::Data {
                        key,
                        value: rng.gen::<[u8; 4]>().to_vec(),
                    },
                    &engineer_sks[target_engineer],
                );
                side_b_parents = Some(vec![data.op_id]);
                side_b.push(data);
                data_ops += 1;
                side_b_post_revoke_writes += 1;
                partition_ticks += 1;
                continue;
            }
            partition_ticks += 1;
            // odd partition ticks fall through to the normal side-A op mix
            // so the bench keeps making forward progress.
        }

        // Roll the op category for the side-A stream.
        let roll: u32 = rng.gen_range(0..100);

        if roll < data_thr {
            // DATA op (side A)
            if engineers_with_grant.is_empty() {
                let e = rng.gen_range(0..cfg.engineers);
                let v = rng.gen_range(0..cfg.vendors);
                let (cred_op, grant_op) = synth_credential_and_grant(
                    &vendor_sks[v],
                    &vendor_pks[v],
                    format!("vendor-{v}"),
                    engineer_pks[e],
                    next_hlc(&mut rng),
                );
                parents_by_engineer.insert(e, vec![grant_op.op_id]);
                side_a.push(cred_op);
                side_a.push(grant_op);
                grant_ops += 1;
                engineers_with_grant.push(e);
                continue;
            }
            let eidx = rng.gen_range(0..engineers_with_grant.len());
            let e = engineers_with_grant[eidx];
            // Skip the partitioned engineer in side-A data ops while the
            // partition is active so the only writes attributed to them
            // during the window come from side B.
            if in_partition && e == target_engineer {
                continue;
            }
            let key = format!(
                "mv:c{}:param{}",
                rng.gen_range(0..cfg.controllers),
                rng.gen_range(0..5)
            );
            let parents = parents_by_engineer.get(&e).cloned().unwrap_or_default();
            let data = Op::new(
                parents,
                next_hlc(&mut rng),
                engineer_pks[e],
                Payload::Data {
                    key,
                    value: rng.gen::<[u8; 4]>().to_vec(),
                },
                &engineer_sks[e],
            );
            parents_by_engineer.insert(e, vec![data.op_id]);
            side_a.push(data);
            data_ops += 1;
        } else if roll < trust_thr {
            // TRUST / CREDENTIAL op
            let e = rng.gen_range(0..cfg.engineers);
            let v = rng.gen_range(0..cfg.vendors);
            let (cred_op, grant_op) = synth_credential_and_grant(
                &vendor_sks[v],
                &vendor_pks[v],
                format!("vendor-{v}"),
                engineer_pks[e],
                next_hlc(&mut rng),
            );
            parents_by_engineer.insert(e, vec![grant_op.op_id]);
            side_a.push(cred_op);
            side_a.push(grant_op);
            grant_ops += 1;
            trust_ops_count += 1;
            if !engineers_with_grant.contains(&e) {
                engineers_with_grant.push(e);
            }
        } else if roll < grant_thr {
            // GRANT for a random engineer.
            let e = rng.gen_range(0..cfg.engineers);
            let v = rng.gen_range(0..cfg.vendors);
            let (cred_op, grant_op) = synth_credential_and_grant(
                &vendor_sks[v],
                &vendor_pks[v],
                format!("vendor-{v}"),
                engineer_pks[e],
                next_hlc(&mut rng),
            );
            parents_by_engineer.insert(e, vec![grant_op.op_id]);
            side_a.push(cred_op);
            side_a.push(grant_op);
            grant_ops += 1;
            if !engineers_with_grant.contains(&e) {
                engineers_with_grant.push(e);
            }
        } else {
            // REVOKE targeting a random granted engineer.
            if engineers_with_grant.is_empty() {
                continue;
            }
            let eidx = rng.gen_range(0..engineers_with_grant.len());
            let e = engineers_with_grant[eidx];
            let v = rng.gen_range(0..cfg.vendors);
            let hlc = next_hlc(&mut rng);
            let revoke = Op::new(
                parents_by_engineer.get(&e).cloned().unwrap_or_default(),
                hlc,
                vendor_pks[v],
                Payload::Revoke {
                    subject_pk: engineer_pks[e],
                    role: "editor".into(),
                    scope_tags: vec!["hv".into(), "mech".into()],
                    at: hlc,
                },
                &vendor_sks[v],
            );
            side_a.push(revoke);
            revoke_ops += 1;
        }
    }

    let generate_ms = t_gen.elapsed().as_millis() as u64;

    // ----- merge sides and replay ----------------------------------------
    let mut dag = Dag::new();
    for op in side_a.iter().chain(side_b.iter()) {
        dag.insert(op.clone());
    }

    // Reset metrics so the counters we read post-replay reflect ONLY this
    // bench run, not the cumulative process state.
    METRICS.reset();

    let t_replay = Instant::now();
    let (state, digest) = replay::replay_full(&dag);
    let replay_ms = t_replay.elapsed().as_millis() as u64;

    let applied = METRICS.counter("ops_applied") as usize;
    let skipped = METRICS.counter("ops_skipped_policy") as usize;
    let _ = state; // state is materialised but not exported here

    let peak_rss_kb = read_peak_rss_kb();

    IotFleetResult {
        data_ops,
        grant_ops,
        revoke_ops,
        trust_ops: trust_ops_count,
        partition_ticks,
        side_b_post_revoke_writes,
        generate_ms,
        replay_ms,
        applied,
        skipped,
        peak_rss_kb,
        digest_prefix: hex(&digest[..8]),
    }
}

/// Read peak resident-set size in kilobytes from /proc/self/status. On
/// non-Linux platforms (or if /proc is unavailable) this returns 0 and
/// the bench simply reports 0KB rather than failing.
fn read_peak_rss_kb() -> u64 {
    let Ok(s) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in s.lines() {
        // VmHWM is the high-water mark of resident memory; VmRSS is
        // current. We prefer VmHWM so the bench captures the peak across
        // generation + replay.
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .trim()
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn synth_credential_and_grant(
    issuer_sk: &SigningKey,
    issuer_pk: &[u8; 32],
    issuer_id: String,
    subject_pk: [u8; 32],
    hlc: Hlc,
) -> (Op, Op) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ecac_core::op::CredentialFormat;
    use ed25519_dalek::Signer;
    use serde_json::json;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let sub_hex = hex(&subject_pk);
    // nbf must be >= the issuer key's activation time, which is the HLC
    // physical_ms of the IssuerKey op. We seed `nbf` with the cred's own
    // HLC physical_ms (which strictly follows the IssuerKey op since HLCs
    // are monotonically advanced) so TrustView::select_key picks up the
    // active key. Using nbf=0 here makes is_active_at return false because
    // activated_at_ms = max(valid_from_ms, op.hlc.physical_ms) > 0.
    let claims = json!({
        "sub_pk": sub_hex,
        "role": "editor",
        "scope": ["hv", "mech"],
        "nbf": hlc.physical_ms,
        "exp": u64::MAX,
        "iss": issuer_id,
        "jti": format!("cred-{}-{}", hlc.physical_ms, hlc.logical),
        "status": { "id": "list-0", "index": 0 }
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let sig: ed25519_dalek::Signature = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");
    let cred_bytes = compact.as_bytes().to_vec();

    let cred_hash: [u8; 32] = blake3::hash(&cred_bytes).into();

    let cred_op = Op::new(
        vec![],
        hlc,
        *issuer_pk,
        Payload::Credential {
            cred_id: format!("cred-{}-{}", hlc.physical_ms, hlc.logical),
            cred_bytes,
            format: CredentialFormat::Jwt,
        },
        issuer_sk,
    );
    let grant_op = Op::new(
        vec![cred_op.op_id],
        hlc,
        *issuer_pk,
        Payload::Grant {
            subject_pk,
            cred_hash,
        },
        issuer_sk,
    );
    (cred_op, grant_op)
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
