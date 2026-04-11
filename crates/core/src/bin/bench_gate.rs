//! M7 microbenchmark: single-gate evaluation latency.
//!
//! Reviewer asks for the cost of a single `Gate(e)` decision in isolation, so
//! we can compare \equack{}'s online-mode authorization latency to a Cedar
//! lookup or an RBAC table check. Setup builds a minimal DAG with one
//! IssuerKey + Credential + Grant (one editor role, scope tags
//! \{hv,mech\}, no expiry) and constructs the EpochIndex via the production
//! `build_auth_epochs_with_trustview` path. The hot loop calls
//! `is_permitted_at_pos` 10K times against that index for the granted
//! subject and reports min/avg/p95/max in nanoseconds.
//!
//! What this measures: the policy check + epoch lookup. It does NOT include
//! signature verification (already characterised in `bench_profile`), DAG
//! insertion, or the MVReg merge — the gate itself.
//!
//! Usage:
//!   cargo run -p ecac-core --bin bench_gate --release -- \
//!       --iters 10000 --out results/m7_gate.csv

use std::env;
use std::fs;
use std::io::Write;
use std::time::Instant;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{CredentialFormat, Op, Payload};
use ecac_core::policy::{self, Action, TagSet};
use ecac_core::trustview::TrustView;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut iters: usize = 10_000;
    let mut out_path = String::from("results/m7_gate.csv");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                i += 1;
                iters = args[i].parse().expect("--iters <usize>");
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

    // -- Setup: minimal DAG with one IssuerKey + Credential + Grant --------
    let issuer_sk = key_pair(0xCEDA_BEEF, b"issuer");
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());
    let subject_sk = key_pair(0xCEDA_BEEF, b"subject");
    let subject_pk = vk_to_bytes(&subject_sk.verifying_key());

    let hlc_ik = Hlc::new(1_000_000, 1);
    let hlc_cred = Hlc::new(1_000_001, 2);

    let issuer_key_op = Op::new(
        vec![],
        hlc_ik,
        issuer_pk,
        Payload::IssuerKey {
            issuer_id: "issuer-0".to_string(),
            key_id: "k1".to_string(),
            algo: "EdDSA".to_string(),
            pubkey: issuer_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &issuer_sk,
    );

    let (cred_op, grant_op) = synth_credential_and_grant(
        &issuer_sk,
        &issuer_pk,
        "issuer-0".to_string(),
        subject_pk,
        hlc_cred,
    );

    let mut dag = Dag::new();
    dag.insert(issuer_key_op);
    dag.insert(cred_op);
    dag.insert(grant_op);
    let order = dag.topo_sort();
    let trust_view = TrustView::build_from_dag(&dag, &order);
    let epoch_index = policy::build_auth_epochs_with_trustview(&dag, &order, &trust_view);

    // Sanity: the gate must allow the granted subject for SetField on a
    // resource with tags {hv,mech}. If this fails the bench is meaningless.
    let mut tags: TagSet = TagSet::new();
    tags.insert("hv".to_string());
    tags.insert("mech".to_string());
    let pos = order.len(); // gate decisions happen at positions >= grant_pos
    let hlc_query = Hlc::new(2_000_000, 1);
    let allowed = policy::is_permitted_at_pos(
        &epoch_index,
        &subject_pk,
        Action::SetField,
        &tags,
        pos,
        hlc_query,
    );
    assert!(allowed, "gate microbench setup is wrong: granted subject is denied");

    // -- Hot loop ---------------------------------------------------------
    // Warm-up.
    for _ in 0..1024 {
        let _ = policy::is_permitted_at_pos(
            &epoch_index,
            &subject_pk,
            Action::SetField,
            &tags,
            pos,
            hlc_query,
        );
    }

    let mut samples_ns: Vec<u64> = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let ok = policy::is_permitted_at_pos(
            &epoch_index,
            &subject_pk,
            Action::SetField,
            &tags,
            pos,
            hlc_query,
        );
        let elapsed = t.elapsed().as_nanos() as u64;
        std::hint::black_box(ok);
        samples_ns.push(elapsed);
    }

    samples_ns.sort_unstable();
    let min = samples_ns.first().copied().unwrap_or(0);
    let max = samples_ns.last().copied().unwrap_or(0);
    let sum: u128 = samples_ns.iter().map(|&x| x as u128).sum();
    let avg = (sum / iters as u128) as u64;
    let p50 = samples_ns[samples_ns.len() / 2];
    let p95 = samples_ns[(samples_ns.len() as f64 * 0.95) as usize];
    let p99 = samples_ns[(samples_ns.len() as f64 * 0.99) as usize];

    eprintln!("[M7-gate] iterations={}", iters);
    eprintln!("  min  : {:>6} ns", min);
    eprintln!("  avg  : {:>6} ns", avg);
    eprintln!("  p50  : {:>6} ns", p50);
    eprintln!("  p95  : {:>6} ns", p95);
    eprintln!("  p99  : {:>6} ns", p99);
    eprintln!("  max  : {:>6} ns", max);

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(csv, "iters,min_ns,avg_ns,p50_ns,p95_ns,p99_ns,max_ns").unwrap();
    writeln!(
        csv,
        "{iters},{min},{avg},{p50},{p95},{p99},{max}"
    )
    .unwrap();
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn synth_credential_and_grant(
    issuer_sk: &SigningKey,
    issuer_pk: &[u8; 32],
    issuer_id: String,
    subject_pk: [u8; 32],
    hlc: Hlc,
) -> (Op, Op) {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let sub_hex = hex(&subject_pk);
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
