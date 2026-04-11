//! E18/E19 bench: adversarial resilience under forged or stale evidence.
//!
//! Reviewer W3 (10 April 2026 revision) asks for two scenarios beyond the
//! benign-fault E16/E17 evaluations:
//!
//!   E18 -- credential compromise
//!     A subject S is granted a credential, makes some legitimate writes,
//!     then has the credential revoked. While partitioned, S keeps writing
//!     using the now-revoked credential. After the merged log is replayed,
//!     every post-revoke write must be skipped at the deny-wins gate. We
//!     also fabricate a GRANT op signed by an unknown issuer key and
//!     confirm the gate refuses to open an epoch from it.
//!
//!   E19 -- forged event injection
//!     Three sub-scenarios:
//!       (a) signature forgery: a data op whose payload bytes are mutated
//!           after signing must fail `Op::verify` and never reach the
//!           gate;
//!       (b) HLC forgery: a data op with a fabricated HLC strictly after
//!           the credential's `exp_ms` is signed correctly but rejected
//!           because the epoch's HLC window has elapsed;
//!       (c) replay/dedup: the same op_id reinserted into the DAG must
//!           collapse to a single application (idempotent merge).
//!
//! Output: a single CSV (`results/e18_e19_adversarial.csv`) with one row
//! per scenario plus a self-checking pass/fail column. The bench panics
//! the process if any expectation is violated so CI catches regressions.

use std::env;
use std::fs;
use std::io::Write;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::metrics::METRICS;
use ecac_core::op::{CredentialFormat, Op, OpId, Payload};
use ecac_core::replay;
use ed25519_dalek::SigningKey;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut out_path = String::from("results/e18_e19_adversarial.csv");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
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

    let mut rows: Vec<Row> = Vec::new();

    rows.push(scenario_credential_revoked());
    rows.push(scenario_forged_grant_unknown_issuer());
    rows.push(scenario_signature_forgery());
    rows.push(scenario_hlc_after_exp());
    rows.push(scenario_duplicate_op_id());

    let mut csv = fs::File::create(&out_path).expect("create CSV");
    writeln!(
        csv,
        "scenario,description,injected,applied,skipped,outcome"
    )
    .unwrap();
    for r in &rows {
        writeln!(
            csv,
            "{},{},{},{},{},{}",
            r.scenario, r.description, r.injected, r.applied, r.skipped, r.outcome
        )
        .unwrap();
        eprintln!(
            "[E18/19] {} -- injected={} applied={} skipped={} -> {}",
            r.scenario, r.injected, r.applied, r.skipped, r.outcome
        );
    }
    eprintln!("[E18/19] wrote {out_path}");
}

#[derive(Debug)]
struct Row {
    scenario: &'static str,
    description: &'static str,
    injected: usize,
    applied: usize,
    skipped: usize,
    outcome: &'static str,
}

// ----- E18 scenarios ---------------------------------------------------------

/// 50 legitimate writes from a granted engineer, then a revoke, then 50
/// further writes from the same engineer using the now-stale credential.
/// All 50 post-revoke writes must be skipped after merged replay.
fn scenario_credential_revoked() -> Row {
    let (vendor_sk, vendor_pk) = make_keypair("vendor/0");
    let (attacker_sk, attacker_pk) = make_keypair("attacker/0");

    let mut ops: Vec<Op> = Vec::new();
    let mut hlc_ms: u64 = 1_000_000;
    let mut next_logical: u32 = 0;
    let mut next_hlc = || -> Hlc {
        hlc_ms += 1;
        next_logical = next_logical.wrapping_add(1);
        Hlc::new(hlc_ms, next_logical)
    };

    // 1. Issuer key for the vendor (so TrustView can verify the VC).
    let ik_hlc = next_hlc();
    ops.push(Op::new(
        vec![],
        ik_hlc,
        vendor_pk,
        Payload::IssuerKey {
            issuer_id: "vendor-0".into(),
            key_id: "k1".into(),
            algo: "EdDSA".into(),
            pubkey: vendor_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &vendor_sk,
    ));

    // 2. Credential + grant for the attacker.
    let cred_hlc = next_hlc();
    let (cred_op, grant_op) = synth_credential_and_grant(
        &vendor_sk,
        &vendor_pk,
        "vendor-0".into(),
        attacker_pk,
        cred_hlc,
    );
    let attacker_grant_id = grant_op.op_id;
    ops.push(cred_op);
    ops.push(grant_op);

    // 3. 50 legitimate writes (chained off the grant so they are unambiguously
    //    causally after the GRANT).
    let mut last_attacker_op: OpId = attacker_grant_id;
    let pre_count = 50usize;
    for i in 0..pre_count {
        let h = next_hlc();
        let op = Op::new(
            vec![last_attacker_op],
            h,
            attacker_pk,
            Payload::Data {
                key: format!("mv:c{}:param0", i % 5),
                value: vec![i as u8],
            },
            &attacker_sk,
        );
        last_attacker_op = op.op_id;
        ops.push(op);
    }

    // 4. Snapshot the attacker's parent chain BEFORE the revoke. The
    //    attacker (partitioned) keeps extending this chain in step 6, while
    //    the side-A revoke advances its own chain forward.
    let attacker_chain_at_partition = vec![last_attacker_op];

    // 5. Vendor issues a REVOKE; the revoke's HLC is below the post-revoke
    //    writes' HLCs so it sorts before them in the deterministic order.
    let revoke_hlc = next_hlc();
    let revoke = Op::new(
        vec![last_attacker_op],
        revoke_hlc,
        vendor_pk,
        Payload::Revoke {
            subject_pk: attacker_pk,
            role: "editor".into(),
            scope_tags: vec!["hv".into(), "mech".into()],
            at: revoke_hlc,
        },
        &vendor_sk,
    );
    ops.push(revoke);

    // 6. 50 post-revoke writes from the attacker, all using the stale
    //    credential. These have HLCs strictly later than the REVOKE, so
    //    they sort after it in the merged total order and the deny-wins
    //    gate must skip every one.
    let post_count = 50usize;
    let mut attacker_tail = attacker_chain_at_partition.clone();
    for i in 0..post_count {
        let h = next_hlc();
        let op = Op::new(
            attacker_tail.clone(),
            h,
            attacker_pk,
            Payload::Data {
                key: format!("mv:c{}:param1", i % 5),
                value: vec![0xAA, i as u8],
            },
            &attacker_sk,
        );
        attacker_tail = vec![op.op_id];
        ops.push(op);
    }

    let (applied, skipped) = replay_and_count(&ops);

    let outcome = if applied == pre_count && skipped == post_count {
        "PASS"
    } else {
        eprintln!(
            "[E18-revoked] EXPECTED applied={} skipped={}, GOT applied={} skipped={}",
            pre_count, post_count, applied, skipped
        );
        "FAIL"
    };
    assert_eq!(applied, pre_count, "E18-revoked: applied count mismatch");
    assert_eq!(skipped, post_count, "E18-revoked: skipped count mismatch");

    Row {
        scenario: "E18-credential-revoked",
        description: "50 pre-revoke writes apply; 50 post-revoke writes skipped at gate",
        injected: post_count,
        applied,
        skipped,
        outcome,
    }
}

/// A GRANT op signed by an issuer key that was never published on the log.
/// The credential's `iss` claim points at an unknown issuer, so TrustView
/// cannot resolve a VerifyingKey, the VC fails verification, no epoch is
/// opened, and any data ops the (still validly-keyed) attacker emits are
/// denied at the gate.
fn scenario_forged_grant_unknown_issuer() -> Row {
    let (real_vendor_sk, real_vendor_pk) = make_keypair("vendor/real");
    let (rogue_vendor_sk, rogue_vendor_pk) = make_keypair("vendor/rogue");
    let (attacker_sk, attacker_pk) = make_keypair("attacker/forged-grant");

    let mut ops: Vec<Op> = Vec::new();
    let mut hlc_ms: u64 = 2_000_000;
    let mut next_logical: u32 = 0;
    let mut next_hlc = || -> Hlc {
        hlc_ms += 1;
        next_logical = next_logical.wrapping_add(1);
        Hlc::new(hlc_ms, next_logical)
    };

    // Real vendor publishes its issuer key. The rogue vendor does NOT.
    let ik_hlc = next_hlc();
    ops.push(Op::new(
        vec![],
        ik_hlc,
        real_vendor_pk,
        Payload::IssuerKey {
            issuer_id: "vendor-real".into(),
            key_id: "k1".into(),
            algo: "EdDSA".into(),
            pubkey: real_vendor_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &real_vendor_sk,
    ));

    // Rogue vendor mints a credential for the attacker referencing an
    // issuer that does not exist in TrustView. The compact JWT is internally
    // consistent (signed by the rogue's own key) but the iss claim points
    // at "vendor-rogue" which has no published IssuerKey.
    let cred_hlc = next_hlc();
    let (cred_op, grant_op) = synth_credential_and_grant(
        &rogue_vendor_sk,
        &rogue_vendor_pk,
        "vendor-rogue".into(),
        attacker_pk,
        cred_hlc,
    );
    ops.push(cred_op);
    ops.push(grant_op);

    // Attacker writes 10 data ops; with no valid epoch they should all be
    // denied at the gate.
    let injected = 10usize;
    let mut last: Vec<OpId> = vec![];
    for i in 0..injected {
        let h = next_hlc();
        let op = Op::new(
            last.clone(),
            h,
            attacker_pk,
            Payload::Data {
                key: format!("mv:c{}:param2", i % 4),
                value: vec![0xCC, i as u8],
            },
            &attacker_sk,
        );
        last = vec![op.op_id];
        ops.push(op);
    }

    let (applied, skipped) = replay_and_count(&ops);

    let outcome = if applied == 0 && skipped == injected {
        "PASS"
    } else {
        eprintln!(
            "[E18-forged-grant] EXPECTED applied=0 skipped={}, GOT applied={} skipped={}",
            injected, applied, skipped
        );
        "FAIL"
    };
    assert_eq!(applied, 0, "E18-forged-grant: applied should be zero");
    assert_eq!(skipped, injected, "E18-forged-grant: skipped should equal injected");

    Row {
        scenario: "E18-forged-grant",
        description: "Grant referencing an unknown-issuer VC opens no epoch; downstream writes denied",
        injected,
        applied,
        skipped,
        outcome,
    }
}

// ----- E19 scenarios ---------------------------------------------------------

/// Mutate a data op's payload after signing. The op_id no longer matches
/// the canonical-CBOR hash of the header, `Op::verify` returns false, and
/// the gate never even runs on the tampered op.
fn scenario_signature_forgery() -> Row {
    let (vendor_sk, vendor_pk) = make_keypair("vendor/sig");
    let (writer_sk, writer_pk) = make_keypair("writer/sig");

    let mut ops: Vec<Op> = Vec::new();
    let mut hlc_ms: u64 = 3_000_000;
    let mut next_logical: u32 = 0;
    let mut next_hlc = || -> Hlc {
        hlc_ms += 1;
        next_logical = next_logical.wrapping_add(1);
        Hlc::new(hlc_ms, next_logical)
    };

    let ik_hlc = next_hlc();
    ops.push(Op::new(
        vec![],
        ik_hlc,
        vendor_pk,
        Payload::IssuerKey {
            issuer_id: "vendor-sig".into(),
            key_id: "k1".into(),
            algo: "EdDSA".into(),
            pubkey: vendor_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &vendor_sk,
    ));

    let cred_hlc = next_hlc();
    let (cred_op, grant_op) = synth_credential_and_grant(
        &vendor_sk,
        &vendor_pk,
        "vendor-sig".into(),
        writer_pk,
        cred_hlc,
    );
    let grant_id = grant_op.op_id;
    ops.push(cred_op);
    ops.push(grant_op);

    // Build a legitimate write so we have something for the gate to apply
    // alongside the tampered op (sanity baseline).
    let baseline = Op::new(
        vec![grant_id],
        next_hlc(),
        writer_pk,
        Payload::Data {
            key: "mv:c0:param0".into(),
            value: vec![0x01],
        },
        &writer_sk,
    );
    ops.push(baseline);

    // Tampered op: sign one payload, then mutate the value bytes after the
    // fact. The op_id was computed over the original header, so the
    // recomputed hash on `verify()` will mismatch and the op is rejected
    // at ingest with no audit hook required.
    let tampered_hlc = next_hlc();
    let mut tampered = Op::new(
        vec![grant_id],
        tampered_hlc,
        writer_pk,
        Payload::Data {
            key: "mv:c0:param1".into(),
            value: vec![0x02],
        },
        &writer_sk,
    );
    if let Payload::Data { ref mut value, .. } = tampered.header.payload {
        value.push(0xFF); // post-sign mutation
    }
    assert!(
        !tampered.verify(),
        "tampered op should fail Op::verify; got verify=true"
    );
    ops.push(tampered);

    let (applied, skipped) = replay_and_count(&ops);

    // Only the baseline op makes it through. The tampered op is dropped at
    // verify() inside replay; replay's data_total counter only ticks for
    // ops that pass the verify check, so it appears as neither applied
    // nor skipped from the perspective of the gate counters.
    let outcome = if applied == 1 && skipped == 0 { "PASS" } else { "FAIL" };
    assert_eq!(applied, 1, "E19-sig-forgery: only baseline should apply");
    assert_eq!(skipped, 0, "E19-sig-forgery: tampered op is dropped pre-gate");

    Row {
        scenario: "E19-sig-forgery",
        description: "Tampered data op fails Op::verify and never reaches the gate",
        injected: 1,
        applied,
        skipped,
        outcome,
    }
}

/// A correctly-signed data op whose HLC is fabricated to land strictly
/// after the credential's `exp_ms`. Replay accepts the op into the DAG
/// (signature is valid) but the gate denies it because the epoch's HLC
/// window has elapsed.
fn scenario_hlc_after_exp() -> Row {
    let (vendor_sk, vendor_pk) = make_keypair("vendor/hlc");
    let (writer_sk, writer_pk) = make_keypair("writer/hlc");

    let mut ops: Vec<Op> = Vec::new();
    let mut hlc_ms: u64 = 4_000_000;
    let mut next_logical: u32 = 0;
    let mut next_hlc = || -> Hlc {
        hlc_ms += 1;
        next_logical = next_logical.wrapping_add(1);
        Hlc::new(hlc_ms, next_logical)
    };

    let ik_hlc = next_hlc();
    ops.push(Op::new(
        vec![],
        ik_hlc,
        vendor_pk,
        Payload::IssuerKey {
            issuer_id: "vendor-hlc".into(),
            key_id: "k1".into(),
            algo: "EdDSA".into(),
            pubkey: vendor_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &vendor_sk,
    ));

    // Credential with a tight exp window: nbf = current ms; exp = nbf + 100 ms.
    let cred_hlc = next_hlc();
    let exp_ms = cred_hlc.physical_ms + 100;
    let (cred_op, grant_op) = synth_credential_and_grant_with_exp(
        &vendor_sk,
        &vendor_pk,
        "vendor-hlc".into(),
        writer_pk,
        cred_hlc,
        exp_ms,
    );
    let grant_id = grant_op.op_id;
    ops.push(cred_op);
    ops.push(grant_op);

    // In-window write: HLC.physical_ms < exp_ms. Should apply.
    let in_window = Op::new(
        vec![grant_id],
        next_hlc(),
        writer_pk,
        Payload::Data {
            key: "mv:c0:param0".into(),
            value: vec![0x01],
        },
        &writer_sk,
    );
    ops.push(in_window);

    // Fabricated-HLC write: HLC.physical_ms = exp_ms + 1_000_000_000 (a year
    // in the future). The op is signed correctly so it ingests cleanly,
    // but the epoch has expired and the gate must deny it.
    let fabricated_hlc = Hlc::new(exp_ms + 1_000_000_000, 0);
    let fabricated = Op::new(
        vec![grant_id],
        fabricated_hlc,
        writer_pk,
        Payload::Data {
            key: "mv:c0:param1".into(),
            value: vec![0x02],
        },
        &writer_sk,
    );
    ops.push(fabricated);

    let (applied, skipped) = replay_and_count(&ops);

    let outcome = if applied == 1 && skipped == 1 { "PASS" } else { "FAIL" };
    assert_eq!(applied, 1, "E19-hlc-after-exp: only in-window op should apply");
    assert_eq!(skipped, 1, "E19-hlc-after-exp: fabricated-HLC op should be denied");

    Row {
        scenario: "E19-hlc-after-exp",
        description: "Fabricated future HLC ingests cleanly but is denied by the expired epoch",
        injected: 1,
        applied,
        skipped,
        outcome,
    }
}

/// Insert the same Op twice; DAG dedup must collapse them into one node and
/// replay must apply the underlying op exactly once. Demonstrates idempotent
/// merge against a duplicate-event injection attack.
fn scenario_duplicate_op_id() -> Row {
    let (vendor_sk, vendor_pk) = make_keypair("vendor/dup");
    let (writer_sk, writer_pk) = make_keypair("writer/dup");

    let mut ops: Vec<Op> = Vec::new();
    let mut hlc_ms: u64 = 5_000_000;
    let mut next_logical: u32 = 0;
    let mut next_hlc = || -> Hlc {
        hlc_ms += 1;
        next_logical = next_logical.wrapping_add(1);
        Hlc::new(hlc_ms, next_logical)
    };

    let ik_hlc = next_hlc();
    ops.push(Op::new(
        vec![],
        ik_hlc,
        vendor_pk,
        Payload::IssuerKey {
            issuer_id: "vendor-dup".into(),
            key_id: "k1".into(),
            algo: "EdDSA".into(),
            pubkey: vendor_pk.to_vec(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
            prev_key_id: None,
        },
        &vendor_sk,
    ));

    let cred_hlc = next_hlc();
    let (cred_op, grant_op) = synth_credential_and_grant(
        &vendor_sk,
        &vendor_pk,
        "vendor-dup".into(),
        writer_pk,
        cred_hlc,
    );
    let grant_id = grant_op.op_id;
    ops.push(cred_op);
    ops.push(grant_op);

    let data = Op::new(
        vec![grant_id],
        next_hlc(),
        writer_pk,
        Payload::Data {
            key: "mv:c0:param0".into(),
            value: vec![0xDE, 0xAD],
        },
        &writer_sk,
    );
    let dup = data.clone(); // identical op_id
    ops.push(data);
    ops.push(dup);

    let (applied, skipped) = replay_and_count(&ops);
    let outcome = if applied == 1 && skipped == 0 { "PASS" } else { "FAIL" };
    assert_eq!(applied, 1, "E19-dup: duplicate op_id should collapse to one apply");
    assert_eq!(skipped, 0, "E19-dup: no skips expected");

    Row {
        scenario: "E19-duplicate-opid",
        description: "Duplicate op_id is deduplicated by DAG; underlying op applied once",
        injected: 1,
        applied,
        skipped,
        outcome,
    }
}

// ----- helpers ---------------------------------------------------------------

fn replay_and_count(ops: &[Op]) -> (usize, usize) {
    let mut dag = Dag::new();
    for op in ops {
        dag.insert(op.clone());
    }
    METRICS.reset();
    let _ = replay::replay_full(&dag);
    let applied = METRICS.counter("ops_applied") as usize;
    let skipped = METRICS.counter("ops_skipped_policy") as usize;
    (applied, skipped)
}

fn make_keypair(label: &str) -> (SigningKey, [u8; 32]) {
    let sk = key_pair_from_label(label);
    let pk = vk_to_bytes(&sk.verifying_key());
    (sk, pk)
}

fn key_pair_from_label(label: &str) -> SigningKey {
    let h = blake3::hash(label.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn synth_credential_and_grant(
    issuer_sk: &SigningKey,
    issuer_pk: &[u8; 32],
    issuer_id: String,
    subject_pk: [u8; 32],
    hlc: Hlc,
) -> (Op, Op) {
    synth_credential_and_grant_with_exp(issuer_sk, issuer_pk, issuer_id, subject_pk, hlc, u64::MAX)
}

fn synth_credential_and_grant_with_exp(
    issuer_sk: &SigningKey,
    issuer_pk: &[u8; 32],
    issuer_id: String,
    subject_pk: [u8; 32],
    hlc: Hlc,
    exp_ms: u64,
) -> (Op, Op) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    use serde_json::json;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let sub_hex = hex(&subject_pk);
    let claims = json!({
        "sub_pk": sub_hex,
        "role": "editor",
        "scope": ["hv", "mech"],
        "nbf": hlc.physical_ms,
        "exp": exp_ms,
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
