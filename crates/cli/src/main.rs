//! ECAC CLI
//!
//! Commands:
//!   1) replay <ops.cbor>
//!      - Loads CBOR-encoded Vec<Op> (or single Op), builds DAG, replays deterministically,
//!        prints deterministic JSON and state digest.
//!   2) project <ops.cbor> <obj field>
//!      - Same replay, then prints a deterministic projection of the requested field.
//!   3) simulate <scenario>
//!      - Synthesizes policy+data scenarios to demonstrate M3 deny-wins gating.
//!        Scenarios: "offline_edit", "grant_after_edit", "both" (default: both).
//!
//! Notes:
//!   - DAG ignores ops whose parents are unknown (pending); replay only uses activated ops.
//!   - Deny-wins gate is enforced iff the log contains *any* Grant/Revoke events.
//!     If there are no policy events, replay behaves like M2 (allow-all).

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::policy;
use ecac_core::policy::Action;
use ecac_core::replay::replay_full;
use ecac_core::state::FieldValue;

/// CLI definition
#[derive(Parser)]
#[command(name = "ecac", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Replay a CBOR ops file and print deterministic state JSON + digest
    Replay {
        /// Path to CBOR file containing Vec<Op> (or a single Op)
        ops: PathBuf,
    },

    /// Project a specific field (obj, field) after replay
    Project {
        /// Path to CBOR file containing Vec<Op> (or a single Op)
        ops: PathBuf,
        /// Object id (as used in keys)
        obj: String,
        /// Field name
        field: String,
    },

    /// Synthesize scenarios to demonstrate deny-wins gating.
    /// Scenarios: "offline_edit", "grant_after_edit", "both" (default: both)
    Simulate {
        /// Scenario name
        #[arg(default_value = "both")]
        scenario: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Replay { ops } => cmd_replay(ops)?,
        Cmd::Project { ops, obj, field } => cmd_project(ops, obj, field)?,
        Cmd::Simulate { scenario } => cmd_simulate(scenario)?,
    }
    Ok(())
}

fn cmd_replay(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let ops = read_ops_cbor(&path)?;
    let (state, digest) = replay_over_ops(&ops);

    println!("{}", state.to_deterministic_json_string());
    println!("digest={}", hex32(&digest));
    Ok(())
}

fn cmd_project(path: PathBuf, obj: String, field: String) -> Result<(), Box<dyn std::error::Error>> {
    let ops = read_ops_cbor(&path)?;
    let (state, _digest) = replay_over_ops(&ops);

    let Some(fields) = state.objects.get(&obj) else {
        println!(r#"{{"error":"object not found","obj":"{}"}}"#, obj);
        return Ok(());
    };
    let Some(fv) = fields.get(&field) else {
        println!(r#"{{"error":"field not found","obj":"{}","field":"{}"}}"#, obj, field);
        return Ok(());
    };

    match fv {
        FieldValue::MV(mv) => {
            let project = mv.project().map(hex);
            // winners should be hash-sorted in JSON; mv.values() returns byte-sorted.
            // We'll compute hash order locally for display parity with core exporter.
            let mut winners = mv.values()
                .into_iter()
                .map(|v| (blake3_hash32(&v), v))
                .collect::<Vec<_>>();
            winners.sort_by(|a, b| if a.0 != b.0 { a.0.cmp(&b.0) } else { a.1.cmp(&b.1) });

            print!(r#"{{"type":"mv","project":{},"winners":["#,
                project.as_ref().map(|s| format!(r#""{}""#, s)).unwrap_or_else(|| "null".into())
            );
            for (i, (_, v)) in winners.iter().enumerate() {
                if i > 0 { print!(","); }
                print!(r#""{}""#, hex(v));
            }
            println!("]}}");
        }
        FieldValue::Set(set) => {
            // Deterministic order from iter_present (lexicographic keys).
            print!(r#"{{"type":"set","elements":["#);
            let mut first = true;
            for (ek, v) in set.iter_present() {
                if !first { print!(","); }
                first = false;
                print!(r#"{{"key":"{}","value":"{}"}}"#, ek, hex(&v));
            }
            println!("]}}");
        }
    }

    Ok(())
}

fn cmd_simulate(scenario: String) -> Result<(), Box<dyn std::error::Error>> {
    match scenario.as_str() {
        "offline_edit" => run_offline_edit()?,
        "grant_after_edit" => run_grant_after_edit()?,
        "both" => {
            run_offline_edit()?;
            println!();
            run_grant_after_edit()?;
        }
        other => {
            eprintln!("unknown scenario '{}'; use offline_edit | grant_after_edit | both", other);
            std::process::exit(2);
        }
    }
    Ok(())
}

fn replay_over_ops(ops: &[Op]) -> (ecac_core::state::State, [u8; 32]) {
    let mut dag = Dag::new();
    for op in ops {
        dag.insert(op.clone());
    }
    replay_full(&dag)
}

/// Read a CBOR file containing either Vec<Op> or a single Op.
fn read_ops_cbor(path: &PathBuf) -> Result<Vec<Op>, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    // Try Vec<Op>
    if let Ok(v) = serde_cbor::from_slice::<Vec<Op>>(&data) {
        return Ok(v);
    }
    // Try single Op
    if let Ok(op) = serde_cbor::from_slice::<Op>(&data) {
        return Ok(vec![op]);
    }
    Err(format!("{}: not a CBOR Vec<Op> or Op", path.display()).into())
}

/// Scenario 1: user edits while admin revokes concurrently; on reconcile, post-revoke edit is skipped.
fn run_offline_edit() -> Result<(), Box<dyn std::error::Error>> {
    println!("-- simulate: offline_edit (grant → write BEFORE → revoke → write AFTER) --");

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let grant = Op::new(
        vec![], Hlc::new(10,1), admin_pk,
        Payload::Grant {
            subject_pk: user_pk, role: "editor".into(), scope_tags: vec!["hv".into()],
            not_before: Hlc::new(10,1), not_after: None
        },
        &admin_sk
    );
    let write_before = Op::new(
        vec![], Hlc::new(11,1), user_pk,
        Payload::Data { key: "mv:o:x".into(), value: b"BEFORE".to_vec() },
        &user_sk
    );
    let revoke = Op::new(
        vec![], Hlc::new(12,1), admin_pk,
        Payload::Revoke { subject_pk: user_pk, role: "editor".into(), scope_tags: vec!["hv".into()], at: Hlc::new(12,1) },
        &admin_sk
    );
    let write_after = Op::new(
        vec![], Hlc::new(13,1), user_pk,
        Payload::Data { key: "mv:o:x".into(), value: b"AFTER".to_vec() },
        &user_sk
    );

    let ops = vec![grant.clone(), write_before.clone(), revoke.clone(), write_after.clone()];
    explain_apply("offline_edit", &ops)?;
    Ok(())
}

/// Scenario 2: user edits, then admin grants; the earlier edit remains denied; a later edit is allowed.
fn run_grant_after_edit() -> Result<(), Box<dyn std::error::Error>> {
    println!("-- simulate: grant_after_edit (write → grant → write) --");

    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    let write_early = Op::new(
        vec![], Hlc::new(10,1), user_pk,
        Payload::Data { key: "mv:o:x".into(), value: b"EARLY".to_vec() },
        &user_sk
    );
    let grant = Op::new(
        vec![], Hlc::new(11,1), admin_pk,
        Payload::Grant {
            subject_pk: user_pk, role: "editor".into(), scope_tags: vec!["hv".into()],
            not_before: Hlc::new(11,1), not_after: None
        },
        &admin_sk
    );
    let write_late = Op::new(
        vec![], Hlc::new(12,1), user_pk,
        Payload::Data { key: "mv:o:x".into(), value: b"LATE".to_vec() },
        &user_sk
    );

    let ops = vec![write_early.clone(), grant.clone(), write_late.clone()];
    explain_apply("grant_after_edit", &ops)?;
    Ok(())
}

/// Build DAG, compute epochs, and print applied vs skipped + final state.
fn explain_apply(label: &str, ops: &[Op]) -> Result<(), Box<dyn std::error::Error>> {
    let mut dag = Dag::new();
    for op in ops { dag.insert(op.clone()); }
    let order = dag.topo_sort();

    let has_policy = order.iter().any(|id| {
        dag.get(id)
            .map(|op| matches!(op.header.payload, Payload::Grant { .. } | Payload::Revoke { .. }))
            .unwrap_or(false)
    });
    let epochs = if has_policy { policy::build_auth_epochs(&dag, &order) } else { Default::default() };

    println!("scenario={}", label);
    println!("order={:?}", order.iter().map(hex32).collect::<Vec<_>>());

    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    for (pos, id) in order.iter().enumerate() {
        let op = dag.get(id).unwrap();
        match &op.header.payload {
            Payload::Data { key, .. } => {
                if let Some((action, _obj, _field, _elem, tags)) = policy::derive_action_and_tags(key) {
                    let allow = if has_policy {
                        policy::is_permitted_at_pos(&epochs, &op.header.author_pk, action, &tags, pos, op.hlc())
                    } else { true };
                    if allow {
                        applied.push((hex32(id), action));
                    } else {
                        skipped.push((hex32(id), action));
                    }
                }
            }
            Payload::Grant { .. } => applied.push((hex32(id), Action::SetField)), // tag as policy
            Payload::Revoke { .. } => applied.push((hex32(id), Action::SetField)), // tag as policy
            _ => {}
        }
    }

    let (state, digest) = replay_full(&dag);

    println!("applied=[{}]", applied.iter().map(|(h,a)| format!(r#"{{"op":"{}","action":"{}"}}"#, h, action_name(*a))).collect::<Vec<_>>().join(","));
    println!("skipped=[{}]", skipped.iter().map(|(h,a)| format!(r#"{{"op":"{}","action":"{}","reason":"deny-wins"}}"#, h, action_name(*a))).collect::<Vec<_>>().join(","));
    println!("{}", state.to_deterministic_json_string());
    println!("digest={}", hex32(&digest));
    Ok(())
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::SetField => "SetField",
        Action::SetAdd => "SetAdd",
        Action::SetRem => "SetRem",
    }
}

/// Hex for arbitrary byte slice.
fn hex<T: AsRef<[u8]>>(v: T) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = v.as_ref();
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0f) as usize] as char);
    }
    out
}

/// Hex for a 32-byte array.
fn hex32(v: &[u8; 32]) -> String {
    hex(v)
}

/// blake3 hash (32 bytes) of a value.
fn blake3_hash32(v: &[u8]) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(v);
    h.finalize().into()
}
