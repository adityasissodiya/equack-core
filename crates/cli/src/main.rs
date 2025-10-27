//! ECAC CLI
//!
//! Commands:
//!   1) replay <ops.cbor>
//!      - Loads CBOR-encoded Vec<Op> (or single Op), builds DAG, replays deterministically,
//!        prints deterministic JSON and state digest.
//!   2) project <ops.cbor> <obj field>
//!      - Same replay, then prints a deterministic projection of the requested field.
//!   3) simulate <scenario>
//!      - Stub for now (M4 uses VC-backed grants). We'll wire a VC-backed simulator later.
//!   4) vc-verify <vc.jwt>
//!      - Verifies a JWT-VC using ./trust and ./trust/status.
//!   5) vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]
//!      - Emits Credential + Grant ops (CBOR) after verifying the VC.
//
// Notes:
//   - DAG ignores ops whose parents are unknown (pending); replay only uses activated ops.
//   - Deny-wins gate is enforced iff the log contains *any* Grant/Revoke events.
//! ECAC CLI
//!
//! Commands:
//!   1) replay <ops.cbor>
//!      - Loads CBOR-encoded Vec<Op> (or single Op), builds DAG, replays deterministically,
//!        prints deterministic JSON and state digest.
//!   2) project <ops.cbor> <obj field>
//!      - Same replay, then prints a deterministic projection of the requested field.
//!   3) simulate <scenario>
//!      - Stub for now (M4 uses VC-backed grants). We'll wire a VC-backed simulator later.
//!   4) vc-verify <vc.jwt>
//!      - Verifies a JWT-VC using ./trust and ./trust/status.
//!   5) vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]
//!      - Emits Credential + Grant ops (CBOR) after verifying the VC.
//!   6) vc-status-set <list_id> <index> <0|1|true|false|on|off>
//!      - Flips a single bit in trust/status/<list_id>.bin (little-endian bit order).
//!
//! Notes:
//!   - DAG ignores ops whose parents are unknown (pending); replay only uses activated ops.
//!   - Deny-wins gate is enforced iff the log contains *any* Grant/Revoke events.

mod commands;
mod simulate; // now implemented as a safe stub for M4

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ecac_core::dag::Dag;
use ecac_core::op::Op;
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

    /// (Temporarily stubbed) Synthesize scenarios. Will be VC-backed in M4.
    Simulate {
        /// Scenario name (ignored for now)
        #[arg(default_value = "both")]
        scenario: String,
    },

    /// Verify a JWT-VC under ./trust (issuers.toml) and ./trust/status
    VcVerify {
        /// Path to compact JWS (JWT-VC)
        vc: PathBuf,
    },

    /// Attach a validated JWT-VC by writing Credential + Grant ops
    VcAttach {
        /// Path to compact JWS (JWT-VC)
        vc: PathBuf,
        /// Issuer secret key (32-byte ed25519) hex
        issuer_sk_hex: String,
        /// Admin secret key (32-byte ed25519) hex
        admin_sk_hex: String,
        /// Output directory (default ".")
        out_dir: Option<PathBuf>,
    },

    /// Flip a bit in a local status list: 1 = revoked, 0 = not revoked
    VcStatusSet {
        /// Status list id (file is ./trust/status/<list_id>.bin)
        list_id: String,
        /// Bit index to set or clear
        index: u32,
        /// New value (true/1 = set, false/0 = clear)
        //#[arg(action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new())]
        //value: bool,
        /// Value to set: 1/0/true/false/on/off
        value: String,
    },
    
}

// fn main() -> anyhow::Result<()> {
//     let cli = Cli::parse();
//     match cli.cmd {
//         Cmd::Replay { ops } => cmd_replay(ops)?,
//         Cmd::Project { ops, obj, field } => cmd_project(ops, obj, field)?,
//         Cmd::Simulate { scenario } => simulate::cmd_simulate(Some(scenario.as_str()))?,
//         Cmd::VcVerify { vc } => commands::cmd_vc_verify(vc.as_os_str().to_str().unwrap())?,
//         Cmd::VcAttach { vc, issuer_sk_hex, admin_sk_hex, out_dir } => {
//             let out = out_dir
//                 .as_ref()
//                 .and_then(|p| p.as_os_str().to_str())
//                 .or_else(|| Some(".")) // default "."
//                 .unwrap();
//             commands::cmd_vc_attach(
//                 vc.as_os_str().to_str().unwrap(),
//                 &issuer_sk_hex,
//                 &admin_sk_hex,
//                 Some(out),
//             )?;
//         }
//         Cmd::VcStatusSet { list_id, index, value } => {
//             commands::cmd_vc_status_set(&list_id, index, value)?;
//         }
//     }
//     Ok(())
// }

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Replay { ops } => cmd_replay(ops)?,
        Cmd::Project { ops, obj, field } => cmd_project(ops, obj, field)?,
        Cmd::Simulate { scenario } => simulate::cmd_simulate(Some(scenario.as_str()))?,
        Cmd::VcVerify { vc } => commands::cmd_vc_verify(vc.as_os_str().to_str().unwrap())?,
        Cmd::VcAttach { vc, issuer_sk_hex, admin_sk_hex, out_dir } => {
            let out = out_dir
                .as_ref()
                .and_then(|p| p.as_os_str().to_str())
                .unwrap_or(".");
            commands::cmd_vc_attach(
                vc.as_os_str().to_str().unwrap(),
                &issuer_sk_hex,
                &admin_sk_hex,
                Some(out),
            )?;
        }
        Cmd::VcStatusSet { list_id, index, value } => {
            let v = parse_bool_flag(&value)?;
            commands::cmd_vc_status_set(&list_id, index, v)?;
        }
    }
    Ok(())
}


fn cmd_replay(path: PathBuf) -> anyhow::Result<()> {
    let ops = read_ops_cbor(&path)?;
    let (state, digest) = replay_over_ops(&ops);

    println!("{}", state.to_deterministic_json_string());
    println!("digest={}", hex32(&digest));
    Ok(())
}

fn cmd_project(path: PathBuf, obj: String, field: String) -> anyhow::Result<()> {
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
            let mut winners = mv
                .values()
                .into_iter()
                .map(|v| (blake3_hash32(&v), v))
                .collect::<Vec<_>>();
            winners.sort_by(|a, b| if a.0 != b.0 { a.0.cmp(&b.0) } else { a.1.cmp(&b.1) });

            print!(
                r#"{{"type":"mv","project":{},"winners":["#,
                project
                    .as_ref()
                    .map(|s| format!(r#""{}""#, s))
                    .unwrap_or_else(|| "null".into())
            );
            for (i, (_, v)) in winners.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                print!(r#""{}""#, hex(v));
            }
            println!("]}}");
        }
        FieldValue::Set(set) => {
            // Deterministic order from iter_present (lexicographic keys).
            print!(r#"{{"type":"set","elements":["#);
            let mut first = true;
            for (ek, v) in set.iter_present() {
                if !first {
                    print!(",");
                }
                first = false;
                print!(r#"{{"key":"{}","value":"{}"}}"#, ek, hex(&v));
            }
            println!("]}}");
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
fn read_ops_cbor(path: &PathBuf) -> anyhow::Result<Vec<Op>> {
    let data = fs::read(path)?;
    // Try Vec<Op>
    if let Ok(v) = serde_cbor::from_slice::<Vec<Op>>(&data) {
        return Ok(v);
    }
    // Try single Op
    if let Ok(op) = serde_cbor::from_slice::<Op>(&data) {
        return Ok(vec![op]);
    }
    anyhow::bail!("{}: not a CBOR Vec<Op> or Op", path.display())
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

fn parse_bool_flag(s: &str) -> anyhow::Result<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "on"  => Ok(true),
        "0" | "false" | "off" => Ok(false),
        other => anyhow::bail!("invalid value '{other}'; expected one of: 1,0,true,false,on,off"),
    }
}
