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
//!      - Verifies a JWT-VC, preferring in-band trust (IssuerKey/StatusListChunk
//!        ops in the RocksDB store selected by ECAC_DB) and falling back to
//!        ./trust + ./trust/status if no in-band trust is available.
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
//!      - Verifies a JWT-VC, preferring in-band trust (IssuerKey/StatusListChunk
//!        ops in the RocksDB store selected by ECAC_DB) and falling back to
//!        ./trust + ./trust/status if no in-band trust is available.
//!   5) vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]
//!      - Emits Credential + Grant ops (CBOR) after verifying the VC.
//!   6) vc-status-set <list_id> <index> <0|1|true|false|on|off>
//!      - Flips a single bit in trust/status/<list_id>.bin (little-endian bit order).
//!   7) keyrotate <tag>
//!      - Derive a new key_version for <tag>, store it in the keyring, and emit a KeyRotate op.
//!   8) grant-key <subject_pk> <tag> <version> <vc.jwt>
//!      - Verify the VC and emit a KeyGrant op bound to (subject_pk, tag, version).
//!   9) show <obj> <field> --subject-pk <hex>
//!      - Replay from the store and print the logical field value as visible to the subject
//!        (plaintext if decryptable; "<redacted>" otherwise).
//!   10) trust-issuer-publish <issuer_id> <key_id> <issuer_sk_hex> [out_dir]
//!       - Emit an IssuerKey op declaring an issuer public key on the log (M10).
//!   11) trust-status-chunk <issuer_id> <list_id> <version> <chunk_index> <bitset_sha256_hex> <chunk.bin> <issuer_sk_hex> [out_dir]
//!       - Emit a StatusListChunk op with a status bitset chunk for revocation (M10).
//!   12) trust-dump
//!       - Build and print the in-band TrustView (issuer keys + status lists) from the store.
//!   13) trust-issuer-revoke <issuer_id> <key_id> <reason> <issuer_sk_hex>
//!       - Emit an IssuerKeyRevoke op to deactivate a previously-published issuer key.

//! Notes:
//!   - DAG ignores ops whose parents are unknown (pending); replay only uses activated ops.
//!   - Deny-wins gate is enforced iff the log contains *any* Grant/Revoke events.

mod commands;
mod simulate; // now implemented as a safe stub for M4
              // M7: evaluation harness (implemented in a separate module)
mod bench;

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ecac_core::crypto::PublicKeyBytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpHeader, OpId, Payload};
use ecac_core::replay::replay_full;
use ecac_core::state::FieldValue;
use serde::Deserialize;

/// CLI definition
#[derive(Parser)]
#[command(name = "ecac", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Deserialize)]
struct OpFlatCompat {
    #[serde(default)]
    parents: Vec<OpId>,
    #[serde(default = "default_hlc")]
    hlc: Hlc,
    author_pk: PublicKeyBytes,
    payload: Payload,
    sig: Vec<u8>,
    op_id: [u8; 32],
}

#[inline]
fn default_hlc() -> Hlc {
    Hlc {
        physical_ms: 0,
        logical: 0,
        node_id: 0,
    }
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

    /// Append a single data op into the RocksDB store.
    ///
    /// This is the M2/M3-style writer:
    ///   - key = "mv:<obj>:<field>"
    ///   - value is the UTF-8 bytes of <value>.
    ///
    /// DB is selected via ECAC_DB or defaults to ".ecac.db".
    Write {
        /// Currently only "data" is supported (reserved for future kinds).
        kind: String,
        /// Object id
        obj: String,
        /// Field name
        field: String,
        /// Logical value (UTF-8)
        value: String,
    },

    /// (Temporarily stubbed) Synthesize scenarios. Will be VC-backed in M4.
    Simulate {
        /// Scenario name (ignored for now)
        #[arg(default_value = "both")]
        scenario: String,
    },

    /// Verify a JWT-VC using in-band trust when available.
    ///
    /// - Preferred path: derive issuer keys and status lists from the
    ///   RocksDB store (ECAC_DB or ".ecac.db") via TrustView, using
    ///   IssuerKey / StatusListChunk ops.
    /// - Fallback path: if no usable in-band trust is present, use
    ///   ./trust/issuers.toml and ./trust/status/*.bin (legacy M4 mode).
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

    /// Mint a demo VC + trust config for local testing.
    ///
    /// - Generates issuer + subject keys.
    /// - Writes ./trust/issuers.toml
    /// - Writes ./vc.jwt
    /// - Prints JSON with issuer_vk_hex, subject_pk_hex, vc_path.
    VcMintDemo,

    /// Publish an in-band issuer key (IssuerKey op) into the store.
    ///
    /// This writes a Payload::IssuerKey op signed by the issuer SK into the
    /// RocksDB store selected by ECAC_DB (default ".ecac.db").
    TrustIssuerPublish {
        /// Logical issuer identifier (matches VC `iss`)
        issuer_id: String,
        /// Logical key identifier (matches VC `kid`)
        key_id: String,
        /// Algorithm label ("EdDSA" for ed25519 keys)
        algo: String,
        /// Issuer secret key (32-byte ed25519) hex
        issuer_sk_hex: String,
        /// Optional previous key id for rollover
        #[arg(long)]
        prev_key_id: Option<String>,
        /// Not-before timestamp in ms since UNIX epoch (defaults to now)
        #[arg(long)]
        valid_from_ms: Option<u64>,
        /// Not-after timestamp in ms since UNIX epoch (defaults to now + 365 days)
        #[arg(long)]
        valid_until_ms: Option<u64>,
    },

    /// Revoke an in-band issuer key on the log.
    ///
    /// This writes a Payload::IssuerKeyRevoke op signed by the issuer SK into
    /// the RocksDB store selected by ECAC_DB (default ".ecac.db").
    TrustIssuerRevoke {
        /// Logical issuer identifier (matches VC `iss`)
        issuer_id: String,
        /// Logical key identifier (matches VC `kid`)
        key_id: String,
        /// Human-readable revocation reason (for audit/debug)
        reason: String,
        /// Issuer secret key (32-byte ed25519) hex
        issuer_sk_hex: String,
    },

    /// Publish a single in-band status-list chunk into the store.
    ///
    /// This writes a Payload::StatusListChunk op signed by the issuer SK.
    TrustStatusChunk {
        /// Issuer identifier owning the list
        issuer_id: String,
        /// Logical status-list identifier
        list_id: String,
        /// Status list version
        version: u32,
        /// Chunk index (0-based)
        chunk_index: u32,
        /// Path to the chunk bytes (bitset) file
        chunk_path: PathBuf,
        /// Issuer secret key (32-byte ed25519) hex
        issuer_sk_hex: String,
        /// Hex-encoded SHA-256 over the COMPLETE status bitset (64 hex chars)
        #[arg(long = "bitset-sha256-hex")]
        bitset_sha256_hex: Option<String>,
    },

    /// Dump the in-band TrustView (issuer keys + status lists) from the store.
    ///
    /// - Reads ops from RocksDB (ECAC_DB or ".ecac.db").
    /// - Builds TrustView from in-band IssuerKey / StatusListChunk ops.
    /// - Prints a deterministic JSON summary (issuers, status_lists, digests).
    TrustDump,

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

    /// Rotate a symmetric key for a confidentiality tag and emit a KeyRotate op.
    ///
    /// DB is selected via ECAC_DB or defaults to ".ecac.db".
    #[command(name = "keyrotate")]
    KeyRotate {
        /// Logical tag name (e.g., "hv", "mech", "confidential")
        tag: String,
    },

    /// Emit a KeyGrant op for a subject on (tag, key_version) backed by a VC.
    ///
    /// - subject_pk is 32-byte ed25519 public key hex.
    /// - VC is verified under ./trust and ./trust/status.
    /// - DB is selected via ECAC_DB or defaults to ".ecac.db".
    GrantKey {
        /// Subject public key (32-byte ed25519) hex
        subject_pk: String,
        /// Logical confidentiality tag ("hv", "mech", ...)
        tag: String,
        /// Symmetric key version for this tag
        version: u32,
        /// Path to compact JWS (JWT-VC)
        vc: PathBuf,
    },

    /// Show the logical value of <obj>.<field> as visible to a given subject.
    ///
    /// - Replays from the RocksDB store (ECAC_DB or ".ecac.db").
    /// - Uses local keyring + KeyGrant ops to try decryption.
    /// - Prints plaintext or "<redacted>".
    Show {
        /// Object id
        obj: String,
        /// Field name
        field: String,
        /// Subject public key (32-byte ed25519) hex
        #[arg(long = "subject-pk")]
        subject_pk: String,
    },

    /// Append op(s) from CBOR file or directory into a RocksDB store
    OpAppend {
        /// Path to RocksDB directory (created if missing)
        #[arg(long, short)]
        db: PathBuf,
        /// A .cbor file or a directory containing *.cbor (or *.op.cbor) files
        input: PathBuf,
    },
    /// Same as op-append, but also emits audit SkippedOp on signature failures
    #[cfg(feature = "audit")]
    OpAppendAudited {
        #[arg(long, short)]
        db: PathBuf,
        input: PathBuf,
    },
    /// Deterministic replay from a RocksDB store (equals `replay <ops.cbor>`)
    ReplayFromStore {
        #[arg(long, short)]
        db: PathBuf,
        /// If set, show latest checkpoint then (for now) do a full replay (incremental will replace this).
        #[arg(long)]
        from_checkpoint: bool,
    },
    /// Create a checkpoint of current materialized state
    CheckpointCreate {
        #[arg(long, short)]
        db: PathBuf,
    },
    /// Show latest checkpoint (if any)
    CheckpointList {
        #[arg(long, short)]
        db: PathBuf,
    },
    /// Load a checkpoint and print deterministic JSON
    CheckpointLoad {
        #[arg(long, short)]
        db: PathBuf,
        id: u64,
    },
    /// Run integrity checks over the store
    VerifyStore {
        #[arg(long, short)]
        db: PathBuf,
    },

    /// Run the M7 evaluation harness and emit CSV/JSON artifacts
    Bench {
        /// Scenario name: hb-chain | concurrent | offline-revoke | partition-3
        #[arg(long, default_value = "hb-chain")]
        scenario: String,
        /// RNG seed for determinism
        #[arg(long, default_value_t = 1u64)]
        seed: u64,
        /// Number of ops to generate
        #[arg(long, default_value_t = 100usize)]
        ops: usize,
        /// Number of peers (>=1). With --net, drives multi-node runs.
        #[arg(long, default_value_t = 1usize)]
        peers: usize,
        /// Enable networked scenarios (requires net feature and M6)
        #[arg(long)]
        net: bool,
        /// Optional partition schedule (JSON). Only meaningful with --net.
        #[arg(long)]
        partition: Option<PathBuf>,
        /// Create a checkpoint every K ops (optional)
        #[arg(long)]
        checkpoint_every: Option<usize>,
        /// Output directory for artifacts
        #[arg(long, default_value = "docs/eval/out")]
        out_dir: PathBuf,
    },
    /// Corrupt signature(s) in an Op/Vec<Op> CBOR to provoke invalid_sig
    OpCorruptSig {
        /// Input .cbor file (Op or Vec<Op>)
        input: PathBuf,
        /// Output .cbor file
        output: PathBuf,
    },

    /// Make a new op with a bogus parent and sign it (to provoke bad_parent)
    OpMakeOrphan {
        /// Base .cbor with at least one Op; cloned payload of last Op is used
        base: PathBuf,
        /// Author secret key (32-byte ed25519) hex
        author_sk_hex: String,
        /// Output .cbor file
        output: PathBuf,
    },
    /// Make a minimal single valid op (Credential) for testing
    OpMakeMin {
        author_sk_hex: String,
        output: String,
    },
    /// Write a minimal Credential + Grant pair into a directory
    OpMakeGrant {
        /// Author (issuer) secret key hex (32-byte ed25519)
        author_sk_hex: String,
        /// Admin secret key hex (32-byte ed25519)
        admin_sk_hex: String,
        /// Output directory
        out_dir: PathBuf,
    },
    // ===== M8 audit subcommands =====
    /// Verify audit chain integrity (hash-link + signatures) in <dir> (default: ".audit")
    AuditVerifyChain {
        /// Audit directory (default: ".audit")
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Export audit log to deterministic JSONL
    AuditExport {
        /// Audit directory (default: ".audit")
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Output file (default: "audit.jsonl")
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify chain AND cross-check replay decisions vs audit (expects "<db>/audit")
    AuditVerifyFull {
        /// DB directory (default: ".ecac.db")
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Dump decoded audit entries (whole log or a single segment)
    AuditCat {
        /// Audit directory (default: ".audit")
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Specific segment file (e.g., "segment-00000001.log")
        #[arg(long)]
        segment: Option<PathBuf>,
    },
    /// Replay the store and write decision events to the on-disk audit sink
    #[cfg(feature = "audit")]
    AuditRecord {
        /// RocksDB directory (default ".ecac.db")
        #[arg(long, default_value = ".ecac.db")]
        db: String,
    },
}

fn decode_op_compat(bytes: &[u8]) -> anyhow::Result<Op> {
    if let Ok(op) = serde_cbor::from_slice::<Op>(bytes) {
        return Ok(op);
    }
    let f: OpFlatCompat = serde_cbor::from_slice(bytes)?;
    Ok(Op {
        header: OpHeader {
            parents: f.parents,
            hlc: f.hlc,
            author_pk: f.author_pk,
            payload: f.payload,
        },
        sig: f.sig,
        op_id: f.op_id,
    })
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Replay { ops } => cmd_replay(ops)?,
        Cmd::Project { ops, obj, field } => cmd_project(ops, obj, field)?,
        Cmd::Write {
            kind,
            obj,
            field,
            value,
        } => {
            // M2/M3-style writer; no encryption-on-write yet.
            commands::cmd_write(&kind, &obj, &field, &value)?;
        }
        Cmd::Simulate { scenario } => simulate::cmd_simulate(Some(scenario.as_str()))?,
        Cmd::VcVerify { vc } => commands::cmd_vc_verify(vc.as_os_str().to_str().unwrap())?,
        Cmd::VcAttach {
            vc,
            issuer_sk_hex,
            admin_sk_hex,
            out_dir,
        } => {
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

        Cmd::VcMintDemo => {
            commands::cmd_vc_mint_demo()?;
        }

        Cmd::TrustIssuerPublish {
            issuer_id,
            key_id,
            algo,
            issuer_sk_hex,
            prev_key_id,
            valid_from_ms,
            valid_until_ms,
        } => {
            commands::cmd_trust_issuer_publish(
                &issuer_id,
                &key_id,
                &algo,
                &issuer_sk_hex,
                prev_key_id.as_deref(),
                valid_from_ms,
                valid_until_ms,
            )?;
        }

        Cmd::TrustIssuerRevoke {
            issuer_id,
            key_id,
            reason,
            issuer_sk_hex,
        } => {
            commands::cmd_trust_issuer_revoke(&issuer_id, &key_id, &reason, &issuer_sk_hex)?;
        }

        Cmd::TrustStatusChunk {
            issuer_id,
            list_id,
            version,
            chunk_index,
            chunk_path,
            issuer_sk_hex,
            bitset_sha256_hex,
        } => {
            commands::cmd_trust_status_chunk(
                &issuer_id,
                &list_id,
                version,
                chunk_index,
                &chunk_path,
                &issuer_sk_hex,
                bitset_sha256_hex.as_deref(),
            )?;
        }

        Cmd::TrustDump => {
            // Build TrustView from the in-band trust ops in the current store.
            commands::cmd_trust_dump()?;
        }

        Cmd::VcStatusSet {
            list_id,
            index,
            value,
        } => {
            let v = parse_bool_flag(&value)?;
            commands::cmd_vc_status_set(&list_id, index, v)?;
        }

        Cmd::KeyRotate { tag } => {
            commands::cmd_keyrotate(&tag)?;
        }

        Cmd::GrantKey {
            subject_pk,
            tag,
            version,
            vc,
        } => {
            commands::cmd_grant_key(&subject_pk, &tag, version, vc.as_os_str().to_str().unwrap())?;
        }

        Cmd::Show {
            obj,
            field,
            subject_pk,
        } => {
            commands::cmd_show(&obj, &field, &subject_pk)?;
        }
        Cmd::OpAppend { db, input } => {
            use ecac_store::Store;
            let store = Store::open(&db, Default::default())?;
            let mut files = Vec::new();
            if input.is_dir() {
                for ent in fs::read_dir(&input)? {
                    let p = ent?.path();
                    if let Some(ext) = p.extension() {
                        if ext == "cbor" {
                            files.push(p);
                        }
                    }
                }
                files.sort();
            } else {
                files.push(input);
            }

            for f in files {
                // Use the same tolerant reader as Replay/Project (handles Vec<Op>, single Op, and flat)
                let ops = read_ops_cbor(&f)?;
                for op in ops {
                    let bytes = ecac_core::serialize::canonical_cbor(&op);
                    let id = store.put_op_cbor(&bytes)?;
                    eprintln!("appended {}", hex32(&id));
                }
            }
        }

        #[cfg(feature = "audit")]
        Cmd::OpAppendAudited { db, input } => {
            let mut files = Vec::new();
            if input.is_dir() {
                for ent in fs::read_dir(&input)? {
                    let p = ent?.path();
                    if let Some(ext) = p.extension() {
                        if ext == "cbor" {
                            files.push(p);
                        }
                    }
                }
                files.sort();
            } else {
                files.push(input);
            }
            commands::cmd_op_append_audited(&db, files)?;
        }

        Cmd::ReplayFromStore {
            db,
            from_checkpoint,
        } => {
            use ecac_store::Store;
            let store = Store::open(&db, Default::default())?;

            // 1) Load all ops in topo order
            let ids = store.topo_ids()?;
            let cbor = store.load_ops_cbor(&ids)?;
            let mut ops = Vec::with_capacity(cbor.len());
            for b in cbor {
                ops.push(decode_op_compat(&b)?);
            }

            // 2) Optional checkpoint fast-path, only if the flag was provided
            let state_opt = if from_checkpoint {
                if let Some((ck_id, _topo)) = store.checkpoint_latest()? {
                    let (mut s, saved_topo) = store.checkpoint_load(ck_id)?;
                    s.set_processed_count(saved_topo as usize);
                    if s.processed_count() > ops.len() {
                        s.set_processed_count(ops.len());
                    }
                    Some(s)
                } else {
                    None
                }
            } else {
                None
            };

            // 3) Full DAG view + incremental apply if we had a checkpoint
            let (state, digest) = replay_over_ops_with_state(state_opt, &ops);
            println!("{}", state.to_deterministic_json_string());
            println!("digest={}", hex32(&digest));
        }

        Cmd::CheckpointCreate { db } => {
            use ecac_store::Store;
            let store = Store::open(&db, Default::default())?;
            let ids = store.topo_ids()?;
            let cbor = store.load_ops_cbor(&ids)?;
            let ops: Vec<Op> = cbor
                .into_iter()
                .map(|b| serde_cbor::from_slice::<Op>(&b))
                .collect::<Result<_, _>>()?;
            let (state, _d) = replay_over_ops(&ops);
            let id = store.checkpoint_create(&state, ids.len() as u64)?;
            println!("{id}");
        }
        Cmd::CheckpointList { db } => {
            use ecac_store::Store;
            let store = Store::open(&db, Default::default())?;
            if let Some((id, topo)) = store.checkpoint_latest()? {
                println!("latest: {} @ topo_idx={}", id, topo);
            } else {
                println!("(no checkpoints)");
            }
        }
        Cmd::CheckpointLoad { db, id } => {
            use ecac_store::Store;
            let store = Store::open(&db, Default::default())?;
            let (state, topo_idx) = store.checkpoint_load(id)?;
            println!("{}", state.to_deterministic_json_string());
            eprintln!("checkpoint_topo_idx={}", topo_idx);
        }
        Cmd::VerifyStore { db } => {
            use ecac_store::Store;
            let store = Store::open(&db, Default::default())?;
            store.verify_integrity()?;
            println!("OK");
        }
        Cmd::Bench {
            scenario,
            seed,
            ops,
            peers,
            net,
            partition,
            checkpoint_every,
            out_dir,
        } => {
            // Delegate to the M7 harness (to be added next)
            bench::run(bench::Options {
                scenario,
                seed,
                ops,
                peers,
                net,
                partition,
                checkpoint_every,
                out_dir,
            })?;
        }
        Cmd::OpCorruptSig { input, output } => {
            commands::cmd_op_corrupt_sig(
                input.as_os_str().to_str().unwrap(),
                output.as_os_str().to_str().unwrap(),
            )?;
        }

        Cmd::OpMakeOrphan {
            base,
            author_sk_hex,
            output,
        } => {
            commands::cmd_op_make_orphan(
                base.as_os_str().to_str().unwrap(),
                &author_sk_hex,
                output.as_os_str().to_str().unwrap(),
            )?;
        }
        // ===== M8 audit subcommands =====
        Cmd::OpMakeGrant {
            author_sk_hex,
            admin_sk_hex,
            out_dir,
        } => {
            commands::cmd_op_make_grant(&author_sk_hex, &admin_sk_hex, out_dir.as_path())?;
        }
        Cmd::AuditVerifyChain { dir } => {
            #[cfg(feature = "audit")]
            {
                commands::cmd_audit_verify(dir.as_ref().and_then(|p| p.to_str()))?;
            }
            #[cfg(not(feature = "audit"))]
            {
                // Silence unused variable warning when audit feature is disabled.
                let _ = &dir;
                eprintln!("audit feature is not enabled; rebuild with --features audit");
            }
        }

        Cmd::AuditExport { dir, out } => {
            #[cfg(feature = "audit")]
            {
                commands::cmd_audit_export(
                    dir.as_ref().and_then(|p| p.to_str()),
                    out.as_ref().and_then(|p| p.to_str()),
                )?;
            }
            #[cfg(not(feature = "audit"))]
            {
                // Silence unused variable warnings when audit feature is disabled.
                let _ = (&dir, &out);
                eprintln!("audit feature is not enabled; rebuild with --features audit");
            }
        }

        Cmd::AuditVerifyFull { db } => {
            #[cfg(feature = "audit")]
            {
                commands::cmd_audit_verify_full(db.as_ref().and_then(|p| p.to_str()))?;
            }
            #[cfg(not(feature = "audit"))]
            {
                // Silence unused variable warning when audit feature is disabled.
                let _ = &db;
                eprintln!("audit feature is not enabled; rebuild with --features audit");
            }
        }

        Cmd::AuditCat { dir, segment } => {
            #[cfg(feature = "audit")]
            {
                let dir_opt = dir.as_ref().and_then(|p| p.to_str());
                let seg_opt = segment.as_ref().and_then(|p| p.to_str());
                commands::cmd_audit_cat(dir_opt, seg_opt)?;
            }
            #[cfg(not(feature = "audit"))]
            {
                // Silence unused variable warnings when audit feature is disabled.
                let _ = (&dir, &segment);
                eprintln!("audit feature is not enabled; rebuild with --features audit");
            }
        }
        #[cfg(feature = "audit")]
        Cmd::AuditRecord { db } => {
            commands::cmd_audit_record(Some(db.as_str()))?;
        }
        Cmd::OpMakeMin {
            author_sk_hex,
            output,
        } => {
            // helper for tests: create a valid one-element Vec<Op> CBOR file
            commands::cmd_op_make_min(&author_sk_hex, &output)?;
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
        println!(
            r#"{{"error":"field not found","obj":"{}","field":"{}"}}"#,
            obj, field
        );
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
            winners.sort_by(|a, b| {
                if a.0 != b.0 {
                    a.0.cmp(&b.0)
                } else {
                    a.1.cmp(&b.1)
                }
            });

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

fn replay_over_ops_with_state(
    st: Option<ecac_core::state::State>,
    ops: &[Op],
) -> (ecac_core::state::State, [u8; 32]) {
    // Build full DAG so policy epochs and HB checks see complete history
    let mut dag = Dag::new();
    for op in ops {
        dag.insert(op.clone());
    }
    match st {
        Some(mut s) => {
            // IMPORTANT: apply_incremental will skip prefix based on s.processed_count()
            let (_s2, digest) = ecac_core::replay::apply_incremental(&mut s, &dag);
            (s, digest)
        }
        None => ecac_core::replay::replay_full(&dag),
    }
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
    // ---- Compatibility: accept legacy *flat* ops (no header wrapper).
    // Older artifacts had fields at the top level:
    // { parents?, hlc?, author_pk, payload, sig, op_id }

    // Try Vec<OpFlatCompat>
    if let Ok(vf) = serde_cbor::from_slice::<Vec<OpFlatCompat>>(&data) {
        let out = vf
            .into_iter()
            .map(|f| Op {
                header: ecac_core::op::OpHeader {
                    parents: f.parents,
                    hlc: f.hlc,
                    author_pk: f.author_pk,
                    payload: f.payload,
                },
                sig: f.sig,
                op_id: f.op_id,
            })
            .collect();
        return Ok(out);
    }
    // Try single OpFlatCompat
    if let Ok(f) = serde_cbor::from_slice::<OpFlatCompat>(&data) {
        let op = Op {
            header: ecac_core::op::OpHeader {
                parents: f.parents,
                hlc: f.hlc,
                author_pk: f.author_pk,
                payload: f.payload,
            },
            sig: f.sig,
            op_id: f.op_id,
        };
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
        "1" | "true" | "on" => Ok(true),
        "0" | "false" | "off" => Ok(false),
        other => anyhow::bail!("invalid value '{other}'; expected one of: 1,0,true,false,on,off"),
    }
}
