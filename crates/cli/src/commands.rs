use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use serde_json::json;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::hlc::Hlc;
use ecac_core::op::{CredentialFormat, Op, Payload};
use ecac_core::serialize::canonical_cbor;
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;
use ecac_core::vc::{blake3_hash32, verify_vc};
use ecac_store::Store;
use serde::{Deserialize, Serialize};
use std::path::Path;

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("bad hex")),
    }
}

fn parse_sk_hex(hex: &str) -> Result<SigningKey> {
    let s = hex.trim();
    if s.len() != 64 {
        return Err(anyhow!("expected 64 hex chars for ed25519 secret key"));
    }
    let b = s.as_bytes();
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Ok(SigningKey::from_bytes(&key))
}

fn to_hex32(arr: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in arr {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[derive(Serialize, Deserialize)]
struct PersistVerifiedVc {
    cred_id: String,
    issuer: String,
    subject_pk: [u8; 32],
    role: String,
    scope_tags: Vec<String>,
    nbf_ms: u64,
    exp_ms: u64,
    status_list_id: Option<String>, // <-- was String
    status_index: Option<u32>,      // <-- was u32
    cred_hash: [u8; 32],
}

pub fn cmd_vc_verify(vc_path: &str) -> Result<()> {
    let compact = fs::read(vc_path)?;
    // By convention, look in ./trust and ./trust/status
    let trust =
        TrustStore::load_from_dir("./trust").map_err(|e| anyhow!("trust load failed: {:?}", e))?;
    let mut status = StatusCache::load_from_dir("./trust/status");

    let v = verify_vc(&compact, &trust, &mut status)
        .map_err(|e| anyhow!("VC verify failed: {:?}", e))?;

    //         // Persist VC caches (M5: avoid re-verification on boot)
    // {
    //     // Allow override via env; falls back to ".ecac.db"
    //     let db_dir = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    //     let store = Store::open(Path::new(&db_dir), Default::default())?;

    //     // Raw compact JWT bytes
    //     store.persist_vc_raw(v.cred_hash, &compact)?;

    //     // Verified struct, as CBOR
    //     let verified_cbor = serde_cbor::to_vec(&v)?;
    //     store.persist_vc_verified(v.cred_hash, &verified_cbor)?;
    // }

    // ---- Persist VC caches (optional but sensible) ----
    // DB path via env ECAC_DB or default ".ecac.db"
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // 1) Raw compact JWT bytes
    store.persist_vc_raw(v.cred_hash, &compact)?;

    // 2) Slim, stable, serde-friendly verified snapshot
    let pv = PersistVerifiedVc {
        cred_id: v.cred_id.clone(),
        issuer: v.issuer.clone(),
        subject_pk: v.subject_pk,
        role: v.role.clone(),
        scope_tags: v.scope_tags.iter().cloned().collect(),
        nbf_ms: v.nbf_ms,
        exp_ms: v.exp_ms,
        status_list_id: v.status_list_id.clone(), // now matches Option<String>
        status_index: v.status_index,             // now matches Option<u32>
        cred_hash: v.cred_hash,
    };

    let verified_cbor = serde_cbor::to_vec(&pv)?;
    store.persist_vc_verified(v.cred_hash, &verified_cbor)?;
    // ---------------------------------------------------

    let out = json!({
        "cred_id": v.cred_id,
        "issuer": v.issuer,
        "subject_pk_hex": to_hex32(&v.subject_pk),
        "role": v.role,
        "scope": v.scope_tags.iter().collect::<Vec<_>>(),
        "nbf_ms": v.nbf_ms,
        "exp_ms": v.exp_ms,
        "status_list_id": v.status_list_id,
        "status_index": v.status_index,
        "cred_hash_hex": to_hex32(&v.cred_hash),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub fn cmd_vc_attach(
    vc_path: &str,
    issuer_sk_hex: &str,
    admin_sk_hex: &str,
    out_dir_opt: Option<&str>,
) -> Result<()> {
    let compact = fs::read(vc_path)?;

    // Verify first (to extract fields & ensure it's valid).
    let trust =
        TrustStore::load_from_dir("./trust").map_err(|e| anyhow!("trust load failed: {:?}", e))?;
    let mut status = StatusCache::load_from_dir("./trust/status");
    let v = verify_vc(&compact, &trust, &mut status)
        .map_err(|e| anyhow!("VC verify failed: {:?}", e))?;

    let cred_hash = blake3_hash32(&compact);

    // Keys
    let issuer_sk = parse_sk_hex(issuer_sk_hex)?;
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());
    let admin_sk = parse_sk_hex(admin_sk_hex)?;
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());

    // Build ops
    let cred_op = Op::new(
        vec![],
        Hlc::new(v.nbf_ms, 1),
        issuer_pk,
        Payload::Credential {
            cred_id: v.cred_id.clone(),
            cred_bytes: compact.clone(),
            format: CredentialFormat::Jwt,
        },
        &issuer_sk,
    );

    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(v.nbf_ms, 2),
        admin_pk,
        Payload::Grant {
            subject_pk: v.subject_pk,
            cred_hash,
        },
        &admin_sk,
    );

    // Write files (ensure dir exists first).
    let out_dir = out_dir_opt.unwrap_or(".");
    let out_dir_path = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir_path)?;

    let mut p1 = out_dir_path.clone();
    p1.push("cred.op.cbor");
    let mut p2 = out_dir_path.clone();
    p2.push("grant.op.cbor");

    fs::write(&p1, canonical_cbor(&cred_op))?;
    fs::write(&p2, canonical_cbor(&grant_op))?;

    println!("credential_op_id={}", to_hex32(&cred_op.op_id));
    println!("grant_op_id      ={}", to_hex32(&grant_op.op_id));
    println!("cred_hash        ={}", to_hex32(&cred_hash));
    println!("wrote: {} and {}", p1.display(), p2.display());
    Ok(())
}

pub fn cmd_vc_status_set(list_id: &str, index: u32, value: bool) -> Result<()> {
    // Ensure ./trust/status/ exists
    let mut dir = PathBuf::from("./trust/status");
    fs::create_dir_all(&dir)?;
    dir.push(format!("{list_id}.bin"));

    // Read existing bytes (or start empty)
    let mut bytes = match fs::read(&dir) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };

    // Little-endian bit order: byte = index/8, bit = index%8
    let i = (index / 8) as usize;
    let b = (index % 8) as u8;

    if bytes.len() <= i {
        bytes.resize(i + 1, 0);
    }

    if value {
        bytes[i] |= 1u8 << b;
    } else {
        bytes[i] &= !(1u8 << b);
    }

    fs::write(&dir, &bytes)?;
    println!(
        "status {}[{}] = {}",
        list_id,
        index,
        if value { 1 } else { 0 }
    );
    println!("wrote {}", dir.display());
    Ok(())
}

// crates/cli/src/commands.rs

#[cfg(feature = "audit")]
pub fn open_audit_sink_default() -> anyhow::Result<Option<ecac_store::StoreAuditHook>> {
    match ecac_store::StoreAuditHook::open_default() {
        Ok(h) => Ok(Some(h)),
        Err(e) => {
            eprintln!("audit: disabled (failed to open default sink: {e})");
            Ok(None)
        }
    }
}

#[cfg(not(feature = "audit"))]
pub fn open_audit_sink_default() -> anyhow::Result<Option<()>> {
    Ok(None)
}

// in crates/cli/src/commands.rs (or a new file)
#[cfg(feature = "audit")]
struct MemAudit(pub Vec<ecac_core::audit::AuditEvent>);

#[cfg(feature = "audit")]
impl ecac_core::audit_hook::AuditHook for MemAudit {
    fn on_event(&mut self, e: ecac_core::audit::AuditEvent) {
        self.0.push(e);
    }
}

// ===== Audit CLI helpers =====

#[cfg(feature = "audit")]
use ecac_core::audit::AuditEvent;
#[cfg(feature = "audit")]
use ecac_store::audit::AuditReader;
#[cfg(feature = "audit")]
use std::io::Read; // fs, Path, Result, Deserialize, Serialize are already imported above

// --- shared local types to read the on-disk audit index/segments ---

#[cfg(feature = "audit")]
#[derive(Deserialize)]
struct CliIndex {
    segments: Vec<CliIndexSeg>,
}

#[cfg(feature = "audit")]
#[derive(Deserialize)]
struct CliIndexSeg {
    // relative path of segment (e.g., "segment-00000001.log")
    path: String,
    // the rest are ignored by the CLI but present in the index file
    #[allow(dead_code)]
    segment_id: Option<u32>,
    #[allow(dead_code)]
    first_seq: Option<u64>,
    #[allow(dead_code)]
    last_seq: Option<u64>,
    #[allow(dead_code)]
    first_hash: Option<[u8; 32]>,
    #[allow(dead_code)]
    last_hash: Option<[u8; 32]>,
}

#[cfg(feature = "audit")]
#[derive(Deserialize, Serialize)]
struct EntryWireCli {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
    signature: Vec<u8>,
}

#[cfg(feature = "audit")]
fn read_u32_be(r: &mut impl Read) -> std::io::Result<Option<u32>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => Ok(Some(u32::from_be_bytes(len))),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "audit")]
fn hex32(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---- audit-verify (chain only) ----

#[cfg(feature = "audit")]
pub fn cmd_audit_verify(dir_opt: Option<&str>) -> Result<()> {
    let dir = dir_opt.unwrap_or(".audit");
    let r = AuditReader::open(Path::new(dir))?;
    r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("OK: audit chain verified at {dir}");
    Ok(())
}

// ---- audit-export ----
// Deterministic JSONL: one JSON object per line, stable field order.
// We first verify the chain; if it passes, we stream decode each segment.

#[cfg(feature = "audit")]
pub fn cmd_audit_export(dir_opt: Option<&str>, out_path_opt: Option<&str>) -> Result<()> {
    let dir = dir_opt.unwrap_or(".audit");
    let out_path = out_path_opt.unwrap_or("audit.jsonl");

    // 1) Integrity check.
    let r = AuditReader::open(Path::new(dir))?;
    r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;

    // 2) Load index and iterate segments in order.
    let index_bytes = fs::read(Path::new(dir).join("index.json"))?;
    let index: CliIndex = serde_json::from_slice(&index_bytes)?;

    let mut out = std::fs::File::create(out_path)?;

    for seg in index.segments {
        let path = Path::new(dir).join(seg.path);
        let mut f = std::fs::File::open(&path)?;
        loop {
            let len = match read_u32_be(&mut f)? {
                Some(n) => n as usize,
                None => break, // EOF at boundary
            };
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            let entry: EntryWireCli = serde_cbor::from_slice(&buf)
                .map_err(|e| anyhow::anyhow!("CBOR decode failed in {:?}: {e}", path))?;

            // Build a stable export record (byte arrays → hex)
            #[derive(Serialize)]
            struct Jsonl<'a> {
                seq: u64,
                ts_monotonic: u64,
                prev_hash_hex: String,
                node_id_hex: String,
                #[serde(borrow)]
                event: &'a AuditEvent,
                signature_hex: String,
            }
            let j = Jsonl {
                seq: entry.seq,
                ts_monotonic: entry.ts_monotonic,
                prev_hash_hex: hex32(&entry.prev_hash),
                node_id_hex: hex32(&entry.node_id),
                event: &entry.event,
                signature_hex: hex32(&entry.signature),
            };

            serde_json::to_writer(&mut out, &j)?;
            // newline-delimited
            use std::io::Write as _;
            out.write_all(b"\n")?;
        }
    }

    println!("wrote deterministic JSONL to {}", out_path);
    Ok(())
}

// ---- audit-cat ----
// Dump decoded entries (pretty JSON) from either the whole log or a single segment.

#[cfg(feature = "audit")]
pub fn cmd_audit_cat(dir_opt: Option<&str>, segment_opt: Option<&str>) -> Result<()> {
    let dir = dir_opt.unwrap_or(".audit");

    let segments: Vec<String> = if let Some(seg_name) = segment_opt {
        vec![seg_name.to_string()]
    } else {
        let idx = fs::read(Path::new(dir).join("index.json"))?;
        let index: CliIndex = serde_json::from_slice(&idx)?;
        index.segments.into_iter().map(|s| s.path).collect()
    };

    for seg in segments {
        let path = Path::new(dir).join(&seg);
        println!("=== {} ===", path.display());
        let mut f = std::fs::File::open(&path)?;
        let mut _offset: u64 = 0;
        loop {
            let len = match read_u32_be(&mut f)? {
                Some(n) => n as usize,
                None => break,
            };
            _offset += 4;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            let entry: EntryWireCli = serde_cbor::from_slice(&buf)?;
            println!(
                "{{\"seq\":{},\"ts_monotonic\":{},\"prev_hash\":\"{}\",\"node_id\":\"{}\",\"event\":{},\"signature\":\"{}\"}}",
                entry.seq,
                entry.ts_monotonic,
                hex32(&entry.prev_hash),
                hex32(&entry.node_id),
                serde_json::to_string(&entry.event)?,
                hex32(&entry.signature),
            );
            _offset += len as u64;
        }
    }
    Ok(())
}

// ---- audit-verify-full (chain + replay cross-check) ----
#[cfg(feature = "audit")]
use ecac_core::dag::Dag; // Op and Store are already imported at the top

// Replay the store and WRITE decision events to the on-disk audit sink.
// Uses the default sink (respects ECAC_NODE_SK_HEX, writes to .audit).
#[cfg(feature = "audit")]
pub fn cmd_audit_record(db_dir_opt: Option<&str>) -> Result<()> {
    use anyhow::Context;
    let db_dir = db_dir_opt.unwrap_or(".ecac.db");
    let store = Store::open(Path::new(db_dir), Default::default())
        .with_context(|| format!("open store at {}", db_dir))?;
    let ids = store.topo_ids().context("load topo ids")?;
    let blobs = store.load_ops_cbor(&ids).context("load ops cbor")?;

    let mut dag = Dag::default();
    for bytes in blobs {
        let op: Op = serde_cbor::from_slice(&bytes).context("decode Op from store")?;
        dag.insert(op);
    }

    // Open default audit sink (creates .audit/*, requires ECAC_NODE_SK_HEX).
    let Some(mut sink) = open_audit_sink_default()? else {
        return Err(anyhow::anyhow!(
            "audit sink unavailable: set ECAC_NODE_SK_HEX (64 hex) and ensure .audit is writable"
        ));
    };

    let (_state, _digest) = ecac_core::replay::replay_full_with_audit(&dag, &mut sink);
    println!("OK: wrote decision events to the audit sink");
    Ok(())
}
/// Verify audit chain integrity and cross-check replay decisions against the on-disk audit.
/// Order of audit dir selection:
///  1) If ECAC_AUDIT_DIR is set, use it (must contain index.json and node_pk.bin)
///  2) <db_dir>/audit
///  3) .audit
/// If `db_dir_opt` is None, <db_dir> defaults to ".ecac.db".

#[cfg(feature = "audit")]
pub fn cmd_audit_verify_full(db_dir_opt: Option<&str>) -> Result<()> {
    use anyhow::Context;
    use std::io::Read as _;

    let db_dir = db_dir_opt.unwrap_or(".ecac.db");
        // 0) ECAC_AUDIT_DIR override
        let audit_dir: PathBuf = if let Ok(env_dir) = std::env::var("ECAC_AUDIT_DIR") {
            let p = PathBuf::from(env_dir);
            if p.join("index.json").exists() && p.join("node_pk.bin").exists() {
                eprintln!("audit: using ECAC_AUDIT_DIR={}", p.display());
                p
            } else {
                return Err(anyhow::anyhow!(
                "ECAC_AUDIT_DIR='{}' is not a valid audit dir (missing index.json/node_pk.bin)",
                    p.display()
                ));
            }
        } else {
            // 1) Prefer <db>/audit; if missing/incomplete, fall back to .audit with a note.
            let primary = Path::new(db_dir).join("audit");
            let fallback = Path::new(".audit");
            if primary.join("index.json").exists() && primary.join("node_pk.bin").exists() {
                primary
            } else if fallback.join("index.json").exists() && fallback.join("node_pk.bin").exists() {
                eprintln!(
                    "audit: '{}' missing or incomplete; falling back to {}",
                    Path::new(db_dir).join("audit").display(),
                    fallback.display()
                );
                fallback.to_path_buf()
            } else {
                return Err(anyhow::anyhow!(
                    "no audit log found in '{}' or '{}'",
                    Path::new(db_dir).join("audit").display(),
                    fallback.display()
                ));
            }
        };

    // 1) Chain integrity.
    let r = AuditReader::open(&audit_dir)?;
    r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("audit: chain OK at {}", audit_dir.display());

    // 2) Rebuild DAG from store (parent-first topo IDs) and replay with in-memory audit.
    let store = Store::open(Path::new(db_dir), Default::default())
        .with_context(|| format!("open store at {}", db_dir))?;
    let ids = store.topo_ids().context("load topo ids")?;
    let blobs = store.load_ops_cbor(&ids).context("load ops cbor")?;

    let mut dag = Dag::default();
    for bytes in blobs {
        let op: Op = serde_cbor::from_slice(&bytes).context("decode Op from store")?;
        // If your Dag uses a different API, change this to the right call.
        dag.insert(op);
    }

    let mut mem = MemAudit(Vec::new());
    let (_state, _digest) = ecac_core::replay::replay_full_with_audit(&dag, &mut mem);

    // 3) Stream the on-disk audit decisions.
    let index_bytes = fs::read(audit_dir.join("index.json"))?;
    let index: CliIndex = serde_json::from_slice(&index_bytes)?;
    let mut disk_events: Vec<AuditEvent> = Vec::new();
    for seg in &index.segments {
        let p = audit_dir.join(&seg.path);
        let mut f =
            std::fs::File::open(&p).with_context(|| format!("open segment {}", p.display()))?;
        loop {
            let len = match read_u32_be(&mut f)? {
                Some(n) => n as usize,
                None => break,
            };
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            let entry: EntryWireCli = serde_cbor::from_slice(&buf)
                .with_context(|| format!("decode CBOR in {}", p.display()))?;
            disk_events.push(entry.event);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    enum Dec {
        Applied {
            op: [u8; 32],
            topo: u64,
            why: &'static str,
        },
        Skipped {
            op: [u8; 32],
            topo: u64,
            why: &'static str,
        },
    }
    fn extract(v: &[AuditEvent]) -> Vec<Dec> {
        use ecac_core::audit::{AppliedReason, SkipReason};
        let mut out = Vec::new();
        for e in v {
            match e {
                AuditEvent::AppliedOp {
                    op_id,
                    topo_idx,
                    reason,
                } => {
                    let why = match reason {
                        AppliedReason::Authorized => "authorized",
                    };
                    out.push(Dec::Applied {
                        op: *op_id,
                        topo: *topo_idx,
                        why,
                    });
                }
                AuditEvent::SkippedOp {
                    op_id,
                    topo_idx,
                    reason,
                } => {
                    let why = match reason {
                        SkipReason::DenyWins => "deny_wins",
                        SkipReason::InvalidSig => "invalid_sig",
                        SkipReason::BadParent => "bad_parent",
                        SkipReason::RevokedCred => "revoked_cred",
                        SkipReason::ExpiredCred => "expired_cred",
                        SkipReason::OutOfScope => "out_of_scope",
                    };
                    out.push(Dec::Skipped {
                        op: *op_id,
                        topo: *topo_idx,
                        why,
                    });
                }
                _ => {}
            }
        }
        out.sort();
        out
    }

    let want = extract(&mem.0);
    let have = extract(&disk_events);
    if want == have {
        println!("OK: replay decisions match audit ({} entries)", want.len());
        return Ok(());
    }

    // Show first mismatch and per-reason counts to debug fast.
    let n = want.len().max(have.len());
    for i in 0..n {
        match (want.get(i), have.get(i)) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(a), Some(b)) => {
                eprintln!("mismatch @ {}:\n  replay: {:?}\n  audit : {:?}", i, a, b);
                break;
            }
            (Some(a), None) => {
                eprintln!("extra in replay @ {}: {:?}", i, a);
                break;
            }
            (None, Some(b)) => {
                eprintln!("missing in replay @ {}: {:?}", i, b);
                break;
            }
            _ => unreachable!(),
        }
    }
    use std::collections::BTreeMap;
    let sum = |src: &[Dec]| -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for d in src {
            match d {
                Dec::Applied { why, .. } | Dec::Skipped { why, .. } => {
                    *m.entry(*why).or_default() += 1;
                }
            }
        }
        m
    };
    eprintln!("replay summary: {:?}", sum(&want));
    eprintln!("audit  summary: {:?}", sum(&have));
    Err(anyhow::anyhow!("audit decisions diverge"))
}
